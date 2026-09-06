"""Fixture-first authority tests for the report-capture production adapter."""
from __future__ import annotations

from collections.abc import Mapping
import ast
import hashlib
import json
import os
from pathlib import Path
import sys

import pytest


SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(ROOT))

import artifact_ledger as AL  # noqa: E402
from audit_snapshot import (  # noqa: E402
    build_audit_snapshot,
    build_production_source_path_authority,
)
from artifact_ledger import (  # noqa: E402
    record_work_unit_artifacts,
    record_work_unit_inputs,
)
from phase_io_contracts import (  # noqa: E402
    ArtifactSpec,
    InputAuthorityRequirement,
    LaunchSpec,
    PhaseIOContract,
    resolve_phase_io_contract,
)
import report_assembly_capture as RAC  # noqa: E402


RUN_ID = "123e4567-e89b-42d3-a456-426614174000"
DIMS = {
    "pipeline": "sc",
    "mode": "thorough",
    "ecosystem": "evm",
    "backend": "claude",
}
OUTPUTS = {
    "project:AUDIT_REPORT.md": ("CLIENT_REPORT", b"# Audit\n"),
    "scratchpad:report_quality.md": ("REPORT_QUALITY", b"# Quality\n"),
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
    authority = build_production_source_path_authority(config, snapshot)
    return {
        **DIMS,
        "project_name": "fixture-project",
        "report_date": "2026-08-04",
        "run_id": RUN_ID,
        "scope": "contracts/",
        "source_snapshot_sha256": snapshot["snapshot_digest"],
        "source_roster_authority_sha256": authority["authority_digest"],
    }


def _launch(contract):
    return LaunchSpec(
        work_unit_key=contract.key,
        **DIMS,
        model="driver",
        timeout_s=30,
        exec_mode="python",
        tool_policy=(),
    )


def _fixture(tmp_path: Path):
    project, scratch = _empty_roots(tmp_path)
    source = RAC._capture_report_assembly_source(
        scratch,
        metadata=_metadata(scratch),
        fixed_source_roles={},
        namespace_roles={},
    )
    source_bytes = RAC._canonical_report_assembly_source_capture_bytes(source)
    contract = resolve_phase_io_contract(
        **DIMS,
        phase="report_assemble",
        work_unit_id="source_capture",
        exact_inputs=(),
        exact_outputs=("report_assembly_source_capture.json",),
        exact_input_authorities={},
    )
    launch = _launch(contract)
    record_work_unit_inputs(
        scratch, project, contract, launch, run_id=RUN_ID
    )
    (scratch / "report_assembly_source_capture.json").write_bytes(source_bytes)
    record_work_unit_artifacts(
        scratch, project, contract, launch, run_id=RUN_ID
    )
    return project, scratch, source_bytes


def _empty_roots(tmp_path: Path) -> tuple[Path, Path]:
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


def _commit_report_index_inputs(
    project: Path,
    scratch: Path,
) -> dict[str, InputAuthorityRequirement]:
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
        target = scratch / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"# Input\n")
    launch = _launch(contract)
    record_work_unit_inputs(
        scratch, project, contract, launch, run_id=RUN_ID
    )
    (scratch / "report_index.md").write_bytes(b"# Index\n")
    (scratch / "report_coverage.md").write_bytes(b"# Coverage\n")
    unit = record_work_unit_artifacts(
        scratch,
        project,
        contract,
        launch,
        run_id=RUN_ID,
        actor="DRIVER",
    )
    return {
        path: InputAuthorityRequirement(
            identity=f"scratchpad:{path}",
            expected_producer_work_unit_key=contract.key,
            expected_writer="DRIVER",
            expected_contract_digest=unit["contract_digest"],
            expected_launch_digest=unit["launch_digest"],
        )
        for path in ("report_index.md", "report_coverage.md")
    }


def _commit_body_manifest_input(
    project: Path,
    scratch: Path,
) -> dict[str, InputAuthorityRequirement]:
    _commit_report_index_inputs(project, scratch)
    relative = "body_manifests/report_fixture.json"
    contract = resolve_phase_io_contract(
        **DIMS,
        phase="report_index",
        work_unit_id="routing",
        exact_inputs=(
            "report_coverage.md",
            "report_index.md",
        ),
        exact_outputs=(relative,),
    )
    launch = _launch(contract)
    record_work_unit_inputs(
        scratch, project, contract, launch, run_id=RUN_ID
    )
    target = scratch / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b"{}\n")
    unit = record_work_unit_artifacts(
        scratch,
        project,
        contract,
        launch,
        run_id=RUN_ID,
        actor="DRIVER",
    )
    return {
        relative: InputAuthorityRequirement(
            identity=f"scratchpad:{relative}",
            expected_producer_work_unit_key=contract.key,
            expected_writer="DRIVER",
            expected_contract_digest=unit["contract_digest"],
            expected_launch_digest=unit["launch_digest"],
        )
    }


def _commit_source_capture(
    project: Path,
    scratch: Path,
    *,
    fixed_source_roles: dict[str, str] | None = None,
    namespace_roles: dict[str, str] | None = None,
    contract_input_paths: tuple[str, ...] | None = None,
    authorities: dict[str, InputAuthorityRequirement] | None = None,
) -> bytes:
    source = RAC._capture_report_assembly_source(
        scratch,
        metadata=_metadata(scratch),
        fixed_source_roles=(
            {} if fixed_source_roles is None else fixed_source_roles
        ),
        namespace_roles={} if namespace_roles is None else namespace_roles,
    )
    source_bytes = RAC._canonical_report_assembly_source_capture_bytes(source)
    exact_inputs = (
        tuple(source["input_paths"])
        if contract_input_paths is None
        else contract_input_paths
    )
    authority_by_path = authorities or {}
    contract = resolve_phase_io_contract(
        **DIMS,
        phase="report_assemble",
        work_unit_id="source_capture",
        exact_inputs=exact_inputs,
        exact_outputs=("report_assembly_source_capture.json",),
        exact_input_authorities={
            path: authority_by_path[path] for path in exact_inputs
        },
    )
    launch = _launch(contract)
    record_work_unit_inputs(
        scratch, project, contract, launch, run_id=RUN_ID
    )
    (scratch / "report_assembly_source_capture.json").write_bytes(source_bytes)
    record_work_unit_artifacts(
        scratch, project, contract, launch, run_id=RUN_ID
    )
    return source_bytes


def _authority_fixture(
    tmp_path: Path,
    *,
    fixed_source_roles: dict[str, str] | None = None,
    namespace_roles: dict[str, str] | None = None,
    with_report_index: bool = False,
    contract_input_paths: tuple[str, ...] | None = None,
) -> tuple[Path, Path, bytes]:
    project, scratch = _empty_roots(tmp_path)
    authorities = (
        _commit_report_index_inputs(project, scratch)
        if with_report_index
        else {}
    )
    raw = _commit_source_capture(
        project,
        scratch,
        fixed_source_roles=fixed_source_roles,
        namespace_roles=namespace_roles,
        contract_input_paths=contract_input_paths,
        authorities=authorities,
    )
    return project, scratch, raw


def _adapter():
    import report_capture_phaseio_authority as adapter

    return adapter


def _commit_final(project: Path, scratch: Path) -> bytes:
    raw = _adapter().build_report_final_capture_bytes(
        scratchpad=scratch,
        project_root=project,
        run_id=RUN_ID,
        expected_config=_config(scratch),
        derived_outputs=OUTPUTS,
    )
    contract = resolve_phase_io_contract(
        **DIMS,
        phase="report_assemble",
        work_unit_id="final_capture",
        exact_inputs=("report_assembly_source_capture.json",),
        exact_outputs=("report_assembly_final_capture.json",),
    )
    launch = _launch(contract)
    record_work_unit_inputs(
        scratch, project, contract, launch, run_id=RUN_ID
    )
    (scratch / "report_assembly_final_capture.json").write_bytes(raw)
    record_work_unit_artifacts(
        scratch, project, contract, launch, run_id=RUN_ID
    )
    return raw


def _assert_all_public_consumers_reject(
    project: Path,
    scratch: Path,
    candidate: bytes,
    *,
    match: str,
) -> None:
    adapter = _adapter()
    calls = (
        lambda: adapter.build_report_final_capture_bytes(
            scratchpad=scratch,
            project_root=project,
            run_id=RUN_ID,
            expected_config=_config(scratch),
            derived_outputs=OUTPUTS,
        ),
        lambda: adapter.validate_report_final_candidate_bytes(
            scratchpad=scratch,
            project_root=project,
            run_id=RUN_ID,
            expected_config=_config(scratch),
            final_capture_bytes=candidate,
        ),
        lambda: adapter.load_committed_report_final_capture_bytes(
            scratchpad=scratch, project_root=project, run_id=RUN_ID,
            expected_config=_config(scratch),
        ),
        lambda: adapter.extract_committed_report_outputs(
            scratchpad=scratch, project_root=project, run_id=RUN_ID,
            expected_config=_config(scratch),
        ),
        lambda: adapter.prepare_committed_report_publication(
            scratchpad=scratch, project_root=project, run_id=RUN_ID,
            expected_config=_config(scratch),
        ),
    )
    for call in calls:
        with pytest.raises(ValueError, match=match):
            call()


def _resign(payload: dict[str, object]) -> bytes:
    unsigned = dict(payload)
    unsigned["capture_digest"] = ""
    payload["capture_digest"] = hashlib.sha256(
        json.dumps(
            unsigned,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()
    return (
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        + b"\n"
    )


def test_public_builder_resolves_committed_source_authority(tmp_path: Path) -> None:
    project, scratch, _ = _fixture(tmp_path)
    raw = _adapter().build_report_final_capture_bytes(
        scratchpad=scratch,
        project_root=project,
        run_id=RUN_ID,
        expected_config=_config(scratch),
        derived_outputs=OUTPUTS,
    )
    payload = json.loads(raw)
    ledger = AL.read_artifact_ledger(scratch)
    unit = ledger["work_units"][
        "sc/thorough/evm/claude/report_assemble/source_capture"
    ]
    assert payload["predecessor_binding"] == {
        "artifact_identity": RAC.SOURCE_CAPTURE_IDENTITY,
        "content_sha256": hashlib.sha256(
            (scratch / "report_assembly_source_capture.json").read_bytes()
        ).hexdigest(),
        "run_id": RUN_ID,
        "producer_work_unit_key": unit["work_unit_key"],
        "contract_digest": unit["contract_digest"],
        "launch_digest": unit["launch_digest"],
        "commit_receipt_digest": unit["commit_authority"]["receipt_digest"],
    }


@pytest.mark.parametrize(
    "mutation",
    (
        {"commit_receipt_digest": "e" * 64},
        {
            "content_sha256": "e" * 64,
            "contract_digest": "e" * 64,
            "launch_digest": "e" * 64,
            "commit_receipt_digest": "e" * 64,
        },
    ),
)
def test_public_candidate_validation_rejects_self_supplied_binding(
    tmp_path: Path,
    mutation: dict[str, str],
) -> None:
    project, scratch, _ = _fixture(tmp_path)
    raw = _adapter().build_report_final_capture_bytes(
        scratchpad=scratch,
        project_root=project,
        run_id=RUN_ID,
        expected_config=_config(scratch),
        derived_outputs=OUTPUTS,
    )
    payload = json.loads(raw)
    payload["predecessor_binding"].update(mutation)
    forged = _resign(payload)
    with pytest.raises(ValueError, match="predecessor|authority|receipt"):
        _adapter().validate_report_final_candidate_bytes(
            scratchpad=scratch,
            project_root=project,
            run_id=RUN_ID,
            expected_config=_config(scratch),
            final_capture_bytes=forged,
        )


def test_public_builder_rejects_mutated_committed_source(tmp_path: Path) -> None:
    project, scratch, _ = _fixture(tmp_path)
    (scratch / "report_assembly_source_capture.json").write_bytes(b"{}")
    with pytest.raises(ValueError, match="source|authority|hash|artifact"):
        _adapter().build_report_final_capture_bytes(
            scratchpad=scratch,
            project_root=project,
            run_id=RUN_ID,
            expected_config=_config(scratch),
            derived_outputs=OUTPUTS,
        )


def test_public_candidate_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    project, scratch, _ = _fixture(tmp_path)
    raw = _adapter().build_report_final_capture_bytes(
        scratchpad=scratch,
        project_root=project,
        run_id=RUN_ID,
        expected_config=_config(scratch),
        derived_outputs=OUTPUTS,
    )
    duplicate = raw[:-2] + b',"schema_version":"forged"}\n'
    with pytest.raises(ValueError, match="duplicate"):
        _adapter().validate_report_final_candidate_bytes(
            scratchpad=scratch,
            project_root=project,
            run_id=RUN_ID,
            expected_config=_config(scratch),
            final_capture_bytes=duplicate,
        )


class _ExplodingMapping(Mapping):
    def __getitem__(self, key):
        raise AssertionError(f"mapping was indexed: {key}")

    def __iter__(self):
        raise AssertionError("mapping was iterated")

    def __len__(self):
        raise AssertionError("mapping length was read")


def test_public_candidate_never_iterates_caller_mapping(tmp_path: Path) -> None:
    project, scratch, _ = _fixture(tmp_path)
    with pytest.raises(TypeError, match="exact bytes"):
        _adapter().validate_report_final_candidate_bytes(
            scratchpad=scratch,
            project_root=project,
            run_id=RUN_ID,
            expected_config=_config(scratch),
            final_capture_bytes=_ExplodingMapping(),
        )

    with pytest.raises(TypeError, match="exact dict"):
        _adapter().build_report_final_capture_bytes(
            scratchpad=scratch,
            project_root=project,
            run_id=RUN_ID,
            expected_config=_config(scratch),
            derived_outputs=_ExplodingMapping(),
        )


def test_committed_validation_extraction_and_publication_replay_both_receipts(
    tmp_path: Path,
) -> None:
    project, scratch, _ = _fixture(tmp_path)
    raw = _commit_final(project, scratch)
    adapter = _adapter()
    assert adapter.load_committed_report_final_capture_bytes(
        scratchpad=scratch, project_root=project, run_id=RUN_ID,
        expected_config=_config(scratch),
    ) == raw
    outputs, absences = adapter.extract_committed_report_outputs(
        scratchpad=scratch, project_root=project, run_id=RUN_ID,
        expected_config=_config(scratch),
    )
    assert outputs == {
        "project:AUDIT_REPORT.md": b"# Audit\n",
        "scratchpad:report_quality.md": b"# Quality\n",
    }
    assert set(absences) == set(RAC.ALLOWED_DERIVED_OUTPUT_ROLES) - set(outputs)
    publication = adapter.prepare_committed_report_publication(
        scratchpad=scratch, project_root=project, run_id=RUN_ID,
        expected_config=_config(scratch),
    )
    assert publication.final_capture_bytes == raw
    assert publication.output_bytes == outputs
    assert publication.absent_output_identities == absences
    assert len(publication.source_commit_receipt_digest) == 64
    assert len(publication.final_commit_receipt_digest) == 64


def test_committed_extraction_rejects_final_or_source_authority_drift(
    tmp_path: Path,
) -> None:
    project, scratch, _ = _fixture(tmp_path)
    _commit_final(project, scratch)
    final_path = scratch / "report_assembly_final_capture.json"
    final_path.write_bytes(final_path.read_bytes() + b" ")
    with pytest.raises(ValueError, match="final|artifact|hash|authority"):
        _adapter().extract_committed_report_outputs(
            scratchpad=scratch, project_root=project, run_id=RUN_ID,
            expected_config=_config(scratch),
        )


@pytest.mark.parametrize("mismatch", ("payload_extra", "contract_extra"))
def test_source_payload_and_phaseio_input_denominators_are_exactly_equal(
    tmp_path: Path,
    mismatch: str,
) -> None:
    project, scratch = _empty_roots(tmp_path)
    authorities = _commit_report_index_inputs(project, scratch)
    if mismatch == "payload_extra":
        fixed = {"report_index.md": "REPORT_INDEX"}
        contract_inputs: tuple[str, ...] = ()
    else:
        fixed = {}
        contract_inputs = ("report_index.md",)
    _commit_source_capture(
        project,
        scratch,
        fixed_source_roles=fixed,
        contract_input_paths=contract_inputs,
        authorities=authorities,
    )
    with pytest.raises(ValueError, match="denominator|input|PhaseIO"):
        _adapter().build_report_final_capture_bytes(
            scratchpad=scratch,
            project_root=project,
            run_id=RUN_ID,
            expected_config=_config(scratch),
            derived_outputs=OUTPUTS,
        )


def test_live_bound_source_content_inconsistency_is_rejected(
    tmp_path: Path,
) -> None:
    project, scratch, _ = _authority_fixture(
        tmp_path,
        fixed_source_roles={"report_index.md": "REPORT_INDEX"},
        with_report_index=True,
    )
    (scratch / "report_index.md").write_bytes(b"# Mutated index\n")
    with pytest.raises(ValueError, match="input|authority|hash|source"):
        _adapter().build_report_final_capture_bytes(
            scratchpad=scratch,
            project_root=project,
            run_id=RUN_ID,
            expected_config=_config(scratch),
            derived_outputs=OUTPUTS,
        )


def test_fixed_absence_becoming_present_rejected_by_all_public_consumers(
    tmp_path: Path,
) -> None:
    project, scratch, _ = _authority_fixture(
        tmp_path,
        fixed_source_roles={
            "report_evidence_projection.md": "REPORT_EVIDENCE_PROJECTION"
        },
    )
    candidate = _commit_final(project, scratch)
    (scratch / "report_evidence_projection.md").write_bytes(b"late\n")
    _assert_all_public_consumers_reject(
        project, scratch, candidate, match="SOURCE|source|absence|drift"
    )


def test_zero_member_namespace_gain_rejected_by_all_public_consumers(
    tmp_path: Path,
) -> None:
    project, scratch, _ = _authority_fixture(
        tmp_path,
        namespace_roles={
            "report_semantic_*.md": "REPORT_SEMANTIC_NAMESPACE"
        },
    )
    candidate = _commit_final(project, scratch)
    (scratch / "report_semantic_survivor.md").write_bytes(b"late\n")
    _assert_all_public_consumers_reject(
        project, scratch, candidate, match="NAMESPACE|namespace|source|drift"
    )


@pytest.mark.parametrize("mutation", ("loss", "replacement"))
def test_namespace_loss_or_replacement_rejected_by_all_public_consumers(
    tmp_path: Path,
    mutation: str,
) -> None:
    project, scratch = _empty_roots(tmp_path)
    authorities = _commit_body_manifest_input(project, scratch)
    _commit_source_capture(
        project,
        scratch,
        namespace_roles={
            "body_manifests/report_*.json": "BODY_MANIFEST_NAMESPACE"
        },
        authorities=authorities,
    )
    candidate = _commit_final(project, scratch)
    (scratch / "body_manifests" / "report_fixture.json").unlink()
    if mutation == "replacement":
        (scratch / "body_manifests" / "report_replacement.json").write_bytes(
            b"{}\n"
        )
    _assert_all_public_consumers_reject(
        project,
        scratch,
        candidate,
        match="NAMESPACE|namespace|input|authority|source|drift",
    )


def test_terminal_source_resolution_replays_one_shot_namespace_gain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, scratch, _ = _authority_fixture(
        tmp_path,
        namespace_roles={
            "report_semantic_*.md": "REPORT_SEMANTIC_NAMESPACE"
        },
    )
    original = RAC._build_report_assembly_final_capture

    def attacked(*args, **kwargs):
        result = original(*args, **kwargs)
        (scratch / "report_semantic_survivor.md").write_bytes(b"one-shot\n")
        return result

    monkeypatch.setattr(RAC, "_build_report_assembly_final_capture", attacked)
    with pytest.raises(ValueError, match="NAMESPACE|namespace|source|drift"):
        _adapter().build_report_final_capture_bytes(
            scratchpad=scratch,
            project_root=project,
            run_id=RUN_ID,
            expected_config=_config(scratch),
            derived_outputs=OUTPUTS,
        )


def test_terminal_final_resolution_semantically_replays_one_shot_output_gain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, scratch, _ = _fixture(tmp_path)
    _commit_final(project, scratch)
    adapter = _adapter()
    original = adapter._source_still_exact

    def attacked(*args, **kwargs):
        original(*args, **kwargs)
        (scratch / "report_traceability_internal.md").write_bytes(b"late\n")

    monkeypatch.setattr(adapter, "_source_still_exact", attacked)
    with pytest.raises(ValueError, match="OUTPUT|output|final|replay"):
        adapter.load_committed_report_final_capture_bytes(
            scratchpad=scratch, project_root=project, run_id=RUN_ID,
            expected_config=_config(scratch),
        )


@pytest.mark.parametrize("consumer", ("load", "extract", "publish"))
def test_terminal_pair_replays_source_after_middle_check_hook(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    consumer: str,
) -> None:
    project, scratch, _ = _authority_fixture(
        tmp_path,
        namespace_roles={
            "report_semantic_*.md": "REPORT_SEMANTIC_NAMESPACE"
        },
    )
    _commit_final(project, scratch)
    adapter = _adapter()
    original = adapter._source_still_exact

    def attacked(*args, **kwargs):
        result = original(*args, **kwargs)
        (scratch / "report_semantic_survivor.md").write_bytes(
            b"late-after-check\n"
        )
        return result

    monkeypatch.setattr(adapter, "_source_still_exact", attacked)
    call = {
        "load": adapter.load_committed_report_final_capture_bytes,
        "extract": adapter.extract_committed_report_outputs,
        "publish": adapter.prepare_committed_report_publication,
    }[consumer]
    with pytest.raises(ValueError, match="NAMESPACE|namespace|source|drift"):
        call(
            scratchpad=scratch,
            project_root=project,
            run_id=RUN_ID,
            expected_config=_config(scratch),
        )


@pytest.mark.parametrize("consumer", ("load", "extract", "publish"))
def test_terminal_combined_epoch_rejects_output_gain_during_third_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    consumer: str,
) -> None:
    project, scratch, _ = _authority_fixture(
        tmp_path,
        namespace_roles={
            "report_semantic_*.md": "REPORT_SEMANTIC_NAMESPACE"
        },
    )
    _commit_final(project, scratch)
    adapter = _adapter()
    original = adapter._source
    calls = 0

    def attacked(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 3:
            (scratch / "report_traceability_internal.md").write_bytes(
                b"late-during-terminal-source\n"
            )
        return original(*args, **kwargs)

    monkeypatch.setattr(adapter, "_source", attacked)
    call = {
        "load": adapter.load_committed_report_final_capture_bytes,
        "extract": adapter.extract_committed_report_outputs,
        "publish": adapter.prepare_committed_report_publication,
    }[consumer]
    with pytest.raises(ValueError, match="OUTPUT|output|combined|terminal"):
        call(
            scratchpad=scratch,
            project_root=project,
            run_id=RUN_ID,
            expected_config=_config(scratch),
        )
    assert calls == 3


@pytest.mark.parametrize("consumer", ("load", "extract", "publish"))
def test_combined_epoch_rejects_output_gain_after_source_half(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    consumer: str,
) -> None:
    project, scratch, _ = _fixture(tmp_path)
    _commit_final(project, scratch)
    adapter = _adapter()
    original = RAC._terminal_source_rebuild
    calls = 0

    def attacked(*args, **kwargs):
        nonlocal calls
        result = original(*args, **kwargs)
        calls += 1
        if calls == 1:
            (scratch / "report_traceability_internal.md").write_bytes(
                b"late-after-source-half\n"
            )
        return result

    monkeypatch.setattr(RAC, "_terminal_source_rebuild", attacked)
    call = {
        "load": adapter.load_committed_report_final_capture_bytes,
        "extract": adapter.extract_committed_report_outputs,
        "publish": adapter.prepare_committed_report_publication,
    }[consumer]
    with pytest.raises(ValueError, match="OUTPUT|output|combined|terminal"):
        call(
            scratchpad=scratch,
            project_root=project,
            run_id=RUN_ID,
            expected_config=_config(scratch),
        )
    assert calls == 1


@pytest.mark.parametrize("consumer", ("load", "extract", "publish"))
def test_combined_epoch_rejects_source_gain_after_output_half(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    consumer: str,
) -> None:
    project, scratch, _ = _authority_fixture(
        tmp_path,
        namespace_roles={
            "report_semantic_*.md": "REPORT_SEMANTIC_NAMESPACE"
        },
    )
    _commit_final(project, scratch)
    adapter = _adapter()
    original = RAC._register_clean_scratch_output_namespace
    calls = 0

    def attacked(*args, **kwargs):
        nonlocal calls
        result = original(*args, **kwargs)
        calls += 1
        if calls == 3:
            (scratch / "report_semantic_survivor.md").write_bytes(
                b"late-after-output-half\n"
            )
        return result

    monkeypatch.setattr(RAC, "_register_clean_scratch_output_namespace", attacked)
    call = {
        "load": adapter.load_committed_report_final_capture_bytes,
        "extract": adapter.extract_committed_report_outputs,
        "publish": adapter.prepare_committed_report_publication,
    }[consumer]
    with pytest.raises(ValueError, match="NAMESPACE|namespace|source|combined"):
        call(
            scratchpad=scratch,
            project_root=project,
            run_id=RUN_ID,
            expected_config=_config(scratch),
        )
    assert calls == 3


@pytest.mark.parametrize(
    ("target", "consumer"),
    (
        ("report_index.md", "load"),
        ("report_assembly_source_capture.json", "extract"),
        ("report_assembly_final_capture.json", "publish"),
    ),
)
def test_combined_epoch_retains_files_after_second_observation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target: str,
    consumer: str,
) -> None:
    project, scratch, _ = _authority_fixture(
        tmp_path,
        fixed_source_roles={"report_index.md": "REPORT_INDEX"},
        with_report_index=True,
    )
    _commit_final(project, scratch)
    adapter = _adapter()
    original = RAC._observe_terminal_exact_file
    observations = 0

    def rewrite_after_observation(*args, **kwargs):
        nonlocal observations
        result = original(*args, **kwargs)
        relative = args[1]
        if relative == target:
            observations += 1
        if relative == target and observations == 2:
            path = scratch / target
            before = path.stat()
            raw = path.read_bytes()
            path.write_bytes(raw)
            os.utime(
                path,
                ns=(before.st_atime_ns, before.st_mtime_ns),
            )
        return result

    monkeypatch.setattr(
        RAC, "_observe_terminal_exact_file", rewrite_after_observation
    )
    call = {
        "load": adapter.load_committed_report_final_capture_bytes,
        "extract": adapter.extract_committed_report_outputs,
        "publish": adapter.prepare_committed_report_publication,
    }[consumer]
    # Windows retained read-share-only handles deny the write itself. POSIX
    # permits it, then the retained fd/live no-follow path/ctime check rejects.
    with pytest.raises((ValueError, OSError)):
        call(
            scratchpad=scratch,
            project_root=project,
            run_id=RUN_ID,
            expected_config=_config(scratch),
        )
    assert observations == 2


@pytest.mark.parametrize("consumer", ("load", "extract", "publish"))
def test_blocked_nested_namespace_gain_rejected_by_terminal_replay(
    tmp_path: Path,
    consumer: str,
) -> None:
    project, scratch = _empty_roots(tmp_path)
    _commit_source_capture(
        project,
        scratch,
        namespace_roles={
            "negative_closure_provider_bundles/**/*": (
                "NEGATIVE_CLOSURE_BUNDLE_NAMESPACE"
            )
        },
    )
    _commit_final(project, scratch)
    nested = scratch / "negative_closure_provider_bundles" / "p" / "deep"
    nested.mkdir(parents=True)
    (nested / "survivor.md").write_bytes(b"late nested\n")
    adapter = _adapter()
    call = {
        "load": adapter.load_committed_report_final_capture_bytes,
        "extract": adapter.extract_committed_report_outputs,
        "publish": adapter.prepare_committed_report_publication,
    }[consumer]
    with pytest.raises(ValueError, match="NAMESPACE|namespace|source|drift"):
        call(
            scratchpad=scratch,
            project_root=project,
            run_id=RUN_ID,
            expected_config=_config(scratch),
        )


def test_production_callsite_ratchet_allows_only_authority_adapter() -> None:
    forbidden = {
        "build_report_assembly_source_capture",
        "build_report_assembly_final_capture",
        "canonical_report_assembly_capture_bytes",
        "canonical_report_assembly_final_capture_bytes",
        "validate_report_assembly_source_capture",
        "validate_report_assembly_final_capture",
        "report_assembly_capture_output_bytes",
        "report_assembly_capture_output_absences",
        "replay_report_assembly_source_capture",
        "replay_report_assembly_final_capture",
        "_capture_report_assembly_source",
        "_build_report_assembly_final_capture",
        "_canonical_report_assembly_source_capture_bytes",
        "_canonical_report_assembly_final_capture_bytes",
        "_validate_report_assembly_source_capture",
        "_validate_report_assembly_final_capture",
        "_report_assembly_capture_output_bytes",
        "_report_assembly_capture_output_absences",
        "_replay_report_assembly_source_capture",
        "_replay_report_assembly_final_capture",
    }
    offenders: list[str] = []
    for path in SCRIPTS.glob("*.py"):
        if path.name.startswith("test_") or path.name in {
            "report_assembly_capture.py",
            "report_capture_phaseio_authority.py",
        }:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = (
                node.func.id
                if isinstance(node.func, ast.Name)
                else node.func.attr
                if isinstance(node.func, ast.Attribute)
                else ""
            )
            if name in forbidden:
                offenders.append(f"{path.name}:{node.lineno}:{name}")
    assert offenders == []


def test_pure_capture_validators_are_private_and_unexported() -> None:
    forbidden = {
        "build_report_assembly_source_capture",
        "build_report_assembly_final_capture",
        "canonical_report_assembly_capture_bytes",
        "canonical_report_assembly_final_capture_bytes",
        "validate_report_assembly_source_capture",
        "validate_report_assembly_final_capture",
        "report_assembly_capture_output_bytes",
        "report_assembly_capture_output_absences",
    }
    assert forbidden.isdisjoint(set(RAC.__all__))
    assert all(not hasattr(RAC, name) for name in forbidden)
