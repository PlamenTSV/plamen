"""Focused acceptance for the atomic final chain hypothesis/mapping provider."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Sequence

import pytest

from artifact_ledger import (
    arm_semantic_mutation,
    finalize_semantic_mutation,
    record_work_unit_artifacts,
    record_work_unit_inputs,
)
from phase_io_contracts import (
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    canonical_work_unit_key,
)
from preverify_chain_pair_projection import (
    HYPOTHESES_LOGICAL,
    MAPPING_LOGICAL,
    ROOT,
    prepare_preverify_chain_pair_projection,
)
import preverify_chain_pair_projection as CHAIN_PAIR
import plamen_driver as DRIVER


RUN_ID = "3f6f3618-d36f-4a40-8551-f6a3b7d40ffd"
FOREIGN_RUN_ID = "7cc15e35-ad39-4bcf-b6bb-384a5c04cb3f"
HYPOTHESES = (
    b"# Hypotheses\n\n"
    b"| Hypothesis | Constituents | Severity |\n"
    b"|---|---|---|\n"
    b"| H-1 | INV-1 | Medium |\n"
)
MAPPING = (
    b"# Finding Mapping\n\n"
    b"| Hypothesis | Source Findings |\n"
    b"|---|---|\n"
    b"| H-1 | INV-1 |\n"
)


def _claim(
    *,
    root: Path,
    project: Path,
    paths: Sequence[str],
    run_id: str,
    work_unit_id: str,
) -> None:
    owner = canonical_work_unit_key(
        "sc",
        "thorough",
        "evm",
        "claude",
        "chain",
        work_unit_id,
    )
    postimages = {
        relative: (root / relative).read_bytes()
        for relative in paths
    }
    for relative in paths:
        (root / relative).unlink()
    contract = PhaseIOContract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="chain",
        work_unit_id=work_unit_id,
        outputs=tuple(
            ArtifactSpec(
                root="scratchpad",
                path=relative,
                owner_key=owner,
                artifact_class="REQUIRED",
                writer="MODEL",
                write_mode="CREATE",
                schema_version="unstructured.v1",
                minimum_gate="FIXTURE_EXACT_BYTES",
                consumers=("sc_verify_queue/preverify_chain_pair",),
            )
            for relative in paths
        ),
        immutable_inputs=(),
        bounded_lookup_inputs=(),
        model_invoked=True,
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        model="fixture-chain",
        timeout_s=60,
        exec_mode="pty",
        tool_policy=("filesystem",),
    )
    record_work_unit_inputs(
        root,
        project,
        contract,
        launch,
        run_id=run_id,
    )
    for relative, raw in postimages.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    record_work_unit_artifacts(
        root,
        project,
        contract,
        launch,
        run_id=run_id,
        actor="MODEL",
    )


def _seed(
    tmp_path: Path,
    *,
    split_runs: bool = False,
) -> tuple[Path, Path]:
    project = tmp_path / "project"
    project.mkdir()
    root = project / ".scratchpad"
    root.mkdir()
    (root / HYPOTHESES_LOGICAL).write_bytes(HYPOTHESES)
    (root / MAPPING_LOGICAL).write_bytes(MAPPING)
    if split_runs:
        _claim(
            root=root,
            project=project,
            paths=(HYPOTHESES_LOGICAL,),
            run_id=RUN_ID,
            work_unit_id="hypotheses",
        )
        _claim(
            root=root,
            project=project,
            paths=(MAPPING_LOGICAL,),
            run_id=FOREIGN_RUN_ID,
            work_unit_id="mapping",
        )
    else:
        _claim(
            root=root,
            project=project,
            paths=(HYPOTHESES_LOGICAL, MAPPING_LOGICAL),
            run_id=RUN_ID,
            work_unit_id="model",
        )
    return root, project


def _seed_pair(
    tmp_path: Path,
    *,
    hypotheses: bytes,
    mapping: bytes,
) -> tuple[Path, Path]:
    project = tmp_path / "project"
    project.mkdir()
    root = project / ".scratchpad"
    root.mkdir()
    (root / HYPOTHESES_LOGICAL).write_bytes(hypotheses)
    (root / MAPPING_LOGICAL).write_bytes(mapping)
    _claim(
        root=root,
        project=project,
        paths=(HYPOTHESES_LOGICAL, MAPPING_LOGICAL),
        run_id=RUN_ID,
        work_unit_id="model",
    )
    return root, project


def _prepare(
    root: Path,
    project: Path,
    *,
    failpoint=None,
) -> dict[str, Any]:
    return prepare_preverify_chain_pair_projection(
        scratchpad=root,
        project_root=project,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase_name="sc_verify_queue",
        run_id=RUN_ID,
        failpoint=failpoint,
    )


def _root_bytes(root: Path) -> dict[str, bytes]:
    return {
        relative: (root / relative).read_bytes()
        for relative in (HYPOTHESES_LOGICAL, MAPPING_LOGICAL)
        if (root / relative).is_file()
    }


def test_exact_current_run_pair_commits_one_atomic_generation(tmp_path: Path):
    root, project = _seed(tmp_path)
    before = _root_bytes(root)

    result = _prepare(root, project)

    assert result["state"] == "OUTPUT_COMMITTED"
    assert result["safe_to_consume"] is True
    assert result["debt"] == []
    assert set(result["logical_to_physical"]) == {
        HYPOTHESES_LOGICAL,
        MAPPING_LOGICAL,
    }
    for logical, physical in result["logical_to_physical"].items():
        assert (root / physical).read_bytes() == before[logical]
    receipt = json.loads(
        (root / result["receipt_path"]).read_text(
            encoding="utf-8", errors="strict"
        )
    )
    assert receipt["publication_atomicity"] == "PAIRED_DIRECTORY_RENAME"
    assert receipt["relation_validation"]["state"] == "EXACT"
    assert receipt["relation_validation"]["issues"] == []
    assert {
        receipt["source_authorities"][logical]["authority_kind"]
        for logical in (HYPOTHESES_LOGICAL, MAPPING_LOGICAL)
    } == {"EXACT_PHASE_IO_PRODUCER"}
    assert _root_bytes(root) == before


def test_contiguous_same_run_mutation_pair_degrades_without_reblessing_roots(
    tmp_path: Path,
):
    root, project = _seed(tmp_path)
    events = []
    for relative in (HYPOTHESES_LOGICAL, MAPPING_LOGICAL):
        events.append(arm_semantic_mutation(
            root,
            project,
            artifact_identity="scratchpad:" + relative,
            mutation_kind="CHAIN_FINAL_ADDITIVE_REPAIR",
            run_id=RUN_ID,
        ))
    mutated = {
        HYPOTHESES_LOGICAL: HYPOTHESES + b"| H-2 | INV-2 | Low |\n",
        MAPPING_LOGICAL: MAPPING + b"| H-2 | INV-2 |\n",
    }
    for relative, raw in mutated.items():
        (root / relative).write_bytes(raw)
    for event in events:
        finalize_semantic_mutation(
            root,
            project,
            str(event["event_id"]),
            run_id=RUN_ID,
            affected_record_ids=("H-2", "INV-2"),
        )

    result = _prepare(root, project)

    assert result["state"] == "DEGRADED_INPUT_AUTHORITY"
    assert result["safe_to_consume"] is False
    assert result["logical_to_physical"] == {}
    assert result["debt"][0]["reason_code"] == (
        "FINAL_CHAIN_PAIR_AUTHORITY_UNAVAILABLE"
    )
    assert _root_bytes(root) == mutated


@pytest.mark.parametrize("failure", ("partial", "foreign"))
def test_partial_or_foreign_pair_degrades_visibly_and_preserves_candidates(
    tmp_path: Path,
    failure: str,
):
    root, project = _seed(tmp_path, split_runs=failure == "foreign")
    if failure == "partial":
        (root / MAPPING_LOGICAL).unlink()
    before = _root_bytes(root)

    result = _prepare(root, project)

    assert result["state"] == "DEGRADED_INPUT_AUTHORITY"
    assert result["safe_to_consume"] is False
    assert result["logical_to_physical"] == {}
    assert result["debt"][0]["reason_code"] == (
        "FINAL_CHAIN_PAIR_AUTHORITY_UNAVAILABLE"
    )
    assert result["debt"][0]["candidate_disposition"] == (
        "PRESERVE_ALL_FOR_VERIFICATION"
    )
    assert result["proof_authority"] == "NONE"
    debt = json.loads(
        (root / result["receipt_path"]).read_text(encoding="utf-8")
    )
    assert debt["phase_io_authority"] == "NONE_DIAGNOSTIC_ONLY"
    assert debt["mutable_roots_rewritten"] is False
    assert debt["logical_to_physical"] == {}
    assert _root_bytes(root) == before
    assert not list((root / ROOT).glob("generation_*"))


def test_clear_dead_mapping_is_visible_debt_without_erasing_the_pair(
    tmp_path: Path,
):
    root, project = _seed_pair(
        tmp_path,
        hypotheses=HYPOTHESES,
        mapping=(
            b"# Finding Mapping\n\n"
            b"| Finding ID | Hypothesis ID | Mapping Status |\n"
            b"|---|---|---|\n"
            b"| INV-1 | H-2 | GROUPED |\n"
        ),
    )
    before = _root_bytes(root)

    result = _prepare(root, project)

    assert result["state"] == "OUTPUT_COMMITTED"
    assert result["safe_to_consume"] is True
    assert result["debt"][0]["reason_code"] == (
        "CHAIN_PAIR_RELATION_CONTRADICTION"
    )
    assert result["debt"][0]["candidate_disposition"] == (
        "PRESERVE_BOTH_ROOTS_FOR_VERIFICATION"
    )
    assert set(result["logical_to_physical"]) == {
        HYPOTHESES_LOGICAL,
        MAPPING_LOGICAL,
    }
    for logical, physical in result["logical_to_physical"].items():
        assert (root / physical).read_bytes() == before[logical]
    receipt = json.loads(
        (root / result["receipt_path"]).read_text(encoding="utf-8")
    )
    relation = receipt["relation_validation"]
    assert relation["state"] == "CONTRADICTED"
    assert relation["mapping_only_hypothesis_ids"] == ["H-2"]
    assert relation["hypotheses_only_hypothesis_ids"] == ["H-1"]
    assert relation["proof_authority"] == "NONE"
    assert _root_bytes(root) == before


def test_clear_constituent_edge_mismatch_is_visible_without_filtering_sources(
    tmp_path: Path,
):
    root, project = _seed_pair(
        tmp_path,
        hypotheses=HYPOTHESES,
        mapping=(
            b"# Finding Mapping\n\n"
            b"| Finding ID | Hypothesis ID | Mapping Status |\n"
            b"|---|---|---|\n"
            b"| INV-2 | H-1 | GROUPED |\n"
        ),
    )
    before = _root_bytes(root)

    result = _prepare(root, project)

    assert result["state"] == "OUTPUT_COMMITTED"
    assert result["debt"][0]["reason_code"] == (
        "CHAIN_PAIR_RELATION_CONTRADICTION"
    )
    receipt = json.loads(
        (root / result["receipt_path"]).read_text(encoding="utf-8")
    )
    relation = receipt["relation_validation"]
    assert relation["hypotheses_only_hypothesis_ids"] == []
    assert relation["mapping_only_hypothesis_ids"] == []
    assert relation["hypotheses_only_edge_count"] == 1
    assert relation["mapping_only_edge_count"] == 1
    assert relation["candidate_records_removed"] == 0
    for logical, physical in result["logical_to_physical"].items():
        assert (root / physical).read_bytes() == before[logical]


def test_ambiguous_relation_format_is_debt_but_preserves_every_source_byte(
    tmp_path: Path,
):
    ambiguous_hypotheses = (
        b"# Hypotheses\n\n"
        b"## Hypothesis H-1\n\n"
        b"Constituents might include INV-1; retain it for verification.\n"
    )
    root, project = _seed_pair(
        tmp_path,
        hypotheses=ambiguous_hypotheses,
        mapping=MAPPING,
    )
    before = _root_bytes(root)

    result = _prepare(root, project)

    assert result["state"] == "OUTPUT_COMMITTED"
    assert result["safe_to_consume"] is True
    assert result["debt"][0]["reason_code"] == (
        "CHAIN_PAIR_RELATION_AMBIGUOUS"
    )
    assert result["debt"][0]["candidate_disposition"] == (
        "PRESERVE_BOTH_ROOTS_FOR_VERIFICATION"
    )
    for logical, physical in result["logical_to_physical"].items():
        assert (root / physical).read_bytes() == before[logical]
    receipt = json.loads(
        (root / result["receipt_path"]).read_text(encoding="utf-8")
    )
    assert receipt["relation_validation"]["state"] == "AMBIGUOUS"
    assert receipt["relation_validation"]["candidate_records_removed"] == 0
    assert _root_bytes(root) == before


def test_relation_row_bound_degrades_to_ambiguity_without_dropping_pair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    hypotheses = (
        b"# Hypotheses\n\n"
        b"| Hypothesis ID | Constituent Findings |\n"
        b"|---|---|\n"
        b"| H-1 | INV-1 |\n"
        b"| H-2 | INV-2 |\n"
    )
    mapping = (
        b"# Finding Mapping\n\n"
        b"| Finding ID | Hypothesis ID |\n"
        b"|---|---|\n"
        b"| INV-1 | H-1 |\n"
        b"| INV-2 | H-2 |\n"
    )
    root, project = _seed_pair(
        tmp_path,
        hypotheses=hypotheses,
        mapping=mapping,
    )
    monkeypatch.setattr(CHAIN_PAIR, "MAX_RELATION_ROWS", 1)

    result = _prepare(root, project)

    assert result["state"] == "OUTPUT_COMMITTED"
    assert result["debt"][0]["reason_code"] == (
        "CHAIN_PAIR_RELATION_AMBIGUOUS"
    )
    receipt = json.loads(
        (root / result["receipt_path"]).read_text(encoding="utf-8")
    )
    assert receipt["relation_validation"]["state"] == "AMBIGUOUS"
    assert receipt["relation_validation"]["candidate_records_removed"] == 0
    assert set(result["logical_to_physical"]) == {
        HYPOTHESES_LOGICAL,
        MAPPING_LOGICAL,
    }


def test_relation_parser_failure_is_nonblocking_and_preserves_pair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    root, project = _seed(tmp_path)
    before = _root_bytes(root)

    def fail_parser(*_args, **_kwargs):
        raise RuntimeError("fixture parser defect")

    monkeypatch.setattr(CHAIN_PAIR, "_typed_relation_rows", fail_parser)
    result = _prepare(root, project)

    assert result["state"] == "OUTPUT_COMMITTED"
    assert result["safe_to_consume"] is True
    assert result["debt"][0]["reason_code"] == (
        "CHAIN_PAIR_RELATION_AMBIGUOUS"
    )
    assert any(
        "relation parser failed safely" in issue
        for issue in result["debt"][0]["issues"]
    )
    for logical, physical in result["logical_to_physical"].items():
        assert (root / physical).read_bytes() == before[logical]
    assert _root_bytes(root) == before


@pytest.mark.parametrize(
    ("interrupt_at", "receipt_persisted"),
    (
        ("after_chain_pair_debt_stage", False),
        ("after_chain_pair_debt_replace", True),
    ),
)
def test_interrupted_degraded_receipt_publish_never_leaves_partial_or_halts_replay(
    tmp_path: Path,
    interrupt_at: str,
    receipt_persisted: bool,
):
    root, project = _seed(tmp_path)
    (root / MAPPING_LOGICAL).unlink()

    def interrupt(label: str) -> None:
        if label == interrupt_at:
            raise RuntimeError("fixture interruption during debt publication")

    interrupted = _prepare(root, project, failpoint=interrupt)

    assert interrupted["state"] == "DEGRADED_INPUT_AUTHORITY"
    assert interrupted["safe_to_consume"] is False
    assert interrupted["logical_to_physical"] == {}
    assert not list((root / ROOT).glob(".debt_*.tmp"))
    if receipt_persisted:
        assert interrupted["receipt_path"]
        persisted = json.loads(
            (root / interrupted["receipt_path"]).read_text(encoding="utf-8")
        )
        assert persisted["receipt_digest"]
        assert any(
            "DEBT_RECEIPT_DURABILITY_UNCERTAIN" in issue
            for issue in interrupted["debt"][0]["issues"]
        )
    else:
        assert interrupted["receipt_path"] is None
        assert interrupted["required_paths"] == []
        assert any(
            "DEBT_RECEIPT_PERSISTENCE_INTERRUPTED" in issue
            for issue in interrupted["debt"][0]["issues"]
        )
        assert not list((root / ROOT).glob("debt_*.json"))

    recovered = _prepare(root, project)
    assert recovered["state"] == "DEGRADED_INPUT_AUTHORITY"
    assert recovered["receipt_path"]
    receipt = json.loads(
        (root / recovered["receipt_path"]).read_text(encoding="utf-8")
    )
    assert receipt["receipt_digest"]
    assert not list((root / ROOT).glob(".debt_*.tmp"))


def test_legacy_partial_debt_receipt_is_repaired_atomically_on_replay(
    tmp_path: Path,
):
    root, project = _seed(tmp_path)
    (root / MAPPING_LOGICAL).unlink()
    first = _prepare(root, project)
    receipt_path = root / first["receipt_path"]
    expected = receipt_path.read_bytes()
    receipt_path.write_bytes(expected[:17])

    replay = _prepare(root, project)

    assert replay["state"] == "DEGRADED_INPUT_AUTHORITY"
    assert replay["receipt_path"] == first["receipt_path"]
    assert receipt_path.read_bytes() == expected
    parsed = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert parsed["receipt_digest"]


def test_unsafe_nonregular_source_degrades_without_halting_debt_observation(
    tmp_path: Path,
):
    root, project = _seed(tmp_path)
    (root / MAPPING_LOGICAL).unlink()
    (root / MAPPING_LOGICAL).mkdir()

    result = _prepare(root, project)

    assert result["state"] == "DEGRADED_INPUT_AUTHORITY"
    assert result["safe_to_consume"] is False
    assert result["receipt_path"]
    receipt = json.loads(
        (root / result["receipt_path"]).read_text(encoding="utf-8")
    )
    assert receipt["observed_roots"][MAPPING_LOGICAL]["status"] == (
        "PRESENT_UNSAFE_OR_UNSTABLE"
    )
    assert result["debt"][0]["reason_code"] == (
        "FINAL_CHAIN_PAIR_AUTHORITY_UNAVAILABLE"
    )


def test_exact_replay_is_idempotent_and_does_not_touch_roots_or_ledgers(
    tmp_path: Path,
):
    root, project = _seed(tmp_path)
    before_roots = _root_bytes(root)
    first = _prepare(root, project)
    ledger_before = (root / "_artifact_state.json").read_bytes()
    files_before = sorted(
        path.relative_to(root).as_posix()
        for path in (root / ROOT).rglob("*")
        if path.is_file()
    )

    second = _prepare(root, project)

    assert second == first
    assert (root / "_artifact_state.json").read_bytes() == ledger_before
    assert _root_bytes(root) == before_roots
    assert sorted(
        path.relative_to(root).as_posix()
        for path in (root / ROOT).rglob("*")
        if path.is_file()
    ) == files_before


def test_interrupted_staging_never_exposes_a_partial_pair_and_replay_recovers(
    tmp_path: Path,
):
    root, project = _seed(tmp_path)
    before = _root_bytes(root)

    def interrupt(label: str) -> None:
        if label == f"after_stage_{HYPOTHESES_LOGICAL}":
            raise RuntimeError("fixture interruption between paired writes")

    failed = _prepare(root, project, failpoint=interrupt)

    assert failed["state"] == "DEGRADED_INPUT_AUTHORITY"
    assert failed["logical_to_physical"] == {}
    assert failed["debt"][0]["reason_code"] == (
        "FINAL_CHAIN_PAIR_ATOMIC_PUBLICATION_FAILED"
    )
    assert not list((root / ROOT).glob("generation_*"))
    assert not list((root / ROOT).glob(".s_*"))
    assert _root_bytes(root) == before

    recovered = _prepare(root, project)
    assert recovered["state"] == "OUTPUT_COMMITTED"
    assert set(recovered["logical_to_physical"]) == {
        HYPOTHESES_LOGICAL,
        MAPPING_LOGICAL,
    }
    assert _root_bytes(root) == before


def test_fresh_chain_auto_map_records_paired_mutation_before_final_projection(
    tmp_path: Path,
):
    root, project = _seed(tmp_path)
    (root / "depth_generic_findings.md").write_text(
        "# Depth Findings\n\n"
        "### Finding [DA-2]: Generic unmapped depth candidate\n"
        "**Verdict**: CONFIRMED\n"
        "**Severity**: Medium\n"
        "**Location**: src/Fixture.sol:20\n"
        "**Description**: Generic fixture mechanism.\n"
        "**Impact**: Requires independent verification.\n",
        encoding="utf-8",
    )
    _claim(
        root=root,
        project=project,
        paths=("depth_generic_findings.md",),
        run_id=RUN_ID,
        work_unit_id="depth_generic_fixture",
    )
    config: dict[str, Any] = {
        "_run_id": RUN_ID,
        "project_root": str(project),
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
    }

    mapped, issues = (
        DRIVER._auto_map_unmapped_depth_findings_with_semantic_authority(
            root,
            config,
            owner_phase="chain",
            gate_issues=("DA-2 is absent from finding_mapping.md",),
        )
    )

    assert mapped == ["DA-2"]
    assert issues == []
    assert "DA-2" in (root / HYPOTHESES_LOGICAL).read_text(encoding="utf-8")
    assert "DA-2" in (root / MAPPING_LOGICAL).read_text(encoding="utf-8")
    assert "_pending_phase_semantic_mutations" not in config

    result = _prepare(root, project)
    assert result["state"] == "OUTPUT_COMMITTED"
    receipt = json.loads(
        (root / result["receipt_path"]).read_text(encoding="utf-8")
    )
    assert {
        receipt["source_authorities"][logical]["authority_kind"]
        for logical in (HYPOTHESES_LOGICAL, MAPPING_LOGICAL)
    } == {"EXACT_PHASE_IO_PRODUCER"}
    assert len({
        receipt["source_authorities"][logical]["producer_work_unit_key"]
        for logical in (HYPOTHESES_LOGICAL, MAPPING_LOGICAL)
    }) == 1


def test_resume_noop_auto_map_does_not_mint_mutation_or_touch_pair(
    tmp_path: Path,
):
    root, project = _seed(tmp_path)
    config: dict[str, Any] = {
        "_run_id": RUN_ID,
        "project_root": str(project),
    }
    before = _root_bytes(root)
    ledger_before = (root / "_artifact_state.json").read_bytes()

    mapped, issues = (
        DRIVER._auto_map_unmapped_depth_findings_with_semantic_authority(
            root,
            config,
            owner_phase="chain",
            gate_issues=(),
        )
    )

    assert mapped == []
    assert issues == []
    assert "_pending_phase_semantic_mutations" not in config
    assert _root_bytes(root) == before
    assert (root / "_artifact_state.json").read_bytes() == ledger_before
    assert not (root / "_semantic_mutations.json").exists()
