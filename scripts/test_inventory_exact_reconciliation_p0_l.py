"""P0-L exact raw-discovery -> chunk -> final-inventory reconciliation.

The reconciliation is a recall boundary, not a truncation heuristic.  Every
canonical finding block in every shard-assigned source artifact must reach a
concrete inventory block, receive a source-bound typed disposition, or remain
content-bearing repair/human-review debt.  Percent coverage never authorizes
loss.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from inventory_reconciliation import (  # noqa: E402
    AUTHORITY_SCHEMA,
    NEGATIVE_EVIDENCE_SCHEMA,
    reconcile_inventory,
    validate_inventory_reconciliation,
    write_inventory_reconciliation,
)
from inventory_reemit_authority import (  # noqa: E402
    _apply_inventory_reemit_repair_for_tests,
)
import plamen_validators as V  # noqa: E402
import plamen_driver as D  # noqa: E402
from artifact_ledger import (  # noqa: E402
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
)
from assurance_limitations import build_current_assurance_manifest  # noqa: E402
from phase_io_contracts import (  # noqa: E402
    LaunchSpec,
    canonical_work_unit_key,
    registered_projection_handoff,
    resolve_phase_io_contract,
)
from plamen_types import Checkpoint, SC_PHASES  # noqa: E402


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_inventory_retry_handoff_is_exact_same_shard_successor_only() -> None:
    def key(shard: str, attempt: int) -> str:
        return canonical_work_unit_key(
            "sc",
            "thorough",
            "evm",
            "codex",
            f"inventory_chunk_{shard}",
            f"model.attempt{attempt:04d}",
        )

    identity = "scratchpad:findings_inventory_chunk_a.md"
    assert registered_projection_handoff(key("a", 1), key("a", 2), identity)
    assert registered_projection_handoff(key("a", 2), key("a", 3), identity)
    assert not registered_projection_handoff(key("a", 1), key("a", 3), identity)
    assert not registered_projection_handoff(
        key("a", 1),
        key("b", 2),
        identity,
    )
    assert not registered_projection_handoff(
        key("a", 1),
        key("a", 2),
        "scratchpad:findings_inventory_chunk_b.md",
    )


def _finding(fid: str, title: str, *, loc: str = "src/Module.sol:L10") -> str:
    return (
        f"### Finding [{fid}]: {title}\n"
        "**Severity**: Medium\n"
        f"**Location**: {loc}\n"
        f"**Root Cause**: mechanism for {title}\n"
        f"**Description**: description for {title}\n"
        f"**Impact**: material effect for {title}\n"
        "**Verdict**: NEEDS_VERIFICATION\n\n"
    )


def _manifest(root: Path, shard: str, *sources: str) -> None:
    lines = [
        f"# {shard} manifest",
        "",
        "| File | Estimated signals |",
        "|------|-------------------|",
        *(f"| {source} | 1 |" for source in sources),
        "",
    ]
    (root / f"{shard}.manifest.md").write_text("\n".join(lines), encoding="utf-8")


def _chunk(root: Path, shard: str, rows: list[tuple[str, str, tuple[str, ...]]]) -> None:
    text = "# Inventory Chunk\n\n## Per-Finding Detail\n\n"
    for local_id, title, source_ids in rows:
        text += _finding(local_id, title).replace(
            "**Verdict**: NEEDS_VERIFICATION\n",
            "**Source IDs**: " + ", ".join(source_ids) + "\n"
            "**Preferred Tag**: [CODE-TRACE]\n"
            "**Verdict**: NEEDS_VERIFICATION\n",
        )
    (root / f"findings_{shard}.md").write_text(text, encoding="utf-8")


def _inventory(root: Path, rows: list[tuple[str, str, tuple[str, ...]]], *, suffix: str = "") -> None:
    text = "# Finding Inventory\n\n## Findings\n\n"
    for inv_id, title, source_ids in rows:
        text += _finding(inv_id, title).replace(
            "**Verdict**: NEEDS_VERIFICATION\n",
            "**Source IDs**: " + ", ".join(source_ids) + "\n"
            "**Verdict**: NEEDS_VERIFICATION\n",
        )
    text += suffix
    (root / "findings_inventory.md").write_text(text, encoding="utf-8")


def _one_retained_candidate(root: Path) -> None:
    (root / "analysis_evm_flow.md").write_text(
        _finding("TF-1", "Generic flow mismatch"), encoding="utf-8"
    )
    _manifest(root, "inventory_chunk_a", "analysis_evm_flow.md")
    _chunk(
        root,
        "inventory_chunk_a",
        [("CC-1", "Generic flow mismatch", ("TF-1",))],
    )
    _inventory(
        root,
        [("INV-001", "Generic flow mismatch", ("TF-1", "CC-1"))],
    )


def _activate_chunk_model(
    project: Path,
    scratchpad: Path,
    config: dict,
    phase_name: str = "inventory_chunk_a",
) -> None:
    output = scratchpad / f"findings_{phase_name}.md"
    raw = output.read_bytes()
    output.unlink()
    sources = tuple(
        D.parse_inventory_shard_manifest(scratchpad, phase_name)
    )
    contract = resolve_phase_io_contract(
        pipeline=config["pipeline"],
        mode=config["mode"],
        ecosystem=config["language"],
        backend=config["cli_backend"],
        phase=phase_name,
        work_unit_id="model.attempt0001",
        exact_inputs=(f"{phase_name}.manifest.md", *sources),
        exact_outputs=(output.name,),
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="fixture-model",
        timeout_s=30,
        exec_mode="headless",
        tool_policy=("filesystem",),
    )
    record_work_unit_inputs(
        scratchpad, project, contract, launch, run_id=config["_run_id"]
    )
    output.write_bytes(raw)
    record_work_unit_artifacts(
        scratchpad,
        project,
        contract,
        launch,
        run_id=config["_run_id"],
        actor="MODEL",
    )


def test_inventory_retry_can_replace_quarantined_prior_attempt(
    tmp_path: Path,
) -> None:
    run_id = "inventory-retry-lineage-fixture"
    source = tmp_path / "analysis_evm_flow.md"
    source.write_text(_finding("TF-1", "Retry candidate"), encoding="utf-8")
    _manifest(tmp_path, "inventory_chunk_a", source.name)
    _chunk(
        tmp_path,
        "inventory_chunk_a",
        [("CC-1", "Incomplete retry candidate", ("TF-1",))],
    )
    output = tmp_path / "findings_inventory_chunk_a.md"
    exact_inputs = ("inventory_chunk_a.manifest.md", source.name)

    def authority(attempt: int) -> tuple[object, LaunchSpec]:
        contract = resolve_phase_io_contract(
            pipeline="sc",
            mode="thorough",
            ecosystem="evm",
            backend="codex",
            phase="inventory_chunk_a",
            work_unit_id=f"model.attempt{attempt:04d}",
            exact_inputs=exact_inputs,
            exact_outputs=(output.name,),
        )
        launch = LaunchSpec(
            work_unit_key=contract.key,
            pipeline=contract.pipeline,
            mode=contract.mode,
            ecosystem=contract.ecosystem,
            backend=contract.backend,
            model="fixture-model",
            timeout_s=30,
            exec_mode="headless",
            tool_policy=("filesystem",),
        )
        return contract, launch

    first_contract, first_launch = authority(1)
    first_raw = output.read_bytes()
    output.unlink()
    record_work_unit_inputs(
        tmp_path, tmp_path, first_contract, first_launch, run_id=run_id
    )
    output.write_bytes(first_raw)
    first = record_work_unit_artifacts(
        tmp_path,
        tmp_path,
        first_contract,
        first_launch,
        run_id=run_id,
        actor="MODEL",
    )
    assert first["semantic_status"] == "ACTIVE"

    output.rename(tmp_path / "findings_inventory_chunk_a.attempt1.rejected.md")
    rejected = record_work_unit_artifacts(
        tmp_path,
        tmp_path,
        first_contract,
        first_launch,
        run_id=run_id,
        status="QUARANTINED",
        actor="MODEL",
        precommit_issues=("attempt 1 rejected before retry",),
    )
    assert rejected["semantic_status"] == "QUARANTINED"

    second_contract, second_launch = authority(2)
    record_work_unit_inputs(
        tmp_path, tmp_path, second_contract, second_launch, run_id=run_id
    )
    output.write_text(
        "# Inventory Chunk\n\n## Source Summary\n\nRetry.\n\n"
        "## Master Table\n\n| ID | Title |\n|---|---|\n| CC-1 | Retry |\n\n"
        "## Per-Finding Detail\n\n"
        + _finding("CC-1", "Complete retry candidate"),
        encoding="utf-8",
    )
    second = record_work_unit_artifacts(
        tmp_path,
        tmp_path,
        second_contract,
        second_launch,
        run_id=run_id,
        actor="MODEL",
    )
    assert second["semantic_status"] == "ACTIVE"
    assert second["execution_state"] == "OUTPUT_COMMITTED"


def _activate_canonical_inventory(
    project: Path,
    scratchpad: Path,
    config: dict,
) -> None:
    _activate_chunk_model(project, scratchpad, config)
    (scratchpad / "findings_inventory.md").unlink(missing_ok=True)
    result, issues = D._run_inventory_canonical_aggregate_transaction(
        scratchpad=scratchpad,
        config=config,
        phase=next(item for item in SC_PHASES if item.name == "inventory"),
        derivation_kind="single_shard",
    )
    assert result["finding_count"] == 1
    assert issues == []


def _authority(
    root: Path,
    *,
    source: str,
    source_id: str,
    disposition: str,
    target: str = "",
    evidence_file: str = "",
    evidence_record_id: str = "",
) -> None:
    source_path = root / source
    result = reconcile_inventory(root, persist=False)
    candidate = next(
        row for row in result["candidates"]
        if row["source_artifact"] == source and row["source_finding_id"] == source_id
    )
    row = {
        "candidate_key": candidate["candidate_key"],
        "source_artifact": source,
        "source_sha256": _sha(source_path),
        "source_finding_id": source_id,
        "source_block_sha256": candidate["source_block_sha256"],
        "disposition": disposition,
        "target_artifact": "findings_inventory.md" if target else "",
        "target_finding_id": target,
        "alias_union": [candidate["candidate_key"]] if disposition == "MERGED_ALIAS" else [],
        "decision_provider_id": "inventory-adjudicator",
        "evidence_provider_id": "source-reviewer" if disposition == "SUPPORTED_REFUTATION" else "",
        "evidence_artifact": evidence_file,
        "evidence_sha256": _sha(root / evidence_file) if evidence_file else "",
        "evidence_record_id": evidence_record_id,
    }
    payload = {
        "schema_version": AUTHORITY_SCHEMA,
        "rows": [row],
    }
    (root / "inventory_disposition_authority.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def test_100_percent_retained_across_two_shards_and_ecosystems(tmp_path: Path) -> None:
    (tmp_path / "analysis_evm_flow.md").write_text(
        _finding("TF-1", "EVM flow mismatch"), encoding="utf-8"
    )
    (tmp_path / "graph_sweep_move.md").write_text(
        _finding("DST-7", "Move state transition gap", loc="sources/module.move:L22"),
        encoding="utf-8",
    )
    _manifest(tmp_path, "inventory_chunk_a", "analysis_evm_flow.md")
    _manifest(tmp_path, "inventory_chunk_b", "graph_sweep_move.md")
    _chunk(tmp_path, "inventory_chunk_a", [("CC-1", "EVM flow mismatch", ("TF-1",))])
    _chunk(tmp_path, "inventory_chunk_b", [("CC-2", "Move state transition gap", ("DST-7",))])
    _inventory(
        tmp_path,
        [
            ("INV-001", "EVM flow mismatch", ("TF-1", "CC-1")),
            ("INV-002", "Move state transition gap", ("DST-7", "CC-2")),
        ],
    )

    receipt = write_inventory_reconciliation(tmp_path)

    assert receipt["summary"] == {
        "AUTHORIZED_MERGE": 0,
        "AUTHORIZED_REFUTATION": 0,
        "HUMAN_REVIEW_DEBT": 0,
        "RETAINED": 2,
        "TOTAL": 2,
    }
    assert receipt["registry_debt_count"] == 0
    assert {
        row["registry_status"] for row in receipt["source_artifacts"]
    } == {"REGISTERED"}
    assert validate_inventory_reconciliation(tmp_path) == []
    assert V._validate_inventory_parity(tmp_path) == []


def test_inventory_reconciliation_has_registered_driver_only_phase_io(
    tmp_path: Path,
) -> None:
    _one_retained_candidate(tmp_path)
    receipt = write_inventory_reconciliation(tmp_path)
    inputs = D._inventory_reconciliation_input_paths(tmp_path, receipt)
    contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="inventory",
        work_unit_id="exact_reconciliation",
        exact_inputs=inputs,
    )
    assert contract.model_invoked is False
    assert set(contract.immutable_inputs) == {
        f"scratchpad:{path}" for path in inputs
    }
    assert {item.identity for item in contract.outputs} == {
        "scratchpad:inventory_reconciliation.json",
        "scratchpad:inventory_reconciliation_human_review.md",
    }
    assert {item.writer for item in contract.outputs} == {"DRIVER"}


def test_inventory_reconciliation_phase_io_binds_and_resume_detects_source_drift(
    tmp_path: Path,
) -> None:
    run_id = "23456789-1234-4234-8234-123456789abc"
    project = tmp_path / "project"
    sp = project / ".scratchpad"
    sp.mkdir(parents=True)
    _one_retained_candidate(sp)
    assert V._validate_inventory_parity(sp) == []
    Checkpoint(run_id=run_id).save(sp)
    config = {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "project_root": str(project),
        "_run_id": run_id,
    }
    _activate_canonical_inventory(project, sp, config)
    assert V._validate_inventory_parity(sp) == []
    phase = next(item for item in SC_PHASES if item.name == "inventory")
    assert D._record_inventory_reconciliation_phase_io(
        scratchpad=sp,
        config=config,
        phase=phase,
    ) == []
    assert D._validate_inventory_reconciliation_phase_io(
        scratchpad=sp,
        project_root=project,
        phase_name="inventory",
        mode="thorough",
        language="evm",
        pipeline="sc",
        backend="claude",
        timeout_s=phase.base_timeout_s,
    ) == []
    ledger = read_artifact_ledger(sp)
    unit = ledger["work_units"][
        "sc/thorough/evm/claude/inventory/exact_reconciliation"
    ]
    assert set(unit["artifacts"]) == {
        "scratchpad:inventory_reconciliation.json",
        "scratchpad:inventory_reconciliation_human_review.md",
    }
    assert "scratchpad:analysis_evm_flow.md" in unit["input_bindings"]
    with (sp / "analysis_evm_flow.md").open("ab") as handle:
        handle.write(b"\ncurrent source drift\n")
    issues = D._validate_inventory_reconciliation_phase_io(
        scratchpad=sp,
        project_root=project,
        phase_name="inventory",
        mode="thorough",
        language="evm",
        pipeline="sc",
        backend="claude",
        timeout_s=phase.base_timeout_s,
    )
    assert issues
    assert any("differ" in issue.lower() or "drift" in issue.lower() for issue in issues)


def test_unresolved_inventory_candidate_is_projected_as_recall_limitation(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    sp = project / ".scratchpad"
    sp.mkdir(parents=True)
    (sp / "analysis_evm_flow.md").write_text(
        _finding("TF-1", "Generic flow mismatch")
        + _finding("TF-2", "Generic sibling mismatch"),
        encoding="utf-8",
    )
    _manifest(sp, "inventory_chunk_a", "analysis_evm_flow.md")
    _chunk(
        sp,
        "inventory_chunk_a",
        [("CC-1", "Generic flow mismatch", ("TF-1",))],
    )
    _inventory(
        sp,
        [("INV-001", "Generic flow mismatch", ("TF-1", "CC-1"))],
    )
    receipt = write_inventory_reconciliation(sp)
    assert receipt["summary"]["HUMAN_REVIEW_DEBT"] == 1
    checkpoint = Checkpoint(
        run_id="3456789a-1234-4234-8234-123456789abc"
    )
    manifest = build_current_assurance_manifest(checkpoint, sp, project)
    rows = [
        row for row in manifest["rows"]
        if row["gate_id"] == "inventory_candidate_unresolved"
    ]
    assert len(rows) == 1
    assert rows[0]["assurance_impact"] == "DISCOVERY_RECALL"
    assert rows[0]["affected_identities"] == ["TF-2"]
    assert manifest["clean_full_audit_claim_allowed"] is False


@pytest.mark.parametrize("total,omitted", [(100, 1), (100, 54)])
def test_any_omitted_identity_is_debt_never_threshold_accepted(
    tmp_path: Path, total: int, omitted: int
) -> None:
    source = "".join(_finding(f"TF-{i}", f"candidate {i}") for i in range(1, total + 1))
    (tmp_path / "analysis_evm_flow.md").write_text(source, encoding="utf-8")
    _manifest(tmp_path, "inventory_chunk_a", "analysis_evm_flow.md")
    kept = total - omitted
    _chunk(
        tmp_path,
        "inventory_chunk_a",
        [(f"CC-{i}", f"candidate {i}", (f"TF-{i}",)) for i in range(1, kept + 1)],
    )
    _inventory(
        tmp_path,
        [(f"INV-{i:03d}", f"candidate {i}", (f"TF-{i}", f"CC-{i}")) for i in range(1, kept + 1)],
    )

    receipt = write_inventory_reconciliation(tmp_path)

    assert receipt["summary"]["HUMAN_REVIEW_DEBT"] == omitted
    assert receipt["summary"]["RETAINED"] == kept
    limitations = (tmp_path / "inventory_reconciliation_human_review.md").read_text(
        encoding="utf-8"
    )
    assert f"### Finding [TF-{total}]" in limitations
    issues = V._validate_inventory_parity(tmp_path)
    assert any("NEEDS_INVENTORY_REVIEW" in issue for issue in issues)
    _apply_inventory_reemit_repair_for_tests(tmp_path)
    repaired = reconcile_inventory(tmp_path)
    assert repaired["summary"]["HUMAN_REVIEW_DEBT"] == 0
    reemit = json.loads(
        (tmp_path / "inventory_reemit_receipt.json").read_text(encoding="utf-8")
    )
    assert len(reemit["rows"]) == omitted


def test_many_to_one_merge_requires_and_preserves_full_alias_union(tmp_path: Path) -> None:
    (tmp_path / "analysis_evm_a.md").write_text(_finding("TF-1", "shared mechanism A"), encoding="utf-8")
    (tmp_path / "analysis_evm_b.md").write_text(_finding("RSW-2", "shared mechanism B"), encoding="utf-8")
    _manifest(tmp_path, "inventory_chunk_a", "analysis_evm_a.md", "analysis_evm_b.md")
    _chunk(
        tmp_path,
        "inventory_chunk_a",
        [("CC-1", "shared mechanism", ("TF-1", "RSW-2"))],
    )
    _inventory(tmp_path, [("INV-001", "shared mechanism", ("TF-1", "RSW-2", "CC-1"))])
    inventory_path = tmp_path / "findings_inventory.md"
    inventory_path.write_text(
        inventory_path.read_text(encoding="utf-8").replace(
            "**Root Cause**: mechanism for shared mechanism\n",
            "**Root Cause**: mechanism for shared mechanism A | "
            "mechanism for shared mechanism B\n",
        ).replace(
            "**Impact**: material effect for shared mechanism\n",
            "**Impact**: material effect for shared mechanism A | "
            "material effect for shared mechanism B\n",
        ),
        encoding="utf-8",
    )

    receipt = write_inventory_reconciliation(tmp_path)

    assert receipt["summary"]["HUMAN_REVIEW_DEBT"] == 2
    assert {row["target_inventory_id"] for row in receipt["candidates"]} == {""}
    assert all(
        row["reason_code"] == "MULTI_SOURCE_COLLAPSE_REQUIRES_EQUIVALENCE"
        for row in receipt["candidates"]
    )
    review = (tmp_path / "inventory_reconciliation_human_review.md").read_text(
        encoding="utf-8"
    )
    assert review.count("mechanism for shared mechanism A") == 1
    assert review.count("mechanism for shared mechanism B") == 1
    assert all(row["proposed_target_finding_id"] == "INV-001" for row in receipt["candidates"])
    assert all(row["proposed_target_block_sha256"] for row in receipt["candidates"])


def test_bare_summary_mention_does_not_count_as_retained_block(tmp_path: Path) -> None:
    (tmp_path / "analysis_evm_flow.md").write_text(_finding("TF-1", "omitted body"), encoding="utf-8")
    _manifest(tmp_path, "inventory_chunk_a", "analysis_evm_flow.md")
    (tmp_path / "findings_inventory_chunk_a.md").write_text(
        "# Inventory Chunk\n\n| Source ID | Disposition |\n|---|---|\n| TF-1 | retained |\n",
        encoding="utf-8",
    )
    _inventory(
        tmp_path,
        [],
        suffix="| Source ID | Disposition |\n|---|---|\n| TF-1 | retained |\n",
    )

    receipt = write_inventory_reconciliation(tmp_path)

    assert receipt["summary"]["HUMAN_REVIEW_DEBT"] == 1
    assert receipt["candidates"][0]["reason_code"] == "MISSING_CHUNK_DISPOSITION"


def test_one_to_one_source_id_cannot_hide_semantic_drift(tmp_path: Path) -> None:
    (tmp_path / "analysis_evm_flow.md").write_text(
        _finding("TF-1", "source mechanism"), encoding="utf-8"
    )
    _manifest(tmp_path, "inventory_chunk_a", "analysis_evm_flow.md")
    _chunk(tmp_path, "inventory_chunk_a", [("CC-1", "source mechanism", ("TF-1",))])
    _inventory(tmp_path, [("INV-001", "rewritten mechanism", ("TF-1", "CC-1"))])

    receipt = write_inventory_reconciliation(tmp_path)

    row = receipt["candidates"][0]
    assert row["disposition"] == "HUMAN_REVIEW_DEBT"
    assert row["reason_code"] == "FINAL_SEMANTIC_PRESERVATION_DEBT"
    assert set(row["required_preservation_axes"]) == {"ROOT_CAUSE", "IMPACT"}
    assert row["proposed_target_finding_id"] == "INV-001"
    review = (tmp_path / "inventory_reconciliation_human_review.md").read_text(
        encoding="utf-8"
    )
    assert "mechanism for source mechanism" in review
    assert "material effect for source mechanism" in review


def test_chunk_source_id_cannot_hide_semantic_drift(tmp_path: Path) -> None:
    (tmp_path / "analysis_evm_flow.md").write_text(
        _finding("TF-1", "source mechanism"), encoding="utf-8"
    )
    _manifest(tmp_path, "inventory_chunk_a", "analysis_evm_flow.md")
    _chunk(tmp_path, "inventory_chunk_a", [("CC-1", "rewritten mechanism", ("TF-1",))])

    receipt = write_inventory_reconciliation(
        tmp_path, phase_name="inventory_chunk_a"
    )

    row = receipt["candidates"][0]
    assert row["disposition"] == "HUMAN_REVIEW_DEBT"
    assert row["reason_code"] == "CHUNK_SEMANTIC_PRESERVATION_DEBT"
    assert set(row["required_preservation_axes"]) == {"ROOT_CAUSE", "IMPACT"}


@pytest.mark.parametrize("evidence_scope", ["IN_SCOPE_SOURCE", "IN_SCOPE_EXECUTION"])
def test_source_bound_negative_evidence_is_supporting_only(
    tmp_path: Path,
    evidence_scope: str,
) -> None:
    (tmp_path / "graph_sweep_move.md").write_text(
        _finding("DST-7", "candidate to refute", loc="sources/m.move:L7"), encoding="utf-8"
    )
    _manifest(tmp_path, "inventory_chunk_a", "graph_sweep_move.md")
    (tmp_path / "findings_inventory_chunk_a.md").write_text("# no retained finding\n", encoding="utf-8")
    _inventory(tmp_path, [])

    preliminary = reconcile_inventory(tmp_path, persist=False)
    candidate = preliminary["candidates"][0]
    evidence = {
        "schema_version": NEGATIVE_EVIDENCE_SCHEMA,
        "provider_id": "source-reviewer",
        "records": [
            {
                "record_id": "NEG-1",
                "candidate_key": candidate["candidate_key"],
                "source_artifact": "graph_sweep_move.md",
                "source_sha256": _sha(tmp_path / "graph_sweep_move.md"),
                "source_finding_id": "DST-7",
                "source_block_sha256": candidate["source_block_sha256"],
                "verdict": "REFUTED",
                "evidence_scope": evidence_scope,
                "proof_scope": "HARM",
                "evidence_pointer": "sources/m.move:L7",
                "evidence_digest": hashlib.sha256(b"independent source trace").hexdigest(),
            }
        ],
    }
    (tmp_path / "inventory_negative_evidence.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    _authority(
        tmp_path,
        source="graph_sweep_move.md",
        source_id="DST-7",
        disposition="SUPPORTED_REFUTATION",
        evidence_file="inventory_negative_evidence.json",
        evidence_record_id="NEG-1",
    )

    receipt = write_inventory_reconciliation(tmp_path)

    assert receipt["summary"]["AUTHORIZED_REFUTATION"] == 0
    assert receipt["summary"]["HUMAN_REVIEW_DEBT"] == 1
    assert receipt["candidates"][0]["reason_code"] == "INVALID_REFUTATION_AUTHORITY"
    assert any(
        "NEEDS_INVENTORY_REVIEW" in issue
        for issue in V._validate_inventory_parity(tmp_path)
    )
    _apply_inventory_reemit_repair_for_tests(tmp_path)
    assert reconcile_inventory(tmp_path)["summary"]["HUMAN_REVIEW_DEBT"] == 0


def test_refutation_without_authority_stays_debt(tmp_path: Path) -> None:
    (tmp_path / "analysis_evm_flow.md").write_text(_finding("TF-1", "unsafe negative"), encoding="utf-8")
    _manifest(tmp_path, "inventory_chunk_a", "analysis_evm_flow.md")
    (tmp_path / "findings_inventory_chunk_a.md").write_text(
        "# Chunk\n\n| Source ID | Verdict |\n|---|---|\n| TF-1 | REFUTED |\n", encoding="utf-8"
    )
    _inventory(tmp_path, [])

    receipt = write_inventory_reconciliation(tmp_path)

    assert receipt["summary"]["HUMAN_REVIEW_DEBT"] == 1
    assert receipt["candidates"][0]["disposition"] == "HUMAN_REVIEW_DEBT"


def test_structural_merge_label_requires_applied_equivalence_authority(tmp_path: Path) -> None:
    (tmp_path / "analysis_evm_flow.md").write_text(
        _finding("TF-1", "authorized alias"), encoding="utf-8"
    )
    _manifest(tmp_path, "inventory_chunk_a", "analysis_evm_flow.md")
    (tmp_path / "findings_inventory_chunk_a.md").write_text("# no retained finding\n", encoding="utf-8")
    _inventory(tmp_path, [("INV-001", "canonical mechanism", ("OTHER-1",))])
    _authority(
        tmp_path,
        source="analysis_evm_flow.md",
        source_id="TF-1",
        disposition="MERGED_ALIAS",
        target="INV-001",
    )

    receipt = write_inventory_reconciliation(tmp_path)

    assert receipt["summary"]["AUTHORIZED_MERGE"] == 0
    assert receipt["summary"]["HUMAN_REVIEW_DEBT"] == 1
    assert receipt["candidates"][0]["target_inventory_id"] == ""
    assert receipt["candidates"][0]["reason_code"] == (
        "MERGE_REQUIRES_APPLIED_EQUIVALENCE_AUTHORITY"
    )
    assert any(
        "NEEDS_INVENTORY_REVIEW" in issue
        for issue in V._validate_inventory_parity(tmp_path)
    )
    _apply_inventory_reemit_repair_for_tests(tmp_path)
    assert reconcile_inventory(tmp_path)["summary"]["HUMAN_REVIEW_DEBT"] == 0


def test_malformed_chunk_preserves_raw_content_as_debt(tmp_path: Path) -> None:
    raw = _finding("TF-9", "raw content survives")
    (tmp_path / "analysis_evm_flow.md").write_text(raw, encoding="utf-8")
    _manifest(tmp_path, "inventory_chunk_a", "analysis_evm_flow.md")
    (tmp_path / "findings_inventory_chunk_a.md").write_bytes(b"\xff\xfe\x00broken")
    _inventory(tmp_path, [])

    receipt = write_inventory_reconciliation(tmp_path)

    assert receipt["summary"]["HUMAN_REVIEW_DEBT"] == 1
    assert "raw content survives" in (
        tmp_path / "inventory_reconciliation_human_review.md"
    ).read_text(encoding="utf-8")
    assert receipt["artifact_issues"]


def test_chunk_gate_reconciles_every_assigned_raw_identity_before_final_merge(
    tmp_path: Path,
) -> None:
    (tmp_path / "analysis_evm_flow.md").write_text(
        _finding("TF-1", "retained") + _finding("TF-2", "omitted"),
        encoding="utf-8",
    )
    _manifest(tmp_path, "inventory_chunk_a", "analysis_evm_flow.md")
    _chunk(tmp_path, "inventory_chunk_a", [("CC-1", "retained", ("TF-1",))])

    issues = V._validate_inventory_chunk_structure(
        tmp_path, "inventory_chunk_a"
    )

    assert any("exact reconciliation" in issue and "1/2" in issue for issue in issues)
    config = {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "project_root": str(tmp_path),
        "_run_id": "34567891-1234-4234-8234-123456789abc",
    }
    _activate_chunk_model(tmp_path, tmp_path, config)
    assert D._record_inventory_reconciliation_phase_io_named(
        scratchpad=tmp_path,
        config=config,
        phase_name="inventory_chunk_a",
        timeout_s=30,
    ) == []
    receipt = json.loads(
        (tmp_path / "inventory_chunk_a.reconciliation.json").read_text(
            encoding="utf-8"
        )
    )
    assert receipt["summary"]["RETAINED"] == 1
    assert receipt["summary"]["HUMAN_REVIEW_DEBT"] == 1
    assert "### Finding [TF-2]" in (
        tmp_path / "inventory_chunk_a.human_review.md"
    ).read_text(encoding="utf-8")


def test_stale_source_hash_invalidates_authority_toward_debt(tmp_path: Path) -> None:
    source = tmp_path / "analysis_evm_flow.md"
    source.write_text(_finding("TF-1", "first version"), encoding="utf-8")
    _manifest(tmp_path, "inventory_chunk_a", source.name)
    (tmp_path / "findings_inventory_chunk_a.md").write_text("# empty\n", encoding="utf-8")
    _inventory(tmp_path, [("INV-001", "merge target", ("OTHER-1",))])
    _authority(
        tmp_path,
        source=source.name,
        source_id="TF-1",
        disposition="MERGED_ALIAS",
        target="INV-001",
    )
    source.write_text(_finding("TF-1", "changed version"), encoding="utf-8")

    receipt = write_inventory_reconciliation(tmp_path)

    assert receipt["summary"]["HUMAN_REVIEW_DEBT"] == 1
    assert receipt["candidates"][0]["reason_code"] in {
        "STALE_DISPOSITION_AUTHORITY",
        "MISSING_CHUNK_DISPOSITION",
    }


def test_resume_is_byte_idempotent_and_tamper_is_recomputed(tmp_path: Path) -> None:
    (tmp_path / "analysis_evm_flow.md").write_text(_finding("TF-1", "stable"), encoding="utf-8")
    _manifest(tmp_path, "inventory_chunk_a", "analysis_evm_flow.md")
    _chunk(tmp_path, "inventory_chunk_a", [("CC-1", "stable", ("TF-1",))])
    _inventory(tmp_path, [("INV-001", "stable", ("TF-1", "CC-1"))])

    write_inventory_reconciliation(tmp_path)
    receipt_path = tmp_path / "inventory_reconciliation.json"
    debt_path = tmp_path / "inventory_reconciliation_human_review.md"
    first = (receipt_path.read_bytes(), debt_path.read_bytes())
    write_inventory_reconciliation(tmp_path)
    assert first == (receipt_path.read_bytes(), debt_path.read_bytes())

    payload = json.loads(receipt_path.read_text(encoding="utf-8"))
    payload["summary"]["RETAINED"] = 999
    receipt_path.write_text(json.dumps(payload), encoding="utf-8")
    assert validate_inventory_reconciliation(tmp_path)
    write_inventory_reconciliation(tmp_path)
    assert validate_inventory_reconciliation(tmp_path) == []


def test_shard_plan_hash_drift_invalidates_receipt_and_reopens_denominator(
    tmp_path: Path,
) -> None:
    (tmp_path / "analysis_evm_flow.md").write_text(
        _finding("TF-1", "first"), encoding="utf-8"
    )
    (tmp_path / "graph_sweep_move.md").write_text(
        _finding("DST-7", "late plan row", loc="sources/m.move:L9"),
        encoding="utf-8",
    )
    _manifest(tmp_path, "inventory_chunk_a", "analysis_evm_flow.md")
    _chunk(tmp_path, "inventory_chunk_a", [("CC-1", "first", ("TF-1",))])
    _inventory(tmp_path, [("INV-001", "first", ("TF-1", "CC-1"))])
    first = write_inventory_reconciliation(tmp_path)
    first_manifest_hash = first["manifest_artifacts"][0]["sha256"]

    _manifest(
        tmp_path,
        "inventory_chunk_a",
        "analysis_evm_flow.md",
        "graph_sweep_move.md",
    )

    assert validate_inventory_reconciliation(tmp_path)
    second = write_inventory_reconciliation(tmp_path)
    assert second["manifest_artifacts"][0]["sha256"] != first_manifest_hash
    assert second["summary"]["TOTAL"] == 2
    assert second["summary"]["HUMAN_REVIEW_DEBT"] == 1


def test_empty_audit_is_exact_clean_path(tmp_path: Path) -> None:
    _inventory(tmp_path, [])

    receipt = write_inventory_reconciliation(tmp_path)

    assert receipt["summary"]["TOTAL"] == 0
    assert receipt["summary"]["HUMAN_REVIEW_DEBT"] == 0
    assert V._validate_inventory_parity(tmp_path) == []
