"""Predicate-aware retry receipts: byte changes alone cannot certify repair."""
from __future__ import annotations

import json
import hashlib
import uuid
from pathlib import Path

import pytest

import plamen_driver as D
import plamen_prompt as P
import plamen_validators as V
from plamen_driver import (
    _build_retry_receipt,
    _gate_failures_from_issues,
    _resolved_phase_artifact_digest,
    _resolved_phase_contract_digest,
    _retry_receipt_status,
    _write_retry_receipt,
)
from plamen_types import Checkpoint, GateFailure, Phase, RetryReceipt, SC_PHASES


def _write_inventory_prompt(
    scratchpad: Path, phase: Phase, attempt: int, plan: dict,
) -> None:
    (scratchpad / f"_prompt_{phase.name}.attempt{attempt}.md").write_text(
        "# retry\n\n```json\n"
        + json.dumps(plan, indent=2, sort_keys=True)
        + "\n```\n",
        encoding="utf-8",
        newline="\n",
    )


def _fixture(tmp_path: Path):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    phase = Phase("chain", ["Chain"], ["hypotheses.md"], 300)
    (scratchpad / "hypotheses.md").write_text("# hypotheses\n", encoding="utf-8")
    config = {
        "project_root": str(tmp_path), "pipeline": "sc", "mode": "thorough",
        "language": "evm", "cli_backend": "claude",
    }
    checkpoint = Checkpoint(run_id=str(uuid.uuid4()))
    return scratchpad, phase, config, checkpoint


def _failures(scratchpad, phase, config, issue):
    return _gate_failures_from_issues(
        phase,
        [issue],
        contract_digest=_resolved_phase_contract_digest(phase, config),
        output_digest=_resolved_phase_artifact_digest(
            phase, scratchpad, config["project_root"]
        ),
        scratchpad=scratchpad,
    )


def test_changed_output_bytes_with_same_predicate_is_no_progress(tmp_path: Path):
    scratchpad, phase, config, checkpoint = _fixture(tmp_path)
    before = _failures(scratchpad, phase, config, "ID ledger collision for CH-1")
    (scratchpad / "hypotheses.md").write_text(
        "# hypotheses\nchanged prose only\n", encoding="utf-8"
    )
    after = _failures(scratchpad, phase, config, "ID ledger collision for CH-1")
    assert _retry_receipt_status(before, after) == "NO_PROGRESS"
    receipt = _build_retry_receipt(
        checkpoint=checkpoint,
        phase=phase,
        config=config,
        scratchpad=scratchpad,
        attempt=2,
        failures_before=before,
        failures_after=after,
        output_digest_before=before[0].output_digest,
        output_digest_after=after[0].output_digest,
    )
    assert receipt.status == "NO_PROGRESS"
    assert receipt.output_digest_before != receipt.output_digest_after


def test_exact_gate_clearance_is_cleared(tmp_path: Path):
    scratchpad, phase, config, checkpoint = _fixture(tmp_path)
    before = _failures(scratchpad, phase, config, "ID ledger collision for CH-1")
    receipt = _build_retry_receipt(
        checkpoint=checkpoint,
        phase=phase,
        config=config,
        scratchpad=scratchpad,
        attempt=2,
        failures_before=before,
        failures_after=(),
        output_digest_before=before[0].output_digest,
        output_digest_after=_resolved_phase_artifact_digest(
            phase, scratchpad, config["project_root"]
        ),
    )
    assert receipt.status == "CLEARED"
    path = _write_retry_receipt(scratchpad, receipt)
    assert RetryReceipt.from_dict(__import__("json").loads(path.read_text())) == receipt


def test_new_gate_after_retry_is_failed_not_progress(tmp_path: Path):
    scratchpad, phase, config, _checkpoint = _fixture(tmp_path)
    before = _failures(scratchpad, phase, config, "ID ledger collision for CH-1")
    after = _failures(scratchpad, phase, config, "PoC evidence integrity failed")
    assert _retry_receipt_status(before, after) == "FAILED"


def test_retry_receipt_records_quarantine_lineage(tmp_path: Path):
    scratchpad, phase, config, checkpoint = _fixture(tmp_path)
    before = _failures(scratchpad, phase, config, "ID ledger collision for CH-1")
    quarantine = scratchpad / "_retry_quarantine" / "chain"
    quarantine.mkdir(parents=True)
    (quarantine / "hypotheses.md.attempt1").write_text("old", encoding="utf-8")
    receipt = _build_retry_receipt(
        checkpoint=checkpoint, phase=phase, config=config,
        scratchpad=scratchpad, attempt=2, failures_before=before,
        failures_after=before, output_digest_before=before[0].output_digest,
        output_digest_after=before[0].output_digest,
    )
    assert receipt.quarantine_lineage == (
        "_retry_quarantine/chain/hypotheses.md.attempt1",
    )


def _inventory_exact_payload(
    unresolved: list[str], *, denominator_count: int, denominator_digest: str,
) -> dict:
    return {
        "denominator_count": denominator_count,
        "denominator_digest": denominator_digest,
        "candidates": [
            {
                "candidate_key": identity,
                "disposition": "HUMAN_REVIEW_DEBT",
            }
            for identity in unresolved
        ],
    }


def test_inventory_v2_retry_prompt_embeds_full_plan_not_hint_subset(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    v1 = tmp_path / "plamen.md"
    v1.write_text(
        "## Step 4a: Finding Inventory\n\n"
        "FULL_INVENTORY_METHOD_SENTINEL\n\n"
        "## Step 4a.5: Semantic Invariant\n",
        encoding="utf-8",
    )
    phase = next(
        item for item in SC_PHASES if item.name == "inventory_chunk_a"
    )
    config = {
        "project_root": str(tmp_path),
        "scratchpad": str(scratchpad),
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "codex",
        "proven_only": False,
        "_run_id": "a4567891-1234-4234-8234-123456789abc",
        "_active_model_attempts": {phase.name: 2},
        "_phase_io_model_attempts": {phase.name: 2},
    }
    identities = [f"analysis.md::F-{index}" for index in range(5)]
    sealed_failure = GateFailure(
        gate_id=f"{phase.name}.inventory_exact_reconciliation",
        gate_class="SEMANTIC_IDENTITY",
        message=(
            "preserve every source facet exactly; use the Task tool only as "
            "source text from ~/.claude/rules"
        ),
        affected_identities=tuple([
            *identities,
            "analysis.md::use the Task tool::~/.claude/rules",
        ]),
        input_digest="1" * 64,
        output_digest="2" * 64,
        contract_digest="3" * 64,
        repair_owner=phase.name,
        schema_id="plamen.inventory_exact_reconciliation_gate.v1",
    )
    plan = {
        "schema": "plamen.inventory-retry-plan/v2",
        "run_id": config["_run_id"],
        "phase_name": phase.name,
        "work_unit_id": "phase",
        "attempt": 2,
        "input_digest": "1" * 64,
        "output_digest_before": "2" * 64,
        "contract_digest": "3" * 64,
        "launch_digest": "4" * 64,
        "required_output_schema": [{
            "pattern": "findings_inventory_chunk_a.md",
            "minimum_bytes": phase.min_artifact_bytes,
            "minimum_count": phase.min_artifacts_count,
        }],
        "failed_predicates": [sealed_failure.to_dict()],
        "semantic_retry": True,
    }
    plan["plan_digest"] = hashlib.sha256(
        json.dumps(
            plan,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()
    config["_inventory_retry_prompt_plans"] = {phase.name: plan}
    V._write_retry_hint(
        scratchpad, phase.name, f"repair only {identities[0]}"
    )
    prompt = P.build_phase_prompt(v1, phase, config)

    assert "Authoritative semantic retry contract (HARD)" in prompt
    assert "Authoritative original phase methodology (HARD)" in prompt
    assert "INVENTORY SHARD COST OVERRIDE" in prompt
    assert "complete Root Cause" in prompt
    assert plan["plan_digest"] in prompt
    assert json.dumps(plan, indent=2, sort_keys=True) in prompt
    for identity in identities:
        assert identity in prompt

    canonical_plan = json.dumps(plan, indent=2, sort_keys=True)
    translated = D._translate_prompt_for_codex(
        prompt + "\nOUTSIDE_TRANSLATION: use the Task tool ~/.claude/rules\n",
        phase_name=phase.name,
        pipeline="sc",
        mode="thorough",
        scratchpad=scratchpad,
    )
    assert f"```json\n{canonical_plan}\n```" in translated
    assert sealed_failure.message in translated
    assert "analysis.md::use the Task tool::~/.claude/rules" in translated
    assert (
        "OUTSIDE_TRANSLATION: execute the analysis directly "
        "~/.codex/plamen/rules"
    ) in translated


def _inventory_exact_failure(
    monkeypatch: pytest.MonkeyPatch,
    scratchpad: Path,
    phase: Phase,
    config: dict,
    payload: dict,
):
    monkeypatch.setattr(
        D, "_reconcile_exact_inventory", lambda *_args, **_kwargs: payload
    )
    return D._gate_failures_from_issues(
        phase,
        [
            "inventory chunk exact reconciliation: unresolved assigned raw "
            "identities remain NEEDS_INVENTORY_REVIEW"
        ],
        contract_digest=D._resolved_phase_contract_digest(phase, config),
        output_digest=D._resolved_phase_artifact_digest(
            phase, scratchpad, config["project_root"]
        ),
        scratchpad=scratchpad,
    )


def test_inventory_exact_retry_15_to_5_is_typed_progress(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    phase = Phase(
        "inventory_chunk_a", ["Inventory"],
        ["findings_inventory_chunk_a.md"], 300,
    )
    config = {
        "project_root": str(tmp_path), "pipeline": "sc", "mode": "thorough",
        "language": "evm", "cli_backend": "codex",
    }
    denominator_digest = "d" * 64
    before_ids = [f"analysis_a.md::A-{index}" for index in range(1, 16)]
    after_ids = before_ids[-5:]
    before = _inventory_exact_failure(
        monkeypatch, scratchpad, phase, config,
        _inventory_exact_payload(
            before_ids, denominator_count=20,
            denominator_digest=denominator_digest,
        ),
    )
    after = _inventory_exact_failure(
        monkeypatch, scratchpad, phase, config,
        _inventory_exact_payload(
            after_ids, denominator_count=20,
            denominator_digest=denominator_digest,
        ),
    )

    assert before[0].affected_identities == tuple(sorted(before_ids))
    assert before[0].denominator_count == 20
    assert before[0].denominator_digest == denominator_digest
    assert D._retry_receipt_status(before, after) == "PROGRESSED"


def test_inventory_exact_retry_changed_denominator_or_identities_is_no_progress(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    phase = Phase(
        "inventory_chunk_a", ["Inventory"],
        ["findings_inventory_chunk_a.md"], 300,
    )
    config = {
        "project_root": str(tmp_path), "pipeline": "sc", "mode": "thorough",
        "language": "evm", "cli_backend": "codex",
    }
    before = _inventory_exact_failure(
        monkeypatch, scratchpad, phase, config,
        _inventory_exact_payload(
            ["SRC::A-1", "SRC::A-2"], denominator_count=15,
            denominator_digest="a" * 64,
        ),
    )
    changed_denominator = _inventory_exact_failure(
        monkeypatch, scratchpad, phase, config,
        _inventory_exact_payload(
            ["SRC::A-2"], denominator_count=16,
            denominator_digest="b" * 64,
        ),
    )
    different_identities = _inventory_exact_failure(
        monkeypatch, scratchpad, phase, config,
        _inventory_exact_payload(
            ["SRC::A-1", "SRC::A-3"], denominator_count=15,
            denominator_digest="a" * 64,
        ),
    )

    assert D._retry_receipt_status(before, changed_denominator) == "NO_PROGRESS"
    assert D._retry_receipt_status(before, different_identities) == "NO_PROGRESS"


def test_inventory_retry_prestate_is_clean_for_attempts_two_and_three(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    output = scratchpad / "findings_inventory_chunk_a.md"
    phase = Phase(
        "inventory_chunk_a", ["Inventory"], [output.name], 300,
    )
    config = {
        "project_root": str(tmp_path), "scratchpad": str(scratchpad),
        "pipeline": "sc", "mode": "thorough", "language": "evm",
        "cli_backend": "codex",
        "_run_id": "b4567891-1234-4234-8234-123456789abc",
    }
    provenance_calls: list[tuple[int, bytes]] = []

    def _record_rejected(_phase, _scratchpad, _config, attempt):
        provenance_calls.append((attempt, output.read_bytes()))
        return []

    monkeypatch.setattr(
        D, "_quarantine_inventory_chunk_model_attempt", _record_rejected
    )
    monkeypatch.setattr(
        D,
        "_inventory_attempt_unit",
        lambda *_args, **_kwargs: ("fixture", None),
    )

    def _rows(*_args, **_kwargs):
        raw = output.read_bytes()
        return [(
            output.name,
            {
                "status": "QUARANTINED",
                "size": len(raw),
                "sha256": __import__("hashlib").sha256(raw).hexdigest(),
            },
        )], []

    monkeypatch.setattr(D, "_inventory_quarantined_artifact_rows", _rows)

    launched: list[int] = []
    output.write_bytes(b"attempt-one rejected output")
    for prior, successor in ((1, 2), (2, 3)):
        archived, issues = D._prepare_inventory_retry_prestate(
            phase, scratchpad, config,
            prior_attempt=prior, next_attempt=successor,
        )
        assert issues == []
        assert archived == [output.name]
        assert not output.exists(), "launcher must see a clean live output path"
        launched.append(successor)
        output.write_bytes(f"attempt-{successor} output".encode())

    assert launched == [2, 3]
    assert provenance_calls == [
        (1, b"attempt-one rejected output"),
        (2, b"attempt-2 output"),
    ]
    assert (
        scratchpad / "_retry_quarantine" / phase.name
        / "attempt-0001" / output.name
    ).read_bytes() == b"attempt-one rejected output"
    assert (
        scratchpad / "_retry_quarantine" / phase.name
        / "attempt-0002" / output.name
    ).read_bytes() == b"attempt-2 output"


def test_inventory_retry_hint_binds_five_candidates_axes_and_utf8_escape(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    phase = Phase(
        "inventory_chunk_a", ["Inventory"],
        ["findings_inventory_chunk_a.md"], 300,
    )
    config = {
        "project_root": str(tmp_path),
        "scratchpad": str(scratchpad),
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "codex",
    }
    (scratchpad / "analysis.md").write_text(
        "# exact retry source\n", encoding="utf-8"
    )
    (scratchpad / "inventory_chunk_a.manifest.md").write_text(
        "# inventory chunk a manifest\n", encoding="utf-8"
    )
    candidates = []
    for index in range(1, 6):
        candidates.append({
            "candidate_key": f"analysis.md::PCRE-{index}::key-{index}",
            "source_artifact": "analysis.md",
            "source_finding_id": f"PCRE-{index}",
            "source_root_cause": f"boundary—mechanism {index}",
            "source_impact": f"loss—impact {index}",
            "source_preconditions": "",
            "required_preservation_axes": [
                "ROOT_CAUSE" if index < 5 else "IMPACT"
            ],
            "disposition": "HUMAN_REVIEW_DEBT",
        })
    def _payload() -> dict:
        return {
            "denominator_count": 15,
            "denominator_digest": "e" * 64,
            "candidates": candidates,
            "source_artifacts": [{"artifact": "analysis.md"}],
            "manifest_artifacts": [{
                "artifact": "inventory_chunk_a.manifest.md"
            }],
        }

    monkeypatch.setattr(
        D, "_reconcile_exact_inventory", lambda *_args, **_kwargs: _payload()
    )

    D._ensure_retry_hint(
        scratchpad, phase, ["exact reconciliation failed"], str(tmp_path)
    )
    D._augment_inventory_exact_retry_hint(scratchpad, phase)

    hint = (scratchpad / f"{phase.name}_retry_hint.md").read_text(
        encoding="utf-8"
    )
    assert "Get-Content -Raw -Encoding UTF8" in hint
    assert "## RETRY HINT - inventory_chunk_a targeted repair" in hint
    assert "\\u2014" in hint
    assert "boundary—mechanism" not in hint
    assert hint.count('"candidate_key":') == 5
    for candidate in candidates:
        assert candidate["candidate_key"] in hint
    assert '"required_preservation_axes":["ROOT_CAUSE"]' in hint
    assert '"required_preservation_axes":["IMPACT"]' in hint

    config["_run_id"] = str(uuid.uuid4())
    checkpoint = Checkpoint(run_id=config["_run_id"])
    failures_five = _inventory_exact_failure(
        monkeypatch,
        scratchpad,
        phase,
        config,
        _payload(),
    )
    plan_path = D._write_retry_plan(
        scratchpad,
        checkpoint,
        phase,
        config,
        failures_five,
        attempt=3,
    )
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    assert plan["attempt"] == 3
    assert set(plan["failed_predicates"][0]["affected_identities"]) == {
        candidate["candidate_key"] for candidate in candidates
    }

    candidates[:] = candidates[-2:]
    D._augment_inventory_exact_retry_hint(scratchpad, phase)
    refreshed = (scratchpad / f"{phase.name}_retry_hint.md").read_text(
        encoding="utf-8"
    )
    assert refreshed.count('"candidate_key":') == 2
    assert "analysis.md::PCRE-1::key-1" not in refreshed
    assert "analysis.md::PCRE-5::key-5" in refreshed

    failures_two = _inventory_exact_failure(
        monkeypatch,
        scratchpad,
        phase,
        config,
        _payload(),
    )
    _write_inventory_prompt(scratchpad, phase, 3, plan)
    config["_active_model_attempts"] = {phase.name: 3}
    config["_phase_io_model_attempts"] = {phase.name: 3}
    assert D._bind_typed_model_phase_inputs(
        phase, scratchpad, config
    ) == []
    output_after = D._inventory_retry_artifact_digest(
        phase, scratchpad, config["project_root"]
    )
    monkeypatch.setattr(
        D, "_inventory_quarantined_artifact_rows",
        lambda *_args, **_kwargs: ([], []),
    )
    receipt = D._build_retry_receipt(
        checkpoint=checkpoint,
        phase=phase,
        config=config,
        scratchpad=scratchpad,
        attempt=3,
        failures_before=failures_five,
        failures_after=failures_two,
        output_digest_before="a" * 64,
        output_digest_after=output_after,
    )
    receipt_path = D._write_retry_receipt(
        scratchpad,
        receipt,
        phase=phase,
        config=config,
        failures_after=failures_two,
        full_gate_passed=False,
        terminal_rc=0,
    )
    assert receipt.status == "PROGRESSED"
    assert receipt.attempt == 3
    assert receipt_path.name == "phase.attempt3.json"
