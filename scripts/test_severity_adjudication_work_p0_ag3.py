"""Fixture-first contracts for driver-neutral severity adjudication work.

These tests deliberately exercise only the new orchestration-neutral boundary.
They do not grant the report writer, verifier, or this module severity authority.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

import pytest

import severity_adjudication_work as W
from worker_execution_receipts import environment_allowlist_sha256
from severity_decision_ledger import (
    LAUNCH_RECEIPT_SCHEMA,
    PROPOSAL_SCHEMA,
    bind_severity_adjudication,
    bind_severity_proposal,
    severity_assessor_input_digest,
    write_severity_decision_ledger,
)
from plamen_parsers import write_skeptic_challenges_json_sidecar


RUN_ID = "33333333-4444-4555-8666-777777777777"
AUDIT_DIGEST = "a" * 64
CONFIG_DIGEST = "b" * 64


def _digest(value) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _decision(
    candidate_id: str, *, proposed: str = "Medium", resolved: bool = False
) -> dict:
    constituents = [candidate_id]
    evidence = [
        {
            "evidence_id": f"EVID-I-{candidate_id}",
            "content_sha256": hashlib.sha256(
                f"impact:{candidate_id}".encode()
            ).hexdigest(),
            "premise_ids": [f"PREM-I-{candidate_id}"],
            "constituent_ids": constituents,
            "proof_scope": "IN_SCOPE_SOURCE",
            "capabilities": ["HARM", "IMPACT", "MECHANISM"],
            "issuer_identity": "driver-evidence-registry",
            "issuer_invocation_id": f"impact-evidence-{candidate_id}",
        },
        {
            "evidence_id": f"EVID-L-{candidate_id}",
            "content_sha256": hashlib.sha256(
                f"likelihood:{candidate_id}".encode()
            ).hexdigest(),
            "premise_ids": [f"PREM-L-{candidate_id}"],
            "constituent_ids": constituents,
            "proof_scope": "IN_SCOPE_SOURCE",
            "capabilities": ["LIKELIHOOD", "MECHANISM"],
            "issuer_identity": "driver-evidence-registry",
            "issuer_invocation_id": f"likelihood-evidence-{candidate_id}",
        },
    ]
    proposal = {
        "schema_version": PROPOSAL_SCHEMA,
        "candidate_id": candidate_id,
        "constituent_ids": constituents,
        "impact": {
            "class": "High",
            "harmed_asset": "protected value",
            "harmed_capability": "accounting integrity",
            "premise_id": f"PREM-I-{candidate_id}",
            "premise_kind": "INTERNAL",
            "evidence_ids": [f"EVID-I-{candidate_id}"],
            "proof_scope": "IN_SCOPE_SOURCE",
        },
        "likelihood": {
            "class": "Medium" if resolved else "Low",
            "actor": "unprivileged participant",
            "preconditions": ["reachable state"],
            "premise_id": f"PREM-L-{candidate_id}",
            "premise_kind": "INTERNAL",
            "evidence_ids": [f"EVID-L-{candidate_id}"],
            "proof_scope": "IN_SCOPE_SOURCE",
        },
        "modifiers": [],
        "proposed_severity": "High" if resolved else proposed,
        "adjustment": None if resolved else {
            "direction": "DOWN",
            "premise_ids": [f"PREM-L-{candidate_id}"],
            "evidence_ids": [f"EVID-L-{candidate_id}"],
            "proof_scope": "IN_SCOPE_SOURCE",
            "rationale": "Independent review is required for the changed tier.",
        },
        "constituent_premise_outcomes": {
            candidate_id: {"impact": "SUPPORTED", "likelihood": "SUPPORTED"}
        },
    }
    source_digest = hashlib.sha256(f"source:{candidate_id}".encode()).hexdigest()
    assessor = f"assessor-{candidate_id}"
    invocation = f"assessor-invocation-{candidate_id}"
    launch = {
        "schema_version": LAUNCH_RECEIPT_SCHEMA,
        "role": "ASSESSOR",
        "run_id": RUN_ID,
        "candidate_id": candidate_id,
        "constituent_ids": constituents,
        "worker_identity": assessor,
        "invocation_id": invocation,
        "backend": "claude",
        "launch_manifest_sha256": hashlib.sha256(
            f"launch:{candidate_id}".encode()
        ).hexdigest(),
        "input_sha256": severity_assessor_input_digest(
            candidate_id=candidate_id,
            constituent_ids=constituents,
            upstream_severity="High",
            run_id=RUN_ID,
            source_receipt_digest=source_digest,
            evidence_receipts=evidence,
        ),
        "output_sha256": _digest(proposal),
    }
    return bind_severity_proposal(
        proposal,
        candidate_id=candidate_id,
        constituent_ids=constituents,
        upstream_severity="High",
        assessor_identity=assessor,
        assessor_invocation_id=invocation,
        run_id=RUN_ID,
        source_receipt_digest=source_digest,
        evidence_receipts=evidence,
        assessor_launch_receipt=launch,
    )


def _write_state(root: Path, decisions: list[dict]) -> None:
    root.mkdir(parents=True, exist_ok=True)
    for decision in decisions:
        candidate_id = decision["candidate_id"]
        (root / f"verify_{candidate_id}.severity_decision.json").write_text(
            json.dumps(decision, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    write_severity_decision_ledger(
        root / "severity_decision_ledger.shadow.json", RUN_ID, decisions
    )


def _methodology(tmp_path: Path) -> dict[str, Path]:
    path = tmp_path / "severity-methodology.md"
    path.write_text("# Direction-neutral severity adjudication\n", encoding="utf-8")
    return {"severity-methodology": path}


def _prepare(tmp_path: Path, **overrides):
    arguments = {
        "run_id": RUN_ID,
        "audit_snapshot_digest": AUDIT_DIGEST,
        "audit_config_digest": CONFIG_DIGEST,
        "methodology_files": _methodology(tmp_path),
        "backend": "fixture-subprocess",
        "transport": "headless-subprocess",
        "effective_model": "fixture-python",
        "working_directory": tmp_path,
        "tool_policy": ["filesystem"],
        "environment_allowlist_digest": environment_allowlist_sha256(()),
        "adjudicator_identity": "independent-severity-adjudicator",
        "invocation_prefix": "ag3",
        "timeout_seconds_per_worker": 30,
    }
    arguments.update(overrides)
    return W.prepare_adjudication_work(tmp_path, **arguments)


def _adjudication_proposal(candidate_id: str) -> dict:
    return {
        "schema_version": "plamen.severity_adjudication_proposal.v1",
        "decision": "ACCEPT_PROPOSED",
        "resolved_severity": "Medium",
        "resolved_premise_ids": [f"PREM-L-{candidate_id}"],
        "evidence_ids": [f"EVID-L-{candidate_id}"],
        "proof_scope": "IN_SCOPE_SOURCE",
        "rationale": "Independent evidence supports the proposed matrix tier.",
        "resolved_axes": {"impact": "High", "likelihood": "Low"},
        "constituent_resolutions": {},
    }


def _write_proposal(tmp_path: Path, candidate_id: str) -> tuple[Path, dict]:
    proposal = _adjudication_proposal(candidate_id)
    path = tmp_path / f"verify_{candidate_id}.severity_adjudication_proposal.json"
    path.write_text(
        json.dumps(proposal, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return path, proposal


def _execute_shard(
    tmp_path: Path,
    plan: dict,
    candidate_id: str,
    *,
    proposals: dict[str, dict] | None = None,
) -> dict:
    """Create proposal bytes only through a real provider-owned subprocess."""

    shard = next(
        row for row in plan["shards"] if candidate_id in row["candidate_ids"]
    )
    payloads = proposals or {
        item: _adjudication_proposal(item) for item in shard["candidate_ids"]
    }
    encoded = json.dumps(payloads, ensure_ascii=False, sort_keys=True)
    output_names = json.dumps(shard["staged_outputs"], sort_keys=True)
    scope = json.dumps(shard["staging_output_scope"])
    script = (
        "import json; from pathlib import Path; "
        f"payloads=json.loads({encoded!r}); names=json.loads({output_names!r}); "
        f"scope=Path(json.loads({scope!r})); scope.mkdir(parents=True, exist_ok=True); "
        "[(scope/names[c]).write_text(json.dumps(payloads[c], sort_keys=True)+'\\n', "
        "encoding='utf-8') for c in sorted(payloads)]"
    )
    return W.execute_adjudication_worker(
        tmp_path,
        shard_id=shard["shard_id"],
        argv=[sys.executable, "-c", script],
        environment={},
        environment_allowlist=(),
        timeout_seconds=30,
    )


def _worker_run_for(tmp_path: Path, plan: dict, candidate_id: str) -> dict:
    shard = next(
        row for row in plan["shards"] if candidate_id in row["candidate_ids"]
    )
    suffix = str(shard["launch_intent_file"]).split(".")[-2]
    return json.loads(
        (tmp_path / f"severity_adjudication_worker_run.{suffix}.json").read_text(
            encoding="utf-8"
        )
    )


def _receipt_first_payload(
    tmp_path: Path,
    *,
    decision: dict,
    plan: dict,
    candidate_id: str,
) -> dict:
    shard = next(
        row for row in plan["shards"] if candidate_id in row["candidate_ids"]
    )
    intent = json.loads((tmp_path / shard["launch_intent_file"]).read_text())
    manifest = json.loads((tmp_path / W.MANIFEST_NAME).read_text())
    item = next(
        row for row in manifest["work_items"] if row["candidate_id"] == candidate_id
    )
    worker_run = _execute_shard(tmp_path, plan, candidate_id)
    proposal_path = tmp_path / f"verify_{candidate_id}.severity_adjudication_proposal.json"
    proposal = json.loads(proposal_path.read_text(encoding="utf-8"))
    launch = {
        "schema_version": LAUNCH_RECEIPT_SCHEMA,
        "role": "ADJUDICATOR",
        "run_id": RUN_ID,
        "candidate_id": candidate_id,
        "constituent_ids": item["constituent_ids"],
        "worker_identity": intent["worker_identity"],
        "invocation_id": intent["invocation_id"],
        "backend": worker_run["backend"],
        "launch_manifest_sha256": worker_run["receipt_digest"],
        "input_sha256": item["adjudicator_input_sha256"],
        "output_sha256": _digest(proposal),
    }
    updated = bind_severity_adjudication(
        proposal,
        decision=decision,
        adjudicator_launch_receipt=launch,
    )
    proposal_bytes = proposal_path.read_bytes()
    unsigned = {
        "schema_version": "plamen.severity_adjudication_receipt.v1",
        "candidate_id": candidate_id,
        "source_decision_digest": decision["decision_digest"],
        "adjudicator_input_sha256": item["adjudicator_input_sha256"],
        "result_decision_digest": updated["decision_digest"],
        "proposal_file": proposal_path.name,
        "proposal_sha256": hashlib.sha256(proposal_bytes).hexdigest(),
        "proposal_size_bytes": len(proposal_bytes),
        "launch_receipt": launch,
    }
    return {**unsigned, "receipt_digest": _digest(unsigned)}


def test_zero_denominator_writes_no_context_prompt_or_launch_intent(tmp_path: Path):
    _write_state(tmp_path, [])
    plan = _prepare(tmp_path)

    assert plan["denominator_ids"] == []
    assert plan["shards"] == []
    assert plan["debt_items"] == []
    assert plan["launch_count"] == 0
    assert not list(tmp_path.glob("severity_adjudication_context.*.json"))
    assert not list(tmp_path.glob("severity_adjudication_prompt.*.md"))
    assert not list(tmp_path.glob("severity_adjudication_launch_intent.*.json"))
    assert not list(tmp_path.glob("severity_adjudication_tool_policy.*.json"))
    assert W.validate_prepared_work(tmp_path) == []


def test_hash_bound_skeptic_challenge_forces_distinct_adjudication_of_resolved_source(
    tmp_path: Path,
):
    decision = _decision("H-1", resolved=True)
    assert decision["status"] == "RESOLVED"
    _write_state(tmp_path, [decision])
    manifest = {
        "phase": "skeptic",
        "required_count": 1,
        "findings": [{
            "finding_id": "H-1",
            "challenge_triggers": ["HIGH_RISK_ADVERSARIAL_REVIEW"],
            "constituent_ids": ["H-1"],
        }],
    }
    (tmp_path / "skeptic_manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    (tmp_path / "skeptic_findings.md").write_text(
        "# Skeptic Challenge Proposals\n\n"
        "## H-1 - Generic\n\n"
        "Proposal Authority: CHALLENGE_ONLY\n"
        "Proposed Direction: UNRESOLVED\n"
        "Proposed Disposition: UNRESOLVED\n"
        "Affected Constituents: H-1\n"
        "Impact Premise ID: PREM-I-H-1\n"
        "Likelihood Premise ID: PREM-L-H-1\n"
        "Premise Challenged: harm scope requires independent review\n"
        "Evidence Receipt IDs: EVID-I-H-1, EVID-L-H-1\n"
        "Proof Scope: IN_SCOPE_SOURCE\n",
        encoding="utf-8",
    )
    (tmp_path / "skeptic_judge_decisions.md").write_text(
        "| Finding ID | Original Severity | Proposed Severity | Decision | Rationale |\n"
        "|------------|-------------------|-------------------|----------|-----------|\n"
        "| H-1 | High | High | UNRESOLVED | challenge only |\n",
        encoding="utf-8",
    )
    assert write_skeptic_challenges_json_sidecar(tmp_path) == 1

    plan = _prepare(tmp_path)
    assert plan["denominator_ids"] == ["H-1"]
    assert plan["shards"][0]["candidate_ids"] == ["H-1"]
    context = json.loads(
        (tmp_path / plan["shards"][0]["context_file"]).read_text(
            encoding="utf-8"
        )
    )
    item = context["items"][0]
    assert item["source_status"] == "CHALLENGE_REQUIRED"
    assert item["skeptic_challenge"]["finding_id"] == "H-1"
    assert context["skeptic_challenge_receipt_digest"]
    assert W.validate_prepared_work(tmp_path) == []


def test_plan_exactly_partitions_denominator_with_four_item_ceiling(tmp_path: Path):
    decisions = [_decision(f"H-{index}") for index in range(1, 10)]
    _write_state(tmp_path, decisions)
    plan = _prepare(tmp_path, max_items_per_worker=4, max_weight_per_worker=8)

    assigned = [item for shard in plan["shards"] for item in shard["candidate_ids"]]
    debt = [row["candidate_id"] for row in plan["debt_items"]]
    assert set(assigned) | set(debt) == set(plan["denominator_ids"])
    assert len(assigned) + len(debt) == len(plan["denominator_ids"])
    assert len(assigned) == len(set(assigned))
    assert all(len(shard["candidate_ids"]) <= 4 for shard in plan["shards"])
    assert all(shard["total_weight"] <= 8 for shard in plan["shards"])
    assert W.validate_prepared_work(tmp_path) == []


def test_single_item_over_byte_cap_becomes_visible_debt_not_launch(tmp_path: Path):
    _write_state(tmp_path, [_decision("H-1")])
    plan = _prepare(tmp_path, max_context_bytes_per_worker=64)

    assert plan["shards"] == []
    assert plan["launch_count"] == 0
    assert plan["debt_items"] == [
        {
            "candidate_id": "H-1",
            "state": "UNSCHEDULABLE_INPUT_CAP",
            "reason": "single adjudication context exceeds configured byte cap",
        }
    ]
    assert W.validate_prepared_work(tmp_path) == []


def test_launch_intent_binds_all_inputs_and_exact_outputs(tmp_path: Path):
    _write_state(tmp_path, [_decision("H-1"), _decision("H-2")])
    plan = _prepare(tmp_path)
    shard = plan["shards"][0]
    intent = json.loads((tmp_path / shard["launch_intent_file"]).read_text())
    context = json.loads((tmp_path / shard["context_file"]).read_text())

    assert intent["run_id"] == RUN_ID
    assert intent["audit_snapshot_digest"] == AUDIT_DIGEST
    assert intent["audit_config_digest"] == CONFIG_DIGEST
    assert intent["methodology_digest"] == plan["methodology_digest"]
    assert intent["backend"] == "fixture-subprocess"
    assert intent["transport"] == "headless-subprocess"
    assert intent["effective_model"] == "fixture-python"
    assert intent["working_directory"] == str(tmp_path.resolve())
    assert intent["tool_policy"] == ["filesystem"]
    assert intent["environment_allowlist_digest"] == environment_allowlist_sha256(())
    assert plan["timeout_seconds_per_worker"] == 30
    assert intent["timeout_seconds_per_worker"] == 30
    assert intent["effective_backend"] == "fixture-subprocess"
    assert intent["assessor_principals"] == [
        {
            "identity": "assessor-H-1",
            "invocation_id": "assessor-invocation-H-1",
        },
        {
            "identity": "assessor-H-2",
            "invocation_id": "assessor-invocation-H-2",
        },
    ]
    policy_path = tmp_path / shard["tool_policy_file"]
    policy_bytes = policy_path.read_bytes()
    assert intent["tool_policy_file"] == policy_path.name
    assert intent["tool_policy_sha256"] == hashlib.sha256(policy_bytes).hexdigest()
    assert intent["tool_policy_size_bytes"] == len(policy_bytes)
    assert intent["source_ledger_digest"] == plan["source_ledger_digest"]
    assert intent["expected_outputs"] == {
        "H-1": "verify_H-1.severity_adjudication_proposal.json",
        "H-2": "verify_H-2.severity_adjudication_proposal.json",
    }
    assert intent["staging_output_scope"] == (
        "severity_adjudication_worker_outputs/0001"
    )
    assert intent["staged_outputs"] == intent["expected_outputs"]
    assert intent["worker_identity"] != "assessor-H-1"
    assert intent["worker_identity"] != "assessor-H-2"
    methodology_bytes = (tmp_path / "severity-methodology.md").read_bytes()
    assert context["methodology_entries"] == [
        {
            "logical_name": "severity-methodology",
            "content_encoding": "utf-8",
            "content_utf8": methodology_bytes.decode("utf-8"),
            "sha256": hashlib.sha256(methodology_bytes).hexdigest(),
            "size_bytes": len(methodology_bytes),
        }
    ]
    assert W.validate_prepared_work(tmp_path) == []


def test_empty_methodology_is_not_a_launchable_binding(tmp_path: Path):
    _write_state(tmp_path, [_decision("H-1")])
    with pytest.raises(W.AdjudicationWorkError, match="at least one"):
        W.prepare_adjudication_work(
            tmp_path,
            run_id=RUN_ID,
            audit_snapshot_digest=AUDIT_DIGEST,
            audit_config_digest=CONFIG_DIGEST,
            methodology_files={},
            backend="claude",
            transport="pty",
            effective_model="claude-opus-test",
            working_directory=tmp_path,
            tool_policy=["filesystem"],
            environment_allowlist_digest="e" * 64,
            adjudicator_identity="independent-severity-adjudicator",
            invocation_prefix="ag3",
        )


def test_assessor_cannot_be_reused_as_adjudicator(tmp_path: Path):
    _write_state(tmp_path, [_decision("H-1")])
    with pytest.raises(W.AdjudicationWorkError, match="distinct"):
        _prepare(tmp_path, adjudicator_identity="assessor-H-1")


def test_resume_is_byte_idempotent_and_reconciles_output_ready(tmp_path: Path):
    decision = _decision("H-1")
    _write_state(tmp_path, [decision])
    first = _prepare(tmp_path)
    tracked = {
        path.name: path.read_bytes()
        for path in tmp_path.glob("severity_adjudication_*")
        if path.is_file()
    }

    _execute_shard(tmp_path, first, "H-1")

    second = _prepare(tmp_path)
    assert second == first
    assert tracked == {
        name: (tmp_path / name).read_bytes() for name in tracked
    }
    receipt = W.reconcile_adjudication_work(tmp_path)
    assert receipt["states"] == {"H-1": "OUTPUT_READY"}
    assert receipt["bind_ready_ids"] == ["H-1"]
    assert receipt["debt_ids"] == []


def test_resume_rejects_audit_or_methodology_drift_without_overwrite(tmp_path: Path):
    _write_state(tmp_path, [_decision("H-1")])
    _prepare(tmp_path)
    plan_path = tmp_path / W.WORK_PLAN_NAME
    before = plan_path.read_bytes()

    with pytest.raises(W.AdjudicationWorkError, match="resume binding"):
        _prepare(tmp_path, audit_snapshot_digest="c" * 64)
    assert plan_path.read_bytes() == before

    methodology = _methodology(tmp_path)
    methodology["severity-methodology"].write_text(
        "# Mutated methodology\n", encoding="utf-8"
    )
    with pytest.raises(W.AdjudicationWorkError, match="resume binding"):
        W.prepare_adjudication_work(
            tmp_path,
            run_id=RUN_ID,
            audit_snapshot_digest=AUDIT_DIGEST,
            audit_config_digest=CONFIG_DIGEST,
            methodology_files=methodology,
            backend="claude",
            transport="pty",
            effective_model="claude-opus-test",
            working_directory=tmp_path,
            tool_policy=["filesystem"],
            environment_allowlist_digest=environment_allowlist_sha256(()),
            adjudicator_identity="independent-severity-adjudicator",
            invocation_prefix="ag3",
        )
    assert plan_path.read_bytes() == before


def test_tampered_partition_context_prompt_or_intent_fails_validation(tmp_path: Path):
    _write_state(tmp_path, [_decision("H-1"), _decision("H-2")])
    plan = _prepare(tmp_path)
    shard = plan["shards"][0]

    plan_path = tmp_path / W.WORK_PLAN_NAME
    original_plan = plan_path.read_bytes()
    tampered = json.loads(original_plan)
    tampered["shards"][0]["candidate_ids"].append("H-1")
    plan_path.write_text(json.dumps(tampered), encoding="utf-8")
    assert any("digest" in issue or "overlap" in issue for issue in W.validate_prepared_work(tmp_path))
    plan_path.write_bytes(original_plan)

    context_path = tmp_path / shard["context_file"]
    context_path.write_text("{}", encoding="utf-8")
    assert any("context" in issue for issue in W.validate_prepared_work(tmp_path))


def test_receipt_first_crash_is_recoverable_only_when_exactly_bound(tmp_path: Path):
    decision = _decision("H-1")
    _write_state(tmp_path, [decision])
    plan = _prepare(tmp_path)
    receipt = _receipt_first_payload(
        tmp_path, decision=decision, plan=plan, candidate_id="H-1"
    )
    receipt_path = tmp_path / "verify_H-1.severity_adjudication_receipt.json"
    receipt_path.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    reconciled = W.reconcile_adjudication_work(tmp_path)
    assert reconciled["states"] == {"H-1": "RECEIPT_PENDING_DECISION_COMMIT"}
    assert reconciled["debt_ids"] == ["H-1"]

    receipt["launch_receipt"]["backend"] = "unbound-backend"
    unsigned = {key: value for key, value in receipt.items() if key != "receipt_digest"}
    receipt["receipt_digest"] = _digest(unsigned)
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    invalid = W.reconcile_adjudication_work(tmp_path)
    assert invalid["states"] == {"H-1": "RECEIPT_INVALID"}


def test_existing_binder_completion_reconciles_as_completed(tmp_path: Path):
    import severity_runtime

    decision = _decision("H-1")
    _write_state(tmp_path, [decision])
    plan = _prepare(tmp_path)
    worker_run = _execute_shard(tmp_path, plan, "H-1")
    shard = plan["shards"][0]
    intent = json.loads((tmp_path / shard["launch_intent_file"]).read_text())

    written, issues = severity_runtime.bind_shadow_adjudication_for_candidate(
        tmp_path,
        "H-1",
        backend=intent["backend"],
        launch_digest=worker_run["receipt_digest"],
        run_id=RUN_ID,
        worker_identity=intent["worker_identity"],
        invocation_id=intent["invocation_id"],
    )
    assert not issues
    assert written
    reconciled = W.reconcile_adjudication_work(tmp_path)
    assert reconciled["states"] == {"H-1": "COMPLETED"}
    assert reconciled["completed_ids"] == ["H-1"]
    assert reconciled["debt_ids"] == []
    assert reconciled["all_terminal"] is True
    assert reconciled["all_resolved"] is True


def test_malformed_worker_output_is_visible_debt(tmp_path: Path):
    _write_state(tmp_path, [_decision("H-1")])
    _prepare(tmp_path)
    (tmp_path / "verify_H-1.severity_adjudication_proposal.json").write_text(
        "{}", encoding="utf-8"
    )

    reconciled = W.reconcile_adjudication_work(tmp_path)
    assert reconciled["states"] == {"H-1": "OUTPUT_INVALID"}
    assert reconciled["debt_ids"] == ["H-1"]
    assert reconciled["all_terminal"] is True


def test_resume_repairs_missing_derived_artifact_but_never_tampered_bytes(
    tmp_path: Path,
):
    _write_state(tmp_path, [_decision("H-1")])
    plan = _prepare(tmp_path)
    prompt_path = tmp_path / plan["shards"][0]["prompt_file"]
    expected_prompt = prompt_path.read_bytes()
    prompt_path.unlink()

    assert _prepare(tmp_path) == plan
    assert prompt_path.read_bytes() == expected_prompt

    prompt_path.write_text("tampered prompt", encoding="utf-8")
    with pytest.raises(W.AdjudicationWorkError, match="different bytes"):
        _prepare(tmp_path)
    assert prompt_path.read_text(encoding="utf-8") == "tampered prompt"
