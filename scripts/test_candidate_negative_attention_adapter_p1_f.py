from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

import attention_repair_shards as attention
import candidate_negative_authority as negative
from plamen_types import attention_queue_binding_sha256


def _typed_authorities() -> tuple[bytes, bytes, bytes]:
    plan_rows = [
        {
            "row": 1,
            "kind": "uncited-security-file",
            "target": "src/A.sol",
            "reason": "not cited",
            "source": "coverage",
            "evidence": "src/A.sol",
        },
        {
            "row": 2,
            "kind": "semantic-gap",
            "target": "bridge routing",
            "reason": "boundary needs review",
            "source": "inventory",
            "evidence": "bridge routing",
        },
        {
            "row": 3,
            "kind": "uncited-security-file",
            "target": "src/B.sol",
            "reason": "not cited",
            "source": "coverage",
            "evidence": "src/B.sol",
        },
        {
            "row": 4,
            "kind": "source-path-authority-debt",
            "target": "src/Missing.sol",
            "reason": "source authority absent",
            "source": "recon",
            "evidence": "src/Missing.sol",
        },
        {
            "row": 5,
            "kind": "semantic-gap",
            "target": "fee rounding",
            "reason": "rounding path needs review",
            "source": "inventory",
            "evidence": "fee rounding",
        },
    ]
    queue_binding = attention_queue_binding_sha256(plan_rows)
    queue_lines = [
        "# Attention Repair Queue",
        "",
        f"QUEUE_BINDING_SHA256: {queue_binding}",
        "",
        "| # | Kind | Target | Reason | Source | Evidence |",
        "|---|---|---|---|---|---|",
        *[
            "| {row} | {kind} | {target} | {reason} | {source} | {evidence} |".format(
                **row
            )
            for row in plan_rows
        ],
    ]
    queue_bytes = ("\n".join(queue_lines) + "\n").encode()
    shard = {
        "ordinal": 1,
        "shard_id": "attention-0001",
        "input_path": "_attention_repair_shards/shard_0001.input.md",
        "output_path": "attention_repair_rows_0001.md",
        "row_numbers": [1, 2, 3, 4, 5],
        "row_binding_sha256": queue_binding,
        "rows": plan_rows,
    }
    plan = {
        "schema": attention.PLAN_SCHEMA,
        "queue_path": "attention_repair_queue.md",
        "queue_file_sha256": attention._sha256(queue_bytes),
        "parent_queue_binding_sha256": queue_binding,
        "row_count": 5,
        "shard_size": 6,
        "shard_count": 1,
        "shards": [shard],
    }
    plan["plan_sha256"] = attention._sha256(attention._canonical_json(plan))
    receipt_rows = [
        {
            "row": 1,
            "kind": "uncited-security-file",
            "target": "src/A.sol",
            "verdict": "SAFE",
            "evidence": "src/A.sol:L7 reviewed",
            "notes": "no exploitable path",
            "coverage_accepted": True,
        },
        {
            "row": 2,
            "kind": "semantic-gap",
            "target": "bridge routing",
            "verdict": "SAFE",
            "evidence": "routing branches reviewed",
            "notes": "guards dominate calls",
            "coverage_accepted": False,
        },
        {
            "row": 3,
            "kind": "uncited-security-file",
            "target": "src/B.sol",
            "verdict": "CONFIRMED",
            "evidence": "src/B.sol:L11 demonstrates the issue",
            "notes": "emitted as ATT-3",
            "coverage_accepted": True,
        },
        {
            "row": 4,
            "kind": "source-path-authority-debt",
            "target": "src/Missing.sol",
            "verdict": "NEEDS_HUMAN",
            "evidence": "src/Missing.sol remains unavailable",
            "notes": "authority debt retained",
            "coverage_accepted": False,
        },
        {
            "row": 5,
            "kind": "semantic-gap",
            "target": "fee rounding",
            "verdict": "NO_FINDING",
            "evidence": "bounded arithmetic reviewed",
            "notes": "no candidate survives",
            "coverage_accepted": False,
        },
    ]
    receipt = {
        "schema": "plamen.attention-repair-application.v1",
        "status": "INCOMPLETE",
        "queue_binding_sha256": queue_binding,
        "queue_file_sha256": attention._sha256(queue_bytes),
        "rows": receipt_rows,
        "accepted_paths": ["src/A.sol", "src/B.sol"],
        "unresolved_paths": ["src/Missing.sol"],
    }
    return (
        queue_bytes,
        (json.dumps(plan, indent=2, sort_keys=True) + "\n").encode(),
        (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode(),
    )


def test_typed_attention_adapter_harvests_every_negative_without_derived_ids() -> None:
    queue_bytes, plan_bytes, receipt_bytes = _typed_authorities()

    ledger = negative.build_attention_repair_candidate_negative_ledger(
        queue_bytes=queue_bytes,
        plan_bytes=plan_bytes,
        application_receipt_bytes=receipt_bytes,
    )

    assert ledger["status"] == "CLEAN"
    assert ledger["event_count"] == 3
    assert ledger["issues"] == []
    assert ledger["attention_authority_binding"]["negative_row_numbers"] == [1, 2, 5]
    assert {event["legacy_disposition"] for event in ledger["events"]} == {
        "SAFE",
        "NO_FINDING",
    }
    assert all(event["source_item_id"].startswith("ATNR-") for event in ledger["events"])
    assert all(event["identity_state"] == "EXACT" for event in ledger["events"])
    assert all(event["proposed_disposition"] == "REFUTATION_PROPOSAL" for event in ledger["events"])
    assert all(event["requires_independent_consumer"] is True for event in ledger["events"])
    assert all(event["proof_scope"] == "NONE" for event in ledger["events"])
    assert all(event["harvest_kind"] == "TYPED_ATTENTION_REPAIR_V1" for event in ledger["events"])
    assert not any(event["legacy_disposition"] == "CONFIRMED" for event in ledger["events"])


def test_typed_attention_adapter_is_exactly_idempotent_and_replayable(
    tmp_path: Path,
) -> None:
    queue_bytes, plan_bytes, receipt_bytes = _typed_authorities()

    first = negative.build_attention_repair_candidate_negative_ledger(
        queue_bytes=queue_bytes,
        plan_bytes=plan_bytes,
        application_receipt_bytes=receipt_bytes,
    )
    second = negative.build_attention_repair_candidate_negative_ledger(
        queue_bytes=queue_bytes,
        plan_bytes=plan_bytes,
        application_receipt_bytes=receipt_bytes,
    )

    assert first == second
    negative.validate_attention_repair_candidate_negative_ledger(
        first,
        queue_bytes=queue_bytes,
        plan_bytes=plan_bytes,
        application_receipt_bytes=receipt_bytes,
    )
    (tmp_path / negative.ATTENTION_REPAIR_QUEUE_ARTIFACT).write_bytes(queue_bytes)
    (tmp_path / negative.ATTENTION_REPAIR_PLAN_ARTIFACT).write_bytes(plan_bytes)
    (tmp_path / negative.ATTENTION_REPAIR_APPLICATION_ARTIFACT).write_bytes(
        receipt_bytes
    )
    assert (
        negative.build_attention_repair_candidate_negative_ledger_from_scratchpad(
            tmp_path
        )
        == first
    )
    negative.validate_attention_repair_candidate_negative_ledger_from_scratchpad(
        first, scratchpad=tmp_path
    )


def test_typed_attention_adapter_rejects_resigned_ledger_metadata_tamper() -> None:
    queue_bytes, plan_bytes, receipt_bytes = _typed_authorities()
    ledger = negative.build_attention_repair_candidate_negative_ledger(
        queue_bytes=queue_bytes,
        plan_bytes=plan_bytes,
        application_receipt_bytes=receipt_bytes,
    )
    tampered = copy.deepcopy(ledger)
    binding = tampered["attention_authority_binding"]
    binding["negative_row_numbers"] = [1, 5]
    binding["binding_digest"] = negative._digest(
        {key: value for key, value in binding.items() if key != "binding_digest"}
    )
    tampered["ledger_digest"] = negative._digest(
        {key: value for key, value in tampered.items() if key != "ledger_digest"}
    )

    negative.validate_candidate_negative_ledger(tampered)
    with pytest.raises(
        negative.CandidateNegativeAuthorityError,
        match="typed adapter projection mismatch",
    ):
        negative.validate_attention_repair_candidate_negative_ledger(
            tampered,
            queue_bytes=queue_bytes,
            plan_bytes=plan_bytes,
            application_receipt_bytes=receipt_bytes,
        )


def test_typed_attention_adapter_rejects_receipt_and_plan_tamper() -> None:
    queue_bytes, plan_bytes, receipt_bytes = _typed_authorities()
    ledger = negative.build_attention_repair_candidate_negative_ledger(
        queue_bytes=queue_bytes,
        plan_bytes=plan_bytes,
        application_receipt_bytes=receipt_bytes,
    )
    receipt = json.loads(receipt_bytes)
    receipt["rows"][0]["notes"] = "different but still well-formed assessment"
    changed_receipt = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode()
    with pytest.raises(
        negative.CandidateNegativeAuthorityError,
        match="typed adapter projection mismatch",
    ):
        negative.validate_attention_repair_candidate_negative_ledger(
            ledger,
            queue_bytes=queue_bytes,
            plan_bytes=plan_bytes,
            application_receipt_bytes=changed_receipt,
        )

    with pytest.raises(
        negative.CandidateNegativeAuthorityError,
        match="exact queue binding",
    ):
        negative.build_attention_repair_candidate_negative_ledger(
            queue_bytes=queue_bytes + b"\n",
            plan_bytes=plan_bytes,
            application_receipt_bytes=receipt_bytes,
        )

    plan = json.loads(plan_bytes)
    plan["shards"][0]["rows"][0]["target"] = "src/Other.sol"
    changed_plan = (json.dumps(plan, indent=2, sort_keys=True) + "\n").encode()
    with pytest.raises(
        negative.CandidateNegativeAuthorityError,
        match="self-hash mismatch",
    ):
        negative.build_attention_repair_candidate_negative_ledger(
            queue_bytes=queue_bytes,
            plan_bytes=changed_plan,
            application_receipt_bytes=receipt_bytes,
        )


def test_typed_attention_adapter_rejects_ambiguous_receipt_json() -> None:
    queue_bytes, plan_bytes, receipt_bytes = _typed_authorities()
    ambiguous = receipt_bytes.replace(
        b'{\n  "accepted_paths"',
        b'{\n  "status": "COMPLETE",\n  "accepted_paths"',
        1,
    )
    with pytest.raises(
        negative.CandidateNegativeAuthorityError,
        match="duplicate JSON object key",
    ):
        negative.build_attention_repair_candidate_negative_ledger(
            queue_bytes=queue_bytes,
            plan_bytes=plan_bytes,
            application_receipt_bytes=ambiguous,
        )


def test_rescan_staged_gate_publishes_real_na_as_visible_debt() -> None:
    output = "scratchpad:rescan_findings.md"
    context = negative.compile_candidate_negative_staged_context(
        b"# finding-output contract\n",
        output,
        "RESCAN",
        phase="rescan",
        invocation_id="rescan-live",
    )
    invalid = (
        "| Candidate ID | Disposition | Notes |\n"
        "|---|---|---|\n"
        "| PC5-1 | N/A | out of scope |\n"
    ).encode()
    valid = invalid.replace(b"N/A", b"REFUTATION_PROPOSAL")

    # `format.nonterminal_enum_spelling` is a presentation property: the
    # legacy terminal spelling is recorded as debt on the ledger, with a
    # repair hint, and the artifact publishes.  The candidate is NOT closed --
    # the event stays EXACT, nonterminal and independently reviewable.
    assert negative.staged_candidate_negative_receipt_validator(
        {output: invalid}, context
    ) == ()
    assert negative.staged_candidate_negative_receipt_validator(
        {output: valid}, context
    ) == ()
    ledger = negative._build_candidate_negative_ledger_from_bytes(
        phase="rescan",
        artifacts=(
            negative.ArtifactInput(
                relative_path=output,
                content=invalid,
                producer_identity="RESCAN",
                producer_invocation_id="rescan-live",
            ),
        ),
        methodology_bytes=b"# finding-output contract\n",
        methodology_identity=negative._STAGED_METHODOLOGY_IDENTITY,
    )
    assert ledger["status"] == "INPUT_DEBT"
    assert {str(issue["code"]) for issue in ledger["issues"]} == {
        "EVENT_NOT_APPLICABLE_WITH_NONZERO_DENOMINATOR"
    }
    assert ledger["events"][0]["source_item_id"] == "PC5-1"
    assert ledger["events"][0]["proposed_disposition"] == "NOT_APPLICABLE_PROPOSAL"


def test_generic_staged_gate_rejects_resigned_unsupported_phase() -> None:
    output = "scratchpad:rescan_findings.md"
    context = negative.compile_candidate_negative_staged_context(
        b"# finding-output contract\n",
        output,
        "RESCAN",
        phase="rescan",
    )
    context["phase"] = "attention_repair"
    context["context_digest"] = negative._digest(
        {key: value for key, value in context.items() if key != "context_digest"}
    )

    assert negative.staged_candidate_negative_receipt_validator(
        {output: b"# no candidates\n"}, context
    ) == ("staged candidate-negative gate context is invalid",)
