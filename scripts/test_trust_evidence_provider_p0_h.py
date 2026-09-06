"""P0-H live-provider boundary: typed severity facts cannot self-mint trust authority.

The current severity substrate is intentionally exercised as-is.  It carries a
typed ``FULLY_TRUSTED_ACTOR`` modifier and hash-bound adjudication metadata, but
does not carry the external trust statement/primary-document artifact or the
four exact trust-scope fields required by ``trust_evidence_authority``.  The
provider must therefore produce explicit review debt and zero negative
authority, never fill those gaps from verifier prose.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from severity_decision_ledger import (
    LAUNCH_RECEIPT_SCHEMA,
    PROPOSAL_SCHEMA,
    bind_severity_adjudication,
    bind_severity_proposal,
    severity_adjudicator_input_digest,
    severity_assessor_input_digest,
    write_severity_decision_ledger,
)
from trust_evidence_authority import resolve_trust_evidence
from trust_evidence_provider import (
    PROVIDER_RECEIPT_FILE,
    build_trust_evidence_provider_state,
    ensure_trust_evidence_provider_state,
    validate_trust_evidence_provider_state,
    write_trust_evidence_provider_state,
)


RUN_ID = "p0-h-provider-run"
FID = "INV-041"
HEX_A = "a" * 64


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


def _checkpoint(root: Path, run_id: str = RUN_ID) -> None:
    (root / "_v2_checkpoint.json").write_text(
        json.dumps({"run_id": run_id}) + "\n", encoding="utf-8"
    )


def _trust_decision(
    candidate_id: str = FID, *, trust_modifier: bool = True, run_id: str = RUN_ID
) -> dict:
    constituents = [candidate_id]
    impact_premise = f"PREM-I-{candidate_id}"
    likelihood_premise = f"PREM-L-{candidate_id}"
    evidence = [
        {
            "evidence_id": f"EVID-I-{candidate_id}",
            "content_sha256": _digest({"impact": candidate_id}),
            "premise_ids": [impact_premise],
            "constituent_ids": constituents,
            "proof_scope": "IN_SCOPE_SOURCE",
            "capabilities": ["HARM", "IMPACT", "MECHANISM"],
            "issuer_identity": "driver-evidence-registry",
            "issuer_invocation_id": f"impact-{candidate_id}",
        },
        {
            "evidence_id": f"EVID-L-{candidate_id}",
            "content_sha256": _digest({"likelihood": candidate_id}),
            "premise_ids": [likelihood_premise],
            "constituent_ids": constituents,
            "proof_scope": "IN_SCOPE_SOURCE",
            "capabilities": ["LIKELIHOOD", "MECHANISM"],
            "issuer_identity": "driver-evidence-registry",
            "issuer_invocation_id": f"likelihood-{candidate_id}",
        },
        {
            "evidence_id": f"EVID-T-{candidate_id}",
            "content_sha256": _digest({"trust-claim": candidate_id}),
            "premise_ids": [likelihood_premise],
            "constituent_ids": constituents,
            "proof_scope": "IN_SCOPE_SOURCE",
            "capabilities": ["MODIFIER_APPLICABILITY"],
            "issuer_identity": "driver-evidence-registry",
            "issuer_invocation_id": f"trust-{candidate_id}",
        },
    ]
    modifiers = []
    proposed = "High"
    adjustment = None
    if trust_modifier:
        modifiers = [
            {
                "kind": "FULLY_TRUSTED_ACTOR",
                "applies": True,
                "applicability_predicate": (
                    "A named authority can replace the protected runtime."
                ),
                "evidence_ids": [f"EVID-T-{candidate_id}"],
                "proof_scope": "IN_SCOPE_SOURCE",
            }
        ]
        proposed = "Medium"
        adjustment = {
            "direction": "DOWN",
            "premise_ids": [likelihood_premise],
            "evidence_ids": [f"EVID-L-{candidate_id}"],
            "proof_scope": "IN_SCOPE_SOURCE",
            "rationale": "The typed proposal requests a trust modifier.",
        }
    proposal = {
        "schema_version": PROPOSAL_SCHEMA,
        "candidate_id": candidate_id,
        "constituent_ids": constituents,
        "impact": {
            "class": "High",
            "harmed_asset": "protocol runtime integrity",
            "harmed_capability": "replace runtime code",
            "premise_id": impact_premise,
            "premise_kind": "INTERNAL",
            "evidence_ids": [f"EVID-I-{candidate_id}"],
            "proof_scope": "IN_SCOPE_SOURCE",
        },
        "likelihood": {
            "class": "Medium",
            "actor": "governance timelock",
            "preconditions": ["named authority invokes the capability"],
            "premise_id": likelihood_premise,
            "premise_kind": "INTERNAL",
            "evidence_ids": [f"EVID-L-{candidate_id}"],
            "proof_scope": "IN_SCOPE_SOURCE",
        },
        "modifiers": modifiers,
        "proposed_severity": proposed,
        "adjustment": adjustment,
        "constituent_premise_outcomes": {
            candidate_id: {"impact": "SUPPORTED", "likelihood": "SUPPORTED"}
        },
    }
    source_digest = _digest({"source": candidate_id})
    assessor = f"verifier-{candidate_id}"
    invocation = f"verifier-invocation-{candidate_id}"
    launch = {
        "schema_version": LAUNCH_RECEIPT_SCHEMA,
        "role": "ASSESSOR",
        "run_id": run_id,
        "candidate_id": candidate_id,
        "constituent_ids": constituents,
        "worker_identity": assessor,
        "invocation_id": invocation,
        "backend": "claude",
        "launch_manifest_sha256": _digest({"launch": candidate_id}),
        "input_sha256": severity_assessor_input_digest(
            candidate_id=candidate_id,
            constituent_ids=constituents,
            upstream_severity="High",
            run_id=run_id,
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
        run_id=run_id,
        source_receipt_digest=source_digest,
        evidence_receipts=evidence,
        assessor_launch_receipt=launch,
    )


def _write_severity_state(root: Path, decisions: list[dict]) -> None:
    for decision in decisions:
        candidate_id = decision["candidate_id"]
        (root / f"verify_{candidate_id}.severity_decision.json").write_text(
            json.dumps(decision, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    ledger_run = str(decisions[0]["run_id"]) if decisions else RUN_ID
    write_severity_decision_ledger(
        root / "severity_decision_ledger.shadow.json", ledger_run, decisions
    )


def _synthetically_adjudicate(decision: dict) -> dict:
    proposal = {
        "schema_version": "plamen.severity_adjudication_proposal.v1",
        "decision": "ACCEPT_PROPOSED",
        "resolved_severity": "Medium",
        "resolved_premise_ids": [f"PREM-L-{FID}"],
        "evidence_ids": [f"EVID-L-{FID}"],
        "proof_scope": "IN_SCOPE_SOURCE",
        "rationale": "Independent adjudicator accepts the proposal.",
        "resolved_axes": {"impact": "High", "likelihood": "Medium"},
        "constituent_resolutions": {},
    }
    launch = {
        "schema_version": LAUNCH_RECEIPT_SCHEMA,
        "role": "ADJUDICATOR",
        "run_id": RUN_ID,
        "candidate_id": FID,
        "constituent_ids": [FID],
        "worker_identity": "independent-adjudicator",
        "invocation_id": "independent-adjudicator-invocation",
        "backend": "claude",
        "launch_manifest_sha256": _digest({"adjudicator-launch": FID}),
        "input_sha256": severity_adjudicator_input_digest(decision),
        "output_sha256": _digest(proposal),
    }
    return bind_severity_adjudication(
        proposal, decision=decision, adjudicator_launch_receipt=launch
    )


def test_zero_denominator_is_an_exact_empty_no_authority_state(tmp_path: Path) -> None:
    _checkpoint(tmp_path)
    _write_severity_state(tmp_path, [])
    ledger, receipt = build_trust_evidence_provider_state(tmp_path)

    assert ledger["records"] == []
    assert receipt["candidate_debts"] == []
    assert receipt["authority_record_count"] == 0
    assert receipt["negative_authority"] == "NONE"

    paths = write_trust_evidence_provider_state(tmp_path)
    before = {path.name: path.read_bytes() for path in paths}
    assert validate_trust_evidence_provider_state(tmp_path) == ()
    assert write_trust_evidence_provider_state(tmp_path) == paths
    assert before == {path.name: path.read_bytes() for path in paths}


def test_same_run_checkpoint_progress_does_not_stale_provider_authority(
    tmp_path: Path,
) -> None:
    """Bind the stable run identity, not mutable phase-progress bytes."""
    _checkpoint(tmp_path)
    _write_severity_state(tmp_path, [])
    write_trust_evidence_provider_state(tmp_path)
    checkpoint = tmp_path / "_v2_checkpoint.json"
    checkpoint.write_text(
        json.dumps({"run_id": RUN_ID, "completed": ["severity_adjudication_shadow"]})
        + "\n",
        encoding="utf-8",
    )

    assert validate_trust_evidence_provider_state(tmp_path) == ()
    _ledger, receipt = build_trust_evidence_provider_state(tmp_path)
    assert all(
        row["path"] != "_v2_checkpoint.json"
        for row in receipt["input_bindings"]
    )


def test_typed_trust_modifier_without_independent_authority_becomes_debt(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    decision = _trust_decision()
    _write_severity_state(tmp_path, [decision])
    source = tmp_path / f"verify_{FID}.md"
    source.write_text(
        "**Trust**: FULLY_TRUSTED\n"
        "**Trust Actor**: raw-prose-actor\n"
        "**Trust Capability**: raw-prose-capability\n"
        "**Trust Action Scope**: raw-prose-action\n"
        "**Trust Asset Scope**: raw-prose-asset\n",
        encoding="utf-8",
    )

    write_trust_evidence_provider_state(tmp_path)
    receipt = json.loads((tmp_path / PROVIDER_RECEIPT_FILE).read_text())
    assert receipt["authority_record_count"] == 0
    assert len(receipt["candidate_debts"]) == 1
    debt = receipt["candidate_debts"][0]
    assert debt["finding_id"] == FID
    assert set(debt["debt_codes"]) >= {
        "TRUST_INDEPENDENT_ADJUDICATION_MISSING",
        "TRUST_EXACT_SCOPE_AUTHORITY_UNAVAILABLE",
        "TRUST_EVIDENCE_PROVENANCE_UNAVAILABLE",
    }
    assert source.name not in {row["path"] for row in receipt["input_bindings"]}

    # An empty provider ledger changes MISSING into exact finding-local debt,
    # but can never authorize the demotion or PoC exemption.
    resolved = resolve_trust_evidence(
        tmp_path,
        finding_id=FID,
        source_artifact=source,
        actor="raw-prose-actor",
        capability="raw-prose-capability",
        action_scope="raw-prose-action",
        asset_scope="raw-prose-asset",
        run_id=RUN_ID,
    )
    assert resolved.authorized is False
    assert resolved.debts == ("TRUST_FINDING_UNBOUND",)


def test_raw_prose_never_creates_a_provider_candidate(tmp_path: Path) -> None:
    _checkpoint(tmp_path)
    _write_severity_state(tmp_path, [_trust_decision(trust_modifier=False)])
    (tmp_path / f"verify_{FID}.md").write_text(
        "FULLY_TRUSTED actor capability action asset\n", encoding="utf-8"
    )

    _ledger, receipt = build_trust_evidence_provider_state(tmp_path)
    assert receipt["candidate_debts"] == []
    assert all(not row["path"].endswith(".md") for row in receipt["input_bindings"])


def test_even_bound_severity_adjudication_cannot_fill_missing_trust_facts(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    decision = _synthetically_adjudicate(_trust_decision())
    _write_severity_state(tmp_path, [decision])

    ledger, receipt = build_trust_evidence_provider_state(tmp_path)
    assert ledger["records"] == []
    debt = receipt["candidate_debts"][0]
    assert "TRUST_EXACT_SCOPE_AUTHORITY_UNAVAILABLE" in debt["debt_codes"]
    assert "TRUST_EVIDENCE_PROVENANCE_UNAVAILABLE" in debt["debt_codes"]
    # A caller-authored launch mapping without the provider-owned worker-run
    # transaction is also not accepted as independent adjudication authority.
    assert "TRUST_ADJUDICATION_PROVIDER_RECEIPT_INVALID" in debt["debt_codes"]


def test_real_provider_owned_adjudication_remains_insufficient_trust_authority(
    tmp_path: Path,
) -> None:
    import severity_runtime
    from test_severity_adjudication_work_p0_ag3 import (
        RUN_ID as ADJUDICATION_RUN_ID,
        _execute_shard,
        _prepare,
    )

    _checkpoint(tmp_path, run_id=ADJUDICATION_RUN_ID)
    decision = _trust_decision(run_id=ADJUDICATION_RUN_ID)
    _write_severity_state(tmp_path, [decision])
    plan = _prepare(tmp_path)
    proposal = {
        "schema_version": "plamen.severity_adjudication_proposal.v1",
        "decision": "ACCEPT_PROPOSED",
        "resolved_severity": "Medium",
        "resolved_premise_ids": [f"PREM-L-{FID}"],
        "evidence_ids": [f"EVID-L-{FID}"],
        "proof_scope": "IN_SCOPE_SOURCE",
        "rationale": "Independent severity adjudication accepts the typed tier.",
        "resolved_axes": {"impact": "High", "likelihood": "Medium"},
        "constituent_resolutions": {},
    }
    worker_run = _execute_shard(
        tmp_path, plan, FID, proposals={FID: proposal}
    )
    shard = next(row for row in plan["shards"] if FID in row["candidate_ids"])
    intent = json.loads((tmp_path / shard["launch_intent_file"]).read_text())
    written, issues = severity_runtime.bind_shadow_adjudication_for_candidate(
        tmp_path,
        FID,
        backend=intent["backend"],
        launch_digest=worker_run["receipt_digest"],
        run_id=ADJUDICATION_RUN_ID,
        worker_identity=intent["worker_identity"],
        invocation_id=intent["invocation_id"],
    )
    assert written and not issues

    ledger, receipt = build_trust_evidence_provider_state(tmp_path)
    assert ledger["records"] == []
    debt = receipt["candidate_debts"][0]
    assert debt["adjudication_state"] == "PROVIDER_VALID_BUT_INSUFFICIENT"
    assert "TRUST_ADJUDICATION_PROVIDER_RECEIPT_INVALID" not in debt["debt_codes"]
    assert set(debt["debt_codes"]) >= {
        "TRUST_EXACT_SCOPE_AUTHORITY_UNAVAILABLE",
        "TRUST_EVIDENCE_PROVENANCE_UNAVAILABLE",
        "TRUST_MODIFIER_RESOLUTION_UNAVAILABLE",
    }
    assert receipt["authority_record_count"] == 0
    write_trust_evidence_provider_state(tmp_path)
    assert validate_trust_evidence_provider_state(tmp_path) == ()


def test_tampered_or_stale_severity_state_is_visible_global_debt(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    decision = _trust_decision()
    _write_severity_state(tmp_path, [decision])
    decision_path = tmp_path / f"verify_{FID}.severity_decision.json"
    payload = json.loads(decision_path.read_text())
    payload["proposed_severity"] = "Informational"
    decision_path.write_text(json.dumps(payload), encoding="utf-8")

    write_trust_evidence_provider_state(tmp_path)
    receipt = json.loads((tmp_path / PROVIDER_RECEIPT_FILE).read_text())
    assert receipt["authority_record_count"] == 0
    assert "TRUST_SEVERITY_STATE_INVALID" in receipt["global_debts"]
    assert validate_trust_evidence_provider_state(tmp_path) == ()

    # Rebinding only the checkpoint cannot make an old run authoritative.
    _checkpoint(tmp_path, run_id="new-run")
    _ledger, stale = build_trust_evidence_provider_state(tmp_path)
    assert stale["authority_record_count"] == 0
    assert "TRUST_SEVERITY_RUN_STALE" in stale["global_debts"]


def test_provider_receipt_tamper_is_detected_without_granting_authority(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    _write_severity_state(tmp_path, [_trust_decision()])
    write_trust_evidence_provider_state(tmp_path)
    path = tmp_path / PROVIDER_RECEIPT_FILE
    payload = json.loads(path.read_text())
    payload["authority_record_count"] = 9
    path.write_text(json.dumps(payload), encoding="utf-8")

    issues = validate_trust_evidence_provider_state(tmp_path)
    assert any("provider receipt" in issue.lower() for issue in issues)
    ledger = json.loads((tmp_path / "trust_evidence_authority.json").read_text())
    assert ledger["records"] == []


def test_provider_receipt_is_a_consume_side_sentinel_against_reauthored_ledger(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    _write_severity_state(tmp_path, [])
    write_trust_evidence_provider_state(tmp_path)

    source = tmp_path / f"verify_{FID}.md"
    source.write_text("typed source placeholder\n", encoding="utf-8")
    evidence = tmp_path / "user_scope_statement.json"
    evidence.write_text("{}\n", encoding="utf-8")
    scope = {
        "actor": "governance timelock",
        "capability": "replace runtime code",
        "action_scope": "replace protected runtime",
        "asset_scope": "protocol runtime integrity",
    }
    row = {
        "finding_id": FID,
        "run_id": RUN_ID,
        "source_artifact": source.name,
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "source_provider_id": "verifier-worker",
        **scope,
        "evidence_kind": "USER_SCOPE_STATEMENT",
        "evidence_path": evidence.name,
        "evidence_sha256": hashlib.sha256(evidence.read_bytes()).hexdigest(),
        "evidence_run_id": RUN_ID,
        "decision": "AUTHORIZED_TRUST_LIMITATION",
        "adjudicator_id": "adjudicator-worker",
        "adjudication_basis_digest": HEX_A,
    }
    row["record_digest"] = _digest(row)
    unsigned = {
        "schema_version": "plamen.trust_evidence_authority.v1",
        "authority": "INDEPENDENT_TRUST_ADJUDICATION",
        "run_id": RUN_ID,
        "producer_role": "independent_trust_adjudicator",
        "adjudicator_id": "adjudicator-worker",
        "records": [row],
    }
    unsigned["ledger_digest"] = _digest(unsigned)
    (tmp_path / "trust_evidence_authority.json").write_text(
        json.dumps(unsigned), encoding="utf-8"
    )

    result = resolve_trust_evidence(
        tmp_path,
        finding_id=FID,
        source_artifact=source,
        run_id=RUN_ID,
        **scope,
    )
    assert result.authorized is False
    assert result.debts == ("TRUST_LEDGER_TAMPERED",)


def test_haltless_ensure_reports_io_debt_and_never_grants_negative_authority(
    tmp_path: Path, monkeypatch
) -> None:
    import trust_evidence_provider as provider

    _checkpoint(tmp_path)
    _write_severity_state(tmp_path, [_trust_decision()])

    def _fail(_path: Path, _value: dict) -> None:
        raise OSError("synthetic read-only scratchpad")

    monkeypatch.setattr(provider, "_atomic_json", _fail)
    paths, issues = ensure_trust_evidence_provider_state(tmp_path)
    assert paths == ()
    assert any("write failed" in issue.lower() for issue in issues)
    assert not (tmp_path / "trust_evidence_authority.json").exists()
