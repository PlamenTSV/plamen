"""Adversarial P0-AG2/P0-P/P0-V/P0-U live-boundary fixtures.

This file is intentionally test-only.  The pure typed ledger already proves
many single-record policy properties; these fixtures define the next missing
runtime contract:

* every direction-neutral challenge is enumerated for a separately launched
  adjudicator;
* adjudicator content is bound to a driver-issued, distinct launch receipt;
* unavailable, malformed, partial, or conflicting adjudication remains
  visible at the upstream retention severity;
* report-index and report-writer output are mutable legacy projections, never
  severity authorities; and
* a digest-bound shadow-vs-legacy receipt makes every mismatch durable without
  mutating the legacy report during the shadow release.

Expected production surface (deliberately small):

``build_shadow_adjudication_manifest(scratchpad, *, run_id) -> dict``
    Reconcile the current shadow ledger and write an idempotent, digest-bound
    manifest containing every challenged decision.

``bind_shadow_adjudication_for_candidate(...) -> (written_paths, issues)``
    Bind one content-only proposal to a distinct driver launch and atomically
    refresh the candidate decision plus the aggregate shadow ledger.

``write_shadow_report_severity_receipt(scratchpad, *, run_id) -> dict``
    Compare report_index/tier-writer projections with the typed ledger and
    write an idempotent drift receipt.  This shadow function MUST NOT rewrite
    report_index.md or any report body.

The current implementation is expected to be red until those runtime hooks
exist.  Do not weaken these tests by falling back to legacy Markdown severity.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from typing import Any, Mapping

import pytest

import severity_runtime as runtime
import severity_adjudication_work as adjudication_work
from worker_execution_receipts import environment_allowlist_sha256
from severity_decision_ledger import (
    ADJUDICATION_PROPOSAL_SCHEMA,
    LAUNCH_RECEIPT_SCHEMA,
    PROPOSAL_SCHEMA,
    bind_severity_proposal,
    parse_severity_adjudication_proposal,
    severity_adjudicator_input_digest,
    severity_assessor_input_digest,
    write_severity_decision_ledger,
)


MANIFEST_SCHEMA = "plamen.severity_adjudication_manifest.v1"
REPORT_RECEIPT_SCHEMA = "plamen.severity_report_shadow_receipt.v1"


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _api(name: str):
    value = getattr(runtime, name, None)
    assert callable(value), (
        f"P0-AG2 runtime seam is absent: severity_runtime.{name} must be "
        "implemented without granting Markdown/report authority"
    )
    return value


def _severity_axes(severity: str) -> tuple[str, str]:
    return {
        "Critical": ("High", "High"),
        "High": ("High", "Medium"),
        "Medium": ("High", "Low"),
        "Low": ("Medium", "Low"),
        "Informational": ("Informational", "Low"),
    }[severity]


def _authoritative_decision(
    *,
    candidate_id: str = "H-101",
    upstream: str = "High",
    proposed: str = "Medium",
    constituents: tuple[str, ...] | None = None,
    outcomes: Mapping[str, Mapping[str, str]] | None = None,
    run_id: str = "run-ag2",
) -> dict[str, Any]:
    members = list(constituents or (candidate_id,))
    impact_class, likelihood_class = _severity_axes(proposed)
    proposal = {
        "schema_version": PROPOSAL_SCHEMA,
        "candidate_id": candidate_id,
        "constituent_ids": members,
        "impact": {
            "class": impact_class,
            "harmed_asset": "protected system value",
            "harmed_capability": "integrity of protected accounting",
            "premise_id": f"PREM-I-{candidate_id}",
            "premise_kind": "INTERNAL",
            "evidence_ids": [f"EVID-I-{candidate_id}"],
            "proof_scope": "IN_SCOPE_SOURCE",
        },
        "likelihood": {
            "class": likelihood_class,
            "actor": "unprivileged participant",
            "preconditions": ["reachable generic state"],
            "premise_id": f"PREM-L-{candidate_id}",
            "premise_kind": "INTERNAL",
            "evidence_ids": [f"EVID-L-{candidate_id}"],
            "proof_scope": "IN_SCOPE_SOURCE",
        },
        "modifiers": [],
        "proposed_severity": proposed,
        "adjustment": (
            None
            if proposed == upstream
            else {
                "direction": (
                    "UP"
                    if ("Critical", "High", "Medium", "Low", "Informational").index(proposed)
                    < ("Critical", "High", "Medium", "Low", "Informational").index(upstream)
                    else "DOWN"
                ),
                "premise_ids": [f"PREM-L-{candidate_id}"],
                "evidence_ids": [f"EVID-L-{candidate_id}"],
                "proof_scope": "IN_SCOPE_SOURCE",
                "rationale": "Typed likelihood premise changes the matrix tier.",
            }
        ),
        "constituent_premise_outcomes": dict(
            outcomes
            or {
                member: {"impact": "SUPPORTED", "likelihood": "SUPPORTED"}
                for member in members
            }
        ),
    }
    assessor_identity = f"verifier-claude-{candidate_id}"
    assessor_invocation = f"assessor-invocation-{candidate_id}"
    evidence = [
        {
            "evidence_id": f"EVID-I-{candidate_id}",
            "content_sha256": hashlib.sha256(
                f"impact:{candidate_id}".encode()
            ).hexdigest(),
            "premise_ids": [f"PREM-I-{candidate_id}"],
            "constituent_ids": members,
            "proof_scope": "IN_SCOPE_SOURCE",
            "capabilities": ["HARM", "IMPACT", "MECHANISM"],
            "issuer_identity": "plamen-driver-evidence-registry",
            "issuer_invocation_id": f"evidence-{candidate_id}",
        },
        {
            "evidence_id": f"EVID-L-{candidate_id}",
            "content_sha256": hashlib.sha256(
                f"likelihood:{candidate_id}".encode()
            ).hexdigest(),
            "premise_ids": [f"PREM-L-{candidate_id}"],
            "constituent_ids": members,
            "proof_scope": "IN_SCOPE_SOURCE",
            "capabilities": ["LIKELIHOOD", "MECHANISM"],
            "issuer_identity": "plamen-driver-evidence-registry",
            "issuer_invocation_id": f"evidence-{candidate_id}",
        },
    ]
    source_receipt = hashlib.sha256(f"source:{candidate_id}".encode()).hexdigest()
    launch_manifest = hashlib.sha256(f"assessor:{candidate_id}".encode()).hexdigest()
    launch_receipt = {
        "schema_version": LAUNCH_RECEIPT_SCHEMA,
        "role": "ASSESSOR",
        "run_id": run_id,
        "candidate_id": candidate_id,
        "constituent_ids": members,
        "worker_identity": assessor_identity,
        "invocation_id": assessor_invocation,
        "backend": "claude",
        "launch_manifest_sha256": launch_manifest,
        "input_sha256": severity_assessor_input_digest(
            candidate_id=candidate_id,
            constituent_ids=members,
            upstream_severity=upstream,
            run_id=run_id,
            source_receipt_digest=source_receipt,
            evidence_receipts=evidence,
        ),
        "output_sha256": _digest(proposal),
    }
    return bind_severity_proposal(
        proposal,
        candidate_id=candidate_id,
        constituent_ids=members,
        upstream_severity=upstream,
        assessor_identity=assessor_identity,
        assessor_invocation_id=assessor_invocation,
        run_id=run_id,
        source_receipt_digest=source_receipt,
        evidence_receipts=evidence,
        assessor_launch_receipt=launch_receipt,
    )


def _write_shadow_state(
    scratchpad: Path, decisions: list[Mapping[str, Any]], *, run_id: str = "run-ag2"
) -> Path:
    scratchpad.mkdir(parents=True, exist_ok=True)
    for decision in decisions:
        candidate_id = str(decision["candidate_id"])
        (scratchpad / f"verify_{candidate_id}.severity_decision.json").write_text(
            json.dumps(decision, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    ledger_path = scratchpad / runtime.SHADOW_LEDGER_NAME
    write_severity_decision_ledger(ledger_path, run_id, decisions)
    return ledger_path


def _adjudication_proposal(
    decision: Mapping[str, Any],
    *,
    resolved: str | None = None,
    adjudication_decision: str = "ACCEPT_PROPOSED",
    constituent_resolutions: Mapping[str, Mapping[str, str]] | None = None,
    rationale: str = "Independent evidence resolves the typed premise.",
) -> dict[str, Any]:
    severity = resolved or str(decision["proposed_severity"])
    impact_class, likelihood_class = _severity_axes(severity)
    candidate_id = str(decision["candidate_id"])
    return {
        "schema_version": ADJUDICATION_PROPOSAL_SCHEMA,
        "decision": adjudication_decision,
        "resolved_severity": severity,
        "resolved_premise_ids": [f"PREM-L-{candidate_id}"],
        "evidence_ids": [f"EVID-L-{candidate_id}"],
        "proof_scope": "IN_SCOPE_SOURCE",
        "rationale": rationale,
        "resolved_axes": {
            "impact": impact_class,
            "likelihood": likelihood_class,
        },
        "constituent_resolutions": dict(constituent_resolutions or {}),
    }


def _execute_observed_adjudicator(
    scratchpad: Path,
    candidate_id: str,
    proposal: Mapping[str, Any],
    *,
    run_id: str = "run-ag2",
    adjudicator_identity: str = "severity-adjudicator-claude",
    invocation_prefix: str = "severity-adjudication-invocation",
) -> dict[str, Any]:
    """Prepare and execute one genuinely observed single-candidate shard."""

    methodology_path = scratchpad / "severity-adjudication-methodology.fixture.md"
    methodology_bytes = b"# Direction-neutral severity adjudication\n"
    if methodology_path.exists():
        assert methodology_path.read_bytes() == methodology_bytes
    else:
        methodology_path.write_bytes(methodology_bytes)

    plan = adjudication_work.prepare_adjudication_work(
        scratchpad,
        run_id=run_id,
        audit_snapshot_digest=hashlib.sha256(b"fixture-audit-snapshot").hexdigest(),
        audit_config_digest=hashlib.sha256(b"fixture-audit-config").hexdigest(),
        methodology_files={"severity-adjudication": methodology_path},
        backend="fixture-subprocess",
        transport="headless-subprocess",
        effective_model="fixture-python",
        working_directory=scratchpad,
        tool_policy=["filesystem-write-assigned-staged-output-only"],
        environment_allowlist_digest=environment_allowlist_sha256(()),
        adjudicator_identity=adjudicator_identity,
        invocation_prefix=invocation_prefix,
        max_items_per_worker=1,
    )
    shards = [
        shard
        for shard in plan["shards"]
        if candidate_id in shard["candidate_ids"]
    ]
    assert len(shards) == 1
    shard = shards[0]
    assert shard["candidate_ids"] == [candidate_id]
    staged_path = (
        Path(str(shard["staging_output_scope"]))
        / str(shard["staged_outputs"][candidate_id])
    )
    raw = (
        json.dumps(
            proposal,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    script = "; ".join(
        (
            "from pathlib import Path",
            f"p=Path({str(staged_path)!r})",
            "p.parent.mkdir(parents=True, exist_ok=True)",
            f"p.write_bytes({raw!r})",
        )
    )
    worker_run = adjudication_work.execute_adjudication_worker(
        scratchpad,
        shard_id=str(shard["shard_id"]),
        argv=[sys.executable, "-c", script],
        environment={},
        environment_allowlist=(),
        timeout_seconds=30,
    )
    assert worker_run == adjudication_work.validate_completed_worker_run_for_candidate(
        scratchpad, candidate_id
    )
    return worker_run


def _bind(
    scratchpad: Path,
    candidate_id: str,
):
    worker_run = adjudication_work.validate_completed_worker_run_for_candidate(
        scratchpad, candidate_id
    )
    binder = _api("bind_shadow_adjudication_for_candidate")
    return binder(
        scratchpad,
        candidate_id,
        backend=str(worker_run["backend"]),
        launch_digest=str(worker_run["receipt_digest"]),
        run_id=str(worker_run["run_id"]),
        worker_identity=str(worker_run["worker_identity"]),
        invocation_id=str(worker_run["invocation_id"]),
    )


def _load_candidate_decision(scratchpad: Path, candidate_id: str) -> dict[str, Any]:
    return json.loads(
        (scratchpad / f"verify_{candidate_id}.severity_decision.json").read_text(
            encoding="utf-8"
        )
    )


def _rename_case_only(path: Path, new_name: str) -> Path:
    """Make a case-only ownership mutation portable on case-folding filesystems."""

    intermediate = path.with_name(f"{path.name}.case-mutation")
    path.rename(intermediate)
    target = path.with_name(new_name)
    intermediate.rename(target)
    return target


def _write_report_index(
    scratchpad: Path,
    *,
    report_id: str,
    candidate_id: str,
    severity: str,
) -> None:
    (scratchpad / "report_index.md").write_text(
        "## Master Finding Index\n\n"
        "| Report ID | Title | Severity | Trust Adjustment | Source Findings |\n"
        "|---|---|---|---|---|\n"
        f"| {report_id} | Generic retained claim | {severity} | None | {candidate_id} |\n",
        encoding="utf-8",
    )


def _receipt(scratchpad: Path) -> dict[str, Any]:
    writer = _api("write_shadow_report_severity_receipt")
    receipt = writer(scratchpad, run_id="run-ag2")
    assert receipt["schema_version"] == REPORT_RECEIPT_SCHEMA
    return receipt


def _events(receipt: Mapping[str, Any], candidate_id: str) -> list[Mapping[str, Any]]:
    return [
        event
        for event in receipt.get("drift_events", [])
        if event.get("candidate_id") == candidate_id
    ]


def test_manifest_enumerates_up_and_down_challenges_without_severity_filter(tmp_path):
    down = _authoritative_decision(candidate_id="H-101", upstream="High", proposed="Medium")
    up = _authoritative_decision(candidate_id="M-202", upstream="Medium", proposed="High")
    assert down["status"] == up["status"] == "CHALLENGE_REQUIRED"
    _write_shadow_state(tmp_path, [down, up])

    build = _api("build_shadow_adjudication_manifest")
    first = build(tmp_path, run_id="run-ag2")
    manifest_path = tmp_path / "severity_adjudication_manifest.shadow.json"
    first_bytes = manifest_path.read_bytes()
    second = build(tmp_path, run_id="run-ag2")

    assert first == second
    assert manifest_path.read_bytes() == first_bytes
    assert first["schema_version"] == MANIFEST_SCHEMA
    rows = {row["candidate_id"]: row for row in first["work_items"]}
    assert set(rows) == {"H-101", "M-202"}
    assert {rows[key]["direction"] for key in rows} == {"DOWN", "UP"}
    for candidate_id, decision in (("H-101", down), ("M-202", up)):
        assert rows[candidate_id]["source_decision_digest"] == decision["decision_digest"]
        assert rows[candidate_id]["input_sha256"] == severity_adjudicator_input_digest(decision)
        assert rows[candidate_id]["status"] == "PENDING"
        assert rows[candidate_id]["expected_output_file"] == (
            f"verify_{candidate_id}.severity_adjudication_proposal.json"
        )


@pytest.mark.parametrize(
    ("upstream", "proposed"),
    (("High", "Medium"), ("Medium", "High")),
)
def test_distinct_adjudicator_can_resolve_evidence_bound_change_in_both_directions(
    tmp_path, upstream, proposed
):
    decision = _authoritative_decision(upstream=upstream, proposed=proposed)
    _write_shadow_state(tmp_path, [decision])
    _execute_observed_adjudicator(
        tmp_path, "H-101", _adjudication_proposal(decision)
    )

    written, issues = _bind(tmp_path, "H-101")
    assert not issues
    assert written
    resolved = _load_candidate_decision(tmp_path, "H-101")
    assert resolved["status"] == "RESOLVED"
    assert resolved["final_severity"] == proposed
    event = resolved["adjudication"]
    assert event["adjudicator_identity"] != decision["assessment"]["assessor_identity"]
    assert event["adjudicator_invocation_id"] != decision["assessment"]["assessor_invocation_id"]
    assert event["adjudicator_authority_binding"]["status"] == "EXACT"
    assert event["resolved_premise_ids"]
    assert event["evidence_ids"]


def test_assessor_cannot_self_adjudicate_even_with_well_formed_content(tmp_path):
    decision = _authoritative_decision()
    _write_shadow_state(tmp_path, [decision])
    source = decision["assessment"]
    with pytest.raises(adjudication_work.AdjudicationWorkError):
        _execute_observed_adjudicator(
            tmp_path,
            "H-101",
            _adjudication_proposal(decision),
            adjudicator_identity=str(source["assessor_identity"]),
            invocation_prefix=str(source["assessor_invocation_id"]),
        )
    retained = _load_candidate_decision(tmp_path, "H-101")
    assert retained["status"] == "CHALLENGE_REQUIRED"
    assert retained["final_severity"] is None
    assert retained["retention_severity"] == "High"


def test_missing_or_malformed_adjudicator_is_haltless_visible_retention_debt(tmp_path):
    decision = _authoritative_decision()
    _write_shadow_state(tmp_path, [decision])
    _write_report_index(
        tmp_path,
        report_id="L-01",
        candidate_id="H-101",
        severity="Low",
    )

    receipt_without_worker = _receipt(tmp_path)
    row = next(row for row in receipt_without_worker["rows"] if row["candidate_id"] == "H-101")
    assert row["authorized_severity"] == "High"
    assert row["severity_status"] == "UNRESOLVED_SEVERITY"
    assert "H-101" in receipt_without_worker["unresolved_candidate_ids"]

    (tmp_path / "verify_H-101.severity_adjudication_proposal.json").write_text(
        '{"schema_version": "broken"}\n', encoding="utf-8"
    )
    binder = _api("bind_shadow_adjudication_for_candidate")
    _written, issues = binder(
        tmp_path,
        "H-101",
        backend="claude",
        launch_digest="0" * 64,
        run_id="run-ag2",
        worker_identity="unobserved-adjudicator",
        invocation_id="unobserved-invocation",
    )
    assert issues
    still_retained = _load_candidate_decision(tmp_path, "H-101")
    assert still_retained["retention_severity"] == "High"
    assert still_retained["final_severity"] is None


def test_conflicting_adjudicators_cannot_last_writer_win_and_resume_is_idempotent(tmp_path):
    decision = _authoritative_decision()
    _write_shadow_state(tmp_path, [decision])
    worker_run = _execute_observed_adjudicator(
        tmp_path, "H-101", _adjudication_proposal(decision)
    )
    proposal_path = tmp_path / "verify_H-101.severity_adjudication_proposal.json"
    first_written, first_issues = _bind(tmp_path, "H-101")
    assert not first_issues and first_written
    first_bytes = {
        path.name: path.read_bytes() for path in first_written if path.exists()
    }

    replay_written, replay_issues = _bind(tmp_path, "H-101")
    assert not replay_issues
    assert {
        path.name: path.read_bytes() for path in replay_written if path.exists()
    } == first_bytes
    replayed = _load_candidate_decision(tmp_path, "H-101")
    assert len(replayed["adjudication_history"]) == 1

    conflicting = _adjudication_proposal(
        replayed,
        resolved="High",
        adjudication_decision="ACCEPT_UPSTREAM",
        rationale="A second principal reaches a conflicting premise decision.",
    )
    proposal_path.write_text(
        json.dumps(conflicting, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    binder = _api("bind_shadow_adjudication_for_candidate")
    _written, issues = binder(
        tmp_path,
        "H-101",
        backend=str(worker_run["backend"]),
        launch_digest="f" * 64,
        run_id=str(worker_run["run_id"]),
        worker_identity="severity-adjudicator-claude-2",
        invocation_id="severity-adjudication-invocation-2",
    )
    conflicted = _load_candidate_decision(tmp_path, "H-101")
    assert issues
    assert not _written
    assert conflicted == replayed
    assert conflicted["status"] == "RESOLVED"
    assert conflicted["final_severity"] == "Medium"
    assert len(conflicted["adjudication_history"]) == 1


def test_grouped_partial_scope_cannot_flatten_unresolved_constituent(tmp_path):
    members = ("H-101", "M-102")
    decision = _authoritative_decision(
        constituents=members,
        outcomes={
            "H-101": {"impact": "SUPPORTED", "likelihood": "SUPPORTED"},
            "M-102": {"impact": "SUPPORTED", "likelihood": "UNRESOLVED"},
        },
    )
    _write_shadow_state(tmp_path, [decision])
    _execute_observed_adjudicator(
        tmp_path,
        "H-101",
        _adjudication_proposal(
            decision,
            constituent_resolutions={
                "H-101": {"impact": "SUPPORTED", "likelihood": "SUPPORTED"},
                "M-102": {"impact": "SUPPORTED", "likelihood": "UNRESOLVED"},
            },
        ),
    )
    _written, issues = _bind(tmp_path, "H-101")
    grouped = _load_candidate_decision(tmp_path, "H-101")
    assert issues or grouped["status"] == "UNRESOLVED_SEVERITY"
    assert grouped["status"] == "UNRESOLVED_SEVERITY"
    assert grouped["final_severity"] is None
    assert grouped["constituent_dispositions"]["M-102"]["disposition"] == (
        "RETAINED_UNRESOLVED"
    )
    assert grouped["constituent_dispositions"]["M-102"]["severity"] == "High"


@pytest.mark.parametrize(
    ("report_id", "observed_severity"),
    (("L-01", "Low"), ("C-01", "Critical")),
)
def test_report_index_cannot_author_tier_change_and_shadow_does_not_mutate_it(
    tmp_path, report_id, observed_severity
):
    decision = _authoritative_decision(upstream="High", proposed="High")
    assert decision["status"] == "RESOLVED"
    _write_shadow_state(tmp_path, [decision])
    _write_report_index(
        tmp_path,
        report_id=report_id,
        candidate_id="H-101",
        severity=observed_severity,
    )
    index_path = tmp_path / "report_index.md"
    before = index_path.read_bytes()

    receipt = _receipt(tmp_path)
    assert index_path.read_bytes() == before
    row = next(row for row in receipt["rows"] if row["candidate_id"] == "H-101")
    assert row["authorized_severity"] == "High"
    assert row["legacy_report_index_severity"] == observed_severity
    events = _events(receipt, "H-101")
    assert any(
        event["surface"] == "REPORT_INDEX"
        and event["observed_severity"] == observed_severity
        and event["authorized_severity"] == "High"
        for event in events
    )
    assert receipt["authority_status"] == "SHADOW_ONLY"


def test_report_writer_cannot_mutate_authorized_tier(tmp_path):
    decision = _authoritative_decision(upstream="High", proposed="High")
    _write_shadow_state(tmp_path, [decision])
    _write_report_index(
        tmp_path,
        report_id="H-01",
        candidate_id="H-101",
        severity="High",
    )
    body_path = tmp_path / "report_critical_high.md"
    body_path.write_text(
        "### [H-01] Generic retained claim\n\n"
        "**Severity**: Low\n\n"
        "**Impact**: Generic protected-value impact.\n",
        encoding="utf-8",
    )
    before_index = (tmp_path / "report_index.md").read_bytes()
    before_body = body_path.read_bytes()

    receipt = _receipt(tmp_path)
    assert (tmp_path / "report_index.md").read_bytes() == before_index
    assert body_path.read_bytes() == before_body
    assert receipt["legacy_artifact_sha256"]["report_critical_high.md"] == (
        hashlib.sha256(before_body).hexdigest()
    )
    events = _events(receipt, "H-101")
    assert any(
        event["surface"] == "REPORT_BODY"
        and event["observed_severity"] == "Low"
        and event["authorized_severity"] == "High"
        for event in events
    )


def test_shadow_vs_legacy_receipt_is_digest_bound_refreshable_and_idempotent(tmp_path):
    decision = _authoritative_decision(upstream="High", proposed="High")
    ledger_path = _write_shadow_state(tmp_path, [decision])
    _write_report_index(
        tmp_path,
        report_id="H-01",
        candidate_id="H-101",
        severity="High",
    )
    receipt_path = tmp_path / "severity_report_shadow_receipt.json"

    first = _receipt(tmp_path)
    first_bytes = receipt_path.read_bytes()
    second = _receipt(tmp_path)
    assert second == first
    assert receipt_path.read_bytes() == first_bytes
    assert first["severity_ledger_digest"] == json.loads(
        ledger_path.read_text(encoding="utf-8")
    )["ledger_digest"]
    assert first["report_index_sha256"] == hashlib.sha256(
        (tmp_path / "report_index.md").read_bytes()
    ).hexdigest()

    _write_report_index(
        tmp_path,
        report_id="M-01",
        candidate_id="H-101",
        severity="Medium",
    )
    refreshed = _receipt(tmp_path)
    assert refreshed["receipt_digest"] != first["receipt_digest"]
    assert refreshed["report_index_sha256"] != first["report_index_sha256"]
    assert _events(refreshed, "H-101")


def test_shadow_report_projection_never_drops_unresolved_identity_without_legacy_row(tmp_path):
    decision = _authoritative_decision()
    _write_shadow_state(tmp_path, [decision])
    (tmp_path / "report_index.md").write_text(
        "## Master Finding Index\n\n_No reportable rows._\n", encoding="utf-8"
    )

    receipt = _receipt(tmp_path)
    rows = {row["candidate_id"]: row for row in receipt["rows"]}
    assert "H-101" in rows
    assert rows["H-101"]["authorized_severity"] == "High"
    assert rows["H-101"]["severity_status"] == "UNRESOLVED_SEVERITY"
    assert "H-101" in receipt["unresolved_candidate_ids"]
    assert any(
        event["surface"] == "REPORT_INDEX"
        and event["drift_kind"] == "MISSING_LEGACY_PROJECTION"
        for event in _events(receipt, "H-101")
    )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("decision", True),
        ("resolved_severity", 7),
        ("resolved_premise_ids", [101]),
        ("evidence_ids", [False]),
        ("proof_scope", 9),
        ("rationale", 42),
        ("resolved_axes", {"impact": True, "likelihood": "Low"}),
        (
            "constituent_resolutions",
            {"H-101": {"impact": 1, "likelihood": "SUPPORTED"}},
        ),
    ),
)
def test_adjudication_model_schema_rejects_non_string_coercion(field, value):
    """Model JSON is a typed interface, not a ``str(value)`` compatibility path."""

    decision = _authoritative_decision()
    proposal = _adjudication_proposal(decision)
    proposal[field] = value
    with pytest.raises(Exception):
        parse_severity_adjudication_proposal(proposal)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("decision", "accept_proposed"),
        ("resolved_severity", "medium"),
        ("proof_scope", "in_scope_source"),
        ("resolved_axes", {"impact": "high", "likelihood": "low"}),
    ),
)
def test_adjudication_model_schema_rejects_case_normalization(field, value):
    """The emitted vocabulary must match the compiled closed enums exactly."""

    decision = _authoritative_decision()
    proposal = _adjudication_proposal(decision)
    proposal[field] = value
    with pytest.raises(Exception):
        parse_severity_adjudication_proposal(proposal)


def test_semantically_equal_but_byte_changed_adjudication_is_not_exact_replay(tmp_path):
    """A model output receipt binds bytes; JSON reformatting is a mutation."""

    decision = _authoritative_decision()
    _write_shadow_state(tmp_path, [decision])
    proposal = _adjudication_proposal(decision)
    worker_run = _execute_observed_adjudicator(tmp_path, "H-101", proposal)
    proposal_path = tmp_path / "verify_H-101.severity_adjudication_proposal.json"
    written, issues = _bind(tmp_path, "H-101")
    assert not issues and written
    governed = {
        path.name: path.read_bytes()
        for path in written
        if path.name != proposal_path.name and path.exists()
    }

    # Same object and canonical digest, different exact worker output bytes.
    proposal_path.write_text(
        json.dumps(proposal, ensure_ascii=False, sort_keys=False) + "\n\n",
        encoding="utf-8",
    )
    binder = _api("bind_shadow_adjudication_for_candidate")
    replay_written, replay_issues = binder(
        tmp_path,
        "H-101",
        backend=str(worker_run["backend"]),
        launch_digest=str(worker_run["receipt_digest"]),
        run_id=str(worker_run["run_id"]),
        worker_identity=str(worker_run["worker_identity"]),
        invocation_id=str(worker_run["invocation_id"]),
    )
    assert replay_issues
    assert not replay_written
    assert {
        path.name: path.read_bytes()
        for path in written
        if path.name in governed and path.exists()
    } == governed


def test_decision_written_ledger_missing_partial_transaction_repairs_on_resume(
    tmp_path, monkeypatch
):
    """A crash after the candidate write must not permanently brick AG2."""

    decision = _authoritative_decision()
    _write_shadow_state(tmp_path, [decision])
    _execute_observed_adjudicator(
        tmp_path, "H-101", _adjudication_proposal(decision)
    )
    original_refresh = runtime._refresh_shadow_ledger
    calls = 0

    def fail_first_refresh(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("fixture crash between decision and aggregate ledger")
        return original_refresh(*args, **kwargs)

    monkeypatch.setattr(runtime, "_refresh_shadow_ledger", fail_first_refresh)
    _written, issues = _bind(tmp_path, "H-101")
    assert issues
    assert _load_candidate_decision(tmp_path, "H-101")["status"] == "RESOLVED"

    monkeypatch.setattr(runtime, "_refresh_shadow_ledger", original_refresh)
    repaired, repair_issues = _bind(tmp_path, "H-101")
    assert not repair_issues
    assert repaired
    final = _load_candidate_decision(tmp_path, "H-101")
    assert final["status"] == "RESOLVED"
    assert len(final["adjudication_history"]) == 1
    ledger = json.loads((tmp_path / runtime.SHADOW_LEDGER_NAME).read_text(encoding="utf-8"))
    assert ledger["decisions"][0] == final


def test_ledger_written_receipt_missing_partial_transaction_repairs_on_resume(
    tmp_path, monkeypatch
):
    """The opposite partial-write direction is expected to remain repairable."""

    decision = _authoritative_decision()
    _write_shadow_state(tmp_path, [decision])
    _execute_observed_adjudicator(
        tmp_path, "H-101", _adjudication_proposal(decision)
    )
    original_atomic = runtime._atomic_json
    failed = False

    def fail_receipt_once(path, value):
        nonlocal failed
        if path.name.endswith(".severity_adjudication_receipt.json") and not failed:
            failed = True
            raise OSError("fixture crash before standalone receipt")
        return original_atomic(path, value)

    monkeypatch.setattr(runtime, "_atomic_json", fail_receipt_once)
    _written, issues = _bind(tmp_path, "H-101")
    assert issues
    monkeypatch.setattr(runtime, "_atomic_json", original_atomic)
    repaired, repair_issues = _bind(tmp_path, "H-101")
    assert not repair_issues and repaired
    assert (tmp_path / "verify_H-101.severity_adjudication_receipt.json").is_file()
    assert len(_load_candidate_decision(tmp_path, "H-101")["adjudication_history"]) == 1


def test_receipt_written_decision_missing_partial_transaction_repairs_on_resume(
    tmp_path, monkeypatch
):
    """Receipt-first commit must recover if the next candidate write crashes."""

    decision = _authoritative_decision()
    _write_shadow_state(tmp_path, [decision])
    _execute_observed_adjudicator(
        tmp_path, "H-101", _adjudication_proposal(decision)
    )
    original_atomic = runtime._atomic_json
    failed = False

    def fail_decision_once(path, value):
        nonlocal failed
        if path.name.endswith(".severity_decision.json") and not failed:
            failed = True
            raise OSError("fixture crash after receipt and before decision")
        return original_atomic(path, value)

    monkeypatch.setattr(runtime, "_atomic_json", fail_decision_once)
    _written, issues = _bind(tmp_path, "H-101")
    assert issues
    assert (tmp_path / "verify_H-101.severity_adjudication_receipt.json").is_file()
    assert _load_candidate_decision(tmp_path, "H-101")["status"] == "CHALLENGE_REQUIRED"

    monkeypatch.setattr(runtime, "_atomic_json", original_atomic)
    repaired, repair_issues = _bind(tmp_path, "H-101")
    assert not repair_issues and repaired
    assert _load_candidate_decision(tmp_path, "H-101")["status"] == "RESOLVED"
    assert len(_load_candidate_decision(tmp_path, "H-101")["adjudication_history"]) == 1


def test_post_adjudication_proposal_mutation_invalidates_report_shadow_authority(tmp_path):
    decision = _authoritative_decision()
    _write_shadow_state(tmp_path, [decision])
    proposal = _adjudication_proposal(decision)
    _execute_observed_adjudicator(tmp_path, "H-101", proposal)
    proposal_path = tmp_path / "verify_H-101.severity_adjudication_proposal.json"
    written, issues = _bind(tmp_path, "H-101")
    assert not issues and written
    _write_report_index(
        tmp_path, report_id="M-01", candidate_id="H-101", severity="Medium"
    )

    proposal["rationale"] = "Valid-looking but post-bind replacement bytes."
    proposal_path.write_text(json.dumps(proposal), encoding="utf-8")
    with pytest.raises(Exception):
        runtime.write_shadow_report_severity_receipt(tmp_path, run_id="run-ag2")


@pytest.mark.parametrize("mutation", ("missing", "digest-valid-wrong-result"))
def test_standalone_adjudication_receipt_is_required_report_authority(
    tmp_path, mutation
):
    decision = _authoritative_decision()
    _write_shadow_state(tmp_path, [decision])
    _execute_observed_adjudicator(
        tmp_path, "H-101", _adjudication_proposal(decision)
    )
    written, issues = _bind(tmp_path, "H-101")
    assert not issues and written
    receipt_path = tmp_path / "verify_H-101.severity_adjudication_receipt.json"
    if mutation == "missing":
        receipt_path.unlink()
    else:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["result_decision_digest"] = "0" * 64
        unsigned = {key: value for key, value in receipt.items() if key != "receipt_digest"}
        receipt["receipt_digest"] = _digest(unsigned)
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    _write_report_index(
        tmp_path, report_id="M-01", candidate_id="H-101", severity="Medium"
    )
    with pytest.raises(Exception):
        runtime.write_shadow_report_severity_receipt(tmp_path, run_id="run-ag2")


@pytest.mark.parametrize(
    "artifact",
    ("provider-completion", "provider-publish", "worker-run"),
)
@pytest.mark.parametrize("mutation", ("missing", "tampered"))
def test_provider_owned_worker_authority_is_replayed_at_report_boundary(
    tmp_path, artifact, mutation
):
    decision = _authoritative_decision()
    _write_shadow_state(tmp_path, [decision])
    worker_run = _execute_observed_adjudicator(
        tmp_path, "H-101", _adjudication_proposal(decision)
    )
    written, issues = _bind(tmp_path, "H-101")
    assert not issues and written
    _write_report_index(
        tmp_path, report_id="M-01", candidate_id="H-101", severity="Medium"
    )

    if artifact == "provider-completion":
        authority_path = tmp_path / str(worker_run["provider_completion_file"])
    elif artifact == "provider-publish":
        authority_path = tmp_path / str(worker_run["provider_publish_file"])
    else:
        matches = list(tmp_path.glob("severity_adjudication_worker_run.*.json"))
        assert len(matches) == 1
        authority_path = matches[0]
    assert authority_path.is_file()
    if mutation == "missing":
        authority_path.unlink()
    else:
        value = json.loads(authority_path.read_text(encoding="utf-8"))
        value["schema_version"] = "plamen.fixture.tampered.v0"
        authority_path.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(Exception):
        runtime.write_shadow_report_severity_receipt(tmp_path, run_id="run-ag2")


def test_report_index_explicit_severity_cannot_hide_behind_report_id_prefix(tmp_path):
    """The semantic Severity cell and the routing prefix must both reconcile."""

    decision = _authoritative_decision(upstream="High", proposed="High")
    _write_shadow_state(tmp_path, [decision])
    _write_report_index(
        tmp_path, report_id="H-01", candidate_id="H-101", severity="Low"
    )
    receipt = _receipt(tmp_path)
    assert any(
        event["surface"] == "REPORT_INDEX"
        and event["observed_severity"] == "Low"
        and event["drift_kind"] == "UNAUTHORIZED_TIER_MUTATION"
        for event in _events(receipt, "H-101")
    )


def test_duplicate_candidate_report_index_mappings_are_ambiguous_not_last_writer_wins(
    tmp_path,
):
    decision = _authoritative_decision(upstream="High", proposed="High")
    _write_shadow_state(tmp_path, [decision])
    (tmp_path / "report_index.md").write_text(
        "## Master Finding Index\n\n"
        "| Report ID | Title | Severity | Source Findings |\n"
        "|---|---|---|---|\n"
        "| H-01 | First route | High | H-101 |\n"
        "| L-01 | Contradictory route | Low | h-101 |\n",
        encoding="utf-8",
    )
    before = (tmp_path / "report_index.md").read_bytes()
    receipt = _receipt(tmp_path)
    assert (tmp_path / "report_index.md").read_bytes() == before
    assert any(
        event["surface"] == "REPORT_INDEX"
        and event["drift_kind"] == "AMBIGUOUS_LEGACY_MAPPING"
        for event in _events(receipt, "H-101")
    )


def test_duplicate_report_id_for_distinct_candidates_is_not_silently_discarded(tmp_path):
    first = _authoritative_decision(
        candidate_id="H-101", upstream="High", proposed="High"
    )
    second = _authoritative_decision(
        candidate_id="M-202", upstream="High", proposed="High"
    )
    _write_shadow_state(tmp_path, [first, second])
    (tmp_path / "report_index.md").write_text(
        "## Master Finding Index\n\n"
        "| Report ID | Title | Severity | Source Findings |\n"
        "|---|---|---|---|\n"
        "| H-01 | First | High | H-101 |\n"
        "| H-01 | Second | High | M-202 |\n",
        encoding="utf-8",
    )
    receipt = _receipt(tmp_path)
    collisions = [
        event
        for event in receipt["drift_events"]
        if event["surface"] == "REPORT_INDEX"
        and event["drift_kind"] == "AMBIGUOUS_LEGACY_MAPPING"
    ]
    assert {event["candidate_id"] for event in collisions} == {"H-101", "M-202"}


def test_duplicate_report_body_sections_are_ambiguous_even_if_one_tier_matches(tmp_path):
    decision = _authoritative_decision(upstream="High", proposed="High")
    _write_shadow_state(tmp_path, [decision])
    _write_report_index(
        tmp_path, report_id="H-01", candidate_id="H-101", severity="High"
    )
    body = tmp_path / "report_critical_high.md"
    body.write_text(
        "### [H-01] First projection\n\n**Severity**: High\n\n"
        "### [H-01] Conflicting projection\n\n**Severity**: Low\n",
        encoding="utf-8",
    )
    before = body.read_bytes()
    receipt = _receipt(tmp_path)
    assert body.read_bytes() == before
    assert any(
        event["surface"] == "REPORT_BODY"
        and event["drift_kind"] == "AMBIGUOUS_LEGACY_MAPPING"
        for event in _events(receipt, "H-101")
    )


def test_report_body_missing_severity_is_visible_drift_not_silent_absence(tmp_path):
    decision = _authoritative_decision(upstream="High", proposed="High")
    _write_shadow_state(tmp_path, [decision])
    _write_report_index(
        tmp_path, report_id="H-01", candidate_id="H-101", severity="High"
    )
    (tmp_path / "report_critical_high.md").write_text(
        "### [H-01] Missing typed tier\n\n**Impact**: Generic material impact.\n",
        encoding="utf-8",
    )
    receipt = _receipt(tmp_path)
    assert any(
        event["surface"] == "REPORT_BODY"
        and event["drift_kind"] == "MISSING_SEVERITY"
        for event in _events(receipt, "H-101")
    )


def test_wrong_case_report_index_filename_is_rejected_without_mutation(tmp_path):
    decision = _authoritative_decision(upstream="High", proposed="High")
    _write_shadow_state(tmp_path, [decision])
    path = tmp_path / "REPORT_INDEX.MD"
    path.write_text(
        "## Master Finding Index\n\n"
        "| Report ID | Title | Severity | Source Findings |\n"
        "|---|---|---|---|\n"
        "| H-01 | Generic | High | H-101 |\n",
        encoding="utf-8",
    )
    before = path.read_bytes()
    with pytest.raises(Exception):
        runtime.write_shadow_report_severity_receipt(tmp_path, run_id="run-ag2")
    assert path.read_bytes() == before


def test_wrong_case_report_body_filename_is_rejected_without_mutation(tmp_path):
    decision = _authoritative_decision(upstream="High", proposed="High")
    _write_shadow_state(tmp_path, [decision])
    _write_report_index(
        tmp_path, report_id="H-01", candidate_id="H-101", severity="High"
    )
    path = tmp_path / "REPORT_CRITICAL_HIGH.MD"
    path.write_text(
        "### [H-01] Generic projection\n\n**Severity**: High\n",
        encoding="utf-8",
    )
    before = path.read_bytes()
    with pytest.raises(Exception):
        runtime.write_shadow_report_severity_receipt(tmp_path, run_id="run-ag2")
    assert path.read_bytes() == before


def test_wrong_case_shadow_ledger_filename_is_rejected_as_authority(tmp_path):
    decision = _authoritative_decision()
    ledger = _write_shadow_state(tmp_path, [decision])
    mutated = _rename_case_only(ledger, runtime.SHADOW_LEDGER_NAME.upper())
    before = mutated.read_bytes()
    with pytest.raises(Exception):
        runtime.build_shadow_adjudication_manifest(tmp_path, run_id="run-ag2")
    assert mutated.read_bytes() == before


def test_wrong_case_candidate_decision_filename_is_rejected_as_authority(tmp_path):
    decision = _authoritative_decision()
    _write_shadow_state(tmp_path, [decision])
    canonical = tmp_path / "verify_H-101.severity_decision.json"
    mutated = _rename_case_only(canonical, "VERIFY_H-101.SEVERITY_DECISION.JSON")
    before = mutated.read_bytes()
    with pytest.raises(Exception):
        runtime.build_shadow_adjudication_manifest(tmp_path, run_id="run-ag2")
    assert mutated.read_bytes() == before


@pytest.mark.parametrize(
    "source_mutation",
    ("delete-verifier-receipt", "replace-verifier-proposal", "replace-verifier-markdown"),
)
def test_report_shadow_revalidates_original_verifier_source_transaction(
    tmp_path, monkeypatch, source_mutation
):
    """The aggregate ledger cannot nominate its own expected source digests."""

    import plamen_parsers as parsers
    import plamen_validators as validators
    from test_severity_live_sidecar_adversarial_review_p0_ag1 import (
        Backend,
        LAUNCH_DIGEST,
        _ignore_poc_gate,
        _policy,
        _prevalidate,
        _setup_plan,
        _write_owned_pair,
    )

    scratchpad, phase_name, items, _plan = _setup_plan(tmp_path)
    proposal_path = _write_owned_pair(scratchpad, items[0])
    _ignore_poc_gate(monkeypatch)
    assert _prevalidate(scratchpad, phase_name) == []
    validators._persist_verifier_output_receipts(
        scratchpad,
        phase_name,
        execution_policy=_policy("sc", Backend.CLAUDE),
        launch_digest=LAUNCH_DIGEST,
    )
    written, issues = runtime.bind_shadow_severity_for_shard(
        scratchpad,
        phase_name,
        backend="claude",
        launch_digest=LAUNCH_DIGEST,
        run_id="run-live-source",
    )
    assert not issues and written
    assert parsers.read_queue_work_plan(scratchpad).shard(phase_name)
    _write_report_index(
        scratchpad, report_id="H-01", candidate_id="H-01", severity="High"
    )

    if source_mutation == "delete-verifier-receipt":
        (scratchpad / "verify_H-01.receipt.json").unlink()
    elif source_mutation == "replace-verifier-proposal":
        proposal = json.loads(proposal_path.read_text(encoding="utf-8"))
        proposal["impact"]["harmed_asset"] = "post-bind replacement"
        proposal_path.write_text(json.dumps(proposal), encoding="utf-8")
    else:
        (scratchpad / "verify_H-01.md").write_text(
            "# post-bind replacement verifier bytes\n", encoding="utf-8"
        )

    with pytest.raises(Exception):
        runtime.write_shadow_report_severity_receipt(
            scratchpad, run_id="run-live-source"
        )


def test_adjudication_binding_revalidates_original_verifier_source_transaction(
    tmp_path, monkeypatch
):
    """A stale AG-1 ledger cannot authorize a new AG-2 state transition."""

    import plamen_validators as validators
    from test_severity_live_sidecar_adversarial_review_p0_ag1 import (
        Backend,
        LAUNCH_DIGEST,
        _ignore_poc_gate,
        _policy,
        _prevalidate,
        _setup_plan,
        _write_owned_pair,
    )

    scratchpad, phase_name, items, _plan = _setup_plan(tmp_path)
    _write_owned_pair(scratchpad, items[0])
    _ignore_poc_gate(monkeypatch)
    assert _prevalidate(scratchpad, phase_name) == []
    validators._persist_verifier_output_receipts(
        scratchpad,
        phase_name,
        execution_policy=_policy("sc", Backend.CLAUDE),
        launch_digest=LAUNCH_DIGEST,
    )
    written, issues = runtime.bind_shadow_severity_for_shard(
        scratchpad,
        phase_name,
        backend="claude",
        launch_digest=LAUNCH_DIGEST,
        run_id="run-live-source",
    )
    assert not issues and written
    decision_path = scratchpad / "verify_H-01.severity_decision.json"
    decision = json.loads(decision_path.read_text(encoding="utf-8"))
    assessment = decision["assessment"]
    proposal = {
        "schema_version": ADJUDICATION_PROPOSAL_SCHEMA,
        "decision": "ACCEPT_MATRIX",
        "resolved_severity": "Critical",
        "resolved_premise_ids": [
            assessment["impact"]["premise_id"],
            assessment["likelihood"]["premise_id"],
        ],
        "evidence_ids": sorted(
            {
                *assessment["impact"]["evidence_ids"],
                *assessment["likelihood"]["evidence_ids"],
            }
        ),
        "proof_scope": "IN_SCOPE_EXECUTION",
        "rationale": "Independent adjudication must not outlive its source transaction.",
        "resolved_axes": {"impact": "High", "likelihood": "High"},
        "constituent_resolutions": {},
    }
    worker_run = _execute_observed_adjudicator(
        scratchpad,
        "H-01",
        proposal,
        run_id="run-live-source",
        adjudicator_identity="independent-severity-adjudicator",
        invocation_prefix="independent-severity-adjudication",
    )
    before = decision_path.read_bytes()
    (scratchpad / "verify_H-01.receipt.json").unlink()

    rebound, bind_issues = runtime.bind_shadow_adjudication_for_candidate(
        scratchpad,
        "H-01",
        backend=str(worker_run["backend"]),
        launch_digest=str(worker_run["receipt_digest"]),
        run_id=str(worker_run["run_id"]),
        worker_identity=str(worker_run["worker_identity"]),
        invocation_id=str(worker_run["invocation_id"]),
    )
    assert bind_issues
    assert not rebound
    assert decision_path.read_bytes() == before
    assert not (
        scratchpad / "verify_H-01.severity_adjudication_receipt.json"
    ).exists()
