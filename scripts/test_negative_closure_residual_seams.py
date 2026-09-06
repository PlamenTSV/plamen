"""Adversarial fixtures for residual in-process negative self-certification seams."""

from __future__ import annotations

import inspect
from pathlib import Path

import closure_broker_v2 as C
import compound_verification as CV
import finding_lifecycle_authority as FL
import report_disposition_authority as R
import test_report_disposition_authority_p0_r as RT
from test_compound_negative_authority_nc5 import _candidate, _refutation
from test_negative_closure_broker_live_cutover import (
    _materialize_exhaustive_provider_bundle,
)


def _authorized_report_lifecycle(tmp_path: Path):
    scratchpad, _project, item, _original = RT._setup(
        tmp_path, status="REFUTED", disposition="BODY"
    )
    supporting = R.build_report_disposition_authority(
        scratchpad, run_id=RT.RUN_ID
    )
    candidate = supporting["finding_lifecycle"]["source_records"]["candidates"][0]
    candidate_bytes = C.canonical_json_bytes(
        {
            "candidate_id": candidate["candidate_id"],
            "lineage_ids": candidate["lineage_ids"],
            "source_record_sha256": candidate["source_record_sha256"],
            "upstream_severity": candidate["upstream_severity"],
            "title": candidate["title"],
            "location": candidate["location"],
            "evidence_pointer": candidate["evidence_pointer"],
        }
    )
    work = {
        "work_item_id": item.work_item_id,
        "candidate_id": item.work_item_id,
        "candidate_premise_ids": ["PREM-REPORT-FULL"],
        "producer_identities": [candidate["producer_identity"]],
        "producer_invocation_ids": [candidate["producer_invocation_id"]],
    }
    _materialize_exhaustive_provider_bundle(
        scratchpad,
        work_item=work,
        candidate_content=candidate_bytes,
    )
    central = C.write_central_negative_closure_authority(scratchpad)
    index = (scratchpad / "report_index.md").read_text(encoding="utf-8")
    index = index.replace(
        f"| M-01 | {item.title} | Medium | {item.work_item_id} |\n", ""
    ).replace(
        "|---|---|---|\n",
        "|---|---|---|\n"
        f"| {item.work_item_id} | Medium | central exhaustive refutation |\n",
        1,
    )
    (scratchpad / "report_index.md").write_text(index, encoding="utf-8")
    authority = R.build_report_disposition_authority(
        scratchpad, run_id=RT.RUN_ID
    )
    return scratchpad, central, authority["finding_lifecycle"]


def test_lifecycle_embedded_closure_is_nonterminal_without_current_replay(
    tmp_path: Path,
) -> None:
    _scratchpad, central, authorized = _authorized_report_lifecycle(tmp_path)
    source = authorized["source_records"]

    caller_rebuilt = FL.build_finding_lifecycle(
        run_id=authorized["run_id"],
        candidates=source["candidates"],
        decisions=source["decisions"],
        projections=source["projections"],
        closure_decisions=source["closure_decisions"],
        authority_identity="caller-controlled-lifecycle",
        authority_invocation_id="caller-controlled-invocation",
    )

    assert caller_rebuilt["candidate_states"][0]["delivery_state"] == "PENDING_BODY"
    assert caller_rebuilt["candidate_states"][0]["terminal_complete"] is False
    assert caller_rebuilt["rejected_decisions"][0]["reason"] == (
        "REFUTATION_REQUIRES_TYPED_EXHAUSTIVE_NEGATIVE_AUTHORITY"
    )
    # A code-owned, root-bound resolver can reproduce the terminal state.
    assert FL.validate_finding_lifecycle(
        authorized, closure_authority=central
    ) == authorized


def test_lifecycle_authorized_bytes_cannot_be_consumed_without_current_replay(
    tmp_path: Path,
) -> None:
    _scratchpad, _central, authorized = _authorized_report_lifecycle(tmp_path)

    try:
        replayed = FL.validate_finding_lifecycle(authorized)
    except FL.FindingLifecycleError:
        return
    assert replayed["candidate_states"][0]["terminal_complete"] is False


def test_lifecycle_current_provider_drift_invalidates_terminal_bytes(
    tmp_path: Path,
) -> None:
    scratchpad, central, authorized = _authorized_report_lifecycle(tmp_path)
    (scratchpad / "closure-inputs/candidate.bin").write_bytes(b"drift")

    try:
        replayed = FL.validate_finding_lifecycle(
            authorized, closure_authority=central
        )
    except FL.FindingLifecycleError:
        return
    assert replayed["candidate_states"][0]["terminal_complete"] is False


def test_compound_manual_closure_mapping_never_authorizes_exclusion(
    tmp_path: Path,
) -> None:
    candidate = _candidate()
    evidence = _refutation(candidate)
    work_item = CV.compile_compound_work_plan(
        (candidate,), candidate.constituents
    ).work_items[0]
    provider_work = {
        "work_item_id": work_item.verification_identity,
        "candidate_id": candidate.chain_id,
        "candidate_premise_ids": ["PREM-COMPOSITION", "PREM-HARM"],
        "producer_identities": ["COMPOSITION-PRODUCER"],
        "producer_invocation_ids": ["COMPOSITION-PRODUCER-INVOCATION"],
    }
    _materialize_exhaustive_provider_bundle(
        tmp_path,
        work_item=provider_work,
        candidate_content=C.canonical_json_bytes(candidate.to_record()),
    )
    central = C.write_central_negative_closure_authority(tmp_path)
    result = CV.evaluate_compound_work_item(
        candidate,
        work_item,
        (evidence,),
        {identity: "CONFIRMED" for identity in candidate.constituents},
        closure_authority=central,
    )
    binding = CV.bind_compound_report(
        candidate,
        result,
        evidence=(evidence,),
        closure_authority=central,
    )
    decision = C.resolve_central_negative_closure(
        central,
        work_item={
            "candidate_id": candidate.chain_id,
            "work_item_id": work_item.verification_identity,
            "candidate_content_sha256": candidate.digest,
        },
        requested_effect=C.REFUTED_FULL,
    )

    issues = CV.validate_compound_report_bindings(
        (binding,), closure_decisions=(decision,)
    )
    assert any(issue.code == "UNAUTHORIZED_NEGATIVE_CLOSURE" for issue in issues)
    assert CV.validate_compound_report_bindings(
        (binding,), closure_authority=central
    ) == ()


def test_compound_validation_replays_current_files_not_binding_hashes(
    tmp_path: Path,
) -> None:
    candidate = _candidate()
    evidence = _refutation(candidate)
    work_item = CV.compile_compound_work_plan(
        (candidate,), candidate.constituents
    ).work_items[0]
    provider_work = {
        "work_item_id": work_item.verification_identity,
        "candidate_id": candidate.chain_id,
        "candidate_premise_ids": ["PREM-COMPOSITION", "PREM-HARM"],
        "producer_identities": ["COMPOSITION-PRODUCER"],
        "producer_invocation_ids": ["COMPOSITION-PRODUCER-INVOCATION"],
    }
    _materialize_exhaustive_provider_bundle(
        tmp_path,
        work_item=provider_work,
        candidate_content=C.canonical_json_bytes(candidate.to_record()),
    )
    central = C.write_central_negative_closure_authority(tmp_path)
    result = CV.evaluate_compound_work_item(
        candidate,
        work_item,
        (evidence,),
        {identity: "CONFIRMED" for identity in candidate.constituents},
        closure_authority=central,
    )
    binding = CV.bind_compound_report(
        candidate,
        result,
        evidence=(evidence,),
        closure_authority=central,
    )
    (tmp_path / "closure-inputs/candidate.bin").write_bytes(b"drift")

    issues = CV.validate_compound_report_bindings(
        (binding,), closure_authority=central
    )
    assert any(issue.code == "UNAUTHORIZED_NEGATIVE_CLOSURE" for issue in issues)


def test_residual_consumers_have_no_mapping_only_terminal_path() -> None:
    lifecycle_source = inspect.getsource(FL._current_replayed_closure_decisions)
    lifecycle_validate_source = inspect.getsource(FL.validate_finding_lifecycle)
    compound_source = inspect.getsource(CV.validate_compound_report_bindings)
    report_source = inspect.getsource(R.build_report_disposition_authority)

    assert "resolve_central_negative_closure" in lifecycle_source
    assert "closure_authority=closure_authority" in lifecycle_validate_source
    assert "resolve_central_negative_closure" in compound_source
    assert "closure_by_digest" not in compound_source
    assert "closure_authority=closure_authority" in report_source
