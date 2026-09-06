"""Live central negative-closure broker cutover contracts.

The terminal-positive fixture is built through the real provider-owned worker
execution substrate in the focused integration suite below; these source-only
tests pin the fail-closed public boundary before the provider fixture is armed.
"""
from __future__ import annotations

import base64
import hashlib
import inspect
import json
from pathlib import Path
import sys

import closure_broker_v2 as C
import application_skeptic as A
import candidate_negative_authority as N
import inventory_reconciliation as I
import negative_closure_policy as P
import pytest
import semantic_dedup_authority as S
import report_disposition_authority as R
import test_report_disposition_authority_p0_r as RT
import test_compound_negative_authority_nc5 as CT
import compound_verification as CV
import finding_lifecycle_authority as FL
import plamen_driver as D
import severity_decision_ledger as SDL
import worker_execution_receipts as W


def _work() -> dict[str, object]:
    return {
        "work_item_id": "WORK-1",
        "candidate_id": "CAND-1",
        "candidate_premise_ids": ["PREM-HARM", "PREM-MECHANISM"],
        "producer_identities": ["SOURCE-WORKER"],
        "producer_invocation_ids": ["SOURCE-INVOCATION"],
    }


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _digested(value: dict[str, object], field: str) -> dict[str, object]:
    row = dict(value)
    row[field] = _sha(C.canonical_json_bytes(value))
    return row


def _write(root: Path, relative: str, raw: bytes) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return path


def _materialize_exhaustive_provider_bundle(
    root: Path,
    *,
    source_producer: str | None = None,
    work_item: dict[str, object] | None = None,
    candidate_content: bytes = b"canonical candidate bytes",
    register: bool = True,
    authority_kind: str = "AUTHENTICATED_EXHAUSTIVE_NEGATIVE_EXECUTION",
) -> tuple[dict[str, object], W.CompletedExecution]:
    bound_work = dict(work_item or _work())
    candidate_id = str(
        bound_work.get("candidate_negative_family_id")
        or bound_work.get("candidate_id")
    )
    work_item_id = str(bound_work["work_item_id"])
    premises = list(bound_work["candidate_premise_ids"])
    producers = list(bound_work.get("producer_identities") or ["SOURCE-WORKER"])
    if source_producer is not None:
        producers = [source_producer]
    producer_invocations = list(
        bound_work.get("producer_invocation_ids") or ["SOURCE-INVOCATION"]
    )
    candidate = candidate_content
    source = b"contract Source {}\n"
    claim = C.canonical_json_bytes(
        {"claim": "bound full claim", "premises": premises}
    )
    evidence_raw = C.canonical_json_bytes(
        {"assessment": "negative", "receipt": "authenticated", "scope": "exhaustive"}
    )
    _write(root, "closure-inputs/candidate.bin", candidate)
    _write(root, "closure-inputs/source.txt", source)
    _write(root, "closure-inputs/claim.json", claim)
    _write(root, "closure-inputs/evidence.json", evidence_raw)

    requested_effect = (
        C.OUT_OF_SCOPE
        if authority_kind == "MECHANICAL_SCOPE_EXCLUSION"
        else C.REFUTED_FULL
    )
    subject_unsigned: dict[str, object] = {
        "schema_version": C.CENTRAL_SUBJECT_SCHEMA,
        "run_id": "RUN-CLOSURE-1",
        "candidate_id": candidate_id,
        "work_item_id": work_item_id,
        "candidate_premise_ids": premises,
        "candidate_content_sha256": _sha(candidate),
        "producer_identities": sorted(producers),
        "producer_invocation_ids": sorted(producer_invocations),
        "current_artifacts": [
            {
                "role": "CANDIDATE",
                "relative_path": "closure-inputs/candidate.bin",
                "sha256": _sha(candidate),
                "size_bytes": len(candidate),
            },
            {
                "role": "CLAIM_MANIFEST",
                "relative_path": "closure-inputs/claim.json",
                "sha256": _sha(claim),
                "size_bytes": len(claim),
            },
            {
                "role": "SOURCE",
                "relative_path": "closure-inputs/source.txt",
                "sha256": _sha(source),
                "size_bytes": len(source),
            },
        ],
        "requested_effect": requested_effect,
    }
    subject = _digested(subject_unsigned, "subject_digest")
    subject_raw = C.canonical_json_bytes(subject)
    _write(root, "closure-inputs/subject.json", subject_raw)

    evidence_unsigned: dict[str, object] = {
        "schema_version": C.CENTRAL_EVIDENCE_SCHEMA,
        "subject_digest": subject["subject_digest"],
        "premise_ids": premises,
        "domain_ids": premises,
        "exhaustive": True,
        "artifacts": [
            {
                "evidence_id": "EVIDENCE-1",
                "relative_path": "closure-inputs/evidence.json",
                "sha256": _sha(evidence_raw),
                "size_bytes": len(evidence_raw),
                "premise_ids": premises,
            }
        ],
    }
    evidence = _digested(evidence_unsigned, "manifest_digest")
    evidence_manifest_raw = C.canonical_json_bytes(evidence)
    _write(root, "closure-inputs/evidence-manifest.json", evidence_manifest_raw)

    mechanical = authority_kind == "MECHANICAL_SCOPE_EXCLUSION"
    provider_id = (
        "plamen.mechanical-scope-exclusion.v1"
        if mechanical
        else "plamen.exhaustive-negative-execution.v1"
    )
    provider_output = {
        "schema_version": "plamen.negative_closure_provider_output.v1",
        "authority_kind": authority_kind,
        "provider_id": provider_id,
        "provider_version": "1.0.0",
        "candidate_id": candidate_id,
        "work_item_id": work_item_id,
        "candidate_premise_ids": premises,
        "evidence_claims": [
            {
                "claim_id": "CLAIM-1",
                "claim_kind": (
                    "MECHANICAL_SCOPE_FACT"
                    if mechanical
                    else "EXHAUSTIVE_NEGATIVE_EXECUTION"
                ),
                "evidence_id": "EVIDENCE-1",
                "evidence_sha256": _sha(evidence_raw),
                "premise_ids": premises,
                "outcome": "OUT_OF_SCOPE" if mechanical else "NO_HARM",
            }
        ],
        "scope_completeness": (
            "EXACT_MECHANICAL_SCOPE" if mechanical else "EXHAUSTIVE_FULL"
        ),
        "oracle_authority": (
            "DETERMINISTIC_MECHANICAL_PROVIDER"
            if mechanical
            else "INDEPENDENT_REVIEWER_ORACLE"
        ),
        "mechanical_scope": (
            {
                "exclusion_rule_id": "scope.rule.exact-denominator",
                "exclusion_rule_version": "1",
                "evaluated_subject_sha256": subject["subject_digest"],
                "result": "OUT_OF_SCOPE",
            }
            if mechanical
            else None
        ),
        "survivor_identity": None,
        "negative_execution": None if mechanical else {
            "execution_assessment_sha256": _sha(evidence_raw),
            "execution_receipt_sha256": _sha(evidence_raw),
            "execution_authenticity": "AUTHENTICATED",
            "execution_result": "NEGATIVE",
            "negative_exhaustiveness": "EXHAUSTIVE",
            "proof_scope": "FULL",
            "required_precondition_ids": premises,
            "represented_precondition_ids": premises,
            "environment_fidelity": "FULL",
            "oracle_authority": "INDEPENDENT_REVIEWER_ORACLE",
            "candidate_state": "REFUTED",
            "negative_disposition_eligible": True,
        },
    }
    output_raw = C.canonical_json_bytes(provider_output)
    allowlist = W.environment_allowlist_sha256(())
    intent = C.canonical_json_bytes(
        {
            "effective_backend": "closure-provider",
            "effective_model": f"{provider_id}@1.0.0",
            "environment_allowlist_sha256": allowlist,
        }
    )
    _write(root, "closure-inputs/intent.json", intent)
    bindings = W.ExecutionBindings(
        run_id="RUN-CLOSURE-1",
        shard_id="closure-provider-1",
        plan=W.BoundInput("closure-inputs/subject.json"),
        manifest=W.BoundInput("closure-inputs/evidence-manifest.json"),
        intent=W.BoundInput("closure-inputs/intent.json"),
        context=W.BoundInput("closure-inputs/candidate.bin"),
        prompt=W.BoundInput("closure-inputs/claim.json"),
        tool_policy=W.BoundInput("closure-inputs/source.txt"),
        worker=W.PrincipalInvocation(
            (
                "PLAMEN_MECHANICAL_SCOPE_PROVIDER"
                if mechanical
                else "PLAMEN_EXHAUSTIVE_NEGATIVE_PROVIDER"
            ),
            "CLOSURE-PROVIDER-INVOCATION",
        ),
        assessors=(
            W.PrincipalInvocation(
                (
                    "PLAMEN_MECHANICAL_SCOPE_REVIEWER"
                    if mechanical
                    else "PLAMEN_EXHAUSTIVE_NEGATIVE_REVIEWER"
                ),
                "CLOSURE-REVIEW-INVOCATION",
            ),
        ),
        effective_backend="closure-provider",
        effective_model=f"{provider_id}@1.0.0",
    )
    encoded = base64.b64encode(output_raw).decode("ascii")
    script = (
        "import base64,pathlib; "
        "p=pathlib.Path('closure-runtime/output/provider-output.json'); "
        "p.parent.mkdir(parents=True,exist_ok=True); "
        f"p.write_bytes(base64.b64decode({encoded!r}))"
    )
    completed = W.run_observed_worker(
        scratchpad=root,
        bindings=bindings,
        argv=[sys.executable, "-c", script],
        cwd=root,
        output_scope_relative="closure-runtime/output",
        expected_outputs=(
            W.ExpectedOutput(
                "negative-closure-output",
                "provider-output.json",
                "closure-provider-output/provider-output.json",
            ),
        ),
        parser_digest=C.central_closure_provider_output_digest,
        environment={},
        environment_allowlist=(),
        timeout_seconds=10,
    )
    bundle_unsigned: dict[str, object] = {
        "schema_version": C.CENTRAL_BUNDLE_SCHEMA,
        "bundle_id": "BUNDLE-1",
        "subject_relative_path": "closure-inputs/subject.json",
        "evidence_manifest_relative_path": "closure-inputs/evidence-manifest.json",
        "provider_output_relative_path": "closure-provider-output/provider-output.json",
        "completion_receipt_relative_path": completed.receipt_path.relative_to(root).as_posix(),
        "completion_sha256": completed.completion_sha256,
        "publish_receipt_relative_path": completed.publish_receipt_path.relative_to(root).as_posix(),
        "publish_sha256": completed.publish_sha256,
    }
    bundle = _digested(bundle_unsigned, "bundle_digest")
    if register:
        registered = C.register_completed_negative_closure_provider(
            root,
            bundle_id="BUNDLE-1",
            subject_relative_path="closure-inputs/subject.json",
            evidence_manifest_relative_path="closure-inputs/evidence-manifest.json",
            provider_output_relative_path=(
                "closure-provider-output/provider-output.json"
            ),
            completed_execution=completed,
        )
        assert json.loads(registered.read_bytes()) == bundle
    else:
        _write(
            root,
            (
                f"{C.CENTRAL_BUNDLE_DIR}/"
                f"bundle-{_sha(b'BUNDLE-1')[:24]}.json"
            ),
            C.canonical_json_bytes(bundle),
        )
    return bundle, completed


def _candidate_negative_plan(root: Path) -> tuple[dict[str, object], dict[str, object]]:
    method = root / "method.md"
    method.write_text("# Generic exact independent-negative methodology\n", encoding="utf-8")
    ledger = N.build_candidate_negative_ledger(
        phase="depth",
        artifacts=[
            N.ArtifactInput(
                relative_path="depth_worker.md",
                content=(
                    "### Finding [NEG-1]: candidate\n"
                    "**Verdict**: REFUTED\n"
                    "**Location**: src/Vault.sol:L9\n"
                    "**Refutation Basis**: exhaustive execution covered every premise\n"
                ).encode("utf-8"),
                producer_identity="SOURCE-WORKER",
                producer_invocation_id="SOURCE-INVOCATION",
            )
        ],
        methodology_path=method,
    )
    N.write_candidate_negative_ledger(root, ledger)
    plan = N.build_candidate_negative_application_plan(
        root, phases=("depth",), max_items_per_shard=4
    )
    return plan, plan["work_items"][0]


def _negative_assessment(item: dict[str, object]) -> dict[str, object]:
    evidence = "independent exact exhaustive provider execution"
    return {
        "work_item_id": item["work_item_id"],
        "assessor_id": "INDEPENDENT-APPLICATION-SKEPTIC",
        "assessor_invocation_id": "APPLICATION-SKEPTIC-INVOCATION",
        "outcome": "AGREE_NEGATIVE",
        "evidence_basis": "IN_SCOPE_EXECUTION",
        "evidence": evidence,
        "evidence_sha256": _sha(evidence.encode("utf-8")),
        "rationale": "provider result independently reviewed",
        "candidate": None,
    }


def _inventory_negative_candidate(root: Path) -> dict[str, object]:
    finding = (
        "### Finding [SRC-1]: generic candidate\n"
        "**Severity**: Medium\n"
        "**Location**: src/Module.sol:L10\n"
        "**Root Cause**: generic mechanism\n"
        "**Description**: generic description\n"
        "**Impact**: generic material impact\n"
        "**Verdict**: REFUTED\n\n"
    )
    (root / "analysis_evm_flow.md").write_text(finding, encoding="utf-8")
    (root / "inventory_chunk_a.manifest.md").write_text(
        "# manifest\n\n| File | Estimated signals |\n|---|---|\n"
        "| analysis_evm_flow.md | 1 |\n",
        encoding="utf-8",
    )
    (root / "findings_inventory_chunk_a.md").write_text(
        "# no retained finding\n", encoding="utf-8"
    )
    (root / "findings_inventory.md").write_text(
        "# Finding Inventory\n\n## Findings\n", encoding="utf-8"
    )
    preliminary = I.reconcile_inventory(root)
    candidate = preliminary["candidates"][0]
    evidence = {
        "schema_version": I.NEGATIVE_EVIDENCE_SCHEMA,
        "provider_id": "source-reviewer",
        "records": [
            {
                "record_id": "NEG-1",
                "candidate_key": candidate["candidate_key"],
                "source_artifact": candidate["source_artifact"],
                "source_sha256": candidate["source_sha256"],
                "source_finding_id": candidate["source_finding_id"],
                "source_block_sha256": candidate["source_block_sha256"],
                "verdict": "REFUTED",
                "evidence_scope": "IN_SCOPE_EXECUTION",
                "proof_scope": "HARM",
                "evidence_pointer": "src/Module.sol:L10",
                "evidence_digest": _sha(b"supporting inventory trace"),
            }
        ],
    }
    evidence_raw = json.dumps(evidence, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    _write(root, "inventory_negative_evidence.json", evidence_raw)
    authority_row = {
        "candidate_key": candidate["candidate_key"],
        "source_artifact": candidate["source_artifact"],
        "source_sha256": candidate["source_sha256"],
        "source_finding_id": candidate["source_finding_id"],
        "source_block_sha256": candidate["source_block_sha256"],
        "disposition": "SUPPORTED_REFUTATION",
        "target_artifact": "",
        "target_finding_id": "",
        "alias_union": [],
        "decision_provider_id": "inventory-adjudicator",
        "evidence_provider_id": "source-reviewer",
        "evidence_artifact": "inventory_negative_evidence.json",
        "evidence_sha256": _sha(evidence_raw),
        "evidence_record_id": "NEG-1",
    }
    (root / I.AUTHORITY_FILE).write_text(
        json.dumps(
            {"schema_version": I.AUTHORITY_SCHEMA, "rows": [authority_row]},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return candidate


def _applied_alias_receipt(root: Path) -> tuple[str, str]:
    def finding(fid: str, title: str, impact: str, source_ids: str) -> str:
        return (
            f"### Finding [{fid}]: {title}\n"
            "**Severity**: Medium\n"
            "**Location**: src/Module.sol:L10\n"
            f"**Source IDs**: {source_ids}\n"
            f"**Root Cause**: mechanism for {title}\n"
            f"**Description**: description for {title}\n"
            "**Preconditions**: a caller reaches the boundary\n"
            f"**Impact**: {impact}\n"
            "**Recommendation**: enforce the invariant\n"
            "**External Premises**: none\n"
            "**Evidence Scope**: exact source path\n\n"
        )

    survivor = finding(
        "INV-001",
        "canonical mechanism",
        "combined material harm",
        "INV-001, INV-002",
    )
    absorbed = finding(
        "INV-002", "boundary variant", "distinct boundary harm", "INV-002"
    )
    pre = survivor + absorbed
    records = S.extract_finding_records(pre)
    post = survivor + S.preserved_member_card(records["INV-002"])
    proposal_text = "# Decisions\n\nMERGE: INV-001, INV-002\n"
    proposals = S.parse_dedup_proposals(proposal_text)
    S.write_applied_receipt(
        root,
        phase_name="sc_semantic_dedup",
        application_kind="PRIMARY",
        proposal_text=proposal_text,
        proposals=proposals,
        input_text=pre,
        output_text=post,
        applied_merges=[("INV-002", "INV-001", "field-complete equivalence")],
    )
    (root / "findings_inventory.md").write_bytes(post.encode("utf-8"))
    return pre, post


def test_empty_live_broker_is_replayable_visible_debt(tmp_path: Path) -> None:
    authority = C.load_central_negative_closure_authority(tmp_path)
    decision = authority.resolve(
        work_item=_work(), requested_effect=C.REFUTED_FULL
    )

    assert decision["status"] == C.DEBT
    assert decision["outcome"] == C.NO_AUTHORITY
    assert decision["reopen_required"] is True
    assert "NO_PROVIDER_AUTHORITY" in decision["debt_reasons"]
    assert authority.ledger["bundle_denominator"] == []


def test_policy_consumes_only_central_replayed_authority(tmp_path: Path) -> None:
    authority = C.load_central_negative_closure_authority(tmp_path)
    assessment = {
        "outcome": "AGREE_NEGATIVE",
        "evidence_basis": "INDEPENDENT_ANALYSIS",
    }

    accepted = P.terminal_negative_authorized(
        work_item=_work(),
        assessment=assessment,
        closure_authority=authority,
        requested_effect=C.REFUTED_FULL,
    )
    assert accepted == (False, "NO_PROVIDER_AUTHORITY")


def test_shadow_receipt_api_cannot_be_passed_as_live_policy_authority() -> None:
    accepted = P.terminal_negative_authorized(
        work_item=_work(),
        assessment={"evidence_basis": "FORMAL_PROOF"},
        authority={"terminal_negative_authorized": True},
        provider_validator=lambda value: value,
    )
    assert accepted == (False, "LEGACY_NEGATIVE_AUTHORITY_NOT_LIVE")


def test_real_observed_exhaustive_provider_authorizes_and_replays(tmp_path: Path) -> None:
    _materialize_exhaustive_provider_bundle(tmp_path)
    authority = C.write_central_negative_closure_authority(tmp_path)

    resolution = authority.resolve(
        work_item=_work(), requested_effect=C.REFUTED_FULL
    )
    assert resolution["status"] == C.AUTHORIZED
    assert resolution["outcome"] == C.REFUTED_FULL
    assert resolution["provider_kind"] == "AUTHENTICATED_EXHAUSTIVE_NEGATIVE_EXECUTION"
    assert resolution["reopen_required"] is False
    assert P.terminal_negative_authorized(
        work_item=_work(),
        assessment={"outcome": "AGREE_NEGATIVE", "evidence_basis": "IN_SCOPE_EXECUTION"},
        closure_authority=C.load_central_negative_closure_authority(tmp_path),
        requested_effect=C.REFUTED_FULL,
    ) == (True, "CENTRAL_REPLAYED_NEGATIVE_CLOSURE_AUTHORITY")


def test_registered_observed_mechanical_scope_provider_replays_exactly(
    tmp_path: Path,
) -> None:
    _materialize_exhaustive_provider_bundle(
        tmp_path,
        authority_kind="MECHANICAL_SCOPE_EXCLUSION",
    )
    authority = C.write_central_negative_closure_authority(tmp_path)
    resolution = authority.resolve(
        work_item=_work(), requested_effect=C.OUT_OF_SCOPE
    )

    assert resolution["status"] == C.AUTHORIZED
    assert resolution["outcome"] == C.OUT_OF_SCOPE
    assert resolution["provider_kind"] == "MECHANICAL_SCOPE_EXCLUSION"
    assert resolution["provider_completion_sha256"]
    assert resolution["provider_publish_sha256"]


def test_application_and_candidate_negative_consume_same_central_receipt(
    tmp_path: Path,
) -> None:
    plan, item = _candidate_negative_plan(tmp_path)
    _materialize_exhaustive_provider_bundle(tmp_path, work_item=item)
    authority = C.write_central_negative_closure_authority(tmp_path)
    expected = authority.resolve(work_item=item, requested_effect=C.REFUTED_FULL)

    generic = A.adjudicate_application_skeptic(
        plan,
        [_negative_assessment(item)],
        closure_authority=authority,
    )
    candidate = N.adjudicate_candidate_negative(
        plan,
        [_negative_assessment(item)],
        closure_authority=authority,
    )

    for receipt in (generic, candidate):
        disposition = receipt["work_dispositions"][0]
        assert receipt["status"] == "COMPLETE"
        assert disposition["disposition"] == "NEGATIVE_AGREEMENT"
        assert disposition["negative_closure_authority_digest"] == expected[
            "resolution_digest"
        ]
        assert disposition[
            "negative_closure_provider_completion_sha256"
        ] == expected["provider_completion_sha256"]
        assert disposition[
            "negative_closure_provider_publish_sha256"
        ] == expected["provider_publish_sha256"]


def test_inventory_refutation_requires_and_records_same_central_receipt(
    tmp_path: Path,
) -> None:
    candidate = _inventory_negative_candidate(tmp_path)
    supporting_only = I.reconcile_inventory(tmp_path)
    assert supporting_only["candidates"][0]["disposition"] == "HUMAN_REVIEW_DEBT"

    work = {
        "work_item_id": candidate["candidate_key"],
        "candidate_id": candidate["candidate_key"],
        "candidate_premise_ids": ["PREM-INVENTORY-HARM"],
        "producer_identities": [candidate.get("producer_key") or "SOURCE-WORKER"],
        "producer_invocation_ids": ["SOURCE-INVOCATION"],
    }
    _materialize_exhaustive_provider_bundle(
        tmp_path,
        work_item=work,
        candidate_content=str(candidate["source_block"]).encode("utf-8"),
    )
    authority = C.write_central_negative_closure_authority(tmp_path)
    expected = authority.resolve(
        work_item={
            "work_item_id": candidate["candidate_key"],
            "candidate_id": candidate["candidate_key"],
            "candidate_content_sha256": candidate["source_block_sha256"],
        },
        requested_effect=C.REFUTED_FULL,
    )
    receipt = I.reconcile_inventory(tmp_path, closure_authority=authority)
    row = receipt["candidates"][0]

    assert expected["status"] == C.AUTHORIZED
    assert row["disposition"] == "AUTHORIZED_REFUTATION"
    assert row["negative_closure_authority_digest"] == expected["resolution_digest"]
    assert row["negative_closure_provider_completion_sha256"] == expected[
        "provider_completion_sha256"
    ]
    assert row["negative_closure_provider_publish_sha256"] == expected[
        "provider_publish_sha256"
    ]


def test_applied_lossless_equivalence_is_a_central_replayed_alias(
    tmp_path: Path,
) -> None:
    pre, post = _applied_alias_receipt(tmp_path)
    absorbed = S.extract_finding_records(pre)["INV-002"]
    authority = C.write_central_negative_closure_authority(tmp_path)
    decision = authority.resolve(
        work_item={
            "candidate_id": "INV-002",
            "work_item_id": "INV-002",
            "candidate_content_sha256": _sha(
                str(absorbed["raw"]).strip().encode("utf-8")
            ),
        },
        requested_effect=C.ALIAS_TO_SURVIVOR,
    )

    assert decision["status"] == C.AUTHORIZED
    assert decision["provider_kind"] == "APPLIED_LOSSLESS_EQUIVALENCE"
    assert decision["survivor_id"] == "INV-001"
    assert decision["provider_publish_sha256"] == _sha(post.encode("utf-8"))

    (tmp_path / "findings_inventory.md").write_bytes(
        (post + "\ncurrent output drift\n").encode("utf-8")
    )
    reopened = C.load_central_negative_closure_authority(tmp_path).resolve(
        work_item={"candidate_id": "INV-002"},
        requested_effect=C.ALIAS_TO_SURVIVOR,
    )
    assert reopened["status"] == C.DEBT
    assert "APPLIED_EQUIVALENCE_REPLAY_FAILED" in reopened["debt_reasons"]


def test_inventory_merge_consumes_applied_equivalence_adapter_only(
    tmp_path: Path,
) -> None:
    pre, _post = _applied_alias_receipt(tmp_path)
    absorbed_raw = S.extract_finding_records(pre)["INV-002"]["raw"]
    (tmp_path / "analysis_evm_flow.md").write_bytes(absorbed_raw.encode("utf-8"))
    (tmp_path / "inventory_chunk_a.manifest.md").write_text(
        "# manifest\n\n| File | Estimated signals |\n|---|---|\n"
        "| analysis_evm_flow.md | 1 |\n",
        encoding="utf-8",
    )
    (tmp_path / "findings_inventory_chunk_a.md").write_text(
        "# no retained finding\n", encoding="utf-8"
    )
    candidate = I.reconcile_inventory(tmp_path)["candidates"][0]
    authority_row = {
        "candidate_key": candidate["candidate_key"],
        "source_artifact": candidate["source_artifact"],
        "source_sha256": candidate["source_sha256"],
        "source_finding_id": candidate["source_finding_id"],
        "source_block_sha256": candidate["source_block_sha256"],
        "disposition": "MERGED_ALIAS",
        "target_artifact": "findings_inventory.md",
        "target_finding_id": "INV-001",
        "alias_union": [candidate["candidate_key"]],
        "decision_provider_id": "inventory-adjudicator",
        "evidence_provider_id": "",
        "evidence_artifact": "",
        "evidence_sha256": "",
        "evidence_record_id": "",
    }
    (tmp_path / I.AUTHORITY_FILE).write_text(
        json.dumps(
            {"schema_version": I.AUTHORITY_SCHEMA, "rows": [authority_row]},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    central = C.write_central_negative_closure_authority(tmp_path)
    receipt = I.reconcile_inventory(tmp_path, closure_authority=central)
    row = receipt["candidates"][0]

    assert row["disposition"] == "AUTHORIZED_MERGE"
    assert row["target_inventory_id"] == "INV-001"
    assert row["closure_authority_effect"] == C.ALIAS_TO_SURVIVOR
    assert row["closure_authority_survivor_id"] == "INV-001"
    assert row["negative_closure_authority_digest"]


def test_report_and_lifecycle_terminal_refutation_require_central_receipt(
    tmp_path: Path,
) -> None:
    sp, _project, item, _original = RT._setup(
        tmp_path, status="REFUTED", disposition="BODY"
    )
    supporting = R.build_report_disposition_authority(sp, run_id=RT.RUN_ID)
    assert supporting["rows"][0]["public_retention_target"] == "BODY"
    candidate = supporting["finding_lifecycle"]["source_records"]["candidates"][0]
    semantic = {
        "candidate_id": candidate["candidate_id"],
        "lineage_ids": candidate["lineage_ids"],
        "source_record_sha256": candidate["source_record_sha256"],
        "upstream_severity": candidate["upstream_severity"],
        "title": candidate["title"],
        "location": candidate["location"],
        "evidence_pointer": candidate["evidence_pointer"],
    }
    candidate_bytes = C.canonical_json_bytes(semantic)
    assert _sha(candidate_bytes) == candidate["candidate_content_sha256"]
    work = {
        "work_item_id": item.work_item_id,
        "candidate_id": item.work_item_id,
        "candidate_premise_ids": ["PREM-REPORT-FULL"],
        "producer_identities": [candidate["producer_identity"]],
        "producer_invocation_ids": [candidate["producer_invocation_id"]],
    }
    _materialize_exhaustive_provider_bundle(
        sp,
        work_item=work,
        candidate_content=candidate_bytes,
    )
    C.write_central_negative_closure_authority(sp)
    index = (sp / "report_index.md").read_text(encoding="utf-8")
    index = index.replace(
        f"| M-01 | {item.title} | Medium | {item.work_item_id} |\n",
        "",
    ).replace(
        "|---|---|---|\n",
        "|---|---|---|\n"
        f"| {item.work_item_id} | Medium | central exhaustive refutation |\n",
        1,
    )
    (sp / "report_index.md").write_text(index, encoding="utf-8")

    authority = R.build_report_disposition_authority(sp, run_id=RT.RUN_ID)
    row = authority["rows"][0]
    lifecycle = authority["finding_lifecycle"]

    assert row["decision_kind"] == "REFUTED"
    assert row["public_retention_target"] == "EXCLUDED"
    assert row["disposition_authorized"] is True
    assert row["negative_closure_authority_digest"]
    assert lifecycle["source_records"]["closure_decisions"]
    assert lifecycle["rejected_decisions"] == []
    assert lifecycle["candidate_states"][0]["claim_state"] == "REFUTED"


def test_terminal_negative_consumer_callsites_cannot_drift_to_local_semantics() -> None:
    sources = {
        "policy": inspect.getsource(P.terminal_negative_authorized),
        "application": inspect.getsource(A.adjudicate_application_skeptic),
        "candidate": inspect.getsource(N.adjudicate_candidate_negative),
        "inventory": inspect.getsource(I.reconcile_inventory),
        "report": inspect.getsource(R.build_report_disposition_authority),
        "lifecycle": inspect.getsource(FL._decision_authorization_reason),
        "compound-evaluate": inspect.getsource(CV.evaluate_compound_work_item),
        "compound-bind": inspect.getsource(CV.bind_compound_report),
    }
    for name, source in sources.items():
        assert "closure_authority" in source or "closure_decisions" in source, name
    assert "resolve_central_negative_closure" in sources["policy"]
    assert "LEGACY_NEGATIVE_AUTHORITY_NOT_LIVE" in sources["policy"]
    assert "CENTRAL_REPLAYED_AUTHORITY" in sources["lifecycle"]
    assert "APPLIED_LOSSLESS_EQUIVALENCE" in inspect.getsource(
        C._build_applied_equivalence_adapter
    )
    driver_source = inspect.getsource(D)
    assert driver_source.count("_refresh_central_negative_closure_authority(") >= 4
    assert "closure_authority=closure_authority" in driver_source
    # Severity refutations remain visible at the upstream retention severity;
    # R10 is an un-demotion/recall floor, not a destructive negative consumer.
    severity_source = inspect.getsource(SDL)
    assert 'disposition = "RETAINED_REFUTED_PREMISE"' in severity_source
    assert "severity = retention_severity" in severity_source


def test_compound_refutation_excludes_only_with_same_central_receipt(
    tmp_path: Path,
) -> None:
    candidate = CT._candidate()
    evidence = CT._refutation(candidate)
    work_item = CV.compile_compound_work_plan(
        (candidate,), candidate.constituents
    ).work_items[0]
    supporting = CV.evaluate_compound_work_item(
        candidate,
        work_item,
        (evidence,),
        {identity: "CONFIRMED" for identity in candidate.constituents},
    )
    assert "TERMINAL_NEGATIVE_CLOSURE_AUTHORITY_MISSING" in supporting.debt_codes

    candidate_bytes = C.canonical_json_bytes(candidate.to_record())
    assert _sha(candidate_bytes) == candidate.digest
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
        candidate_content=candidate_bytes,
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
    decision = central.resolve(
        work_item={
            "candidate_id": candidate.chain_id,
            "work_item_id": work_item.verification_identity,
            "candidate_content_sha256": candidate.digest,
        },
        requested_effect=C.REFUTED_FULL,
    )

    assert result.closure_authority_digest == decision["resolution_digest"]
    assert binding.disposition is CV.ReportDisposition.EXCLUDED_REFUTED
    assert CV.validate_compound_report_bindings(
        (binding,), closure_authority=central
    ) == ()


@pytest.mark.parametrize(
    ("relative", "replacement"),
    (
        ("closure-inputs/candidate.bin", b"candidate changed"),
        ("closure-inputs/evidence.json", b"evidence changed"),
    ),
)
def test_current_subject_or_evidence_drift_reopens(
    tmp_path: Path, relative: str, replacement: bytes
) -> None:
    _materialize_exhaustive_provider_bundle(tmp_path)
    C.write_central_negative_closure_authority(tmp_path)
    (tmp_path / relative).write_bytes(replacement)

    resolution = C.load_central_negative_closure_authority(tmp_path).resolve(
        work_item=_work(), requested_effect=C.REFUTED_FULL
    )
    assert resolution["status"] == C.DEBT
    assert resolution["reopen_required"] is True
    assert "BUNDLE_REPLAY_FAILED" in resolution["debt_reasons"]


def test_source_producer_cannot_self_author_negative_closure(tmp_path: Path) -> None:
    _materialize_exhaustive_provider_bundle(
        tmp_path,
        source_producer="PLAMEN_EXHAUSTIVE_NEGATIVE_PROVIDER",
        register=False,
    )
    resolution = C.load_central_negative_closure_authority(tmp_path).resolve(
        work_item=_work(), requested_effect=C.REFUTED_FULL
    )
    assert resolution["status"] == C.DEBT
    assert "BUNDLE_REPLAY_FAILED" in resolution["debt_reasons"]


def test_broker_ledger_crash_resume_and_idempotence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _materialize_exhaustive_provider_bundle(tmp_path)
    original_replace = C.os.replace

    def crash(_source: object, _target: object) -> None:
        raise OSError("injected pre-publish crash")

    monkeypatch.setattr(C.os, "replace", crash)
    with pytest.raises(OSError, match="injected"):
        C.write_central_negative_closure_authority(tmp_path)
    assert not (tmp_path / C.CENTRAL_LEDGER_NAME).exists()

    monkeypatch.setattr(C.os, "replace", original_replace)
    first = C.write_central_negative_closure_authority(tmp_path)
    before = (tmp_path / C.CENTRAL_LEDGER_NAME).read_bytes()
    second = C.write_central_negative_closure_authority(tmp_path)
    assert (tmp_path / C.CENTRAL_LEDGER_NAME).read_bytes() == before
    assert first.ledger == second.ledger
