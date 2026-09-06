"""P1-M: typed EVIDENCE_FACT compound work reaches the ordinary verifier.

These fixtures describe the adapter boundary before its production module is
introduced.  The adapter is intentionally pure: the driver owns the atomic
queue/receipt transaction, while this module must either return a complete
new denominator or preserve the complete old denominator with visible debt.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from compound_verification import (  # noqa: E402
    CompoundCandidate,
    ConstituentAuthorityBinding,
    compile_compound_work_plan,
)
from p0af_v2_queue_adapter import (  # noqa: E402
    CANDIDATE_FILE,
    ROUTE_DEBT_FILE,
    WORK_AUTHORITY_FILE,
    plan_p0af_v2_queue_delivery,
)
from queue_work_items import QueueWorkItem  # noqa: E402


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    ).hexdigest()


def _payload_digest(value: dict) -> str:
    return _digest({key: item for key, item in value.items() if key != "payload_digest"})


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _canonical_ids(root: Path, identities: tuple[str, ...] = ()) -> None:
    records = [
        {
            "canonical_id": f"CID-{index:016X}",
            "artifact": "findings_inventory.md",
            "local_id": identity,
            "local_id_raw": identity,
            "referenced_ids": [],
        }
        for index, identity in enumerate(identities, 1)
    ]
    _write_json(
        root / "_canonical_finding_ids.json",
        {
            "schema_version": "plamen.canonical_finding_ids.v1",
            "generated_at": "2026-01-01T00:00:00+00:00",
            "last_phase": "chain",
            "pipeline": "sc",
            "mode": "thorough",
            "record_count": len(records),
            "records": records,
        },
    )


def _artifacts(root: Path, *, subject: str = "CH-17", with_work: bool = True) -> None:
    _canonical_ids(root)
    fact_rows = [
        {
            "fact_id": "AUTH-FACT-0001",
            "evidence": [{"locus": "src/Auth.sol:L10-L20"}],
        },
        {
            "fact_id": "AUTH-FACT-0002",
            "evidence": [{"locus": "src/Auth.sol:L40-L50"}],
        },
    ]
    for row in fact_rows:
        row["fact_digest"] = _digest(row)
    fact_authority = {
        "schema_version": "plamen.authentication_role_fact_authority.v1",
        "facts": fact_rows,
    }
    fact_authority["authority_digest"] = _digest(fact_authority)
    _write_json(root / "authentication_role_fact_authority.json", fact_authority)
    bindings = tuple(
        ConstituentAuthorityBinding.create(
            {
                "constituent_id": row["fact_id"],
                "constituent_kind": "EVIDENCE_FACT",
                "fact_digest": row["fact_digest"],
                "authority_digest": fact_authority["authority_digest"],
                "source_artifact": "authentication_role_fact_authority.json",
            }
        )
        for row in fact_rows
    )
    candidate = CompoundCandidate.create(
        chain_id=subject,
        constituents=tuple(binding.constituent_id for binding in bindings),
        evidence_constituent_bindings=bindings,
        severity_upgrade_justified=True,
        ordering_edges=(),
        preconditions=("Both authenticated role transitions are reachable.",),
        postconditions=("Independent execution must establish composed harm.",),
        combined_impact_claim="A composed harm hypothesis requiring execution.",
        proposed_severity="Medium",
        source_lineage=("arm_before_trust_chain_analysis.json:candidate=1",),
        coverage_lineage=("MZO-0001",),
        pipeline="SC",
        mode="thorough",
    )
    candidate_payload = {
        "schema_version": "plamen.arm_before_trust_compound_candidates.v1",
        "source_analysis_digest": "d" * 64,
        "source_composition_digest": "e" * 64,
        "source_fact_authority_digest": fact_authority["authority_digest"],
        "identity_denominator_artifact": "_canonical_finding_ids.json",
        "identity_denominator_digest": hashlib.sha256(
            (root / "_canonical_finding_ids.json").read_bytes()
        ).hexdigest(),
        "proof_authority": "NONE",
        "candidate_count": 1 if with_work else 0,
        "candidates": [candidate.to_record()] if with_work else [],
    }
    candidate_payload["payload_digest"] = _payload_digest(candidate_payload)
    _write_json(root / CANDIDATE_FILE, candidate_payload)

    plan = compile_compound_work_plan(
        (candidate,) if with_work else (),
        known_constituent_identities=(),
        known_evidence_constituents=bindings,
    ).to_record()
    work_payload = {
        "schema_version": "plamen.arm_before_trust_compound_work_authority.v1",
        "candidate_payload_digest": candidate_payload["payload_digest"],
        "proof_authority": "NONE",
        "compound_work_plan": plan,
    }
    work_payload["payload_digest"] = _payload_digest(work_payload)
    _write_json(root / WORK_AUTHORITY_FILE, work_payload)
    ready = [
        row["subject_id"]
        for row in plan["work_items"]
        if row["readiness"] == "READY"
    ]
    debt = {
        "schema_version": "plamen.arm_before_trust_p0af_route_debt.v1",
        "status": "READY_PENDING_QUEUE_DELIVERY" if ready else "CLEAN_NO_NOMINATION",
        "work_authority_digest": work_payload["payload_digest"],
        "ready_work_item_ids": ready,
        "ordinary_verification_required": bool(ready),
        "route": "P0_AF_V2_QUEUE_ADAPTER_REQUIRED",
        "proof_authority": "NONE",
    }
    debt["payload_digest"] = _payload_digest(debt)
    _write_json(root / ROUTE_DEBT_FILE, debt)


def test_valid_v2_work_is_added_as_unproven_ordinary_verification(tmp_path: Path) -> None:
    _artifacts(tmp_path)

    result = plan_p0af_v2_queue_delivery(tmp_path, ())

    assert result.debt is None
    assert result.receipt["status"] == "DELIVERED"
    assert result.receipt["delivered_work_item_ids"] == ["CH-17"]
    assert result.receipt["proof_authority"] == "NONE"
    assert len(result.queue_items) == 1
    item = result.queue_items[0]
    assert isinstance(item, QueueWorkItem)
    assert item.work_item_id == "CH-17"
    assert item.candidate_identity == "CH-17"
    assert item.constituents == ("AUTH-FACT-0001", "AUTH-FACT-0002")
    assert item.bug_class == "chain-composition"
    assert item.poc_class == "sequence"
    assert item.effective_evidence_scope == "IN_SCOPE_SOURCE"
    assert item.effective_proof_scope == "ANALYTICAL"
    assert item.effective_harm_scope == "UNPROVEN"
    assert CANDIDATE_FILE in item.primary_artifacts
    assert WORK_AUTHORITY_FILE in item.primary_artifacts
    typed_loci = "\n".join(
        record.note or "" for record in item.location_records
    )
    assert "fact=AUTH-FACT-0001;locus=src/Auth.sol:L10-L20" in typed_loci
    assert "fact=AUTH-FACT-0002;locus=src/Auth.sol:L40-L50" in typed_loci
    assert "authentication_role_fact_authority.json" in item.primary_artifacts


def test_resume_is_exact_and_adapter_owned_projection_can_refresh(tmp_path: Path) -> None:
    _artifacts(tmp_path)
    first = plan_p0af_v2_queue_delivery(tmp_path, ())
    second = plan_p0af_v2_queue_delivery(
        tmp_path, first.queue_items, prior_receipt=first.receipt
    )

    assert second.debt is None
    assert second.queue_items == first.queue_items
    assert second.receipt == first.receipt
    assert second.receipt["queue_record_set_digest"] == first.receipt[
        "queue_record_set_digest"
    ]
    assert second.receipt["status"] == "DELIVERED"


@pytest.mark.parametrize(
    ("artifact", "mutate"),
    [
        (CANDIDATE_FILE, lambda value: value.__setitem__("candidate_count", 2)),
        (WORK_AUTHORITY_FILE, lambda value: value.__setitem__("proof_authority", "PROOF")),
        (ROUTE_DEBT_FILE, lambda value: value.__setitem__("route", "BYPASS")),
        (
            "authentication_role_fact_authority.json",
            lambda value: value["facts"][0].__setitem__("fact_digest", "f" * 64),
        ),
    ],
)
def test_tamper_preserves_entire_prior_queue_and_emits_debt(
    tmp_path: Path, artifact: str, mutate,
) -> None:
    _artifacts(tmp_path)
    baseline = plan_p0af_v2_queue_delivery(tmp_path, ()).queue_items
    payload = json.loads((tmp_path / artifact).read_text(encoding="utf-8"))
    mutate(payload)
    _write_json(tmp_path / artifact, payload)

    result = plan_p0af_v2_queue_delivery(tmp_path, baseline)

    assert result.queue_items == baseline
    assert result.receipt is None
    assert result.debt["status"] == "COMPLETED_WITH_DEBT"
    assert result.debt["ordinary_verification_delivery_complete"] is False
    assert result.debt["proof_authority"] == "NONE"


def test_identity_denominator_drift_is_debt_not_partial_delivery(tmp_path: Path) -> None:
    _artifacts(tmp_path)
    _canonical_ids(tmp_path, ("H-01",))

    result = plan_p0af_v2_queue_delivery(tmp_path, ())

    assert result.queue_items == ()
    assert result.receipt is None
    assert result.debt["error_code"] == "P0_AF_V2_INPUT_INVALID"


def test_non_owned_subject_collision_preserves_queue(tmp_path: Path) -> None:
    _artifacts(tmp_path)
    foreign = QueueWorkItem.from_legacy_row(
        {
            "queue #": "1",
            "finding id": "CH-17",
            "severity": "Low",
            "title": "Unrelated pre-existing candidate",
            "bug class": "state-machine",
            "preferred tag": "CODE-TRACE",
            "location": "findings_inventory.md",
            "primary artifact": "findings_inventory.md",
            "poc class": "structural",
        }
    )

    result = plan_p0af_v2_queue_delivery(tmp_path, (foreign,))

    assert result.queue_items == (foreign,)
    assert result.receipt is None
    assert result.debt["error_code"] == "P0_AF_V2_IDENTITY_COLLISION"


def test_blocked_or_issue_bearing_plan_never_partially_delivers(tmp_path: Path) -> None:
    _artifacts(tmp_path)
    work = json.loads((tmp_path / WORK_AUTHORITY_FILE).read_text(encoding="utf-8"))
    work["compound_work_plan"]["issues"] = [
        {
            "code": "BLOCKED_MISSING_CONSTITUENT",
            "subject_id": "CH-17",
            "detail": "fixture",
            "candidate_digests": [],
        }
    ]
    work["payload_digest"] = _payload_digest(work)
    _write_json(tmp_path / WORK_AUTHORITY_FILE, work)
    route = json.loads((tmp_path / ROUTE_DEBT_FILE).read_text(encoding="utf-8"))
    route["work_authority_digest"] = work["payload_digest"]
    route["payload_digest"] = _payload_digest(route)
    _write_json(tmp_path / ROUTE_DEBT_FILE, route)

    result = plan_p0af_v2_queue_delivery(tmp_path, ())

    assert result.queue_items == ()
    assert result.receipt is None
    assert result.debt["error_code"] == "P0_AF_V2_BLOCKED_WORK"


def test_no_nomination_is_clean_no_op(tmp_path: Path) -> None:
    _artifacts(tmp_path, with_work=False)

    result = plan_p0af_v2_queue_delivery(tmp_path, ())

    assert result.queue_items == ()
    assert result.debt is None
    assert result.receipt["status"] == "CLEAN_NO_OP"
    assert result.receipt["delivered_work_item_ids"] == []


def test_missing_or_symlinked_authority_is_visible_debt(tmp_path: Path) -> None:
    _artifacts(tmp_path)
    (tmp_path / "authentication_role_fact_authority.json").unlink()

    missing = plan_p0af_v2_queue_delivery(tmp_path, ())

    assert missing.queue_items == ()
    assert missing.debt["error_code"] == "P0_AF_V2_INPUT_INVALID"

    source = tmp_path / "outside.json"
    _write_json(source, {"authority_digest": "c" * 64, "facts": []})
    try:
        (tmp_path / "authentication_role_fact_authority.json").symlink_to(source)
    except OSError:
        pytest.skip("symlink creation is unavailable on this host")
    linked = plan_p0af_v2_queue_delivery(tmp_path, ())
    assert linked.queue_items == ()
    assert linked.debt["error_code"] == "P0_AF_V2_INPUT_INVALID"
