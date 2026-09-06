"""Typed additive post-verification candidate universe fixtures."""
from __future__ import annotations

import json
import hashlib
from pathlib import Path

import pytest

from post_verify_candidate_delta import (
    PostVerifyCandidateDeltaError,
    load_report_candidate_universe,
    load_post_verify_late_delivery_statuses,
    write_or_validate_post_verify_candidate_delta,
)
from mandatory_reverification import compile_report_reopen_denominator
from report_disposition_authority import write_report_disposition_authority
from post_verify_lifecycle import parse_post_verify_candidate_proposals
from queue_work_items import (
    QueueWorkItem,
    queue_record_set_digest,
    queue_records_from_json,
    queue_records_to_json,
    validate_queue_work_items,
)
from verification_method_compiler import OPERATOR_RECEIPT_SCHEMA, stable_digest
from verification_operator_consumers import (
    build_verifier_operator_consumer_authority,
    write_or_validate_verifier_operator_consumer_authority,
)


RUN_ID = "post-verify-delta-run"


def _base_item() -> QueueWorkItem:
    return QueueWorkItem.from_legacy_row({
        "finding id": "BASE-1",
        "severity": "Medium",
        "title": "Base candidate",
        "bug class": "STATE_TRANSITION",
        "preferred tag": "CODE-TRACE",
        "location": "src/Base.sol:10",
        "primary artifact": "findings_inventory.md",
        "poc class": "structural",
    })


def _seed(root: Path, *, clean: bool = False) -> tuple[bytes, bytes]:
    root.mkdir(parents=True, exist_ok=True)
    base_raw = (queue_records_to_json((_base_item(),)) + "\n").encode()
    (root / "verification_queue.work_items.json").write_bytes(base_raw)
    inventory_raw = (
        b"# Findings Inventory\n\n"
        b"### Finding [BASE-1]: Base candidate\n"
    )
    (root / "findings_inventory.md").write_bytes(inventory_raw)
    if clean:
        source = "# Post Verify Extract\n\n**Status**: CLEAN_NO_CANDIDATES\n"
    else:
        source = (
            "# Post Verify Extract\n\n"
            "### Finding [VER-1]: Late candidate\n"
            "**Severity**: Medium\n"
            "**Location**: src/Late.sol:20\n"
            "**Root Cause**: A late independent mechanism remains.\n"
            "**Impact**: A protected state transition may be violated.\n"
            "**Source Verify File**: verify_BASE-1.md\n"
        )
        (root / "verify_BASE-1.md").write_text(
            "# Verification\n", encoding="utf-8"
        )
    (root / "post_verify_extract.md").write_text(source, encoding="utf-8")
    return base_raw, inventory_raw


def _canonical_digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _recompute_delta_digests(root: Path, payload: dict[str, object]) -> None:
    rows = payload["rows"]
    assert isinstance(rows, list)
    delta_items = []
    for row in rows:
        assert isinstance(row, dict)
        item = QueueWorkItem.from_dict(row["work_item"])
        row["work_item_digest"] = item.digest
        delta_items.append(item)
    base_raw = (root / "verification_queue.work_items.json").read_bytes()
    base_items = queue_records_from_json(
        base_raw.decode("utf-8", errors="strict")
    )
    union = validate_queue_work_items((*base_items, *delta_items))
    payload["base_queue_binding"] = {
        "artifact": "verification_queue.work_items.json",
        "sha256": hashlib.sha256(base_raw).hexdigest(),
        "size_bytes": len(base_raw),
        "record_count": len(base_items),
        "record_set_digest": queue_record_set_digest(base_items),
    }
    bindings = payload["source_bindings"]
    debts = payload["debts"]
    assert isinstance(bindings, list)
    assert isinstance(debts, list)
    payload["source_binding_count"] = len(bindings)
    payload["source_set_digest"] = _canonical_digest(bindings)
    payload["row_count"] = len(rows)
    payload["debt_count"] = len(debts)
    payload["source_candidate_count"] = len(rows) + len(debts)
    payload["status"] = "COMPLETED_WITH_DEBT" if debts else "CLEAN"
    payload["delta_record_set_digest"] = queue_record_set_digest(delta_items)
    payload["union_record_count"] = len(union)
    payload["union_record_set_digest"] = queue_record_set_digest(union)
    unsigned = {
        key: value for key, value in payload.items()
        if key != "delta_digest"
    }
    payload["delta_digest"] = _canonical_digest(unsigned)


def _operator_projection(root: Path) -> dict[str, object]:
    observation = {
        "title": "Operator-side late candidate",
        "mechanism": "A source-bound operator observation remains.",
        "location": "src/Operator.sol:77",
        "evidence": "src/Operator.sol:77",
        "candidate_state": "PROPOSED",
        "terminal_authority": False,
        "source_work_item_id": "BASE-1",
    }
    receipt_unsigned = {
        "schema_version": OPERATOR_RECEIPT_SCHEMA,
        "work_item_id": "BASE-1",
        "method_dispatch_id": "dispatch-1",
        "dispatch_receipt_digest": "1" * 64,
        "launch_digest": "2" * 64,
        "proposal_sha256": "3" * 64,
        "verifier_sha256": "4" * 64,
        "selected_module_hashes": [],
        "context_packet_digest": "5" * 64,
        "context_status": "RESOLVED",
        "operators": [],
        "debts": [],
        "new_observations": [observation],
        "application_authority": "APPLICATION_EVIDENCE_ONLY",
        "terminal_authority": False,
    }
    receipt = {
        **receipt_unsigned,
        "receipt_digest": stable_digest(receipt_unsigned),
    }
    receipt_path = root / "verify_BASE-1.operator_receipt.json"
    receipt_path.write_text(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    authority = build_verifier_operator_consumer_authority(
        run_id=RUN_ID,
        receipt_paths=[receipt_path],
        scratchpad=root,
    )
    authority_path = root / "verification_operator_consumer_authority.json"
    write_or_validate_verifier_operator_consumer_authority(
        authority_path, authority
    )
    candidate = authority["candidates"][0]
    work = authority["late_verification_shards"][0]["rows"][0]
    authority_raw = authority_path.read_bytes()
    return {
        **work,
        "finding id": candidate["candidate_id"],
        "severity": str(work.get("severity") or "Unknown"),
        "title": candidate["title"],
        "location": candidate["location"],
        "mechanism": candidate["mechanism"],
        "evidence": candidate["evidence"],
        "source_kind": "VERIFIER_OPERATOR_AUTHORITY",
        "source_authority_artifact": authority_path.name,
        "source_authority_sha256": hashlib.sha256(authority_raw).hexdigest(),
        "source_record_ordinal": 1,
        "source_record_digest": candidate["candidate_digest"],
    }


def test_delta_adds_late_candidate_without_mutating_t8_or_inventory(
    tmp_path: Path,
) -> None:
    base_raw, inventory_raw = _seed(tmp_path)
    proposals = parse_post_verify_candidate_proposals(tmp_path)
    assert proposals["proposal_count"] == 1
    derived_id = proposals["proposals"][0]["work_item_id"]
    assert derived_id.startswith("VER-")
    assert derived_id != "VER-1"

    payload = write_or_validate_post_verify_candidate_delta(
        tmp_path,
        run_id=RUN_ID,
        operator_proposals=(),
    )

    assert payload["status"] == "CLEAN"
    assert payload["row_count"] == 1
    assert payload["source_candidate_count"] == 1
    assert payload["debt_count"] == 0
    assert payload["rows"][0]["work_item"]["work_item_id"] == derived_id
    assert payload["rows"][0]["claim"]["premise"]
    assert payload["rows"][0]["claim"]["harm"]
    assert (
        tmp_path / "verification_queue.work_items.json"
    ).read_bytes() == base_raw
    assert (tmp_path / "findings_inventory.md").read_bytes() == inventory_raw

    universe = load_report_candidate_universe(
        tmp_path, run_id=RUN_ID
    )
    assert {row.item.work_item_id for row in universe} == {
        "BASE-1", derived_id
    }
    assert next(
        row for row in universe if row.item.work_item_id == derived_id
    ).source_kind == "POST_VERIFY_EXTRACT"


def test_delta_replay_is_byte_identical_and_source_tamper_rejects(
    tmp_path: Path,
) -> None:
    _seed(tmp_path)
    first = write_or_validate_post_verify_candidate_delta(
        tmp_path, run_id=RUN_ID, operator_proposals=()
    )
    path = tmp_path / "post_verify_candidate_delta.json"
    before = path.read_bytes()
    second = write_or_validate_post_verify_candidate_delta(
        tmp_path, run_id=RUN_ID, operator_proposals=()
    )
    assert first == second
    assert path.read_bytes() == before

    with open(tmp_path / "post_verify_extract.md", "a", encoding="utf-8") as f:
        f.write("\nchanged\n")
    with pytest.raises(PostVerifyCandidateDeltaError):
        load_report_candidate_universe(tmp_path, run_id=RUN_ID)


def test_explicit_clean_zero_delta_is_nonvacuous_and_missing_source_is_debt(
    tmp_path: Path,
) -> None:
    _seed(tmp_path, clean=True)
    clean = write_or_validate_post_verify_candidate_delta(
        tmp_path, run_id=RUN_ID, operator_proposals=()
    )
    assert clean["status"] == "CLEAN"
    assert clean["source_candidate_count"] == 0
    assert clean["row_count"] == 0
    assert clean["debt_count"] == 0
    assert len(load_report_candidate_universe(tmp_path, run_id=RUN_ID)) == 1

    other = tmp_path / "missing"
    other.mkdir()
    (other / "verification_queue.work_items.json").write_text(
        queue_records_to_json((_base_item(),)) + "\n",
        encoding="utf-8",
    )
    debt = write_or_validate_post_verify_candidate_delta(
        other, run_id=RUN_ID, operator_proposals=()
    )
    assert debt["status"] == "COMPLETED_WITH_DEBT"
    assert debt["source_candidate_count"] == 1
    assert debt["row_count"] == 0
    assert debt["debt_count"] == 1
    assert debt["terminal_authority"] is False


@pytest.mark.parametrize("source_kind", ["legacy", "operator"])
def test_self_consistent_source_unbound_row_forgery_is_rejected(
    tmp_path: Path,
    source_kind: str,
) -> None:
    _seed(tmp_path, clean=source_kind == "operator")
    operator_proposals = (
        (_operator_projection(tmp_path),)
        if source_kind == "operator"
        else ()
    )
    write_or_validate_post_verify_candidate_delta(
        tmp_path,
        run_id=RUN_ID,
        operator_proposals=operator_proposals,
    )
    delta_path = tmp_path / "post_verify_candidate_delta.json"
    payload = json.loads(delta_path.read_text(encoding="utf-8"))
    target = next(
        row for row in payload["rows"]
        if (
            row["source_kind"] == "VERIFIER_OPERATOR_AUTHORITY"
            if source_kind == "operator"
            else row["source_kind"] == "POST_VERIFY_EXTRACT"
        )
    )
    target["work_item"]["title"] = "Self-consistently forged title"
    target["claim"]["premise"] = "Self-consistently forged premise."
    target["claim"]["harm"] = "Self-consistently forged harm."
    _recompute_delta_digests(tmp_path, payload)
    delta_path.write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(
        PostVerifyCandidateDeltaError,
        match="source replay|source-derived",
    ):
        load_report_candidate_universe(tmp_path, run_id=RUN_ID)


def test_self_consistent_delta_row_reorder_is_rejected(
    tmp_path: Path,
) -> None:
    _seed(tmp_path)
    with open(
        tmp_path / "post_verify_extract.md", "a", encoding="utf-8"
    ) as handle:
        handle.write(
            "\n### Finding [VER-2]: Second late candidate\n"
            "**Severity**: Low\n"
            "**Location**: src/Late.sol:30\n"
            "**Root Cause**: A second late mechanism remains.\n"
            "**Impact**: A second protected transition may be violated.\n"
            "**Source Verify File**: verify_BASE-1.md\n"
        )
    write_or_validate_post_verify_candidate_delta(
        tmp_path, run_id=RUN_ID, operator_proposals=()
    )
    delta_path = tmp_path / "post_verify_candidate_delta.json"
    payload = json.loads(delta_path.read_text(encoding="utf-8"))
    assert len(payload["rows"]) == 2
    payload["rows"].reverse()
    _recompute_delta_digests(tmp_path, payload)
    delta_path.write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(
        PostVerifyCandidateDeltaError,
        match="source replay|canonical",
    ):
        load_report_candidate_universe(tmp_path, run_id=RUN_ID)


def _write_late_delivery(
    root: Path,
    *,
    candidate_id: str,
    source_record_digest: str,
    verdict: str,
) -> None:
    verify = (
        f"# Verify {candidate_id}\n\n"
        f"**Verdict**: {verdict}\n"
        "**Severity**: Medium\n"
        "**Description**: Independently reviewed late observation.\n"
    ).encode()
    verify_name = f"verify_{candidate_id}.md"
    (root / verify_name).write_bytes(verify)
    unsigned = {
        "schema_version": "plamen.post_verify_late_delivery.v1",
        "proof_authority": "NONE",
        "row_count": 1,
        "rows": [{
            "candidate_id": candidate_id,
            "delivery_state": "INDEPENDENT_VERIFICATION_RECORDED",
            "verify_artifact": verify_name,
            "verify_sha256": hashlib.sha256(verify).hexdigest(),
            "source_candidate_digest": source_record_digest,
            "source_work_item_id": None,
            "source_operator_receipt": None,
            "source_operator_receipt_sha256": None,
            "source_operator_receipt_digest": None,
            "finding_lifecycle_obligation_id": None,
        }],
    }
    payload = {
        **unsigned,
        "receipt_sha256": hashlib.sha256(
            json.dumps(
                unsigned, sort_keys=True, separators=(",", ":")
            ).encode()
        ).hexdigest(),
    }
    (root / "post_verify_late_delivery.json").write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def test_late_negative_is_body_retained_and_creates_one_reopen_obligation(
    tmp_path: Path,
) -> None:
    _seed(tmp_path)
    delta = write_or_validate_post_verify_candidate_delta(
        tmp_path, run_id=RUN_ID, operator_proposals=()
    )
    row = delta["rows"][0]
    candidate_id = row["work_item"]["work_item_id"]
    _write_late_delivery(
        tmp_path,
        candidate_id=candidate_id,
        source_record_digest=row["source_record_digest"],
        verdict="REFUTED",
    )

    statuses = load_post_verify_late_delivery_statuses(
        tmp_path, run_id=RUN_ID
    )
    assert statuses[candidate_id].verifier_status == "REFUTED"
    assert statuses[candidate_id].terminal_negative_authority is False

    authority = write_report_disposition_authority(
        tmp_path, run_id=RUN_ID
    )
    disposition = next(
        item for item in authority["rows"]
        if item["candidate_id"] == candidate_id
    )
    assert disposition["public_retention_target"] == "BODY"
    assert disposition["negative_proposal_status"] == "REFUTED"
    assert disposition["mandatory_reverification"] is True
    assert disposition["mandatory_reverification_id"]
    obligations = [
        item for item in authority["finding_lifecycle"]["obligations"]
        if item["candidate_id"] == candidate_id
        and item["obligation_kind"] == "RECOVERY_INDEPENDENT_VERIFICATION"
    ]
    assert len(obligations) == 1
    sources = {
        item["path"] for item in authority["source_artifacts"]
    }
    assert {
        "post_verify_candidate_delta.json",
        "post_verify_extract.md",
        "post_verify_late_delivery.json",
    }.issubset(sources)
    reopen = compile_report_reopen_denominator(
        tmp_path, run_id=RUN_ID
    )
    assert reopen["source_obligation_count"] == 1
    assert reopen["candidate_count"] == 1
    assert reopen["input_debt_count"] == 0
    assert reopen["candidates"][0]["candidate_id"] == candidate_id
    assert reopen["candidates"][0]["premise"] == row["claim"]["premise"]
    assert reopen["candidates"][0]["harm"] == row["claim"]["harm"]
    assert reopen["candidates"][0]["evidence"] == row["claim"]["evidence"]

    _seed(tmp_path)
    write_or_validate_post_verify_candidate_delta(
        tmp_path, run_id=RUN_ID, operator_proposals=()
    )
    (tmp_path / "verification_queue.work_items.json").write_text(
        queue_records_to_json(()) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(PostVerifyCandidateDeltaError):
        load_report_candidate_universe(tmp_path, run_id=RUN_ID)
