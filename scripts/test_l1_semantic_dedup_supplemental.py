from __future__ import annotations

import json
from pathlib import Path

import pytest

import l1_semantic_dedup_supplemental as SUBJECT
import semantic_dedup_authority as AUTHORITY


RUN_ID = "36c814c6-dff6-4b2e-bd7a-a210094ac65e"


def _finding(
    finding_id: str,
    *,
    title: str,
    location: str,
    source_ids: str,
    severity: str = "High",
) -> str:
    return (
        f"### Finding [{finding_id}]: {title}\n"
        f"**Severity**: {severity}\n"
        f"**Location**: {location}\n"
        f"**Source IDs**: {source_ids}\n"
        "**Root Cause**: The same missing transition guard.\n"
        "**Description**: An invalid state reaches a protected consumer.\n"
        "**Preconditions**: An untrusted input reaches the transition.\n"
        "**Impact**: A security-sensitive state transition is admitted.\n"
        "**Recommendation**: Enforce the guard at every entry path.\n"
        "**External Premises**: None.\n"
        "**Evidence Scope**: The named transition and direct consumer.\n"
        "[CODE-TRACE]\n\n"
    )


def _inventory() -> bytes:
    return (
        "# Findings Inventory\n\n"
        + _finding(
            "INV-001",
            title="Complete alpha omission",
            location="consensus/state.rs:10-50",
            source_ids="A-1, A-2",
        )
        + _finding(
            "INV-002",
            title="Alpha boundary variant",
            location="consensus/state.rs:20-25",
            source_ids="A-2",
        )
        + _finding(
            "INV-003",
            title="Complete beta omission",
            location="network/auth.rs:70-100",
            source_ids="B-1, B-2",
        )
        + _finding(
            "INV-004",
            title="Complete beta omission",
            location="network/auth.rs:75-80",
            source_ids="B-2",
        )
        + _finding(
            "INV-005",
            title="Independent persistence defect",
            location="storage/write.rs:130-145",
            source_ids="C-1",
        )
    ).encode("utf-8")


def _decisions() -> bytes:
    return (
        "# Semantic Dedup Decisions\n\n"
        "MERGE: INV-001, INV-002\tsame mechanism and repair\n"
        "KEEP: INV-003\n"
        "KEEP: INV-004\n"
        "KEEP: INV-005\n"
    ).encode("utf-8")


def _live_pairs() -> bytes:
    return (
        "# Dedup candidates\n\n"
        "| Finding A | Finding B | Title Score | Signal | Same Sev? |\n"
        "|---|---|---|---|---|\n"
        "| INV-001: alpha | INV-002: alpha | 0.88 | "
        "location overlap (L20-25 vs L20-25) | yes |\n"
    ).encode("utf-8")


def _full_pairs(*extra: str) -> bytes:
    rows = [
        "# Dedup candidates",
        "",
        "| Finding A | Finding B | Title Score | Signal | Same Sev? |",
        "|---|---|---|---|---|",
        "| INV-001: alpha | INV-002: alpha | 0.88 | "
        "location overlap (L20-25 vs L20-25) | yes |",
        "| INV-003: beta | INV-004: beta | 1.00 | "
        "location overlap (L75-80 vs L75-80) | yes |",
        *extra,
    ]
    return ("\n".join(rows) + "\n").encode("utf-8")


def _derive(**overrides: bytes | str) -> bytes:
    values: dict[str, bytes | str] = {
        "inventory_raw": _inventory(),
        "decisions_raw": _decisions(),
        "candidate_pairs_raw": _live_pairs(),
        "candidate_pairs_full_raw": _full_pairs(),
        "run_id": RUN_ID,
    }
    values.update(overrides)
    return SUBJECT.derive_supplemental_proposals(**values)  # type: ignore[arg-type]


def _ids(raw: bytes) -> set[str]:
    return set(
        AUTHORITY.extract_finding_records(raw.decode("utf-8", errors="strict"))
    )


def test_derivation_is_canonical_deterministic_and_conservative() -> None:
    first = _derive()
    second = _derive()
    assert first == second
    payload = json.loads(first)
    assert first == SUBJECT._canonical_json(payload)
    assert payload["schema_version"] == SUBJECT.PROPOSAL_SCHEMA
    assert payload["run_id"] == RUN_ID
    assert payload["state"] == SUBJECT.ACTIVE
    assert payload["debt"] == []
    assert payload["proposals"] == [
        {
            "action": "MERGE",
            "absorbed_id": "INV-004",
            "proposal_id": payload["proposals"][0]["proposal_id"],
            "signal_kind": SUBJECT.SIGNAL_KIND,
            "source_pair_digest": payload["proposals"][0]["source_pair_digest"],
            "survivor_id": "INV-003",
        }
    ]
    assert set(payload["source_artifacts"]) == set(SUBJECT.SOURCE_PATHS)
    SUBJECT.validate_supplemental_proposals(
        first,
        inventory_raw=_inventory(),
        decisions_raw=_decisions(),
        run_id=RUN_ID,
    )


@pytest.mark.parametrize(
    "inventory,decisions,full_row",
    [
        (
            _inventory(),
            _decisions()
            + b"\n### KEEP SEPARATE: INV-003 vs INV-004\n",
            "",
        ),
        (
            _inventory(),
            _decisions(),
            "| INV-003: beta | INV-004: beta | 1.00 | "
            "location overlap (L75-80 vs L76-80) | yes |",
        ),
        (
            _inventory().replace(
                b"### Finding [INV-004]: Complete beta omission\n"
                b"**Severity**: High",
                b"### Finding [INV-004]: Complete beta omission\n"
                b"**Severity**: Medium",
            ),
            _decisions(),
            "",
        ),
        (
            _inventory().replace(
                b"**Source IDs**: B-1, B-2",
                b"**Source IDs**: B-1, B-2, B-3, B-4, B-5",
            ),
            _decisions(),
            "",
        ),
    ],
)
def test_evaluated_inexact_mismatched_or_aggregate_pairs_stay_live(
    inventory: bytes,
    decisions: bytes,
    full_row: str,
) -> None:
    full = (
        _full_pairs().replace(
            b"| INV-003: beta | INV-004: beta | 1.00 | "
            b"location overlap (L75-80 vs L75-80) | yes |",
            full_row.encode("utf-8"),
        )
        if full_row
        else _full_pairs()
    )
    payload = json.loads(
        _derive(
            inventory_raw=inventory,
            decisions_raw=decisions,
            candidate_pairs_full_raw=full,
        )
    )
    assert payload["proposals"] == []


def test_successful_staged_application_returns_one_exact_partition(
    tmp_path: Path,
) -> None:
    outside = tmp_path / "caller-owned.txt"
    outside.write_bytes(b"unchanged")
    staging = tmp_path / "stage"
    proposal = _derive()
    result = SUBJECT.apply_supplemental_in_staging(
        staging_dir=staging,
        inventory_raw=_inventory(),
        model_decisions_raw=_decisions(),
        proposal_raw=proposal,
        run_id=RUN_ID,
    )
    assert outside.read_bytes() == b"unchanged"
    assert _ids(result["final_inventory"]) == {"INV-001", "INV-003", "INV-005"}
    assert {
        key: row["survivor"] for key, row in result["aliases"].items()
    } == {"INV-002": "INV-001", "INV-004": "INV-003"}
    receipt = json.loads(result["combined_receipt"])
    assert result["combined_receipt"] == AUTHORITY.canonical_json_bytes(receipt)
    AUTHORITY._validate_payload(receipt)
    assert receipt["supplemental_state"] == SUBJECT.APPLIED
    assert [stage["application_kind"] for stage in receipt["application_stages"]] == [
        "PRIMARY",
        "SUPPLEMENTAL",
    ]
    assert (
        receipt["application_stages"][0]["output_artifact"]["sha256"]
        == receipt["application_stages"][1]["input_artifact"]["sha256"]
    )
    assert set(receipt["input_artifact"]["finding_ids"]) == (
        set(receipt["output_artifact"]["finding_ids"])
        | set(receipt["accepted_absorbed_ids"])
    )
    assert result["projection_inputs"]["absorbed_finding_ids"] == [
        "INV-002",
        "INV-004",
    ]
    # All implementation writes remain below the supplied staging root.
    assert all(
        staging.resolve() in path.resolve().parents
        for path in staging.rglob("*")
        if path.is_file()
    )


def test_authenticated_degraded_artifact_is_primary_only(
    tmp_path: Path,
) -> None:
    proposal = SUBJECT.derive_degraded_supplemental_proposals(
        inventory_raw=_inventory(),
        decisions_raw=_decisions(),
        candidate_pairs_raw=_live_pairs(),
        candidate_pairs_full_raw=_full_pairs(),
        run_id=RUN_ID,
        debt="injected proposal derivation failure",
    )
    result = SUBJECT.apply_supplemental_in_staging(
        staging_dir=tmp_path / "stage",
        inventory_raw=_inventory(),
        model_decisions_raw=_decisions(),
        proposal_raw=proposal,
        run_id=RUN_ID,
    )
    assert result["supplemental_state"] == SUBJECT.DEGRADED_PRIMARY_ONLY
    assert _ids(result["final_inventory"]) == {
        "INV-001",
        "INV-003",
        "INV-004",
        "INV-005",
    }
    assert set(result["aliases"]) == {"INV-002"}
    assert any(
        "injected proposal derivation failure" in str(row)
        for row in result["supplemental_debt"]
    )


def test_supplemental_apply_failure_returns_exact_primary_floor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*args: object, **kwargs: object) -> int:
        raise RuntimeError("injected application failure")

    monkeypatch.setattr(SUBJECT, "_apply_merges_to_inventory", fail)
    result = SUBJECT.apply_supplemental_in_staging(
        staging_dir=tmp_path / "stage",
        inventory_raw=_inventory(),
        model_decisions_raw=_decisions(),
        proposal_raw=_derive(),
        run_id=RUN_ID,
    )
    assert result["supplemental_state"] == SUBJECT.DEGRADED_PRIMARY_ONLY
    assert _ids(result["final_inventory"]) == {
        "INV-001",
        "INV-003",
        "INV-004",
        "INV-005",
    }
    assert set(result["aliases"]) == {"INV-002"}
    assert any(
        "injected application failure" in str(row)
        for row in result["supplemental_debt"]
    )


def test_tampered_proposal_is_rejected_before_staging_mutation(
    tmp_path: Path,
) -> None:
    staging = tmp_path / "stage"
    with pytest.raises(
        SUBJECT.SupplementalDedupError,
        match="invalid JSON|canonical",
    ):
        SUBJECT.apply_supplemental_in_staging(
            staging_dir=staging,
            inventory_raw=_inventory(),
            model_decisions_raw=_decisions(),
            proposal_raw=_derive() + b"TAMPER",
            run_id=RUN_ID,
        )
    assert not staging.exists()
