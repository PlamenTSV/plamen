from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import mandatory_reverification as M
from finding_producer_registry import (
    canonical_digest,
    write_application_skeptic_proposal_projection,
)
from queue_work_items import QueueWorkItem


def _seed_authority(root: Path) -> str:
    raw = b'{"schema_version":"fixture.security-obligation-authority.v1"}\n'
    (root / "security_obligation_authority.json").write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def _pending_row(
    authority_sha256: str,
    ordinal: int,
    *,
    finding_id: str = "INV-901",
) -> dict[str, str]:
    binding = {
        "obligation_id": "SOBL-009-" + f"{ordinal:04d}",
        "display_id": "SO-009",
        "alias_id": "SOT-" + f"{ordinal:04d}",
        "relation_id": "SWR-" + f"{ordinal:04d}",
        "object_id": "src/Bridge.sol::bridge",
        "symbol": f"wrappedAsset{ordinal}",
        "finding_id": finding_id,
        "receipt_id": "SOR-" + f"{ordinal:04d}",
        "question": "Does the exact wrapper relation preserve native/token semantics?",
        "source_artifact": "security_obligation_authority.json",
        "source_artifact_sha256": authority_sha256,
    }
    return {
        **binding,
        "alias_binding_sha256": hashlib.sha256(
            json.dumps(
                binding,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest(),
    }


def _reseal(row: dict[str, str]) -> None:
    binding = {
        key: value for key, value in row.items() if key != "alias_binding_sha256"
    }
    row["alias_binding_sha256"] = hashlib.sha256(
        json.dumps(
            binding,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _install_reader(
    monkeypatch: pytest.MonkeyPatch,
    rows: list[dict[str, str]],
) -> None:
    import security_obligation_authority as S

    monkeypatch.setattr(
        S,
        "read_pending_security_obligation_verification",
        lambda _scratchpad: [dict(row) for row in rows],
        raising=False,
    )


def _candidate_negative_proposal() -> dict[str, object]:
    unsigned: dict[str, object] = {
        "schema_version": "plamen.finding_candidate_proposal.v1",
        "producer": "application_skeptic",
        "source_obligation_id": "OBL-CANDIDATE-NEGATIVE",
        "source_work_item_id": "ASW-" + "B" * 24,
        "assessor_identity": "independent-assessor",
        "assessor_invocation_id": "assessment-candidate-negative",
        "assessor_evidence_sha256": "b" * 64,
        "candidate": {
            "title": "Candidate-negative proposal",
            "mechanism": "A bounded alternate transition remains reachable.",
            "harm": "A security-relevant state property may be violated.",
        },
    }
    digest = canonical_digest(unsigned)
    return {
        **unsigned,
        "proposal_id": "ASCP-" + digest[:24].upper(),
        "proposal_digest": digest,
    }


def _inventory_seed() -> str:
    return (
        "# Findings Inventory\n\n"
        "### Finding [INV-901]: Existing security-obligation finding\n"
        "**Source IDs**: [BASE-901]\n"
        "**Severity**: Medium\n"
        "**Location**: src/Bridge.sol:10\n"
        "**Preferred Tag**: CODE-TRACE\n"
        "**Primary Artifact**: depth_findings.md\n\n"
        "**Description**: Existing bounded candidate.\n"
    )


def test_pending_alias_is_compiled_when_no_legacy_projection_exists(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_sha = _seed_authority(tmp_path)
    _install_reader(monkeypatch, [_pending_row(source_sha, 1)])

    denominator = M.compile_primary_reopen_denominator(
        tmp_path, run_id="run-p1c-only"
    )

    assert denominator["status"] == "READY"
    assert denominator["source_obligation_count"] == 1
    assert denominator["candidate_count"] == 1
    candidate = denominator["candidates"][0]
    assert candidate["candidate_id"] == "INV-901"
    assert candidate["source_candidate_id"] == "SOT-0001"
    assert candidate["source_proposal_id"] == "SOR-0001"
    assert candidate["source_obligation_id"] == "SOT-0001"
    assert candidate["candidate_content_sha256"] == _pending_row(
        source_sha, 1
    )["alias_binding_sha256"]
    assert candidate["source_artifact_sha256"] == source_sha
    assert "SWR-0001" in candidate["evidence"]
    assert "wrappedAsset1" in candidate["evidence"]
    assert "security-obligation:SOBL-009-0001" in candidate["evidence"]


def test_pending_non_alias_obligation_receipt_is_also_conserved(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_sha = _seed_authority(tmp_path)
    row = _pending_row(source_sha, 1)
    row.update({
        "obligation_id": "SOBL-GENERIC-0001",
        "display_id": "SO-001",
        "alias_id": "",
        "relation_id": "",
        "object_id": "",
        "symbol": "",
    })
    _reseal(row)
    _install_reader(monkeypatch, [row])

    denominator = M.compile_primary_reopen_denominator(
        tmp_path, run_id="run-p1c-generic"
    )

    assert denominator["candidate_count"] == 1
    assert denominator["input_debt_count"] == 0
    candidate = denominator["candidates"][0]
    assert candidate["source_candidate_id"] == "SOR-0001"
    assert candidate["source_obligation_id"] == "SOR-0001"
    assert "alias:none" in candidate["evidence"]


def test_pending_subject_alias_without_relation_tuple_is_conserved(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_sha = _seed_authority(tmp_path)
    row = _pending_row(source_sha, 1)
    row.update({
        "obligation_id": "SOBL-SUBJECT-0001",
        "display_id": "SO-001",
        "relation_id": "",
        "symbol": "",
    })
    _reseal(row)
    _install_reader(monkeypatch, [row])

    denominator = M.compile_primary_reopen_denominator(
        tmp_path, run_id="run-p1c-subject-alias"
    )

    assert denominator["candidate_count"] == 1
    assert denominator["input_debt_count"] == 0
    assert denominator["candidates"][0]["source_candidate_id"] == "SOT-0001"
    assert "object:src/Bridge.sol::bridge" in denominator["candidates"][0][
        "evidence"
    ]


def test_pending_alias_is_unioned_with_candidate_negative_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import plamen_validators as V

    source_sha = _seed_authority(tmp_path)
    _install_reader(monkeypatch, [_pending_row(source_sha, 1)])
    (tmp_path / "findings_inventory.md").write_text(
        _inventory_seed(), encoding="utf-8"
    )
    write_application_skeptic_proposal_projection(
        tmp_path,
        [_candidate_negative_proposal()],
        projection_name="candidate_negative_skeptic_proposals.md",
    )
    assert V._promote_depth_findings_to_inventory(tmp_path) == ["ASKP-1"]

    denominator = M.compile_primary_reopen_denominator(
        tmp_path, run_id="run-p1c-union"
    )

    assert denominator["status"] == "READY"
    assert denominator["source_obligation_count"] == 2
    assert denominator["candidate_count"] == 2
    assert {
        row["source_artifact"] for row in denominator["candidates"]
    } == {
        "security_obligation_authority.json",
        "candidate_negative_skeptic_proposals.md",
    }


def test_more_than_twelve_pending_aliases_are_conserved_without_cap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_sha = _seed_authority(tmp_path)
    _install_reader(
        monkeypatch,
        [_pending_row(source_sha, ordinal) for ordinal in range(1, 15)],
    )

    denominator = M.compile_primary_reopen_denominator(
        tmp_path, run_id="run-p1c-fourteen"
    )
    recovery_rows = M.mandatory_recovery_rows(denominator)

    assert denominator["source_obligation_count"] == 14
    assert denominator["candidate_count"] == 14
    assert denominator["input_debt_count"] == 0
    assert len(recovery_rows) == 14
    assert len({row["work_item_id"] for row in recovery_rows}) == 14
    assert len({row["source_identity"] for row in recovery_rows}) == 14


def test_two_aliases_for_one_finding_remain_independent_recovery_obligations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_sha = _seed_authority(tmp_path)
    _install_reader(
        monkeypatch,
        [
            _pending_row(source_sha, 1, finding_id="INV-777"),
            _pending_row(source_sha, 2, finding_id="INV-777"),
        ],
    )
    denominator = M.compile_primary_reopen_denominator(
        tmp_path, run_id="run-p1c-shared-finding"
    )
    first, second = denominator["candidates"]

    assert denominator["candidate_count"] == 2
    assert {first["candidate_id"], second["candidate_id"]} == {"INV-777"}
    assert first["obligation_id"] != second["obligation_id"]

    first_work_id = "MRVW-" + first["obligation_id"][4:]
    evidence = {
        first["obligation_id"]: {
            "obligation_id": first["obligation_id"],
            "candidate_packet_sha256": first["candidate_packet_sha256"],
            "source_obligation_id": first["source_obligation_id"],
            "work_item_id": first_work_id,
            "completion_authorized": True,
            "output_sha256": "1" * 64,
            "receipt_sha256": "2" * 64,
            "contract_digest": "3" * 64,
            "execution_receipt_digest": "4" * 64,
        }
    }
    completion = M.reconcile_mandatory_recovery_completion(
        denominator=denominator,
        recovery_evidence=evidence,
    )

    state_by_id = {
        row["obligation_id"]: row["completion_state"]
        for row in completion["rows"]
    }
    assert state_by_id[first["obligation_id"]] == "EXACTLY_COMPLETED"
    assert state_by_id[second["obligation_id"]] == "RETRY_REQUIRED"


def test_two_alias_obligations_may_share_one_primary_queue_work_item(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_sha = _seed_authority(tmp_path)
    _install_reader(
        monkeypatch,
        [
            _pending_row(source_sha, 1, finding_id="INV-777"),
            _pending_row(source_sha, 2, finding_id="INV-777"),
        ],
    )
    denominator = M.compile_primary_reopen_denominator(
        tmp_path, run_id="run-p1c-shared-work"
    )
    item = QueueWorkItem.from_legacy_row({
        "finding id": "INV-777",
        "severity": "Medium",
        "title": "Shared finding",
        "bug class": "state-transition",
        "preferred tag": "CODE-TRACE",
        "location": "src/Bridge.sol:L10",
        "primary artifact": "depth_findings.md",
        "mechanism": "A bounded transition remains reachable.",
        "harm": "A protected state property may be violated.",
        "evidence": "Exact source locus and path are available.",
    })

    active, routing = M.route_mandatory_reverification(
        denominator=denominator,
        active_items=(item,),
        fallback_items=(),
    )

    assert active == (item,)
    assert routing["route_count"] == 2
    assert {row["assigned_work_item_id"] for row in routing["routes"]} == {
        "INV-777"
    }
    assert len({row["obligation_id"] for row in routing["routes"]}) == 2
    assert len({row["candidate_packet_sha256"] for row in routing["routes"]}) == 2


@pytest.mark.parametrize(
    "mutate",
    [
        lambda row: row.pop("receipt_id"),
        lambda row: row.__setitem__("source_artifact_sha256", "f" * 64),
        lambda row: row.__setitem__("source_artifact", "other.json"),
        lambda row: row.__setitem__("finding_id", "INV-CHANGED"),
        lambda row: row.__setitem__("receipt_id", "SOR-CHANGED"),
    ],
)
def test_malformed_or_stale_pending_alias_becomes_visible_source_debt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutate,
) -> None:
    source_sha = _seed_authority(tmp_path)
    row = _pending_row(source_sha, 1)
    mutate(row)
    _install_reader(monkeypatch, [row])

    denominator = M.compile_primary_reopen_denominator(
        tmp_path, run_id="run-p1c-debt"
    )

    assert denominator["status"] == "COMPLETED_WITH_DEBT"
    assert denominator["source_obligation_count"] == 1
    assert denominator["candidate_count"] == 0
    assert denominator["input_debt_count"] == 1
    assert denominator["input_debts"][0]["reason_code"].startswith(
        "SECURITY_OBLIGATION_"
    )


def test_duplicate_pending_alias_is_not_silently_coalesced(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_sha = _seed_authority(tmp_path)
    row = _pending_row(source_sha, 1)
    _install_reader(monkeypatch, [row, row])

    denominator = M.compile_primary_reopen_denominator(
        tmp_path, run_id="run-p1c-duplicate"
    )

    assert denominator["source_obligation_count"] == 2
    assert denominator["candidate_count"] == 1
    assert denominator["input_debt_count"] == 1
    assert denominator["input_debts"][0]["reason_code"] == (
        "SECURITY_OBLIGATION_DUPLICATE_ALIAS"
    )


def test_p1c_reader_failure_is_visible_when_authority_exists(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _seed_authority(tmp_path)
    import security_obligation_authority as S

    def fail(_scratchpad: Path):
        raise ValueError("fixture authority replay failed")

    monkeypatch.setattr(
        S,
        "read_pending_security_obligation_verification",
        fail,
        raising=False,
    )

    denominator = M.compile_primary_reopen_denominator(
        tmp_path, run_id="run-p1c-reader-failure"
    )

    assert denominator["source_obligation_count"] == 1
    assert denominator["candidate_count"] == 0
    assert denominator["input_debt_count"] == 1
    assert denominator["input_debts"][0]["reason_code"] == (
        "SECURITY_OBLIGATION_AUTHORITY_UNAVAILABLE"
    )


def test_so000_reader_row_is_debt_and_never_finding_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_reader(
        monkeypatch,
        [{
            "obligation_id": "SOBL-AUTHORITY-DEBT",
            "display_id": "SO-000",
            "alias_id": "",
            "relation_id": "",
            "object_id": "",
            "symbol": "",
            "finding_id": "",
            "receipt_id": "",
            "question": "Is the authority current?",
            "source_artifact": "security_obligation_authority.json",
            "source_artifact_sha256": "",
            "alias_binding_sha256": "a" * 64,
        }],
    )

    denominator = M.compile_primary_reopen_denominator(
        tmp_path, run_id="run-p1c-so000"
    )

    assert denominator["source_obligation_count"] == 1
    assert denominator["candidate_count"] == 0
    assert denominator["input_debt_count"] == 1
    assert denominator["input_debts"][0]["reason_code"] == (
        "SECURITY_OBLIGATION_AUTHORITY_DEBT"
    )
