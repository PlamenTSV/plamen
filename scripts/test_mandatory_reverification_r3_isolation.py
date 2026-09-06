"""R3 fixtures for per-candidate mandatory re-verification isolation."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import mandatory_reverification as M
from finding_producer_registry import (
    canonical_digest,
    write_application_skeptic_proposal_projection,
)


def _proposal(token: str, *, mechanism: str | None = None) -> dict[str, object]:
    unsigned: dict[str, object] = {
        "schema_version": "plamen.finding_candidate_proposal.v1",
        "producer": "application_skeptic",
        "source_obligation_id": f"OBL-{token}",
        "source_work_item_id": "ASW-" + token * 24,
        "assessor_identity": "independent-assessor",
        "assessor_invocation_id": f"assessment-{token}",
        "assessor_evidence_sha256": token.lower() * 64,
        "candidate": {
            "title": f"Candidate {token}",
            "mechanism": mechanism or f"Mechanism {token}",
            "harm": f"Harm {token}",
        },
    }
    digest = canonical_digest(unsigned)
    return {
        **unsigned,
        "proposal_id": "ASCP-" + digest[:24].upper(),
        "proposal_digest": digest,
    }


def _candidate(token: str) -> dict[str, object]:
    return {
        "obligation_kind": "ADDITIVE_REOPEN",
        "candidate_id": f"INV-{token}",
        "source_candidate_id": f"ASKP-{token}",
        "source_artifact": "application_skeptic_proposals.md",
        "source_artifact_sha256": "a" * 64,
        "source_proposal_id": f"ASCP-{token}",
        "source_obligation_id": f"ASW-{token}",
        "candidate_content_sha256": "b" * 64,
        "premise": f"Premise {token}",
        "harm": f"Harm {token}",
        "evidence": f"Evidence {token}",
    }


def _build(*candidates: dict[str, object]) -> dict[str, object]:
    return M.build_mandatory_reverification_denominator(
        run_id="run-r3-isolation",
        candidates=candidates,
        source_bindings=[{
            "artifact": "application_skeptic_proposals.md",
            "sha256": "a" * 64,
        }],
        source_obligation_count=len(candidates),
    )


def test_producer_valid_tab_candidate_does_not_abort_siblings(tmp_path: Path) -> None:
    proposals = [
        _proposal("A"),
        _proposal("B", mechanism="tab\tseparated mechanism"),
        _proposal("C"),
    ]
    write_application_skeptic_proposal_projection(tmp_path, proposals)

    parsed, debts, observed = M._parse_primary_projection_candidates(
        tmp_path / "application_skeptic_proposals.md",
        producer="application_skeptic",
    )

    assert observed == 3
    assert debts == []
    assert len(parsed) == 3
    assert "tab\tseparated mechanism" in {
        row["candidate"]["mechanism"] for row in parsed
    }
    tab_candidate = _candidate("302")
    tab_candidate["premise"] = "tab\tseparated mechanism"
    denominator = _build(_candidate("301"), tab_candidate, _candidate("303"))
    assert denominator["candidate_count"] == 3
    assert denominator["input_debt_count"] == 0


def test_one_malformed_projection_row_is_typed_debt_not_bulk_loss(
    tmp_path: Path,
) -> None:
    write_application_skeptic_proposal_projection(
        tmp_path, [_proposal("A"), _proposal("B"), _proposal("C")]
    )
    path = tmp_path / "application_skeptic_proposals.md"
    text = path.read_text(encoding="utf-8")
    blocks = text.split("### Finding ")
    blocks[2] = blocks[2].replace(
        "**Proposal Digest**: ", "**Proposal Digest**: " + "0" * 64 + "\nBROKEN: ", 1
    )
    path.write_text("### Finding ".join(blocks), encoding="utf-8")

    parsed, debts, observed = M._parse_primary_projection_candidates(
        path, producer="application_skeptic"
    )

    assert observed == 3
    assert len(parsed) == 2
    assert len(debts) == 1
    assert debts[0]["reason_code"] == "SOURCE_PROJECTION_CANDIDATE_MALFORMED"
    assert debts[0]["source_identity"].startswith("ASCP-")


def test_duplicate_candidate_packet_becomes_debt_without_erasing_valid_row() -> None:
    first = _candidate("101")
    duplicate = deepcopy(first)
    second = _candidate("102")

    denominator = _build(first, duplicate, second)

    assert denominator["candidate_count"] == 2
    assert denominator["input_debt_count"] == 1
    assert denominator["source_obligation_count"] == 3
    assert denominator["input_debts"][0]["reason_code"] == (
        "CANDIDATE_OBLIGATION_ID_DUPLICATE"
    )
    assert denominator["terminal_negative_authority"] is False


def test_repeated_projection_ids_are_quarantined_per_row(tmp_path: Path) -> None:
    write_application_skeptic_proposal_projection(tmp_path, [_proposal("D")])
    path = tmp_path / "application_skeptic_proposals.md"
    text = path.read_text(encoding="utf-8")
    start = text.index("### Finding ")
    end = text.index("<!-- PLAMEN_STATUS: COMPLETE -->")
    block = text[start:end]
    path.write_text(text[:end] + block + text[end:], encoding="utf-8")

    parsed, debts, observed = M._parse_primary_projection_candidates(
        path, producer="application_skeptic"
    )

    assert observed == 2
    assert len(parsed) == 1
    assert len(debts) == 1
    assert debts[0]["reason_code"] == "SOURCE_PROJECTION_CANDIDATE_ID_DUPLICATE"


def test_isolated_denominator_resume_is_byte_deterministic(tmp_path: Path) -> None:
    malformed = _candidate("202")
    malformed["candidate_content_sha256"] = "not-a-digest"
    denominator = _build(_candidate("201"), malformed, _candidate("203"))
    path = tmp_path / M.DENOMINATOR_FILE

    assert denominator["candidate_count"] == 2
    assert denominator["input_debt_count"] == 1
    assert denominator["input_debts"][0]["reason_code"] == (
        "CANDIDATE_INPUT_MALFORMED"
    )
    assert M.write_or_validate_mandatory_artifact(path, denominator) is True
    first = path.read_bytes()
    assert M.write_or_validate_mandatory_artifact(path, denominator) is False
    assert path.read_bytes() == first
    assert _build(_candidate("201"), malformed, _candidate("203")) == denominator
