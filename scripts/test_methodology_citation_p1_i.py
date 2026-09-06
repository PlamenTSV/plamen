"""P1-I application-evidence citation normalization fixtures.

These fixtures deliberately exercise only methodology-application evidence.
Resolving a citation is an application attestation input, never a finding
validity, severity, or disposition authority.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

import methodology_application as A
from methodology_citation import MethodologyCitationResolver
import plamen_validators as V


def _resolver(project: Path) -> MethodologyCitationResolver:
    return MethodologyCitationResolver(project, scratchpad=project / ".scratchpad")


@pytest.mark.parametrize(
    "evidence",
    (
        "src/State.sol:2",
        "src/State.sol:L2",
        r"src\State.sol:2",
        r"src\State.sol:L2",
        "[TRACE: src/State.sol:2 reached branch]",
    ),
)
def test_legacy_and_canonical_forms_normalize_to_one_location(
    tmp_path: Path, evidence: str
) -> None:
    source = tmp_path / "src" / "State.sol"
    source.parent.mkdir()
    source.write_text("line one\nline two\n", encoding="utf-8")

    result = _resolver(tmp_path).resolve_evidence(evidence)

    assert result.has_valid_citation
    assert result.citations[0].canonical == "src/State.sol:L2"


def test_spaces_are_supported_only_with_an_explicit_quote_boundary(tmp_path: Path) -> None:
    source = tmp_path / "contracts" / "Bridge Router.sol"
    source.parent.mkdir()
    source.write_text("one\ntwo\nthree\n", encoding="utf-8")

    for evidence in (
        "`contracts/Bridge Router.sol:3`",
        "'contracts/Bridge Router.sol:L3'",
        '"contracts\\Bridge Router.sol:3"',
    ):
        result = _resolver(tmp_path).resolve_evidence(evidence)
        assert result.has_valid_citation
        assert result.citations[0].canonical == "contracts/Bridge Router.sol:L3"

    assert not _resolver(tmp_path).resolve_evidence(
        "contracts/Bridge Router.sol:3"
    ).has_valid_citation


@pytest.mark.skipif(os.name != "nt", reason="Windows drive-colon fixture")
def test_absolute_windows_drive_colon_normalizes_to_project_relative(tmp_path: Path) -> None:
    source = tmp_path / "src" / "State.sol"
    source.parent.mkdir()
    source.write_text("one\ntwo\n", encoding="utf-8")

    result = _resolver(tmp_path).resolve_evidence(f"`{source}:2`")

    assert result.has_valid_citation
    assert result.citations[0].canonical == "src/State.sol:L2"


@pytest.mark.parametrize(
    ("evidence", "reason"),
    (
        ("src/Missing.sol:1", "NONEXISTENT"),
        ("src/State.sol:0", "LINE_ZERO"),
        ("src/State.sol:L999", "LINE_BEYOND_EOF"),
        ("src/../src/State.sol:1", "TRAVERSAL"),
    ),
)
def test_nonexistent_zero_beyond_eof_and_traversal_are_rejected(
    tmp_path: Path, evidence: str, reason: str
) -> None:
    source = tmp_path / "src" / "State.sol"
    source.parent.mkdir()
    source.write_text("one\ntwo\n", encoding="utf-8")

    result = _resolver(tmp_path).resolve_evidence(evidence)

    assert not result.has_valid_citation
    assert reason in {row.reason for row in result.rejections}


@pytest.mark.parametrize(
    "evidence",
    (
        "src/State.sol",
        "src/State.sol:L",
        "src/State.sol:line2",
        "src/State.txt:2",
        "src/State.sol:-1",
        "src/State.sol:L" + ("9" * 5000),
    ),
)
def test_malformed_or_non_source_tokens_are_not_citations(
    tmp_path: Path, evidence: str
) -> None:
    source = tmp_path / "src" / "State.sol"
    source.parent.mkdir()
    source.write_text("one\ntwo\n", encoding="utf-8")

    assert not _resolver(tmp_path).resolve_evidence(evidence).has_valid_citation


def test_out_of_root_absolute_path_and_symlink_escape_are_rejected(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    outside = tmp_path / "Outside.sol"
    outside.write_text("outside\n", encoding="utf-8")
    resolver = _resolver(project)

    absolute = resolver.resolve_evidence(f"`{outside}:1`")
    assert not absolute.has_valid_citation
    assert "OUT_OF_ROOT" in {row.reason for row in absolute.rejections}

    link = project / "Escape.sol"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        return
    escaped = resolver.resolve_evidence("Escape.sol:1")
    assert not escaped.has_valid_citation
    assert "OUT_OF_ROOT" in {row.reason for row in escaped.rejections}


def test_unique_suffix_is_resolved_but_ambiguous_basename_is_rejected(
    tmp_path: Path,
) -> None:
    for folder in ("alpha", "beta"):
        source = tmp_path / folder / "State.sol"
        source.parent.mkdir()
        source.write_text("line\n", encoding="utf-8")
    unique = tmp_path / "gamma" / "Unique.sol"
    unique.parent.mkdir()
    unique.write_text("line\n", encoding="utf-8")
    resolver = _resolver(tmp_path)

    ambiguous = resolver.resolve_evidence("State.sol:1")
    exact = resolver.resolve_evidence("alpha/State.sol:1")
    suffix = resolver.resolve_evidence("Unique.sol:1")

    assert not ambiguous.has_valid_citation
    assert "AMBIGUOUS" in {row.reason for row in ambiguous.rejections}
    assert exact.citations[0].canonical == "alpha/State.sol:L1"
    assert suffix.citations[0].canonical == "gamma/Unique.sol:L1"


def test_scratchpad_sources_cannot_certify_methodology_application(tmp_path: Path) -> None:
    forged = tmp_path / ".scratchpad" / "Forged.sol"
    forged.parent.mkdir()
    forged.write_text("forged\n", encoding="utf-8")

    result = _resolver(tmp_path).resolve_evidence(".scratchpad/Forged.sol:1")

    assert not result.has_valid_citation
    assert "SCRATCHPAD_EXCLUDED" in {row.reason for row in result.rejections}


def _descriptor(path: Path) -> dict[str, object]:
    return {
        "skill": "STATE_TRACE",
        "path": path.as_posix(),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "top_level_checklist_step_ids": ["1"],
    }


def _application_result(project: Path, evidence: str) -> tuple[dict[str, object], bytes]:
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    methodology = project.parent / "STATE_TRACE_SKILL.md"
    methodology.write_text("# immutable methodology\n", encoding="utf-8")
    entry = {
        "worker_id": "D1",
        "output": "depth_state_findings.md",
        "prompt_sha256": "a" * 64,
        "prompt_snapshot_required": False,
        "methodologies": [_descriptor(methodology)],
    }
    entry["dispatch_contract_sha256"] = A.worker_dispatch_contract_sha256(
        "depth", entry
    )
    A.write_phase_dispatch(
        scratchpad, phase="depth", backend="claude-pty", entries=[entry]
    )
    contract = entry["dispatch_contract_sha256"]
    trace_payload = {
        "schema_version": 1,
        "rows": [
            {
                "skill": "STATE_TRACE",
                "step": "1",
                "executed": "safe",
                "evidence": evidence,
                "result": "SAFE: concrete cited branch preserves the local relation",
            }
        ],
    }
    output = (
        "<!-- PLAMEN_DISPATCH_PHASE: depth -->\n"
        "<!-- PLAMEN_DISPATCH_WORKER: D1 -->\n"
        "<!-- PLAMEN_DISPATCH_OUTPUT: depth_state_findings.md -->\n"
        f"<!-- PLAMEN_DISPATCH_CONTRACT_SHA256: {contract} -->\n\n"
        "## Step Execution Trace\n\n"
        f"{A.TRACE_JSON_BEGIN}\n{json.dumps(trace_payload)}\n{A.TRACE_JSON_END}\n"
    ).encode("utf-8")
    (scratchpad / "depth_state_findings.md").write_bytes(output)
    return (
        A.validate_phase_application(
            scratchpad,
            project,
            phase="depth",
            trusted_methodology_roots=[project.parent],
        ),
        output,
    )


def test_legacy_repair_changes_only_application_evidence_not_finding_authority(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    source = project / "src" / "State.sol"
    source.parent.mkdir(parents=True)
    source.write_text("branch\n", encoding="utf-8")

    result, original_output = _application_result(project, "src/State.sol:1")

    assert result["status"] == "SKEPTIC_PENDING"
    row = result["rows"][0]
    assert row["application_completeness"] == "APPLIED"
    assert row["evidence_basis"] == "IN_SCOPE_SOURCE"
    assert row["skeptic_required"] is True
    assert row["negative_closure_eligible"] is True
    assert result["assurance"] == "PRODUCER_ATTESTATION_ONLY"
    assert (project / ".scratchpad" / "depth_state_findings.md").read_bytes() == original_output
    assert not ({"finding_id", "severity", "verdict"} & set(row))


def test_depth_trace_validator_uses_the_same_two_form_application_contract(
    tmp_path: Path,
) -> None:
    source = tmp_path / "src" / "State.sol"
    source.parent.mkdir()
    source.write_text("one\ntwo\n", encoding="utf-8")

    assert V._step_trace_evidence_has_citation("src/State.sol:2", tmp_path)
    assert V._step_trace_evidence_has_citation("src/State.sol:L2", tmp_path)
