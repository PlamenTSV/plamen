"""Tests for v2.0.8 P3 — verdict_manifest.json (evidence-chain integrity).

Covers:
  P3.1  _classify_integrity + _write_verdict_manifest in mechanical_verify
        — CONSISTENT / INFLATED_PROSE / MECHANICAL_UNAVAILABLE classes;
        effective_tag is the authoritative downstream evidence.
  P3.2  Skeptic prompt directive references effective_tag.
  P3.3  Report-index prompt rule 5 references effective_tag (not verifier prose).
  P3.4  Tests for all of the above plus a synthetic inflation case.
"""
from __future__ import annotations

import json
import sys
import types
from dataclasses import dataclass
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

from mechanical_verify import (  # noqa: E402
    _classify_integrity,
    _extract_verifier_prose_tag,
    _write_verdict_manifest,
    read_verdict_manifest,
)


@dataclass
class _FakeResult:
    """Minimal stand-in for mechanical_verify.ExecResult so tests don't
    depend on the dataclass module-level definition."""
    verify_file: str
    finding_id: str
    status: str


# ---------------------------------------------------------------------------
# P3.1 — _classify_integrity matrix
# ---------------------------------------------------------------------------


def test_p31_consistent_when_prose_matches_mechanical_pass():
    """Both PASS and prose POC-PASS → CONSISTENT, effective_tag preserved."""
    state, tag = _classify_integrity("[POC-PASS]", "PASS")
    assert state == "CONSISTENT"
    assert tag == "[POC-PASS]"


def test_p31_mechanical_pass_upgrades_conservative_prose():
    """If mechanical actually PASSED but prose claimed only [CODE-TRACE],
    mechanical truth WINS — effective_tag upgraded to [POC-PASS]."""
    state, tag = _classify_integrity("[CODE-TRACE]", "PASS")
    assert state == "CONSISTENT"
    assert tag == "[POC-PASS]"


def test_p31_inflated_prose_when_poc_pass_but_no_test():
    """Codex Point 5 canonical case: prose [POC-PASS] + mechanical NO_TEST_FILE
    → INFLATED_PROSE, effective_tag downgraded with [INTEGRITY-DOWNGRADE] flag.
    """
    state, tag = _classify_integrity("[POC-PASS]", "NO_TEST_FILE")
    assert state == "INFLATED_PROSE"
    assert "[CODE-TRACE]" in tag
    assert "[INTEGRITY-DOWNGRADE]" in tag


def test_p31_inflated_prose_when_poc_pass_but_fail():
    """Prose claims PASS but mechanical FAILED → also INFLATED_PROSE."""
    state, tag = _classify_integrity("[POC-PASS]", "FAIL")
    assert state == "INFLATED_PROSE"
    assert "[INTEGRITY-DOWNGRADE]" in tag


def test_p31_consistent_when_prose_and_mechanical_both_fail():
    """Both indicate failure → CONSISTENT (verifier wasn't inflating)."""
    state, tag = _classify_integrity("[POC-FAIL]", "FAIL")
    assert state == "CONSISTENT"
    assert tag == "[POC-FAIL]"


def test_p31_mechanical_unavailable_preserves_prose_with_flag():
    """Toolchain unavailable → MECHANICAL_UNAVAILABLE; effective preserves
    prose + flag (we couldn't verify either way)."""
    state, tag = _classify_integrity("[POC-PASS]", "TOOLCHAIN_UNAVAILABLE")
    assert state == "MECHANICAL_UNAVAILABLE"
    assert "[POC-PASS]" in tag
    assert "[MECHANICAL-UNAVAILABLE]" in tag


def test_p31_empty_prose_no_test_falls_to_code_trace():
    """No prose tag + NO_TEST_FILE → effective [CODE-TRACE] (the floor)."""
    state, tag = _classify_integrity("", "NO_TEST_FILE")
    assert state == "CONSISTENT"
    assert tag == "[CODE-TRACE]"


def test_p31_medusa_pass_treated_as_proof_grade():
    """[MEDUSA-PASS] is in the proof-grade set; PASS confirms it."""
    state, tag = _classify_integrity("[MEDUSA-PASS]", "PASS")
    assert state == "CONSISTENT"
    assert tag == "[MEDUSA-PASS]"


def test_p31_medusa_pass_no_test_is_inflated():
    """[MEDUSA-PASS] claimed but no mechanical test → INFLATED_PROSE."""
    state, _ = _classify_integrity("[MEDUSA-PASS]", "NO_TEST_FILE")
    assert state == "INFLATED_PROSE"


# ---------------------------------------------------------------------------
# P3.1 — _extract_verifier_prose_tag
# ---------------------------------------------------------------------------


def test_p31_extract_prose_tag_from_verify_file(tmp_path):
    """Reads the FIRST evidence-tag token from verify_<ID>.md."""
    (tmp_path / "verify_HH-01.md").write_text(
        "**Severity**: High\n"
        "**Evidence Tag**: [POC-PASS]\n"
        "**Verdict**: CONFIRMED\n",
        encoding="utf-8",
    )
    assert _extract_verifier_prose_tag(tmp_path / "verify_HH-01.md") == "[POC-PASS]"


def test_p31_extract_prose_tag_missing_returns_empty(tmp_path):
    """No evidence tag in the file → ''."""
    (tmp_path / "verify_HH-02.md").write_text(
        "**Severity**: High\nJust prose, no tags.\n", encoding="utf-8",
    )
    assert _extract_verifier_prose_tag(tmp_path / "verify_HH-02.md") == ""


def test_p31_extract_prose_tag_nonexistent_returns_empty(tmp_path):
    """File doesn't exist → ''."""
    assert _extract_verifier_prose_tag(tmp_path / "verify_NOPE.md") == ""


# ---------------------------------------------------------------------------
# P3.1 — _write_verdict_manifest end-to-end
# ---------------------------------------------------------------------------


def test_p31_manifest_round_trip(tmp_path):
    """Write a verdict manifest from synthetic results; read back; semantic
    equivalence; schema_version correct.
    """
    (tmp_path / "verify_HH-01.md").write_text(
        "**Evidence Tag**: [POC-PASS]\n", encoding="utf-8",
    )
    (tmp_path / "verify_HH-02.md").write_text(
        "**Evidence Tag**: [POC-PASS]\n", encoding="utf-8",
    )
    (tmp_path / "verify_HH-03.md").write_text(
        "**Evidence Tag**: [CODE-TRACE]\n", encoding="utf-8",
    )
    results = [
        _FakeResult(verify_file="verify_HH-01.md", finding_id="HH-01", status="PASS"),
        _FakeResult(verify_file="verify_HH-02.md", finding_id="HH-02", status="NO_TEST_FILE"),
        _FakeResult(verify_file="verify_HH-03.md", finding_id="HH-03", status="NO_TEST_FILE"),
    ]
    _write_verdict_manifest(results, tmp_path)
    out = tmp_path / "verdict_manifest.json"
    assert out.exists()
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "plamen.verdict_manifest.v1"
    assert payload["row_count"] == 3
    # Read via helper too
    rows = read_verdict_manifest(tmp_path)
    by_id = {r["finding_id"]: r for r in rows}
    # HH-01: CONSISTENT (POC-PASS + PASS)
    assert by_id["HH-01"]["integrity_state"] == "CONSISTENT"
    assert by_id["HH-01"]["effective_tag"] == "[POC-PASS]"
    # HH-02: INFLATED_PROSE (POC-PASS prose + NO_TEST_FILE mechanical)
    assert by_id["HH-02"]["integrity_state"] == "INFLATED_PROSE"
    assert "[INTEGRITY-DOWNGRADE]" in by_id["HH-02"]["effective_tag"]
    # HH-03: CONSISTENT ([CODE-TRACE] prose + NO_TEST_FILE — verifier was honest)
    assert by_id["HH-03"]["integrity_state"] == "CONSISTENT"
    assert by_id["HH-03"]["effective_tag"] == "[CODE-TRACE]"


def test_p31_exact_semantic_replay_preserves_physical_identity(
    tmp_path, monkeypatch,
):
    import mechanical_verify as mechanical

    verify = tmp_path / "verify_HH-01.md"
    verify.write_text("**Evidence Tag**: [CODE-TRACE]\n", encoding="utf-8")
    results = [
        _FakeResult(
            verify_file=verify.name,
            finding_id="HH-01",
            status="NO_TEST_FILE",
        )
    ]
    clock = {"value": "2026-01-01T00:00:00"}
    monkeypatch.setattr(mechanical.time, "strftime", lambda _fmt: clock["value"])
    mechanical._write_verdict_manifest(results, tmp_path)
    path = tmp_path / "verdict_manifest.json"
    before = path.stat()
    clock["value"] = "2099-12-31T23:59:59"
    mechanical._write_verdict_manifest(results, tmp_path)
    after = path.stat()
    assert (after.st_dev, after.st_ino, after.st_mtime_ns) == (
        before.st_dev, before.st_ino, before.st_mtime_ns,
    )


def test_p31_read_returns_empty_on_missing(tmp_path):
    """No verdict_manifest.json → []."""
    assert read_verdict_manifest(tmp_path) == []


def test_p31_read_rejects_wrong_schema(tmp_path):
    """Wrong schema_version → [] (reader is strict about contract)."""
    payload = {
        "schema_version": "plamen.something_else.v1",
        "verdicts": [{"finding_id": "X"}],
    }
    (tmp_path / "verdict_manifest.json").write_text(
        json.dumps(payload), encoding="utf-8",
    )
    assert read_verdict_manifest(tmp_path) == []


# ---------------------------------------------------------------------------
# P3.1 — inflation-shape scenario (synthetic)
# ---------------------------------------------------------------------------


def test_p31_inflation_shape_caught(tmp_path):
    """Synthetic mirror of an observed failure: a verifier prose-claims
    [POC-PASS] across multiple findings, but mechanical execution shows
    NO_TEST_FILE for all of them. P3 must flag every one as INFLATED_PROSE.
    """
    # 5 verify files all claiming [POC-PASS] but with no real test backing
    for i in range(1, 6):
        (tmp_path / f"verify_HH-0{i}.md").write_text(
            f"**Severity**: High\n**Evidence Tag**: [POC-PASS]\n"
            f"**Verdict**: CONFIRMED\n", encoding="utf-8",
        )
    results = [
        _FakeResult(verify_file=f"verify_HH-0{i}.md",
                    finding_id=f"HH-0{i}", status="NO_TEST_FILE")
        for i in range(1, 6)
    ]
    _write_verdict_manifest(results, tmp_path)
    rows = read_verdict_manifest(tmp_path)
    inflated = [r for r in rows if r["integrity_state"] == "INFLATED_PROSE"]
    assert len(inflated) == 5, (
        f"Expected 5 INFLATED_PROSE entries (inflation-shape scenario), got "
        f"{len(inflated)}"
    )
    # All effective_tags must carry the downgrade flag.
    assert all("[INTEGRITY-DOWNGRADE]" in r["effective_tag"] for r in inflated)


# ---------------------------------------------------------------------------
# P3.2/P3.3 — prompt updates reference verdict_manifest.json
# ---------------------------------------------------------------------------


def test_p32_skeptic_prompt_references_verdict_manifest():
    """Skeptic prompt directs the LLM to consume effective_tag from manifest."""
    text = (
        SCRIPTS_DIR.parent / "prompts" / "shared" / "v2" / "phase5-skeptic.md"
    ).read_text(encoding="utf-8")
    assert "verdict_manifest.json" in text
    assert "effective_tag" in text
    assert "INFLATED_PROSE" in text


def test_p33_report_index_prompt_references_verdict_manifest():
    """Report-index rule 5 references effective_tag (not verifier prose)."""
    text = (
        SCRIPTS_DIR.parent / "prompts" / "shared" / "v2" / "phase6a-report-index.md"
    ).read_text(encoding="utf-8")
    assert "verdict_manifest.json" in text
    assert "effective_tag" in text
    assert "INFLATED_PROSE" in text or "integrity_state" in text
