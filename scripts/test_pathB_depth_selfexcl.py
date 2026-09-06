"""F3 — depth-agent belief-based self-exclusion recall net.

Depth agents self-drop confirmed-mechanism candidates under "Non-Reportable /
Absorbed Candidates" (or "self-dropped") sections of depth_*_findings.md. Unlike
a verifier-refuted finding, these drops are frequently justified WITHOUT an
in-scope refutation — either citing no referent, or resting on an UNVERIFIED
EXTERNAL assumption ("reverts on insufficiency", "atomic", "out of scope",
"assume ...", "guaranteed by ...") — silently dropping a true positive.

Fix (depth analogue of the Phase 3c per-contract net):
- GATE: _validate_depth_self_exclusion flags absorbed candidates that (a) cite no
  concrete in-scope referent OR (b) rest on an unverified external assumption.
- DRIVER: _reemit_depth_self_exclusions mints `### Finding [DXRE-k]` blocks
  only for content-bearing rows; content-less rows become source-bound
  `Review Disposition [DXRE-k]` methodology debt.

Counterplan narrowing: legitimately-refuted candidates that cite a concrete
in-scope refutation (a real file:Lnnn, no external assumption) are NOT
re-emitted; content-less re-emits route to APPENDIX only (no body flood).

Recall-safe: the validator ONLY ever adds candidates; never removes/refutes a
finding, never hard-fails a clean run. Idempotent across retries.
"""

from __future__ import annotations

import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

import plamen_driver as D  # noqa: E402
from plamen_validators import _validate_depth_self_exclusion  # noqa: E402


def _write(sp: Path, name: str, text: str) -> None:
    (sp / name).write_text(text, encoding="utf-8")


# A first-pass breadth finding the depth agent could legitimately cite as a
# referent (populates the referent universe).
PROVIDED_BREADTH = (
    "# Breadth Agent 1\n\n"
    "## Findings\n\n"
    "## Finding [B1-4]: Reentrancy in withdraw\n\n"
    "**Severity**: High\n"
    "**Location**: vault.sol:L120\n"
    "**Description**: classic reentrancy.\n"
)


# --------------------------------------------------------------------------
# (1) DROP-REPRODUCTION: absorbed candidate dropped on "reverts on
#     insufficiency" with NO cited referent -> flagged + re-emitted as DXRE.
# --------------------------------------------------------------------------

def test_drop_reproduction_external_assumption_no_referent_flagged_and_reemitted(tmp_path):
    _write(tmp_path, "analysis_1.md", PROVIDED_BREADTH)
    _write(
        tmp_path,
        "depth_token_flow_findings.md",
        "# Depth Token-Flow Agent\n\n"
        "## Findings\n\n"
        "## Finding [TF-1]: A real reported finding\n\n"
        "**Severity**: High\n"
        "**Location**: Pool.sol:L50\n"
        "**Description**: real.\n\n"
        "## Non-Reportable / Absorbed Candidates\n\n"
        "- ABSORBED underflow in payout drains funds — dropped because the "
        "call reverts on insufficiency\n",
    )

    warnings, recovered = _validate_depth_self_exclusion(tmp_path)
    assert warnings, "external-assumption drop must produce a warning"
    assert recovered, "the suppressed candidate must be recovered for re-emit"
    assert recovered[0]["external_assumption"] is True

    # This source row has no concrete location, so it is retained as review
    # debt rather than fabricated into a vulnerability finding.
    out = D._reemit_depth_self_exclusions(tmp_path, recovered)
    assert out is not None and out.exists()
    assert out.name == "depth_selfexcl_reemit_findings.md"
    body = out.read_text(encoding="utf-8")
    assert "### Review Disposition [DXRE-1]:" in body
    assert "CONTENT_LESS_HUMAN_REVIEW" in body
    assert "### Finding [DXRE-1]:" not in body
    assert "<!-- PLAMEN_STATUS: COMPLETE -->" in body


# --------------------------------------------------------------------------
# (2) HEALTHY NO-OP: absorbed candidate citing a concrete file:Lnnn
#     refutation (no external assumption) -> NOT flagged / NOT re-emitted.
# --------------------------------------------------------------------------

def test_healthy_noop_concrete_inscope_refutation_not_reemitted(tmp_path):
    _write(tmp_path, "analysis_1.md", PROVIDED_BREADTH)
    _write(
        tmp_path,
        "depth_state_trace_findings.md",
        "# Depth State-Trace Agent\n\n"
        "## Findings\n\n"
        "## Non-Reportable / Absorbed Candidates\n\n"
        "- ABSORBED potential double-spend refuted: the guard at "
        "Ledger.sol:L120 requires nonce increment before payout\n",
    )
    warnings, recovered = _validate_depth_self_exclusion(tmp_path)
    assert warnings == []
    assert recovered == []
    assert not (tmp_path / "depth_selfexcl_reemit_findings.md").exists()


# --------------------------------------------------------------------------
# (3) IDEMPOTENCY: a line already tagged [RE-EMITTED] is not re-flagged.
# --------------------------------------------------------------------------

def test_idempotency_reemitted_line_not_reflagged(tmp_path):
    _write(tmp_path, "analysis_1.md", PROVIDED_BREADTH)
    # A depth file that already contains a driver-minted re-emit tag on the entry.
    _write(
        tmp_path,
        "depth_edge_case_findings.md",
        "# Depth Edge-Case Agent\n\n"
        "## Findings\n\n"
        "## Non-Reportable / Absorbed Candidates\n\n"
        "- ABSORBED overflow drains funds — dropped, assume oracle fresh "
        "[RE-EMITTED: depth self-exclusion without in-scope referent]\n",
    )
    warnings, recovered = _validate_depth_self_exclusion(tmp_path)
    assert warnings == []
    assert recovered == []

    # Also confirm the driver-owned re-emit artifact is excluded from re-scanning:
    # feeding a previously-generated DXRE file back through the validator is a no-op.
    _write(tmp_path, "analysis_1.md", PROVIDED_BREADTH)
    _write(
        tmp_path,
        "depth_selfexcl_reemit_findings.md",
        "# Depth Self-Exclusion Re-Emit\n\n"
        "## Non-Reportable / Absorbed Candidates\n\n"
        "### Finding [DXRE-1]: underflow drains funds "
        "[RE-EMITTED: depth self-exclusion without in-scope referent]\n"
        "**Location**: Pool.sol:L9\n",
    )
    warnings2, recovered2 = _validate_depth_self_exclusion(tmp_path)
    assert recovered2 == [], "driver-owned re-emit file must not be re-scanned"


# --------------------------------------------------------------------------
# CONTENT ROUTING: content-less -> methodology/human-review debt;
# content-bearing -> own severity at LOW confidence (dedup/resolve). Both KEPT,
# neither dropped, and content-less rows never become vulnerability findings.
# --------------------------------------------------------------------------

def test_contentless_reemit_routes_to_appendix_not_body(tmp_path):
    _write(tmp_path, "analysis_1.md", PROVIDED_BREADTH)
    # "out of scope" external assumption, no concrete location, no harm signal.
    _write(
        tmp_path,
        "depth_external_findings.md",
        "# Depth External Agent\n\n"
        "## Findings\n\n"
        "## Non-Reportable / Absorbed Candidates\n\n"
        "- ABSORBED some concern, out of scope\n",
    )
    warnings, recovered = _validate_depth_self_exclusion(tmp_path)
    assert recovered
    assert recovered[0]["content_bearing"] is False

    out = D._reemit_depth_self_exclusions(tmp_path, recovered)
    body = out.read_text(encoding="utf-8")
    assert "**Severity**:" not in body
    assert "CONTENT_LESS_HUMAN_REVIEW" in body
    assert "### Review Disposition [DXRE-1]:" in body
    assert "### Finding [DXRE-1]:" not in body
    assert "[DXRE-1]" in body  # kept, not dropped


def test_contentbearing_reemit_keeps_severity_at_low_confidence(tmp_path):
    _write(tmp_path, "analysis_1.md", PROVIDED_BREADTH)
    # Concrete location + harm vocabulary + external assumption to trigger.
    # Severity supplied as a table-row cell so it is parsed and preserved.
    _write(
        tmp_path,
        "depth_token_flow_findings.md",
        "# Depth Token-Flow Agent\n\n"
        "## Findings\n\n"
        "## Non-Reportable / Absorbed Candidates\n\n"
        "| ABSORBED reward accounting drains funds at Vault.sol:L412 stale "
        "balance lets attacker steal, but assume keeper acts honestly | High |\n",
    )
    warnings, recovered = _validate_depth_self_exclusion(tmp_path)
    assert recovered
    assert recovered[0]["content_bearing"] is True

    out = D._reemit_depth_self_exclusions(tmp_path, recovered)
    body = out.read_text(encoding="utf-8")
    assert "**Severity**: High" in body  # own severity preserved, not downgraded
    assert "**Severity**: Informational" not in body
    assert "CONTENT-LESS" not in body
    assert "**Confidence**: LOW" in body  # LOW confidence per F3
    assert "vault.sol:l412" in body.lower()


# --------------------------------------------------------------------------
# RECALL-SAFETY: never false-fire / never crash on a clean run.
# --------------------------------------------------------------------------

def test_recall_safe_no_self_exclusion_section(tmp_path):
    _write(tmp_path, "analysis_1.md", PROVIDED_BREADTH)
    _write(
        tmp_path,
        "depth_edge_case_findings.md",
        "# Depth Edge-Case Agent\n\n## Findings\n\n"
        "## Finding [DE-1]: only findings here\n\n"
        "**Severity**: Low\n**Location**: vault.sol:L9\n**Description**: x.\n",
    )
    warnings, recovered = _validate_depth_self_exclusion(tmp_path)
    assert warnings == []
    assert recovered == []
    assert not (tmp_path / "depth_selfexcl_reemit_findings.md").exists()


def test_recall_safe_no_depth_files(tmp_path):
    _write(tmp_path, "analysis_1.md", PROVIDED_BREADTH)
    assert _validate_depth_self_exclusion(tmp_path) == ([], [])


def test_recall_safe_empty_scratchpad(tmp_path):
    assert _validate_depth_self_exclusion(tmp_path) == ([], [])


def test_recall_safe_unparseable_depth_file(tmp_path):
    (tmp_path / "depth_x_findings.md").write_bytes(b"\xff\xfe\x00\x01garbage")
    warnings, recovered = _validate_depth_self_exclusion(tmp_path)
    assert isinstance(warnings, list) and isinstance(recovered, list)


def test_reemit_noop_on_empty_recovered(tmp_path):
    assert D._reemit_depth_self_exclusions(tmp_path, []) is None
    assert not (tmp_path / "depth_selfexcl_reemit_findings.md").exists()


# --------------------------------------------------------------------------
# MIXED: only the referent-less/external entry is flagged; the concretely-refuted
# one is left alone.
# --------------------------------------------------------------------------

def test_mixed_only_unjustified_drop_flagged(tmp_path):
    _write(tmp_path, "analysis_1.md", PROVIDED_BREADTH)
    _write(
        tmp_path,
        "depth_state_trace_findings.md",
        "# Depth State-Trace Agent\n\n## Findings\n\n"
        "## Non-Reportable / Absorbed Candidates\n\n"
        "- ABSORBED reentrancy refuted by guard at Vault.sol:L120 (nonReentrant)\n"
        "- ABSORBED underflow drains funds — dropped, not demonstrable\n",
    )
    warnings, recovered = _validate_depth_self_exclusion(tmp_path)
    assert len(recovered) == 1, "exactly one unjustified drop expected"
    assert "underflow" in recovered[0]["line_text"]
    joined = " ".join(c["line_text"] for c in recovered)
    assert "nonReentrant" not in joined


# --------------------------------------------------------------------------
# BLEMISH 1: a bare Markdown horizontal rule (---, ***, ___) inside an absorbed
# section must be treated as a separator, NOT minted as a spurious content-less
# entry. (Old entry regex `^\s*(?:[-*+]|\|)` matched the leading -/* and would
# have emitted one recovered stub per HR line.)
# --------------------------------------------------------------------------

def test_bare_hr_in_section_not_emitted_as_entry(tmp_path):
    _write(tmp_path, "analysis_1.md", PROVIDED_BREADTH)
    _write(
        tmp_path,
        "depth_edge_case_findings.md",
        "# Depth Edge-Case Agent\n\n## Findings\n\n"
        "## Non-Reportable / Absorbed Candidates\n\n"
        "---\n"
        "***\n"
        "___\n",
    )
    warnings, recovered = _validate_depth_self_exclusion(tmp_path)
    assert recovered == [], "bare horizontal rules must not become entries"
    assert warnings == []
    assert not (tmp_path / "depth_selfexcl_reemit_findings.md").exists()


# --------------------------------------------------------------------------
# BLEMISH 2: a multi-line absorbed bullet whose concrete file:Lnnn (and
# severity) sits on CONTINUATION lines must fold into ONE logical entry and be
# classified CONTENT-BEARING at its own severity (re-emitted, NOT appendix) —
# not scanned per physical line (which misses the location and mis-routes the
# drop to a content-less appendix stub, and turns a `**`-prefixed continuation
# line into its own spurious entry).
# --------------------------------------------------------------------------

def test_multiline_absorbed_bullet_location_on_continuation_is_content_bearing(tmp_path):
    _write(tmp_path, "analysis_1.md", PROVIDED_BREADTH)
    # Harm on line 1; concrete file:Lnnn + severity on **-prefixed continuation
    # lines. External assumption ("assume ...") triggers the net.
    _write(
        tmp_path,
        "depth_token_flow_findings.md",
        "# Depth Token-Flow Agent\n\n## Findings\n\n"
        "## Non-Reportable / Absorbed Candidates\n\n"
        "- ABSORBED reward accounting drains funds, but assume keeper honest\n"
        "  **Location**: Vault.sol:L412\n"
        "  **Severity**: High\n",
    )
    warnings, recovered = _validate_depth_self_exclusion(tmp_path)
    assert len(recovered) == 1, "continuation lines must fold into ONE entry"
    cand = recovered[0]
    assert cand["content_bearing"] is True, "location on line 2 must be detected"
    # _norm_referent_location lowercases + drops the leading "L" on the line no.
    assert "vault.sol:412" in cand["location"].lower()

    out = D._reemit_depth_self_exclusions(tmp_path, recovered)
    body = out.read_text(encoding="utf-8")
    # Own severity preserved (content-bearing), NOT downgraded to appendix.
    assert "**Severity**: High" in body
    assert "**Severity**: Informational" not in body
    assert "CONTENT-LESS" not in body
    # Exactly one DXRE block — not one per physical line.
    assert body.count("### Finding [DXRE-") == 1


if __name__ == "__main__":
    import pytest

    sys.exit(pytest.main([__file__, "-q"]))
