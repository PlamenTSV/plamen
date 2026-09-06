"""Pipeline v2.8.9 — depth/scanner promotion retention leak (retention sweep).

Root cause: the depth-promotion bridge (`_promote_depth_findings_to_inventory`)
and its receipt gate (`_validate_depth_promotion_receipt`) parse finding blocks
via `_parse_depth_finding_blocks`, whose heading regex only accepts ids in
`_PROMOTABLE_FEEDER_ID_PATTERN`. That pattern had `DST-`/`DEC-`/`BS-` but the SC
depth/scanner agents actually emit `DS-` (state-trace), `DE-` (edge-case),
`DT-` (token-flow), `BLIND-` (scanners). Result: 0 findings parsed from four core
channels → bridge promoted nothing, receipt gate passed vacuously → Medium+
depth-only findings (incl. a CONFIRMED High, DS-1) silently dropped.

Fix: (1) add `DS-/DE-/DT-/BLIND-` to `_PROMOTABLE_FEEDER_ID_PATTERN`; (2) add
`depth_token_flow_findings.md` to `_DEPTH_PROMOTION_FILES` (it was absent — the
list was authored L1-first where token-flow does not load).

Run: pytest scripts/test_pipeline_v2_8_9_retention.py -q
"""
from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

import plamen_parsers as P  # noqa: E402
import plamen_validators as V  # noqa: E402


def _mkscratch(files: dict[str, str]) -> Path:
    sp = Path(tempfile.mkdtemp(prefix="plamen_v289_"))
    for name, body in files.items():
        (sp / name).write_text(body, encoding="utf-8")
    return sp


def _full(s: str) -> bool:
    return bool(re.fullmatch(P._PROMOTABLE_FEEDER_ID_PATTERN, s))


# ---------------------------------------------------------------------------
# Pattern: recognizes the actually-emitted ids, no over-match
# ---------------------------------------------------------------------------

def test_pattern_matches_real_depth_scanner_ids():
    for x in ["DS-1", "DE-3", "DT-5", "BLIND-A1", "BLIND-B-1", "BLIND-C1", "PERT-1"]:
        assert _full(x), x


def test_pattern_still_matches_preexisting_prefixes():
    # DST-=design_stress, DEC-/DX- distinct channels must still resolve.
    for x in ["DST-2", "DEC-1", "DX-7", "VS-6", "ATT-1"]:
        assert _full(x), x


def test_pattern_does_not_match_report_ids_or_word_internal():
    for x in ["C-01", "M-12", "H-05", "L-3", "I-2"]:
        assert not _full(x), x
    pat = re.compile(r"\b" + P._PROMOTABLE_FEEDER_ID_PATTERN + r"\b")
    context_free = re.compile(
        r"\b" + P._PROMOTABLE_CONTEXT_FREE_FEEDER_ID_PATTERN + r"\b"
    )
    # DS-/DE-/DT- require a digit, so they cannot match inside DST-/DEC-/DX-N
    # nor inside ordinary words.
    # Generic producer-local IDs are valid only at an owning-artifact boundary;
    # context-free extraction must reject ordinary word-shaped tokens.
    assert context_free.findall("see WORDS-1 and ADDRESS-12") == []
    assert pat.findall("| C-02 | Critical | drains funds |") == []


# ---------------------------------------------------------------------------
# Block parser: parses the real heading form, ignores non-finding headings
# ---------------------------------------------------------------------------

def test_block_parser_parses_ds_de_blind_headings():
    sp = _mkscratch({
        "depth_state_trace_findings.md": (
            "## DEPTH ANALYSIS: State Trace\n\n"
            "### Finding [DS-1]: Drain via empty swapData\n"
            "**Severity**: High\n**Location**: NativeVault.sol:L530\n"
            "**Verdict**: CONFIRMED\n**Preferred Tag**: [CODE-TRACE]\n"
            "**Description**: distinct mechanism.\n\n"
            "### Source: DS-9 (mutation analysis of an existing finding)\n"
            "this is a perturbation/source analysis block, NOT a new finding\n\n"
            "### Finding [BLIND-C1]: renounceOwnership callable\n"
            "**Severity**: Medium\n**Location**: CrossChainRouter.sol:L19\n"
            "**Verdict**: CONFIRMED\n**Description**: permanent ownership loss.\n"
        ),
    })
    ids = [b["id"] for b in P._parse_depth_finding_blocks(sp / "depth_state_trace_findings.md")]
    assert "DS-1" in ids and "BLIND-C1" in ids, ids
    # The `### Source: DS-9 ...` heading is NOT a finding heading (id not adjacent
    # to the heading marker) and must NOT be parsed as a candidate.
    assert "DS-9" not in ids, ids


def test_token_flow_file_now_in_promotion_globs():
    import fnmatch
    assert any(fnmatch.fnmatch("depth_token_flow_findings.md", pat) for pat in P._DEPTH_PROMOTION_FILES)


# ---------------------------------------------------------------------------
# End-to-end: bridge promotes a DS- depth-only finding; gate accounts for it
# ---------------------------------------------------------------------------

_INV = (
    "# Findings Inventory\n\n"
    "### Finding [INV-001]: Existing unrelated finding\n"
    "**Severity**: Medium\n**Location**: CrossChainRouter.sol:L100\n"
    "**Description**: unrelated.\n"
)

_DEPTH_DS1 = (
    "## DEPTH ANALYSIS: State Trace\n\n"
    "### Finding [DS-1]: withdrawToNativeChain ETH-path drains any held WrappedToken via empty swapData\n"
    "**Severity**: High\n"
    "**Location**: NativeVault.sol:L530-600\n"
    "**Verdict**: CONFIRMED\n"
    "**Preferred Tag**: [CODE-TRACE]\n"
    "**Description**: empty swapData returns amount unswapped; withdraw pays out "
    "an attacker-chosen output token from accumulated balances. Distinct from public withdraw.\n"
)


def test_bridge_promotes_ds_finding_and_gate_accounts():
    sp = _mkscratch({
        "findings_inventory.md": _INV,
        "depth_state_trace_findings.md": _DEPTH_DS1,
    })
    promoted = V._promote_depth_findings_to_inventory(sp)
    assert "DS-1" in promoted, promoted
    inv_text = (sp / "findings_inventory.md").read_text(encoding="utf-8")
    assert re.search(r"\bDS-1\b", inv_text), "DS-1 not written into inventory"
    # Gate is now satisfied (DS-1 accounted in inventory).
    assert V._validate_depth_promotion_receipt(sp) == []


def test_gate_now_has_teeth_when_confirmed_finding_unpromoted():
    """Pre-fix the gate passed VACUOUSLY (couldn't parse DS-). Now a CONFIRMED
    DS- finding absent from inventory with no promotion MUST be flagged."""
    sp = _mkscratch({
        "findings_inventory.md": _INV,          # does NOT contain DS-1
        "depth_state_trace_findings.md": _DEPTH_DS1,
        # no depth_promotion_receipt.md → not blocked-as-dup
    })
    issues = V._validate_depth_promotion_receipt(sp)
    assert any("DS-1" in i for i in issues), issues
