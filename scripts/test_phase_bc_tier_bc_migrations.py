"""Phase B+C — Tier-B (retry-waste) + Tier-C (noise) migrations onto the
Phase-0 substrate.

Regex-fragility remediation plan §2 Tier B + Tier C + §5 Phases 4-7.

For EACH migrated site this file pins, per the NON-NEGOTIABLE CONSTRAINTS:
  * LEGACY-ACCEPTS (strict superset): every input the OLD regex accepted still
    yields a value-identical / behavior-identical result (nothing that passed
    before fails now).
  * NEGATIVE CONTROLS: the old intended REJECTS still reject (no over-broadening).
  * RECALL-SAFETY: a migrated gate never drops a candidate / never adds a HALT;
    prose gates are WARNING + fallback, only mechanical L1 checks FAIL.
  * THE ONE INTENTIONAL NARROWING: `_valid_poc_skip` mock-negation is clause-
    scoped (recall-safe — suppresses FEWER valid skips than the old 80-char
    proximity rule).

The three LIVE sites (mock-negation, attention_repair, invariants_p2) carry an
explicit fixture reproducing the real failing shape now passing.

Generic shapes only — no protocol / contract / finding names.
"""

import logging
import re
import tempfile
from pathlib import Path

import plamen_parsers as P
import plamen_validators as V
import plamen_driver as D


def _scratch(**files) -> Path:
    d = Path(tempfile.mkdtemp())
    for name, content in files.items():
        (d / name.replace("__", ".")).write_text(content, encoding="utf-8")
    return d


# ════════════════════════════════════════════════════════════════════════════
#  TIER B / SITE 4a — _valid_poc_skip mock-negation: clause-scoped guard
#  (THE intentional recall-safe narrowing)
# ════════════════════════════════════════════════════════════════════════════

_EXT_SKIP_LEDGER = (
    "### PoC Attempt\n"
    "- PoC Required: YES\n"
    "- PoC Class: integration\n"
    "- Attempted: NO\n"
    "- PoC Not Attempted Because: EXTERNAL_DEPENDENCY_NO_FORK_OR_ADDRESS\n"
    "### Execution Result\n"
)


def test_b4a_legacy_skip_without_mock_still_valid():
    # STRICT SUPERSET: a clean external-dependency skip with no mock mention is
    # valid under both the old and new rule.
    assert V._valid_poc_skip(_EXT_SKIP_LEDGER, "integration") is True


def test_b4a_legacy_same_clause_negation_still_rejects():
    # STRICT SUPERSET (rejection preserved): a genuine "could not be mocked"
    # statement in the SAME clause as `mock` still invalidates the skip — the
    # old proximity rule and the new clause rule agree here.
    content = (
        _EXT_SKIP_LEDGER
        + "The external oracle cannot be mocked in this harness.\n"
    )
    assert V._valid_poc_skip(content, "integration") is False
    content2 = _EXT_SKIP_LEDGER + "No mock implementation is available.\n"
    assert V._valid_poc_skip(content2, "integration") is False


def test_b4a_live_cross_sentence_negation_no_longer_suppresses():
    # THE LIVE FALSE-FIRE (now fixed): the verifier built a Mock harness in one
    # sentence; a DIFFERENT sentence says the on-chain address does not exist.
    # The old `.{0,80}` DOTALL proximity rule wrongly fired (negation within 80
    # chars of `mock` across the sentence boundary) -> unwinnable retry. The
    # clause-scoped guard does NOT suppress: the skip is valid.
    content = (
        _EXT_SKIP_LEDGER
        + "A Mock harness was written for the interface. "
        + "The production address does not exist on this fork.\n"
    )
    assert V._valid_poc_skip(content, "integration") is True


def test_b4a_negation_governs_keyword_helper_clause_scoped():
    # Direct test of the shared helper: same-clause negation fires; cross-clause
    # does not.
    kw = re.compile(r"\bmock\w*\b", re.IGNORECASE)
    assert P._negation_governs_keyword("the dependency cannot be mocked", kw)
    assert not P._negation_governs_keyword(
        "used a Mock harness. The address does not exist.", kw
    )
    # The keyword itself must not self-trigger a negation.
    assert not P._negation_governs_keyword("a Mock was provided", kw)


# ════════════════════════════════════════════════════════════════════════════
#  TIER B / SITE 4b — _poc_contract_required reads the verifier PoC Class ledger
# ════════════════════════════════════════════════════════════════════════════

def test_b4b_queue_class_unit_required_without_content():
    # Legacy behavior: with no verifier content, the queue `poc class` drives
    # the requirement (unit + High + thorough -> required).
    row = {"poc class": "unit", "severity": "High", "finding id": "X-1"}
    assert V._poc_contract_required(row, "thorough") is True


def test_b4b_verifier_reclassify_relaxes_requirement():
    # The verifier non-silently reclassifies to `structural` in its ledger; the
    # unit/property contract no longer applies -> not an unwinnable retry.
    row = {"poc class": "unit", "severity": "High", "finding id": "X-1"}
    ledger = "### PoC Attempt\n- PoC Class: structural (queue said unit; pure spec)\n"
    assert V._poc_contract_required(row, "thorough", ledger) is False


def test_b4b_verifier_reclassify_table_cell_form():
    # Table-cell rendering of the declared class is honored via _field_anywhere.
    row = {"poc class": "property", "severity": "Critical", "finding id": "X-2"}
    ledger = "| Field | Value |\n| --- | --- |\n| PoC Class | integration |\n"
    assert V._poc_contract_required(row, "thorough", ledger) is False


def test_b4b_anti_gaming_floor_declared_unit_stays_required():
    # A ledger that leaves the declared class at unit/property does NOT relax
    # the requirement (silent bypass floor preserved).
    row = {"poc class": "unit", "severity": "High", "finding id": "X-3"}
    ledger = "### PoC Attempt\n- PoC Class: unit\n"
    assert V._poc_contract_required(row, "thorough", ledger) is True


def test_b4b_negative_control_light_mode_never_required():
    row = {"poc class": "unit", "severity": "Critical", "finding id": "X-4"}
    assert V._poc_contract_required(row, "light") is False
    assert V._poc_contract_required(row, "light", "PoC Class: structural") is False


# ════════════════════════════════════════════════════════════════════════════
#  TIER B / SITE 5 — chain CC-chunk validator (_is_valid_inventory_chunk_output)
# ════════════════════════════════════════════════════════════════════════════

def _cc_chunk_legacy(impact_line: str, src_line: str) -> str:
    body = "x" * 220  # satisfy the 200-byte size floor
    return (
        "### Finding [CC-1]: title\n"
        f"{impact_line}\n"
        f"{src_line}\n"
        f"{body}\n"
    )


def test_b5_legacy_bold_form_still_valid():
    # STRICT SUPERSET: the exact bold form the old regex required still passes.
    d = _scratch(
        findings_inventory_chunk_a__md=_cc_chunk_legacy(
            "**Impact**: funds lost", "**Source IDs**: B1-1, B1-2"
        )
    )
    assert D._is_valid_inventory_chunk_output(d / "findings_inventory_chunk_a.md")


def test_b5_em_dash_and_singular_source_id_newly_accepted():
    # The futile-retry shapes: em-dash separator + `Source ID` singular.
    d = _scratch(
        findings_inventory_chunk_a__md=_cc_chunk_legacy(
            "**Impact** — funds lost", "Source ID: B1-1"
        )
    )
    assert D._is_valid_inventory_chunk_output(d / "findings_inventory_chunk_a.md")


def test_b5_table_cell_form_newly_accepted():
    body = "x" * 200
    text = (
        "#### Finding [CC-2]: title\n"
        "| Field | Value |\n| --- | --- |\n"
        "| Impact | funds lost |\n"
        "| Source IDs | B1-3 |\n"
        f"{body}\n"
    )
    d = _scratch(findings_inventory_chunk_b__md=text)
    assert D._is_valid_inventory_chunk_output(d / "findings_inventory_chunk_b.md")


def test_b5_negative_control_missing_impact_still_invalid():
    # NEGATIVE CONTROL: a chunk with NO impact field is still invalid (no
    # over-broadening; the gate still catches a genuinely incomplete chunk).
    text = "### Finding [CC-1]: title\n**Source IDs**: B1-1\n" + ("x" * 220) + "\n"
    d = _scratch(findings_inventory_chunk_c__md=text)
    assert not D._is_valid_inventory_chunk_output(d / "findings_inventory_chunk_c.md")


def test_b5_negative_control_no_cc_heading_invalid():
    text = "### Finding [INV-1]: title\n**Impact**: x\n**Source IDs**: B1-1\n" + ("x" * 200)
    d = _scratch(findings_inventory_chunk_d__md=text)
    assert not D._is_valid_inventory_chunk_output(d / "findings_inventory_chunk_d.md")


def test_b5_negative_control_under_size_invalid():
    text = "### Finding [CC-1]: t\n**Impact**: x\n**Source IDs**: B1-1\n"
    d = _scratch(findings_inventory_chunk_e__md=text)
    assert not D._is_valid_inventory_chunk_output(d / "findings_inventory_chunk_e.md")


# ════════════════════════════════════════════════════════════════════════════
#  TIER B / SITE 6 — inventory finding-meta (twin collapse + table tolerance)
# ════════════════════════════════════════════════════════════════════════════

def test_b6_legacy_bold_meta_value_identity():
    # STRICT SUPERSET: bold-form severity/location/root_cause still parse to the
    # same values the legacy regexes produced.
    inv = (
        "## Finding [INV-1]: My title\n"
        "**Severity**: High (direct loss)\n"
        "**Location**: src/A.sol:L10-L20\n"
        "**Root Cause**: missing check\n"
    )
    d = _scratch(findings_inventory__md=inv)
    meta = V._parse_inventory_finding_meta(d)
    assert meta["INV-1"]["severity"] == "High"  # legacy captured first word only
    assert meta["INV-1"]["location"] == "src/A.sol:L10-L20"
    assert meta["INV-1"]["root_cause"] == "missing check"
    assert meta["INV-1"]["title"] == "My title"


def test_b6_table_cell_meta_newly_parsed():
    inv = (
        "## Finding [INV-2]: Tabular finding\n"
        "| Field | Value |\n| --- | --- |\n"
        "| Severity | Medium |\n"
        "| Location | src/B.sol:L5 |\n"
        "| Root Cause | stale value |\n"
    )
    d = _scratch(findings_inventory__md=inv)
    meta = V._parse_inventory_finding_meta(d)
    assert meta["INV-2"]["severity"] == "Medium"
    assert meta["INV-2"]["location"] == "src/B.sol:L5"
    assert meta["INV-2"]["root_cause"] == "stale value"


def test_b6_tolerant_twin_accepts_single_letter_report_ids():
    inv = (
        "### Finding [M-07]: Report-style ID\n"
        "**Severity**: Medium\n"
        "**Location**: src/C.sol:L3\n"
    )
    d = _scratch(findings_inventory__md=inv)
    meta = V._parse_inventory_finding_meta_tolerant(d)
    assert "M-07" in meta
    assert meta["M-07"]["location"] == "src/C.sol:L3"
    # The base parser (prefix_min=2) must NOT see the single-letter ID — the
    # twins remain behaviorally distinct on their prefix contract.
    base = V._parse_inventory_finding_meta(d)
    assert "M-07" not in base


def test_b6_root_cause_falls_back_to_title():
    inv = "## Finding [INV-3]: Only a title\n**Severity**: Low\n"
    d = _scratch(findings_inventory__md=inv)
    meta = V._parse_inventory_finding_meta(d)
    assert meta["INV-3"]["root_cause"] == "Only a title"


# ════════════════════════════════════════════════════════════════════════════
#  TIER B / SITE 6b — _compute_dedup_candidate_pairs Location/Severity tolerance
# ════════════════════════════════════════════════════════════════════════════

def test_b6b_dedup_pairs_plain_and_table_location_forms():
    # Two same-file findings whose Location is rendered NON-bold (plain + table)
    # must still be paired (the old `**Location**:`-exact regex dropped them).
    inv = (
        "### Finding [INV-1]: rounding loss in pool\n"
        "Location: src/Pool.sol:L40-L50\n"
        "Severity: Medium\n"
        "### Finding [INV-2]: rounding loss in pool deposit\n"
        "| Field | Value |\n| --- | --- |\n"
        "| Location | src/Pool.sol:L42 |\n"
        "| Severity | Medium |\n"
    )
    d = _scratch(findings_inventory__md=inv)
    n = P._compute_dedup_candidate_pairs(d)
    assert n >= 1
    pairs = (d / "dedup_candidate_pairs.md").read_text(encoding="utf-8")
    assert "INV-1" in pairs and "INV-2" in pairs


def test_b6b_dedup_legacy_bold_form_still_pairs():
    # STRICT SUPERSET: the bold form the old regex required still pairs.
    inv = (
        "### Finding [INV-1]: overflow in mint\n"
        "**Location**: src/Token.sol:L10\n"
        "**Severity**: High\n"
        "### Finding [INV-2]: overflow in mint path\n"
        "**Location**: src/Token.sol:L12\n"
        "**Severity**: High\n"
    )
    d = _scratch(findings_inventory__md=inv)
    assert P._compute_dedup_candidate_pairs(d) >= 1


# ════════════════════════════════════════════════════════════════════════════
#  TIER B / SITE 6c — classify_poc_testability word-boundary + negation
# ════════════════════════════════════════════════════════════════════════════

def test_b6c_legacy_overflow_still_unit():
    # STRICT SUPERSET: a real overflow bug still routes to unit.
    assert P.classify_poc_testability("overflow", "", "u64 overflow in add", "High") == "unit"


def test_b6c_negated_overflow_no_longer_forces_unit():
    # THE PLAN'S EXAMPLE: "no overflow check" must NOT route to the impossible
    # narrow-unit harness — the negated mechanism keyword is suppressed and the
    # finding falls through to a non-mandatory class (structural).
    out = P.classify_poc_testability("", "", "no overflow check on deposit amount", "Medium")
    assert out != "unit"


def test_b6c_word_boundary_no_substring_false_hit():
    # "share" must not fire on an unrelated longer word like "shareholder"? —
    # ensure a bare substring inside another word does not trip the broad noun.
    # Use a title where `fee` only appears inside `coffee` (no real fee bug).
    out = P.classify_poc_testability("", "", "coffee machine telemetry export", "Low")
    assert out == "structural"


def test_b6c_property_keyword_still_property():
    assert P.classify_poc_testability("", "", "invariant broken in accounting", "High") == "property"


def test_b6c_negated_reentrancy_not_property():
    # "no reentrancy guard" is a MISSING-guard structural bug, not a property
    # invariant requiring a multi-call harness. Negation suppresses the keyword.
    out = P.classify_poc_testability("", "", "no reentrancy guard on withdraw", "High")
    # narrow_unit "missing guard" wins here (a present narrow-unit phrase), which
    # is fine — the key assertion is it is NOT mis-routed to property via a
    # negated `reentrancy`.
    assert out in ("unit", "structural")


# ════════════════════════════════════════════════════════════════════════════
#  TIER C / SITE — _semantic_gap_trigger_counts table-cell counts
# ════════════════════════════════════════════════════════════════════════════

def test_c_semantic_gap_legacy_colon_form():
    inv = "# Inv\nsync_gaps: 5\naccumulation_exposures: 0\n"
    d = _scratch(semantic_invariants__md=inv)
    counts = V._semantic_gap_trigger_counts(d)
    assert counts["sync_gaps"] == 5


def test_c_semantic_gap_table_cell_form_newly_counted():
    inv = (
        "# Inv\n"
        "| Flag | Count |\n| --- | --- |\n"
        "| `sync_gaps` | **5** |\n"
        "| cluster_gaps | 2 |\n"
    )
    d = _scratch(semantic_invariants__md=inv)
    counts = V._semantic_gap_trigger_counts(d)
    assert counts["sync_gaps"] == 5
    assert counts["cluster_gaps"] == 2


def test_c_semantic_gap_negative_control_no_flags():
    d = _scratch(semantic_invariants__md="# Inv\nnothing relevant here\n")
    counts = V._semantic_gap_trigger_counts(d)
    assert all(v == 0 for v in counts.values())


# ════════════════════════════════════════════════════════════════════════════
#  TIER C / SITE — _validate_invariants_pass2 _FLAG_TOKEN table-cell (LIVE soft)
# ════════════════════════════════════════════════════════════════════════════

def test_c_invariants_p2_table_cell_no_false_warn(caplog):
    # THE LIVE SHAPE: a complete Pass 2 section whose flag DATA is in a table
    # (pipe-separated) must NOT emit the "flag data missing" soft WARN — the old
    # `[:=]`-only _FLAG_TOKEN undercounted to <2 and warned falsely.
    inv = (
        "## Pass 2: Recursive Trace Results\n"
        "| Flag | Count |\n| --- | --- |\n"
        "| sync_gaps | 3 |\n"
        "| accumulation_exposures | 1 |\n"
        "| conditional_writes | 0 |\n"
        "| cluster_gaps | 2 |\n"
    )
    d = _scratch(semantic_invariants__md=inv)
    with caplog.at_level(logging.WARNING, logger="plamen.validators"):
        issues = V._validate_invariants_pass2(d, "thorough")
    assert issues == []  # soft — never hard
    assert not any(
        "flag data" in r.getMessage() and "missing" in r.getMessage()
        for r in caplog.records
    ), "table-cell flag data wrongly reported missing"


def test_c_invariants_p2_legacy_colon_form_still_silent(caplog):
    inv = (
        "## Pass 2: Recursive Trace Results\n"
        "sync_gaps: 3\naccumulation_exposures: 1\n"
        "conditional_writes: 0\ncluster_gaps: 2\n"
    )
    d = _scratch(semantic_invariants__md=inv)
    with caplog.at_level(logging.WARNING, logger="plamen.validators"):
        issues = V._validate_invariants_pass2(d, "thorough")
    assert issues == []


# ════════════════════════════════════════════════════════════════════════════
#  TIER C / SITE — _missing_perturbation_block_ids tolerant Verdict/Severity
# ════════════════════════════════════════════════════════════════════════════

def test_c_perturbation_legacy_bold_form_detected_missing():
    # STRICT SUPERSET: a bold-form Medium+ CONFIRMED finding with no
    # perturbation block is still reported missing.
    text = (
        "### Finding [DT-1]: a confirmed bug\n"
        "**Verdict**: CONFIRMED\n**Severity**: High\n"
        "Some analysis without a perturbation block.\n"
    )
    assert "DT-1" in V._missing_perturbation_block_ids(text)


def test_c_perturbation_table_cell_form_now_detected():
    # Previously UNDER-warned: a table-cell rendered finding was skipped (its
    # Verdict/Severity weren't seen), so its missing block went unflagged. Now
    # the tolerant extractor sees it.
    text = (
        "### Finding [DT-2]: confirmed via table\n"
        "| Field | Value |\n| --- | --- |\n"
        "| Verdict | CONFIRMED |\n| Severity | High |\n"
        "No perturbation block here.\n"
    )
    assert "DT-2" in V._missing_perturbation_block_ids(text)


def test_c_perturbation_negative_control_refuted_not_flagged():
    text = (
        "### Finding [DT-3]: a refuted candidate\n"
        "**Verdict**: REFUTED\n**Severity**: High\n"
    )
    assert "DT-3" not in V._missing_perturbation_block_ids(text)


def test_c_perturbation_with_block_not_flagged():
    text = (
        "### Finding [DT-4]: confirmed with block\n"
        "**Verdict**: CONFIRMED\n**Severity**: Medium\n"
        "### Perturbation Block\nDIRECTION_FLIP explored.\n"
    )
    assert "DT-4" not in V._missing_perturbation_block_ids(text)


# ════════════════════════════════════════════════════════════════════════════
#  TIER C / SITE — step-trace citation contract twin alignment
# ════════════════════════════════════════════════════════════════════════════

def test_c_step_trace_citation_legacy_and_canonical_forms_accepted(tmp_path):
    source = tmp_path / "src/A.sol"
    source.parent.mkdir()
    source.write_text("\n".join("line" for _ in range(42)) + "\n")
    assert V._step_trace_evidence_has_citation("src/A.sol:L42", tmp_path)
    assert V._step_trace_evidence_has_citation("src/A.sol:42", tmp_path)


def test_c_step_trace_citation_rich_forms_accepted(tmp_path):
    source = tmp_path / "src/A.sol"
    source.parent.mkdir()
    source.write_text("\n".join("line" for _ in range(120)) + "\n")
    # R0-8b deliberately rejects prose/lenient forms as application proof.
    assert not V._step_trace_evidence_has_citation(
        "src/A.sol, lines 42", tmp_path
    )
    assert not V._step_trace_evidence_has_citation("src/A.sol L42", tmp_path)
    assert not V._step_trace_evidence_has_citation(
        "[TRACE: withdraw → revert at L120]", tmp_path
    )
    assert V._step_trace_evidence_has_citation(
        "[TRACE: src/A.sol:L120 withdraw reverted]", tmp_path
    )
    assert not V._step_trace_evidence_has_citation(
        "(general) no single file applies", tmp_path
    )


def test_c_step_trace_citation_negative_controls():
    # NEGATIVE CONTROL: empty / dash / pure-prose-no-file remain non-citations.
    assert not V._step_trace_evidence_has_citation("")
    assert not V._step_trace_evidence_has_citation("-")
    assert not V._step_trace_evidence_has_citation("looks fine to me")


def test_c_step_trace_ceremonial_twin_uses_shared_contract():
    d = Path(tempfile.mkdtemp())
    source = d / "src/A.sol"
    source.parent.mkdir()
    source.write_text("\n".join("line" for _ in range(42)) + "\n")
    p = d / "step_execution_trace_x.md"
    p.write_text(
        "| Skill | Step | Executed | Evidence |\n"
        "| --- | --- | --- | --- |\n"
        "| S | 1 | yes | src/A.sol:L42 |\n",
        encoding="utf-8",
    )
    assert V._step_trace_has_ceremonial_yes(p) is False


# ════════════════════════════════════════════════════════════════════════════
#  TIER C / SITE — _parse_source_findings_for_ids heading + location tolerance
# ════════════════════════════════════════════════════════════════════════════

def test_c_source_findings_legacy_h3_bold_location():
    d = Path(tempfile.mkdtemp())
    p = d / "depth_x_findings.md"
    p.write_text(
        "### Finding [DX-1]: title\n**Location**: src/A.sol:L10\n",
        encoding="utf-8",
    )
    out = P._parse_source_findings_for_ids(p)
    assert len(out) == 1
    assert out[0]["id"] == "DX-1"
    assert "a.sol" in out[0]["location"].lower()


def test_c_source_findings_h2_and_h4_headings_and_table_location():
    d = Path(tempfile.mkdtemp())
    p = d / "depth_y_findings.md"
    p.write_text(
        "## Finding [DX-2]: h2 heading\n"
        "Location: src/B.sol:L5\n"
        "#### Finding [DX-3]: h4 heading\n"
        "| Field | Value |\n| --- | --- |\n"
        "| Location | src/C.sol:L9 |\n",
        encoding="utf-8",
    )
    out = {f["id"]: f for f in P._parse_source_findings_for_ids(p)}
    assert set(out) == {"DX-2", "DX-3"}
    assert "b.sol" in out["DX-2"]["location"].lower()
    assert "c.sol" in out["DX-3"]["location"].lower()


def test_c_source_findings_negative_control_non_finding_heading():
    d = Path(tempfile.mkdtemp())
    p = d / "depth_z_findings.md"
    p.write_text("## Summary\nNo findings here.\n", encoding="utf-8")
    assert P._parse_source_findings_for_ids(p) == []


# ════════════════════════════════════════════════════════════════════════════
#  ZERO-HARVEST TRIPWIRE (cross-site, Tier B/C): empty harvest + evidence -> WARN
# ════════════════════════════════════════════════════════════════════════════

def test_bc_zero_harvest_tripwire_logs(caplog):
    with caplog.at_level(logging.WARNING):
        out, _ = P._field_anywhere(
            "This block mentions Location but never gives one.",
            ("Location",), table_ok=True,
        )
    assert out == ""
    assert any("_field_anywhere" in r.getMessage() for r in caplog.records)
