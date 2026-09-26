"""Metamorphic heading-index reader contract; no providers or audit targets.

Prepared with the draft migration; run only after the parent applies it and
regenerates runtime closure. These tests exercise the real runtime reader.
"""
import pytest

import artifact_surface as S
import report_heading_presentation as H


TITLE = "Paired accounting state can diverge"
EXPECTED = {"H-01": (TITLE, "CONTESTED")}


def _table(headers=("Report ID", "Title", "Verification"), rows=None, *, outer=True):
    if rows is None:
        rows = [("H-01", TITLE, "CONTESTED")]
    def line(cells):
        body = " | ".join(cells)
        return f"| {body} |" if outer else body
    return "\n".join([line(headers), line(["---"] * len(headers)), *(line(row) for row in rows)]) + "\n"


def _index(table=None, heading="## Master Finding Index"):
    return heading + "\n\n" + (_table() if table is None else table)


@pytest.mark.parametrize("heading", [
    "## Master Finding Index", "### Master Finding Index", "#### Master Finding Index",
    "Master Finding Index\n--------------------", "Master Finding Index\n====================",
    "### **Master Finding Index** ###",
])
@pytest.mark.parametrize("outer", [True, False])
def test_heading_level_and_optional_outer_pipes_are_representation_only(heading, outer):
    assert H._index_rows(_index(_table(outer=outer), heading)) == EXPECTED


def test_reordered_decorated_alias_columns_and_cells():
    table = _table(
        ("**Verdict**", "Finding&nbsp;Title", "`Report Identifier`", "Unconsumed"),
        [("[CONTESTED]", f"**{TITLE}**", "`[h-01]`", "arbitrary context")],
        outer=False,
    )
    assert H._index_rows(_index(table)) == EXPECTED


@pytest.mark.parametrize("title", [r"Left \| right state can diverge", "`Left | right` state can diverge"])
def test_escaped_and_inline_code_pipes_preserve_cell_boundaries(title):
    assert H._index_rows(_index(_table(rows=[("H-01", title, "CONTESTED")]))) == {
        "H-01": ("Left | right state can diverge", "CONTESTED")}


def test_equivalent_duplicate_roles_and_duplicate_rows_resolve():
    headers = ("Report ID", "ID", "Report Identifier", "Title", "Finding Title", "Verification", "Verdict")
    row = ("H-01", "1", "[h-01]", TITLE, f"**{TITLE}**", "CONTESTED", "[CONTESTED]")
    assert H._index_rows(_index(_table(headers, [row, row]))) == EXPECTED


@pytest.mark.parametrize("role,header,value", [
    ("report_id", "Report Identifier", "H-02"),
    ("report_id", "ID", "unreadable"),
    ("report_id", "Report Identifier", "1"),
    ("title", "Finding Title", "An entirely different substantive claim"),
    ("verification", "Verdict", "CONFIRMED"),
    ("verification", "Verdict", "NOT VERIFIED"),
    ("verification", "Verdict", "unknown"),
])
def test_unknown_or_conflicting_companion_claim_cannot_be_ignored(role, header, value):
    table = _table(("Report ID", "Title", "Verification", header), [("H-01", TITLE, "CONTESTED", value)])
    with pytest.raises(H.ReportHeadingError, match=rf"index\.{role}\.(conflict|unknown)"):
        H._index_rows(_index(table))


@pytest.mark.parametrize("later", [("H-01", TITLE, "CONFIRMED"), ("H-01", "Changed substantive title", "CONTESTED")])
def test_duplicate_rows_never_last_win(later):
    with pytest.raises(H.ReportHeadingError, match="duplicate_row.conflict"):
        H._index_rows(_index(_table(rows=[("H-01", TITLE, "CONTESTED"), later])))


@pytest.mark.parametrize("identity", ["H-01 / H-02", "Finding H-01", "1", "H-01suffix", "[H-01"])
def test_report_identity_uses_only_finite_exact_grammar(identity):
    with pytest.raises(H.ReportHeadingError, match="index.report_id"):
        H._index_rows(_index(_table(rows=[(identity, TITLE, "CONTESTED")])))


@pytest.mark.parametrize("identity", ["H-0001", "H-1000", "I-1234567890", "H-001"])
def test_decimal_report_identity_has_no_artificial_digit_limit_or_zero_collapse(identity):
    assert H._index_rows(_index(_table(rows=[(identity, TITLE, "CONTESTED")]))) == {
        identity: (TITLE, "CONTESTED")}


@pytest.mark.parametrize("status", [
    "CONFIRMED [POC-PASS]", "[POC-PASS]; CONFIRMED", "[CONFIRMED] [CODE-TRACE]",
    "[STATIC-TRACE]; **CONFIRMED**", "CONFIRMED / CONFIRMED", "[PROD-SOURCE]; CONFIRMED",
])
def test_canonical_evidence_annotations_do_not_compete_with_exact_status(status):
    assert H._index_rows(_index(_table(rows=[("H-01", TITLE, status)]))) == {"H-01": (TITLE, "CONFIRMED")}


@pytest.mark.parametrize("status", [
    "NOT VERIFIED", "CONFIRMED / CONTESTED", "UNVERIFIEDNESS", "[POC-PASS]",
    "CONFIRMED unknown", "CONFIRMED [UNKNOWN-TAG]", "[MECHANICAL-VERIFIED]",
    "CONFIRMED [", "CONFIRMED ]", "[CONFIRMED", "CONFIRMED]",
])
def test_unknown_or_contradictory_status_does_not_authorize_heading(status):
    with pytest.raises(H.ReportHeadingError, match="index.verification"):
        H._index_rows(_index(_table(rows=[("H-01", TITLE, status)])))


@pytest.mark.parametrize("status", ["UNVERIFIED", "VERIFIED", "CONFIRMED", "CONTESTED", "UNRESOLVED"])
def test_status_tokens_remain_distinct(status):
    assert H._index_rows(_index(_table(rows=[("H-01", TITLE, status)]))) == {"H-01": (TITLE, status)}


def test_evidence_tag_column_never_supplies_or_overrides_verdict():
    table = _table(("Report ID", "Title", "Verdict", "Evidence Tag"), [("H-01", TITLE, "CONTESTED", "[POC-PASS]")])
    assert H._index_rows(_index(table)) == EXPECTED
    table = _table(("Report ID", "Title", "Evidence Tag"), [("H-01", TITLE, "VERIFIED")])
    with pytest.raises(H.ReportHeadingError, match="index.verification.missing"):
        H._index_rows(_index(table))


def _quoted(text):
    return "\n".join("> " + line for line in text.splitlines()) + "\n"


@pytest.mark.parametrize("wrap", [_quoted, lambda text: "```markdown\n" + text + "```\n", lambda text: "<!--\n" + text + "-->\n"])
def test_example_section_cannot_authorize_rows(wrap):
    decoy = _index(_table(rows=[("H-99", "Decoy claim", "VERIFIED")]))
    assert H._index_rows(wrap(decoy) + "\n" + _index()) == EXPECTED
    assert H._index_rows(wrap(decoy)) == {}


@pytest.mark.parametrize("wrap", [_quoted, lambda text: "~~~markdown\n" + text + "~~~\n", lambda text: "<!--\n" + text + "-->\n"])
def test_example_heading_cannot_truncate_live_section(wrap):
    decoy = "## Another Section\n\n" + _table(rows=[("H-99", "Decoy claim", "VERIFIED")])
    text = "## Master Finding Index\n\n" + wrap(decoy) + "\n" + _table()
    assert H._index_rows(text) == EXPECTED


def test_quoted_row_cannot_compete_inside_live_table():
    table = _table() + "> | H-01 | Decoy claim | VERIFIED |\n"
    assert H._index_rows(_index(table)) == EXPECTED


@pytest.mark.parametrize("opener", ["```markdown\n", "~~~\n", "<!--\n"])
def test_unterminated_example_boundary_cannot_authorize_recovered_mentions(opener):
    with pytest.raises(H.ReportHeadingError, match="ambiguous_quotation"):
        H._index_rows(opener + _index())


def test_absent_or_empty_index_preserves_empty_map():
    assert H._index_rows("") == {}
    assert H._index_rows("## Master Finding Index\n\nNo active entries.\n") == {}
    assert H._index_rows(_index(_table(rows=[]))) == {}


def test_missing_separator_is_not_a_semantic_change():
    table = "| Report ID | Title | Verification |\n" + f"| H-01 | {TITLE} | CONTESTED |\n"
    assert H._index_rows(_index(table)) == EXPECTED


def test_live_subheading_keeps_scope_but_peer_heading_ends_it():
    decoy = _table(rows=[("H-99", "Outside scope", "VERIFIED")])
    text = "## Master Finding Index\n\n### Active Entries\n\n" + _table() + "\n## Appendix\n\n" + decoy
    assert H._index_rows(text) == EXPECTED


def test_equivalent_repeated_sections_resolve_and_conflicting_sections_reject():
    assert H._index_rows(_index() + "\n" + _index()) == EXPECTED
    with pytest.raises(H.ReportHeadingError, match="duplicate_row.conflict"):
        H._index_rows(_index() + "\n" + _index(_table(rows=[("H-01", TITLE, "VERIFIED")])))


def test_substantive_title_is_not_privacy_or_fuzzy_normalized_by_reader():
    altered = "Paired accounting state cannot diverge"
    actual = H._index_rows(_index(_table(rows=[("H-01", altered, "CONTESTED")])))
    assert actual["H-01"][0] == altered
    assert H.public_heading_title(actual["H-01"][0]) != H.public_heading_title(TITLE)


@pytest.mark.parametrize("limit_name,limit", [("MAX_PHYSICAL_LINES", 6), ("MAX_LINE_CHARS", 30)])
def test_partial_surface_never_returns_authoritative_prefix(monkeypatch, limit_name, limit):
    monkeypatch.setattr(S, limit_name, limit)
    with pytest.raises(H.ReportHeadingError, match="incomplete_surface"):
        H._index_rows(_index() + "\n" + "additional physical line\n" * 3)


def test_lossy_decode_never_returns_authoritative_prefix():
    with pytest.raises(H.ReportHeadingError, match="incomplete_surface"):
        H._index_rows(_index().encode() + b"\xff")
