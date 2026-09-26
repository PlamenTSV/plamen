"""Portable conformance cases for the shared artifact boundary and consumers.

Synthetic documents only: no local audit directories, provider calls, network,
or target code. Presentation mutations must preserve observed values; semantic
controls must change them. Every serialized document must reach a fixed point.
"""

from itertools import permutations

import pytest

import artifact_surface as A
import plamen_driver as D
import plamen_parsers as P


def _fixed_point(text):
    once = A.normalized_text(text)
    assert A.normalized_text(once) == once
    return once


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
@pytest.mark.parametrize("prefix", ["", "- ", "> ", "1. "])
@pytest.mark.parametrize("label", ["Severity", "**Severity**", "`Severity`", "_Severity_"])
@pytest.mark.parametrize("separator", [": ", ":", " = ", " — "])
def test_composed_field_presentations(newline, prefix, label, separator):
    text = f"{prefix}{label}{separator}High{newline}{prefix}Verdict:OPEN{newline}"
    for document in (text, _fixed_point(text)):
        assert A.read_field(document, "severity").value == "High"
        assert A.read_field(document, "verdict").value == "OPEN"
        assert A.read_field(document.replace("High", "Low"), "severity").value == "Low"


@pytest.mark.parametrize("order", list(permutations(range(3))))
@pytest.mark.parametrize("decorated", [False, True])
@pytest.mark.parametrize("outer_pipes", [False, True])
def test_table_column_order_and_decoration(order, decorated, outer_pipes):
    headers = ["Finding ID", "Verdict", "Notes"]
    values = ["A-1", "OPEN", "retained"]
    def row(cells):
        text = " | ".join(cells[i] for i in order)
        return "| " + text + " |" if outer_pipes else text
    if decorated:
        headers = [f"**{cell}**" for cell in headers]
        values = [f"`{cell}`" for cell in values]
    text = "\n".join([row(headers), row(["---"] * 3), row(values)])
    for document in (text, _fixed_point(text)):
        table = A.find_table(document, required_roles=("candidate_id", "disposition"))
        assert table is not None
        assert table.rows[0].identity().key == "A-1"
        assert table.rows[0].get("disposition") == "OPEN"


@pytest.mark.parametrize("text", [
    "Title\n---", "Title\n===", "> alpha\nbeta", "> alpha\n> beta\nplain",
    "~~~text\n```\nFLAG: COMPLETE\n~~~",
    "````text\n```\nFLAG: COMPLETE\n````",
    "- alpha\n- beta", "Severity:High\nVerdict:OPEN",
])
def test_serialization_fixed_point(text):
    _fixed_point(text)


@pytest.mark.parametrize("opening,closing", [("~~~text", "~~~"), ("````text", "````")])
def test_delimiter_looking_content_stays_quoted(opening, closing):
    text = f"{opening}\n```\nFLAG: COMPLETE\n{closing}"
    for document in (text, _fixed_point(text)):
        surf = A.surface(document)
        assert not surf.defects
        assert not A.find_assertions(surf, "FLAG")
        assert len(A.find_mentions(surf, "FLAG")) == 1


@pytest.mark.parametrize("text", [
    "Finding A-1: related to [B-2]",
    "Finding `A-1`: related to [B-2]",
    "Finding [A-1]: related to [B-2]",
    "[A-1]: related to Finding B-2",
])
def test_subject_identity_is_not_a_later_reference(text):
    assert A.candidate_identity(text).key == "A-1"
    assert A.candidate_identity(text.replace("A-1", "C-3")).key == "C-3"


def test_released_memoryview_is_visible_decoding_debt():
    view = memoryview(b"document")
    view.release()
    surf = A.surface(view)
    assert surf.defects
    assert all(d.closure == A.DEBT for d in surf.defects)


def test_line_truncation_is_visible(monkeypatch):
    monkeypatch.setattr(A, "MAX_LINE_CHARS", 24)
    surf = A.surface("x" * 25)
    assert surf.truncated
    assert any(d.physical_line == 1 and d.repair_hint for d in surf.defects)


def test_horizontal_table_header_is_not_a_scalar_field():
    text = "| Severity | Notes |\n|---|---|\n| High | detail |"
    assert A.read_field(text, "severity") is None


@pytest.mark.parametrize("header", ["", "| Field | Value |\n|---|---|\n"])
def test_vertical_field_tables_retain_the_first_field(header):
    text = header + "| Severity | High |\n| Verdict | OPEN |"
    assert A.read_field(text, "severity").value == "High"
    assert A.read_field(text, "verdict").value == "OPEN"


def test_custom_column_roles_are_normalized():
    table = A.read_tables(
        "| finding id | note |\n|---|---|\n| A-1 | retained |",
        roles={"subject": ("**Finding ID**",)},
    )[0]
    assert table.rows[0].get("subject") == "A-1"


@pytest.mark.parametrize("token", ["FLAGSHIP", "FLAG_SUFFIX", "FLAG-SUFFIX"])
def test_tokens_require_identifier_boundaries(token):
    assert not A.find_assertions(f"{token}: COMPLETE", "FLAG")
    assert A.find_assertions("FLAG: COMPLETE", "FLAG")


_COMPLETE = "<!-- PLAMEN_STATUS: COMPLETE -->"
_PENDING = "<!-- PLAMEN_STATUS: IN_PROGRESS -->"
_LIFECYCLE_CASES = [
    ("comment", _COMPLETE, True),
    ("compact", "<!--PLAMEN_STATUS:COMPLETE-->", True),
    ("lowercase", "<!-- plamen_status: complete -->", True),
    ("bold", "**PLAMEN_STATUS: COMPLETE**", True),
    ("inline-code", "`PLAMEN_STATUS: COMPLETE`", True),
    ("list", "- " + _COMPLETE, True),
    ("quote", "> " + _COMPLETE, True),
    ("period", "PLAMEN_STATUS: COMPLETE.", True),
    ("synonym", "PLAMEN_STATUS: DONE", True),
    ("unfinished", _PENDING, False),
    ("failed", "PLAMEN_STATUS: FAILED", False),
    ("negated", "PLAMEN_STATUS: NOT_COMPLETE", False),
    ("final-status-pending", _COMPLETE + "\n" + _PENDING, False),
    ("final-status-complete", _PENDING + "\n" + _COMPLETE, True),
    ("same-line-pending", _COMPLETE + _PENDING, False),
    ("same-line-complete", _PENDING + _COMPLETE, True),
    ("same-line-mention", "Example: I will write " + _COMPLETE + _PENDING, False),
    ("recovered-comment", "<!-- PLAMEN_STATUS: IN_PROGRESS\nbody\n" + _COMPLETE, True),
    ("quoted-example", "```\n" + _COMPLETE + "\n```", False),
    ("quoted-example-tilde", "~~~text\n```\n" + _COMPLETE + "\n~~~", False),
    ("example-and-pending", "```\n" + _COMPLETE + "\n```\n" + _PENDING, False),
    ("narrative", "I will end with " + _COMPLETE + " when done.", False),
    ("empty", "", False),
]


@pytest.mark.parametrize("name,marker,expected", _LIFECYCLE_CASES, ids=[c[0] for c in _LIFECYCLE_CASES])
def test_completion_consumers_agree(tmp_path, name, marker, expected):
    text = (
        "<!-- PLAMEN_ARTIFACT: document.md -->\n"
        "<!-- PLAMEN_PHASE: recon -->\n\n"
        "# Document\n\n" + "Substantive local document content. " * 20
        + "\n\n" + marker + "\n"
    )
    path = tmp_path / "document.md"
    path.write_text(text, encoding="utf-8")
    assert P.is_artifact_complete(path, 1) is expected
    assert D._worker_has_complete_signal(text) is expected
    assert D._depth_worker_has_complete_signal(text) is expected
    assert D._recon_worker_complete(tmp_path, path.name)[0] is expected


def test_current_status_overrides_legacy_sentinel():
    text = "<!-- PLAMEN:PHASE4B:worker:COMPLETE -->\n" + _PENDING
    assert not D._worker_has_complete_signal(text)


@pytest.mark.parametrize("status", ["", "IN_PROGRESS", "FAILED"])
def test_explicit_current_status_prevents_legacy_fallback(status):
    text = f"<!-- PLAMEN:PHASE4B:worker:COMPLETE -->\nPLAMEN_STATUS:{status}"
    assert not D._worker_has_complete_signal(text)


@pytest.mark.parametrize("marker", [
    "XPLAMEN:PHASE4B:worker:COMPLETE",
    "PLAMEN:PHASE4B:worker:COMPLETE_GARBAGE",
    "PLAMEN:PHASE4B:worker:COMPLETE-NOT",
])
def test_legacy_marker_requires_exact_identifier_and_status(marker):
    assert not D._worker_has_complete_signal(f"<!-- {marker} -->")


def test_valid_legacy_suffix_remains_supported():
    assert D._worker_has_complete_signal("<!-- PLAMEN:PHASE4B:worker:COMPLETE:12 -->")


def test_dispatch_marker_normalization_keeps_value_and_last_assignment():
    text = "<!-- PLAMEN_ARTIFACT: `document.md` -->"
    assert D._worker_marker_values(text, "PLAMEN_ARTIFACT") == ["document.md"]
    assert D._worker_marker_values(
        "<!-- EXPECTED_OUTPUT: old.md -->\n<!-- EXPECTED_OUTPUT: document.md -->",
        "EXPECTED_OUTPUT",
    ) == ["document.md"]


def test_comment_recovery_records_debt_and_keeps_multiline_payloads():
    broken = "<!-- PLAMEN_STATUS: IN_PROGRESS\nbody\n" + _COMPLETE
    surf = A.surface(broken)
    assert any(d.property_violated == "format.unterminated_html_comment" for d in surf.defects)
    valid = '<!-- DOCUMENT_DATA:\n{"state":"OPEN"}\n-->'
    assert not A.surface(valid).defects
    assert len(A.find_assertions(valid, "DOCUMENT_DATA")) == 1
    _fixed_point(valid)


def test_recon_dispatch_markers_are_checked_with_a_job(tmp_path):
    text = (
        "<!-- **PLAMEN_ARTIFACT**: `document.md` -->\n"
        "<!-- PLAMEN_PHASE: recon -->\n"
        "<!-- PLAMEN_OWNER: worker -->\n"
        "<!-- **RECON_ROLE**: `notes` -->\n"
        "<!-- **EXPECTED_OUTPUT**: `document.md` -->\n"
        "\n# Document\n\n" + "Substantive document text. " * 20 + "\n\n" + _COMPLETE
    )
    path = tmp_path / "document.md"
    path.write_text(text, encoding="utf-8")
    job = {"agent_id": "worker", "role": "notes"}
    assert D._recon_worker_complete(tmp_path, path.name, job=job)[0]
    path.write_text(text.replace("`document.md`", "`foreign.md`"), encoding="utf-8")
    assert not D._recon_worker_complete(tmp_path, path.name, job=job)[0]
