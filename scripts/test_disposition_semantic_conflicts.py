"""Conservative report placement across competing semantic assertions."""

from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import plamen_parsers as P


def _parse(tmp_path: Path, headers: str, rows: list[str]):
    count = len(headers.strip("|").split("|"))
    text = headers + "\n|" + "---|" * count + "\n" + "\n".join(rows) + "\n"
    (tmp_path / "disposition.md").write_text(text, encoding="utf-8")
    return P.parse_disposition_md(tmp_path)


@pytest.mark.parametrize("ids", [("H-01", "M-02"), ("M-02", "H-01")])
def test_conflicting_identity_columns_keep_every_report_id_in_body(tmp_path, ids):
    parsed = _parse(tmp_path, "| Report ID | Finding ID | Disposition | Reason |", [
        f"| {ids[0]} | {ids[1]} | APPENDIX | source reason |",
    ])
    assert set(parsed) == {"H-01", "M-02"}
    for disposition, reason in parsed.values():
        assert disposition == "BODY"
        assert "identity.report_placement_subject.conflict" in reason
        assert "H-01" in reason and "M-02" in reason
        assert "source reason" in reason


@pytest.mark.parametrize("values", [
    ("APPENDIX", "BODY"), ("BODY", "APPENDIX"),
    ("APPENDIX", "MAYBE"), ("MAYBE", "APPENDIX"),
])
def test_competing_disposition_columns_cannot_route_to_appendix(tmp_path, values):
    parsed = _parse(tmp_path, "| Report ID | Disposition | Placement |", [
        f"| L-07 | {values[0]} | {values[1]} |",
    ])
    assert parsed["L-07"][0] == "BODY"
    assert "disposition.report_placement_proposal." in parsed["L-07"][1]


@pytest.mark.parametrize("rows", [
    ["| L-07 | BODY | first |", "| L-07 | APPENDIX | second |"],
    ["| L-07 | APPENDIX | second |", "| L-07 | BODY | first |"],
])
def test_duplicate_rows_do_not_last_win_to_appendix(tmp_path, rows):
    parsed = _parse(tmp_path, "| Report ID | Disposition | Reason |", rows)
    assert parsed["L-07"][0] == "BODY"
    assert "disposition.report_placement_proposal.conflict" in parsed["L-07"][1]
    assert "first" in parsed["L-07"][1] and "second" in parsed["L-07"][1]


@pytest.mark.parametrize("rows", [
    ["| L-07 | MAYBE |", "| L-07 | APPENDIX |"],
    ["| L-07 | APPENDIX |", "| L-07 | MAYBE |"],
])
def test_unknown_duplicate_row_keeps_known_report_id_open(tmp_path, rows):
    parsed = _parse(tmp_path, "| Report ID | Disposition |", rows)
    assert parsed["L-07"][0] == "BODY"
    assert "disposition.report_placement_proposal.unknown" in parsed["L-07"][1]


def test_equivalent_aliases_and_ordinal_are_not_identity_conflicts(tmp_path):
    parsed = _parse(tmp_path, "| ID | Report ID | Finding ID | Disposition | Placement |", [
        "| 1 | **L-07** | Finding [l-07] | Appendix-only | APPENDIX |",
    ])
    assert set(parsed) == {"L-07"}
    assert parsed["L-07"][0] == "APPENDIX"
    assert "[FAIL_CLOSED]" not in parsed["L-07"][1]


def test_unknown_competing_identity_retains_known_report_id_in_body(tmp_path):
    parsed = _parse(tmp_path, "| Report ID | Finding ID | Disposition |", [
        "| H-01 | unrecognized | APPENDIX |",
    ])
    assert set(parsed) == {"H-01"}
    assert parsed["H-01"][0] == "BODY"
    assert "identity.report_placement_subject.unknown" in parsed["H-01"][1]


def test_later_clean_row_does_not_hide_identity_conflict(tmp_path):
    parsed = _parse(tmp_path, "| Report ID | Finding ID | Disposition |", [
        "| H-01 | M-02 | APPENDIX |",
        "| H-01 | H-01 | APPENDIX |",
    ])
    assert {key: value[0] for key, value in parsed.items()} == {
        "H-01": "BODY", "M-02": "BODY",
    }


def test_equivalent_duplicate_rows_remain_appendix(tmp_path):
    parsed = _parse(tmp_path, "| Report ID | Disposition |", [
        "| L-07 | APPENDIX |", "| l-07 | Appendix-only |",
    ])
    assert parsed["L-07"][0] == "APPENDIX"


def test_absent_and_unrecognized_report_identity_behavior_is_preserved(tmp_path):
    assert P.parse_disposition_md(tmp_path) == {}
    parsed = _parse(tmp_path, "| Report ID | Disposition |", [
        "| DT-7 | APPENDIX |", "| H-1234 | APPENDIX |", "| 1 | APPENDIX |",
    ])
    assert parsed == {}
