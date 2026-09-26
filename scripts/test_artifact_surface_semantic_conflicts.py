"""Synthetic contracts for checked role resolution, without audit fixtures."""

from __future__ import annotations

import itertools
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import artifact_surface as A  # noqa: E402


def _table(headers: tuple[str, ...], cells: tuple[str, ...]) -> A.Table:
    text = (
        "| " + " | ".join(headers) + " |\n"
        + "|" + "|".join("---" for _ in headers) + "|\n"
        + "| " + " | ".join(cells) + " |\n"
    )
    return A.read_tables(text)[0]


def _identity(value: str) -> str | None | A.IgnoredRoleValue:
    if value.isdecimal():
        return A.IGNORE_ROLE_VALUE
    if A.is_zero_candidate_placeholder(value):
        return "ZERO_CANDIDATES"
    identity = A.candidate_identity(value)
    return identity.key if identity else None


def _placement(value: str) -> str | None:
    return {
        "BODY": "BODY", "REPORTABLE": "BODY",
        "APPENDIX": "APPENDIX", "APPENDIX_ONLY": "APPENDIX",
    }.get(A.normalize_enum(value))


def _resolve(table: A.Table, role="candidate_id", normalizer=_identity,
             property_name="identity.candidate_id") -> A.RoleResolution:
    return table.resolve_role(
        table.rows[0], role, normalizer=normalizer, property_name=property_name
    )


def test_all_matching_indexes_are_preserved_without_changing_legacy_get():
    table = _table(("ID", "Finding ID", "Finding ID"), ("1", "DS-1", "DS-2"))
    assert table.role_indices("candidate_id") == (0, 1, 2)
    assert table.role_index("candidate_id") == 1
    assert table.rows[0].get("candidate_id") == "DS-1"
    assert table.role_indices("disposition") == ()
    result = _resolve(table)
    assert result.state == "CONFLICT" and result.value is None
    assert [item.normalized for item in result.assertions] == [None, "DS-1", "DS-2"]
    assert [item.state for item in result.assertions] == ["IGNORED", "RESOLVED", "RESOLVED"]
    assert [item.column for item in result.assertions] == [0, 1, 2]
    assert [item.header for item in result.assertions] == ["ID", "Finding ID", "Finding ID"]
    assert [item.raw for item in result.assertions] == ["1", "DS-1", "DS-2"]
    assert all(item.physical_line == 3 for item in result.assertions)
    conflict = next(d for d in result.defects if d.blocking)
    assert conflict.property_violated == "identity.candidate_id.conflict"
    assert "DS-1" in conflict.observed and "DS-2" in conflict.observed


@pytest.mark.parametrize("cells", [("DS-1", "**DS-1**"), ("1", "DS-1")])
def test_equivalent_identity_or_explicit_ordinal_ignore_resolves(cells):
    result = _resolve(_table(("ID", "Finding ID"), cells))
    assert result.state == "RESOLVED" and result.value == "DS-1"
    assert result.defects and not any(d.blocking for d in result.defects)


@pytest.mark.parametrize("columns", list(itertools.permutations([
    ("ID", "DS-1"), ("Finding ID", "DS-2"), ("Candidate ID", "DS-1")
])))
def test_identity_conflict_is_invariant_to_rank_and_column_order(columns):
    headers, cells = zip(*columns)
    result = _resolve(_table(headers, cells))
    assert result.state == "CONFLICT" and result.value is None
    assert {item.normalized for item in result.assertions} == {"DS-1", "DS-2"}
    assert any(d.blocking for d in result.defects)


def test_zero_candidate_assertion_and_real_candidate_conflict():
    result = _resolve(_table(("Finding ID", "ID"), ("N/A", "DS-1")))
    assert result.state == "CONFLICT" and result.value is None
    assert {item.normalized for item in result.assertions} == {"ZERO_CANDIDATES", "DS-1"}


@pytest.mark.parametrize("cells,state,value", [
    (("Appendix", "**Appendix-only**"), "RESOLVED", "APPENDIX"),
    (("BODY", "APPENDIX"), "CONFLICT", None),
    (("APPENDIX", "unclear"), "UNKNOWN", None),
    (("unclear", "unclear"), "UNKNOWN", None),
])
def test_disposition_aliases_conflicts_and_unknowns(cells, state, value):
    result = _resolve(_table(("Disposition", "Status"), cells),
                      "disposition", _placement, "disposition.report_placement")
    assert (result.state, result.value) == (state, value)
    assert any(d.blocking for d in result.defects) == (state != "RESOLVED")


@pytest.mark.parametrize("cells,state", [
    (("High", "**HIGH**"), "RESOLVED"),
    (("HIGH", "LOW"), "CONFLICT"),
])
def test_severity_normalization_does_not_hide_tier_conflicts(cells, state):
    def severity(value):
        normalized = A.normalize_enum(value)
        return normalized if normalized in {"HIGH", "LOW"} else None

    result = _resolve(_table(("Severity", "Risk Level"), cells),
                      "severity", severity, "severity.report_tier")
    assert result.state == state
    assert any(d.blocking for d in result.defects) == (state == "CONFLICT")


def test_missing_unknown_and_ignored_are_distinct_and_never_values():
    missing = _resolve(_table(("Notes",), ("text",)))
    unknown = _resolve(_table(("Finding ID",), ("unrecognized",)))
    ignored = _resolve(_table(("ID",), ("1",)))
    assert [r.state for r in (missing, unknown, ignored)] == ["MISSING", "UNKNOWN", "IGNORED"]
    assert all(r.value is None for r in (missing, unknown, ignored))
    assert missing.assertions == ()
    assert unknown.assertions[0].raw == "unrecognized"
    assert ignored.assertions[0].state == "IGNORED"
    assert any(d.blocking for d in missing.defects)
    assert any(d.blocking for d in unknown.defects)
    assert ignored.defects == ()


def test_empty_companion_cell_retains_known_identity_and_visible_debt():
    result = _resolve(_table(("Finding ID", "ID"), ("DS-1", "")))
    assert result.state == "RESOLVED" and result.value == "DS-1"
    assert result.assertions[1].state == "MISSING"
    assert any("missing_companion_role_cell" in d.property_violated for d in result.defects)
    assert not any(d.blocking for d in result.defects)


def test_physically_missing_cell_is_not_an_unknown_assertion():
    table = _table(("Finding ID", "ID"), ("DS-1",))
    result = _resolve(table)
    assert result.state == "RESOLVED"
    assert result.assertions[1].raw is None
    assert result.assertions[1].state == "MISSING"


def test_non_authoritative_role_conflicts_are_visible_debt():
    result = _resolve(_table(("Notes", "Comment"), ("first", "second")),
                      "notes", A.normalize_cell, "supporting.notes")
    assert result.state == "CONFLICT" and result.value is None
    assert any(d.property_violated == "supporting.notes.conflict" for d in result.defects)
    assert not any(d.blocking for d in result.defects)


@pytest.mark.parametrize("normalizer", [lambda _value: False, lambda _value: ""])
def test_invalid_normalizer_outputs_are_unknown(normalizer):
    result = _resolve(_table(("Finding ID",), ("DS-1",)), normalizer=normalizer)
    assert result.state == "UNKNOWN" and result.value is None
    assert any(d.blocking for d in result.defects)


def test_normalizer_exception_preserves_assertion_and_blocks_resolution():
    def broken(_value):
        raise ValueError("synthetic unavailable vocabulary")

    result = _resolve(_table(("Finding ID",), ("DS-1",)), normalizer=broken)
    assert result.state == "UNKNOWN" and result.value is None
    assert result.assertions[0].raw == "DS-1"
    assert any(d.blocking for d in result.defects)
