"""A consolidation survivor is not a disposition subject.

`report_index.md`'s Consolidation Map names the surviving report finding in its
first column and the absorbed internal IDs in `Consolidated From`.  Reading the
first column as the disposition subject demanded typed non-body authority for
the finding that STAYS IN THE BODY -- which no authority ever grants -- so any
merge at all halted report_index.  STEP 1.5 consolidation is mandatory in the
report-index prompt, so this fires on every real report.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import report_disposition_authority as R  # noqa: E402

_MAP = """
| Report ID | Consolidated From | Consolidation Reason |
|-----------|------------------|---------------------|
| L-03 | H-39, H-40, H-55 | Same fix pattern: add zero-value validation |
| L-08 | H-70, H-71 | Same fix pattern: add event emission |
"""


def test_only_absorbed_ids_are_subjects() -> None:
    subjects = R._consolidation_subject_ids(_MAP)
    assert subjects == {"H-39", "H-40", "H-55", "H-70", "H-71"}
    # the survivors stay in the body and need no non-body authority
    assert "L-03" not in subjects
    assert "L-08" not in subjects


def test_first_column_reading_was_the_defect() -> None:
    """Negative control: the old extractor claimed the survivors."""
    legacy = R._first_column_ids(_MAP)
    assert "L-03" in legacy and "L-08" in legacy


def test_unrecognised_headers_treat_every_id_as_a_subject() -> None:
    """Conservative fallback: an unknown shape never silently drops a subject."""
    section = """
| Thing | Other |
|---|---|
| H-1 | H-2 |
"""
    assert R._consolidation_subject_ids(section) == {"H-1", "H-2"}


def test_survivor_column_is_excluded_even_without_a_subject_column() -> None:
    section = """
| Report ID | Notes |
|---|---|
| M-01 | absorbed H-9 |
"""
    subjects = R._consolidation_subject_ids(section)
    assert subjects == {"H-9"}
    assert "M-01" not in subjects


def test_excluded_findings_still_use_the_first_column() -> None:
    """Control: the Excluded Findings table's first column IS the subject."""
    section = """
| Internal ID | Severity | Title | Exclusion Reason |
|---|---|---|---|
| H-12 | Low | a title | DUPLICATE OF M-01 |
"""
    assert "H-12" in R._first_column_ids(section)
