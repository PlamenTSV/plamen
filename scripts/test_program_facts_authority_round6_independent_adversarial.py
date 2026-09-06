"""Independent test-governance probe for the R6 TCB disposition."""

from __future__ import annotations

import pytest

import test_program_facts_authority_round5_independent_adversarial as red


def test_impossible_tcb_red_constrains_the_expected_failure_type() -> None:
    """An unrelated setup/runtime failure must not be accepted as the xfail."""

    marks = tuple(
        mark
        for mark in getattr(
            red.test_lexically_captured_semantic_compiler_is_not_reflection_mutable,
            "pytestmark",
            (),
        )
        if mark.name == "xfail"
    )
    assert len(marks) == 1
    mark = marks[0]
    assert mark.kwargs.get("strict") is True
    assert mark.kwargs.get("raises") is AssertionError
