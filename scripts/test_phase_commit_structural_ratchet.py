"""Migration ratchet for the remaining legacy checkpoint mutation surface.

P0-AC is not pipeline-wide while the driver can directly project completion or
degraded state.  These ceilings freeze the reviewed debt boundary: later work
may replace legacy calls with ``PhaseCommitController``, but cannot add another
untyped mutation without deliberately changing this test and its review.
"""

from __future__ import annotations

import ast
from pathlib import Path


DRIVER = Path(__file__).with_name("plamen_driver.py")
MAX_DIRECT_MARK_COMPLETED = 0
# One reviewed residual is a denominator-change invalidator, not a completion
# projection: `_invalidate_post_verify_suffix` atomically rewinds a set of
# downstream phases before any one of them can be recommitted.  The only other
# append lives inside PhaseCommitController itself and this AST ratchet does not
# classify that authority implementation as a caller bypass.
MAX_DIRECT_DEGRADED_APPEND = 1


def _is_attribute_chain(node: ast.AST, *names: str) -> bool:
    current = node
    for name in reversed(names):
        if not isinstance(current, ast.Attribute) or current.attr != name:
            return False
        current = current.value
    return isinstance(current, ast.Name) and current.id == "checkpoint"


def _legacy_mutation_counts() -> tuple[int, int]:
    tree = ast.parse(DRIVER.read_text(encoding="utf-8"), filename=str(DRIVER))
    completed = 0
    degraded = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if _is_attribute_chain(node.func, "mark_completed"):
            completed += 1
        if _is_attribute_chain(node.func, "degraded", "append"):
            degraded += 1
    return completed, degraded


def test_legacy_checkpoint_mutation_surface_cannot_grow() -> None:
    completed, degraded = _legacy_mutation_counts()
    assert completed <= MAX_DIRECT_MARK_COMPLETED, (
        "new direct checkpoint.mark_completed call bypasses typed phase-commit "
        f"authority: reviewed ceiling={MAX_DIRECT_MARK_COMPLETED}, actual={completed}"
    )
    assert degraded <= MAX_DIRECT_DEGRADED_APPEND, (
        "new direct checkpoint.degraded.append call bypasses typed phase-commit "
        f"authority: reviewed ceiling={MAX_DIRECT_DEGRADED_APPEND}, actual={degraded}"
    )
