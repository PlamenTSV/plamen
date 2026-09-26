"""A retry hint must carry the cause the system already knows.

DODO run34 breadth: 6/8 workers published; B4 and B8 were rejected with
`STAGED_SEMANTIC_REJECTED` for stated, fixable contract violations --

    a real breadth candidate cannot use N/A; use the exact nonterminal
    NOT_APPLICABLE_PROPOSAL enum
    breadth negative uses a derived identity; add one explicit candidate ID

Those strings were sitting in the compatibility receipts. The retry hint said
only that outputs "were not substantial" and told the worker to re-spawn. The
outputs WERE substantial; they were refused on semantics. A retry that does not
carry the reason re-runs blind and repeats the mistake -- run31 went 5/7 ->
retry -> still 5/7 exactly this way.

This is the same defect class as the recon retry hint (which reported "some
files are empty" about an entirely different file than the one that actually
failed): the system holds a precise diagnosis and discards it before the
consumer who needs it.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import plamen_validators as V  # noqa: E402
from plamen_driver import _phase_staged_rejection_reasons  # noqa: E402


_REASONS = [
    "a real breadth candidate cannot use N/A; use the exact nonterminal "
    "NOT_APPLICABLE_PROPOSAL enum",
    "breadth negative uses a derived identity; add one explicit candidate ID",
]


def _seed(tmp_path: Path) -> Path:
    scratch = tmp_path / "scratch"
    (scratch / ".posix_v2_compat_receipts").mkdir(parents=True)
    (scratch / ".posix_v2_compat_receipts"
     / f"breadth.breadth_worker_B4.attempt3.{'a' * 32}.json").write_text(
        json.dumps({
            "label": "breadth_worker_B4",
            "status": "STAGED_SEMANTIC_REJECTED",
            "staged_output_rejection_reasons": _REASONS,
        }),
        encoding="utf-8",
    )
    (scratch / "spawn_manifest.md").write_text(
        "| Agent | Output |\n|---|---|\n"
        "| B4 | analysis_economic_parameters.md |\n",
        encoding="utf-8",
    )
    return scratch


def test_reader_recovers_reasons_without_a_known_label(tmp_path: Path) -> None:
    """The hint generator has no worker label; the reader must still find it."""
    scratch = _seed(tmp_path)
    found = _phase_staged_rejection_reasons(scratch, phase_name="breadth")
    assert any("NOT_APPLICABLE_PROPOSAL" in r for r in found), found


def test_breadth_hint_carries_the_stated_cause(tmp_path: Path) -> None:
    scratch = _seed(tmp_path)
    hint = V._generate_breadth_retry_hint(
        scratch, ["analysis_*.md manifest-exact incomplete (8 expected)"]
    )
    assert "SEMANTIC REJECTIONS" in hint, hint
    assert "NOT_APPLICABLE_PROPOSAL" in hint
    assert "explicit candidate ID" in hint
    # and it must not claim the output was merely too small
    assert "DID produce substantial" in hint


def test_clean_retry_carries_no_false_semantic_claim(tmp_path: Path) -> None:
    """No staged rejections -> no SEMANTIC REJECTIONS section."""
    scratch = tmp_path / "clean"
    scratch.mkdir()
    (scratch / "spawn_manifest.md").write_text(
        "| Agent | Output |\n|---|---|\n| B1 | analysis_core_state.md |\n",
        encoding="utf-8",
    )
    hint = V._generate_breadth_retry_hint(scratch, ["analysis_*.md incomplete"])
    assert "SEMANTIC REJECTIONS" not in hint


def test_depth_alias_still_works(tmp_path: Path) -> None:
    """The depth-scoped call sites must keep working after generalization."""
    from plamen_driver import _depth_staged_rejection_reasons
    scratch = tmp_path / "d"
    (scratch / ".posix_v2_compat_receipts").mkdir(parents=True)
    (scratch / ".posix_v2_compat_receipts"
     / f"depth.depth_worker_x.attempt3.{'b' * 32}.json").write_text(
        json.dumps({"staged_output_rejection_reasons": ["depth reason"]}),
        encoding="utf-8",
    )
    found = _depth_staged_rejection_reasons(
        scratch, label="depth_worker_x", attempt=3,
    )
    assert "depth reason" in found
