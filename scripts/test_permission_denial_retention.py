"""A permission denial must not discard a completed artifact -- nor vanish.

DODO run31, breadth worker B2: the worker was refused four `Glob` shapes,
routed around them, completed its task, and produced a valid 95KB
`analysis_access_control.md` carrying 11 findings. The artifact sat complete in
its staging lane and was DISCARDED, because
`claude_stream_json_evidence` treated any `permission_denials` entry on a
successful result as a hard contradiction::

    if permission_denials:
        _fail("RESULT_PERMISSION_DENIED", "successful result contains permission denials")

Two sibling workers (B1, B3) did equivalent work under the identical policy and
published fine, so the policy was workable -- B2 merely used call shapes the
hook does not admit. The denials themselves were CORRECT: `safe_search_roots`
deliberately excludes the project root because a search there would traverse
`.scratchpad`.

Losing a true finding is the unacceptable error in this pipeline, and every
other degraded path records visible debt instead of dropping work. So denials
are now retained as bound, hashed coverage evidence, and the driver projects
them into the phase debt ledger. Publication stays gated on the worker actually
producing its exact expected output and passing the staged validator -- the real
soundness check.

The two properties below must hold TOGETHER. Retention without visibility would
just be provenance laundering, which is the defect class this driver exists to
prevent.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import plamen_driver as D  # noqa: E402
from claude_stream_json_evidence import ClaudeStreamJsonEvidence  # noqa: E402


def test_evidence_record_carries_denials() -> None:
    """The record must expose count, digest and tool names."""
    for field in (
        "permission_denial_count",
        "permission_denial_digest",
        "permission_denial_tools",
    ):
        assert field in ClaudeStreamJsonEvidence.__dataclass_fields__, (
            f"{field} is not carried on the evidence record; retained denials "
            "would be invisible"
        )


def test_denial_is_no_longer_a_hard_contradiction() -> None:
    """Source-level pin: a denial must not fail the evidence parse."""
    source = (_SCRIPTS / "claude_stream_json_evidence.py").read_text("utf-8")
    assert '_fail(\n                "RESULT_PERMISSION_DENIED"' not in source, (
        "a permission denial again discards the whole result; this threw away "
        "a valid 95KB analysis carrying 11 findings in DODO run31"
    )


def _write_receipt(scratchpad: Path, *, label: str, denials: int) -> None:
    root = scratchpad / ".posix_v2_compat_receipts"
    root.mkdir(parents=True, exist_ok=True)
    payload = {
        "label": label,
        "completion_evidence": {
            "status": "COMPLETED",
            "permission_denial_count": denials,
            "permission_denial_digest": "a" * 64 if denials else "",
            "permission_denial_tools": ["Glob"] if denials else [],
        },
    }
    (root / f"breadth.{label}.attempt3.{'b' * 32}.json").write_text(
        json.dumps(payload), encoding="utf-8",
    )


def test_retained_denials_are_projected_as_visible_debt(tmp_path: Path) -> None:
    """Retention MUST be paired with visibility, or it is laundering."""
    _write_receipt(tmp_path, label="breadth_worker_B2", denials=4)
    rows = D._record_permission_denial_coverage_debt(tmp_path, "breadth")
    assert rows == 1

    sentinel = tmp_path / "breadth.degraded"
    assert sentinel.exists(), "no debt sentinel was written"
    text = sentinel.read_text(encoding="utf-8")
    assert "PROVIDER_PERMISSION_DENIED_COVERAGE" in text
    assert "breadth_worker_B2" in text
    assert "Glob" in text
    assert "4" in text


def test_clean_workers_produce_no_debt(tmp_path: Path) -> None:
    """A worker with no denials must not be slandered with coverage debt."""
    _write_receipt(tmp_path, label="breadth_worker_B1", denials=0)
    assert D._record_permission_denial_coverage_debt(tmp_path, "breadth") == 0
    assert not (tmp_path / "breadth.degraded").exists()


def test_projection_is_resilient_to_junk_receipts(tmp_path: Path) -> None:
    """Debt projection must never fail a phase."""
    root = tmp_path / ".posix_v2_compat_receipts"
    root.mkdir(parents=True)
    (root / "breadth.x.attempt1.junk.json").write_text("{not json", encoding="utf-8")
    assert D._record_permission_denial_coverage_debt(tmp_path, "breadth") == 0


def test_absent_receipt_root_is_not_an_error(tmp_path: Path) -> None:
    assert D._record_permission_denial_coverage_debt(tmp_path, "breadth") == 0
