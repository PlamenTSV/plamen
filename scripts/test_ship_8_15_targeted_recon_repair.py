"""Ship 8.15 -- Targeted recon repair.

Root cause (prior post-mortem): on a recon gate failure, `_quarantine_stale_on_retry`
quarantined EVERY expected artifact >=500 bytes regardless of which one failed.
A 443-byte recon_summary.md failure quarantined 5 VALID drafts (design_context,
contract_inventory, state_variables, function_list, template_recommendations),
forcing a full re-run + recompaction.

Current worker-pool fix: canonical recon artifacts are authenticated
prepass/canonical-merge authority and are never retry-owned. Recon quarantine
targets only isolated worker shards; other phases retain targeted quarantine.
"""

from __future__ import annotations

import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

import plamen_driver as D  # noqa: E402
from plamen_validators import (  # noqa: E402
    _quarantine_stale_on_retry,
    _pattern_implicated_by_missing,
)

RECON = next(p for p in D.SC_PHASES if p.name == "recon")
BIG = "x" * 800  # >= 500 bytes -> "stale", quarantine-eligible


def _seed_recon(sp: Path, *, summary_bytes: int = 800):
    sp.mkdir(parents=True, exist_ok=True)
    for name in RECON.expected_artifacts:
        if name == "recon_summary.md":
            (sp / name).write_text("y" * summary_bytes, encoding="utf-8")
        else:
            (sp / name).write_text(BIG, encoding="utf-8")


def _qdir(sp: Path) -> Path:
    return sp / "_retry_quarantine" / "recon"


# --------------------------------------------------------------------------
# helper unit tests
# --------------------------------------------------------------------------

def test_pattern_implicated_concrete_match():
    missing = ["recon content: recon_summary.md is too small (443 bytes)"]
    assert _pattern_implicated_by_missing("recon_summary.md", missing) is True
    assert _pattern_implicated_by_missing("design_context.md", missing) is False


def test_pattern_implicated_glob_prefix():
    missing = ["graph_callgraph.md absent from shard"]
    assert _pattern_implicated_by_missing("graph_*.md", missing) is True
    assert _pattern_implicated_by_missing("verify_*.md", missing) is False


def test_pattern_implicated_empty_missing_is_false():
    assert _pattern_implicated_by_missing("recon_summary.md", []) is False


# --------------------------------------------------------------------------
# targeted quarantine
# --------------------------------------------------------------------------

def test_recon_canonical_artifact_is_not_worker_retry_owned(tmp_path):
    """A canonical failure cannot remove the prepass producer bundle."""
    sp = tmp_path / ".scratchpad"
    _seed_recon(sp)
    missing = ["recon content: design_context.md missing Operational Implications"]
    renamed = _quarantine_stale_on_retry(sp, RECON, missing)
    assert renamed == []
    for keep in RECON.expected_artifacts:
        assert (sp / keep).exists(), f"{keep} should be preserved"
        assert not (_qdir(sp) / keep).exists()


def test_undersized_summary_preserves_valid_drafts(tmp_path):
    """The exact failure: recon_summary.md is 443 bytes (<500) and the
    only implicated file. It is below the quarantine threshold (left for the
    RESUMPTION PROTOCOL to regenerate); NO valid draft is quarantined."""
    sp = tmp_path / ".scratchpad"
    _seed_recon(sp, summary_bytes=443)
    missing = [
        "rc=-2 parity: recon_summary.md is too small after nonzero rc (443 bytes, min=512)",
        "recon content: recon_summary.md is too small to be a clean handoff (443 bytes, min=512)",
    ]
    renamed = _quarantine_stale_on_retry(sp, RECON, missing)
    assert renamed == []  # summary <500 -> not quarantined; nothing else implicated
    for keep in RECON.expected_artifacts:
        if keep == "recon_summary.md":
            continue
        assert (sp / keep).exists(), f"{keep} must be preserved (was destroyed pre-8.15)"


def test_recon_global_failure_preserves_whole_canonical_bundle(tmp_path):
    """A structural failure still cannot split prepass producer authority."""
    sp = tmp_path / ".scratchpad"
    _seed_recon(sp)
    missing = ["structural: phase produced no valid handoff"]
    renamed = _quarantine_stale_on_retry(sp, RECON, missing)
    assert renamed == []
    assert all((sp / name).is_file() for name in RECON.expected_artifacts)


def test_accumulate_phases_still_skip_quarantine(tmp_path):
    """Regression: breadth/depth/rescan still skip quarantine entirely."""
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    breadth = next(p for p in D.SC_PHASES if p.name == "breadth")
    (sp / "analysis_core_state.md").write_text(BIG, encoding="utf-8")
    renamed = _quarantine_stale_on_retry(sp, breadth, ["analysis_core_state.md missing"])
    assert renamed == []
