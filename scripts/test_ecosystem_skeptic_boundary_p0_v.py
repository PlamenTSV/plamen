"""P0-V/P0-AI reachability fixtures for ecosystem Phase-5 prompts.

These prompt files are inputs to standard verification workers.  They may point
at the independent skeptic/adjudication contract, but must not embed a second
orchestration path that can self-dispose findings or silently narrow the
challenge denominator to High/Critical findings.
"""
from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent

PHASE_PROMPTS = tuple(
    ROOT / "prompts" / ecosystem / "phase5-verification-prompt.md"
    for ecosystem in ("evm", "solana", "aptos", "sui", "soroban", "daml")
)
SELF_CHECKS = tuple(
    ROOT / "prompts" / ecosystem / "self-check-checklists.md"
    for ecosystem in ("evm", "solana", "aptos", "sui", "soroban")
)


def _read(path: Path) -> str:
    # Some inherited checklists intentionally retain a UTF-8 BOM.
    return path.read_text(encoding="utf-8-sig")


def test_ecosystem_verifiers_expose_only_compact_independent_boundary():
    required = (
        "independent semantic trigger manifest across all severities",
        "proposal-only",
        "distinct typed adjudicator",
        "every exact manifest finding id once",
        "report-authoritative typed severity/disposition ledger",
        "`unresolved` and `partial` preserve the highest supported upstream tier",
        "remain visible in the report body",
    )
    forbidden = (
        "## skeptic-judge verification",
        "### step 1: spawn skeptic agent",
        "### step 3: spawn judge agent",
        "for each high/crit finding after standard verification",
        "final verdict = standard verdict",
        "| judge: skeptic_wins |",
        "judge agent (haiku, only if disagreement)",
    )

    for path in PHASE_PROMPTS:
        assert path.is_file(), path
        text = _read(path)
        lower = text.lower()
        assert not [token for token in forbidden if token in lower], path
        assert not [token for token in required if token not in lower], path

        marker = "## Independent Skeptic Challenge Boundary (Thorough mode)"
        assert text.count(marker) == 1, path
        boundary = text.split(marker, 1)[1].split(
            "## Cross-Batch Consistency Check", 1
        )[0]
        assert "Task(" not in boundary, path
        assert "### Step" not in boundary, path
        assert len(boundary.splitlines()) <= 16, path


def test_ecosystem_self_checks_enforce_exact_id_receipt_and_authority():
    required = (
        "eligible findings across all severity tiers",
        "exactly one row for every exact manifest finding id",
        "proposal-only",
        "separate typed adjudicator",
        "report-authoritative typed severity/disposition ledger",
        "`unresolved` and `partial` findings preserved",
        "remained visible in the report body",
        "explicit human review rather than silently skipping an id",
    )
    forbidden = (
        "## after skeptic-judge",
        "all high/crit findings received skeptic agent",
        "if skeptic disagreed: judge agent spawned",
        "final verdicts applied per ruling table",
        "skeptic_*.md and judge_*.md files exist",
    )

    for path in SELF_CHECKS:
        assert path.is_file(), path
        lower = _read(path).lower()
        assert not [token for token in forbidden if token in lower], path
        assert not [token for token in required if token not in lower], path


def test_ecosystem_boundary_does_not_make_uncertainty_a_discount():
    for path in (*PHASE_PROMPTS, *SELF_CHECKS):
        lower = _read(path).lower()
        assert "unresolved demotion" not in lower, path
        assert "partial demotion" not in lower, path
        assert "unresolved findings are demoted" not in lower, path
        assert "partial findings are demoted" not in lower, path
