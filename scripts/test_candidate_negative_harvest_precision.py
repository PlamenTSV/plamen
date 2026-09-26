"""The candidate-negative harvester must not manufacture phantom candidates.

DODO run34 breadth produced 8 artifacts carrying 130 findings. Two were
DISCARDED by the staged candidate-negative gate:

  * `analysis_economic_parameters.md` -- 124KB, 17 findings, every one
    correctly IDed. Rejected because a METHODOLOGY SELF-REPORT table

        | Check | Status | Location |
        | Replay check before state changes | n/a (absent) | - |

    was harvested as a candidate. That row says "this CHECK does not apply",
    not "this CANDIDATE is not applicable"; the table has no candidate
    denominator at all. The harvest minted a DERIVED-identity
    NOT_APPLICABLE candidate and then flagged it twice.

  * `analysis_cross_chain_encoding.md` -- 104KB, 13 findings. Rejected over

        | - (zero rows) | NOT_APPLICABLE_PROPOSAL | ... |

    i.e. a zero-denominator attestation using BOTH the right placeholder and
    the right nonterminal enum, which merely omitted the `Candidate ID` column
    header. The existing filter required an explicit ID column, so it could
    not fire.

Both are false positives against workers that did substantially correct work.
Because any debt reason blocks publication outright, a formatting imperfection
was costing 30 real findings -- inverting the recall-safety the contract exists
to protect.

The negative controls below matter as much as the positives: the harvester must
still catch a REAL derived-identity negative and a REAL terminal-closure
spelling, or this fix would trade false positives for false negatives.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import candidate_negative_authority as CN  # noqa: E402


_METHODOLOGY = Path(__file__).resolve().parents[1] / "rules" / "finding-output-format.md"


def _issues(body: str) -> list[str]:
    art = CN.ArtifactInput(
        relative_path="analysis_probe.md",
        content=body.encode("utf-8"),
        producer_identity="breadth_worker_P",
        producer_invocation_id="p" * 32,
    )
    ledger = CN.build_candidate_negative_ledger(
        phase="breadth", artifacts=[art],
        methodology_path=_METHODOLOGY, prior_ledger=None,
    )
    return [str(issue.get("code")) for issue in ledger["issues"]]


def test_methodology_self_report_table_is_not_harvested() -> None:
    """The exact run34 B4 shape."""
    body = (
        "# Probe\n\n### Step 4 - Replay protection\n\n"
        "| Check | Status | Location |\n|---|---|---|\n"
        "| Replay check before state changes | n/a (absent) | - |\n"
    )
    assert _issues(body) == []


def test_zero_denominator_row_without_an_id_column_is_not_harvested() -> None:
    """The exact run34 B8 shape."""
    body = (
        "# Probe\n\n## Candidates\n\n"
        "| Candidate | Disposition | Notes |\n|---|---|---|\n"
        "| — (zero rows) | NOT_APPLICABLE_PROPOSAL | zero-data projection |\n"
    )
    assert _issues(body) == []


def test_real_derived_identity_negative_is_still_caught() -> None:
    """NEGATIVE CONTROL: a real candidate without an ID must still be debt."""
    body = (
        "# Probe\n\n## Candidates\n\n"
        "| Candidate | Disposition | Notes |\n|---|---|---|\n"
        "| unchecked external call in withdraw() | REFUTATION_PROPOSAL | "
        "guarded by nonReentrant |\n"
    )
    assert "DERIVED_SOURCE_ITEM_ID" in _issues(body), (
        "a real candidate lacking an explicit ID must still raise debt; the "
        "precision fix must not blind the harvester"
    )


def test_terminal_na_on_a_real_candidate_is_still_caught() -> None:
    """NEGATIVE CONTROL: bare N/A on a real candidate is still a violation."""
    body = (
        "# Probe\n\n## Candidates\n\n"
        "| Candidate ID | Candidate | Disposition |\n|---|---|---|\n"
        "| B1-4 | reentrancy in claimRefund | N/A |\n"
    )
    codes = _issues(body)
    assert codes, "a real candidate using terminal N/A must still be debt"


def test_every_run34_breadth_artifact_publishes() -> None:
    """Regression against the real retained artifacts, when present."""
    base = Path(
        "/Users/ptsanev/dodo-v3-validation-run34/omni-chain-contracts"
        "/.scratchpad/.worker_transactions/breadth"
    )
    artifacts = sorted(base.glob("*/attempts/*/output/analysis_*.md"))
    if not artifacts:
        import pytest
        pytest.skip("run34 evidence tree not present on this machine")
    total_events = 0
    for path in artifacts:
        art = CN.ArtifactInput(
            relative_path=path.name, content=path.read_bytes(),
            producer_identity="w", producer_invocation_id="x" * 32,
        )
        ledger = CN.build_candidate_negative_ledger(
            phase="breadth", artifacts=[art],
            methodology_path=_METHODOLOGY, prior_ledger=None,
        )
        assert ledger["issues"] == [], (
            f"{path.name} would still be discarded: {ledger['issues']}"
        )
        total_events += len(ledger.get("events", []))
    assert total_events > 0, "harvester mints nothing; it has been blinded"


@pytest.mark.parametrize("phase", ["breadth", "rescan", "depth"])
def test_precision_holds_for_every_phase_running_this_gate(phase: str) -> None:
    """The staged candidate-negative gate runs for breadth, rescan AND depth.

    `_staged_methodology_repair_output_validator` selects
    `staged_prepublication_candidate_negative_validator` for breadth/rescan and
    `staged_depth_candidate_negative_receipt_validator` for depth, so a
    checklist-row false positive costs artifacts in all three. Depth is the
    worst case: it produces ~15 artifacts per wave.
    """
    body = (
        "# Probe\n\n### Step 4 - Replay protection\n\n"
        "| Check | Status | Location |\n|---|---|---|\n"
        "| Replay check before state changes | n/a (absent) | - |\n"
    )
    art = CN.ArtifactInput(
        relative_path="probe.md", content=body.encode("utf-8"),
        producer_identity=f"{phase}_worker_P", producer_invocation_id="p" * 32,
    )
    ledger = CN.build_candidate_negative_ledger(
        phase=phase, artifacts=[art],
        methodology_path=_METHODOLOGY, prior_ledger=None,
    )
    assert ledger["issues"] == [], (
        f"{phase} still harvests a methodology self-report row as a candidate"
    )


_RUN46_INVARIANT_REGISTER = """
## Economic Invariant Register (ECONOMIC_DESIGN_AUDIT S2)

| # | Invariant | Params | Admin can break? | Functions assuming it | Status |
|---|---|---|---|---|---|
| I1 | Tokens approved to an external spender are denominated in the token actually received | `params.fromToken`, `amount` | n/a (any caller) | `_doMixSwap` | **BROKEN** -> `[B3-1]` |
| I2 | `amount` credited == value actually delivered to the contract | `amount`, `msg.value` | n/a (any caller) | `withdrawToNativeChain` | **BROKEN** -> `[B3-2]` |
| I7 | Allowance granted == allowance consumed | `gasFee`, `amountInMax` | n/a | `_handleBitcoinWithdraw` | **BROKEN** -> `[B3-8]` |
| I8 | Total supply / emission backing | - | - | - | N/A - no mint, burn, rebase, emission, or share-accounting primitive exists in any of the three contracts |

## Finding [B3-1]: `_doMixSwap` grants a spend allowance against an unrelated token

**Verdict**: CONFIRMED
**Severity**: High
**Location**: contracts/GatewayCrossChain.sol:L200
**Description**: allowance denominated in the wrong token.
**Impact**: attacker drains the approved balance.
**Material Harm**: depositors lose the approved amount.
"""


def test_invariant_register_with_an_incidental_na_row_is_not_harvested() -> None:
    """DODO run46 breadth B3: a skill-mandated invariant register (`#` column,
    free-text `Status`, one `N/A` cell) is a report on invariants, not a
    candidate table.  It must mint no DERIVED / N/A candidate."""
    assert _issues(_RUN46_INVARIANT_REGISTER) == []


def test_idless_table_speaking_dispositions_is_still_harvested() -> None:
    """Negative control: an ID-less table whose rows ARE dispositions keeps the
    derived-identity and terminal-N/A contract."""
    body = """
| Candidate | Verdict |
|---|---|
| reentrancy in claimRefund | REFUTATION_PROPOSAL |
| oracle staleness | N/A |
"""
    codes = _issues(body)
    assert "DERIVED_SOURCE_ITEM_ID" in codes
    assert "EVENT_NOT_APPLICABLE_WITH_NONZERO_DENOMINATOR" in codes


_RUN47_OPENGREP_ATTESTATION = """
## OpenGrep Obligation Disposition

| Candidate ID | Row | Disposition |
|---|---|---|
| — | none (shard contains zero scanner rows) | NOT_APPLICABLE_PROPOSAL |

**Verdict**: NOT_APPLICABLE_PROPOSAL
**Non-Value-Bearing Category**: OBSERVABILITY_ONLY
**Invariant Commitment**: NOT_REQUIRED_NON_VALUE_BEARING: the assigned shard is a
deterministic zero-data absence projection and carries no rows to classify.

## Finding [B6-1]: replayed message accepted twice

**Verdict**: CONFIRMED
**Severity**: High
**Location**: contracts/GatewaySend.sol:L120
**Description**: no nonce binding on the inbound message.
**Impact**: attacker replays a deposit.
**Material Harm**: depositors lose replayed amounts.
"""


def test_section_level_zero_candidate_attestation_is_not_harvested() -> None:
    """DODO run47 breadth B6: a non-candidate section restating the explicit
    zero-candidate table attestation as `**Verdict**: NOT_APPLICABLE_PROPOSAL`
    names no candidate and must mint no DERIVED entity."""
    assert _issues(_RUN47_OPENGREP_ATTESTATION) == []


def test_candidate_heading_with_not_applicable_proposal_is_still_an_event() -> None:
    """Negative control: a real, explicitly-IDed candidate proposing
    NOT_APPLICABLE_PROPOSAL stays in the denominator (EXACT event, no debt)."""
    body = _RUN47_OPENGREP_ATTESTATION.replace(
        "## OpenGrep Obligation Disposition", "### Finding [B6-9]: emission backing"
    )
    art = CN.ArtifactInput(
        relative_path="analysis_probe.md", content=body.encode("utf-8"),
        producer_identity="breadth_worker_P", producer_invocation_id="p" * 32,
    )
    ledger = CN.build_candidate_negative_ledger(
        phase="breadth", artifacts=[art], methodology_path=_METHODOLOGY, prior_ledger=None,
    )
    exact = [e for e in ledger["events"] if e.get("source_item_id") == "B6-9"]
    assert len(exact) == 1 and exact[0]["identity_state"] == "EXACT"
    assert exact[0]["proposed_disposition"] == "NOT_APPLICABLE_PROPOSAL"


# ==========================================================================
# Depth-shape precision (2026-09-20 downstream discovery, actions 12 and 14).
# Every depth role is instructed to emit these tables.  No DODO run had ever
# committed a depth core artifact, so their harvest behaviour was unobserved;
# these pin it before run48 reaches depth.
# ==========================================================================

_DEPTH_FINDING = """
## Finding [DEPTH-TF-2]: Fee accounting drops the refund leg

**Verdict**: CONFIRMED
**Severity**: Medium
**Location**: contracts/GatewayTransferNative.sol:L88
**Description**: refund path never credits the accumulator.
**Impact**: depositors lose the refunded amount.
**Material Harm**: depositors lose the refunded fee permanently.
**Evidence**: `accFee` is not updated at L88.
"""

_PERTURBATION_BLOCK = """
### Perturbation Block - DEPTH-TF-2

| Operator | Probe | Verdict |
|---|---|---|
| DIRECTION_FLIP | withdrawal rounding at L88 | safe — symmetric rounding |
| BOUNDARY | amount = 0 at L88 | safe — reverts before the write |
| ROLE_SWAP | keeper calls refund | N/A |
| TIMING | same-block refund | N/A |
"""

_SKILL_CHECKLIST = """
## Skill Execution Checklist

| # | Check | Status | Location |
|---|---|---|---|
| 1 | inbound message decoder audited | N/A | — |
| 2 | peer registry reviewed | N/A | — |
| 3 | replay guard traced | N/A | — |

| # | Skill Step | Status | Notes |
|---|---|---|---|
| 1 | enumerate write sites | N/A | no accumulator in scope |
| 2 | trace refund leg | N/A | covered by DEPTH-TF-2 |
"""

_CHAIN_SUMMARY_TIER = """
## Chain Summary

| Finding ID | Title | Severity | Postconditions Created |
|---|---|---|---|
| [DEPTH-TF-2] | Fee accounting drops the refund leg | N/A (refuted) | none |
"""


def test_depth_perturbation_block_is_a_self_report_not_a_candidate_table() -> None:
    assert _issues(_DEPTH_FINDING + _PERTURBATION_BLOCK) == []


def test_depth_perturbation_block_with_only_safe_rows_is_not_harvested() -> None:
    body = _PERTURBATION_BLOCK.replace("| N/A |", "| safe — no divergence |")
    assert _issues(_DEPTH_FINDING + body) == []


def test_skill_execution_checklists_are_not_candidate_tables() -> None:
    assert _issues(_DEPTH_FINDING + _SKILL_CHECKLIST) == []


def test_severity_cell_is_a_tier_never_a_disposition() -> None:
    assert _issues(_DEPTH_FINDING + _CHAIN_SUMMARY_TIER) == []
    for tier in ("N/A", "Not Applicable", "—"):
        body = _CHAIN_SUMMARY_TIER.replace("N/A (refuted)", tier)
        assert _issues(_DEPTH_FINDING + body) == [], tier


def test_severity_is_not_a_block_disposition_field() -> None:
    body = _DEPTH_FINDING.replace(
        "**Severity**: Medium", "**Severity**: N/A"
    )
    assert _issues(body) == []


@pytest.mark.parametrize("cell", ["[DEPTH-TF-2]", "DEPTH-TF-2", "Finding [DEPTH-TF-2]"])
def test_decorated_identity_cells_keep_exact_credit(cell: str) -> None:
    """Brackets and the role word are Markdown decoration, not identity."""
    body = _DEPTH_FINDING + f"""
| Finding ID | Verdict |
|---|---|
| {cell} | REFUTATION_PROPOSAL |
"""
    issues = _issues(body)
    assert "DERIVED_SOURCE_ITEM_ID" not in issues, issues


def test_ambiguous_identity_cell_stays_derived() -> None:
    body = _DEPTH_FINDING + """
| Finding ID | Verdict |
|---|---|
| [A]/[B] | REFUTATION_PROPOSAL |
"""
    assert "DERIVED_SOURCE_ITEM_ID" in _issues(body)


def test_terminal_na_in_a_verdict_column_with_a_real_id_is_still_caught() -> None:
    """Control: an ID column means the full per-row contract still applies."""
    body = _DEPTH_FINDING + """
| Finding ID | Verdict |
|---|---|
| DEPTH-TF-9 | N/A |
"""
    assert _issues(body) != []


_OBLIGATION_RECEIPTS = """
## Obligation Dispositions

[OBLIG:security_obligations.md:SO-004] STATUS:D KEY:no reachable sink for the tainted length
[OBLIG:function_summary.md:GatewaySend.quote] STATUS:DISMISSED KEY:view-only, no state delta
[OBLIG:opengrep_findings.md:12] STATUS:D KEY:rule fires on a test fixture
"""


def test_obligation_receipts_are_not_charged_candidate_identity_debt() -> None:
    """A receipt disposes a DRIVER-OWNED obligation row.

    Its identity is the obligation key, so "this candidate has no explicit ID"
    is not a property it can violate.  Charging it denied every depth worker
    that correctly dismissed an obligation the driver handed it.
    """
    assert _issues(_DEPTH_FINDING + _OBLIGATION_RECEIPTS) == []


def test_unnamed_heading_negative_is_still_derived_identity_debt() -> None:
    """Control: a real candidate with no ID still raises identity debt."""
    body = """
## Finding: an unnamed refutation

**Verdict**: REFUTATION_PROPOSAL
**Location**: contracts/GatewaySend.sol:L20
**Description**: the guard already blocks it.
"""
    assert "DERIVED_SOURCE_ITEM_ID" in _issues(body)
