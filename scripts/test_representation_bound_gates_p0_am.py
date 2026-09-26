"""P0-AM: metamorphic + adversarial tests for the representation-bound gates
in ``scripts/plamen_validators.py``.

THE BUG CLASS UNDER TEST
------------------------
A gate tests a REPRESENTATION (exact line shape, decoration, whole-line
anchoring, exact occurrence counts, column position, string equality,
vocabulary allowlists) instead of the PROPERTY it exists to protect, and then
fails CLOSED by discarding the artifact.

Measured, not theoretical. DODO run48 (2026-09-20): every core depth worker
SUCCEEDED, staged its artifact, and the staged obligation validator rejected
them all. The two exact reasons from the run receipts were "malformed
obligation receipt-like line rejected" (the worker wrapped each receipt in
BACKTICKS) and "malformed structured obligation evidence ignored" (a PROSE
sentence NAMED the marker token while explaining where markers were placed).
Neither line had any semantic defect. Both were presentation.

EVERY TEST HERE COMES IN A PAIR
-------------------------------
1. METAMORPHIC: a semantically-equivalent presentation mutation must produce
   an EQUIVALENT verdict. This is what proves the gate is no longer
   representation-bound.
2. ADVERSARIAL: a mutation that really does change MEANING must STILL be
   rejected. A fix that accepts everything is a worse bug than the one being
   fixed, so every metamorphic test is paired with its control.

Worker bytes below are copied verbatim from the read-only run48 scratchpad
(``worker.depth-token-flow`` / recon projections). Nothing here reads those
paths at runtime.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import plamen_validators as V  # noqa: E402
import artifact_surface as A  # noqa: E402


# ---------------------------------------------------------------------------
# Real run48 worker bytes (bounded excerpts, copied verbatim)
# ---------------------------------------------------------------------------

RUN48_DEPTH_FINDING = """<!-- PLAMEN_DISPATCH_PHASE: depth -->
<!-- PLAMEN_DISPATCH_WORKER: depth-token-flow -->
<!-- PLAMEN_DISPATCH_OUTPUT: depth_token_flow_findings.md -->
<!-- PLAMEN_ARTIFACT: depth_token_flow_findings.md -->
<!-- PLAMEN_OWNER: depth-token-flow -->
<!-- PLAMEN_PHASE: depth -->
<!-- AGENT_ROW: depth-token-flow -->
<!-- EXPECTED_OUTPUT: depth_token_flow_findings.md -->

# Depth: Token Flow

### Finding [DT-1]: `claimRefund` transfers before clearing the refund record

**Verdict**: CONFIRMED
**Step Execution**: ✓1,2,3,4,5,6
**Rules Applied**: [R4:✓, R10:✓]
**Preferred Tag**: CODE-TRACE
**Severity**: High
**Location**: `contracts/GatewayTransferNative.sol:L671-L672`

**Description**
`claimRefund` is a claim function whose state marker is the existence of
`refundInfos[externalId]`. This code clears the marker after the value leaves.

**Impact**
One recorded refund can be paid out repeatedly.

**Material Harm**: Any refund beneficiary loses the remaining pool balance to a
reentrant claimant.

### Perturbation Block - DT-1

| Dimension | Perturbation | Verdict | Evidence |
|---|---|---|---|
| Sibling contract | Same defect in `GatewayCrossChain`? | **YES** | transfer `contracts/GatewayCrossChain.sol:L581`, delete `L582` |
| Actor category | Owner-set `bots[]` member | Same path | `contracts/GatewayTransferNative.sol:L668` |

### Finding [DT-2]: Fee split rounds toward the protocol

**Verdict**: CONFIRMED
**Severity**: Medium
**Location**: `contracts/GatewayTransferNative.sol:L403`

**Description**
Integer division truncates the user leg.

**Impact**
Dust accrues to the protocol on every transfer.

### Perturbation Block - DT-2

| Dimension | Perturbation | Verdict | Evidence |
|---|---|---|---|
| Boundary | amount=1 | user receives 0 | `contracts/GatewayTransferNative.sol:L403` |

## Step Execution Trace

| Skill | Step | Executed | Evidence | Result |
|-------|------|----------|----------|--------|
| DEPTH_ROLE_TOKEN_FLOW | h2:your-role | yes | `contracts/GatewayTransferNative.sol:L403` | Deep focused analysis performed. |
| DEPTH_ROLE_TOKEN_FLOW | h2:mandatory-analysis-checks | yes | `contracts/GatewayTransferNative.sol:L671` | Devil's advocate applied per finding. |

<!-- PLAMEN_FINDINGS_COUNT: 2 -->
<!-- PLAMEN_STATUS: COMPLETE -->
"""

RUN48_CONSTRAINT_VARIABLES = """# Constraint Variables

## Constraint Variables

| Variable | Source Location | Bound / Enforcement | Setter | Status |
|---|---|---|---|---|
| `feePercent` | `contracts/GatewayTransferNative.sol:L58` | `require(fee < 1000)` in `setFeePercent` | `setFeePercent` | BOUNDED |
| `MAX_DEADLINE` | `contracts/GatewayTransferNative.sol:L61` | constant `200` | none | CONSTANT |
"""

RUN48_MODIFIERS = """# Modifiers

## Modifier Application Map

| Function | Source Location | Modifier / Guard | Status |
|---|---|---|---|
| `claimRefund` | `contracts/GatewayTransferNative.sol:L661` | `require(bots[msg.sender] || msg.sender == receiver)` | GUARDED |
| `setFeePercent` | `contracts/GatewayTransferNative.sol:L120` | `onlyOwner` | GUARDED |
"""


def _write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


# ===========================================================================
# The classification rule itself
# ===========================================================================

def test_closure_is_derived_not_chosen():
    """A fixer names the family and READS the answer; it never decides."""
    assert V._defect("identity.candidate_id").closure == A.FAIL_CLOSED
    assert V._defect("dedup.merge_decision").closure == A.FAIL_CLOSED
    assert V._defect("severity.cap").closure == A.FAIL_CLOSED
    assert V._defect("disposition.body_vs_appendix").closure == A.FAIL_CLOSED
    for name in (
        "receipt.line_grammar",
        "schema.projection_table",
        "coverage.pde_section",
        "format.duplicate_section",
        "ownership.marker_presence",
        "trace.table_binding",
        "quality.crossbatch_signal",
    ):
        assert V._defect(name).closure == A.DEBT, name


def test_only_a_closed_defect_discards_an_artifact():
    debt = A.CheckResult((V._defect("receipt.line_grammar"),))
    assert not debt.should_discard
    closed = A.CheckResult((V._defect("identity.candidate_id"),))
    assert closed.should_discard


# ===========================================================================
# GATE 1 - compute_depth_row_statuses / _missing_perturbation_block_ids
# ===========================================================================

PERTURBATION_MUTATIONS = {
    "bold": ("### Perturbation Block - DT-", "**Perturbation Block - DT-"),
    "list_marker": ("### Perturbation Block - DT-", "- ### Perturbation Block - DT-"),
    "h1": ("### Perturbation Block - DT-", "# Perturbation Block - DT-"),
    "blockquote": ("### Perturbation Block - DT-", "> ### Perturbation Block - DT-"),
    "field_label": ("### Perturbation Block - DT-", "**Perturbation Block**: DT-"),
}


def test_perturbation_baseline_accepts_real_worker_bytes():
    assert V._missing_perturbation_block_ids(RUN48_DEPTH_FINDING) == []


@pytest.mark.parametrize("name", sorted(PERTURBATION_MUTATIONS))
def test_perturbation_is_not_representation_bound(name):
    """METAMORPHIC: five measured heading spellings, one verdict."""
    old, new = PERTURBATION_MUTATIONS[name]
    mutated = RUN48_DEPTH_FINDING.replace(old, new)
    assert V._missing_perturbation_block_ids(mutated) == []


def test_perturbation_heading_depth_and_crlf_are_presentation():
    assert V._missing_perturbation_block_ids(
        RUN48_DEPTH_FINDING.replace("### Finding [DT-", "#### Finding [DT-")
    ) == []
    assert V._missing_perturbation_block_ids(
        RUN48_DEPTH_FINDING.replace("\n", "\r\n")
    ) == []


def test_perturbation_adversarial_missing_block_still_detected():
    """ADVERSARIAL: really remove the block and the obligation still fires."""
    stripped = "\n".join(
        line for line in RUN48_DEPTH_FINDING.splitlines()
        if "Perturbation" not in line
    )
    assert V._missing_perturbation_block_ids(stripped) == ["DT-1", "DT-2"]


def test_perturbation_narrative_mention_is_not_a_block():
    """ADVERSARIAL: naming perturbation in prose does not satisfy the gate."""
    stripped = "\n".join(
        line for line in RUN48_DEPTH_FINDING.splitlines()
        if "Perturbation" not in line
    )
    narrated = stripped.replace(
        "**Impact**\nOne recorded refund",
        "We considered a perturbation of the fee parameter but found nothing.\n"
        "**Impact**\nOne recorded refund",
    )
    assert "DT-1" in V._missing_perturbation_block_ids(narrated)


# ===========================================================================
# GATE 2 - _depth_artifact_is_stub
# ===========================================================================

STUB_PROSE_MUTATIONS = (
    "Note: the reservation header said `Writing in progress` until this final overwrite.",
    "I removed the PLAMEN-STUB: sentinel from the header before writing findings.",
    "Operators note the batch is writing in progress when paused.",
)


@pytest.mark.parametrize("sentence", STUB_PROSE_MUTATIONS)
def test_stub_prose_mention_does_not_declare_a_stub(tmp_path, sentence):
    """METAMORPHIC: a prose sentence NAMING the marker is a MENTION."""
    path = _write(
        tmp_path,
        "depth_token_flow_findings.md",
        RUN48_DEPTH_FINDING + "\n" + sentence + "\n",
    )
    assert V._depth_artifact_is_stub(path) is None


def test_stub_adversarial_real_reservation_still_detected(tmp_path):
    """ADVERSARIAL: an unpopulated reservation header is still a stub."""
    path = _write(
        tmp_path,
        "depth_token_flow_findings.md",
        "# depth_token_flow_findings.md\n\nWriting in progress\n",
    )
    assert "WRITE-THEN-VERIFY" in (V._depth_artifact_is_stub(path) or "")


def test_stub_adversarial_sentinel_comment_still_detected(tmp_path):
    path = _write(
        tmp_path,
        "depth_token_flow_findings.md",
        "# x\n\n<!-- PLAMEN-STUB: content to follow -->\n",
    )
    assert "PLAMEN-STUB" in (V._depth_artifact_is_stub(path) or "")


# ===========================================================================
# GATE 3 - validate_depth_artifact_ownership / validate_breadth_artifact_ownership
# ===========================================================================

def _own(path: Path, output="depth_token_flow_findings.md", owner="depth-token-flow"):
    return V.validate_depth_artifact_ownership(
        path, expected_output=output, expected_owner=owner
    )


def test_ownership_baseline_accepts_real_worker_bytes(tmp_path):
    ok, reasons = _own(_write(tmp_path, "a.md", RUN48_DEPTH_FINDING))
    assert ok and reasons == []


def test_ownership_fenced_marker_block_no_longer_erases_ownership(tmp_path):
    """METAMORPHIC: the literal run48 'wrapped in BACKTICKS' rejection."""
    lines = RUN48_DEPTH_FINDING.splitlines()
    last_marker = max(i for i, l in enumerate(lines[:20]) if l.startswith("<!--"))
    fenced = ["```"] + lines[: last_marker + 1] + ["```"] + lines[last_marker + 1 :]
    ok, reasons = _own(_write(tmp_path, "a.md", "\n".join(fenced)))
    assert ok, reasons
    assert any("code fence" in r for r in reasons)
    assert all(A.DEBT in r for r in reasons)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda t: t.replace("\n", "\r\n"),
        lambda t: t.replace(
            "<!-- PLAMEN_OWNER: depth-token-flow -->",
            "<!-- PLAMEN_OWNER: **depth-token-flow** -->",
        ),
        lambda t: t.replace(
            "<!-- AGENT_ROW: depth-token-flow -->",
            "<!-- AGENT_ROW: depth-token-flow&nbsp; -->",
        ),
        lambda t: t.replace(
            "<!-- PLAMEN_ARTIFACT: depth_token_flow_findings.md -->",
            "<!-- PLAMEN_ARTIFACT: `depth_token_flow_findings.md` -->",
        ),
    ],
)
def test_ownership_decoration_is_presentation(tmp_path, mutation):
    ok, reasons = _own(_write(tmp_path, "a.md", mutation(RUN48_DEPTH_FINDING)))
    assert ok, reasons


def test_ownership_adversarial_cross_write_still_blocks(tmp_path):
    """ADVERSARIAL: a genuine cross-write is still FAIL_CLOSED."""
    path = _write(tmp_path, "a.md", RUN48_DEPTH_FINDING)
    ok, reasons = _own(path, owner="depth-state-trace")
    assert not ok
    assert any(A.FAIL_CLOSED in r and "identity" in r for r in reasons)

    ok, reasons = _own(path, output="depth_edge_case_findings.md")
    assert not ok
    assert any(A.FAIL_CLOSED in r for r in reasons)


def test_ownership_absent_marker_is_debt_not_discard(tmp_path):
    ok, reasons = _own(_write(tmp_path, "a.md", "# nothing\n\nprose\n"))
    assert ok
    assert reasons and all(A.DEBT in r for r in reasons)


# ===========================================================================
# GATE 4/5 - niche schema + semantic-gap trigger
# ===========================================================================

NICHE_FINDING = """# Niche: Semantic Gap

## Finding [SGI-1]: conditional write leaves the mirror stale

**Verdict**: CONFIRMED
**Step Execution**: ✓1,2,3
**Rules Applied**: [R10:✓]
**Preferred Tag**: CODE-TRACE
**Severity**: Medium
**Location**: `contracts/A.sol:L120`
**Description**: The mirror is only written on the else branch.
**Impact**: Readers see a stale mirror.
**Material Harm**: Any depositor loses the delta between the mirror and the real balance.
**Evidence**: `contracts/A.sol:L120`
**Producer Disposition**: CANDIDATE
**Gap Type**: CONDITIONAL
"""


def test_niche_phase_field_synonyms_are_meaning_not_label(tmp_path):
    """METAMORPHIC: `Producer Disposition` / `Gap Type` carry the same content."""
    path = _write(tmp_path, "niche_semantic_gap_findings.md", NICHE_FINDING)
    assert V._validate_niche_candidate_schema(
        path, additional_required_fields=("Investigation Result",)
    ) == []


def test_niche_adversarial_missing_standard_field_still_reported(tmp_path):
    stripped = NICHE_FINDING.replace(
        "**Severity**: Medium\n", ""
    ).replace("**Location**: `contracts/A.sol:L120`\n", "")
    path = _write(tmp_path, "niche_semantic_gap_findings.md", stripped)
    issues = V._validate_niche_candidate_schema(path)
    assert issues and "Severity" in issues[0]


def test_niche_preacceptance_never_halts_the_depth_phase(tmp_path):
    """The gate is `schema.*` -> DEBT; it must not return a blocking issue."""
    _write(tmp_path, "niche_semantic_gap_findings.md", "# empty\n")
    assert V._validate_niche_findings_preacceptance(tmp_path, "thorough") == []


def test_semantic_gap_english_prose_does_not_arm_the_trigger(tmp_path):
    """METAMORPHIC: flag tokens are SHOUTED; lowercase English is not a flag."""
    _write(
        tmp_path,
        "semantic_invariants.md",
        "Invariant I-1 holds unconditionally across all paths.\n"
        "The write at L120 is conditional on `msg.sender == owner`.\n",
    )
    assert V._semantic_gap_required(tmp_path) is False


def test_semantic_gap_adversarial_real_flag_still_arms(tmp_path):
    _write(
        tmp_path,
        "semantic_invariants.md",
        "| flag | value |\n|---|---|\n| CONDITIONAL_WRITE | present |\n",
    )
    assert V._semantic_gap_required(tmp_path) is True


# ===========================================================================
# GATE 6/7 - recon projection tables
# ===========================================================================

CV_MUTATIONS = {
    "heading_parenthetical": ("## Constraint Variables", "## Constraint Variables (in-scope)"),
    "heading_depth": ("## Constraint Variables", "### Constraint Variables"),
    "heading_bold": ("## Constraint Variables", "## **Constraint Variables**"),
    "column_rename": ("Source Location", "Location"),
}


@pytest.mark.parametrize("name", sorted(CV_MUTATIONS))
def test_constraint_projection_is_not_representation_bound(name):
    old, new = CV_MUTATIONS[name]
    assert V._constraint_variables_structure_issues(
        RUN48_CONSTRAINT_VARIABLES.replace(old, new)
    ) == []


def test_constraint_projection_tolerates_an_extra_column():
    """METAMORPHIC: an extra, MORE informative column is not fatal."""
    mutated = (
        RUN48_CONSTRAINT_VARIABLES
        .replace("| Variable |", "| # | Variable |")
        .replace("|---|---|---|---|---|", "|---|---|---|---|---|---|")
        .replace("| `feePercent` |", "| 1 | `feePercent` |")
        .replace("| `MAX_DEADLINE` |", "| 2 | `MAX_DEADLINE` |")
    )
    assert V._constraint_variables_structure_issues(mutated) == []


def test_constraint_projection_adversarial_absent_table_still_reported():
    issues = V._constraint_variables_structure_issues("# nothing\n\nprose only\n")
    assert issues and "column roles" in issues[0]


MODIFIER_MUTATIONS = {
    "heading_parenthetical": ("## Modifier Application Map", "## Modifier Application Map (per function)"),
    "heading_depth": ("## Modifier Application Map", "### Modifier Application Map"),
    "heading_case": ("## Modifier Application Map", "## Modifier application map"),
    "column_rename": ("Modifier / Guard", "Guard"),
}


@pytest.mark.parametrize("name", sorted(MODIFIER_MUTATIONS))
def test_modifier_projection_is_not_representation_bound(name):
    old, new = MODIFIER_MUTATIONS[name]
    assert V._modifier_application_map_structure_issues(
        RUN48_MODIFIERS.replace(old, new)
    ) == []


def test_modifier_projection_adversarial_absent_table_still_reported():
    issues = V._modifier_application_map_structure_issues("# nothing\n")
    assert issues and "column roles" in issues[0]


def test_recon_projection_defects_are_soft_not_hard(tmp_path):
    """The projection gate must never reject the FIRST phase of an audit."""
    _write(tmp_path, "constraint_variables.md", "# nothing\n")
    _write(tmp_path, "modifiers.md", "# nothing\n")
    hard, soft = V._validate_recon_content_structure(tmp_path)
    assert not any("constraint-variable" in h for h in hard)
    assert not any("modifier application" in h for h in hard)
    assert any("constraint-variable" in s for s in soft)
    assert any("modifier application" in s for s in soft)


# ===========================================================================
# GATE 9 - crossbatch fail signals
# ===========================================================================

CROSSBATCH_CLEAN = """# Cross-Batch Consistency

Overall: PASS
Verifiers Checked: 12
"""


@pytest.mark.parametrize(
    "sentence",
    [
        "No schema violations detected.",
        "0 severity mismatches.",
        "No missing severity field anywhere.",
        "No evidence-tag mismatches.",
    ],
)
def test_crossbatch_negated_report_is_not_a_failure(tmp_path, sentence):
    """METAMORPHIC: reporting the ABSENCE of problems is not a problem."""
    _write(tmp_path, "cross_batch_consistency.md", CROSSBATCH_CLEAN + sentence + "\n")
    assert V._validate_crossbatch_quality(tmp_path) == []


def test_crossbatch_adversarial_real_signal_is_recorded_as_debt(tmp_path):
    """ADVERSARIAL: a genuine assertion is still SEEN - as visible debt."""
    _write(
        tmp_path,
        "cross_batch_consistency.md",
        CROSSBATCH_CLEAN + "Schema violations: 4 findings lack a severity field.\n",
    )
    assert V._validate_crossbatch_quality(tmp_path) == []
    ledger = tmp_path / V._REPRESENTATION_DEBT_LEDGER
    assert ledger.exists()
    assert "consistency/schema issues reported" in ledger.read_text(encoding="utf-8")


# ===========================================================================
# GATE 10 - report body identity
# ===========================================================================

REPORT_BODY = """## High Findings

### [H-01] Bound the fee setter

**Severity**: High
**Location**: `contracts/Vault.sol:L40`

**Description**
The fee setter has no upper bound.

**Impact**
An owner can set a 100% fee and take every deposit, so depositors lose funds.

**PoC Result**
Executed: the harness drained the vault.

**Recommendation**
Add `require(fee < MAX_FEE)`.
"""

MANIFEST = {
    "findings": [
        {
            "report_id": "H-01",
            "severity": "High",
            "location": "contracts/Vault.sol:L40",
            "report_blocked": False,
        }
    ]
}


def test_report_body_baseline_ok():
    assert V._validate_report_body(REPORT_BODY, MANIFEST)["ok"]


def test_report_body_remediation_entry_is_not_a_duplicate_binding():
    """METAMORPHIC: a Priority Remediation Order entry is not a section."""
    body = REPORT_BODY + (
        "\n## Priority Remediation Order\n\n"
        "### [H-01] Bound the fee setter - Immediate\n"
    )
    result = V._validate_report_body(body, MANIFEST)
    assert result["ok"], result


@pytest.mark.parametrize(
    "heading",
    ["### H-01 Bound the fee setter", "#### [H-01] Bound the fee setter",
     "### **[H-01]** Bound the fee setter", "### [ H-01 ] Bound the fee setter"],
)
def test_report_body_identity_spellings_are_one_identity(heading):
    body = REPORT_BODY.replace("### [H-01] Bound the fee setter", heading)
    result = V._validate_report_body(body, MANIFEST)
    assert result["missing"] == [], result


def test_report_body_negated_blocked_tag_is_not_an_assertion():
    """METAMORPHIC: 'is not [REPORT-BLOCKED]' is a NEGATION, not a tag."""
    body = REPORT_BODY.replace(
        "**Recommendation**",
        "This finding is not [REPORT-BLOCKED]; evidence is complete.\n\n"
        "**Recommendation**",
    )
    result = V._validate_report_body(body, MANIFEST)
    assert result["blocked_violations"] == []
    assert result["ok"]


def test_report_body_adversarial_missing_finding_still_blocks():
    """ADVERSARIAL: a manifest finding absent from the body is FAIL_CLOSED."""
    result = V._validate_report_body("## High Findings\n\nnothing\n", MANIFEST)
    assert not result["ok"]
    assert result["missing"] == ["H-01"]


def test_report_body_adversarial_real_blocked_tag_still_seen():
    body = REPORT_BODY.replace(
        "**Description**", "[REPORT-BLOCKED: no verifier evidence]\n\n**Description**"
    )
    result = V._validate_report_body(body, MANIFEST)
    assert result["blocked_violations"]


# ===========================================================================
# GATE 11/13 - Master Finding Index identity
# ===========================================================================

REPORT_INDEX = """# Report Index

## Summary Counts

| Severity | Count |
|----------|-------|
| Critical | 1 |
| High | 1 |

## Master Finding Index

| Report ID | Title | Severity | Verification | Trust Adj. | Internal Hypothesis |
|---|---|---|---|---|---|
| C-01 | Refund replay | Critical | VERIFIED | - | INV-001 |
| H-01 | Fee setter unbounded | High | CONFIRMED | - | INV-002 |

## Excluded Findings

| Internal ID | Severity | Title | Exclusion Reason |
|---|---|---|---|
| INV-003 | Low | Naming | DROP_NON_SECURITY |
"""


def test_master_index_baseline(tmp_path):
    _write(tmp_path, "report_index.md", REPORT_INDEX)
    master, excluded, master_list = V._collect_index_acknowledged_ids(tmp_path)
    assert master == {"INV-001", "INV-002"}
    assert excluded == {"INV-003"}
    assert sorted(master_list) == ["INV-001", "INV-002"]


def test_master_index_extra_column_does_not_invent_a_duplicate(tmp_path):
    """METAMORPHIC: the measured single-extra-column defect, verbatim.

    Appending ONE correct `Notes` column containing "see INV-002" invented a
    duplicate binding AND a dropout in the same row under the last-regex-match
    column heuristic.
    """
    mutated = (
        REPORT_INDEX
        .replace("| Trust Adj. | Internal Hypothesis |", "| Trust Adj. | Notes | Internal Hypothesis |")
        .replace("|---|---|---|---|---|---|\n| C-01", "|---|---|---|---|---|---|---|\n| C-01")
        .replace("| VERIFIED | - | INV-001 |", "| VERIFIED | - | see INV-002 | INV-001 |")
        .replace("| CONFIRMED | - | INV-002 |", "| CONFIRMED | - | - | INV-002 |")
    )
    _write(tmp_path, "report_index.md", mutated)
    master, _excluded, master_list = V._collect_index_acknowledged_ids(tmp_path)
    assert master == {"INV-001", "INV-002"}
    assert sorted(master_list) == ["INV-001", "INV-002"]


@pytest.mark.parametrize(
    "heading", ["### Master Finding Index", "## Master Finding Index (promoted)"]
)
def test_master_index_heading_depth_is_presentation(tmp_path, heading):
    _write(
        tmp_path,
        "report_index.md",
        REPORT_INDEX.replace("## Master Finding Index", heading),
    )
    master, _excluded, _list = V._collect_index_acknowledged_ids(tmp_path)
    assert master == {"INV-001", "INV-002"}


def test_master_index_adversarial_genuine_double_binding_still_seen(tmp_path):
    """ADVERSARIAL: one internal ID sole-bound in two rows is still a dup."""
    mutated = REPORT_INDEX.replace(
        "| H-01 | Fee setter unbounded | High | CONFIRMED | - | INV-002 |",
        "| H-01 | Fee setter unbounded | High | CONFIRMED | - | INV-001 |",
    )
    _write(tmp_path, "report_index.md", mutated)
    _master, _excluded, master_list = V._collect_index_acknowledged_ids(tmp_path)
    assert master_list.count("INV-001") == 2


@pytest.mark.parametrize(
    "mutation",
    [
        lambda t: t.replace("| C-01 |", "| **C-01** |").replace("| H-01 |", "| **H-01** |"),
        lambda t: t.replace("| C-01 |", "| `C-01` |").replace("| H-01 |", "| `H-01` |"),
        lambda t: t.replace("| Report ID | Title |", "| Report&nbsp;ID | Title |"),
    ],
)
def test_master_counts_survive_decoration(mutation):
    """METAMORPHIC: decorated report IDs no longer zero the parity gate."""
    section = mutation(REPORT_INDEX[REPORT_INDEX.index("## Master Finding Index"):])
    counts = V._master_counts_from_section(section)
    assert counts["C"] == 1 and counts["H"] == 1


def test_master_counts_adversarial_empty_section_is_zero():
    assert sum(V._master_counts_from_section("## Master Finding Index\n\nnone\n").values()) == 0


# ===========================================================================
# GATE 12 - report_coverage UNACCOUNTED (was FAILING OPEN)
# ===========================================================================

COVERAGE = """# Report Coverage Audit

## Raw Candidate Ledger

| Source File | Candidate ID | Status | Report ID / Reason |
|---|---|---|---|
| depth_token_flow_findings.md | DT-4 | UNACCOUNTED | - |
| depth_token_flow_findings.md | DT-5 | PROMOTED | H-01 |
"""


def test_coverage_baseline_detects_unaccounted(tmp_path):
    _write(tmp_path, "report_coverage.md", COVERAGE)
    issues = V._validate_report_coverage_accounting(tmp_path)
    assert any("UNACCOUNTED" in i and "DT-4" in i for i in issues)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda t: t.replace("| UNACCOUNTED |", "| **UNACCOUNTED** |"),
        lambda t: t.replace("| UNACCOUNTED |", "| `UNACCOUNTED` |"),
        lambda t: t.replace("| UNACCOUNTED |", "| UNACCOUNTED (pending human review) |"),
        lambda t: t.replace("## Raw Candidate Ledger", "## Coverage Audit Ledger"),
        lambda t: t.replace("## Raw Candidate Ledger", "## Raw Candidate Accounting"),
        lambda t: t.replace("## Raw Candidate Ledger", "### Raw Candidate Ledger"),
    ],
)
def test_coverage_dropped_candidate_can_no_longer_hide(tmp_path, mutation):
    """METAMORPHIC on a FAIL-OPEN gate: the worst case in the whole census.

    Each of these six zero-semantic-change edits made a real dropped finding
    INVISIBLE and shipped it silently.
    """
    _write(tmp_path, "report_coverage.md", mutation(COVERAGE))
    issues = V._validate_report_coverage_accounting(tmp_path)
    assert any("UNACCOUNTED" in i and "DT-4" in i for i in issues)


def test_coverage_adversarial_clean_ledger_is_clean(tmp_path):
    _write(tmp_path, "report_coverage.md", COVERAGE.replace("UNACCOUNTED", "PROMOTED"))
    issues = V._validate_report_coverage_accounting(tmp_path)
    assert not any("UNACCOUNTED" in i for i in issues)


# ===========================================================================
# GATE 14 - per-contract content-bearing (severity/disposition demotion)
# ===========================================================================

@pytest.mark.parametrize(
    "title",
    [
        "Refund path drains user funds",
        "Withdrawal becomes permanently unavailable for every user",
        "Owner can seize the vault without consent",
        "Message replays on the destination chain",
        "Accounting diverges from the real ledger",
        "Depositors receive less than their pro-rata share",
    ],
)
def test_content_bearing_survives_english_pluralization(title):
    """METAMORPHIC: `drains`/`funds` mean what `drain`/`fund` mean."""
    assert V._percontract_candidate_is_content_bearing(
        title, "contracts/A.sol:L12", ""
    )


def test_content_bearing_adversarial_bare_stub_is_still_content_less():
    assert not V._percontract_candidate_is_content_bearing(
        "already known", "contracts/A.sol:L12", "dup of [B1-2]"
    )


def test_content_bearing_adversarial_no_location_is_still_content_less():
    assert not V._percontract_candidate_is_content_bearing(
        "Refund path drains user funds", "", ""
    )


# ===========================================================================
# GATE 15 - obligation receipts (disposition inversion)
# ===========================================================================

OBLIG = """## Obligation Receipts - opengrep_findings.md

| Row | Rule | Notes |
|---|---|---|
| 1 | reentrancy | reported as DT-1 |
| 2 | naming | style only |
"""


def test_obligation_receipts_baseline():
    assert V._parse_obligation_table_receipts(OBLIG, "opengrep_findings.md") == {
        "1": "REPORTED", "2": "DISMISSED",
    }


@pytest.mark.parametrize(
    "mutation",
    [
        lambda t: t.replace("## Obligation Receipts", "# Obligation Receipts"),
        lambda t: t.replace("## Obligation Receipts", "##### Obligation Receipts"),
        lambda t: t.replace("| 1 |", "| **1** |"),
        lambda t: t.replace("| 1 |", "| Row 1 |"),
        lambda t: t.replace("| 1 | reentrancy | reported as DT-1 |",
                            "| 1 | reentrancy | reported as DT-1 |<!-- ok -->"),
    ],
)
def test_obligation_receipts_presentation_does_not_lose_a_receipt(mutation):
    receipts = V._parse_obligation_table_receipts(
        mutation(OBLIG), "opengrep_findings.md"
    )
    assert receipts.get("1") == "REPORTED", receipts


def test_obligation_receipts_negated_keyword_no_longer_inverts_disposition():
    """METAMORPHIC: 'confirmed, not a false positive' is NOT a dismissal."""
    mutated = OBLIG.replace("reported as DT-1", "confirmed, not a false positive")
    receipts = V._parse_obligation_table_receipts(mutated, "opengrep_findings.md")
    assert receipts.get("1") == "REPORTED", receipts


def test_obligation_receipts_adversarial_real_dismissal_still_dismissed():
    receipts = V._parse_obligation_table_receipts(OBLIG, "opengrep_findings.md")
    assert receipts.get("2") == "DISMISSED"


def test_obligation_receipts_adversarial_unrelated_table_not_absorbed():
    unrelated = "## Findings Summary\n\n| Row | Rule |\n|---|---|\n| 1 | x |\n"
    assert V._parse_obligation_table_receipts(unrelated, "opengrep_findings.md") == {}


# ===========================================================================
# GATE 16 - function_summary contract identity
# ===========================================================================

FUNCTION_SUMMARY = """# Function Summary

## Vault.sol

| Function | State Writes | External Calls |
|---|---|---|
| deposit | `balances[msg.sender]` | `token.transferFrom` |
"""


@pytest.mark.parametrize(
    "heading",
    ["## Vault.sol", "## `Vault.sol`", "## Vault.sol - core vault", "### Vault.sol",
     "## **Vault.sol**"],
)
def test_function_summary_contract_heading_is_an_identity(tmp_path, heading):
    _write(
        tmp_path,
        "function_summary.md",
        FUNCTION_SUMMARY.replace("## Vault.sol", heading),
    )
    rows = V._parse_function_summary_rows(tmp_path)
    assert rows and rows[0]["contract"].startswith("Vault.sol"), rows


def test_function_summary_adversarial_non_source_heading_is_not_a_contract(tmp_path):
    _write(
        tmp_path,
        "function_summary.md",
        FUNCTION_SUMMARY.replace("## Vault.sol", "## Overview"),
    )
    rows = V._parse_function_summary_rows(tmp_path)
    assert rows and rows[0]["contract"] != "Overview"


# ===========================================================================
# GATE 17 - step execution trace (ONE extractor, not two)
# ===========================================================================

def test_step_trace_baseline_on_real_worker_bytes():
    assert V._embedded_step_trace_table(RUN48_DEPTH_FINDING) is not None
    assert V._step_trace_table_lines_anywhere(RUN48_DEPTH_FINDING) is not None


@pytest.mark.parametrize(
    "mutation",
    [
        lambda t: t.replace("## Step Execution Trace", "## Step Execution Trace (skills)"),
        lambda t: t.replace("## Step Execution Trace", "### Step Execution Trace"),
        lambda t: t.replace("| Skill | Step | Executed | Evidence | Result |",
                            "| Skill | Step | Done | Evidence | Result |"),
        lambda t: t.replace("| Skill | Step | Executed | Evidence | Result |",
                            "| Skill | Step | Executed | Evidence | Result | Notes |")
                   .replace("|-------|------|----------|----------|--------|",
                            "|-------|------|----------|----------|--------|-------|"),
    ],
)
def test_step_trace_extractors_agree_under_presentation(mutation):
    """METAMORPHIC: the two extractors used to DISAGREE on identical bytes."""
    mutated = mutation(RUN48_DEPTH_FINDING)
    embedded = V._embedded_step_trace_table(mutated)
    anywhere = V._step_trace_table_lines_anywhere(mutated)
    assert embedded is not None, "embedded extractor lost the trace"
    assert anywhere is not None, "anywhere extractor lost the trace"
    assert embedded[0] == anywhere


def test_step_trace_adversarial_absent_table_is_none():
    stripped = "\n".join(
        line for line in RUN48_DEPTH_FINDING.splitlines()
        if "Skill" not in line and "DEPTH_ROLE_TOKEN_FLOW" not in line
    )
    assert V._embedded_step_trace_table(stripped) is None


def test_step_trace_adversarial_fenced_quotation_is_not_the_table():
    fenced = RUN48_DEPTH_FINDING.replace(
        "## Step Execution Trace",
        "```\n| Skill | Step | Executed | Evidence | Result |\n```\n\n## Step Execution Trace",
    )
    embedded = V._embedded_step_trace_table(fenced)
    assert embedded is not None


# ===========================================================================
# GATE 19 - verify-file identity resolution
# ===========================================================================

VERIFY_BODY = "# verify\n\n**Verdict**: CONFIRMED\n" + ("x" * 200) + "\n"


@pytest.mark.parametrize(
    "filename",
    [
        "verify_INV-001.md", "verify_F-INV-001.md", "verify_F_INV-001.md",
        "verify_[INV-001].md", "verify_inv-001.md", "verify_INV001.md",
        "verify_INV-1.md", "verify-INV-001.md", "verify_INV-001_final.md",
    ],
)
def test_verify_file_identity_is_not_filename_punctuation(tmp_path, filename):
    """METAMORPHIC: nine spellings of one verifier output, one identity."""
    _write(tmp_path, filename, VERIFY_BODY)
    assert V._verify_file_present_for_id(tmp_path, "INV-001")


def test_verify_file_adversarial_different_identity_does_not_satisfy(tmp_path):
    """ADVERSARIAL: another finding's verify file is NOT this one's."""
    _write(tmp_path, "verify_INV-002.md", VERIFY_BODY)
    _write(tmp_path, "verify_OTHER-999.md", VERIFY_BODY)
    assert not V._verify_file_present_for_id(tmp_path, "INV-001")


def test_verify_file_adversarial_prefix_collision_is_not_a_match(tmp_path):
    _write(tmp_path, "verify_INV-10.md", VERIFY_BODY)
    assert not V._verify_file_present_for_id(tmp_path, "INV-1")


# ===========================================================================
# GATE 20 - chain severity-upgrade justification (SEVERITY, fail-closed)
# ===========================================================================

CHAIN_JUSTIFIED = (
    "Constituents: A-1,B-2 | Severity-Upgrade-Justified: YES | "
    "Combined-Impact: the pair drains the whole pool in one transaction\n"
)


def test_chain_justification_baseline():
    assert V._chain_upgrade_justified_tolerant(CHAIN_JUSTIFIED)


@pytest.mark.parametrize(
    "section",
    [
        "Constituents: A-1,B-2 | **Severity-Upgrade-Justified**: YES | "
        "**Combined-Impact**: the pair drains the whole pool\n",
        "Constituents: A-1,B-2 | Combined-Impact: the pair drains the whole pool | "
        "Severity-Upgrade-Justified: YES\n",
        "| Field | Value |\n|---|---|\n| Severity-Upgrade-Justified | YES |\n"
        "| Combined-Impact | the pair drains the whole pool |\n",
        "Severity-Upgrade-Justified: `YES`\nCombined-Impact: the pair drains the pool\n",
    ],
)
def test_chain_justification_is_not_representation_bound(section):
    """METAMORPHIC: four measured renderings preserve one compound finding."""
    assert V._chain_upgrade_justified_tolerant(section)


@pytest.mark.parametrize(
    "section",
    [
        "Constituents: A-1,B-2 | Severity-Upgrade-Justified: NO | Combined-Impact: NONE\n",
        "Constituents: A-1,B-2 | Severity-Upgrade-Justified: YES | Combined-Impact: NONE\n",
        "Constituents: A-1,B-2 | Severity-Upgrade-Justified: YES | Combined-Impact: \n",
        "Constituents: A-1,B-2\n",
    ],
)
def test_chain_justification_adversarial_unjustified_still_false(section):
    """ADVERSARIAL: the gate can only PRESERVE, never invent, an upgrade."""
    assert not V._chain_upgrade_justified_tolerant(section)


# ===========================================================================
# GATE 21 - depth iteration counters (was failing OPEN)
# ===========================================================================

LOOP_LOG_VIOLATION = """# Adaptive Loop Log

{iterations}
{uncertain}
"""


@pytest.mark.parametrize(
    "iterations,uncertain",
    [
        ("Iterations: 1", "Iter 1 uncertain Medium+: 3"),
        ("**Iterations**: 1", "Iter 1 uncertain Medium+: 3"),
        ("Iterations completed: 1", "Iter 1 uncertain Medium+: 3"),
        ("Iterations: 1", "**Iter 1 uncertain Medium+**: 3"),
        ("| Iterations | 1 |", "| iter1_uncertain_medium_plus | 3 |"),
    ],
)
def test_depth_iteration_violation_is_detected_in_every_rendering(
    tmp_path, iterations, uncertain
):
    """METAMORPHIC on a FAIL-OPEN gate: bolding the label disabled it."""
    _write(
        tmp_path,
        "adaptive_loop_log.md",
        LOOP_LOG_VIOLATION.format(iterations=iterations, uncertain=uncertain),
    )
    issues = V._validate_depth_iterations(tmp_path, "thorough")
    assert issues and "iter >= 2" in issues[0], (iterations, uncertain, issues)


def test_depth_iteration_adversarial_compliant_log_is_clean(tmp_path):
    _write(
        tmp_path,
        "adaptive_loop_log.md",
        LOOP_LOG_VIOLATION.format(
            iterations="**Iterations**: 3", uncertain="**Iter 1 uncertain Medium+**: 3"
        ),
    )
    assert V._validate_depth_iterations(tmp_path, "thorough") == []


# ===========================================================================
# GATE 22/23 - PoC ledger fields
# ===========================================================================

@pytest.mark.parametrize(
    "line",
    [
        "PoC Not Attempted Because: NO_BUILD_ENVIRONMENT",
        "PoC Not Attempted Because: **NO_BUILD_ENVIRONMENT**",
        "PoC Not Attempted Because: there is NO_BUILD_ENVIRONMENT in this container",
        "Skip Reason: NO_BUILD_ENVIRONMENT",
        "| PoC Not Attempted Because | NO_BUILD_ENVIRONMENT |",
    ],
)
def test_poc_skip_code_reads_the_taxonomy_wherever_it_is_stated(line):
    assert V._poc_skip_code("### PoC Attempt\n" + line + "\n") == "NO_BUILD_ENVIRONMENT"


def test_poc_skip_code_adversarial_no_taxonomy_code_is_empty():
    assert V._poc_skip_code(
        "PoC Not Attempted Because: we simply did not feel like it\n"
    ) == ""


def test_poc_skip_code_adversarial_negated_code_is_not_a_code():
    assert V._poc_skip_code(
        "PoC Not Attempted Because: this is not NO_BUILD_ENVIRONMENT\n"
    ) == ""


@pytest.mark.parametrize(
    "rendering",
    ["Attempted: YES", "- Attempted: **YES**", "| Attempted | YES |",
     "**PoC Attempted**: YES"],
)
def test_poc_attempted_is_read_by_meaning(rendering):
    assert V._poc_attempted_value("### PoC Attempt\n" + rendering + "\n") == "YES"


def test_poc_attempted_adversarial_no_is_still_no():
    assert V._poc_attempted_value("- Attempted: **NO**\n") == "NO"
    assert V._poc_attempted_value("### PoC Attempt\nnothing here\n") == ""


def test_poc_passed_accepts_the_participle():
    assert V._poc_attempted_and_passed("- Attempted: YES\n- **Result**: PASSED\n")
    assert V._poc_attempted_and_passed("Attempted: YES\nResult: PASS\n")


def test_poc_passed_adversarial_failure_is_not_a_pass():
    assert not V._poc_attempted_and_passed("Attempted: YES\nResult: FAIL\n")
    assert not V._poc_attempted_and_passed("Attempted: NO\nResult: PASS\n")


# ===========================================================================
# GATE 24 - material harm (force-by-default PoC trigger)
# ===========================================================================

@pytest.mark.parametrize(
    "harm",
    [
        "Any depositor loses funds when the refund path overwrites the record.",
        "Any peer can permanently halt block production.",
        "Depositors receive 25-50% less than their pro-rata share.",
        "The owner can seize every user's collateral without consent.",
        "A user's withdrawal reverts forever after the parameter is zeroed.",
        "Cross-chain assets are routed to the wrong recipient.",
    ],
)
def test_material_harm_sees_the_projects_own_mandated_style(harm):
    """METAMORPHIC: four of these six were invisible to the measured list."""
    assert V._has_concrete_material_harm(f"**Material Harm**: {harm}\n")


def test_material_harm_adversarial_pure_quality_is_not_harm():
    assert not V._has_concrete_material_harm(
        "**Material Harm**: The variable name is inconsistent with the docs.\n"
    )


# ===========================================================================
# GATE 25 - PDE section
# ===========================================================================

PDE = """# Niche: Semantic Consistency

## Pre-Commit Dimension Enumeration

| Dimension | Enumerated |
|---|---|
| sibling | yes |
"""


@pytest.mark.parametrize(
    "heading",
    [
        "## Pre-Commit Dimension Enumeration",
        "### Pre-Commit Dimension Enumeration",
        "## Pre Commit Dimension Enumeration",
        "## PreCommit Dimension Enumeration",
        "## Dimension Enumeration (Pre-Commit)",
    ],
)
def test_pde_section_is_located_by_meaning(tmp_path, heading):
    _write(
        tmp_path,
        "niche_semantic_consistency_findings.md",
        PDE.replace("## Pre-Commit Dimension Enumeration", heading),
    )
    assert V._check_pde_section_present(tmp_path) == []


def test_pde_adversarial_absent_section_still_reported(tmp_path):
    _write(tmp_path, "niche_semantic_consistency_findings.md", "# nothing\n")
    assert V._check_pde_section_present(tmp_path)


# ===========================================================================
# GATE 26 - dedup decision dispositions (DEDUP, fail-closed)
# ===========================================================================

DEDUP_DECISIONS = """# Dedup Agent Decisions

## Merge Decisions

| Survivor | Absorbed | Same Root Cause |
|---|---|---|
| H-01 | H-07 | yes |

## Kept Separate

| Report IDs | Reason |
|---|---|
| M-02, M-05 | different fixes |
"""


def test_dedup_dispositions_baseline(tmp_path):
    _write(tmp_path, "report_dedup_agent_decisions.md", DEDUP_DECISIONS)
    dispositions, issues = V._report_dedup_decision_dispositions(tmp_path)
    assert dispositions, issues


@pytest.mark.parametrize(
    "mutation",
    [
        lambda t: t.replace("## Merge Decisions", "### Merge Decisions"),
        lambda t: t.replace("## Merge Decisions", "## Consolidations"),
        lambda t: t.replace("## Kept Separate", "#### Kept Separate"),
        lambda t: t.replace("## Merge Decisions", "## **Merge Decisions**"),
    ],
)
def test_dedup_section_heading_depth_is_presentation(tmp_path, mutation):
    """METAMORPHIC: an H3 arm silently discarded EVERY decision row."""
    _write(tmp_path, "report_dedup_agent_decisions.md", mutation(DEDUP_DECISIONS))
    dispositions, _issues = V._report_dedup_decision_dispositions(tmp_path)
    assert dispositions, "decision rows were discarded by heading depth"


def test_dedup_adversarial_unrelated_section_is_not_a_decision(tmp_path):
    _write(
        tmp_path,
        "report_dedup_agent_decisions.md",
        "# Dedup\n\n## Appendix\n\n| Survivor | Absorbed |\n|---|---|\n| H-01 | H-07 |\n",
    )
    dispositions, _issues = V._report_dedup_decision_dispositions(tmp_path)
    assert dispositions == {}


# ===========================================================================
# GATE 8 - attention repair queue binding (identity, normalized)
# ===========================================================================

SHA = "a" * 64


@pytest.mark.parametrize(
    "rendering",
    [
        f"QUEUE_BINDING_SHA256: {SHA}",
        f"QUEUE_BINDING_SHA256: {SHA}.",
        f"QUEUE_BINDING_SHA256: `{SHA}`",
        f"**QUEUE_BINDING_SHA256**: {SHA}",
        f"| QUEUE_BINDING_SHA256 | {SHA} |",
    ],
)
def test_queue_binding_sha_is_an_identity_not_a_line_shape(rendering):
    assert V._attention_queue_binding_value(rendering) == SHA


def test_queue_binding_adversarial_different_sha_is_different():
    assert V._attention_queue_binding_value(f"QUEUE_BINDING_SHA256: {'b' * 64}") != SHA
    assert V._attention_queue_binding_value("no binding here") == ""


# ===========================================================================
# GATE 18 - inventory chunk detail blocks
# ===========================================================================

INVENTORY_CHUNK = """# Findings Chunk

## Master Table

| Finding ID | Title | Severity |
|---|---|---|
| CC-1 | Refund replay | High |

## Per-Finding Detail

### Finding [CC-1]: Refund replay

**Source IDs**: DT-1
**Severity**: High
**Location**: `contracts/A.sol:L671`
**Preferred Tag**: CODE-TRACE
**Verdict**: CONFIRMED
**Description**: marker cleared after transfer
**Impact**: repeated payout
"""


@pytest.mark.parametrize(
    "mutation",
    [
        lambda t: t,
        lambda t: t.replace("### Finding [CC-1]:", "#### Finding [CC-1]:"),
        lambda t: t.replace("### Finding [CC-1]:", "### Finding CC-1:"),
        lambda t: t.replace("### Finding [CC-1]:", "### Finding `[CC-1]`:"),
        lambda t: t.replace("## Per-Finding Detail", "## Findings Detail"),
    ],
)
def test_inventory_chunk_shape_defects_never_halt(tmp_path, mutation):
    """The shape issues are `schema.detail_block` -> DEBT, never blocking."""
    _write(tmp_path, "findings_chunk1.md", mutation(INVENTORY_CHUNK))
    issues = V._validate_inventory_chunk_structure(tmp_path, "chunk1")
    assert not any("detail block" in i or "detail heading" in i for i in issues)


def test_inventory_chunk_detail_headings_are_identity(tmp_path):
    """METAMORPHIC: bracket punctuation and heading depth are presentation."""
    for mutated in (
        INVENTORY_CHUNK,
        INVENTORY_CHUNK.replace("### Finding [CC-1]:", "#### Finding [CC-1]:"),
        INVENTORY_CHUNK.replace("### Finding [CC-1]:", "### Finding CC-1:"),
    ):
        _write(tmp_path, "findings_chunk1.md", mutated)
        V._validate_inventory_chunk_structure(tmp_path, "chunk1")
        ledger = tmp_path / V._REPRESENTATION_DEBT_LEDGER
        text = ledger.read_text(encoding="utf-8") if ledger.exists() else ""
        assert "0 per-finding detail block" not in text
