"""CI tests: prompt files must name every label / heading / token
their corresponding validators check for.

Regression guard against the inventory-Description bug class — where
a validator silently enforces a schema (8 required `**Field**:` labels
per per-finding detail block) but the prompt never tells the LLM what
the schema is, so the LLM improvises and ~30% of findings drift.

These tests are CHEAP — they only read prompt files and grep for
substrings. They run in <1 second and catch the next time someone
adds a validator requirement without updating the prompt (or vice
versa).

Run: `pytest scripts/test_prompt_validator_alignment.py -v`
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

_HERE = Path(__file__).resolve().parent
_REPO = _HERE.parent
for p in (_HERE, _REPO):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))


def _read(rel_path: str) -> str:
    """Read a file relative to repo root; return empty string if missing
    so individual tests show the right failure rather than ImportError."""
    p = _REPO / rel_path
    if not p.is_file():
        return ""
    return p.read_text(encoding="utf-8", errors="replace")


# ---------------------------------------------------------------------------
# SC inventory: 8 required per-finding-detail field labels (commit 5653b1b)
# Validator: scripts/plamen_validators.py:_validate_inventory_chunk_structure
# ---------------------------------------------------------------------------

_REQUIRED_INVENTORY_FIELDS = [
    "Source IDs",
    "Severity",
    "Location",
    "Preferred Tag",
    "Verdict",
    "Root Cause",
    "Description",
    "Impact",
]

_SC_INVENTORY_PROMPTS = [
    "prompts/evm/phase4a-inventory-prompt.md",
    "prompts/aptos/phase4a-inventory-prompt.md",
    "prompts/solana/phase4a-inventory-prompt.md",
    "prompts/soroban/phase4a-inventory-prompt.md",
    "prompts/sui/phase4a-inventory-prompt.md",
]


@pytest.mark.parametrize("prompt_path", _SC_INVENTORY_PROMPTS)
@pytest.mark.parametrize("field", _REQUIRED_INVENTORY_FIELDS)
def test_sc_inventory_prompt_names_required_field(prompt_path, field):
    """Each SC inventory prompt must name every required field label
    that `_validate_inventory_chunk_structure` checks for, so the LLM
    sees the schema before writing."""
    text = _read(prompt_path)
    assert text, f"prompt missing: {prompt_path}"
    label = f"**{field}**"
    assert label in text, (
        f"{prompt_path} missing required field label `{label}` — "
        f"validator silently enforces this; prompt must teach it"
    )


@pytest.mark.parametrize("prompt_path", _SC_INVENTORY_PROMPTS)
def test_sc_inventory_prompt_has_per_finding_block(prompt_path):
    """Each SC inventory prompt must have a Per-Finding Detail block
    section (the validator parses `### Finding [<ID>]:` headings out
    of this section)."""
    text = _read(prompt_path)
    assert "Per-Finding Detail blocks" in text or "## Per-Finding Detail" in text, (
        f"{prompt_path} missing Per-Finding Detail section schema"
    )


# ---------------------------------------------------------------------------
# L1 inventory: Source IDs label (commit 0fb7fd0, Row 2)
# Validator: scripts/plamen_parsers.py:_inventory_blocks line 4668
# ---------------------------------------------------------------------------


def test_l1_inventory_uses_source_ids_label():
    """L1 v2 inventory's per-finding template must emit `**Source IDs**`
    so the parser at plamen_parsers.py:4668 (which only aliases
    'Source IDs' / 'Source ID') populates the source_ids field.

    The original prompt used `**Source**:` + `**Original IDs**:` which
    neither alias matches → source_ids field came back empty for every
    L1 finding.
    """
    text = _read("prompts/l1/v2/phase4a-inventory-prompt.md")
    assert text, "L1 v2 inventory prompt missing"
    assert "**Source IDs**" in text, (
        "L1 v2 inventory template must emit `**Source IDs**:` — "
        "parser alias set is ('Source IDs', 'Source ID') only"
    )
    # Negative: the old labels should be gone
    assert "**Original IDs**" not in text, (
        "stale `**Original IDs**:` still in L1 inventory prompt — "
        "parser does not alias this label"
    )


# ---------------------------------------------------------------------------
# L1 recon: mandatory Key Invariants + Operational Implications sections
# (commit 5653b1b, Row 3)
# Validator: scripts/plamen_validators.py:_validate_recon_content_structure
# ---------------------------------------------------------------------------


def test_l1_recon_mandates_key_invariants_section():
    text = _read("prompts/l1/v2/phase1-recon-prompt.md")
    assert text, "L1 v2 recon prompt missing"
    assert "Key Invariants" in text, (
        "L1 v2 recon prompt must instruct the LLM to write a "
        "`## Key Invariants` section in design_context.md — "
        "validator hard-fails when absent"
    )


def test_l1_recon_mandates_operational_implications_section():
    text = _read("prompts/l1/v2/phase1-recon-prompt.md")
    assert "Operational Implications" in text, (
        "L1 v2 recon prompt must instruct the LLM to write a "
        "`## Operational Implications` section in design_context.md — "
        "validator hard-fails when absent"
    )


def test_l1_recon_mandates_section_is_present_in_a_directive_block():
    """The mention must appear inside a MANDATORY directive context,
    not just incidentally in passing prose."""
    text = _read("prompts/l1/v2/phase1-recon-prompt.md")
    # Look for the section heading literally in a markdown template — should
    # appear with `## Key Invariants` formatting (the validator regex matches
    # `^##\s+Key Invariants` headings).
    assert "## Key Invariants" in text, (
        "L1 v2 recon must show `## Key Invariants` as a literal markdown "
        "heading in the design_context.md template — not just mention "
        "the words in prose"
    )
    assert "## Operational Implications" in text, (
        "L1 v2 recon must show `## Operational Implications` as a literal "
        "markdown heading in the design_context.md template"
    )


# ---------------------------------------------------------------------------
# Non-EVM verify: PoC ledger schema (commit 0fb7fd0, Row 5)
# Validator: scripts/plamen_validators.py:_validate_poc_attempt_coverage
# ---------------------------------------------------------------------------

_NON_EVM_VERIFY_PROMPTS = [
    "prompts/solana/phase5-verification-prompt.md",
    "prompts/aptos/phase5-verification-prompt.md",
    "prompts/sui/phase5-verification-prompt.md",
    "prompts/soroban/phase5-verification-prompt.md",
]

_POC_LEDGER_FIELDS = [
    "PoC Required",
    "PoC Class",
    "Attempted",
    "PoC Not Attempted Because",
    "Test File",
    "Command",
]


@pytest.mark.parametrize("prompt_path", _NON_EVM_VERIFY_PROMPTS)
@pytest.mark.parametrize("field", _POC_LEDGER_FIELDS)
def test_non_evm_verify_prompt_names_poc_ledger_field(prompt_path, field):
    """Every non-EVM verify prompt must name every PoC ledger field
    the validator checks for. EVM + L1 already had the schema; the 4
    non-EVM chains did not before commit 0fb7fd0."""
    text = _read(prompt_path)
    assert text, f"prompt missing: {prompt_path}"
    assert field in text, (
        f"{prompt_path} missing PoC ledger field `{field}` — "
        f"_validate_poc_attempt_coverage soft-warns when absent"
    )


@pytest.mark.parametrize("prompt_path", _NON_EVM_VERIFY_PROMPTS)
def test_non_evm_verify_prompt_has_poc_attempt_block(prompt_path):
    text = _read(prompt_path)
    assert "### PoC Attempt" in text, (
        f"{prompt_path} missing `### PoC Attempt` block — "
        f"verify outputs cannot satisfy ledger contract"
    )


@pytest.mark.parametrize("prompt_path", _NON_EVM_VERIFY_PROMPTS)
def test_non_evm_verify_prompt_lists_allowed_skip_reasons(prompt_path):
    """Allowed skip-reason codes must be enumerated so the LLM picks
    from a known set rather than inventing a free-text reason that
    would fail validator parsing."""
    text = _read(prompt_path)
    for code in (
        "NO_BUILD_ENVIRONMENT",
        "EXTERNAL_DEPENDENCY_NO_FORK_OR_ADDRESS",
        "DEPLOYMENT_ONLY_REQUIRES_LIVE_EXTERNAL",
        "PURE_SPEC_OR_DOCS_ONLY",
        "STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION",
    ):
        assert code in text, (
            f"{prompt_path} missing skip-reason code `{code}` "
            f"in PoC ledger schema"
        )


# ---------------------------------------------------------------------------
# Finding format: Preferred Tag alias documentation (commit f9f38e5, Row 4)
# Parser: scripts/plamen_parsers.py:_parse_depth_finding_blocks line 3272
# ---------------------------------------------------------------------------


def test_finding_format_documents_preferred_tag_alias():
    """`rules/finding-output-format.md` must document `Preferred Tag`
    as a finding-block label so depth agents know which tag the
    verifier-side parser actually consumes."""
    text = _read("rules/finding-output-format.md")
    assert text, "rules/finding-output-format.md missing"
    assert "Preferred Tag" in text, (
        "finding-output-format must document `**Preferred Tag**:` — "
        "_parse_depth_finding_blocks accepts this alias and it's the "
        "primary label the verifier-side queue uses"
    )


# ---------------------------------------------------------------------------
# Tier writer: REPORT-BLOCKED tag legend (commit f9f38e5, Row 7)
# Validator: scripts/plamen_validators.py:_validate_report_body
# ---------------------------------------------------------------------------


def test_tier_writer_legend_includes_report_blocked():
    text = _read("prompts/shared/v2/phase6b-tier-writers.md")
    assert text, "phase6b-tier-writers prompt missing"
    # Must appear in the verification status tags legend table
    assert "[REPORT-BLOCKED]" in text or "REPORT-BLOCKED" in text, (
        "tier-writer legend must list `[REPORT-BLOCKED]` — "
        "_validate_report_body accepts this tag when the manifest "
        "marks the finding report_blocked=true"
    )


# ---------------------------------------------------------------------------
# Graph sweeps: per-sweep content tokens (commit 0fb7fd0, Row 6)
# Validator: scripts/plamen_validators.py:_validate_graph_sweeps
# ---------------------------------------------------------------------------


def test_graph_sweeps_directive_lists_network_amplification_tokens():
    """`_build_graph_sweeps_artifact_directive` must include the 6
    required tokens (ingress / dedup / validation / egress / verdict /
    evidence) when network_amplification sweep is relevant.

    We can't read the runtime-rendered directive here, but the source
    function must reference all 6 tokens so the rendered prompt
    eventually contains them.
    """
    src = _read("scripts/plamen_prompt.py")
    # Check the function emits each token in its content schema lines.
    # Tolerance for any case / quotation:
    for token in ("ingress", "dedup", "validation", "egress", "verdict", "evidence"):
        assert token in src.lower(), (
            f"_build_graph_sweeps_artifact_directive must reference "
            f"`{token}` token — validator soft-warns when missing"
        )


def test_graph_sweeps_directive_lists_lifecycle_replay_tokens():
    src = _read("scripts/plamen_prompt.py")
    for token in ("insert", "consume", "evict", "replay"):
        assert token in src.lower(), (
            f"_build_graph_sweeps_artifact_directive must reference "
            f"`{token}` token — validator soft-warns when missing"
        )


# ---------------------------------------------------------------------------
# Cross-cutting: every required field in finding-output-format.md is
# either parseable by depth parser or documented as alias-only.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# M1/M2 (recall-build-plan §5.3): the new/edited prompts must pass the mechanical
# prompt-gate consistency checker — no unknown `.md` filename tokens, and the
# example_tokens carry finding-ID shapes (or nothing), never numeric shard tokens.
# Checker: scripts/plamen_prompt.py:_check_prompt_name_consistency
# ---------------------------------------------------------------------------

import importlib  # noqa: E402


def _phase_by_name(name: str):
    pt = importlib.import_module("plamen_types")
    for lst in (pt.SC_PHASES, pt.L1_PHASES):
        for p in lst:
            if p.name == name:
                return p
    return None


def test_axis_coverage_prompt_passes_consistency_checker():
    """M2's new deriver-worker prompt (phase4b8-axis-coverage.md) must produce
    ZERO unknown filename tokens against the axis_coverage Phase + the legitimate
    subproducer allowlist. hot_function_axes.md (driver-written matrix) and
    axis_coverage_findings.md must be recognized."""
    pp = importlib.import_module("plamen_prompt")
    ph = _phase_by_name("axis_coverage")
    assert ph is not None, "axis_coverage phase not registered"
    text = _read("prompts/shared/v2/phase4b8-axis-coverage.md")
    assert text, "phase4b8-axis-coverage.md prompt missing"
    unknowns = pp._check_prompt_name_consistency(text, ph)
    assert unknowns == [], (
        f"axis_coverage prompt has unrecognized filename tokens: {unknowns} — "
        "add them to _LEGITIMATE_SUBPRODUCER_PATTERNS or the phase artifacts"
    )


def test_axis_coverage_example_tokens_not_numeric_shards():
    """example_tokens must be finding-ID / role shapes, never numeric shard
    tokens (`a`, `b`, `1`, `2`) that would mislead the filename generator."""
    ph = _phase_by_name("axis_coverage")
    assert ph is not None
    for tok in (getattr(ph, "example_tokens", []) or []):
        assert not str(tok).strip().isdigit(), (
            f"axis_coverage example_token {tok!r} is a numeric shard token"
        )
        assert str(tok).strip().lower() not in {"a", "b", "c"}, (
            f"axis_coverage example_token {tok!r} is a shard-letter token"
        )


def test_m1_edited_skeptic_prompts_pass_consistency_checker():
    """M1's committed-invariant [CI-n] hooks were added to the exploration-skeptic
    (4b.6) and skeptic (5.1) prompts. Neither may introduce an unknown filename
    token — the CI blocks reference no new `.md` artifacts."""
    pp = importlib.import_module("plamen_prompt")
    for phname, rel in (
        ("exploration_skeptic", "prompts/shared/v2/phase4b6-exploration-skeptic.md"),
        ("skeptic", "prompts/shared/v2/phase5-skeptic.md"),
    ):
        ph = _phase_by_name(phname)
        assert ph is not None, f"{phname} phase not registered"
        text = _read(rel)
        assert text, f"{rel} prompt missing"
        unknowns = pp._check_prompt_name_consistency(text, ph)
        assert unknowns == [], (
            f"{rel} introduced unrecognized filename tokens after M1 edit: "
            f"{unknowns}"
        )


def test_m1_ci_block_present_in_skeptic_prompts():
    """Positive lock: the committed-invariant [CI-n] emission hook is actually
    present in both skeptic-phase prompts (M1's emitter contract)."""
    for rel in (
        "prompts/shared/v2/phase4b6-exploration-skeptic.md",
        "prompts/shared/v2/phase5-skeptic.md",
    ):
        text = _read(rel)
        assert text, f"{rel} missing"
        assert "committed-invariant" in text and "CI-" in text, (
            f"{rel} missing the M1 committed-invariant [CI-n] emission hook"
        )


def test_late_verifier_ci_is_explicitly_next_run_not_current_run_verified():
    for rel in (
        "prompts/evm/phase5-verification-prompt.md",
        "prompts/shared/v2/phase5-verification-sc.md",
    ):
        text = _read(rel)
        assert "HUMAN_REVIEW_NEXT_RUN" in text
        assert "MUST NOT be claimed as current-run verified" in text
    evm = _read("prompts/evm/phase5-verification-prompt.md")
    assert "mechanically harvested downstream into falsifiable candidates" not in evm


def test_finding_format_evidence_label_consistency():
    """Both `**Evidence**:` (code snippets) and `**Depth Evidence**`
    (tag list) are documented — make sure neither was accidentally
    removed in a future edit."""
    text = _read("rules/finding-output-format.md")
    assert "**Evidence**" in text, (
        "finding-output-format must keep `**Evidence**: Code snippets` "
        "row — depth parser reads this as a fallback for Preferred Tag"
    )
    assert "**Depth Evidence**" in text, (
        "finding-output-format must keep `**Depth Evidence**` row — "
        "this is the tag-list field, separate from Preferred Tag"
    )
