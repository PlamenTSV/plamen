"""Force-by-default PoC gate (approved plan, Part A).

ROOT CAUSE: `_poc_contract_required` keyed the mandatory-PoC decision off the
finding's PoC CLASS (a pre-code-read LLM estimate / verifier self-declaration),
and that class is PROVEN-UNRELIABLE — the mechanical seed
`classify_poc_testability` defaults hard-to-classify findings to `structural`,
and empirically EVERY sampled lazy skip (a concrete testable harm self-declared
structural with no real blocker) rode that default straight past the gate.

Fix: a finding whose verify content asserts a CONCRETE material harm is FORCED
into a testable PoC class UNLESS a real, CLOSED, code-grounded blocker excuses
it (`_has_valid_skip_blocker`): FULLY_TRUSTED_DESIGN, DEPLOY_OR_TX_ORDERING,
EXTERNAL_DEP_NO_FORK, LIVE_ARTIFACT_REQUIRED, SPEC_DOCS_NO_STATE_DELTA, or a
REFUTED verdict.

All fixtures below are GENERIC/synthetic (no protocol, contract, or contest
proper nouns) — a semi-trusted HARVESTER role, a TTL/archival finding, a
fully-trusted UPGRADE authority, and a deploy-gap initialize race, per the
no-overfit rule.

Run: pytest scripts/test_poc_force_gate.py -v
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

import plamen_validators as V  # noqa: E402


# ===========================================================================
# Generic fixtures (4 validated anchor shapes, genericized)
# ===========================================================================

# (1) SEMI-TRUSTED DRAIN — concrete material harm, actor explicitly semi-
# trusted (NOT fully-trusted) -> no valid blocker -> FORCED. The semi-trust
# caveat and the harm assertion are separate sentences so the negation token
# in the first ("not fully-trusted") does not clause-scope over "drain" in
# the second (matches the shared `_negation_governs_keyword` clause model).
_SEMI_TRUSTED_DRAIN = (
    "**Verdict**: CONFIRMED\n"
    "**Material Harm**: The HARVESTER/PROXY role is semi-trusted, not "
    "fully-trusted, and acts within normal operational duties. Calling the "
    "harvest entry point early lets the caller drain the custodied token "
    "pool to its own address, so depositors permanently lose their "
    "principal.\n"
    "### PoC Attempt\n"
    "- PoC Required: NO\n"
    "- PoC Class: {poc_class}\n"
    "- Attempted: NO\n"
    "- PoC Not Attempted Because: STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION\n"
)

# (2) TTL/ARCHIVAL — concrete material harm (liveness brick via archival),
# skip reason is an environment excuse, NOT a valid blocker -> FORCED. The
# renewal caveat and the harm assertion are separate sentences for the same
# clause-scoping reason as above ("without renewal" must not shadow "brick").
_TTL_ARCHIVAL = (
    "**Verdict**: CONFIRMED\n"
    "**Material Harm**: The TTL window elapses without renewal. Once "
    "elapsed, the instance is silently archived and the user's position "
    "becomes an unreachable liveness brick that permanently halts the "
    "account.\n"
    "### PoC Attempt\n"
    "- PoC Required: NO\n"
    "- PoC Class: {poc_class}\n"
    "- Attempted: NO\n"
    "- PoC Not Attempted Because: STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION\n"
    "- Note: Env::default cannot model eviction, so no test was written.\n"
)

# (3) FULLY-TRUSTED UPGRADE — concrete material harm framed around a
# fully-trusted governance/upgrade authority acting within its granted powers,
# with absence-of-timelock/M-of-N being the only "defect" -> valid blocker
# (FULLY_TRUSTED_DESIGN) -> SKIP remains valid.
_FULLY_TRUSTED_UPGRADE = (
    "**Verdict**: CONFIRMED\n"
    "**Material Harm**: A fully-trusted UPGRADE/governance authority can "
    "brick the contract by pointing it at an incompatible implementation; "
    "there is an absence of timelock/M-of-N, and a PoC would only "
    "re-demonstrate that the upgrade authority can upgrade — the system "
    "works as designed.\n"
    "### PoC Attempt\n"
    "- PoC Required: NO\n"
    "- PoC Class: {poc_class}\n"
    "- Attempted: NO\n"
    "- PoC Not Attempted Because: STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION\n"
)

# (4) DEPLOY-GAP RACE — concrete material harm via an initialize front-run in
# the gap between deployment and the deployer's initialize call -> valid
# blocker (DEPLOY_OR_TX_ORDERING) -> SKIP remains valid.
_DEPLOY_GAP_RACE = (
    "**Verdict**: CONFIRMED\n"
    "**Material Harm**: An attacker calls initialize in the gap between "
    "deployment and the deployer's initialize call (a deploy-time front-run), "
    "seizing the owner role and locking out the legitimate deployer.\n"
    "### PoC Attempt\n"
    "- PoC Required: NO\n"
    "- PoC Class: {poc_class}\n"
    "- Attempted: NO\n"
    "- PoC Not Attempted Because: STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION\n"
)


def _row(fid: str, sev: str, poc_class: str) -> dict:
    return {"finding id": fid, "severity": sev, "poc class": poc_class}


# ===========================================================================
# Anchor 1 — SEMI-TRUSTED DRAIN: FORCED, no valid blocker
# ===========================================================================

def test_semi_trusted_drain_forced():
    content = _SEMI_TRUSTED_DRAIN.format(poc_class="structural")
    assert V._has_concrete_material_harm(content) is True
    assert V._has_fully_trusted_actor_blocker(content) is False
    assert V._has_valid_skip_blocker(content, "High") is False
    row = _row("H-01", "High", "structural")
    assert V._poc_contract_required(row, "thorough", content) is True
    assert V._effective_poc_class("structural", content) in {"unit", "property"}


def test_semi_trusted_drain_label_independent():
    # Same forced outcome regardless of the queue/declared class label.
    for declared in ("unit", "property", "structural"):
        content = _SEMI_TRUSTED_DRAIN.format(poc_class=declared)
        row = _row("H-01", "High", declared)
        assert V._poc_contract_required(row, "thorough", content) is True, declared


# ===========================================================================
# Anchor 2 — TTL/ARCHIVAL: FORCED, environment excuse is not a valid blocker
# ===========================================================================

def test_ttl_archival_forced():
    content = _TTL_ARCHIVAL.format(poc_class="structural")
    assert V._has_concrete_material_harm(content) is True
    assert V._has_valid_skip_blocker(content, "High") is False
    row = _row("H-06", "High", "structural")
    assert V._poc_contract_required(row, "thorough", content) is True


def test_ttl_archival_label_independent():
    for declared in ("unit", "property", "structural"):
        content = _TTL_ARCHIVAL.format(poc_class=declared)
        row = _row("H-06", "High", declared)
        assert V._poc_contract_required(row, "thorough", content) is True, declared


# ===========================================================================
# Anchor 3 — FULLY-TRUSTED prose: proposal-only -> PoC remains required
# ===========================================================================

def test_fully_trusted_upgrade_prose_has_no_skip_authority():
    content = _FULLY_TRUSTED_UPGRADE.format(poc_class="structural")
    assert V._has_concrete_material_harm(content) is True
    assert V._has_fully_trusted_actor_blocker(content) is False
    assert V._has_valid_skip_blocker(content, "High") is False
    row = _row("H-03", "High", "structural")
    assert V._poc_contract_required(row, "thorough", content) is True


def test_fully_trusted_upgrade_proposal_never_relaxes_any_label():
    for declared in ("unit", "property", "structural"):
        content = _FULLY_TRUSTED_UPGRADE.format(poc_class=declared)
        row = _row("H-03", "High", declared)
        # Neither a declared class nor a trust phrase can manufacture the typed
        # independent authority required to relax verification.
        assert V._poc_contract_required(row, "thorough", content) is True, declared


# ===========================================================================
# Anchor 4 — DEPLOY-GAP RACE: valid blocker -> SKIP remains valid
# ===========================================================================

def test_deploy_gap_race_skip_valid():
    content = _DEPLOY_GAP_RACE.format(poc_class="structural")
    assert V._has_concrete_material_harm(content) is True
    assert V._has_deploy_ordering_blocker(content) is True
    assert V._has_valid_skip_blocker(content, "High") is True
    row = _row("H-48", "High", "structural")
    assert V._poc_contract_required(row, "thorough", content) is False


def test_deploy_gap_race_label_independent():
    for declared in ("unit", "property", "structural"):
        content = _DEPLOY_GAP_RACE.format(poc_class=declared)
        row = _row("H-48", "High", declared)
        expected = declared in {"unit", "property"}
        assert V._poc_contract_required(row, "thorough", content) is expected, declared


# ===========================================================================
# Hard invariant: default force regardless of severity-eligible tiers
# ===========================================================================

def test_default_force_regardless_of_declared_class():
    content = _SEMI_TRUSTED_DRAIN.format(poc_class="structural")
    for declared in ("unit", "property", "structural", "integration", "spec", "docs"):
        row = _row("H-77", "Medium", declared)
        assert V._poc_contract_required(row, "core", content) is True, declared


def test_skip_taxonomy_rejects_raw_trust_and_keeps_other_blockers():
    # FULLY_TRUSTED_DESIGN prose is proposal-only; the P0-H suite separately
    # covers the valid typed-authority path.
    assert V._has_valid_skip_blocker(
        _FULLY_TRUSTED_UPGRADE.format(poc_class="structural"), "High"
    ) is False
    # DEPLOY_OR_TX_ORDERING
    assert V._has_valid_skip_blocker(
        _DEPLOY_GAP_RACE.format(poc_class="structural"), "High"
    ) is True
    # EXTERNAL_DEP_NO_FORK (no reachable RPC in this env -> valid blocker)
    ext_content = (
        "**Material Harm**: A misbehaving integration drains funds to the "
        "wrong recipient. The deployed contract address is "
        "0x1234567890abcdef1234567890abcdef12345678 and is live on mainnet.\n"
    )
    assert V._has_valid_skip_blocker(ext_content, "High") is True
    # LIVE_ARTIFACT_REQUIRED
    live_artifact_content = (
        "**Material Harm**: The attacker steals funds, but this requires "
        "deploying a malicious attacker-controlled contract as a second "
        "deployment to trigger the callback.\n"
    )
    assert V._has_valid_skip_blocker(live_artifact_content, "High") is True
    # SPEC_DOCS_NO_STATE_DELTA (no concrete material harm at all)
    spec_content = (
        "**Material Harm**: The NatSpec comment says 'returns the fee' but "
        "the function is named getRate(); this is a naming/documentation "
        "mismatch only.\n"
    )
    assert V._has_valid_skip_blocker(spec_content, "Low") is True
    # REFUTED
    refuted_content = (
        "**Verdict**: REFUTED\n"
        "**Material Harm**: The harvester would drain the custodied pool, "
        "but the guard already prevents this path.\n"
    )
    assert V._has_valid_skip_blocker(refuted_content, "High") is True


def test_bare_internal_fund_loss_is_not_an_external_dependency_blocker():
    """A material-harm phrase alone cannot manufacture external provenance.

    This is the discriminator boundary: otherwise any ordinary in-scope loss
    of funds is silently excused whenever no fork RPC is configured.
    """
    content = (
        "**Verdict**: CONFIRMED\n"
        "**Material Harm**: The internal accounting path causes loss of funds "
        "for depositors.\n"
        "### PoC Attempt\n"
        "- Attempted: NO\n"
        "- PoC Not Attempted Because: "
        "EXTERNAL_DEPENDENCY_NO_FORK_OR_ADDRESS\n"
    )
    assert V._matches_external_integration_harm(content) is True
    assert V._has_external_integration_provenance(content) is False
    assert V._has_valid_skip_blocker(content, "High") is False


def test_external_dependency_blocker_requires_harm_and_external_provenance():
    content = (
        "**Verdict**: CONFIRMED\n"
        "**Material Harm**: An untrusted external integration returns a "
        "recipient that misroutes funds to the wrong destination.\n"
        "### PoC Attempt\n"
        "- Attempted: NO\n"
        "- PoC Not Attempted Because: "
        "EXTERNAL_DEPENDENCY_NO_FORK_OR_ADDRESS\n"
    )
    assert V._matches_external_integration_harm(content) is True
    assert V._has_external_integration_provenance(content) is True
    assert V._has_valid_skip_blocker(content, "High") is True

    provenance_without_harm = (
        "**Verdict**: CONFIRMED\n"
        "The path invokes an external integration, but no material state or "
        "fund delta is asserted.\n"
    )
    assert V._has_external_integration_provenance(provenance_without_harm) is True
    assert V._matches_external_integration_harm(provenance_without_harm) is False


# ===========================================================================
# No-demote floor (Edit 5): a forced [POC-FAIL] without a harm-asserting
# ledger must NOT demote severity — falls back to CODE-TRACE at baseline.
# ===========================================================================

def _queue(scratchpad: Path, fid: str, sev: str, poc_class: str) -> None:
    (scratchpad / "verification_queue.md").write_text(
        "| Finding ID | Severity | Title | Location | PoC Class |\n"
        "|---|---|---|---|---|\n"
        f"| {fid} | {sev} | t | F.sol:1 | {poc_class} |\n",
        encoding="utf-8",
    )


def test_no_demote_forced_poc_fail_without_harm_assertion(tmp_path):
    # A forced attempt where the ledger shows Attempted: NO (or an explicit
    # no-executable-harm-assertion disposition) despite carrying a bare
    # [POC-FAIL] evidence tag elsewhere in the file -- Impact-Premise unmet,
    # must NOT demote.
    fid = "H-90"
    _queue(tmp_path, fid, "High", "property")
    (tmp_path / f"verify_{fid}.md").write_text(
        "**Verdict**: REFUTED\n"
        "**Material Harm**: The harvester drains the custodied pool.\n"
        "### PoC Attempt\n"
        "- Attempted: NO\n"
        "- PoC Not Attempted Because: NO_BUILD_ENVIRONMENT\n"
        "### Execution Result\n"
        "- Result: NOT_EXECUTED\n"
        "- Evidence Tag: [POC-FAIL]\n",
        encoding="utf-8",
    )
    demotions = V._apply_poc_fail_demotions(tmp_path, "thorough")
    assert demotions == [], (
        "a [POC-FAIL] with Attempted: NO (no harm-asserting test ran) must "
        "NOT demote — Impact-Premise unmet, falls back to CODE-TRACE baseline"
    )


def test_prose_claim_that_harm_was_tested_cannot_self_authorize_demotion(tmp_path):
    # P1-E: Attempted/Result prose proves neither oracle provenance nor
    # exhaustive negative scope.  Without the candidate-bound runtime
    # assessment, preserve severity and create explicit re-verification debt.
    fid = "H-91"
    _queue(tmp_path, fid, "High", "unit")
    (tmp_path / f"verify_{fid}.md").write_text(
        "**Verdict**: REFUTED\n"
        "**Material Harm**: The harvester drains the custodied pool.\n"
        "### PoC Attempt\n"
        "- Attempted: YES\n"
        "### Execution Result\n"
        "- Result: FAIL (balance unchanged; guard blocked the drain)\n"
        "- Evidence Tag: [POC-FAIL]\n",
        encoding="utf-8",
    )
    demotions = V._apply_poc_fail_demotions(tmp_path, "thorough")
    assert demotions == []
    debt = json.loads(
        (tmp_path / "execution_scope_reverification.json").read_text(
            encoding="utf-8"
        )
    )
    assert debt["candidates"][0]["candidate_id"] == fid
    assert debt["candidates"][0]["severity_preserved"] == "High"


def test_no_demote_helper_direct():
    # Direct unit coverage of the helper itself.
    no_attempt = (
        "### PoC Attempt\n- Attempted: NO\n"
        "- PoC Not Attempted Because: STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION\n"
    )
    assert V._poc_fail_asserts_harm(no_attempt, no_attempt) is False
    ran_and_failed = (
        "### PoC Attempt\n- Attempted: YES\n"
        "### Execution Result\n- Result: FAIL (state unchanged)\n"
    )
    assert V._poc_fail_asserts_harm(ran_and_failed, ran_and_failed) is True


# ===========================================================================
# Non-regression: default (no-new-arg) call paths are unaffected
# ===========================================================================

def test_effective_poc_class_default_signature_unaffected():
    assert V._effective_poc_class("structural") == "structural"
    assert V._effective_poc_class("unit", None) == "unit"


def test_poc_contract_required_default_signature_unaffected():
    row = {"poc class": "structural", "severity": "Low", "finding id": "X-1"}
    assert V._poc_contract_required(row, "thorough") is False


# ===========================================================================
# Regression: a negated PoC-LEDGER phrase must not suppress a POSITIVE harm
# ("No fund-drain assertion attempted" can make a negation-aware guard suppress
# positive "drain ... is achievable" mentions and misclassify material harm).
# ===========================================================================

def test_negated_ledger_phrase_does_not_suppress_positive_harm():
    content = (
        "**Severity**: High — realized via a semi-trusted OPERATOR role.\n"
        "A caller-supplied selector on a direct dispatch enables drain of a "
        "custodied asset; an authorization condition is auto-satisfied so the "
        "custodied balance drains.\n"
        "### PoC Attempt\n- Attempted: NO\n"
        "- PoC Not Attempted Because: STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION\n"
        "No fund-drain assertion is disputable by a single harness.\n"
    )
    # The positive harm ("drains") must register despite the negated ledger line.
    assert V._has_concrete_material_harm(content) is True
    # Semi-trusted actor -> FULLY_TRUSTED_DESIGN must NOT excuse it -> no blocker.
    assert V._has_valid_skip_blocker(content) is False
    row = {"poc class": "structural", "severity": "High", "finding id": "X-1"}
    assert V._poc_contract_required(row, "thorough", content) is True


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
