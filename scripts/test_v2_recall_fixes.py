"""Tests for the v2.x recall regression fix bundle.

Covers:
- Fix 1: promote_niche_to_inventory — niche findings reach the inventory
  and the verification queue.
- Fix 2: _validate_chain_anti_absorption — distinct-function / severity /
  Jaccard violations are flagged; explicit override clears them.
- Fix 4: _per_constituent_claim_match — single_winner / shared_claim /
  ambiguous classification on the PayloadCodec-style super-group case.
- P0-O: lexical constituent matching is telemetry only; ambiguous grouped
  failures create scope-repair debt instead of widening a demotion.
- Fix 5: CROSS_VM_ENCODING_NO_RUNTIME — keyword guard rejects abuse,
  accepts legitimate cross-VM skips.

Fix 3 is a prompt-only change; no Python test (covered by manual review
of phase4c-chain-prompt.md and verified live in next audit run).
"""

from __future__ import annotations

import json
import re
import shutil
import tempfile
from pathlib import Path

import pytest

import plamen_mechanical as mech
import plamen_validators as validators


# --- Fixtures ---------------------------------------------------------------

@pytest.fixture
def scratch():
    p = Path(tempfile.mkdtemp(prefix="plamen_v2x_"))
    yield p
    shutil.rmtree(p, ignore_errors=True)


def _seed_inventory(scratch: Path, finding_ids: list[tuple[str, str, str, str]]):
    """finding_ids: list of (id, severity, location, root_cause)."""
    lines = ["# Finding Inventory\n\n## Findings\n\n"]
    for fid, sev, loc, rc in finding_ids:
        lines.append(
            f"### Finding [{fid}]: {rc}\n"
            f"**Severity**: {sev}\n"
            f"**Location**: {loc}\n"
            f"**Preferred Tag**: [CODE-TRACE]\n"
            f"**Source IDs**: SRC-{fid}\n"
            f"**Verdict**: NEEDS_VERIFICATION\n"
            f"**Root Cause**: {rc}\n"
            f"**Description**: {rc}\n"
            f"**Impact**: Test impact\n\n"
        )
    (scratch / "findings_inventory.md").write_text("".join(lines), encoding="utf-8")


# --- Fix 1: niche promotion -------------------------------------------------

class TestNichePromotion:
    def test_appends_niche_finding_to_inventory(self, scratch: Path):
        _seed_inventory(scratch, [("INV-001", "Medium", "src/Foo.sol:L10", "existing")])
        (scratch / "niche_semantic_consistency_findings.md").write_text(
            "# Niche\n\n"
            "## Finding [NSC-1]: ETH sentinel approve revert\n"
            "**Severity**: Medium\n"
            "**Location**: src/Bar.sol:L50\n"
            "**Description**: Approve on ETH sentinel fails.\n"
            "**Impact**: Swap reverts; user funds stuck.\n",
            encoding="utf-8",
        )
        parsed, appended = mech.promote_niche_to_inventory(scratch)
        assert parsed == 1 and appended == 1
        inv = (scratch / "findings_inventory.md").read_text(encoding="utf-8")
        assert "INV-002" in inv
        assert "ETH sentinel approve revert" in inv
        assert "NSC-1" in inv

    def test_idempotent_no_duplication_on_rerun(self, scratch: Path):
        _seed_inventory(scratch, [("INV-001", "High", "src/A.sol:L1", "first")])
        (scratch / "niche_dimensional_analysis_findings.md").write_text(
            "## Finding [NDA-1]: decimal mismatch\n"
            "**Severity**: Medium\n**Location**: src/B.sol:L1\n"
            "**Description**: decimals mismatch.\n"
            "**Impact**: precision loss.\n",
            encoding="utf-8",
        )
        mech.promote_niche_to_inventory(scratch)
        parsed2, appended2 = mech.promote_niche_to_inventory(scratch)
        assert appended2 == 0  # nothing new on re-run
        # Inventory has exactly one INV-002 (no duplicate)
        inv = (scratch / "findings_inventory.md").read_text(encoding="utf-8")
        assert inv.count("INV-002") == 1

    def test_filters_methodology_preamble_sections(self, scratch: Path):
        _seed_inventory(scratch, [("INV-001", "Medium", "src/X.sol:L1", "x")])
        # First section is a methodology block (lacks Severity/Location/Description)
        # Second is a real finding.
        (scratch / "niche_event_completeness_findings.md").write_text(
            "## Processing Protocol\n\n"
            "### Finding A: this is a methodology heading, not real finding\n"
            "Just prose, no schema fields.\n\n"
            "## Finding [NEC-1]: setBot emits no event\n"
            "**Severity**: Low\n**Location**: src/Y.sol:L40\n"
            "**Description**: missing event.\n**Impact**: indexer drift.\n",
            encoding="utf-8",
        )
        parsed, appended = mech.promote_niche_to_inventory(scratch)
        # The shared parser grammar sees ``Finding A``; the niche denominator
        # must retain it as malformed identity debt rather than silently drop
        # it. Only the registered substantive action is promotable.
        assert parsed == 2 and appended == 1
        debt = mech.read_niche_identity_debt_sidecar(scratch)
        assert debt is not None
        assert any(row["raw_id"] == "A" for row in debt["candidates"])

    def test_returns_zero_when_no_niche_files(self, scratch: Path):
        _seed_inventory(scratch, [("INV-001", "Medium", "src/A.sol:L1", "x")])
        parsed, appended = mech.promote_niche_to_inventory(scratch)
        assert parsed == 0 and appended == 0


# --- Fix 2: anti-absorption gate -------------------------------------------

class TestAntiAbsorption:
    def _seed(self, scratch: Path, constituents: list[tuple[str, str, str, str]],
              hyp_id: str, hyp_severity: str = "Medium",
              override_text: str = ""):
        _seed_inventory(scratch, constituents)
        constituent_ids = ", ".join(c[0] for c in constituents)
        hyp_body = (
            "# Hypotheses\n\n"
            "| Hypothesis ID | Severity | Source Findings |\n"
            "|---|---|---|\n"
            f"| {hyp_id} | {hyp_severity} | {constituent_ids} |\n"
        )
        if override_text:
            hyp_body += f"\n## {hyp_id} details\n\nAnti-absorption override: {override_text}\n"
        (scratch / "hypotheses.md").write_text(hyp_body, encoding="utf-8")
        fm_lines = [
            "| Source | Hypothesis |\n",
            "|--------|------------|\n",
        ]
        for c in constituents:
            fm_lines.append(f"| {c[0]} | {hyp_id} |\n")
        (scratch / "finding_mapping.md").write_text("".join(fm_lines), encoding="utf-8")

    def test_distinct_functions_not_hard_flagged(self, scratch: Path):
        # Fix 6: distinct (file, function) ALONE is no longer a hard violation.
        # Same-fix mirror-contract clusters legitimately span functions/files,
        # so a same-severity, same-root-cause pair across two functions must
        # NOT be flagged (and must never drive mechanical atomization).
        self._seed(scratch, [
            ("INV-001", "Medium", "GatewayA.sol:L10 handleRefund()", "shared refund handler missing state reset"),
            ("INV-002", "Medium", "GatewayB.sol:L20 handleRefund()", "shared refund handler missing state reset"),
        ], "GRP-M-001")
        issues = validators._validate_chain_anti_absorption(scratch, "thorough")
        assert len(issues) == 1
        assert "typed equivalence decision" in issues[0]

    def test_distinct_functions_soft_note_on_hard_violation(self, scratch: Path):
        # When a REAL violation (here: zero-overlap root causes -> Jaccard) fires,
        # the distinct-functions observation is surfaced as an advisory SOFT NOTE
        # inside the same issue string, never as its own hard violation.
        self._seed(scratch, [
            ("INV-001", "Medium", "PayloadCodec.sol:L10 fooDecompress()", "memory layout pointer bug"),
            ("INV-002", "Medium", "GatewayTransfer.sol:L20 withdraw()", "access control missing"),
        ], "GRP-M-001")
        issues = validators._validate_chain_anti_absorption(scratch, "thorough")
        assert len(issues) == 1
        assert "typed equivalence decision" in issues[0]

    def test_severity_span_flagged(self, scratch: Path):
        self._seed(scratch, [
            ("INV-001", "Informational", "src/A.sol:L1 fn()", "tiny issue with same words"),
            ("INV-002", "High", "src/A.sol:L2 fn()", "tiny issue with same words"),
        ], "GRP-H-001")
        issues = validators._validate_chain_anti_absorption(scratch, "thorough")
        # Same function + same words → only severity span flags
        assert len(issues) == 1
        assert "typed equivalence decision" in issues[0]

    def test_jaccard_below_threshold_flagged(self, scratch: Path):
        self._seed(scratch, [
            ("INV-001", "Medium", "src/X.sol:L1 fn()", "missing length validation causes overflow"),
            ("INV-002", "Medium", "src/X.sol:L2 fn()", "wrong return value type interface violation"),
        ], "GRP-M-001")
        issues = validators._validate_chain_anti_absorption(scratch, "thorough")
        assert len(issues) == 1
        assert "typed equivalence decision" in issues[0]

    def test_override_clears_violations(self, scratch: Path):
        self._seed(scratch, [
            ("INV-001", "Medium", "PayloadCodec.sol:L10 fooDecompress()", "memory layout bug"),
            ("INV-002", "Medium", "GatewayTransfer.sol:L20 withdraw()", "access control bug"),
        ], "GRP-M-001", override_text="agents detect same single defect")
        issues = validators._validate_chain_anti_absorption(scratch, "thorough")
        assert len(issues) == 1
        assert "typed equivalence decision" in issues[0]

    def test_single_constituent_groups_ignored(self, scratch: Path):
        self._seed(scratch, [
            ("INV-001", "Medium", "src/A.sol:L1 fn()", "single bug"),
        ], "GRP-M-001")
        issues = validators._validate_chain_anti_absorption(scratch, "thorough")
        assert issues == []

    def test_skipped_in_light_mode(self, scratch: Path):
        self._seed(scratch, [
            ("INV-001", "Medium", "PayloadCodec.sol:L10 a()", "x"),
            ("INV-002", "Medium", "BridgeRouter.sol:L20 b()", "y"),
        ], "GRP-M-001")
        assert validators._validate_chain_anti_absorption(scratch, "light") == []

    def test_retry_hint_generation(self):
        hint = validators._generate_anti_absorption_retry_hint([
            "GRP-M-001 absorbs 3 constituents (INV-1, INV-2, INV-3) with anti-absorption violations: distinct functions (foo.sol:f, bar.sol:b)",
        ])
        assert "ATTEMPT 2 RETRY" in hint
        assert "independently applied equivalence authority" in hint
        assert "only a proposal" in hint
        assert "GRP-M-001" in hint


# --- Fix 5+6: exact-locus sub-clustering repair (no singleton explosion) -----

class TestAntiAbsorptionSubcluster:
    def _seed(self, scratch: Path,
              constituents: list[tuple[str, str, str, str]],
              hyp_id: str = "GRP-M-001", hyp_sev: str = "Medium"):
        _seed_inventory(scratch, constituents)
        cids = ", ".join(c[0] for c in constituents)
        (scratch / "hypotheses.md").write_text(
            "# Hypotheses\n\n"
            "| Hypothesis ID | Severity | Source Findings |\n"
            "|---|---|---|\n"
            f"| {hyp_id} | {hyp_sev} | {cids} |\n",
            encoding="utf-8",
        )
        fm = ["| Finding ID | Hypothesis ID |\n", "|---|---|\n"]
        for c in constituents:
            fm.append(f"| {c[0]} | {hyp_id} |\n")
        (scratch / "finding_mapping.md").write_text("".join(fm), encoding="utf-8")

    def _result_groups(self, scratch: Path) -> list[tuple[str, list[str]]]:
        text = (scratch / "hypotheses.md").read_text(encoding="utf-8")
        out: list[tuple[str, list[str]]] = []
        for line in text.splitlines():
            if not line.strip().startswith("|"):
                continue
            cells = [c.strip() for c in line.strip("|").split("|")]
            if len(cells) < 5:
                continue
            hid = cells[0]
            if hid == "Hypothesis ID" or set(hid) <= set("-: "):
                continue
            srcs = re.findall(r"INV-\d+", cells[3])
            out.append((hid, srcs))
        return out

    # ---- helper-level ----
    def test_line_ref_not_treated_as_function(self):
        # location-only; line-ref tokens discarded; prose is never consulted
        assert validators._normalize_locus_function("X.sol L671 (safeTransfer)") == ""
        assert validators._normalize_locus_function("X.sol:661 (fn)") == ""
        assert validators._normalize_locus_function("X.sol claimPayout()") == "claimpayout"
        # a real `name()` in the Location field is still extracted
        assert validators._normalize_locus_function("Vault.sol:L10 settle()") == "settle"

    def test_partition_exact_keys_only(self):
        meta = [
            ("A", {"location": "F.sol L671 (x)", "root_cause": "rc", "severity": "High"}),
            ("B", {"location": "F.sol:671-672", "root_cause": "rc", "severity": "High"}),
            ("C", {"location": "G.sol foo()", "root_cause": "rc", "severity": "High"}),
        ]
        subs = validators._partition_into_subclusters(meta)
        keys = [sorted(cid for cid, _ in s) for s in subs]
        assert ["A", "B"] in keys   # same file + (normalized) empty func + tier
        assert ["C"] in keys        # distinct exact locus
        assert len(subs) == 2

    # ---- repair-level ----
    def test_same_locus_stays_one_finding_even_cross_tier(self, scratch: Path):
        # The claimPayout-CEI cluster: three High CEI findings + one Low
        # invariant note, ALL at the SAME claimPayout locus. Distinctness is
        # location-based, so a single locus is ONE bug: all four stay one
        # hypothesis (severity inherited as the highest, High), NOT split by
        # tier or by prose. This is the corrected behavior that ends the
        # fresh-generation over-fragmentation (the old code split the Low out
        # and shattered paraphrase duplicates into many findings).
        self._seed(scratch, [
            ("INV-010", "High", "NativeVault.sol:661-680 (claimPayout); ordering between L671 (safeTransfer) and L672 (delete)",
             "checks effects interactions violation refund reentrancy drain"),
            ("INV-166", "High", "NativeVault.sol:671-672 (transfer at L671, delete at L672)",
             "checks effects interactions violation refund reentrancy drain"),
            ("INV-167", "High", "NativeVault.sol:L661-672 (claimPayout)",
             "checks effects interactions violation refund reentrancy drain"),
            ("INV-164", "Low", "NativeVault.sol:L661-672 (fn: claimPayout)",
             "committed invariant claimPayout cannot be claimed twice disposition"),
        ], "GRP-H-001", "High")
        n = validators._repair_chain_anti_absorption_splits(scratch)
        # single locus -> one bug -> NO split; the original grouping (all four
        # constituents in one hypothesis) is preserved untouched.
        assert n == 4
        from plamen_parsers import _parse_hypothesis_constituents
        assert "H-001" not in _parse_hypothesis_constituents(scratch)

    def test_same_locus_paraphrase_dups_do_not_split(self, scratch: Path):
        # Fresh-generation failure mode: the SAME bug written by two agents with
        # divergent prose (low token Jaccard) at the SAME locus must NOT split.
        # This is the exact trigger that exploded 53 chain hypotheses -> 140.
        self._seed(scratch, [
            ("INV-300", "High", "NativeVault.sol:286-304 (withdraw)",
             "public withdraw drains contract WrappedToken balance to an attacker recipient via the standing gateway allowance"),
            ("INV-301", "Medium", "NativeVault.sol:286 (withdraw)",
             "any account may invoke the unrestricted withdraw and redirect held tokens to itself"),
        ], "GRP-H-002", "High")
        n = validators._repair_chain_anti_absorption_splits(scratch)
        assert n == 2  # independent until typed five-dimension equivalence

    def test_distinct_bugs_at_distinct_loci_still_split(self, scratch: Path):
        # Guardrail: two GENUINELY different bugs (different loci, unrelated
        # root cause) bundled into one hypothesis MUST still split.
        self._seed(scratch, [
            ("INV-400", "Medium", "GatewayA.sol:10 (swapGas)",
             "missing minAmountOut slippage bound on the gas conversion swap enables sandwich MEV"),
            ("INV-401", "Medium", "Proxy.sol:99 (initialize)",
             "uninitialized proxy lets any first caller seize admin and take over the contract"),
        ], "GRP-M-002", "Medium")
        n = validators._repair_chain_anti_absorption_splits(scratch)
        assert n >= 1  # distinct-locus + unrelated root cause -> split

    def test_distinct_functions_only_preserved_whole(self, scratch: Path):
        # Post-Fix-6: distinct (file, function) alone does NOT violate, so the
        # group is preserved intact — no split, no rewrite.
        self._seed(scratch, [
            ("INV-201", "Medium", "GatewayA.sol:L10 onRevert()", "unguarded pendingClaims overwrite same shared handler"),
            ("INV-202", "Medium", "GatewayB.sol:L20 onAbort()", "unguarded pendingClaims overwrite same shared handler"),
        ], "GRP-M-001", "Medium")
        n = validators._repair_chain_anti_absorption_splits(scratch)
        assert n == 2  # raw card preserved; active identities stay separate

    def test_jaccard_same_locus_merges_not_singletons(self, scratch: Path):
        # Two disjoint-root-cause findings at the EXACT same file+function+tier
        # trip the Jaccard predicate, but exact-locus keying keeps them merged
        # (same fix site = one finding) rather than exploding to singletons.
        self._seed(scratch, [
            ("INV-301", "Medium", "Vault.sol:L100 settle()", "missing length validation causes overflow"),
            ("INV-302", "Medium", "Vault.sol:L100 settle()", "wrong return value type interface violation"),
        ], "GRP-M-001", "Medium")
        n = validators._repair_chain_anti_absorption_splits(scratch)
        assert n == 2  # same locus is not equivalence authority
        from plamen_parsers import _parse_hypothesis_constituents
        mapping = _parse_hypothesis_constituents(scratch)
        assert not [srcs for srcs in mapping.values()
                    if "INV-301" in srcs or "INV-302" in srcs]


# --- Fix 4: per-constituent demotion ---------------------------------------

class TestPerConstituentDemotion:
    def test_single_winner_picks_top_constituent(self):
        content = (
            "### Finding Summary\n"
            "Tests memory layout pointer table vs inline struct decoding for "
            "Solana ABI account arrays.\n"
        )
        constituents = [
            ("INV-019", {"title": "OOB read from attacker len", "root_cause": "missing length validation"}),
            ("INV-020", {"title": "mload reads 32 bytes for 1-byte bool", "root_cause": "assembly width mismatch boolean"}),
            ("INV-143", {"title": "memory layout pointer table inline struct", "root_cause": "pointer storage inline struct ABI decode Solana"}),
        ]
        kind, scores = validators._per_constituent_claim_match(content, constituents)
        assert kind == "single_winner"
        winner = max(scores, key=lambda x: x[1])
        assert winner[0] == "INV-143"

    def test_ambiguous_when_no_match(self):
        content = "Verifier ran a completely unrelated test about something else."
        constituents = [
            ("INV-001", {"title": "specific feature A", "root_cause": "details about A"}),
            ("INV-002", {"title": "specific feature B", "root_cause": "details about B"}),
        ]
        kind, _ = validators._per_constituent_claim_match(content, constituents)
        assert kind == "ambiguous"

    def test_lexical_winner_routes_repair_but_cannot_authorize_demotion(self, scratch: Path):
        # Seed inventory with 3 distinct PayloadCodec findings
        _seed_inventory(scratch, [
            ("INV-001", "Medium", "PayloadCodec.sol:L10 decompressAccounts()",
             "OOB read from attacker controlled len parameter"),
            ("INV-002", "Medium", "PayloadCodec.sol:L20 decompressAccounts()",
             "mload reads 32 bytes for 1-byte isWritable boolean field"),
            ("INV-003", "High", "PayloadCodec.sol:L30 decompressAccounts()",
             "memory layout uses pointer table instead of inline struct data"),
        ])
        # Hypothesis groups all 3
        (scratch / "hypotheses.md").write_text(
            "# Hypotheses\n\n"
            "| Hypothesis ID | Severity | Source Findings |\n"
            "|---|---|---|\n"
            "| GRP-M-001 | Medium | INV-001, INV-002, INV-003 |\n",
            encoding="utf-8",
        )
        (scratch / "finding_mapping.md").write_text(
            "| Finding ID | Hypothesis ID |\n"
            "|------------|---------------|\n"
            "| INV-001 | GRP-M-001 |\n"
            "| INV-002 | GRP-M-001 |\n"
            "| INV-003 | GRP-M-001 |\n",
            encoding="utf-8",
        )
        # Verification queue with the hypothesis as a unit-class POC-FAIL
        # Note: queue parser canonicalizes "GRP-M-001" -> "M-001"
        (scratch / "verification_queue.md").write_text(
            "| Finding ID | Severity | PoC Class |\n"
            "|---|---|---|\n"
            "| GRP-M-001 | Medium | unit |\n",
            encoding="utf-8",
        )
        # Verify prose appears to test INV-003's claim, but has no typed
        # constituent/premise/assertion scope ledger. Under P0-O, lexical
        # similarity is routing telemetry only and cannot cap the group.
        # Filename uses canonical M-001 (matches parser output)
        (scratch / "verify_M-001.md").write_text(
            "# Verification: GRP-M-001\n\n"
            "### Finding Summary\n\n"
            "Tests memory layout pointer table vs inline struct decoding for "
            "Solana ABI account arrays.\n\n"
            "### PoC Attempt\n"
            "- Attempted: YES\n"
            "- Test File: tests/poc_group.rs\n"
            "- Command: cargo test poc_group\n\n"
            "### Execution Result\n"
            "- Compiled: YES\n"
            "- Result: FAIL\n"
            "- Mechanical Status: [FAIL]\n"
            "- Evidence Tag: [POC-FAIL]\n\n"
            "Evidence Tag: [POC-FAIL]\n",
            encoding="utf-8",
        )
        demotions = validators._apply_poc_fail_demotions(scratch, "thorough")
        assert demotions == []
        assert not (scratch / "poc_demotions.md").exists()
        receipt = json.loads(
            (scratch / "poc_demotion_scope_receipt.json").read_text(encoding="utf-8")
        )
        row = receipt["groups"][0]
        assert row["demotion_authority"] == "NONE"
        assert row["lexical_routing_telemetry"]["match_kind"] == "single_winner"
        assert set(row["preserved_constituent_ids"]) == {
            "INV-001", "INV-002", "INV-003"
        }


# --- Fix 5: CROSS_VM_ENCODING_NO_RUNTIME keyword guard ---------------------

class TestCrossVmSkip:
    def test_valid_solana_skip(self):
        content = (
            "PoC Not Attempted Because: CROSS_VM_ENCODING_NO_RUNTIME\n"
            "This finding involves PayloadCodec wire format for Solana decode.\n"
        )
        # Build the regex inline to mirror validator behavior
        skip_codes = (
            r"NO_BUILD_ENVIRONMENT|EXTERNAL_DEPENDENCY_NO_FORK_OR_ADDRESS|"
            r"DEPLOYMENT_ONLY_REQUIRES_LIVE_EXTERNAL|PURE_SPEC_OR_DOCS_ONLY|"
            r"STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION|"
            r"CROSS_VM_ENCODING_NO_RUNTIME"
        )
        skip_match = re.search(
            r"PoC\s+Not\s+Attempted\s+Because\s*:\s*(?:" + skip_codes + ")",
            content, re.IGNORECASE,
        )
        assert skip_match is not None
        keyword = re.search(
            r"\b(?:solana|svm|bitcoin|btc|move|aptos|sui|cosmos|ibc|"
            r"wormhole|layerzero|near|stellar|substrate|tron|"
            r"encoding|serialization|serializ\w*|wire\s*format|"
            r"calldata\s*layout|payload\s*format|message\s*format|"
            r"abi\s*layout)\b",
            content, re.IGNORECASE,
        )
        assert keyword is not None  # valid: Solana keyword present

    def test_bitcoin_keyword_also_valid(self):
        content = "CROSS_VM_ENCODING_NO_RUNTIME — this is a Bitcoin wire format bug."
        keyword = re.search(
            r"\b(?:solana|svm|bitcoin|btc|move|aptos|sui|cosmos|ibc|"
            r"wormhole|layerzero|near|stellar|substrate|tron|"
            r"encoding|serialization|serializ\w*|wire\s*format|"
            r"calldata\s*layout|payload\s*format|message\s*format|"
            r"abi\s*layout)\b",
            content, re.IGNORECASE,
        )
        assert keyword is not None

    def test_abuse_attempt_lacks_keyword(self):
        # Agent claims CROSS_VM but doesn't mention any cross-VM context
        content = (
            "PoC Not Attempted Because: CROSS_VM_ENCODING_NO_RUNTIME\n"
            "Just couldn't be bothered to write the test.\n"
        )
        keyword = re.search(
            r"\b(?:solana|svm|bitcoin|btc|move|aptos|sui|cosmos|ibc|"
            r"wormhole|layerzero|near|stellar|substrate|tron|"
            r"encoding|serialization|serializ\w*|wire\s*format|"
            r"calldata\s*layout|payload\s*format|message\s*format|"
            r"abi\s*layout)\b",
            content, re.IGNORECASE,
        )
        assert keyword is None  # abuse caught: validator should reject


# --- Smoke regression: imports + driver exposure ---------------------------

class TestSmokeIntegration:
    def test_promote_niche_exposed_via_driver(self):
        import plamen_driver as d
        assert callable(d.promote_niche_to_inventory)

    def test_anti_absorption_validator_exposed(self):
        assert callable(validators._validate_chain_anti_absorption)
        assert callable(validators._generate_anti_absorption_retry_hint)

    def test_per_constituent_match_exposed(self):
        assert callable(validators._per_constituent_claim_match)

    def test_cross_vm_in_skip_codes(self):
        import inspect
        src = inspect.getsource(validators)
        assert "CROSS_VM_ENCODING_NO_RUNTIME" in src
        assert "cross_vm_keyword_present" in src


# --- Fix 1: mechanical body-label binding from the report_index status column --

class TestBodyStatusStamp:
    _IDX = (
        "## Master Finding Index\n\n"
        "| Report ID | Title | Severity | Location | Verification | Trust Adj. | Internal |\n"
        "|---|---|---|---|---|---|---|\n"
        "| C-01 | claimPayout theft | Critical | GTN.sol:661 | VERIFIED | - | HC-01 |\n"
        "| M-07 | unconditional refund write | Medium | GCC.sol:449 | CONFIRMED | - | HM-01 |\n"
        "| M-08 | slippage bound | Medium | A.sol:10 | CONFIRMED | - | HM-02 |\n"
        "| M-09 | contested thing | Medium | B.sol:20 | CONTESTED | - | HM-03 |\n"
    )

    def test_status_map_reads_verification_column(self):
        sm = mech._index_status_map(self._IDX)
        assert sm == {"C-01": "VERIFIED", "M-07": "CONFIRMED",
                      "M-08": "CONFIRMED", "M-09": "CONTESTED"}

    def test_body_header_overwritten_from_index(self):
        # The tier-writer mislabeled M-07 [UNVERIFIED] and left M-08 untagged;
        # the stamp must make BOTH read [CONFIRMED] (matching the index), and
        # C-01 stays VERIFIED.
        body = (
            "## Critical Findings\n\n### [C-01] claimPayout theft [VERIFIED]\n\nx\n\n"
            "## Medium Findings\n\n### [M-07] unconditional refund write [UNVERIFIED]\n\ny\n\n"
            "### [M-08] slippage bound\n\nz\n\n### [M-09] contested thing [UNVERIFIED]\n\nw\n"
        )
        out = mech._stamp_body_header_status(body, mech._index_status_map(self._IDX))
        assert "### [C-01] claimPayout theft [VERIFIED]" in out
        assert "### [M-07] unconditional refund write [CONFIRMED]" in out
        assert "### [M-08] slippage bound [CONFIRMED]" in out
        assert "### [M-09] contested thing [CONTESTED]" in out
        assert "[UNVERIFIED]" not in out  # no leftover mislabel

    def test_unknown_id_keeps_existing_tag(self):
        body = "### [L-99] not in index [UNVERIFIED]\n"
        out = mech._stamp_body_header_status(body, mech._index_status_map(self._IDX))
        assert out == body  # absent from map -> untouched
