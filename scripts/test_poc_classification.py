"""Unit tests for v2.4.0 PoC testability classification and demotion logic.

Targets:
  - classify_poc_testability      (Change 2: mechanical classification)
  - _validate_poc_attempt_coverage (Change 4: enforcement gate)
  - _apply_poc_fail_demotions     (Change 5: demotion on POC-FAIL)
  - _write_queue_subset_manifest  (poc_class column integration)

Run: `python test_poc_classification.py`
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

from plamen_driver import (  # noqa: E402
    classify_poc_testability,
    _find_verify_file,
    _validate_verify_completion,
    _validate_poc_attempt_coverage,
    _apply_poc_fail_demotions,
    _validate_poc_pass_integrity,
    _queue_rows_from_inventory,
    _write_queue_subset_manifest,
)
from plamen_parsers import parse_verification_queue_rows  # noqa: E402

PASS, FAIL = 0, 0


def check(label: str, ok: bool, detail: str = "") -> None:
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  PASS  {label}")
    else:
        FAIL += 1
        print(f"  FAIL  {label} :: {detail}")


def _mkscratch(files: dict[str, str]) -> Path:
    sp = Path(tempfile.mkdtemp(prefix="plamen_poc_"))
    for name, body in files.items():
        (sp / name).write_text(body, encoding="utf-8")
    return sp


# --------------------------------------------------------------------------
# classify_poc_testability
# --------------------------------------------------------------------------

def test_classify_unit_patterns():
    """Panic, overflow, unwrap -> unit."""
    print("\n--- classify_poc_testability: unit patterns ---")
    check("panic in title", classify_poc_testability("", "", "Panic on invalid block header", "High") == "unit")
    check("overflow in bug_class", classify_poc_testability("arithmetic overflow", "", "Fee calculation", "Medium") == "unit")
    check("unwrap in title", classify_poc_testability("", "", "Unwrap on None in validator set", "High") == "unit")
    check("validation in bug_class", classify_poc_testability("input validation", "", "Missing bounds", "Medium") == "unit")
    check("truncat in title", classify_poc_testability("", "", "Truncation in u32 cast", "Low") == "unit")
    check("off-by-one", classify_poc_testability("off-by-one", "", "Array index", "Medium") == "unit")


def test_classify_property_patterns():
    """Invariant, state corruption -> property."""
    print("\n--- classify_poc_testability: property patterns ---")
    check("invariant in bug_class", classify_poc_testability("invariant violation", "", "Balance", "High") == "property")
    check("state corruption", classify_poc_testability("state corruption", "", "Epoch state", "Critical") == "property")
    check("accumulator", classify_poc_testability("accumulator drift", "", "Reward calc", "Medium") == "property")
    check("fuzz tag", classify_poc_testability("", "[FUZZ-PASS]", "Something", "Medium") == "property")
    check("non-det tag", classify_poc_testability("", "[NON-DET-PASS]", "Map iteration", "High") == "property")


def test_classify_structural_patterns():
    """Timing, TOCTOU, cross-client -> structural."""
    print("\n--- classify_poc_testability: structural patterns ---")
    check("toctou", classify_poc_testability("toctou", "", "File lock race", "High") == "structural")
    check("race condition", classify_poc_testability("race condition", "", "Goroutine data race", "High") == "structural")
    check("cross-client", classify_poc_testability("cross-client divergence", "", "EVM diff", "High") == "structural")
    check("byzantine", classify_poc_testability("byzantine tolerance", "", "2/3 threshold", "Critical") == "structural")
    check("network partition", classify_poc_testability("network partition", "", "Split brain", "High") == "structural")
    check("missing setter beats approve keyword", classify_poc_testability("", "CODE-TRACE", "MessageRouter.Approve Has No Admin Setter", "Low") == "structural")
    check("missing event beats setter/withdraw keywords", classify_poc_testability("", "CODE-TRACE", "Event Emission Missing on setBot, superWithdraw, setGasLimit, and setSlippage", "Low") == "structural")


def test_classify_integration_patterns():
    """RPC, network, p2p -> integration."""
    print("\n--- classify_poc_testability: integration patterns ---")
    check("rpc", classify_poc_testability("rpc surface", "", "Engine API", "Medium") == "integration")
    check("p2p", classify_poc_testability("p2p dos", "", "Message flood", "High") == "integration")
    check("handshake", classify_poc_testability("", "", "TLS handshake timeout", "Medium") == "integration")


def test_classify_map_iteration_exception():
    """Non-determinism from map iteration is property-testable."""
    print("\n--- classify_poc_testability: map iteration exception ---")
    check("map iter non-det -> property",
          classify_poc_testability("non-determinism", "", "Map iteration order in fee calc", "High") == "property")
    check("plain non-det -> structural",
          classify_poc_testability("non-determinism", "", "Random seed usage", "High") == "structural")


def test_classify_severity_catchall():
    """Unclassified findings default to structural (no false demotion on design bugs)."""
    print("\n--- classify_poc_testability: severity catch-all ---")
    check("critical unclassified -> structural",
          classify_poc_testability("unclassified", "", "Some bug", "Critical") == "structural")
    check("low unclassified -> structural",
          classify_poc_testability("unclassified", "", "Some bug", "Low") == "structural")


def test_classify_tag_fallback():
    """LSP-TRACE / CODE-TRACE tag -> structural."""
    print("\n--- classify_poc_testability: tag fallback ---")
    check("lsp-trace tag -> structural",
          classify_poc_testability("", "[LSP-TRACE]", "Some bug", "Medium") == "structural")
    check("code-trace tag -> structural",
          classify_poc_testability("", "[CODE-TRACE]", "Some bug", "Medium") == "structural")


# --------------------------------------------------------------------------
# _validate_poc_attempt_coverage
# --------------------------------------------------------------------------

def test_validate_poc_coverage_light_skips():
    """Light mode skips entirely."""
    print("\n--- _validate_poc_attempt_coverage: light mode ---")
    sp = _mkscratch({
        "verification_queue.md": (
            "# Verification Queue Manifest\n"
            "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact | PoC Class |\n"
            "|---------|-----------|----------|-------|-----------|--------------|----------|------------------|-----------|\n"
            "| 1 | F-01 | High | Panic bug | panic | [POC-PASS] | file.rs:10 | depth.md | unit |\n"
        ),
        "verify_F-01.md": "# Verify\nEvidence Tag: [CODE-TRACE]\n",
    })
    result = _validate_poc_attempt_coverage(sp, "light")
    check("light returns empty", result == [])


def test_validate_poc_coverage_thorough_warns():
    """Thorough mode warns on missing PoC attempt for unit-class."""
    print("\n--- _validate_poc_attempt_coverage: thorough warnings ---")
    sp = _mkscratch({
        "verification_queue.md": (
            "# Verification Queue Manifest\n"
            "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact | PoC Class |\n"
            "|---------|-----------|----------|-------|-----------|--------------|----------|------------------|-----------|\n"
            "| 1 | F-01 | High | Panic bug | panic | [POC-PASS] | file.rs:10 | depth.md | unit |\n"
            "| 2 | F-02 | Medium | State issue | invariant | [FUZZ-PASS] | file.rs:20 | depth.md | property |\n"
            "| 3 | F-03 | Low | Timing bug | timing | [CODE-TRACE] | file.rs:30 | depth.md | structural |\n"
        ),
        "verify_F-01.md": "# Verify F-01\nEvidence Tag: [CODE-TRACE]\nVerdict: CONTESTED\n",
        "verify_F-02.md": "# Verify F-02\nEvidence Tag: [CODE-TRACE]\nVerdict: CONTESTED\n",
        "verify_F-03.md": "# Verify F-03\nEvidence Tag: [CODE-TRACE]\nVerdict: CONTESTED\n",
    })
    result = _validate_poc_attempt_coverage(sp, "thorough")
    check("warns on F-01 (unit, no section)", any("F-01" in w for w in result))
    check("warns on F-02 (property, no section)", any("F-02" in w for w in result))
    check("no warn on F-03 (structural)", not any("F-03" in w for w in result))


def test_validate_poc_coverage_core_narrows():
    """Core mode checks Medium+ unit/property rows."""
    print("\n--- _validate_poc_attempt_coverage: core narrowing ---")
    sp = _mkscratch({
        "verification_queue.md": (
            "# Verification Queue Manifest\n"
            "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact | PoC Class |\n"
            "|---------|-----------|----------|-------|-----------|--------------|----------|------------------|-----------|\n"
            "| 1 | F-01 | High | Panic bug | panic | [POC-PASS] | file.rs:10 | depth.md | unit |\n"
            "| 2 | F-02 | Medium | Overflow | overflow | [POC-PASS] | file.rs:20 | depth.md | unit |\n"
        ),
        "verify_F-01.md": "# Verify F-01\nEvidence Tag: [CODE-TRACE]\n",
        "verify_F-02.md": "# Verify F-02\nEvidence Tag: [CODE-TRACE]\n",
    })
    result = _validate_poc_attempt_coverage(sp, "core")
    check("warns on F-01 (high+unit)", any("F-01" in w for w in result))
    check("warns on F-02 (medium+unit in core)", any("F-02" in w for w in result))


def test_validate_poc_coverage_pass_no_warn():
    """POC-PASS evidence -> no warning regardless."""
    print("\n--- _validate_poc_attempt_coverage: pass suppresses ---")
    sp = _mkscratch({
        "verification_queue.md": (
            "# Verification Queue Manifest\n"
            "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact | PoC Class |\n"
            "|---------|-----------|----------|-------|-----------|--------------|----------|------------------|-----------|\n"
            "| 1 | F-01 | High | Panic bug | panic | [POC-PASS] | file.rs:10 | depth.md | unit |\n"
        ),
        "verify_F-01.md": "# Verify F-01\nEvidence Tag: [POC-PASS]\nVerdict: CONFIRMED\n",
    })
    result = _validate_poc_attempt_coverage(sp, "thorough")
    check("no warn when POC-PASS", result == [])


def test_validate_poc_coverage_rejects_na_execution_for_testable_rows():
    """Unit/property rows cannot bypass execution with Compiled: N/A."""
    print("\n--- _validate_poc_attempt_coverage: rejects N/A execution ---")
    sp = _mkscratch({
        "verification_queue.md": (
            "# Verification Queue Manifest\n"
            "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact | PoC Class |\n"
            "|---------|-----------|----------|-------|-----------|--------------|----------|------------------|-----------|\n"
            "| 1 | H-10 | Medium | Accounting drift | accounting | [POC-PASS] | Vault.sol:10 | hypotheses.md | unit |\n"
        ),
        "verify_H-10.md": (
            "# Verify H-10\n"
            "Severity: Medium\n"
            "Evidence Tag: [CODE-TRACE]\n"
            "Verdict: CONFIRMED\n\n"
            "### PoC Attempt\n"
            "- PoC Required: YES\n"
            "- PoC Class: unit\n"
            "- Attempted: NO\n"
            "- PoC Not Attempted Because: N/A\n"
            "- Test File: N/A\n"
            "- Command: N/A\n\n"
            "### Execution Result\n"
            "- Compiled: N/A (no Foundry test written - structural property verified via code trace)\n"
            "- Result: N/A\n"
        ),
    })
    result = _validate_poc_attempt_coverage(sp, "thorough")
    check("warns on N/A execution", any("H-10" in w for w in result))


def test_validate_poc_coverage_allows_environmental_skip():
    """A real environmental blocker is accepted for testable rows."""
    print("\n--- _validate_poc_attempt_coverage: environmental skip ---")
    sp = _mkscratch({
        "verification_queue.md": (
            "# Verification Queue Manifest\n"
            "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact | PoC Class |\n"
            "|---------|-----------|----------|-------|-----------|--------------|----------|------------------|-----------|\n"
            "| 1 | H-11 | Medium | External price source | oracle | [POC-PASS] | Oracle.sol:10 | hypotheses.md | property |\n"
        ),
        "verify_H-11.md": (
            "# Verify H-11\n"
            "Severity: Medium\n"
            "Evidence Tag: [CODE-TRACE]\n"
            "Verdict: CONTESTED\n\n"
            "### PoC Attempt\n"
            "- PoC Required: YES\n"
            "- PoC Class: property\n"
            "- Attempted: NO\n"
            "- PoC Not Attempted Because: EXTERNAL_DEPENDENCY_NO_FORK_OR_ADDRESS\n"
            "- Test File: N/A\n"
            "- Command: N/A\n\n"
            "### Execution Result\n"
            "- Compiled: N/A\n"
            "- Result: NOT_EXECUTED\n"
        ),
    })
    result = _validate_poc_attempt_coverage(sp, "thorough")
    check("no warn with allowed environmental blocker", result == [])


def test_verify_completion_hard_fails_mandatory_poc_without_ledger():
    """Core Medium+ unit/property verifier shards require PoC ledger."""
    print("\n--- _validate_verify_completion: hard PoC ledger contract ---")
    sp = _mkscratch({
        "verification_queue.md": (
            "# Verification Queue Manifest\n"
            "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact | PoC Class |\n"
            "|---------|-----------|----------|-------|-----------|--------------|----------|------------------|-----------|\n"
            "| 1 | H-10 | Medium | Accounting drift | accounting | [POC-PASS] | Vault.sol:10 | hypotheses.md | unit |\n"
        ),
        "verify_H-10.md": (
            "# Verify H-10\n"
            "Severity: Medium\n"
            "Evidence Tag: [CODE-TRACE]\n"
            "Verdict: CONFIRMED\n"
            "This verifier file is intentionally long enough to satisfy the "
            "minimum byte gate while still omitting the mandatory PoC ledger "
            "for a unit-class Medium finding in Core mode.\n"
        ),
    })
    issues = _validate_verify_completion(sp, "sc_verify_medium_a", mode="core")
    check("hard-fails ledgerless mandatory PoC row", any("PoC contract" in i for i in issues), repr(issues))


def test_verify_completion_accepts_real_attempt_even_if_not_poc_pass():
    """A compile/runtime failure counts as an attempt; proof strength is separate."""
    print("\n--- _validate_verify_completion: attempted PoC satisfies coverage ---")
    sp = _mkscratch({
        "verification_queue.md": (
            "# Verification Queue Manifest\n"
            "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact | PoC Class |\n"
            "|---------|-----------|----------|-------|-----------|--------------|----------|------------------|-----------|\n"
            "| 1 | H-11 | Medium | Accounting drift | accounting | [POC-PASS] | Vault.sol:10 | hypotheses.md | unit |\n"
        ),
        "verify_H-11.md": (
            "# Verify H-11\n"
            "Severity: Medium\n"
            "Evidence Tag: [CODE-TRACE]\n"
            "Verdict: CONTESTED\n\n"
            "### PoC Attempt\n"
            "- PoC Required: YES\n"
            "- PoC Class: unit\n"
            "- Attempted: YES\n"
            "- PoC Not Attempted Because: N/A\n"
            "- Test File: test/VerifyH11.t.sol\n"
            "- Command: forge test --match-test test_H11 -vvv\n\n"
            "### Execution Result\n"
            "- Compiled: NO (attempts: 1)\n"
            "- Result: NOT_EXECUTED\n"
            "- Output: compile error retained for verifier trace\n"
        ),
    })
    issues = _validate_verify_completion(sp, "sc_verify_medium_a", mode="core")
    check("attempted PoC does not fail completion", issues == [], repr(issues))


def test_verify_completion_accepts_bold_skip_ledger_with_explanation():
    """Markdown-bold ledger labels and inline blocker explanations parse correctly."""
    print("\n--- _validate_verify_completion: bold skip ledger accepted ---")
    sp = _mkscratch({
        "verification_queue.md": (
            "# Verification Queue Manifest\n"
            "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact | PoC Class |\n"
            "|---------|-----------|----------|-------|-----------|--------------|----------|------------------|-----------|\n"
            "| 1 | H-12 | Medium | Cross env issue | integration | [CODE-TRACE] | BridgeRouter.sol:10 | hypotheses.md | unit |\n"
        ),
        "verify_H-12.md": (
            "# Verify H-12\n"
            "**Severity**: Medium\n"
            "**Evidence Tag**: [CODE-TRACE]\n"
            "**Verdict**: CONTESTED\n\n"
            "### PoC Attempt\n"
            "- **PoC Required**: YES\n"
            "- **PoC Class**: unit\n"
            "- **Attempted**: NO\n"
            "- **PoC Not Attempted Because**: EXTERNAL_DEPENDENCY_NO_FORK_OR_ADDRESS - live address unavailable\n"
            "- **Test File**: N/A\n"
            "- **Command**: N/A\n\n"
            "### Execution Result\n"
            "- **Compiled**: N/A\n"
            "- **Result**: NOT_EXECUTED\n"
            "- **Output**: no fork address for the external dependency\n"
        ),
    })
    issues = _validate_verify_completion(sp, "sc_verify_medium_a", mode="core")
    check("bold skip ledger is parsed", issues == [], repr(issues))


def test_verify_completion_rejects_bold_structural_skip_for_unit():
    """STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION remains invalid for unit rows."""
    print("\n--- _validate_verify_completion: structural skip rejected for unit ---")
    sp = _mkscratch({
        "verification_queue.md": (
            "# Verification Queue Manifest\n"
            "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact | PoC Class |\n"
            "|---------|-----------|----------|-------|-----------|--------------|----------|------------------|-----------|\n"
            "| 1 | H-13 | Medium | Unit-testable design issue | access-control | [CODE-TRACE] | BridgeRouter.sol:10 | hypotheses.md | unit |\n"
        ),
        "verify_H-13.md": (
            "# Verify H-13\n"
            "**Severity**: Medium\n"
            "**Evidence Tag**: [CODE-TRACE]\n"
            "**Verdict**: CONFIRMED\n\n"
            "### PoC Attempt\n"
            "- **PoC Required**: YES\n"
            "- **PoC Class**: unit\n"
            "- **Attempted**: NO\n"
            "- **PoC Not Attempted Because**: STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION - design risk only\n"
            "- **Test File**: N/A\n"
            "- **Command**: N/A\n\n"
            "### Execution Result\n"
            "- **Compiled**: N/A\n"
            "- **Result**: NOT_EXECUTED\n"
            "- **Output**: not executed\n"
        ),
    })
    issues = _validate_verify_completion(sp, "sc_verify_medium_a", mode="core")
    check("unit structural skip fails hard", any("H-13 mandatory unit" in i for i in issues), repr(issues))


def test_verify_completion_rejects_deployment_skip_for_unit():
    """DEPLOYMENT_ONLY_REQUIRES_LIVE_EXTERNAL is not valid for unit-class rows."""
    print("\n--- _validate_verify_completion: deployment skip rejected for unit ---")
    sp = _mkscratch({
        "verification_queue.md": (
            "# Verification Queue Manifest\n"
            "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact | PoC Class |\n"
            "|---------|-----------|----------|-------|-----------|--------------|----------|------------------|-----------|\n"
            "| 1 | H-14 | Medium | Fee mutation | accounting | [CODE-TRACE] | BridgeRouter.sol:10 | hypotheses.md | unit |\n"
        ),
        "verify_H-14.md": (
            "# Verify H-14\n"
            "**Severity**: Medium\n"
            "**Evidence Tag**: [CODE-TRACE]\n"
            "**Verdict**: CONFIRMED\n\n"
            "### PoC Attempt\n"
            "- **PoC Required**: YES\n"
            "- **PoC Class**: unit\n"
            "- **Attempted**: NO\n"
            "- **PoC Not Attempted Because**: DEPLOYMENT_ONLY_REQUIRES_LIVE_EXTERNAL - timing window\n"
            "- **Test File**: N/A\n"
            "- **Command**: N/A\n\n"
            "### Execution Result\n"
            "- **Compiled**: N/A\n"
            "- **Result**: NOT_EXECUTED\n"
            "- **Output**: not executed\n"
        ),
    })
    issues = _validate_verify_completion(sp, "sc_verify_medium_a", mode="core")
    check("unit deployment skip fails hard", any("H-14 mandatory unit" in i for i in issues), repr(issues))


def test_verify_completion_rejects_missing_mock_external_skip():
    """Missing-mock excuses must not satisfy mandatory unit PoC coverage."""
    print("\n--- _validate_verify_completion: missing mock skip rejected ---")
    sp = _mkscratch({
        "verification_queue.md": (
            "# Verification Queue Manifest\n"
            "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact | PoC Class |\n"
            "|---------|-----------|----------|-------|-----------|--------------|----------|------------------|-----------|\n"
            "| 1 | H-15 | Medium | Token mismatch | validation | [CODE-TRACE] | BridgeRouter.sol:10 | hypotheses.md | unit |\n"
        ),
        "verify_H-15.md": (
            "# Verify H-15\n"
            "**Severity**: Medium\n"
            "**Evidence Tag**: [CODE-TRACE]\n"
            "**Verdict**: CONFIRMED\n\n"
            "### PoC Attempt\n"
            "- **PoC Required**: YES\n"
            "- **PoC Class**: unit\n"
            "- **Attempted**: NO\n"
            "- **PoC Not Attempted Because**: EXTERNAL_DEPENDENCY_NO_FORK_OR_ADDRESS - mock does not implement token routing\n"
            "- **Test File**: N/A\n"
            "- **Command**: N/A\n\n"
            "### Execution Result\n"
            "- **Compiled**: N/A\n"
            "- **Result**: NOT_EXECUTED\n"
            "- **Output**: not executed\n"
        ),
    })
    issues = _validate_verify_completion(sp, "sc_verify_medium_a", mode="core")
    check("missing mock skip fails hard", any("H-15 mandatory unit" in i for i in issues), repr(issues))


def test_verify_completion_reports_all_poc_contract_failures():
    """Retry hints must see every bad ledger in the shard, not just the first six."""
    print("\n--- _validate_verify_completion: reports all PoC failures ---")
    rows = []
    files = {}
    for idx in range(1, 9):
        fid = f"H-{idx}"
        rows.append(
            f"| {idx} | {fid} | Medium | Unit issue {idx} | logic | [CODE-TRACE] | BridgeRouter.sol:{idx} | hypotheses.md | unit |\n"
        )
        files[f"verify_{fid}.md"] = (
            f"# Verify {fid}\n"
            "**Severity**: Medium\n"
            "**Evidence Tag**: [CODE-TRACE]\n"
            "**Verdict**: CONFIRMED\n\n"
            "### PoC Attempt\n"
            "- **PoC Required**: YES\n"
            "- **PoC Class**: unit\n"
            "- **Attempted**: NO\n"
            "- **PoC Not Attempted Because**: STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION\n"
            "- **Test File**: N/A\n"
            "- **Command**: N/A\n\n"
            "### Execution Result\n"
            "- **Compiled**: N/A\n"
            "- **Result**: NOT_EXECUTED\n"
            "- **Output**: not executed\n"
        )
    files["verification_queue.md"] = (
        "# Verification Queue Manifest\n"
        "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact | PoC Class |\n"
        "|---------|-----------|----------|-------|-----------|--------------|----------|------------------|-----------|\n"
        + "".join(rows)
    )
    sp = _mkscratch(files)
    # This fixture invokes the post-routing shard writer directly; seed the
    # canonical v3 queue authority through the real queue producer first.
    _write_queue_subset_manifest(
        sp / "verification_queue.md",
        parse_verification_queue_rows(sp),
    )
    # Uniform per-shard target (4) now spreads 8 Medium findings across
    # multiple medium shards instead of one. Validate that EVERY bad ledger is
    # surfaced across all populated shards (the original "not just the first
    # six" intent), regardless of which shard each finding lands in.
    import plamen_driver as _D
    shards = _D.ensure_sc_verify_shard_manifests(sp)
    detail = "\n".join(
        line
        for name, rows_in in shards.items()
        if rows_in
        for line in _validate_verify_completion(sp, name, mode="core")
    )
    check("all eight failures are surfaced", all(f"H-{i} mandatory unit" in detail for i in range(1, 9)), detail)


# --------------------------------------------------------------------------
# _apply_poc_fail_demotions
# --------------------------------------------------------------------------

def test_demotions_unit_poc_fail():
    """A prose-only unit POC-FAIL has no negative authority."""
    print("\n--- _apply_poc_fail_demotions: unit proposal requires typed evidence ---")
    sp = _mkscratch({
        "verification_queue.md": (
            "# Verification Queue Manifest\n"
            "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact | PoC Class |\n"
            "|---------|-----------|----------|-------|-----------|--------------|----------|------------------|-----------|\n"
            "| 1 | F-01 | High | Panic bug | panic | [POC-PASS] | file.rs:10 | depth.md | unit |\n"
        ),
        "verify_F-01.md": "# Verify F-01\nEvidence Tag: [POC-FAIL]\nVerdict: REFUTED\nThe system did not panic.\n",
    })
    result = _apply_poc_fail_demotions(sp, "thorough")
    check("no untyped demotion", result == [])
    check("legacy cap absent", not (sp / "poc_demotions.md").exists())
    check("reverification debt written", (sp / "execution_scope_reverification.json").exists())


def test_demotions_property_poc_fail():
    """A prose-only property POC-FAIL has no negative authority."""
    print("\n--- _apply_poc_fail_demotions: property proposal requires typed evidence ---")
    sp = _mkscratch({
        "verification_queue.md": (
            "# Verification Queue Manifest\n"
            "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact | PoC Class |\n"
            "|---------|-----------|----------|-------|-----------|--------------|----------|------------------|-----------|\n"
            "| 1 | F-02 | Critical | Invariant break | invariant | [FUZZ-PASS] | file.rs:20 | depth.md | property |\n"
        ),
        "verify_F-02.md": "# Verify F-02\nEvidence Tag: [POC-FAIL]\nVerdict: REFUTED\nInvariant held after 1000 iterations.\n",
    })
    result = _apply_poc_fail_demotions(sp, "thorough")
    check("no untyped demotion", result == [])
    check("reverification debt written", (sp / "execution_scope_reverification.json").exists())


def test_demotions_code_trace_no_demotion():
    """CODE-TRACE is inconclusive — no demotion."""
    print("\n--- _apply_poc_fail_demotions: code-trace no demotion ---")
    sp = _mkscratch({
        "verification_queue.md": (
            "# Verification Queue Manifest\n"
            "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact | PoC Class |\n"
            "|---------|-----------|----------|-------|-----------|--------------|----------|------------------|-----------|\n"
            "| 1 | F-01 | High | Panic bug | panic | [POC-PASS] | file.rs:10 | depth.md | unit |\n"
        ),
        "verify_F-01.md": "# Verify F-01\nEvidence Tag: [CODE-TRACE]\nVerdict: CONTESTED\n",
    })
    result = _apply_poc_fail_demotions(sp, "thorough")
    check("no demotion for CODE-TRACE", result == [])
    check("no file written", not (sp / "poc_demotions.md").exists())


def test_demotions_structural_no_demotion():
    """Structural-class is never demoted even with POC-FAIL."""
    print("\n--- _apply_poc_fail_demotions: structural exempt ---")
    sp = _mkscratch({
        "verification_queue.md": (
            "# Verification Queue Manifest\n"
            "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact | PoC Class |\n"
            "|---------|-----------|----------|-------|-----------|--------------|----------|------------------|-----------|\n"
            "| 1 | F-03 | High | Race cond | race condition | [CODE-TRACE] | file.rs:30 | depth.md | structural |\n"
        ),
        "verify_F-03.md": "# Verify F-03\nEvidence Tag: [POC-FAIL]\nVerdict: REFUTED\n",
    })
    result = _apply_poc_fail_demotions(sp, "thorough")
    check("no demotion for structural", result == [])


def test_demotions_light_skips():
    """Light mode skips demotion entirely."""
    print("\n--- _apply_poc_fail_demotions: light mode ---")
    sp = _mkscratch({
        "verification_queue.md": (
            "# Verification Queue Manifest\n"
            "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact | PoC Class |\n"
            "|---------|-----------|----------|-------|-----------|--------------|----------|------------------|-----------|\n"
            "| 1 | F-01 | High | Panic | panic | [POC-PASS] | file.rs:10 | depth.md | unit |\n"
        ),
        "verify_F-01.md": "# Verify F-01\nEvidence Tag: [POC-FAIL]\n",
    })
    result = _apply_poc_fail_demotions(sp, "light")
    check("light returns empty", result == [])


# --------------------------------------------------------------------------
# Queue manifest integration (poc_class column)
# --------------------------------------------------------------------------

def test_queue_manifest_has_poc_class_column():
    """Written manifest includes PoC Class column."""
    print("\n--- _write_queue_subset_manifest: poc_class column ---")
    sp = _mkscratch({})
    rows = [
        {
            "queue #": "1", "finding id": "F-01", "severity": "High",
            "title": "Panic", "bug class": "panic", "preferred tag": "POC-PASS",
            "location": "file.rs:10", "primary artifact": "depth.md",
            "poc class": "unit",
        }
    ]
    outpath = sp / "test_manifest.md"
    _write_queue_subset_manifest(outpath, rows)
    content = outpath.read_text(encoding="utf-8")
    check("header has PoC Class", "PoC Class" in content)
    check("row has unit", "| unit |" in content)


def test_queue_from_inventory_classifies():
    """_queue_rows_from_inventory adds poc_class to each row."""
    print("\n--- _queue_rows_from_inventory: classification ---")
    sp = _mkscratch({
        "findings_inventory.md": (
            "## Finding [F-01]: Panic on invalid input\n\n"
            "**Severity**: High\n"
            "**Location**: crates/domain/src/lib.rs:45\n"
            "**Bug Class**: panic\n"
            "**Preferred Tag**: [POC-PASS]\n"
            "**Description**: Unwrap on None\n\n"
            "---\n\n"
            "## Finding [F-02]: Network flood DoS\n\n"
            "**Severity**: Medium\n"
            "**Location**: crates/net/src/handler.rs:120\n"
            "**Bug Class**: p2p dos\n"
            "**Preferred Tag**: [FUZZ-PASS]\n"
            "**Description**: Unbounded message queue\n\n"
        ),
    })
    rows = _queue_rows_from_inventory(sp)
    check("2 rows", len(rows) == 2)
    if len(rows) >= 2:
        check("F-01 is unit", rows[0].get("poc class") == "unit")
        # FUZZ-PASS tag overrides p2p keyword -> property (fuzzable)
        check("F-02 is property (fuzz tag)", rows[1].get("poc class") == "property")


# --------------------------------------------------------------------------
# _find_verify_file
# --------------------------------------------------------------------------

def test_find_verify_file_variants():
    """Finds verify file under various naming conventions."""
    print("\n--- _find_verify_file: naming variants ---")
    sp = _mkscratch({
        "verify_F-01.md": "content",
    })
    check("exact match", _find_verify_file(sp, "F-01") is not None)
    check("missing returns None", _find_verify_file(sp, "F-99") is None)

    sp2 = _mkscratch({
        "verify_L1-H-C03.md": "content",
    })
    check("L1 format", _find_verify_file(sp2, "L1-H-C03") is not None)


# --------------------------------------------------------------------------
# _validate_poc_pass_integrity (PoC correctness sanity check)
# --------------------------------------------------------------------------

def test_poc_pass_integrity_clean():
    """POC-PASS with matching location -> no downgrade."""
    print("\n--- _validate_poc_pass_integrity: clean pass ---")
    sp = _mkscratch({
        "verification_queue.md": (
            "# Verification Queue Manifest\n"
            "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact | PoC Class |\n"
            "|---------|-----------|----------|-------|-----------|--------------|----------|------------------|-----------|\n"
            "| 1 | F-01 | High | Panic bug | panic | [POC-PASS] | crates/core/src/lib.rs:45 | depth.md | unit |\n"
        ),
        "verify_F-01.md": (
            "# Verify F-01\n"
            "Evidence Tag: [POC-PASS]\n"
            "### PoC Attempt\n"
            "- **Attempt 1 result**: PASS\n"
            "```rust\n"
            "use crate::core::lib;\n"
            "#[test]\n"
            "fn test_F_01() {\n"
            "    let result = lib::process(0);\n"
            "    assert!(result.is_err());\n"
            "}\n"
            "```\n"
        ),
    })
    result = _validate_poc_pass_integrity(sp)
    check("no downgrades for clean pass", result == [])


def test_poc_pass_integrity_trivial_assert():
    """POC-PASS with only assert!(true) -> downgrade."""
    print("\n--- _validate_poc_pass_integrity: trivial assertion ---")
    sp = _mkscratch({
        "verification_queue.md": (
            "# Verification Queue Manifest\n"
            "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact | PoC Class |\n"
            "|---------|-----------|----------|-------|-----------|--------------|----------|------------------|-----------|\n"
            "| 1 | F-01 | High | Panic bug | panic | [POC-PASS] | crates/core/src/lib.rs:45 | depth.md | unit |\n"
        ),
        "verify_F-01.md": (
            "# Verify F-01\n"
            "Evidence Tag: [POC-PASS]\n"
            "### PoC Attempt\n"
            "- **Attempt 1 result**: PASS\n"
            "```rust\n"
            "#[test]\n"
            "fn test_F_01() {\n"
            "    assert!(true);\n"
            "}\n"
            "```\n"
        ),
    })
    result = _validate_poc_pass_integrity(sp)
    check("downgrades trivial assert", len(result) == 1)
    if result:
        check("reason mentions trivial", "trivial" in result[0]["reason"].lower())


def test_poc_pass_integrity_no_assert():
    """POC-PASS with no assertion at all -> downgrade."""
    print("\n--- _validate_poc_pass_integrity: no assertion ---")
    sp = _mkscratch({
        "verification_queue.md": (
            "# Verification Queue Manifest\n"
            "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact | PoC Class |\n"
            "|---------|-----------|----------|-------|-----------|--------------|----------|------------------|-----------|\n"
            "| 1 | F-01 | High | Panic bug | panic | [POC-PASS] | crates/core/src/lib.rs:45 | depth.md | unit |\n"
        ),
        "verify_F-01.md": (
            "# Verify F-01\n"
            "Evidence Tag: [POC-PASS]\n"
            "### PoC Attempt\n"
            "- **Attempt 1 result**: PASS\n"
            "```rust\n"
            "#[test]\n"
            "fn test_F_01() {\n"
            "    let _ = process(0);\n"
            "}\n"
            "```\n"
        ),
    })
    result = _validate_poc_pass_integrity(sp)
    check("downgrades no-assert", len(result) == 1)


def test_poc_pass_integrity_should_panic_ok():
    """#[should_panic] is a valid assertion for panic-class bugs."""
    print("\n--- _validate_poc_pass_integrity: should_panic valid ---")
    sp = _mkscratch({
        "verification_queue.md": (
            "# Verification Queue Manifest\n"
            "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact | PoC Class |\n"
            "|---------|-----------|----------|-------|-----------|--------------|----------|------------------|-----------|\n"
            "| 1 | F-01 | High | Panic bug | panic | [POC-PASS] | crates/core/src/lib.rs:45 | depth.md | unit |\n"
        ),
        "verify_F-01.md": (
            "# Verify F-01\n"
            "Evidence Tag: [POC-PASS]\n"
            "### PoC Attempt\n"
            "- **Attempt 1 result**: PASS\n"
            "```rust\n"
            "#[test]\n"
            "#[should_panic]\n"
            "fn test_F_01() {\n"
            "    process(0);\n"
            "}\n"
            "```\n"
        ),
    })
    result = _validate_poc_pass_integrity(sp)
    check("should_panic is valid for panic bugs", result == [])


def test_poc_pass_integrity_code_trace_skip():
    """CODE-TRACE findings are not checked for PoC integrity."""
    print("\n--- _validate_poc_pass_integrity: code-trace skips ---")
    sp = _mkscratch({
        "verification_queue.md": (
            "# Verification Queue Manifest\n"
            "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact | PoC Class |\n"
            "|---------|-----------|----------|-------|-----------|--------------|----------|------------------|-----------|\n"
            "| 1 | F-01 | High | Timing | toctou | [CODE-TRACE] | file.rs:10 | depth.md | structural |\n"
        ),
        "verify_F-01.md": "# Verify F-01\nEvidence Tag: [CODE-TRACE]\n",
    })
    result = _validate_poc_pass_integrity(sp)
    check("code-trace not checked", result == [])


# --------------------------------------------------------------------------
# P1 fix regression tests
# --------------------------------------------------------------------------

def test_demotions_retry_override():
    """POC-FAIL in Attempt 1 + POC-PASS in Attempt 2 -> no demotion (retry won)."""
    print("\n--- _apply_poc_fail_demotions: retry override ---")
    sp = _mkscratch({
        "verification_queue.md": (
            "# Verification Queue Manifest\n"
            "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact | PoC Class |\n"
            "|---------|-----------|----------|-------|-----------|--------------|----------|------------------|-----------|\n"
            "| 1 | F-01 | High | Panic bug | panic | [POC-PASS] | file.rs:10 | depth.md | unit |\n"
        ),
        "verify_F-01.md": (
            "# Verify F-01\n"
            "Evidence Tag: [POC-PASS]\n"
            "### PoC Attempt\n"
            "- **Attempt 1 result**: ASSERTION_FAIL\n"
            "- **Self-diagnosis**: setup was wrong\n"
            "- **Attempt 2 result**: PASS\n"
            "- **Conclusion**: [POC-PASS] with retry\n"
            "Evidence Tag: [POC-FAIL] was initial, now [POC-PASS]\n"
            "```rust\n"
            "assert!(result.is_err());\n"
            "```\n"
        ),
    })
    result = _apply_poc_fail_demotions(sp, "thorough")
    check("no demotion when retry succeeded", result == [])


def test_demotions_poc_fail_scoped_to_section():
    """POC-FAIL quoted in prose outside PoC Attempt section -> no demotion."""
    print("\n--- _apply_poc_fail_demotions: section scoping ---")
    sp = _mkscratch({
        "verification_queue.md": (
            "# Verification Queue Manifest\n"
            "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact | PoC Class |\n"
            "|---------|-----------|----------|-------|-----------|--------------|----------|------------------|-----------|\n"
            "| 1 | F-01 | High | Panic bug | panic | [POC-PASS] | file.rs:10 | depth.md | unit |\n"
        ),
        "verify_F-01.md": (
            "# Verify F-01\n"
            "Evidence Tag: [CODE-TRACE]\n"
            "## Analysis\n"
            "If the input were invalid, this would result in [POC-FAIL] per the protocol.\n"
            "However our trace shows the path is reachable.\n"
        ),
    })
    result = _apply_poc_fail_demotions(sp, "thorough")
    check("no demotion for quoted POC-FAIL in prose", result == [])


def test_demotions_evidence_tag_line_fallback():
    """A bare POC-FAIL evidence tag remains proposal/debt only."""
    print("\n--- _apply_poc_fail_demotions: evidence tag has no authority ---")
    sp = _mkscratch({
        "verification_queue.md": (
            "# Verification Queue Manifest\n"
            "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact | PoC Class |\n"
            "|---------|-----------|----------|-------|-----------|--------------|----------|------------------|-----------|\n"
            "| 1 | F-01 | High | Panic bug | panic | [POC-PASS] | file.rs:10 | depth.md | unit |\n"
        ),
        "verify_F-01.md": (
            "# Verify F-01\n"
            "Evidence Tag: [POC-FAIL]\n"
            "Verdict: REFUTED\n"
            "The system handled the input correctly.\n"
        ),
    })
    result = _apply_poc_fail_demotions(sp, "thorough")
    check("bare evidence tag does not demote", result == [])
    check("reverification debt written", (sp / "execution_scope_reverification.json").exists())


def test_poc_pass_integrity_fuzz_pass():
    """FUZZ-PASS with no assertion -> downgrade (same as POC-PASS)."""
    print("\n--- _validate_poc_pass_integrity: fuzz-pass no assert ---")
    sp = _mkscratch({
        "verification_queue.md": (
            "# Verification Queue Manifest\n"
            "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact | PoC Class |\n"
            "|---------|-----------|----------|-------|-----------|--------------|----------|------------------|-----------|\n"
            "| 1 | F-01 | High | State issue | invariant | [FUZZ-PASS] | file.rs:20 | depth.md | property |\n"
        ),
        "verify_F-01.md": (
            "# Verify F-01\n"
            "Evidence Tag: [FUZZ-PASS]\n"
            "### PoC Attempt\n"
            "```rust\n"
            "fn fuzz_test(input: &[u8]) {\n"
            "    let _ = process(input);\n"
            "}\n"
            "```\n"
        ),
    })
    result = _validate_poc_pass_integrity(sp)
    check("downgrades fuzz-pass with no assert", len(result) == 1)


def test_poc_pass_integrity_nondet_pass_valid():
    """NON-DET-PASS with proper assertion -> no downgrade."""
    print("\n--- _validate_poc_pass_integrity: non-det-pass valid ---")
    sp = _mkscratch({
        "verification_queue.md": (
            "# Verification Queue Manifest\n"
            "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact | PoC Class |\n"
            "|---------|-----------|----------|-------|-----------|--------------|----------|------------------|-----------|\n"
            "| 1 | F-01 | High | Map non-det | non-determinism | [NON-DET-PASS] | file.rs:20 | depth.md | property |\n"
        ),
        "verify_F-01.md": (
            "# Verify F-01\n"
            "Evidence Tag: [NON-DET-PASS]\n"
            "### PoC Attempt\n"
            "```rust\n"
            "#[test]\n"
            "fn test_non_det() {\n"
            "    let results: Vec<_> = (0..100).map(|_| compute()).collect();\n"
            "    assert_ne!(results[0], results[99]);\n"
            "}\n"
            "```\n"
        ),
    })
    result = _validate_poc_pass_integrity(sp)
    check("non-det-pass with real assert is valid", result == [])


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

if __name__ == "__main__":
    test_classify_unit_patterns()
    test_classify_property_patterns()
    test_classify_structural_patterns()
    test_classify_integration_patterns()
    test_classify_map_iteration_exception()
    test_classify_severity_catchall()
    test_classify_tag_fallback()
    test_validate_poc_coverage_light_skips()
    test_validate_poc_coverage_thorough_warns()
    test_validate_poc_coverage_core_narrows()
    test_validate_poc_coverage_pass_no_warn()
    test_validate_poc_coverage_rejects_na_execution_for_testable_rows()
    test_validate_poc_coverage_allows_environmental_skip()
    test_verify_completion_hard_fails_mandatory_poc_without_ledger()
    test_verify_completion_accepts_real_attempt_even_if_not_poc_pass()
    test_verify_completion_accepts_bold_skip_ledger_with_explanation()
    test_verify_completion_rejects_bold_structural_skip_for_unit()
    test_verify_completion_rejects_deployment_skip_for_unit()
    test_verify_completion_rejects_missing_mock_external_skip()
    test_verify_completion_reports_all_poc_contract_failures()
    test_demotions_unit_poc_fail()
    test_demotions_property_poc_fail()
    test_demotions_code_trace_no_demotion()
    test_demotions_structural_no_demotion()
    test_demotions_light_skips()
    test_queue_manifest_has_poc_class_column()
    test_queue_from_inventory_classifies()
    test_find_verify_file_variants()
    test_poc_pass_integrity_clean()
    test_poc_pass_integrity_trivial_assert()
    test_poc_pass_integrity_no_assert()
    test_poc_pass_integrity_should_panic_ok()
    test_poc_pass_integrity_code_trace_skip()
    test_demotions_retry_override()
    test_demotions_poc_fail_scoped_to_section()
    test_demotions_evidence_tag_line_fallback()
    test_poc_pass_integrity_fuzz_pass()
    test_poc_pass_integrity_nondet_pass_valid()

    print(f"\n{'='*60}")
    print(f"  RESULTS: {PASS} passed, {FAIL} failed")
    print(f"{'='*60}")
    sys.exit(1 if FAIL > 0 else 0)
