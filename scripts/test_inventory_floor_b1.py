"""B1 inventory floor + B2 verify graceful fallback negative controls.

The inventory phase can degrade (a chunk failed, the LLM merge truncated, the
file was never written or is empty). When that happens `findings_inventory.md`
is missing and verification terminally halts even though real findings exist on
disk in the breadth/depth/chunk artifacts.

`ensure_findings_inventory_floor` reconstructs the inventory honestly from the
completed artifacts. The invariant is recall-safety: NEVER fewer findings than
exist in the source artifacts (no loss), NEVER more (no fabrication). A truly
empty scratchpad yields a valid empty inventory, not a crash. An inventory that
already holds real findings is left untouched (NO-OP — never clobbered, never
re-fabricated).

Run: pytest scripts/test_inventory_floor_b1.py -q
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import plamen_mechanical as M  # noqa: E402
import plamen_driver as D  # noqa: E402
import plamen_validators as V  # noqa: E402

_MISSING_MSG = "verification queue parity: findings_inventory.md missing"


def _mk() -> Path:
    return Path(tempfile.mkdtemp())


def _inv(scratchpad: Path) -> str:
    return (scratchpad / "findings_inventory.md").read_text(encoding="utf-8")


def _inv_block_count(scratchpad: Path) -> int:
    return _inv(scratchpad).count("### Finding [INV-")


# --------------------------------------------------------------------------- #
# B1: reconstruct exactly N findings — never fewer (no loss), never more
#     (no fabrication).
# --------------------------------------------------------------------------- #
def test_b1_floor_reconstructs_exactly_n_from_chunks():
    """Inventory DELETED but chunks hold 2 distinct findings -> exactly 2
    reconstructed, every source ID preserved."""
    d = _mk()
    (d / "findings_inventory_chunk_a.md").write_text(
        "\n".join([
            "### Finding [AC-1]: Reentrancy in withdraw",
            "**Severity**: High",
            "**Location**: src/A.sol:L10",
            "**Source IDs**: AC-1",
            "**Root Cause**: external call before state update",
            "",
            "### Finding [AC-2]: Missing zero-address check",
            "**Severity**: Low",
            "**Location**: src/A.sol:L20",
            "**Source IDs**: AC-2",
            "**Root Cause**: unchecked input",
            "",
        ]),
        encoding="utf-8",
    )
    # Precondition: inventory genuinely absent.
    assert not (d / "findings_inventory.md").exists()

    n, src = M.ensure_findings_inventory_floor(d)

    assert n == 2, "must reconstruct exactly the 2 findings that exist"
    assert src == 1
    inv = _inv(d)
    assert "INV-001" in inv and "INV-002" in inv
    # No loss: both source IDs carried forward.
    assert "AC-1" in inv and "AC-2" in inv
    assert _inv_block_count(d) == 2


def test_b1_floor_reconstructs_from_breadth_and_depth_no_loss_no_fabrication():
    """Mixed chunk + breadth analysis_* + depth_*_findings sources with 5
    DISTINCT findings (distinct loc+title) -> exactly 5, no fabrication."""
    d = _mk()
    (d / "findings_inventory_chunk_a.md").write_text(
        "\n".join([
            "### Finding [AC-1]: Reentrancy in withdraw",
            "**Severity**: High",
            "**Location**: src/A.sol:L10",
            "**Source IDs**: AC-1",
            "",
            "### Finding [AC-2]: Missing zero check",
            "**Severity**: Low",
            "**Location**: src/A.sol:L20",
            "**Source IDs**: AC-2",
            "",
        ]),
        encoding="utf-8",
    )
    (d / "analysis_token_flow.md").write_text(
        "\n".join([
            "### Finding [TF-1]: Fee rounding loss",
            "**Severity**: Medium",
            "**Location**: src/B.sol:L30",
            "**Description**: rounding favors protocol",
            "",
            "### Finding [TF-2]: Slippage bound missing",
            "**Severity**: Medium",
            "**Location**: src/B.sol:L40",
            "**Description**: no amountOutMin",
            "",
        ]),
        encoding="utf-8",
    )
    (d / "depth_edge_case_findings.md").write_text(
        "\n".join([
            "### Finding [DE-1]: Overflow at max supply",
            "**Severity**: High",
            "**Location**: src/C.sol:L50",
            "**Description**: unchecked multiplication",
            "**Verdict**: CONFIRMED",
            "",
        ]),
        encoding="utf-8",
    )

    n, src = M.ensure_findings_inventory_floor(d)

    assert n == 5, "5 distinct findings exist; reconstruct exactly 5 (no loss)"
    assert src == 3
    inv = _inv(d)
    # No fabrication: every reconstructed ID traces to a real source finding.
    for sid in ("AC-1", "AC-2", "TF-1", "TF-2", "DE-1"):
        assert sid in inv, f"{sid} must be preserved"
    assert _inv_block_count(d) == 5


def test_b1_floor_conservative_merge_only_collapses_exact_duplicates():
    """Disjoint producers survive pre-verification even when title/location
    render identically; a later semantic-dedup/verifier may consolidate them.

    Exact prose equality is not proof that two independently sourced candidates
    share a root cause.  The floor is a recall-recovery boundary, so it may only
    couple rows with a concrete shared provenance anchor.
    """
    d = _mk()
    (d / "findings_inventory_chunk_a.md").write_text(
        "\n".join([
            "### Finding [AC-1]: Reentrancy in withdraw",
            "**Severity**: High",
            "**Location**: src/A.sol:L10",
            "**Source IDs**: AC-1",
            "",
            # Same loc+title as AC-1, but disjoint provenance -> keep until
            # semantic dedup/verification proves identity.
            "### Finding [TF-9]: Reentrancy in withdraw",
            "**Severity**: High",
            "**Location**: src/A.sol:L10",
            "**Source IDs**: TF-9",
            "",
            # Same LOCATION but different title -> distinct sibling, kept.
            "### Finding [AC-3]: Missing event in withdraw",
            "**Severity**: Low",
            "**Location**: src/A.sol:L10",
            "**Source IDs**: AC-3",
            "",
        ]),
        encoding="utf-8",
    )

    n, _src = M.ensure_findings_inventory_floor(d)

    # All three survive the recall floor; this boundary does not infer semantic
    # identity from duplicated prose alone.
    assert n == 3
    inv = _inv(d)
    # Both candidate provenance IDs are preserved (no pre-verify loss).
    assert "AC-1" in inv and "TF-9" in inv
    # The distinct sibling is NOT dropped.
    assert "AC-3" in inv


# --------------------------------------------------------------------------- #
# B1: truly-empty scratchpad -> valid empty inventory, no crash.
# --------------------------------------------------------------------------- #
def test_b1_floor_empty_scratchpad_writes_valid_empty_inventory():
    d = _mk()
    n, src = M.ensure_findings_inventory_floor(d)
    assert n == 0
    assert src == 0
    # File MUST exist (clean empty path, not a crash / not absent).
    assert (d / "findings_inventory.md").exists()
    inv = _inv(d)
    assert "# Finding Inventory" in inv
    assert "| Total | 0 |" in inv
    assert _inv_block_count(d) == 0


def test_b1_floor_sources_present_but_zero_findings_is_empty_path():
    """Source artifacts exist but contain NO parseable findings (e.g. a header-
    only degraded file) -> still the clean empty path, no crash."""
    d = _mk()
    (d / "analysis_core_state.md").write_text(
        "# Core State Analysis\n\nNo findings identified.\n", encoding="utf-8"
    )
    (d / "depth_token_flow_findings.md").write_text(
        "# Depth Token Flow\n\n(empty — agent found nothing)\n", encoding="utf-8"
    )
    n, src = M.ensure_findings_inventory_floor(d)
    assert n == 0
    assert src == 2  # both source artifacts were scanned
    assert (d / "findings_inventory.md").exists()
    assert _inv_block_count(d) == 0


# --------------------------------------------------------------------------- #
# B1: NO-OP when a real inventory already exists — never clobber, never
#     fabricate on top of it.
# --------------------------------------------------------------------------- #
def test_b1_floor_is_noop_when_real_inventory_present():
    d = _mk()
    real = "\n".join([
        "# Finding Inventory",
        "",
        "## Findings",
        "",
        "### Finding [INV-001]: real finding",
        "**Severity**: High",
        "**Location**: src/X.sol:L1",
        "**Source IDs**: AC-9",
        "",
        "### Finding [INV-002]: another real finding",
        "**Severity**: Low",
        "**Location**: src/Y.sol:L2",
        "**Source IDs**: AC-8",
        "",
    ])
    (d / "findings_inventory.md").write_text(real, encoding="utf-8")
    # A chunk that, if the floor ran, would inject a fabricated extra finding.
    (d / "findings_inventory_chunk_a.md").write_text(
        "### Finding [ZZ-1]: should NOT appear\n"
        "**Severity**: High\n**Location**: src/Z.sol:L9\n**Source IDs**: ZZ-1\n",
        encoding="utf-8",
    )

    before = _inv(d)
    n, src = M.ensure_findings_inventory_floor(d)
    after = _inv(d)

    assert before == after, "real inventory must be left byte-identical"
    assert src == 0, "NO-OP scans no sources"
    assert n == 2
    assert "ZZ-1" not in after, "floor must not fabricate onto a real inventory"


# --------------------------------------------------------------------------- #
# B2: driver degrade decision helper — missing inventory must NOT be terminal.
# --------------------------------------------------------------------------- #
def test_b2_degrade_helper_reconstructs_and_continues_on_recoverable():
    """_inventory_degrade_floor_ok returns True (degrade-and-continue) when the
    inventory is missing but artifacts are recoverable; the inventory ends up
    present with the recovered findings."""
    d = _mk()
    (d / "depth_state_trace_findings.md").write_text(
        "\n".join([
            "### Finding [DS-1]: Stale snapshot used in payout",
            "**Severity**: High",
            "**Location**: src/S.sol:L7",
            "**Description**: snapshot read before refresh",
            "**Verdict**: CONFIRMED",
            "",
        ]),
        encoding="utf-8",
    )
    assert not (d / "findings_inventory.md").exists()

    ok = D._inventory_degrade_floor_ok(d)

    assert ok is True, "recoverable inventory must degrade-continue, not halt"
    assert (d / "findings_inventory.md").exists()
    assert "DS-1" in _inv(d)


def test_b2_degrade_helper_empty_audit_is_clean_continue_not_crash():
    """Genuinely empty audit (no inventory, no findings anywhere) -> the helper
    still returns True with a valid empty inventory written (clean empty path)."""
    d = _mk()
    ok = D._inventory_degrade_floor_ok(d)
    assert ok is True
    assert (d / "findings_inventory.md").exists()
    assert _inv_block_count(d) == 0


def test_b2_degrade_helper_noop_when_inventory_present():
    """Inventory PRESENT with usable findings -> helper returns True via the
    fast path WITHOUT reconstructing (no false reconstruction)."""
    d = _mk()
    real = "\n".join(
        ["# Finding Inventory", "", "## Findings", ""]
        + [
            line
            for i in range(1, 5)
            for line in (
                f"### Finding [INV-{i:03d}]: real finding {i}",
                "**Severity**: Medium",
                f"**Location**: src/F.sol:L{i}",
                f"**Source IDs**: AC-{i}",
                "",
            )
        ]
    )
    (d / "findings_inventory.md").write_text(real, encoding="utf-8")
    before = _inv(d)

    ok = D._inventory_degrade_floor_ok(d)

    assert ok is True
    # No floor receipt should be written when the fast path is taken.
    assert not (d / "inventory_floor_receipt.md").exists()
    assert _inv(d) == before


# --------------------------------------------------------------------------- #
# B2: verify-queue parity VALIDATOR graceful fallback (ROOT, validator-level).
#     A missing/empty inventory must NOT terminally return the "missing" error
#     whenever real findings remain recoverable on disk; verification proceeds
#     on the honest reconstructed inventory. A genuinely empty audit is a clean
#     empty path. An inventory already present yields unchanged behavior.
# --------------------------------------------------------------------------- #
def test_b2_parity_validator_reconstructs_missing_inventory_not_terminal():
    """Inventory missing + a recoverable depth finding -> the parity validator
    floor-reconstructs and does NOT emit the terminal 'missing' error; the
    inventory ends up present with the recovered finding routed into the
    verification queue (no silently-skipped verification)."""
    d = _mk()
    (d / "depth_state_trace_findings.md").write_text(
        "\n".join([
            "### Finding [DS-1]: Stale snapshot used in payout",
            "**Severity**: High",
            "**Location**: src/S.sol:L7",
            "**Description**: snapshot read before refresh",
            "**Verdict**: CONFIRMED",
            "",
        ]),
        encoding="utf-8",
    )
    assert not (d / "findings_inventory.md").exists()

    issues = V._validate_verification_queue_inventory_parity(d)

    # The terminal hard-fail must NOT be returned — that would silently skip
    # verification of a finding that genuinely exists.
    assert _MISSING_MSG not in issues
    # The floor put an honest inventory on disk carrying the real finding.
    assert (d / "findings_inventory.md").exists()
    assert "DS-1" in _inv(d)
    assert _inv_block_count(d) == 1


def test_b2_parity_validator_empty_inventory_file_reconstructs():
    """A degraded inventory FILE exists but holds zero usable finding blocks
    (present-but-empty) while a real finding exists in artifacts -> the
    validator reconstructs rather than reading the empty file and failing."""
    d = _mk()
    # Present-but-empty inventory (header only, no INV blocks).
    (d / "findings_inventory.md").write_text(
        "# Finding Inventory\n\n## Findings\n\n_No findings._\n", encoding="utf-8"
    )
    (d / "analysis_core_state.md").write_text(
        "\n".join([
            "### Finding [CS-1]: Missing access control on setOracle",
            "**Severity**: High",
            "**Location**: src/Core.sol:L42",
            "**Description**: anyone can repoint the oracle",
            "",
        ]),
        encoding="utf-8",
    )

    issues = V._validate_verification_queue_inventory_parity(d)

    assert _MISSING_MSG not in issues
    # Reconstructed from the real artifact (empty file did not block recovery).
    assert "CS-1" in _inv(d)
    assert _inv_block_count(d) == 1


def test_b2_parity_validator_genuinely_empty_audit_is_clean_empty_path():
    """Inventory missing AND zero findings anywhere -> the validator must take
    the clean empty path (no 'missing' terminal error, no crash), since there
    is nothing to verify and nothing was silently dropped."""
    d = _mk()
    assert not (d / "findings_inventory.md").exists()

    issues = V._validate_verification_queue_inventory_parity(d)

    assert issues == [], "genuinely empty audit must be a clean empty path"
    # Floor wrote a structurally valid empty inventory (not absent / not a crash).
    assert (d / "findings_inventory.md").exists()
    assert _inv_block_count(d) == 0


def test_b2_floor_builder_resolves_from_sys_modules_no_static_import():
    """Architecture invariant: the validator reconstructs via the B1 floor
    WITHOUT a static validators->mechanical import. The resolver finds the
    builder in sys.modules (mechanical is loaded at runtime because it imports
    validators), and the validator-source contains no reverse-import token."""
    # The resolver returns the real builder when mechanical is loaded.
    builder = V._resolve_inventory_floor_builder()
    assert builder is M.ensure_findings_inventory_floor

    # And the validators source carries NO reverse-import statement (the
    # dependency-direction invariant the modularization gate enforces).
    src = Path(V.__file__).read_text(encoding="utf-8")
    assert "import plamen_mechanical" not in src
    assert "from plamen_mechanical" not in src


def test_b2_floor_builder_explicit_injection_overrides_resolution():
    """The driver may inject the floor builder explicitly; when it does, that
    callable is used (no reliance on sys.modules resolution)."""
    d = _mk()
    (d / "depth_edge_case_findings.md").write_text(
        "\n".join([
            "### Finding [DE-7]: Off-by-one in bound check",
            "**Severity**: Medium",
            "**Location**: src/E.sol:L3",
            "**Description**: inclusive vs exclusive bound",
            "",
        ]),
        encoding="utf-8",
    )
    called: dict[str, int] = {"n": 0}

    def _spy(scratchpad):
        called["n"] += 1
        return M.ensure_findings_inventory_floor(scratchpad)

    issues = V._validate_verification_queue_inventory_parity(d, floor_builder=_spy)

    assert called["n"] == 1, "injected builder must be used"
    assert _MISSING_MSG not in issues
    assert "DE-7" in _inv(d)


def test_b2_parity_validator_no_builder_surfaces_missing_not_silent():
    """Recall-safety: if NO floor builder is resolvable (mechanical genuinely
    unavailable) and the inventory is missing, the validator surfaces the honest
    'missing' error rather than silently skipping verification."""
    d = _mk()
    (d / "depth_edge_case_findings.md").write_text(
        "### Finding [DE-1]: x\n**Severity**: High\n**Location**: src/A.sol:L1\n"
        "**Description**: y\n",
        encoding="utf-8",
    )
    assert not (d / "findings_inventory.md").exists()

    # Force resolution to fail by injecting a builder that returns None-like
    # absence is not possible; instead simulate "no builder" by monkeypatching
    # the resolver to return None for this call.
    orig = V._resolve_inventory_floor_builder
    V._resolve_inventory_floor_builder = lambda: None
    try:
        issues = V._validate_verification_queue_inventory_parity(d)
    finally:
        V._resolve_inventory_floor_builder = orig

    # No builder + missing inventory -> honest hard error, NOT a silent skip.
    assert _MISSING_MSG in issues
    # And it did NOT fabricate an inventory it couldn't honestly build.
    assert not (d / "findings_inventory.md").exists()


def test_b2_parity_validator_present_inventory_unchanged_behavior():
    """Inventory PRESENT with usable findings that ARE routed -> the validator
    behaves exactly as before (no false reconstruction, no floor receipt, file
    byte-identical, clean parity)."""
    d = _mk()
    real = "\n".join(
        ["# Finding Inventory", "", "## Findings", ""]
        + [
            line
            for i in range(1, 3)
            for line in (
                f"### Finding [INV-{i:03d}]: real finding {i}",
                "**Severity**: Medium",
                f"**Location**: src/F.sol:L{i}",
                f"**Source IDs**: AC-{i}",
                "",
            )
        ]
    )
    (d / "findings_inventory.md").write_text(real, encoding="utf-8")
    # Route both inventory IDs into the active verification queue so parity is
    # clean (this isolates the test to the floor-fallback path, not routing).
    (d / "verification_queue.md").write_text(
        "\n".join([
            "# Verification Queue",
            "",
            "| Finding ID | Severity | Location | Preferred Verification |",
            "|------------|----------|----------|------------------------|",
            "| INV-001 | Medium | src/F.sol:L1 | CODE-TRACE |",
            "| INV-002 | Medium | src/F.sol:L2 | CODE-TRACE |",
            "",
        ]),
        encoding="utf-8",
    )
    before = _inv(d)

    issues = V._validate_verification_queue_inventory_parity(d)

    # No floor receipt -> the fallback path was NOT taken (no false reconstruction).
    assert not (d / "inventory_floor_receipt.md").exists()
    assert _inv(d) == before, "present inventory must be left byte-identical"
    # Parity is clean (both IDs routed); the 'missing' error must never appear.
    assert _MISSING_MSG not in issues
