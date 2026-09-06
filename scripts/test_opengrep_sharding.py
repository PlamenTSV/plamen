"""Tests for Ship 7 of the artifact-complete PTY supervision plan.

Validates ``plamen_driver.shard_opengrep_obligations`` and
``_check_opengrep_sharding_preservation``.

Numbered tests 30-34 match the plan's ``test_opengrep_sharding.py``
section. Tests use synthetic ``spawn_manifest.md`` + ``opengrep_findings.md``
fixtures in ``tmp_path`` -- no real opengrep run, no live subprocess.

Sharding policy under test (verbatim from the plan):

  - Per-agent file named ``opengrep_obligations_{agent_id}_{focus_slug}.md``.
  - Every row routed to >= 1 shard (no disappearance).
  - Rows that match >= 1 agent by focus-area-token are duplicated into
    every matching shard with the same DEDUP_KEY (cross-cutting).
  - Rows that match ZERO agents land in
    ``opengrep_obligations_UNASSIGNED.md`` AND the core_state agent's
    shard.
  - No protocol-specific filenames, counts, or rules -- focus-area
    matching is purely token-based.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

import plamen_driver as D  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_manifest(sp: Path, rows: list[tuple[str, str]]) -> None:
    """Synthesize a spawn_manifest.md the sharder can parse.
    ``rows`` is [(agent_id, focus_area), ...]."""
    header = (
        "# Spawn Manifest\n\n"
        "| Template | Required? | Agent ID | Focus Area | "
        "Expected Output | Status | Type |\n"
        "|----------|-----------|----------|------------|"
        "-----------------|--------|------|\n"
    )
    body_lines = []
    for aid, focus in rows:
        body_lines.append(
            f"| TPL | YES | {aid} | {focus} | analysis_{focus}.md "
            f"| PENDING | agent |"
        )
    (sp / "spawn_manifest.md").write_text(
        header + "\n".join(body_lines) + "\n", encoding="utf-8"
    )


def _write_opengrep_findings(sp: Path, rows: list[dict]) -> None:
    """Synthesize an opengrep_findings.md the sharder can parse.
    Each row dict: {rule, severity, location, message}."""
    lines = [
        "# OpenGrep Findings",
        "",
        "| Row | Rule | Severity | Location | Message |",
        "| --- | --- | --- | --- | --- |",
    ]
    for i, r in enumerate(rows, start=1):
        lines.append(
            f"| {i} | {r.get('rule','sample-rule')} | "
            f"{r.get('severity','warning')} | "
            f"{r.get('location','Foo.sol:1')} | "
            f"{r.get('message','example finding')} |"
        )
    (sp / "opengrep_findings.md").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )


def _read_dedup_keys(path: Path) -> set[int]:
    """Extract DEDUP_KEYs (as ints) from a shard file."""
    if not path.exists():
        return set()
    text = path.read_text(encoding="utf-8", errors="replace")
    out: set[int] = set()
    for m in re.finditer(
        r"<!--\s*DEDUP_KEY:\s*opengrep:(\d+)\s*-->", text
    ):
        out.add(int(m.group(1)))
    return out


# ---------------------------------------------------------------------------
# Ship 8.3 -- namespace hygiene: shard files must not carry PLAMEN_* markers
# ---------------------------------------------------------------------------


def test_shard_files_use_opengrep_namespace_not_plamen(tmp_path: Path):
    """Shard metadata must live in the OPENGREP_SHARD_* namespace, NOT the
    PLAMEN_* lifecycle namespace. A breadth agent reading its shard
    (per the Subagent Prompt Template) must not be able to copy a
    `PLAMEN_*` marker out of the shard into its analysis file -- the
    contamination vector that produced B6's malformed header on
    a prior run. Assert: every shard (including UNASSIGNED) contains
    OPENGREP_SHARD_* markers and ZERO `PLAMEN_` substrings."""
    sp = tmp_path
    _write_manifest(sp, [("B1", "core_state"), ("B6", "storage_layout")])
    _write_opengrep_findings(
        sp,
        [
            {"location": "contracts/Vault.sol:42"},
            {"location": "lib/Unmatched.sol:7"},  # forces an UNASSIGNED row
        ],
    )
    result = D.shard_opengrep_obligations(sp)
    assert result, "sharder should have produced files"
    for owner, info in result.items():
        path = Path(info["shard_path"])
        text = path.read_text(encoding="utf-8")
        assert "PLAMEN_" not in text, (
            f"{path.name} contains a PLAMEN_ marker -- shard files must not "
            f"share the lifecycle namespace (contamination vector)"
        )
        assert "OPENGREP_SHARD_OWNER" in text, (
            f"{path.name} missing OPENGREP_SHARD_OWNER metadata"
        )
    # The UNASSIGNED file additionally carries the kind marker.
    unassigned = Path(result["UNASSIGNED"]["shard_path"])
    assert "OPENGREP_SHARD_KIND: UNASSIGNED" in unassigned.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Test 30 -- canonical filename emitted per agent
# ---------------------------------------------------------------------------


def test_shard_emits_per_agent_file_with_canonical_name(tmp_path: Path):
    """For each agent row in spawn_manifest.md, the sharder MUST emit
    a file named ``opengrep_obligations_{agent_id}_{focus_slug}.md``
    in the scratchpad. The filename is the single source of truth the
    breadth subagent prompt injects."""
    sp = tmp_path
    _write_manifest(
        sp,
        [
            ("B1", "core_state"),
            ("B3", "access_control"),
            ("B6", "storage_layout"),
        ],
    )
    _write_opengrep_findings(
        sp,
        [
            {"location": "contracts/Vault.sol:42"},
            {"location": "contracts/AccessController.sol:99"},
        ],
    )

    result = D.shard_opengrep_obligations(sp)

    expected_filenames = {
        "B1": "opengrep_obligations_B1_core_state.md",
        "B3": "opengrep_obligations_B3_access_control.md",
        "B6": "opengrep_obligations_B6_storage_layout.md",
        "UNASSIGNED": "opengrep_obligations_UNASSIGNED.md",
    }
    for owner, expected_name in expected_filenames.items():
        assert owner in result, (
            f"missing shard entry for {owner!r}; got: {list(result.keys())!r}"
        )
        on_disk = Path(result[owner]["shard_path"])
        assert on_disk.exists(), f"shard file for {owner} not written"
        assert on_disk.name == expected_name, (
            f"canonical filename mismatch for {owner}: "
            f"expected {expected_name!r}, got {on_disk.name!r}"
        )


# ---------------------------------------------------------------------------
# Test 31 -- unassigned rows routed to UNASSIGNED + core_state
# ---------------------------------------------------------------------------


def test_shard_routes_unassigned_to_core_state_plus_unassigned_file(
    tmp_path: Path,
):
    """A row whose Location file path matches NO agent's focus-area
    tokens MUST appear in BOTH ``opengrep_obligations_UNASSIGNED.md``
    AND the core_state agent's shard. No row may disappear."""
    sp = tmp_path
    # Two agents whose focus areas share NO tokens with "Mystery.sol".
    _write_manifest(
        sp,
        [
            ("B1", "core_state"),
            ("B3", "access_control"),
        ],
    )
    # Two unassignable rows + one that matches B3 (access in path).
    _write_opengrep_findings(
        sp,
        [
            {"location": "lib/Mystery.sol:10"},
            {"location": "tools/Utility.sol:5"},
            {"location": "contracts/AccessController.sol:88"},
        ],
    )

    result = D.shard_opengrep_obligations(sp)

    unassigned_path = sp / "opengrep_obligations_UNASSIGNED.md"
    core_path = sp / "opengrep_obligations_B1_core_state.md"
    access_path = sp / "opengrep_obligations_B3_access_control.md"

    unassigned_keys = _read_dedup_keys(unassigned_path)
    core_keys = _read_dedup_keys(core_path)
    access_keys = _read_dedup_keys(access_path)

    # Rows 1 and 2 are unassigned -> UNASSIGNED AND core_state (B1).
    assert {1, 2}.issubset(unassigned_keys), (
        f"UNASSIGNED missing rows 1/2: {unassigned_keys!r}"
    )
    assert {1, 2}.issubset(core_keys), (
        f"core_state (B1) missing rows 1/2: {core_keys!r}"
    )
    # Row 3 matches B3, NOT unassigned.
    assert 3 in access_keys
    assert 3 not in unassigned_keys
    # core_state shard MUST NOT absorb a row that another agent owned
    # (rows already routed don't fall back).
    assert 3 not in core_keys


# ---------------------------------------------------------------------------
# Test 32 -- cross-cutting rows duplicated with DEDUP_KEY
# ---------------------------------------------------------------------------


def test_shard_duplicates_cross_cutting_rows_with_dedup_key(tmp_path: Path):
    """A row whose Location matches MULTIPLE agents' focus areas MUST
    be duplicated into each matching shard. Every copy carries the
    SAME DEDUP_KEY so global accounting still treats it as one row."""
    sp = tmp_path
    # cross_chain and timing share the "cross" / "chain" / "timing"
    # tokens with cross_chain_timing's focus area.
    _write_manifest(
        sp,
        [
            ("B1", "core_state"),
            ("B2", "cross_chain_timing"),
            ("B5", "cross_chain_msg"),
        ],
    )
    _write_opengrep_findings(
        sp,
        [
            # cross + chain tokens match both B2 and B5
            {"location": "contracts/CrossChainBridgeRouter.sol:42"},
        ],
    )

    D.shard_opengrep_obligations(sp)

    b2_path = sp / "opengrep_obligations_B2_cross_chain_timing.md"
    b5_path = sp / "opengrep_obligations_B5_cross_chain_msg.md"
    b1_path = sp / "opengrep_obligations_B1_core_state.md"
    unassigned_path = sp / "opengrep_obligations_UNASSIGNED.md"

    b2_keys = _read_dedup_keys(b2_path)
    b5_keys = _read_dedup_keys(b5_path)
    b1_keys = _read_dedup_keys(b1_path)
    unassigned_keys = _read_dedup_keys(unassigned_path)

    # Cross-cutting: row 1 appears in BOTH B2 and B5 shards with the
    # same DEDUP_KEY value.
    assert 1 in b2_keys, f"B2 missing the cross-cutting row: {b2_keys!r}"
    assert 1 in b5_keys, f"B5 missing the cross-cutting row: {b5_keys!r}"
    # Same key value (1) in both shards -- not a fresh per-shard ID.
    assert b2_keys & b5_keys == {1}
    # B1 (core_state) gets the row only when no other agent matched;
    # here cross-cutting matches landed on B2/B5 so B1 stays clean.
    assert 1 not in b1_keys
    # UNASSIGNED MUST be empty for this row.
    assert 1 not in unassigned_keys


# ---------------------------------------------------------------------------
# Test 33 -- global coverage preserves original row count
# ---------------------------------------------------------------------------


def test_shard_global_coverage_preserves_total_count(tmp_path: Path):
    """The union of DEDUP_KEYs across every shard MUST equal the set
    of row indices in opengrep_findings.md. No row may disappear and
    no row beyond the original set may appear (the sharder cannot
    fabricate rows). Verified via
    ``_check_opengrep_sharding_preservation`` returning [] and via
    direct union arithmetic."""
    sp = tmp_path
    _write_manifest(
        sp,
        [
            ("B1", "core_state"),
            ("B3", "access_control"),
            ("B7", "migration"),
        ],
    )
    # Mix of matching (gateway/access), cross-cutting (migration+state),
    # and unassigned (lib).
    _write_opengrep_findings(
        sp,
        [
            {"location": "contracts/MessageRouter.sol:10"},        # 1 -> no token match -> UNASSIGNED+core
            {"location": "contracts/AccessController.sol:5"},    # 2 -> B3 (access)
            {"location": "contracts/Migration.sol:99"},          # 3 -> B7 (migration)
            {"location": "src/CoreState.sol:1"},                 # 4 -> B1 (core/state)
            {"location": "lib/Utility.sol:7"},                   # 5 -> UNASSIGNED+core
            {"location": "contracts/MigrationCore.sol:42"},      # 6 -> B1 + B7 (cross-cutting)
        ],
    )
    expected_rows = {1, 2, 3, 4, 5, 6}

    D.shard_opengrep_obligations(sp)

    # Union via direct inspection
    union = set()
    for path in sp.glob("opengrep_obligations_*.md"):
        union |= _read_dedup_keys(path)
    assert union == expected_rows, (
        f"DEDUP_KEY union mismatch.\n  expected: {sorted(expected_rows)!r}\n  got: "
        f"{sorted(union)!r}"
    )

    # And via the preservation check.
    issues = D._check_opengrep_sharding_preservation(sp)
    assert issues == [], f"preservation reported issues: {issues!r}"


# ---------------------------------------------------------------------------
# Test 34 -- shard filename matches the subagent prompt injection
# ---------------------------------------------------------------------------


def test_shard_filename_matches_subagent_prompt_injection():
    """The breadth Subagent Prompt Template (Ship 2) injects the
    per-agent shard path as
    ``opengrep_obligations_{agent_id}_{focus_area_slug}.md``. The
    sharder MUST produce filenames using the SAME format -- otherwise
    the subagent reads a different file than the sharder wrote.

    This test pins the canonical filename helper against the contract
    documented in phase3-breadth.md."""
    # The helper IS the single source of truth, so any future change
    # must touch this assertion -- exactly the audit trail we want.
    assert (
        D._opengrep_shard_filename("B3", "access_control")
        == "opengrep_obligations_B3_access_control.md"
    )
    # Spaces / mixed case in focus area should slugify deterministically
    # so the orchestrator's runtime substitution and the sharder's
    # write both produce the same path.
    assert (
        D._opengrep_shard_filename("B1", "Core State")
        == "opengrep_obligations_B1_core_state.md"
    )
    # Adversarial characters get scrubbed (filesystem safety).
    assert (
        D._opengrep_shard_filename("B8", "token/flow!")
        == "opengrep_obligations_B8_token_flow.md"
    )
    # Empty inputs degrade to "unknown" rather than producing an
    # invalid filename.
    assert (
        D._opengrep_shard_filename("", "")
        == "opengrep_obligations_unknown_unknown.md"
    )
    # The UNASSIGNED file uses the canonical literal.
    assert D._OPENGREP_UNASSIGNED_FILENAME == "opengrep_obligations_UNASSIGNED.md"

    # Spot-check that the breadth prompt template still references the
    # same canonical filename pattern (would fail if Ship 2's prompt
    # text drifts).
    prompt = (
        Path(D.__file__).resolve().parent.parent
        / "prompts" / "shared" / "v2" / "phase3-breadth.md"
    )
    text = prompt.read_text(encoding="utf-8", errors="replace")
    assert "opengrep_obligations_" in text, (
        "phase3-breadth.md does not reference the canonical "
        "opengrep_obligations_ filename family -- Ship 2 contract "
        "drifted from Ship 7 sharder output"
    )


def test_long_focus_filename_is_bounded_deterministic_and_collision_resistant():
    focus = (
        "cross_chain_message_integrity_oncall_onrevert_onabort_trusted_gateway_"
        "verification_message_decode_correctness_swapdatahelperlib_gatewaysend_"
        "duplicate_decoder_drift"
    )
    first = D._opengrep_shard_filename("B7", focus)
    second = D._opengrep_shard_filename("B7", focus)
    neighbor = D._opengrep_shard_filename("B7", focus + "_neighbor")

    assert first == second
    assert first.startswith("opengrep_obligations_B7_cross_chain_")
    assert re.search(r"_[0-9a-f]{12}\.md$", first)
    assert len(first.encode("ascii")) <= D._OPENGREP_SHARD_FILENAME_MAX_BYTES
    assert neighbor != first


def test_long_focus_shard_preserves_every_obligation(tmp_path: Path):
    focus = (
        "core_state_feepercent_slippage_minreturnamount_expreturnamount_max_"
        "deadline_deadline_gaslimit_staleness_across_gatewaycrosschain_"
        "gatewaysend_gatewaytransfernative"
    )
    _write_manifest(tmp_path, [("B1", focus), ("B2", "access_control")])
    _write_opengrep_findings(
        tmp_path,
        [
            {"location": "contracts/GatewayCrossChain.sol:42"},
            {"location": "contracts/UnmatchedLibrary.sol:7"},
        ],
    )

    result = D.shard_opengrep_obligations(tmp_path)
    shard = Path(result["B1"]["shard_path"])
    assert shard.is_file()
    assert len(shard.name.encode("ascii")) <= 96
    assert D._check_opengrep_sharding_preservation(tmp_path) == []


@pytest.mark.skipif(sys.platform != "win32", reason="native Win32 path budget")
def test_long_focus_shard_writes_below_native_windows_legacy_limit(
    tmp_path: Path,
):
    component_budget = max(1, min(50, 150 - len(str(tmp_path)) - 1))
    scratchpad = tmp_path / ("s" * component_budget)
    scratchpad.mkdir()
    focus = "storage_layout_" + ("upgradeable_gateway_contracts_" * 20)
    _write_manifest(scratchpad, [("B9", focus)])
    _write_opengrep_findings(
        scratchpad,
        [{"location": "contracts/ProxyStorage.sol:9", "message": "storage slot"}],
    )

    result = D.shard_opengrep_obligations(scratchpad)
    shard = Path(result["B9"]["shard_path"])
    assert shard.is_file()
    assert not str(shard).startswith("\\\\?\\")
    assert len(str(shard)) < 260
    assert D._check_opengrep_sharding_preservation(scratchpad) == []


# ---------------------------------------------------------------------------
# Defensive counterparts
# ---------------------------------------------------------------------------


def test_shard_no_manifest_returns_empty(tmp_path: Path):
    """No spawn_manifest.md -> sharder no-ops (returns {}); no
    files are created. The breadth subagent falls back to reading
    opengrep_findings.md directly per the Ship 2 template's fallback
    rule."""
    sp = tmp_path
    _write_opengrep_findings(sp, [{"location": "Foo.sol:1"}])
    assert D.shard_opengrep_obligations(sp) == {}
    assert not any(sp.glob("opengrep_obligations_*"))


def test_shard_no_opengrep_rows_returns_empty(tmp_path: Path):
    """Manifest exists but opengrep_findings.md is missing or empty
    -> sharder no-ops. Subagents read empty receipts per template."""
    sp = tmp_path
    _write_manifest(sp, [("B1", "core_state")])
    assert D.shard_opengrep_obligations(sp) == {}
    assert not any(sp.glob("opengrep_obligations_*"))


def test_shard_idempotent_same_inputs_same_bytes(tmp_path: Path):
    """Calling the sharder twice with the same inputs produces
    byte-identical files. This is the property the driver wiring
    relies on for retry safety."""
    sp = tmp_path
    _write_manifest(sp, [("B1", "core_state"), ("B3", "access_control")])
    _write_opengrep_findings(
        sp,
        [
            {"location": "contracts/AccessController.sol:10"},
            {"location": "lib/Util.sol:5"},
        ],
    )
    D.shard_opengrep_obligations(sp)
    first_snapshot = {
        p.name: p.read_bytes() for p in sp.glob("opengrep_obligations_*.md")
    }
    D.shard_opengrep_obligations(sp)
    second_snapshot = {
        p.name: p.read_bytes() for p in sp.glob("opengrep_obligations_*.md")
    }
    assert first_snapshot == second_snapshot


# ===========================================================================
# Ship 7 routing-quality correction: semantic content routing
# ===========================================================================
#
# The original sharder routed by file-path token intersection alone, which
# under-routes: an access-control finding in CrossChainRouter.sol matched
# only the cross-chain agents (filename contains cross/chain) and the
# access_control agent never saw it. These tests prove content-based
# semantic routing (row rule + message + location) reaches the right
# expert regardless of which file the finding lives in.

_FULL_AGENTS = [
    ("B1", "core_state"),
    ("B2", "cross_chain_timing"),
    ("B3", "access_control"),
    ("B4", "centralization"),
    ("B5", "cross_chain_msg"),
    ("B6", "storage_layout"),
    ("B7", "migration"),
    ("B8", "token_flow"),
]


def _shard_dedup_keys_for(sp: Path, agent_id: str, focus: str) -> set[int]:
    return _read_dedup_keys(
        sp / f"opengrep_obligations_{agent_id}_{focus}.md"
    )


def test_semantic_access_control_in_cross_chain_file_routes_to_access(
    tmp_path: Path,
):
    """The reviewer's canonical example: an onlyOwner / auth finding
    located in CrossChainRouter.sol MUST route to access_control even
    though the filename screams cross-chain. It SHOULD also reach the
    cross-chain agents via file-path (over-routing is acceptable), but
    access_control reaching it is the non-negotiable property."""
    sp = tmp_path
    _write_manifest(sp, _FULL_AGENTS)
    _write_opengrep_findings(
        sp,
        [
            {
                "rule": "missing-access-control",
                "message": "setOwner lacks onlyOwner modifier; any caller can seize ownership",
                "location": "contracts/CrossChainRouter.sol:42",
            },
        ],
    )
    D.shard_opengrep_obligations(sp)

    access_keys = _shard_dedup_keys_for(sp, "B3", "access_control")
    unassigned = _read_dedup_keys(sp / "opengrep_obligations_UNASSIGNED.md")

    assert 1 in access_keys, (
        "access_control agent MUST see the onlyOwner finding even though "
        "it lives in a cross-chain-named file"
    )
    # Must NOT be unassigned (it clearly belongs to access_control).
    assert 1 not in unassigned


def test_semantic_token_transfer_in_cross_chain_file_is_cross_cutting(
    tmp_path: Path,
):
    """A token-transfer finding in a cross-chain file routes to BOTH
    token_flow (semantic) AND the cross-chain agents (file path),
    preserving a single global DEDUP_KEY across all the shards it
    lands in."""
    sp = tmp_path
    _write_manifest(sp, _FULL_AGENTS)
    _write_opengrep_findings(
        sp,
        [
            {
                "rule": "unchecked-transfer-return",
                "message": "ERC20 transfer return value ignored; token amount may not move",
                "location": "contracts/CrossChainRouter.sol:88",
            },
        ],
    )
    D.shard_opengrep_obligations(sp)

    token_keys = _shard_dedup_keys_for(sp, "B8", "token_flow")
    msg_keys = _shard_dedup_keys_for(sp, "B5", "cross_chain_msg")
    timing_keys = _shard_dedup_keys_for(sp, "B2", "cross_chain_timing")

    assert 1 in token_keys, "token_flow MUST see the transfer finding"
    # At least one cross-chain agent sees it via file-path routing.
    assert 1 in msg_keys or 1 in timing_keys, (
        "a cross-chain agent should also see it (file-path over-routing)"
    )
    # Single global DEDUP_KEY: every shard that has the row uses key 1.
    union = set()
    for p in sp.glob("opengrep_obligations_*.md"):
        union |= _read_dedup_keys(p)
    assert union == {1}, f"expected only DEDUP_KEY 1 globally; got {union!r}"


def test_semantic_initializer_routes_to_migration_and_storage(
    tmp_path: Path,
):
    """Initializer / reinitializer / upgrade text routes to migration
    (init/reinitializer/upgrade keywords) and storage_layout (proxy
    keyword) as appropriate -- not to whatever file it happens to
    live in."""
    sp = tmp_path
    _write_manifest(sp, _FULL_AGENTS)
    _write_opengrep_findings(
        sp,
        [
            {
                "rule": "reinitializer-risk",
                "message": "reinitializer allows re-initialize after upgrade via proxy",
                "location": "src/SomeContract.sol:5",
            },
        ],
    )
    D.shard_opengrep_obligations(sp)

    migration_keys = _shard_dedup_keys_for(sp, "B7", "migration")
    storage_keys = _shard_dedup_keys_for(sp, "B6", "storage_layout")

    assert 1 in migration_keys, "migration agent MUST see initializer finding"
    assert 1 in storage_keys, "storage_layout agent MUST see proxy finding"


def test_semantic_cross_cutting_preserves_single_dedup_key(tmp_path: Path):
    """A row matching multiple semantic buckets (auth + token + upgrade)
    is duplicated into every matching agent shard, but the DEDUP_KEY is
    identical in all of them so global accounting counts it once."""
    sp = tmp_path
    _write_manifest(sp, _FULL_AGENTS)
    _write_opengrep_findings(
        sp,
        [
            {
                "rule": "multi-concern",
                "message": "onlyOwner setter changes fee and transfers token balance during upgrade",
                "location": "src/Mixed.sol:10",
            },
        ],
    )
    D.shard_opengrep_obligations(sp)

    # Count how many agent shards contain the row.
    shards_with_row = [
        p.name
        for p in sp.glob("opengrep_obligations_*.md")
        if 1 in _read_dedup_keys(p)
    ]
    # It should be cross-cutting (more than one shard).
    assert len(shards_with_row) >= 2, (
        f"expected cross-cutting routing to >= 2 shards; got {shards_with_row!r}"
    )
    # All copies share the same single DEDUP_KEY value.
    union = set()
    for p in sp.glob("opengrep_obligations_*.md"):
        union |= _read_dedup_keys(p)
    assert union == {1}


def test_semantic_routing_no_row_disappears(tmp_path: Path):
    """End-to-end preservation under semantic routing: a mix of
    semantically-routable, file-path-routable, and totally-unmatched
    rows still yields a complete DEDUP_KEY union with zero loss."""
    sp = tmp_path
    _write_manifest(sp, _FULL_AGENTS)
    _write_opengrep_findings(
        sp,
        [
            # 1: semantic access-control in a cross-chain file
            {
                "rule": "auth",
                "message": "onlyOwner missing on privileged setter",
                "location": "contracts/CrossChainRouter.sol:1",
            },
            # 2: semantic token in a neutral file
            {
                "rule": "tok",
                "message": "approve allowance not reset, balance drained",
                "location": "src/Helper.sol:2",
            },
            # 3: no semantic keyword, no focus-area file token -> unassigned
            {
                "rule": "misc",
                "message": "code style nit here",
                "location": "lib/Obscure.sol:3",
            },
            # 4: storage/proxy semantic
            {
                "rule": "proxy",
                "message": "delegatecall to user-controlled slot",
                "location": "src/Other.sol:4",
            },
        ],
    )
    D.shard_opengrep_obligations(sp)

    # Preservation: union of DEDUP_KEYs == {1,2,3,4}.
    union = set()
    for p in sp.glob("opengrep_obligations_*.md"):
        union |= _read_dedup_keys(p)
    assert union == {1, 2, 3, 4}, f"row(s) lost: {sorted(union)!r}"
    assert D._check_opengrep_sharding_preservation(sp) == []

    # Row 3 (no match) must be in UNASSIGNED and core_state.
    unassigned = _read_dedup_keys(sp / "opengrep_obligations_UNASSIGNED.md")
    core = _shard_dedup_keys_for(sp, "B1", "core_state")
    assert 3 in unassigned
    assert 3 in core
    # Row 1 (access-control) must reach the access_control agent.
    assert 1 in _shard_dedup_keys_for(sp, "B3", "access_control")
    # Row 2 (token) must reach token_flow.
    assert 2 in _shard_dedup_keys_for(sp, "B8", "token_flow")
    # Row 4 (storage) must reach storage_layout.
    assert 4 in _shard_dedup_keys_for(sp, "B6", "storage_layout")
