"""Live smoke tests for plamen_driver.py phase-loop policy.

Pytest-discoverable integration tests. Each scenario spawns a subprocess
that monkeypatches run_phase to exercise the driver's phase-loop policy
without needing Claude CLI or network access.

Run all:    pytest test_driver_smoke.py -v
Run fast:   pytest test_driver_smoke.py -v -m "not slow"
Standalone: python test_driver_smoke.py

Eleven scenarios:
  A. Breadth critical halt + resume retry
     Silent breadth. Assert EXIT_DEGRADED=3, `breadth.degraded` marker,
     `breadth` IN degraded / NOT IN completed. Second run must retry
     breadth without re-running recon/instantiate.
  B. Manifest-aware quorum override
     Instantiate writes a real 5-row `spawn_manifest.md`. Breadth writes
     only 3 `analysis_*.md` files. Assert the quorum ratchets 3 -> 5 and
     breadth halts despite having artifacts on disk.
  C. Empty-verify short-circuit
     Upstream phases succeed. `findings_inventory.md` + `hypotheses.md`
     contain ZERO Medium+ markers. Assert verify writes `verify_NONE.md`,
     is marked completed (not degraded), and pipeline proceeds to report.
  D. Depth manifest-aware quorum override
     L1 writes `phase4b_manifest.md` declaring 5 depth agents. Depth writes
     only 3 `depth_*_findings.md` files. Assert depth halts despite clearing
     the old fixed floor of 3.
  E. Depth pre-baked gatefail -> degrade-and-continue (v2.8.16)
     L1 depth writes enough artifacts to satisfy the glob gate, but appends a
     `[GATE FAIL] ... pre-baked reads` violation. Assert the driver retries
     depth once + one S1.5 targeted-repair attempt (3 depth calls), degrades,
     and CONTINUES past depth (L1 now mirrors SC; haltless-on-any-mode).
  F. Never-cut tail-gap -> degrade-and-continue (v2.8.16)
     L1 depth clears quorum but omits one required post-depth artifact and
     checkpoint entry. Assert retry + S1.5 repair (3 depth calls), degrade,
     and continue to later thorough-mode phases (no force-halt).
  G. Depth exit validation
     L1 depth clears quorum and writes all artifacts, but `depth_exit.md`
     has an invalid criterion / insufficient explored paths. Assert retry and
     degrade/halt.
  H. Verify completeness gate
     Verification queue expects 3 verifier files, phase writes only 2.
     Assert retry, degraded exit, and deterministic missing-file recovery/stub
     instead of falsely completing or launching an unmocked live worker.
  I. Phase-containment detector
     Inventory writes later-phase artifacts. Assert retry and degrade/halt.
  K. Inventory sharding
     L1 breadth produces enough analysis files to trigger inventory sharding.
     Assert chunk phases complete and final inventory is produced without a
     parity halt.

Not a unit test of internal helpers. Black-box check that the runtime
policy (critical halt, manifest-exact quorum, empty-queue short-circuit)
holds end-to-end. Monkeypatches `run_phase`, `detect_rate_limit`, and
`recon_prepass.run_recon_prepass` so we exercise only the phase loop —
not shell, git, or subprocess state.

Run: `python test_driver_smoke.py`.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent
DRIVER = SCRIPTS_DIR / "plamen_driver.py"


# ---------- stub script executed inside each subprocess ----------
#
# __TOKEN__ placeholder substitution (not .format()) so embedded
# `{...}` f-strings in the stub pass through unscathed.
#
# Scenario selection is via __SCENARIO__ in {"A","B","C","D","E","F","G","H","I"}.

RUNNER_TEMPLATE = r"""
import sys, types, json
from pathlib import Path
sys.path.insert(0, r'__SCRIPTS_DIR__')

# Block real recon_prepass BEFORE plamen_driver imports it.
_stub_mod = types.ModuleType("recon_prepass")
_stub_mod.run_recon_prepass = lambda cfg: "stub-prepass"
sys.modules["recon_prepass"] = _stub_mod

import plamen_driver as pd

CALL_LOG = Path(r'__CALL_LOG__')
SCENARIO = "__SCENARIO__"

# Smoke tests run unattended. Critical failures should surface as process
# exit codes/checkpoint state, not block waiting for an interactive choice.
pd.display.wait_halt_choice = lambda: False
pd.display.wait_critical_halt_choice = lambda: "exit"

_RECON_ARTIFACTS = [
    "recon_summary.md", "design_context.md", "attack_surface.md",
    "state_variables.md", "function_list.md", "contract_inventory.md",
    "template_recommendations.md", "detected_patterns.md",
    "setter_list.md", "emit_list.md", "build_status.md",
]

_L1_RECON_ARTIFACTS = [
    "recon_summary.md", "threat_model.md", "subsystem_map.md",
    "attack_surface.md", "trust_boundaries.md",
    "template_recommendations.md", "scope_leftover.md",
]

_STUB_BODY = (
    "# stub artifact\n"
    "This file is written by test_driver_smoke.py to clear the "
    "min_artifact_bytes gate. It has no semantic content.\n"
    "padding " * 20 + "\n"
)

# Ship 8.1: depth is now a supervised phase, so on a fresh audit (which
# the smoke test is -- main() plants the fresh-audit sentinel) each
# canonical depth file must carry COMPLETE markers and pass the
# depth-appropriate structural check. This body is a marker-complete,
# zero-findings depth stub (No Findings rationale present) used wherever
# a scenario writes a depth_*_findings.md that should COUNT as complete.
# Scenarios that intentionally omit depth files still fail the gate via
# the MISSING bucket, preserving their quorum/halt intent.
_DEPTH_COMPLETE_BODY = (
    "<!-- PLAMEN_ARTIFACT: depth_role_findings.md -->\n"
    "<!-- PLAMEN_STATUS: IN_PROGRESS -->\n"
    "<!-- PLAMEN_PHASE: depth -->\n"
    "<!-- PLAMEN_VERSION: 1 -->\n"
    "# Depth findings (smoke stub)\n\n"
    "## No Findings\n\n"
    "Smoke-test stub: no findings; body clears min_artifact_bytes.\n"
    + "padding " * 20 + "\n"
    "## Semantic Proof Checks\n\nstub\n"
    "<!-- PLAMEN_STATUS: COMPLETE -->\n"
    "<!-- PLAMEN_FINDINGS_COUNT: 0 -->\n"
)

# Real-ish manifest with 5 breadth agent rows. Parsed by
# parse_breadth_manifest_count() via the `| Template | Required |` header.
_MANIFEST_5_ROWS = (
    "# Spawn Manifest\n\n"
    "| Row Type | Template | Required? | Agent ID | Focus Area | Expected Output | Status |\n"
    "|----------|----------|-----------|----------|------------|-----------------|--------|\n"
    "| AGENT | core-state | YES | agent_1 | storage + accounting | analysis_storage_accounting.md | PENDING |\n"
    "| AGENT | access-control | YES | agent_2 | role + caps | analysis_role_caps.md | PENDING |\n"
    "| AGENT | token-flow | YES | agent_3 | transfer/mint/burn | analysis_transfer_mint_burn.md | PENDING |\n"
    "| AGENT | economic | YES | agent_4 | fees + incentives | analysis_fees_incentives.md | PENDING |\n"
    "| AGENT | oracle-external | YES | agent_5 | price + xchain | analysis_price_xchain.md | PENDING |\n"
    "\n**Gate Check**: All REQUIRED templates have agents? YES\n"
)

_MANIFEST_1_ROW = (
    "# Spawn Manifest\n\n"
    "| Row Type | Template | Required? | Agent ID | Focus Area | Expected Output | Status |\n"
    "|----------|----------|-----------|----------|------------|-----------------|--------|\n"
    "| AGENT | core-state | YES | agent_1 | storage + accounting | analysis_storage_accounting.md | PENDING |\n"
    "\n**Gate Check**: All REQUIRED templates have agents? YES\n"
)

_MANIFEST_5_OUTPUTS = [
    "analysis_storage_accounting.md",
    "analysis_role_caps.md",
    "analysis_transfer_mint_burn.md",
    "analysis_fees_incentives.md",
    "analysis_price_xchain.md",
]

_DEPTH_MANIFEST_5_ROWS = (
    "# Depth Loop Manifest\n\n"
    "| Agent | Role | Model | Output |\n"
    "|-------|------|-------|--------|\n"
    "| depth-consensus-invariant | consensus | opus | depth_consensus_invariant_findings.md |\n"
    "| depth-network-surface | network | opus | depth_network_surface_findings.md |\n"
    "| depth-state-trace | state | opus | depth_state_trace_findings.md |\n"
    "| depth-external | external | sonnet | depth_external_findings.md |\n"
    "| depth-edge-case | edge | sonnet | depth_edge_case_findings.md |\n"
)

# Inventory / hypotheses body with ZERO Medium+ severity markers.
# Scenario C uses this so is_verification_queue_empty() returns True.
_INVENTORY_LOW_ONLY = (
    "# Findings Inventory\n\n"
    "## Findings\n\n"
    "### Finding F-01\n"
    "**Severity**: Low\n"
    "**Location**: src/Stub.sol:L10\n"
    "Missing event emission on admin setter.\n\n"
    "### Finding F-02\n"
    "**Severity**: Informational\n"
    "**Location**: src/Stub.sol:L42\n"
    "Variable could be immutable.\n\n"
    "Pure informational/low output. No Medium+ tokens anywhere.\n"
    "padding " * 10 + "\n"
)

_ANALYSIS_LOW_ONLY = (
    "### Finding [F-01]\n"
    "**Severity**: Low\n"
    "**Location**: src/Stub.sol:L10\n"
    "Missing event emission on admin setter.\n\n"
    "### Finding [F-02]\n"
    "**Severity**: Informational\n"
    "**Location**: src/Stub.sol:L42\n"
    "Variable could be immutable.\n"
)

_INVENTORY_MEDIUM_THREE = (
    "# Findings Inventory\n\n"
    "### Finding [F-01]\n"
    "**Severity**: Medium\n"
    "**Location**: src/Stub.sol:L10\n"
    "Medium finding one.\n\n"
    "### Finding [F-02]\n"
    "**Severity**: Medium\n"
    "**Location**: src/Stub.sol:L20\n"
    "Medium finding two.\n\n"
    "### Finding [F-03]\n"
    "**Severity**: Medium\n"
    "**Location**: src/Stub.sol:L30\n"
    "Medium finding three.\n"
)

_ANALYSIS_MEDIUM_THREE = (
    "### Finding [F-01]\n"
    "**Severity**: Medium\n"
    "**Location**: src/Stub.sol:L10\n"
    "Medium finding one.\n\n"
    "### Finding [F-02]\n"
    "**Severity**: Medium\n"
    "**Location**: src/Stub.sol:L20\n"
    "Medium finding two.\n\n"
    "### Finding [F-03]\n"
    "**Severity**: High\n"
    "**Location**: src/Stub.sol:L30\n"
    "High finding three.\n"
)

_ANALYSIS_MEDIUM_ONE = (
    "### Finding [F-01]\n"
    "**Severity**: Medium\n"
    "**Location**: src/Stub.sol:L10\n"
    "Medium finding one.\n"
    + ("padding " * 20) + "\n"
)

def _analysis_low_unique(fid, line):
    return (
        f"### Finding [{fid}]\n"
        "**Severity**: Low\n"
        f"**Location**: src/Stub.sol:L{line}\n"
        "Low-severity finding for inventory sharding.\n"
    )

def _write(p, text):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def _breadth_marked(name, body, count):
    # Ship 8.1: when a multi-row spawn_manifest.md is present (scenarios
    # B/C), breadth runs manifest-exact and -- on a fresh audit (sentinel
    # planted by main()) -- requires each output to be COMPLETE-marked and
    # structurally sound (## Findings heading + FINDINGS_COUNT). Wrap the
    # analysis body so the success-path scenario's breadth files pass.
    return (
        f"<!-- PLAMEN_ARTIFACT: {name} -->\n"
        "<!-- PLAMEN_STATUS: IN_PROGRESS -->\n"
        "<!-- PLAMEN_PHASE: breadth -->\n"
        "<!-- PLAMEN_VERSION: 1 -->\n"
        "# Analysis\n\n"
        "## Findings\n\n"
        f"{body}\n"
        "<!-- PLAMEN_STATUS: COMPLETE -->\n"
        f"<!-- PLAMEN_FINDINGS_COUNT: {count} -->\n"
    )


def _write_depth_support_artifacts(scratch, *, valid_checkpoint=True,
                                   valid_exit=True, include_skill_gap=True):
    _write(scratch / "design_stress_findings.md", _STUB_BODY)
    _write(scratch / "perturbation_findings.md", _STUB_BODY)
    _write(scratch / "confidence_scores.md", _STUB_BODY)
    if include_skill_gap:
        _write(scratch / "skill_execution_gaps.md", _STUB_BODY)

    if valid_checkpoint:
        _write(
            scratch / "never_cut_checkpoint.md",
            "\n".join([
                "depth-consensus-invariant: SPAWNED depth_consensus_invariant_findings.md",
                "depth-network-surface: SPAWNED depth_network_surface_findings.md",
                "depth-state-trace: SPAWNED depth_state_trace_findings.md",
                "depth-external: SPAWNED depth_external_findings.md",
                "depth-edge-case: SPAWNED depth_edge_case_findings.md",
                "design-stress: SPAWNED design_stress_findings.md",
                "perturbation: SPAWNED perturbation_findings.md",
                "confidence-scoring: SPAWNED confidence_scores.md",
                "skill-execution-checklist: SPAWNED skill_execution_gaps.md",
            ]) + "\n"
        )
    else:
        _write(
            scratch / "never_cut_checkpoint.md",
            "\n".join([
                "depth-consensus-invariant: SPAWNED depth_consensus_invariant_findings.md",
                "depth-network-surface: SPAWNED depth_network_surface_findings.md",
                "depth-state-trace: SPAWNED depth_state_trace_findings.md",
            ]) + "\n"
        )

    if valid_exit:
        _write(
            scratch / "depth_exit.md",
            "criterion: 1\n"
            "rationale: depth loop completed normally\n"
            "explored_paths:\n"
            "- consensus path\n"
            "- network path\n"
            "- state path\n"
        )
    else:
        _write(
            scratch / "depth_exit.md",
            "criterion: 4\n"
            "rationale:\n"
            "explored_paths:\n"
            "- only one path\n"
        )


def stub_run_phase(phase, config, attempt):
    scratch = Path(config["scratchpad"])
    with CALL_LOG.open("a", encoding="utf-8") as f:
        f.write(f"{phase.name}:{attempt}\n")

    # Scenario K invariant for crossbatch phase: write the consistency stub
    # ONLY when the crossbatch phase fires, not earlier — phase containment
    # detector flags pre-emption otherwise.
    if SCENARIO == "K" and phase.name == "crossbatch":
        ids = [f"INV-{i:03d}" for i in range(1, 7)]
        cb_lines = [
            "# Cross-Batch Consistency", "",
            f"Files checked: {len(ids)}", "Overall: PASS", "",
            "| Finding ID | Severity | Status |",
            "|------------|----------|--------|",
        ]
        cb_lines.extend(f"| {fid} | Low | CONSISTENT |" for fid in ids)
        _write(scratch / "cross_batch_consistency.md",
               "\n".join(cb_lines) + "\n")
        return 0

    # Phase E11: body-writer phase stubs for K. Body writer must produce a
    # tier file whose report IDs match the manifest. K's findings are all
    # Low, so only report_low_info needs real content; the other tier
    # files satisfy soft-pass with empty manifest.
    if SCENARIO == "K" and phase.name == "report_body_writer_low_info":
        # Driver has already written body_manifests/report_low_info.json
        # by this point (report_index is upstream). Read it and emit a
        # body file with the exact report IDs the manifest expects.
        manifest_path = scratch / "body_manifests" / "report_low_info.json"
        if manifest_path.exists():
            try:
                manifest = json.loads(
                    manifest_path.read_text(encoding="utf-8")
                )
            except Exception:
                manifest = {"findings": []}
        else:
            manifest = {"findings": []}
        out_lines = ["# Low and Informational Findings", "", "## Low Findings", ""]
        for f in manifest.get("findings", []):
            out_lines.extend([
                f"### [{f['report_id']}] {f['title']}",
                f"**Severity**: {f['severity']}",
                f"**Location**: {f['location']}",
                f"**Evidence Tag**: {f['evidence_tag']}",
                f"**Description**: {f.get('description') or 'Stub description.'}",
                f"**Impact**: Low-severity informational stub finding from "
                "the inventory-shard smoke fixture.",
                "**PoC Result**: PASS (smoke test stub).",
                f"**Recommendation**: {f.get('recommendation') or 'N/A'}",
                "",
            ])
        _write(scratch / "report_low_info.md", "\n".join(out_lines) + "\n")
        return 0
    if SCENARIO == "K" and phase.name in (
        "report_body_writer_critical_high",
        "report_body_writer_medium_a",
        "report_body_writer_medium_b",
    ):
        # No findings in this tier — manifest is absent, body validator
        # soft-passes. File must clear min_artifact_bytes (100) to pass the
        # filename gate, so emit a substantial empty-tier note.
        out_name = phase.expected_artifacts[0]
        _write(
            scratch / out_name,
            f"# {phase.name.replace('report_body_writer_', '').title()} Findings\n\n"
            "_No findings of this severity tier were produced by the "
            "verification stage in this run. This is an authentic empty "
            "tier; it is not a placeholder for a missing finding._\n\n"
            "## Provenance\n\nManifest: absent (no report_index assignments).\n"
            f"Phase: {phase.name}.\nResult: validator soft-pass.\n",
        )
        return 0

    # Scenario K invariant: as soon as the mechanical queue exists, ensure
    # matching verify_INV-NNN.md files are on disk so the new Phase E1
    # parity gate sees a complete set, and emit a complete crossbatch
    # consistency stub so the new E3 coverage gate also passes. Idempotent.
    if SCENARIO == "K":
        queue_path = scratch / "verification_queue.md"
        if queue_path.exists():
            ids = [f"INV-{i:03d}" for i in range(1, 7)]
            for fid in ids:
                target = scratch / f"verify_{fid}.md"
                if target.exists():
                    continue
                _write(
                    target,
                    f"# {fid}\n\n"
                    "**Verdict**: CONFIRMED\n"
                    "**Severity**: Low\n"
                    "**Impact**: Low\n"
                    "**Likelihood**: Medium\n"
                    f"**Location**: src/Stub.sol:L{10 + int(fid.split('-')[1])}\n"
                    "**Description**: Stub low-severity finding for "
                    "inventory shard smoke test.\n"
                    "**Recommendation**: N/A — smoke test stub.\n"
                    "**Evidence Tag**: CODE-TRACE\n"
                    "**Preferred Tag**: CODE-TRACE\n",
                )
            # cross_batch_consistency.md emission moved to the explicit
            # `crossbatch` phase stub above to avoid phase-containment
            # false-positive flags from earlier phases.

    if phase.name == "recon":
        names = _L1_RECON_ARTIFACTS if config["pipeline"] == "l1" else _RECON_ARTIFACTS
        recon_body = (
            "# Recon Smoke Artifact\n\n"
            "This fixture intentionally contains enough structured content "
            "to satisfy the recon artifact gate after recon became critical.\n\n"
            "## Files Cited\n\n"
            "- src/Stub.sol\n\n"
            "## Scope\n\n"
            "All smoke-test modules are synthetic and in scope.\n\n"
            "## Notes\n\n"
            "No production vulnerability conclusions are encoded here.\n"
            "The synthetic source tree contains a single contract file, so "
            "the audit surface, contract inventory, function list, state "
            "variables, template recommendations, and build record all point "
            "to src/Stub.sol. The generated artifacts are deliberately concise "
            "but complete for exercising driver phase transitions, retry "
            "handling, and gate behavior in isolation from real tooling.\n"
        )
        build_status_body = (
            "# Build Status\n\n"
            "## Status\n\n"
            "Build command: smoke-fixture build check.\n"
            "Result: SKIPPED - synthetic test project uses generated source "
            "files and does not invoke forge, hardhat, cargo, move, slither, "
            "aderyn, or opengrep.\n\n"
            "## Fallback\n\n"
            "Static-analysis fallback: source fixture src/Stub.sol was cited "
            "by recon artifacts. This is a substantive status record for the "
            "driver smoke suite, not a production audit result.\n"
        )
        # Specialized bodies for content-structure gate (v2.1.9)
        attack_surface_body = (
            "# Attack Surface\n\n"
            "## External Entry Points\n\n"
            "- `deposit()` — permissionless, accepts ETH\n"
            "- `withdraw()` — permissionless, sends ETH\n\n"
            "## Public Functions\n\n"
            "- `balanceOf(address)` — view\n\n"
            "## Attack Vectors\n\n"
            "Reentrancy on withdraw path.\n"
        )
        design_context_body = (
            "# Design Context\n\n"
            "## Key Invariants\n\n"
            "1. totalSupply == sum(balances)\n\n"
            "## Operational Implications\n\n"
            "The supply invariant means deposit/withdraw must update both "
            "totalSupply and the user balance atomically.\n\n"
            "## Architecture\n\nSingle-contract vault pattern.\n"
        )
        for name in names:
            if name == "scope_leftover.md":
                _write(
                    scratch / name,
                    "# Scope Leftover\n\n"
                    "This smoke fixture has no uncovered production files. "
                    "The table is intentionally empty because all synthetic "
                    "modules are covered by the recon artifacts.\n\n"
                    "| File | LOC | Reason | Status |\n"
                    "|------|-----|--------|--------|\n"
                    "\n"
                    "Gate note: substantial non-stub scope ledger for "
                    "critical recon smoke tests.\n"
                    "\n",
                )
            elif name == "attack_surface.md":
                _write(scratch / name, attack_surface_body)
            elif name == "build_status.md":
                _write(scratch / name, build_status_body)
            elif name == "design_context.md":
                _write(scratch / name, design_context_body)
            else:
                _write(scratch / name, recon_body)
        if config["pipeline"] == "l1":
            _write(
                scratch / "subsystem_map.md",
                "# Subsystem Map\n\n"
                "## Core\n\n- src/Stub.sol\n\n"
                "## Network\n\n- src/Stub.sol\n\n"
                "## Scope\n\nSynthetic smoke fixture; all modules acknowledged.\n",
            )
        return 0

    if phase.name == "bake":
        _write(scratch / "primitive_status.md", _STUB_BODY)
        return 0

    if phase.name == "instantiate":
        # Scenarios B and C use five rows for manifest-exact quorum. Other
        # scenarios still need a valid producer manifest now that instantiate
        # owns schema validation.
        body = _MANIFEST_5_ROWS if SCENARIO in ("B", "C") else _MANIFEST_1_ROW
        _write(scratch / "spawn_manifest.md", body)
        return 0

    if phase.name == "breadth":
        if SCENARIO == "A":
            # Silent. No analysis_*.md written -> glob gate fails.
            return 0
        if SCENARIO == "B":
            # 3 of 5. Passes the fallback floor of 3 but fails the
            # manifest-exact gate of 5.
            for name in _MANIFEST_5_OUTPUTS[:3]:
                _write(scratch / name, _STUB_BODY)
            return 0
        if SCENARIO == "C":
            # Pass the manifest-exact gate comfortably (5 files). Fresh
            # mode requires COMPLETE markers + ## Findings structure.
            for name in _MANIFEST_5_OUTPUTS:
                _write(scratch / name, _breadth_marked(name, _ANALYSIS_LOW_ONLY, 2))
            return 0
        if SCENARIO in ("D", "E", "F", "G", "I"):
            for i in range(5):
                _write(scratch / f"analysis_agent_{i}.md", _ANALYSIS_LOW_ONLY)
            return 0
        if SCENARIO == "K":
            for i in range(6):
                _write(
                    scratch / f"analysis_agent_{i}.md",
                    _analysis_low_unique(f"F-{i+1}", 10 + i),
                )
            return 0
        if SCENARIO == "H":
            for i in range(3):
                _write(scratch / f"analysis_agent_{i}.md", _ANALYSIS_MEDIUM_ONE)
            return 0

    if phase.name == "depth":
        # depth is critical and needs >=3 substantial depth_*_findings.md.
        # Scenario C requires clearing this to reach verify short-circuit.
        if SCENARIO == "K":
            _write(scratch / "depth_consensus_invariant_findings.md", _DEPTH_COMPLETE_BODY)
            _write(scratch / "depth_network_surface_findings.md", _DEPTH_COMPLETE_BODY)
            _write(scratch / "depth_state_trace_findings.md", _DEPTH_COMPLETE_BODY)
            _write(scratch / "depth_external_findings.md", _DEPTH_COMPLETE_BODY)
            _write(scratch / "depth_edge_case_findings.md", _DEPTH_COMPLETE_BODY)
            _write_depth_support_artifacts(scratch)
            _write(
                scratch / "depth_exit.md",
                "\n".join([
                    "- criterion: 1",
                    "  verdict: PASS",
                    "  rationale: Stub depth coverage satisfied for shard smoke test.",
                    "  explored_paths:",
                    "    - src/Stub.sol:L10",
                    "    - src/Stub.sol:L11",
                    "    - src/Stub.sol:L12",
                ]) + "\n"
            )
            return 0
        if SCENARIO == "D":
            _write(scratch / "depth_consensus_invariant_findings.md", _DEPTH_COMPLETE_BODY)
            _write(scratch / "depth_network_surface_findings.md", _DEPTH_COMPLETE_BODY)
            _write(scratch / "depth_state_trace_findings.md", _DEPTH_COMPLETE_BODY)
            _write_depth_support_artifacts(scratch)
            return 0
        if SCENARIO == "E":
            _write(scratch / "depth_consensus_invariant_findings.md", _DEPTH_COMPLETE_BODY)
            _write(scratch / "depth_network_surface_findings.md", _DEPTH_COMPLETE_BODY)
            _write(scratch / "depth_state_trace_findings.md", _DEPTH_COMPLETE_BODY)
            _write(scratch / "depth_external_findings.md", _DEPTH_COMPLETE_BODY)
            _write(scratch / "depth_edge_case_findings.md", _DEPTH_COMPLETE_BODY)
            _write_depth_support_artifacts(scratch)
            with (scratch / "violations.md").open("a", encoding="utf-8") as f:
                f.write("[GATE FAIL] depth_consensus_invariant: 0 pre-baked reads (need >=2)\n")
            return 0
        if SCENARIO == "F":
            _write(scratch / "depth_consensus_invariant_findings.md", _DEPTH_COMPLETE_BODY)
            _write(scratch / "depth_network_surface_findings.md", _DEPTH_COMPLETE_BODY)
            _write(scratch / "depth_state_trace_findings.md", _DEPTH_COMPLETE_BODY)
            _write(scratch / "depth_external_findings.md", _DEPTH_COMPLETE_BODY)
            _write(scratch / "depth_edge_case_findings.md", _DEPTH_COMPLETE_BODY)
            _write_depth_support_artifacts(
                scratch, valid_checkpoint=False, include_skill_gap=False
            )
            return 0
        if SCENARIO == "G":
            _write(scratch / "depth_consensus_invariant_findings.md", _DEPTH_COMPLETE_BODY)
            _write(scratch / "depth_network_surface_findings.md", _DEPTH_COMPLETE_BODY)
            _write(scratch / "depth_state_trace_findings.md", _DEPTH_COMPLETE_BODY)
            _write(scratch / "depth_external_findings.md", _DEPTH_COMPLETE_BODY)
            _write(scratch / "depth_edge_case_findings.md", _DEPTH_COMPLETE_BODY)
            _write_depth_support_artifacts(scratch, valid_exit=False)
            return 0
        if SCENARIO == "H":
            _write(scratch / "depth_consensus_invariant_findings.md", _DEPTH_COMPLETE_BODY)
            _write(scratch / "depth_network_surface_findings.md", _DEPTH_COMPLETE_BODY)
            _write(scratch / "depth_state_trace_findings.md", _DEPTH_COMPLETE_BODY)
            _write(scratch / "depth_external_findings.md", _DEPTH_COMPLETE_BODY)
            _write(scratch / "depth_edge_case_findings.md", _DEPTH_COMPLETE_BODY)
            _write_depth_support_artifacts(scratch)
            return 0
        for role in ("token_flow", "state_trace", "edge_case", "external"):
            _write(scratch / f"depth_{role}_findings.md", _DEPTH_COMPLETE_BODY)
        if SCENARIO == "C":
            _write_depth_support_artifacts(scratch)
        return 0

    if phase.name == "inventory":
        # Scenario C wants zero Medium+ markers so verify short-circuits.
        if SCENARIO == "K":
            _write(
                scratch / "findings_inventory.md",
                "# Findings Inventory\n\n"
                "| Finding ID | Severity | Title | Source IDs | Location |\n"
                "|-----------|----------|-------|------------|----------|\n"
                "| F-1 | Low | one | F-1 | src/Stub.sol:L10 |\n"
                "| F-2 | Low | two | F-2 | src/Stub.sol:L11 |\n"
                "| F-3 | Low | three | F-3 | src/Stub.sol:L12 |\n"
                "| F-4 | Low | four | F-4 | src/Stub.sol:L13 |\n"
                "| F-5 | Low | five | F-5 | src/Stub.sol:L14 |\n"
                "| F-6 | Low | six | F-6 | src/Stub.sol:L15 |\n"
            )
            # Phase E1 parity: scenario K runs in LIGHT mode, so verify
            # shard phases (modes={"thorough"}) never fire. Write the verify
            # files here so the aggregate parity gate sees a complete set.
            for fid in (f"INV-{i:03d}" for i in range(1, 7)):
                _write(
                    scratch / f"verify_{fid}.md",
                    f"# {fid}\n\n"
                    "**Verdict**: CONFIRMED\n"
                    "**Severity**: Low\n"
                    "**Impact**: Low\n"
                    "**Likelihood**: Medium\n"
                    f"**Location**: src/Stub.sol:L{10 + int(fid.split('-')[1])}\n"
                    "**Description**: Stub low-severity finding for "
                    "inventory shard smoke test.\n"
                    "**Recommendation**: N/A — smoke test stub.\n"
                    "**Evidence Tag**: CODE-TRACE\n"
                    "**Preferred Tag**: CODE-TRACE\n",
                )
            return 0
        if SCENARIO == "H":
            body = _INVENTORY_MEDIUM_THREE
        else:
            body = _INVENTORY_LOW_ONLY if SCENARIO in ("C", "D", "E", "F", "G", "I") else _STUB_BODY
        _write(scratch / "findings_inventory.md", body)
        if SCENARIO == "I":
            _write(scratch / "semantic_invariants.md", _STUB_BODY)
            _write(scratch / "depth_agent_0_findings.md", _STUB_BODY)
        return 0

    if phase.name == "inventory_chunk_a" and SCENARIO == "K":
        _write(
            scratch / "findings_inventory_chunk_a.md",
            "# Findings Inventory Chunk A\n\n"
            "| Finding ID | Severity | Title | Source IDs | Location |\n"
            "|-----------|----------|-------|------------|----------|\n"
            "| F-1 | Low | one | F-1 | src/Stub.sol:L10 |\n"
            "| F-2 | Low | two | F-2 | src/Stub.sol:L11 |\n"
            "| F-3 | Low | three | F-3 | src/Stub.sol:L12 |\n"
        )
        return 0
    if phase.name == "inventory_chunk_b" and SCENARIO == "K":
        _write(
            scratch / "findings_inventory_chunk_b.md",
            "# Findings Inventory Chunk B\n\n"
            "| Finding ID | Severity | Title | Source IDs | Location |\n"
            "|-----------|----------|-------|------------|----------|\n"
            "| F-4 | Low | four | F-4 | src/Stub.sol:L13 |\n"
            "| F-5 | Low | five | F-5 | src/Stub.sol:L14 |\n"
            "| F-6 | Low | six | F-6 | src/Stub.sol:L15 |\n"
        )
        return 0

    if phase.name == "invariants":
        _write(scratch / "semantic_invariants.md", _STUB_BODY)
        if SCENARIO in ("D", "E"):
            _write(scratch / "phase4b_manifest.md", _DEPTH_MANIFEST_5_ROWS)
            _write(scratch / "violations.md", "# test violations\n",)
        return 0

    if phase.name == "chain":
        # hypotheses.md is the preferred severity-count source. In C we
        # want it present (so is_verification_queue_empty uses it) and
        # clean of Medium+ markers.
        body = _INVENTORY_LOW_ONLY if SCENARIO == "C" else _STUB_BODY
        _write(scratch / "hypotheses.md", body)
        _write(scratch / "finding_mapping.md", _STUB_BODY)
        _write(scratch / "enabler_results.md", _STUB_BODY)
        return 0

    if phase.name == "inventory" and SCENARIO == "H":
        _write(scratch / "findings_inventory.md", _INVENTORY_MEDIUM_THREE)
        return 0

    if phase.name == "verify_queue" and SCENARIO == "H":
        _write(
            scratch / "verification_queue.md",
            "# Verification Queue Manifest\n"
            "| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact |\n"
            "|---------|-----------|----------|-------|-----------|--------------|----------|------------------|\n"
            "| 1 | F-1 | Medium | one | class | [CODE-TRACE] | src/Stub.sol:L10 | findings_inventory.md |\n"
            "| 2 | F-2 | Medium | two | class | [CODE-TRACE] | src/Stub.sol:L20 | findings_inventory.md |\n"
            "| 3 | F-3 | Medium | three | class | [CODE-TRACE] | src/Stub.sol:L30 | findings_inventory.md |\n"
            "Total: 3 findings | Expected verify_F-*.md files: 3\n"
        )
        return 0
    if phase.name == "verify_medium_a" and SCENARIO == "H":
        _write(
            scratch / "verify_F-01.md",
            "Preferred Tag: [CODE-TRACE]\nEvidence Tag: [CODE-TRACE]\n"
            "Verdict: CONFIRMED\nEvidence details: " + "trace " * 20 + "\n"
        )
        _write(
            scratch / "verify_F-02.md",
            "Preferred Tag: [CODE-TRACE]\nEvidence Tag: [CODE-TRACE]\n"
            "Verdict: CONFIRMED\nEvidence details: " + "trace " * 20 + "\n"
        )
        return 0

    # Scenario K: after inventory sharding, the mechanical queue route
    # generates 6 active rows (INV-001..INV-006). The new Phase E1 parity
    # gate requires a verify file per row before verify_aggregate /
    # report_index. The smoke test isn't validating the verify-shard agent;
    # write valid stubs here so the gate sees parity. NOT a weakening of
    # E1 — the gate fires correctly when these files are absent.
    if SCENARIO == "K" and phase.name in (
        "verify_low_a", "verify_low_b", "verify_low_c", "verify_low_d",
        "verify_medium_a", "verify_medium_b", "verify_medium_c",
        "verify_medium_d", "verify_medium_e", "verify_medium_f",
        "verify_crithigh", "verify_high_b", "verify_high_c",
        "verify_high_d", "verify_high_e", "verify_high_f",
        "verify_high_g", "verify_high_h", "verify_high_i", "verify_high_j",
    ):
        for fid in (f"INV-{i:03d}" for i in range(1, 7)):
            target = scratch / f"verify_{fid}.md"
            if target.exists():
                continue
            _write(
                target,
                f"# {fid}\n\n"
                "**Verdict**: CONFIRMED\n"
                "**Severity**: Low\n"
                "**Impact**: Low\n"
                "**Likelihood**: Medium\n"
                f"**Location**: src/Stub.sol:L{10 + int(fid.split('-')[1])}\n"
                "**Description**: Stub low-severity finding for inventory "
                "shard smoke test.\n"
                "**Recommendation**: N/A — smoke test stub.\n"
                "**Evidence Tag**: CODE-TRACE\n"
                "**Preferred Tag**: CODE-TRACE\n",
            )
        return 0

    # Fallback: satisfy the phase's expected_artifacts so we don't
    # accidentally halt on an unrelated phase.
    for pattern in phase.expected_artifacts:
        if any(c in pattern for c in "*?["):
            _write(scratch / pattern.replace("*", "stub"), _STUB_BODY)
        elif pattern == "AUDIT_REPORT.md":
            _write(Path(config["project_root"]) / "AUDIT_REPORT.md",
                   _STUB_BODY)
        else:
            _write(scratch / pattern, _STUB_BODY)
    return 0


pd.run_phase = stub_run_phase
pd.detect_rate_limit = lambda _p: False
# Verify-recovery is an inter-phase worker subprocess, not routed through
# run_phase. Keep this phase-loop smoke harness hermetic: return the missing IDs
# so the deterministic stub/degrade path is exercised without launching a real
# Claude/Codex process.
pd._run_verify_recovery_shard = lambda _config, missing: [
    fid for fid, _row in missing
]

sys.argv = ["plamen_driver.py", r'__CONFIG_PATH__']
try:
    pd.main()
except SystemExit as e:
    sys.exit(int(e.code or 0))
sys.exit(0)
"""


# ---------- harness ----------

def _run_driver(tmp: Path, config_path: Path, call_log: Path,
                scenario: str) -> int:
    script = (RUNNER_TEMPLATE
              .replace("__SCRIPTS_DIR__", str(SCRIPTS_DIR))
              .replace("__CALL_LOG__", str(call_log))
              .replace("__CONFIG_PATH__", str(config_path))
              .replace("__SCENARIO__", scenario))
    # Write the runner to a temp file rather than passing it inline via
    # `python -c "<script>"`. The template grows as the pipeline gains
    # phases/fixtures and on Windows an inline `-c` argument is capped at
    # ~32K chars (CreateProcess lpCommandLine -> WinError 206 "filename or
    # extension is too long"). A temp file has no such limit.
    runner_path = tmp / "_smoke_runner.py"
    runner_path.write_text(script, encoding="utf-8")
    # This lane validates phase-loop behavior, not installed tool discovery.
    # The dedicated audit-snapshot tests cover executable binding.  An empty
    # PATH makes every optional tool deterministically UNAVAILABLE and avoids
    # paying a real CLI startup cost in each isolated smoke subprocess.
    empty_path = tmp / "_empty_path"
    empty_path.mkdir(exist_ok=True)
    child_env = dict(os.environ)
    child_env["PATH"] = str(empty_path)
    proc = subprocess.run(
        [sys.executable, str(runner_path)],
        capture_output=True,
        text=True,
        cwd=str(tmp),
        env=child_env,
        # A production startup traversal bug once left this integration lane
        # waiting forever and orphaned the child when only the outer pytest
        # process was killed. Keep every scenario self-bounding so a future
        # regression fails as a TimeoutExpired error instead of masking the
        # rest of the integration baseline.
        timeout=120,
    )
    sys.stdout.write(proc.stdout)
    sys.stderr.write(proc.stderr)
    return proc.returncode


def _assert(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


def _make_project(prefix: str, mode: str = "light",
                  pipeline: str = "sc",
                  extra_config: dict | None = None) -> tuple:
    tmp = Path(tempfile.mkdtemp(prefix=prefix))
    project = tmp / "project"
    scratch = project / ".scratchpad"
    project.mkdir()
    scratch.mkdir()
    source_dir = project / "src"
    source_dir.mkdir()
    if pipeline == "l1":
        (source_dir / "node.rs").write_text(
            "pub fn process_block() -> bool { true }\n",
            encoding="utf-8",
        )
    else:
        (source_dir / "Protocol.sol").write_text(
            "// SPDX-License-Identifier: MIT\n"
            "pragma solidity ^0.8.20;\n"
            "contract Protocol { function ready() external pure returns (bool) { return true; } }\n",
            encoding="utf-8",
        )

    config = {
        "project_root": str(project),
        "scratchpad": str(scratch),
        "language": "rust" if pipeline == "l1" else "evm",
        "mode": mode,
        "pipeline": pipeline,
    }
    if extra_config:
        config.update(extra_config)
    cfg_path = tmp / "config.json"
    cfg_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    call_log = scratch / "_stub_calls.log"
    return tmp, project, scratch, cfg_path, call_log


# ---------- scenarios ----------

@pytest.mark.integration
def test_scenario_a_breadth_halt_and_resume() -> None:
    """Breadth critical halt + resume retry."""
    tmp, project, scratch, cfg_path, call_log = _make_project("plamen_smoke_a_")
    try:
        # Run 1: expect halt
        rc = _run_driver(tmp, cfg_path, call_log, "A")
        _assert(rc == 3, f"A.run1 exit: got {rc}, expected 3 (EXIT_DEGRADED)")

        ckpt = json.loads(
            (scratch / "_v2_checkpoint.json").read_text(encoding="utf-8")
        )
        _assert("breadth" not in ckpt["completed"],
                f"A.run1: 'breadth' must NOT be completed; got {ckpt['completed']}")
        _assert("breadth" in ckpt["degraded"],
                f"A.run1: 'breadth' must be degraded; got {ckpt['degraded']}")
        _assert("recon" in ckpt["completed"] and "instantiate" in ckpt["completed"],
                f"A.run1: recon/instantiate should complete; got {ckpt['completed']}")
        _assert((scratch / "breadth.degraded").exists(),
                "A.run1: breadth.degraded marker missing")

        breadth_attempts = [c for c in call_log.read_text(encoding="utf-8").splitlines()
                            if c.startswith("breadth:")]
        _assert(len(breadth_attempts) == 3,
                f"A.run1: breadth is a RECOVERING phase -> 3 hinted attempts before "
                f"degrade (all-backend extended retry budget); got {breadth_attempts}")

        # Run 2: resume, expect breadth retried, recon/instantiate skipped
        call_log.write_text("", encoding="utf-8")
        rc2 = _run_driver(tmp, cfg_path, call_log, "A")
        _assert(rc2 == 3, f"A.run2 exit: got {rc2}, expected 3 (still degraded)")

        calls2 = call_log.read_text(encoding="utf-8").splitlines()
        _assert(len([c for c in calls2 if c.startswith("breadth:")]) == 3,
                f"A.run2: breadth (recovering) retries to 3 hinted attempts; got {calls2}")
        _assert(len([c for c in calls2 if c.startswith("recon:")]) == 0,
                f"A.run2: recon must NOT rerun; got {calls2}")
        _assert(len([c for c in calls2 if c.startswith("instantiate:")]) == 0,
                f"A.run2: instantiate must NOT rerun; got {calls2}")

        print("[scenario A] PASS")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@pytest.mark.integration
def test_scenario_b_manifest_quorum() -> None:
    """Manifest-aware quorum override (3 of 5)."""
    tmp, project, scratch, cfg_path, call_log = _make_project("plamen_smoke_b_")
    try:
        rc = _run_driver(tmp, cfg_path, call_log, "B")
        # Breadth writes 3 files, manifest declares 5 -> gate fails both attempts
        _assert(rc == 3, f"B exit: got {rc}, expected 3 (manifest quorum halt)")

        # Verify 3 analysis files are actually on disk — this confirms
        # the halt was due to quorum, not a hardcoded 3-floor failure.
        analysis_files = list(scratch.glob("analysis_*.md"))
        _assert(len(analysis_files) == 3,
                f"B: expected 3 analysis_*.md on disk; got {len(analysis_files)}")

        # Manifest override must have logged the ratchet. Look at stderr
        # (captured into our own stderr by _run_driver). Instead of
        # grepping stderr, check behavior: breadth must be degraded,
        # not completed.
        ckpt = json.loads(
            (scratch / "_v2_checkpoint.json").read_text(encoding="utf-8")
        )
        _assert("breadth" in ckpt["degraded"],
                f"B: breadth must be degraded; got {ckpt['degraded']}")
        _assert("breadth" not in ckpt["completed"],
                f"B: breadth must NOT be completed; got {ckpt['completed']}")
        _assert((scratch / "breadth.degraded").exists(),
                "B: breadth.degraded marker missing")

        # Sanity: parse_breadth_manifest_count returns 5 for our manifest.
        import sys as _s
        _s.path.insert(0, str(SCRIPTS_DIR))
        import plamen_driver as _pd
        parsed = _pd.parse_breadth_manifest_count(scratch)
        _assert(parsed == 5,
                f"B: parse_breadth_manifest_count should return 5; got {parsed}")

        print("[scenario B] PASS")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@pytest.mark.integration
def test_scenario_c_empty_verify_shortcircuit() -> None:
    """Empty-verify short-circuit (0 Medium+ findings).

    Verifies that when findings are all Low/Info, the verify shards
    complete (short-circuit or trivial pass) and the pipeline proceeds
    through to report_assemble.
    """
    tmp, project, scratch, cfg_path, call_log = _make_project("plamen_smoke_c_")
    try:
        rc = _run_driver(tmp, cfg_path, call_log, "C")
        _assert(rc == 0, f"C exit: got {rc}, expected 0 (pipeline completed)")

        ckpt = json.loads(
            (scratch / "_v2_checkpoint.json").read_text(encoding="utf-8")
        )
        # Verify phases are now sharded (sc_verify_*). Check that at least
        # one verify-related phase completed and none degraded.
        verify_completed = [p for p in ckpt["completed"]
                           if "verify" in p]
        _assert(len(verify_completed) > 0,
                f"C: at least one verify phase must complete; got {ckpt['completed']}")
        verify_degraded = [p for p in ckpt.get("degraded", [])
                          if "verify" in p]
        _assert(len(verify_degraded) == 0,
                f"C: no verify phase should be degraded; got {verify_degraded}")

        # Report must have completed (proves pipeline continued past verify).
        _assert("report_assemble" in ckpt["completed"],
                f"C: report_assemble should complete; got {ckpt['completed']}")
        _assert((project / "AUDIT_REPORT.md").exists(),
                "C: AUDIT_REPORT.md missing — report phase did not run")

        print("[scenario C] PASS")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@pytest.mark.integration
def test_scenario_d_depth_manifest_quorum() -> None:
    """Depth manifest-aware quorum override (3 of 5)."""
    tmp, project, scratch, cfg_path, call_log = _make_project(
        "plamen_smoke_d_", pipeline="l1"
    )
    try:
        rc = _run_driver(tmp, cfg_path, call_log, "D")
        _assert(rc == 3, f"D exit: got {rc}, expected 3 (depth quorum halt)")

        depth_files = list(scratch.glob("depth*_findings.md"))
        _assert(len(depth_files) == 3,
                f"D: expected 3 depth*_findings.md on disk; got {len(depth_files)}")

        ckpt = json.loads(
            (scratch / "_v2_checkpoint.json").read_text(encoding="utf-8")
        )
        _assert("depth" in ckpt["degraded"],
                f"D: depth must be degraded; got {ckpt['degraded']}")
        _assert("depth" not in ckpt["completed"],
                f"D: depth must NOT be completed; got {ckpt['completed']}")

        import sys as _s
        _s.path.insert(0, str(SCRIPTS_DIR))
        import plamen_driver as _pd
        parsed = _pd.parse_depth_manifest_count(scratch)
        _assert(parsed == 5,
                f"D: parse_depth_manifest_count should return 5; got {parsed}")

        print("[scenario D] PASS")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@pytest.mark.integration
def test_scenario_e_depth_gatefail_enforced() -> None:
    """Depth pre-baked gatefail -> degrade-and-continue (v2.8.16).

    L1 depth used to force-halt on a tail-artifact/violation gap. v2.8.16
    makes L1 mirror SC: when the 5 core depth role findings are present, the
    driver retries once, runs one S1.5 targeted-repair attempt (3 depth calls
    total), marks depth degraded, then DEGRADES-AND-CONTINUES instead of
    halting. The audit must progress past depth on the core findings
    (haltless-on-any-mode goal). Any later non-zero exit comes from a
    downstream stub-artifact gap, not from depth policy.
    """
    tmp, project, scratch, cfg_path, call_log = _make_project(
        "plamen_smoke_e_", pipeline="l1"
    )
    try:
        _run_driver(tmp, cfg_path, call_log, "E")

        calls = call_log.read_text(encoding="utf-8").splitlines()
        depth_calls = [c for c in calls if c.startswith("depth:")]
        _assert(len(depth_calls) == 3,
                f"E: depth should retry once + one S1.5 repair (3 calls); got {depth_calls}")

        ckpt = json.loads(
            (scratch / "_v2_checkpoint.json").read_text(encoding="utf-8")
        )
        _assert("depth" in ckpt["degraded"],
                f"E: depth must be degraded; got {ckpt['degraded']}")
        _assert("depth" not in ckpt.get("completed", []),
                f"E: degraded depth must not be completed; got {ckpt.get('completed')}")
        _assert((scratch / "depth.degraded").exists(),
                "E: depth.degraded marker missing")
        # The defining v2.8.16 contract: the pipeline does NOT halt at depth.
        # It continues to the post-depth phase (verify_queue) on the core findings.
        _assert("verify_queue" in ckpt.get("completed", []),
                f"E: pipeline must continue past degraded depth; completed={ckpt.get('completed')}")

        print("[scenario E] PASS")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@pytest.mark.integration
def test_scenario_f_never_cut_enforced() -> None:
    """Never-cut tail-gap on depth -> degrade-and-continue (v2.8.16, Thorough).

    F omits a required post-depth artifact + checkpoint entry. As with E,
    L1 depth no longer force-halts: it retries once + one S1.5 repair (3 depth
    calls), marks depth degraded, then continues to the later thorough-mode
    phases (attention_repair runs after depth) on the core findings.
    """
    tmp, project, scratch, cfg_path, call_log = _make_project(
        "plamen_smoke_f_", pipeline="l1", mode="thorough"
    )
    try:
        _run_driver(tmp, cfg_path, call_log, "F")

        calls = call_log.read_text(encoding="utf-8").splitlines()
        depth_calls = [c for c in calls if c.startswith("depth:")]
        _assert(len(depth_calls) == 3,
                f"F: depth should retry once + one S1.5 repair (3 calls); got {depth_calls}")

        ckpt = json.loads(
            (scratch / "_v2_checkpoint.json").read_text(encoding="utf-8")
        )
        _assert("depth" in ckpt["degraded"],
                f"F: depth must be degraded; got {ckpt['degraded']}")
        _assert("depth" not in ckpt.get("completed", []),
                f"F: degraded depth must not be completed; got {ckpt.get('completed')}")
        # Haltless: depth degrades and the pipeline advances to a later
        # thorough-mode phase (attention_repair is invoked after depth).
        _assert(any(c.startswith("attention_repair:") for c in calls),
                f"F: pipeline must continue past degraded depth; calls={calls}")

        print("[scenario F] PASS")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@pytest.mark.integration
def test_scenario_g_depth_exit_validation() -> None:
    """Depth exit validation — now a warning (v2.8.0).

    _validate_depth_exit was downgraded from hard fail to log.warning.
    Depth should complete (not degrade) even with an invalid exit artifact.
    The pipeline continues beyond depth.
    """
    tmp, project, scratch, cfg_path, call_log = _make_project(
        "plamen_smoke_g_", pipeline="l1"
    )
    try:
        rc = _run_driver(tmp, cfg_path, call_log, "G")

        calls = call_log.read_text(encoding="utf-8").splitlines()
        depth_calls = [c for c in calls if c.startswith("depth:")]
        _assert(len(depth_calls) == 1,
                f"G: depth should pass on first attempt (exit is now warning); got {depth_calls}")

        ckpt = json.loads(
            (scratch / "_v2_checkpoint.json").read_text(encoding="utf-8")
        )
        _assert("depth" in ckpt["completed"],
                f"G: depth must be completed (exit validation is now warning); got completed={ckpt['completed']}")
        _assert("depth" not in ckpt.get("degraded", []),
                f"G: depth must NOT be degraded; got degraded={ckpt.get('degraded', [])}")

        print("[scenario G] PASS")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@pytest.mark.integration
def test_scenario_h_verify_completeness_gate() -> None:
    """Verify completeness gate."""
    tmp, project, scratch, cfg_path, call_log = _make_project(
        "plamen_smoke_h_", pipeline="l1"
    )
    try:
        _write = lambda p, t: Path(p).write_text(t, encoding="utf-8")
        (project / "src").mkdir(parents=True, exist_ok=True)
        _write(project / "src" / "Stub.sol", ("contract Stub {}\n" * 40))
        _write(
            scratch / "findings_inventory.md",
            "# Findings Inventory\n\n"
            "### Finding [F-01]\n"
            "**Severity**: Medium\n"
            "**Location**: src/Stub.sol:L10\n"
            "Medium finding one.\n\n"
            "### Finding [F-02]\n"
            "**Severity**: Medium\n"
            "**Location**: src/Stub.sol:L20\n"
            "Medium finding two.\n\n"
            "### Finding [F-03]\n"
            "**Severity**: Medium\n"
            "**Location**: src/Stub.sol:L30\n"
            "Medium finding three.\n",
        )
        rc = _run_driver(tmp, cfg_path, call_log, "H")
        _assert(rc == 3, f"H exit: got {rc}, expected 3 (degraded verification)")

        ckpt = json.loads(
            (scratch / "_v2_checkpoint.json").read_text(encoding="utf-8")
        )
        _assert("verify_medium_a" in ckpt["degraded"],
                f"H: verify_medium_a must be degraded; got {ckpt['degraded']}")
        _assert("verify_medium_a" not in ckpt["completed"],
                f"H: verify_medium_a must NOT be completed; got {ckpt['completed']}")
        _assert((scratch / "verify_medium_a.degraded").exists(),
                "H: verify_medium_a.degraded marker missing")
        recovery_stub = scratch / "verify_F-03.md"
        _assert(recovery_stub.exists(),
                "H: missing F-3 must receive a deterministic unverified stub")
        _assert("VERIFICATION NOT EXECUTED" in recovery_stub.read_text(encoding="utf-8"),
                "H: F-3 recovery stub must disclose that verification did not run")
        _assert("Verdict: CONFIRMED" in (scratch / "verify_F-01.md").read_text(encoding="utf-8"),
                "H: a present verifier result must not be overwritten by recovery")
        print("[scenario H] PASS")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@pytest.mark.integration
def test_scenario_i_phase_containment_detector() -> None:
    """Phase-containment detector.

    Inventory writes later-phase artifacts. That phase-boundary violation is
    a hard failure signal even if inventory's own required artifact exists:
    the driver must retry inventory, then degrade/halt instead of checkpointing
    inventory as clean and continuing with quarantined overflow.
    """
    tmp, project, scratch, cfg_path, call_log = _make_project(
        "plamen_smoke_i_", pipeline="l1"
    )
    try:
        rc = _run_driver(tmp, cfg_path, call_log, "I")
        _assert(rc == 3,
                f"I exit: got {rc}, expected 3 (containment hard failure)")

        ckpt = json.loads(
            (scratch / "_v2_checkpoint.json").read_text(encoding="utf-8")
        )
        _assert("inventory" in ckpt["degraded"],
                f"I: inventory must be degraded on containment failure; "
                f"got degraded={ckpt.get('degraded', [])}")
        _assert("inventory" not in ckpt["completed"],
                f"I: inventory must NOT be completed after foreign writes; "
                f"got completed={ckpt['completed']}")
        _assert((scratch / "inventory.degraded").exists(),
                "I: inventory.degraded marker missing")

        calls = call_log.read_text(encoding="utf-8").splitlines()
        inventory_calls = [c for c in calls if c.startswith("inventory:")]
        # CONTAINMENT failures are NOT hint-recoverable, so inventory does NOT
        # get the extra hinted retry here — it stays at 2 attempts and falls to
        # the standard quarantine + halt path (the extended retry budget applies
        # only to coverage/content gaps, e.g. scenario A's breadth).
        _assert(len(inventory_calls) == 2,
                f"I: inventory containment violation -> no extra hinted retry "
                f"(2 attempts), straight to quarantine+halt; got {inventory_calls}")
        depth_calls = [c for c in calls if c.startswith("depth:")]
        _assert(len(depth_calls) == 0,
                f"I: driver must halt at inventory before depth; got {depth_calls}")

        # Foreign artifacts should be quarantined to _overflow/
        overflow = scratch / "_overflow" / "inventory"
        _assert(overflow.exists(), "I: _overflow/inventory missing")
        quarantined = {p.name for p in overflow.iterdir()}
        _assert("semantic_invariants.md" in quarantined
                and "depth_agent_0_findings.md" in quarantined,
                f"I: expected foreign artifacts in overflow; got {quarantined}")
        # The foreign files should NOT remain in the main scratchpad
        _assert(not (scratch / "depth_agent_0_findings.md").exists(),
                "I: foreign artifact was NOT quarantined from scratchpad")

        print("[scenario I] PASS")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_scenario_j_breadth_model_override() -> None:
    """Breadth model override (fast, no subprocess)."""
    sys.path.insert(0, str(SCRIPTS_DIR))
    import plamen_driver as _pd
    phase = next(p for p in _pd.L1_PHASES if p.name == "breadth")
    model = _pd.phase_model(
        phase, "thorough", {"breadth_model_override": "claude-opus-4-6"}
    )
    _assert(model == "claude-opus-4-6",
            f"J: breadth override should win; got {model}")
    light_model = _pd.phase_model(
        phase, "light", {"breadth_model_override": "claude-opus-4-6"}
    )
    _assert(light_model == "sonnet",
            f"J: light mode must still force sonnet; got {light_model}")
    print("[scenario J] PASS")


@pytest.mark.integration
@pytest.mark.xfail(reason="L1 depth never-cut gate evolved past stub expectations — needs rework")
def test_scenario_k_inventory_sharding() -> None:
    """Inventory sharding."""
    tmp, project, scratch, cfg_path, call_log = _make_project(
        "plamen_smoke_k_", pipeline="l1",
        extra_config={"inventory_target_per_shard": 2, "inventory_max_shards": 3}
    )
    try:
        rc = _run_driver(tmp, cfg_path, call_log, "K")
        _assert(rc == 0, f"K exit: got {rc}, expected 0 (pipeline completed)")

        ckpt = json.loads(
            (scratch / "_v2_checkpoint.json").read_text(encoding="utf-8")
        )
        for name in ("inventory_prepare", "inventory_chunk_a", "inventory_chunk_b", "inventory"):
            _assert(name in ckpt["completed"],
                    f"K: {name} must be completed; got {ckpt['completed']}")
        _assert((scratch / "inventory_shard_plan.md").exists(),
                "K: inventory_shard_plan.md missing")
        _assert((scratch / "inventory_chunk_a.manifest.md").exists(),
                "K: inventory_chunk_a.manifest.md missing")
        _assert((scratch / "findings_inventory_chunk_a.md").exists(),
                "K: findings_inventory_chunk_a.md missing")
        _assert((scratch / "findings_inventory_chunk_b.md").exists(),
                "K: findings_inventory_chunk_b.md missing")
        _assert((scratch / "findings_inventory.md").exists(),
                "K: findings_inventory.md missing")
        _assert("inventory" not in ckpt["degraded"],
                f"K: inventory must NOT be degraded; got {ckpt['degraded']}")
        print("[scenario K] PASS")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------- entry ----------

def main() -> None:
    test_scenario_a_breadth_halt_and_resume()
    test_scenario_b_manifest_quorum()
    test_scenario_c_empty_verify_shortcircuit()
    test_scenario_d_depth_manifest_quorum()
    test_scenario_e_depth_gatefail_enforced()
    test_scenario_f_never_cut_enforced()
    test_scenario_g_depth_exit_validation()
    test_scenario_h_verify_completeness_gate()
    test_scenario_i_phase_containment_detector()
    test_scenario_j_breadth_model_override()
    test_scenario_k_inventory_sharding()
    print("\nALL PASS")


if __name__ == "__main__":
    main()
