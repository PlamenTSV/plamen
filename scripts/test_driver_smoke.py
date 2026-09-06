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
    Instantiate writes a real 5-row `spawn_manifest_proposal.md`; the typed
    driver successor publishes `spawn_manifest.md`. Breadth writes
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
     Assert chunk phases complete, all six source identities survive the
     merge exactly once, and inventory itself incurs no debt. The hermetic
     light-mode runner intentionally lacks later live composition/report
     providers, so unrelated downstream debt remains visible.

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
import sys, types, json, hashlib
from pathlib import Path
sys.path.insert(0, r'__SCRIPTS_DIR__')

# Block real recon_prepass BEFORE plamen_driver imports it.
_stub_mod = types.ModuleType("recon_prepass")
_stub_mod.run_recon_prepass = lambda cfg: "stub-prepass"
def _recon_prepass_expected_owner_prefix(cfg):
    language = str(cfg.get("language") or "unknown").strip().lower()
    ecosystem = {"solidity": "evm", "ethereum": "evm"}.get(
        language, language
    )
    return "/".join((
        str(cfg.get("pipeline") or "sc").strip().lower(),
        str(cfg.get("mode") or "core").strip().lower(),
        ecosystem,
        str(cfg.get("cli_backend") or "claude").strip().lower(),
        "recon",
    ))
_stub_mod.recon_prepass_expected_owner_prefix = (
    _recon_prepass_expected_owner_prefix
)
_stub_mod.assert_recon_prepass_dispatch_authority = lambda cfg: (
    _recon_prepass_expected_owner_prefix(cfg) + "/prepass"
)
def _resolve_snapshot_build_root(cfg):
    root = Path(cfg["project_root"]).resolve()
    cfg["_resolved_build_root"] = str(root)
    return root
_stub_mod.resolve_snapshot_build_root = _resolve_snapshot_build_root
_stub_mod.prepare_snapshot_bound_inputs = lambda cfg: {
    "status": "UNCHANGED", "reason": "driver-smoke immutable-input stub"
}
# Deterministic recon-side dependency enumeration imports these helpers lazily.
# The phase-loop harness owns no real source corpus, so provide the closed empty
# dependency surface instead of degrading recon because its module is stubbed.
_stub_mod._is_production_source_path = lambda _path, _root: True
_stub_mod._detect_external_dependency_markers = lambda _root: []
_stub_mod._production_source_files = lambda root, suffixes: [
    path for path in Path(root).rglob("*")
    if path.is_file() and path.suffix.lower() in set(suffixes)
]
_stub_mod._rel = lambda path, root: Path(path).resolve().relative_to(
    Path(root).resolve()
)
sys.modules["recon_prepass"] = _stub_mod

import plamen_driver as pd
# This harness exercises phase-loop policy rather than recon-prepass byte
# archival.  The dedicated recon-prepass suites cover the authenticated retry
# baseline; keep that orthogonal subsystem out of these black-box scenarios.
pd._ensure_recon_prepass_retry_baseline = lambda _scratch, _cfg: []
from artifact_ledger import (
    read_artifact_ledger as _smoke_read_artifact_ledger,
    record_work_unit_artifacts as _smoke_record_artifacts,
    record_work_unit_inputs as _smoke_record_inputs,
)
from phase_io_contracts import (
    ArtifactSpec as _SmokeArtifactSpec,
    LaunchSpec as _SmokeLaunchSpec,
    PhaseIOContract as _SmokePhaseIOContract,
    canonical_work_unit_key as _smoke_work_unit_key,
)

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
    "| AGENT | token-flow-tracing | YES | agent_3 | transfer/mint/burn | analysis_transfer_mint_burn.md | PENDING |\n"
    "| AGENT | economic-design-audit | YES | agent_4 | fees + incentives | analysis_fees_incentives.md | PENDING |\n"
    "| AGENT | oracle-analysis | YES | agent_5 | price + xchain | analysis_price_xchain.md | PENDING |\n"
    "\n**Gate Check**: All REQUIRED templates have agents? YES\n"
)

_MANIFEST_1_ROW = (
    "# Spawn Manifest\n\n"
    "| Row Type | Template | Required? | Agent ID | Focus Area | Expected Output | Status |\n"
    "|----------|----------|-----------|----------|------------|-----------------|--------|\n"
    "| AGENT | core-state | YES | agent_1 | storage + accounting | analysis_storage_accounting.md | PENDING |\n"
    "\n**Gate Check**: All REQUIRED templates have agents? YES\n"
)

_MANIFEST_3_ROWS = (
    "# Spawn Manifest\n\n"
    "| Row Type | Template | Required? | Agent ID | Focus Area | Expected Output | Status |\n"
    "|----------|----------|-----------|----------|------------|-----------------|--------|\n"
    "| AGENT | core-state | YES | agent_1 | storage + accounting | analysis_storage_accounting.md | PENDING |\n"
    "| AGENT | access-control | YES | agent_2 | role + caps | analysis_role_caps.md | PENDING |\n"
    "| AGENT | token-flow-tracing | YES | agent_3 | transfer/mint/burn | analysis_transfer_mint_burn.md | PENDING |\n"
    "\n**Gate Check**: All REQUIRED templates have agents? YES\n"
)

_MANIFEST_4_ROWS = _MANIFEST_3_ROWS.replace(
    "\n**Gate Check**",
    "| AGENT | economic-design-audit | YES | agent_4 | fees + incentives | analysis_fees_incentives.md | PENDING |\n"
    "\n**Gate Check**",
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
    "**Preferred Tag**: [CODE-TRACE]\n"
    "**Verdict**: NEEDS_VERIFICATION\n"
    "**Root Cause**: The admin setter omits its state-change event.\n"
    "**Description**: Missing event emission on admin setter.\n"
    "**Impact**: Off-chain observers can miss the administrative change.\n\n"
    "### Finding [F-02]\n"
    "**Severity**: Informational\n"
    "**Location**: src/Stub.sol:L42\n"
    "**Preferred Tag**: [CODE-TRACE]\n"
    "**Verdict**: NEEDS_VERIFICATION\n"
    "**Root Cause**: A construction-only value uses mutable storage.\n"
    "**Description**: The variable is assigned only during construction and "
    "remains unchanged after deployment.\n"
    "**Impact**: The contract pays avoidable storage-read cost without a "
    "security-critical state transition.\n"
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
    "**Preferred Tag**: [CODE-TRACE]\n"
    "**Verdict**: NEEDS_VERIFICATION\n"
    "**Root Cause**: Missing validation permits transition one.\n"
    "**Description**: Medium finding one.\n"
    "**Impact**: Synthetic medium impact one.\n\n"
    "### Finding [F-02]\n"
    "**Severity**: Medium\n"
    "**Location**: src/Stub.sol:L20\n"
    "**Preferred Tag**: [CODE-TRACE]\n"
    "**Verdict**: NEEDS_VERIFICATION\n"
    "**Root Cause**: Missing validation permits transition two.\n"
    "**Description**: Medium finding two.\n"
    "**Impact**: Synthetic medium impact two.\n\n"
    "### Finding [F-03]\n"
    "**Severity**: High\n"
    "**Location**: src/Stub.sol:L30\n"
    "**Preferred Tag**: [CODE-TRACE]\n"
    "**Verdict**: NEEDS_VERIFICATION\n"
    "**Root Cause**: Missing validation permits transition three.\n"
    "**Description**: High finding three.\n"
    "**Impact**: Synthetic high impact three.\n"
)

_ANALYSIS_MEDIUM_ONE = (
    "### Finding [F-01]\n"
    "**Severity**: Medium\n"
    "**Location**: src/Stub.sol:L10\n"
    "**Preferred Tag**: [CODE-TRACE]\n"
    "**Verdict**: NEEDS_VERIFICATION\n"
    "**Root Cause**: Missing validation permits transition one.\n"
    "**Description**: Medium finding one.\n"
    "**Impact**: Synthetic medium impact one.\n"
    + ("padding " * 20) + "\n"
)

def _analysis_low_unique(fid, line):
    return (
        f"### Finding [{fid}]: Exact smoke candidate\n"
        "**Severity**: Low\n"
        f"**Location**: src/Stub.sol:L{line}\n"
        "**Preferred Tag**: [CODE-TRACE]\n"
        "**Verdict**: NEEDS_VERIFICATION\n"
        "**Root Cause**: Missing validation permits an unauthorized state transition.\n"
        "**Description**: An unchecked input can bypass the synthetic phase-loop guard.\n"
        "**Impact**: The state can become inconsistent until the next repair operation.\n"
    )

_STUB_PHASE_CONTEXT = None
_STUB_WRITE_ORDINAL = 0


def _prepare_smoke_exact_consumer_boundary(phase, config, attempt):
    # Compile the real Claude capability policy for the hermetic launcher.
    if phase.name not in pd._CLAUDE_EXACT_CONSUMER_PHASES:
        return
    scratch = Path(config["scratchpad"])
    snapshot = (
        scratch / "_smoke_runtime" /
        f"{phase.name}.attempt-{attempt:04d}.prompt.md"
    )
    snapshot.parent.mkdir(parents=True, exist_ok=True)
    snapshot.write_text(
        f"Hermetic exact-consumer prompt for {phase.name} attempt {attempt}.\n",
        encoding="utf-8",
    )
    pd._prepare_claude_phase_tool_boundary(
        phase=phase,
        scratchpad=scratch,
        config=config,
        attempt=attempt,
        prompt_snapshot=snapshot,
    )


def _record_smoke_exact_write_receipt(target, text):
    # Run the real PreToolUse hook before one fixture-owned model write.
    context = _STUB_PHASE_CONTEXT
    if context is None:
        return
    phase, config, attempt = context
    state = config.get("_claude_phase_tool_boundaries", {}).get(phase.name)
    if not isinstance(state, dict):
        return
    policy_path = Path(state["policy_path"])
    policy = pd.claude_phase_tool_policy.load_policy(policy_path)
    resolved = Path(target).resolve(strict=False)
    allowed = {
        Path(value).resolve(strict=False)
        for value in policy.get("exact_write_files", [])
    }
    if resolved not in allowed:
        return
    event = {
        "session_id": f"smoke-{phase.name}-{attempt}",
        "tool_use_id": f"write-{resolved.name}",
        "cwd": str(Path(config["project_root"]).resolve()),
        "tool_name": "Write",
        "tool_input": {"file_path": str(resolved), "content": text},
    }
    code, output = pd.claude_phase_tool_policy.run_hook(
        policy_path,
        json.dumps(event, sort_keys=True).encode("utf-8"),
    )
    decision = (
        output.get("hookSpecificOutput", {}).get("permissionDecision")
        if isinstance(output, dict)
        else None
    )
    if code != 0 or decision != "allow":
        raise RuntimeError(
            f"smoke exact-consumer Write was not authorized: "
            f"{phase.name}/{resolved.name}: code={code}, output={output!r}"
        )


def _write(p, text):
    # Write one smoke MODEL output with an explicit arm-before-write receipt.
    # The phase-loop smoke replaces the live worker launcher. As production
    # consumers became PhaseIO-strict, leaving these synthetic worker bytes
    # unowned stopped testing the intended phase-loop policy and instead tested
    # a fixture artifact-authority violation. Each test-only write therefore
    # uses a unique zero-input MODEL work unit before touching disk.
    global _STUB_WRITE_ORDINAL
    target = Path(p)
    context = _STUB_PHASE_CONTEXT
    armed = None
    if context is not None:
        phase, config, attempt = context
        scratch = Path(config["scratchpad"])
        project = Path(config["project_root"])
        try:
            relative = target.relative_to(scratch).as_posix()
            root_name = "scratchpad"
        except ValueError:
            relative = target.relative_to(project).as_posix()
            root_name = "project"
        identity = f"{root_name}:{relative}"

        # The real phase loop arms migrated MODEL contracts before invoking
        # this stub.  Do not interpose a second smoke owner on an output that
        # already belongs to such an INPUTS_BOUND transaction: the production
        # post-run commit must observe the exact prestate it froze.  The
        # synthetic zero-input owner below is only for auxiliary fixture bytes
        # whose production provider is intentionally bypassed by this smoke.
        pending_owner = False
        try:
            ledger = _smoke_read_artifact_ledger(scratch)
            for unit in ledger.get("work_units", {}).values():
                if (
                    isinstance(unit, dict)
                    and unit.get("run_id") == config["_run_id"]
                    and unit.get("semantic_status") == "INPUTS_BOUND"
                    and unit.get("execution_state")
                    == "INPUTS_BOUND_PREEXECUTION"
                    and identity in (unit.get("output_prestates") or {})
                ):
                    pending_owner = True
                    break
        except Exception:
            pending_owner = False
        if pending_owner:
            _record_smoke_exact_write_receipt(target, text)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
            return

        _STUB_WRITE_ORDINAL += 1
        work_id = (
            f"smoke_fixture.attempt-{attempt}."
            f"write-{_STUB_WRITE_ORDINAL:04d}"
        )
        owner = _smoke_work_unit_key(
            config.get("pipeline", "sc"),
            config.get("mode", "light"),
            config.get("language", "unknown"),
            config.get("cli_backend", "claude"),
            phase.name,
            work_id,
        )
        contract = _SmokePhaseIOContract(
            pipeline=config.get("pipeline", "sc"),
            mode=config.get("mode", "light"),
            ecosystem=config.get("language", "unknown"),
            backend=config.get("cli_backend", "claude"),
            phase=phase.name,
            work_unit_id=work_id,
            outputs=(
                _SmokeArtifactSpec(
                    root=root_name,
                    path=relative,
                    owner_key=owner,
                    artifact_class="REQUIRED",
                    writer="MODEL",
                    write_mode="REPLACE",
                    schema_version="plamen.driver_smoke_fixture.v1",
                    minimum_gate="TEST_ONLY_ARM_BEFORE_WRITE",
                    consumers=(
                        "semantic_identity/projection",
                        "verify_queue/preverify_capture",
                        "sc_verify_queue/preverify_capture",
                    ),
                ),
            ),
            immutable_inputs=(),
            bounded_lookup_inputs=(),
            model_invoked=True,
        )
        launch = _SmokeLaunchSpec(
            work_unit_key=contract.key,
            pipeline=contract.pipeline,
            mode=contract.mode,
            ecosystem=contract.ecosystem,
            backend=contract.backend,
            model="smoke-fixture",
            timeout_s=30,
            exec_mode="headless",
            tool_policy=("filesystem",),
        )
        unit = _smoke_record_inputs(
            scratch,
            project,
            contract,
            launch,
            run_id=config["_run_id"],
        )
        if (
            unit.get("semantic_status") == "INPUTS_BOUND"
            and unit.get("execution_state") == "INPUTS_BOUND_PREEXECUTION"
        ):
            armed = (scratch, project, contract, launch, config["_run_id"])

    _record_smoke_exact_write_receipt(target, text)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")

    if armed is not None:
        scratch, project, contract, launch, run_id = armed
        _smoke_record_artifacts(
            scratch,
            project,
            contract,
            launch,
            run_id=run_id,
            actor="MODEL",
        )


def _write_group(items):
    # Commit related smoke model outputs as one exact producer unit.
    global _STUB_WRITE_ORDINAL
    phase, config, attempt = _STUB_PHASE_CONTEXT
    scratch = Path(config["scratchpad"])
    project = Path(config["project_root"])
    normalized = []
    for target, text in items:
        target = Path(target)
        relative = target.relative_to(scratch).as_posix()
        normalized.append((target, relative, text))
    _STUB_WRITE_ORDINAL += 1
    work_id = "model"
    owner = _smoke_work_unit_key(
        config.get("pipeline", "sc"),
        config.get("mode", "light"),
        config.get("language", "unknown"),
        config.get("cli_backend", "claude"),
        phase.name,
        work_id,
    )
    contract = _SmokePhaseIOContract(
        pipeline=config.get("pipeline", "sc"),
        mode=config.get("mode", "light"),
        ecosystem=config.get("language", "unknown"),
        backend=config.get("cli_backend", "claude"),
        phase=phase.name,
        work_unit_id=work_id,
        outputs=tuple(
            _SmokeArtifactSpec(
                root="scratchpad",
                path=relative,
                owner_key=owner,
                artifact_class="REQUIRED",
                writer="MODEL",
                write_mode="REPLACE",
                schema_version="unstructured.v1",
                minimum_gate="FIXTURE_EXACT_BYTES",
                consumers=("sc_verify_queue/preverify_chain_pair",),
            )
            for _target, relative, _text in normalized
        ),
        immutable_inputs=(),
        bounded_lookup_inputs=(),
        model_invoked=True,
    )
    launch = _SmokeLaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="smoke-fixture",
        timeout_s=30,
        exec_mode="pty",
        tool_policy=("filesystem",),
    )
    _smoke_record_inputs(
        scratch, project, contract, launch, run_id=config["_run_id"],
    )
    for target, _relative, text in normalized:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    _smoke_record_artifacts(
        scratch,
        project,
        contract,
        launch,
        run_id=config["_run_id"],
        actor="MODEL",
    )


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
                                   valid_exit=True, include_skill_gap=True,
                                   findings_body=_STUB_BODY):
    _write(scratch / "design_stress_findings.md", findings_body)
    _write(scratch / "perturbation_findings.md", findings_body)
    if include_skill_gap:
        _write(scratch / "skill_execution_gaps.md", findings_body)

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
    global _STUB_PHASE_CONTEXT, _STUB_WRITE_ORDINAL
    _STUB_PHASE_CONTEXT = (phase, config, attempt)
    _STUB_WRITE_ORDINAL = 0
    scratch = Path(config["scratchpad"])
    with CALL_LOG.open("a", encoding="utf-8") as f:
        f.write(f"{phase.name}:{attempt}\n")
    # ``run_phase`` is replaced by this hermetic provider, so reproduce the
    # production launcher's exact-consumer capability compilation here.  Every
    # matching ``_write`` still crosses the real hook and persists the same
    # receipt that the post-run authority validator requires.
    _prepare_smoke_exact_consumer_boundary(phase, config, attempt)

    # Production ``run_phase`` owns Instantiate's just-in-time input bind
    # because its retry ordinal is receipt-governed.  Replacing ``run_phase``
    # means the fixture must reproduce that one precondition before emitting
    # the proposal; all producer bindings themselves remain real ledger rows.
    if phase.name == "instantiate":
        config.setdefault("_active_model_attempts", {})[phase.name] = attempt
        bind_issues = pd._bind_typed_model_phase_inputs(
            phase, scratch, config
        )
        if bind_issues:
            raise RuntimeError(
                "smoke Instantiate semantic bind failed: "
                + "; ".join(bind_issues)
            )

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

    # Scenario C exercises a canonical zero verification denominator.  The
    # report-index model stub must still honor the current typed projection
    # contract: an empty Master Finding Index is a real table, not a generic
    # prose placeholder.  Keeping this in the provider fixture avoids
    # weakening production status-projection validation for nonempty audits.
    if SCENARIO == "C" and phase.name == "report_index":
        _write(
            scratch / "report_index.md",
            "# Report Index\n\n"
            "## Summary\n\n"
            "| Severity | Count |\n"
            "|---|---:|\n"
            "| Critical | 0 |\n"
            "| High | 0 |\n"
            "| Medium | 0 |\n"
            "| Low | 0 |\n"
            "| Informational | 0 |\n\n"
            "## Master Finding Index\n\n"
            "| Report ID | Title | Severity | Location | Verification | "
            "Trust Adj. | Internal Hypothesis |\n"
            "|---|---|---|---|---|---|---|\n\n"
            "No reportable, independently verified findings were produced.\n",
        )
        _write(
            scratch / "report_coverage.md",
            "# Report Coverage\n\n"
            "## Raw Candidate Ledger\n\n"
            "| Source | Finding ID | Severity | Disposition | Notes |\n"
            "|---|---|---|---|---|\n\n"
            "Total: 0 candidates; verification denominator was empty.\n",
        )
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
        # B deliberately exercises a five-row Core manifest. Light scenarios
        # use the documented 3-4-row contract so they reach the phase behavior
        # each smoke test actually targets.
        if SCENARIO == "B":
            body = _MANIFEST_5_ROWS
        elif SCENARIO == "C":
            body = _MANIFEST_4_ROWS
        else:
            body = _MANIFEST_3_ROWS
        _write(scratch / "spawn_manifest_proposal.md", body)
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
            # Pass the manifest-exact Light gate comfortably (4 files). Fresh
            # mode requires COMPLETE markers + ## Findings structure.
            for name in _MANIFEST_5_OUTPUTS[:4]:
                _write(scratch / name, _breadth_marked(name, _ANALYSIS_LOW_ONLY, 2))
            return 0
        if SCENARIO in ("D", "E", "F", "G", "I"):
            for i in range(5):
                _write(scratch / f"analysis_agent_{i}.md", _ANALYSIS_LOW_ONLY)
            if SCENARIO == "I":
                # Inventory is now a deterministic Python merge, so exercise
                # the same later-phase foreign-write boundary from the live
                # breadth worker instead of an unreachable inventory subprocess.
                _write(scratch / "semantic_invariants.md", _STUB_BODY)
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
            # This lane proves an authenticated empty verification
            # denominator.  Its auxiliary depth artifacts must therefore be
            # zero-finding too; the generic smoke body contains synthetic
            # finding blocks and the real promotion engine correctly treats
            # those as candidates.
            _write_depth_support_artifacts(
                scratch, findings_body=_DEPTH_COMPLETE_BODY,
            )
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

    if phase.name.startswith("inventory_chunk_"):
        # P0-L exact reconciliation requires the smoke worker to preserve one
        # source-bound disposition per assigned raw finding. A generic stub
        # can no longer stand in for a shard because that was the production
        # loss mode this gate is designed to catch.
        import re
        manifest = scratch / f"{phase.name}.manifest.md"
        assigned = []
        if manifest.is_file():
            for match in re.finditer(
                r"(?m)^\s*\|\s*`?([A-Za-z0-9_.-]+\.md)`?\s*\|",
                manifest.read_text(encoding="utf-8", errors="replace"),
            ):
                name = match.group(1)
                if name not in assigned:
                    assigned.append(name)
        blocks = [
            f"# {phase.name} exact smoke inventory",
            "",
            "## Source Summary",
            "",
            "Synthetic exact-source shard for phase-loop testing.",
            "",
            "## Master Table",
            "",
            "| Finding ID | Severity | Title | Source IDs | Location |",
            "|---|---|---|---|---|",
        ]
        details = ["", "## Per-Finding Detail", ""]
        ordinal = 0
        for source_name in assigned:
            source = scratch / source_name
            text = source.read_text(encoding="utf-8", errors="replace") if source.is_file() else ""
            matches = list(re.finditer(
                r"(?im)^#{2,4}\s+Finding\s+\[?([A-Za-z][A-Za-z0-9_-]*-\d+)\]?[^\n]*$",
                text,
            ))
            for match_index, match in enumerate(matches):
                ordinal += 1
                source_id = match.group(1)
                block_end = (
                    matches[match_index + 1].start()
                    if match_index + 1 < len(matches)
                    else len(text)
                )
                source_block = text[match.start():block_end]

                def source_field(label, fallback):
                    field_match = re.search(
                        rf"(?im)^\*\*{re.escape(label)}\*\*:\s*(.+?)\s*$",
                        source_block,
                    )
                    return field_match.group(1).strip() if field_match else fallback

                title_match = re.search(r"\]\s*:\s*(.+?)\s*$", match.group(0))
                title = title_match.group(1).strip() if title_match else "Exact smoke candidate"
                location = source_field("Location", f"src/Stub.sol:L{10 + ordinal}")
                preferred_tag = source_field("Preferred Tag", "[CODE-TRACE]")
                verdict = source_field("Verdict", "NEEDS_VERIFICATION")
                root_cause = source_field(
                    "Root Cause", "Missing validation permits an unauthorized state transition."
                )
                description = source_field(
                    "Description", "An unchecked input can bypass the synthetic phase-loop guard."
                )
                impact = source_field(
                    "Impact", "The state can become inconsistent until the next repair operation."
                )
                qualified = f"{source_name}:{source_id}"
                # Chunk-local ordinals restart in every independently spawned
                # inventory worker.  Derive the fixture identity from the
                # source-qualified candidate so cross-shard merge cannot
                # collapse distinct findings that happen to share CC-1.
                local_id = (
                    "CC-"
                    + str(int(hashlib.sha256(qualified.encode("utf-8")).hexdigest()[:12], 16))
                )
                blocks.append(
                    f"| {local_id} | Low | {title} | {qualified} | {location} |"
                )
                details.extend([
                    f"### Finding [{local_id}]: {title}",
                    "",
                    f"**Source IDs**: {qualified}",
                    "**Severity**: Low",
                    f"**Location**: {location}",
                    f"**Preferred Tag**: {preferred_tag}",
                    f"**Verdict**: {verdict}",
                    f"**Root Cause**: {root_cause}",
                    f"**Description**: {description}",
                    f"**Impact**: {impact}",
                    "",
                ])
        if ordinal == 0:
            details.extend([
                "## No Findings",
                "",
                "No assigned source finding blocks were present in this smoke shard.",
                "",
            ])
        _write(
            scratch / f"findings_{phase.name}.md",
            "\n".join([*blocks, *details]) + "\n",
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
        if SCENARIO == "C":
            empty_hypotheses = (
                "# Empty chain projection\n\n"
                "<!-- PLAMEN_CHAIN_RELATION_COUNT: 0 -->\n\n"
                "| Hypothesis | Constituents |\n"
                "|---|---|\n\n"
                "The authenticated low-only smoke denominator produced no "
                "chain candidates.\n" + "padding " * 40 + "\n"
            )
            empty_mapping = (
                "# Empty finding mapping\n\n"
                "<!-- PLAMEN_CHAIN_RELATION_COUNT: 0 -->\n\n"
                "| Hypothesis | Source Findings |\n"
                "|---|---|\n\n"
                "The authenticated low-only smoke denominator produced no "
                "chain candidates.\n" + "padding " * 40 + "\n"
            )
            # The real phase loop has already armed the registered chain/model
            # transaction.  ``_write`` detects that pending owner and writes
            # only the bytes; the production post-run path commits the exact
            # six-input contract and live launch receipt atomically.
            _write(scratch / "hypotheses.md", empty_hypotheses)
            _write(scratch / "finding_mapping.md", empty_mapping)
            _write(scratch / "enabler_results.md", empty_hypotheses)
        else:
            _write(scratch / "hypotheses.md", _STUB_BODY)
            _write(scratch / "finding_mapping.md", _STUB_BODY)
            _write(scratch / "enabler_results.md", _STUB_BODY)
        return 0

    if phase.name == "chain_agent2" and SCENARIO == "C":
        # As with chain/model, the production loop owns the already-armed
        # three-output transaction.  The smoke launcher supplies only model
        # bytes and leaves exact contract/launch commit to that real path.
        empty_synthesis = (
            "# Empty chain synthesis\n\n"
            "## No Hypotheses\n\n"
            "The authenticated low-only chain denominator has no synthesis "
            "candidates.\n" + "padding " * 40 + "\n"
        )
        _write(scratch / "chain_hypotheses.md", empty_synthesis)
        _write(scratch / "composition_coverage.md", empty_synthesis)
        _write(scratch / "synthesis_full.md", empty_synthesis)
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
# Program Facts Stage 2 is a separately covered deterministic integration.
# This smoke module exercises the phase-loop/checkpoint policy and must not run
# a real graph bake or publish PhaseIO sidecars before its phase stubs begin.
# Keep the substitute shaped like the production outcome consumed by main().
pd._ensure_program_facts_stage2_emit_only = lambda **_kwargs: types.SimpleNamespace(
    state="SMOKE_STUBBED",
    reused=False,
    consumer_activation=False,
)
# Auxiliary writable-root startup reconciles host-global provider journals.
# That boundary has its own integration suite and makes this otherwise-hermetic
# phase-loop lane depend on unrelated workstation history (including large
# cleanup ledgers).  Keep the production driver call in place, but substitute
# the already-replayed allow outcome in this generated smoke process only.
pd._run_auxiliary_writable_root_startup_boundary = (
    lambda _scratchpad, _config, _checkpoint: {
        "allocation_permitted": True,
        "allocation_disposition": "ALLOW_NEW_LEASES",
        "runtime_debt": [],
    }
)
# Verify-recovery is an inter-phase worker subprocess, not routed through
# run_phase. Keep this phase-loop smoke harness hermetic: return the missing IDs
# so the deterministic stub/degrade path is exercised without launching a real
# Claude/Codex process.
pd._run_verify_recovery_shard = lambda _config, missing: [
    fid for fid, _row in missing
]
# Scenario C is specifically the empty-verification phase-loop contract.  Its
# model subprocess is already replaced by ``stub_run_phase`` above, so those
# synthetic Markdown bytes cannot carry a real producer receipt.  Let only
# this scenario cross the unrelated model-input admission boundary; central
# closure replay/cache, mechanical queue construction, verification, report
# integrity, and checkpoint transitions remain the real implementations.
if SCENARIO == "C":
    _real_bind_typed_model_phase_inputs = pd._bind_typed_model_phase_inputs
    _scenario_c_model_stubs = {"sc_semantic_dedup"}
    pd._bind_typed_model_phase_inputs = (
        lambda _phase, _scratch, _config: []
        if _phase.name in _scenario_c_model_stubs
        else _real_bind_typed_model_phase_inputs(_phase, _scratch, _config)
    )
    # Keep the deterministic chain-prep transactions live. They are the real
    # registered producers of the exact Agent-2 denominator (candidate pairs,
    # variable map, state resolution, and the enabler prefill), so bypassing
    # them would make an otherwise valid model fixture unauthoritative.

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
    try:
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
            # The current authenticated artifact-ledger boundary makes these
            # full phase-loop scenarios substantially slower on Windows.  Do
            # not install ``faulthandler.dump_traceback_later`` in the child:
            # CPython's all-thread dumper is unsafe while another live thread
            # can disappear, and has produced a real 0xC0000005 in this lane.
            # The parent timeout remains the single process-lifetime bound.
            # Scenario C traverses the complete 30-shard empty-verification
            # closure plus report reconciliation. Authenticated T0--T9, typed
            # report publication, and final disposition replay are all serial
            # authority boundaries; a clean Windows run can exceed 30 minutes
            # without a retry or model stall. Keep a finite parent-owned bound,
            # but leave enough headroom for the secured path to finish.
            timeout=2700 if scenario == "C" else 300,
        )
    except subprocess.TimeoutExpired as exc:
        if exc.stdout:
            sys.stdout.write(
                exc.stdout.decode(errors="replace")
                if isinstance(exc.stdout, bytes) else exc.stdout
            )
        if exc.stderr:
            sys.stderr.write(
                exc.stderr.decode(errors="replace")
                if isinstance(exc.stderr, bytes) else exc.stderr
            )
        raise
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
        # These phase-loop scenarios span Light/Core and L1.  Claude's
        # authenticated contained route is intentionally SC Thorough-only;
        # use the supported Codex matrix for this backend-neutral stub lane.
        "cli_backend": "codex",
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
        _assert(len(breadth_attempts) == 2,
                f"A.run1: an identical retry must stop after attempt 2 records "
                f"NO_PROGRESS; got {breadth_attempts}")
        receipt = json.loads((
            scratch / "_retry_receipts" / "breadth" / "phase.attempt2.json"
        ).read_text(encoding="utf-8"))
        _assert(receipt["status"] == "NO_PROGRESS",
                f"A.run1: retry receipt must explain suppression; got {receipt}")

        # Run 2: resume, expect breadth retried, recon/instantiate skipped
        call_log.write_text("", encoding="utf-8")
        rc2 = _run_driver(tmp, cfg_path, call_log, "A")
        _assert(rc2 == 3, f"A.run2 exit: got {rc2}, expected 3 (still degraded)")

        calls2 = call_log.read_text(encoding="utf-8").splitlines()
        _assert(len([c for c in calls2 if c.startswith("breadth:")]) == 2,
                f"A.run2: identical retry again stops on typed NO_PROGRESS; got {calls2}")
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
    tmp, project, scratch, cfg_path, call_log = _make_project(
        "plamen_smoke_b_", mode="core"
    )
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
        # The hermetic runner cannot provide live Claude exact-consumer or
        # optional recon-tool authority, so unrelated analysis phases remain
        # visibly degraded.  The empty-verification contract succeeds when it
        # ships without verify or report-integrity debt.
        _assert(rc == 3, f"C exit: got {rc}, expected 3 (known harness debt)")

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
        _assert("report_floor" not in ckpt.get("degraded", []),
                "C: authenticated empty denominator created report-integrity debt")

        # Report must have completed (proves pipeline continued past verify).
        _assert("report_assemble" in ckpt["completed"],
                f"C: report_assemble should complete; got {ckpt['completed']}")
        _assert((project / "AUDIT_REPORT.md").exists(),
                "C: AUDIT_REPORT.md missing — report phase did not run")

        _assert(
            not (scratch / "_overflow" / "report_integrity_no_ship").exists(),
            "C: empty-denominator report was incorrectly quarantined",
        )

        print("[scenario C] PASS")
    finally:
        if os.environ.get("PLAMEN_KEEP_FAILED_SMOKE") == "1":
            print(f"[scenario C] retained diagnostic root: {tmp}")
        else:
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
        # Do not pre-seed scratchpad evidence before startup.  The live stub
        # writes the inventory at its owning phase; a pre-existing inventory
        # with no snapshot/run identity is correctly rejected as
        # LEGACY_UNBOUND by the non-destructive startup contract.
        rc = _run_driver(tmp, cfg_path, call_log, "H")
        _assert(rc == 3, f"H exit: got {rc}, expected 3 (degraded verification)")

        ckpt = json.loads(
            (scratch / "_v2_checkpoint.json").read_text(encoding="utf-8")
        )
        _assert("verify_medium_a" in ckpt["degraded"],
                f"H: verify_medium_a must be degraded; got {ckpt['degraded']}")
        _assert("verify_medium_a" in ckpt["completed"],
                f"H: completed-with-debt shard must remain resumably completed; "
                f"got {ckpt['completed']}")
        _assert(
            ckpt.get("phase_commits", {}).get("verify_medium_a", {}).get("state")
            == "COMPLETED_WITH_DEBT",
            "H: verify_medium_a needs typed COMPLETED_WITH_DEBT authority",
        )
        _assert((scratch / "verify_medium_a.degraded").exists(),
                "H: verify_medium_a.degraded marker missing")
        runtime_debt = json.loads(
            (scratch / "verification_runtime_debt.json").read_text(encoding="utf-8")
        )
        _assert(runtime_debt["proof_authority"] == "NONE",
                "H: unresolved dynamic workers must have no proof authority")
        _assert(runtime_debt["report_verification_projection"] == "CONTESTED",
                "H: unresolved candidates must remain report-visible")
        queue_rows = __import__("plamen_parsers").parse_verification_queue_rows(
            scratch
        )
        expected_pending = [
            str(row.get("finding id") or "").strip()
            for row in queue_rows
            if str(row.get("finding id") or "").strip()
            and not (scratch / f"verify_{str(row.get('finding id') or '').strip()}.md").exists()
        ]
        _assert(
            runtime_debt["pending_work_item_ids"] == expected_pending,
            "H: every exact queue identity lacking verifier output must "
            f"remain pending; got {runtime_debt['pending_work_item_ids']}, "
            f"expected {expected_pending}",
        )
        _assert(
            not any(
                (scratch / f"verify_{finding_id}.md").exists()
                for finding_id in runtime_debt["pending_work_item_ids"]
            ),
            "H: dynamic verifier debt must not synthesize per-finding proof stubs",
        )
        print("[scenario H] PASS")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@pytest.mark.integration
def test_scenario_i_phase_containment_detector() -> None:
    """Phase-containment detector.

    Breadth writes a later-phase artifact. That phase-boundary violation is a
    hard failure signal even if breadth's own required artifacts exist: the
    driver must retry breadth, then degrade/halt instead of checkpointing it as
    clean and continuing with quarantined overflow. Inventory is Python-only.
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
        _assert("breadth" in ckpt["degraded"],
                f"I: breadth must be degraded on containment failure; "
                f"got degraded={ckpt.get('degraded', [])}")
        _assert("breadth" not in ckpt["completed"],
                f"I: breadth must NOT be completed after foreign writes; "
                f"got completed={ckpt['completed']}")
        _assert((scratch / "breadth.degraded").exists(),
                "I: breadth.degraded marker missing")

        calls = call_log.read_text(encoding="utf-8").splitlines()
        breadth_calls = [c for c in calls if c.startswith("breadth:")]
        # CONTAINMENT failures are NOT hint-recoverable, so breadth does NOT
        # get the extra hinted retry here — it stays at 2 attempts and falls to
        # the standard quarantine + halt path (the extended retry budget applies
        # only to coverage/content gaps, e.g. scenario A's breadth).
        _assert(len(breadth_calls) == 2,
                f"I: breadth containment violation -> no extra hinted retry "
                f"(2 attempts), straight to quarantine+halt; got {breadth_calls}")
        inventory_calls = [c for c in calls if c.startswith("inventory:")]
        _assert(len(inventory_calls) == 0,
                f"I: driver must halt at breadth before inventory; got {inventory_calls}")
        depth_calls = [c for c in calls if c.startswith("depth:")]
        _assert(len(depth_calls) == 0,
                f"I: driver must halt at breadth before depth; got {depth_calls}")

        # Foreign artifacts should be quarantined to _overflow/
        overflow = scratch / "_overflow" / "breadth"
        _assert(overflow.exists(), "I: _overflow/breadth missing")
        quarantined = {p.name for p in overflow.iterdir()}
        _assert("semantic_invariants.md" in quarantined,
                f"I: expected foreign artifacts in overflow; got {quarantined}")
        # The foreign files should NOT remain in the main scratchpad
        _assert(not (scratch / "semantic_invariants.md").exists(),
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
        phase, "thorough", {"breadth_model_override": "claude-opus-5"}
    )
    _assert(model == "claude-opus-5",
            f"J: breadth override should win; got {model}")
    light_model = _pd.phase_model(
        phase, "light", {"breadth_model_override": "claude-opus-5"}
    )
    _assert(light_model == "claude-sonnet-5",
            f"J: light mode must still force sonnet; got {light_model}")
    print("[scenario J] PASS")


@pytest.mark.integration
def test_scenario_k_inventory_sharding() -> None:
    """Inventory sharding."""
    tmp, project, scratch, cfg_path, call_log = _make_project(
        "plamen_smoke_k_", pipeline="l1",
        extra_config={"inventory_target_per_shard": 2, "inventory_max_shards": 3}
    )
    try:
        rc = _run_driver(tmp, cfg_path, call_log, "K")
        _assert(rc == 3, f"K exit: got {rc}, expected 3 (known harness debt)")

        ckpt = json.loads(
            (scratch / "_v2_checkpoint.json").read_text(encoding="utf-8")
        )
        inventory_phases = (
            "inventory_prepare",
            "inventory_chunk_a",
            "inventory_chunk_b",
            "inventory_chunk_c",
            "inventory",
        )
        for name in inventory_phases:
            _assert(name in ckpt["completed"],
                    f"K: {name} must be completed; got {ckpt['completed']}")
            _assert(name not in ckpt["degraded"],
                    f"K: {name} must not carry debt; got {ckpt['degraded']}")
            _assert(
                ckpt.get("phase_commits", {}).get(name, {}).get("state") == "CLEAN",
                f"K: {name} must have a CLEAN typed phase commit",
            )
        _assert((scratch / "inventory_shard_plan.md").exists(),
                "K: inventory_shard_plan.md missing")
        manifest_texts = []
        for shard in ("a", "b", "c"):
            manifest = scratch / f"inventory_chunk_{shard}.manifest.md"
            output = scratch / f"findings_inventory_chunk_{shard}.md"
            _assert(manifest.exists(), f"K: {manifest.name} missing")
            _assert(output.exists(), f"K: {output.name} missing")
            manifest_texts.append(
                manifest.read_text(encoding="utf-8", errors="replace")
            )
        assigned_sources = __import__("re").findall(
            r"\banalysis_agent_\d+\.md\b", "\n".join(manifest_texts)
        )
        expected_sources = [f"analysis_agent_{i}.md" for i in range(6)]
        _assert(
            __import__("collections").Counter(assigned_sources)
            == __import__("collections").Counter(expected_sources),
            "K: every breadth source must be assigned to exactly one shard; "
            f"got {assigned_sources}",
        )
        for text in manifest_texts:
            _assert(
                len(__import__("re").findall(r"\banalysis_agent_\d+\.md\b", text)) == 2,
                "K: the 6-source/3-shard fixture must assign exactly two sources per shard",
            )
        _assert((scratch / "findings_inventory.md").exists(),
                "K: findings_inventory.md missing")
        inventory = (scratch / "findings_inventory.md").read_text(
            encoding="utf-8", errors="replace"
        )
        inventory_ids = __import__("re").findall(
            r"(?m)^### Finding \[(INV-\d+)\]", inventory
        )
        _assert(
            len(inventory_ids) == len(set(inventory_ids)) == 6,
            "K: six distinct shard inputs must survive exactly once; "
            f"got {inventory_ids}",
        )
        source_fields = "\n".join(
            __import__("re").findall(
                r"(?im)^\*\*Source IDs\*\*:\s*(.+?)\s*$", inventory
            )
        )
        source_ids = __import__("re").findall(r"\bF-\d+\b", source_fields)
        expected_ids = [f"F-{i}" for i in range(1, 7)]
        _assert(
            __import__("collections").Counter(source_ids)
            == __import__("collections").Counter(expected_ids),
            "K: exact F-1..F-6 source identities must survive once each; "
            f"got {source_ids}",
        )
        orphans = scratch / "promotion_orphans.md"
        _assert(orphans.exists(), "K: promotion completeness receipt is missing")
        orphan_text = orphans.read_text(encoding="utf-8", errors="replace")
        _assert(
            "Exact delivered/repeated subjects excluded: 6 | Orphans: 0"
            in orphan_text,
            "K: exact retained source identities must be reconciled and must "
            "not be re-harvested as promotion gaps",
        )
        _assert(
            set(ckpt.get("degraded", []))
            == {"verify_queue", "mechanical_verify", "report_index"},
            "K: rc=3 may reflect only the explicitly modeled downstream "
            f"provider debt; got {ckpt.get('degraded', [])}",
        )
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
