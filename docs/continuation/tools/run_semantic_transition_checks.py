#!/usr/bin/env python3
"""Run bounded, offline regression slices; this is NOT an audit E2E runner.

Each suite has its own process so legacy import aliases cannot leak between
files. Results survive a later failure. No audit or model provider is launched.
Regenerate the runtime closure first, and freeze runtime sources during a run.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
import xml.etree.ElementTree as ET


GROUPS = {
    "semantics": [
        ("test_artifact_surface.py", ""),
        ("test_artifact_surface_conformance.py", ""),
        ("test_artifact_surface_semantic_conflicts.py", ""),
        ("test_disposition_semantic_conflicts.py", ""),
        ("test_representation_purge_parsers.py", ""),
        ("test_representation_bound_gates_p0_am.py", ""),
        ("test_representation_tolerant_driver_gates.py", ""),
        ("test_candidate_negative_representation_purge_p0.py", ""),
        ("test_security_obligation_representation_purge.py", ""),
        ("test_material_harm_floor.py", ""),
        ("test_worker_prelaunch_matrix.py", ""),
        ("test_recon_canonical_prepass_handoff.py", ""),
    ],
    "transitions": [
        ("test_depth_additive_successor_transaction.py",
         "every_postimage_boundary or partial_resume or source_cas or unresolved_niche"),
        ("test_chain_tail_transaction_failpoint_matrix_p0_t.py", ""),
        ("test_chain_tail_isolated_phase_io_p0_t.py",
         "primary_exact_chain_agent2 or isolated_driver_commits or committed_model_is_not_rerun or zero_work_final"),
        ("test_live_verify_queue_main_boundary_a0.py", ""),
        ("test_report_index_phase_io_p0_ae.py", ""),
        ("test_report_index_mechanical_commit_p0_ae.py", ""),
        ("test_report_body_pure_derivation.py", ""),
        ("test_report_body_attempt_authority.py", ""),
        ("test_report_body_bridge_routing.py", ""),
        ("test_audit_completion_receipt.py", ""),
        ("test_e2e_acceptance_verifier.py", ""),
    ],
    "report-tail": [
        # Controlled Codex children and offline setter/readback Forge tests.
        # Intentionally ends degraded; never label this full audit acceptance.
        ("test_nonempty_report_straight_line.py", ""),
    ],
    "readiness": [
        ("test_report_quality_empty_authority.py", ""),
        ("test_claude_transport_wizard.py", ""),
        ("test_macos_public_wizard_entry.py", ""),
    ],
    "depth-queue": [
        ("test_depth_to_queue_same_run_semantics.py", ""),
    ],
    "depth-report": [
        ("test_depth_to_empty_report_same_run.py", ""),
    ],
    "inventory-report": [
        # Real local child transport; benign synthetic records and explicit
        # seeded upstream/depth boundaries. Not a real audit or full E2E.
        ("test_inventory_to_empty_report_same_run.py", ""),
    ],
    "inventory-transport": [
        ("test_headless_phase_identity.py", ""),
        ("test_codex_compat_diagnostics.py", ""),
        ("test_driver_staging_and_native_runtime_authorities.py", ""),
    ],
    "inventory-provenance": [
        ("test_inventory_reemit_source_action_continuity.py", ""),
        ("test_inventory_reemit_pure_planning_p0_an.py", ""),
        ("test_inventory_reemit_repair_nc2.py", ""),
        ("test_inventory_aggregate_source_action_delivery_p0_z.py", ""),
        ("test_inventory_canonical_aggregate_phaseio_p0_l.py", ""),
        ("test_inventory_prepass_niche_source_delivery.py", ""),
    ],
    "empty-report": [
        ("test_core_empty_report_assembly_integration.py", ""),
    ],
    "ledger-replay": [
        ("test_artifact_ledger_noop_publication.py", ""),
        ("test_artifact_ledger_transaction_cas.py", ""),
    ],
    "assurance-handoff": [
        ("test_assurance_recovery_diagnostics.py", ""),
        ("test_assurance_byte_identical_handoff.py", ""),
        ("test_report_transaction_producer_handoff_p0_ac.py", ""),
    ],
    "evidence-quality": [
        ("test_report_evidence_assessment_publication.py", ""),
        ("test_report_evidence_delivery_legacy_oracle.py", ""),
        ("test_report_evidence_delivery_pure.py", ""),
        ("test_report_evidence_runtime_p1_k.py", ""),
        ("test_report_evidence_adversarial_review_p1_k.py", ""),
    ],
    "heading-projection": [
        ("test_report_heading_surface.py", ""),
        ("test_report_heading_presentation.py", ""),
        ("test_report_title_and_blocked_leak.py", ""),
        ("test_v2_recall_fixes.py", "TestBodyStatusStamp"),
        ("test_fix1_fix3_status_and_external_assumption.py", "header_status_regex"),
        ("test_report_index_mechanical_commit_p0_ae.py", ""),
        ("test_audit_completion_receipt.py", ""),
    ],
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--group", choices=[*GROUPS, "all"], default="all")
    parser.add_argument("--output", type=Path, required=True,
                        help="New results directory; existing paths are refused")
    parser.add_argument("--timeout", type=float, default=1800)
    parser.add_argument("--stack-dump-after", type=float, default=0,
                        help="Opt-in Python stack timer; disabled by default after observed CPython 3.12 traceback stalls")
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    if args.stack_dump_after < 0:
        parser.error("--stack-dump-after cannot be negative")
    root = Path(__file__).resolve().parents[3]
    args.output.mkdir(parents=True, exist_ok=False)
    output = args.output.resolve()
    closure = root / "verification_policy/toolchain_runtime_closure.v1.json"
    closure_hash = hashlib.sha256(closure.read_bytes()).hexdigest()
    selected = [entry for name, entries in GROUPS.items()
                if args.group in {name, "all"} for entry in entries]
    evidence = {
        "schema": "plamen.offline-semantic-transition-checks.v1",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "python": sys.executable,
        "root": str(root),
        "runtime_closure_sha256": closure_hash,
        "production_e2e": False,
        "provider_calls": False,
        "audit_launched": False,
        "results": [],
    }
    for name, selection in selected:
        if hashlib.sha256(closure.read_bytes()).hexdigest() != closure_hash:
            raise RuntimeError("runtime closure changed during test run")
        source = root / "scripts" / name
        junit = output / f"{name}.xml"
        command = [sys.executable, "-m", "pytest", str(source), "-q",
                   "-p", "no:cacheprovider", "--tb=short", f"--junitxml={junit}",
                   f"--basetemp={output / (name + '.fixtures')}"]
        if args.stack_dump_after:
            command += ["-o", f"faulthandler_timeout={args.stack_dump_after}"]
        if selection:
            command += ["-k", selection]
        start = time.monotonic()
        print(f"RUN {name}" + (f" [{selection}]" if selection else ""), flush=True)
        with (output / f"{name}.log").open("w", encoding="utf-8") as log:
            try:
                result = subprocess.run(command, cwd=root, stdout=log,
                                        stderr=subprocess.STDOUT, timeout=args.timeout)
                code = result.returncode
                state = ("PASSED" if code == 0 else
                         "SIGNAL_TERMINATED" if code < 0 else "FAILED")
            except subprocess.TimeoutExpired:
                code, state = None, "TIMED_OUT"
        counts = None
        if junit.is_file():
            suites = ET.parse(junit).getroot().iter("testsuite")
            counts = {key: 0 for key in ("tests", "failures", "errors", "skipped")}
            for suite in suites:
                for key in counts:
                    counts[key] += int(suite.get(key, "0"))
            if state == "PASSED" and counts["skipped"]:
                state = "PASSED_WITH_SKIPS"
        evidence["results"].append({
            "suite": name, "selection": selection, "argv": command,
            "test_source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "exit_code": code, "state": state,
            "counts": counts,
            "elapsed_seconds": round(time.monotonic() - start, 3),
            "log": f"{name}.log",
        })
        (output / "results.json").write_text(json.dumps(evidence, indent=2) + "\n")
        print(f"{state} {name} ({evidence['results'][-1]['elapsed_seconds']}s)", flush=True)
    return int(any(item["state"] != "PASSED" for item in evidence["results"]))


if __name__ == "__main__":
    raise SystemExit(main())
