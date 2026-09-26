"""Supported Core policy-empty queue into real aggregate/R10/report prework.

This zero-active route complements, never replaces, nonempty verifier and
provider E2E acceptance. No production validation functions are substituted.
"""
from pathlib import Path
from types import SimpleNamespace
import json
import os
import sys

import pytest

import plamen_driver as D
import plamen_validators as V
from artifact_ledger import read_artifact_ledger
from audit_snapshot import build_audit_snapshot
import test_live_verify_queue_main_boundary_a0 as QUEUE
from test_verification_report_tail_same_run_integration import (
    _install_supported_queue_seed,
)
from verify_queue_transaction import validate_live_verify_queue_publication
from test_support_startup_permit import durable_startup_permit


pytestmark = pytest.mark.integration


@pytest.fixture
def core_report_prework(tmp_path: Path, monkeypatch):
    project = tmp_path / "core-report-project"
    (project / "src").mkdir(parents=True)
    (project / "src" / "Unit.sol").write_text(
        "pragma solidity ^0.8.20; contract Unit { uint256 public value; }\n",
        encoding="utf-8",
    )
    _install_supported_queue_seed(monkeypatch, severity="Low", mode="core")
    initial_dimensions = QUEUE.ADAPTER_FIXTURE._dimensions

    def dimensions(**kwargs):
        config = initial_dimensions(**kwargs)
        config["_auxiliary_writable_root_startup_binding"] = durable_startup_permit(
            kwargs["root"], run_id=kwargs["run_id"],
        )
        config["_audit_snapshot"] = build_audit_snapshot(
            config, Path(__file__).resolve().parent.parent,
        )
        return config

    monkeypatch.setattr(QUEUE.ADAPTER_FIXTURE, "_dimensions", dimensions)
    root, config, run_id = QUEUE._seed(
        project, pipeline="sc", backend="codex", preseed_adapter_successors=False,
    )
    dependency = D._ensure_recon_dependency_parity(root, str(project), config)
    assert dependency["expected_ids"] == []
    assert dependency["researched"] == dependency["unresolved"] == 0
    dependency_binding = read_artifact_ledger(root)["artifact_bindings"][
        "scratchpad:external_dependency_research.md"
    ]
    assert dependency_binding["owner_key"].endswith("/recon/dependency_reconcile")
    assert dependency_binding["run_id"] == run_id
    assert dependency_binding["status"] == "ACTIVE"
    inventory_before = (root / "findings_inventory.md").read_bytes()
    assert D._run_sc_semantic_dedup_noop(
        root, config, "fixture conservative preserve-all",
    ) == ["dedup_decisions.md", "findings_inventory_deduped.md"]
    assert (root / "findings_inventory_deduped.md").read_bytes() == inventory_before
    dedup_binding = read_artifact_ledger(root)["artifact_bindings"][
        "scratchpad:dedup_decisions.md"
    ]
    assert dedup_binding["owner_key"].endswith("/sc_semantic_dedup/noop_passthrough")
    assert dedup_binding["run_id"] == run_id
    assert dedup_binding["status"] == "ACTIVE"
    queue_phase, phases = QUEUE._phase_and_graph("sc")
    checkpoint = QUEUE._checkpoint(root, config, run_id)
    result = QUEUE._invoke(
        boundary=QUEUE._boundary(), phase=queue_phase, checkpoint=checkpoint,
        root=root, config=config, phases=phases,
    )
    assert result["state"] == "COMMITTED" and result["safe_to_continue"], result
    plan = result["cutover_result"]["plan"]
    before = {
        name: (root / name).read_bytes() if (root / name).is_file() else None
        for name in plan["public_output_denominator"]
    }
    assert V.parse_verification_queue_rows(root) == []
    excluded = json.loads((root / "verification_queue_evidence_excluded.json").read_text())["rows"]
    assert [(row["finding id"], row["severity"]) for row in excluded] == [
        ("INV-1", "Low"), ("INV-2", "Low"), ("INV-3", "Low"),
    ]
    assert all(row["exclusion reason"] == "AUTHORIZED_EXCLUDED" for row in excluded)
    empty, reason = V.is_verification_queue_empty(root, "sc")
    assert empty, reason
    aggregate = next(phase for phase in phases if phase.name == "sc_verify_aggregate")
    kwargs = dict(scratchpad=root, config=config, phase=aggregate)
    assert D._write_empty_verify_aggregate_projection(**kwargs, reason=reason) == []
    assert D._close_empty_verify_aggregate_r10(**kwargs) == []
    compute = json.loads((root / "external_assumption_undemotion_compute.json").read_text())
    assert compute["outcome"] == "CLEAN_ZERO", compute
    severity = next(row for row in phases if row.name == "severity_adjudication_shadow")

    def no_severity_worker(*_args, **_kwargs):
        pytest.fail("zero severity denominator must not launch a provider worker")

    with monkeypatch.context() as severity_guard:
        severity_guard.setattr(
            D, "_build_severity_adjudication_worker_launch_spec", no_severity_worker,
        )
        reconciliation, severity_issues = D._run_severity_adjudication_shadow_phase(
            severity, config, root,
        )
    assert severity_issues == []
    assert reconciliation["denominator_count"] == 0
    assert reconciliation["all_resolved"] is True
    severity_binding = read_artifact_ledger(root)["artifact_bindings"][
        "scratchpad:severity_decision_ledger.shadow.json"
    ]
    assert severity_binding["owner_key"].endswith(
        "/severity_adjudication_shadow/source_empty"
    )
    assert severity_binding["status"] == "ACTIVE"
    assert D._reconcile_trust_evidence_provider_state(root, config) == []
    _bb_terminal, bb_issues = D._run_bb_policy_terminal_boundary(root, config)
    assert bb_issues == []
    gate_ok, gate_issues = D.gate_passes(root, str(project), severity)
    assert gate_ok, gate_issues
    D.PhaseCommitController(checkpoint, root, str(project), config).commit(
        severity, "CLEAN", (), clean_transients=True,
    )
    ready, issues = D._run_report_index_prework_transaction(root, config)
    assert ready and not issues, issues
    assert D._r10_report_consumer_ready_issues(root, config) == []
    assert validate_live_verify_queue_publication(
        scratchpad=root, project_root=project, plan=plan, run_id=run_id,
    )["safe_to_consume"] is True
    assert {
        name: (root / name).read_bytes() if (root / name).is_file() else None
        for name in before
    } == before
    return SimpleNamespace(
        root=root, project=project, config=config, run_id=run_id,
        phases=phases, checkpoint=checkpoint, plan=plan, excluded=excluded,
    )


def test_core_policy_empty_publication_reaches_authentic_report_prework(core_report_prework):
    case = core_report_prework
    ledger = read_artifact_ledger(case.root)
    for suffix in ("/empty_aggregate_projection", "/report_index/prework"):
        units = [row for key, row in ledger["work_units"].items() if key.endswith(suffix)]
        assert len(units) == 1
        assert units[0]["run_id"] == case.run_id
        assert units[0]["semantic_status"] == "ACTIVE"
        assert units[0]["execution_state"] == "OUTPUT_COMMITTED"
    roster = json.loads((case.root / "verification_runtime_roster.json").read_text())
    assert roster["pipeline"] == "sc" and roster["mode"] == "core"
    assert roster["ordered_work_item_ids"] == roster["work_units"] == []
    assert not (case.root / "report_index.md").exists()


def _run_report_child(case, monkeypatch, request):
    """Exercise real report routing/authority with a provider-free local child."""
    if os.name != "posix":
        pytest.skip("harmless report child requires POSIX compatibility")
    import posix_v2_compat_runtime as compat

    phase = next(row for row in case.phases if row.name == "report_index")
    contract, launch = D._typed_model_phase_contract_and_launch(
        phase, case.root, case.config,
    )
    assert contract is not None and contract.model_invoked
    assert D._bind_typed_model_phase_inputs(phase, case.root, case.config) == []
    outputs = {
        "report_index.md": (
            "# Report Index\n\n"
            "The authenticated Core queue contains no active report candidates. "
            "No reportable finding is asserted here. Retained policy exclusions "
            "remain in the upstream evidence.\n"
        ),
        "report_coverage.md": (
            "# Report Coverage\n\n"
            "The authenticated active candidate denominator is zero. This "
            "worker makes no finding, merge, or exclusion decision; canonical "
            "coverage must retain the upstream identities.\n"
        ),
    }
    binary = case.project.parent / "fixture-codex-core-report"
    binary.write_text(
        f"#!{sys.executable} -B\n"
        "import json,re,sys\nfrom pathlib import Path\n"
        "if sys.argv[1:] == ['--version']:\n"
        " print('codex-cli core-report-fixture'); raise SystemExit(0)\n"
        "prompt=sys.stdin.read()\n"
        f"sys.stderr.write('OpenAI Codex v0.test\\n--------\\nworkdir: /fixture\\nmodel: {launch.model}\\nprovider: openai\\n--------\\nuser\\n')\n"
        "blocks=[json.loads(b) for b in re.findall(r'```json\\s*(.*?)\\s*```',prompt,re.S)]\n"
        "routing=next(b for b in blocks if b.get('schema')=='plamen.posix_v2_codex_local_phaseio.v1')\n"
        f"outputs={outputs!r}\n"
        "for route in routing['output_routes']:\n"
        " target=Path(route['path']); target.write_text(outputs[target.name])\n"
        "Path(sys.argv[sys.argv.index('-o')+1]).write_text('complete\\n')\n"
        "print(json.dumps({'type':'turn.completed'}))\n",
        encoding="utf-8",
    )
    binary.chmod(0o755)
    session = compat.issue_posix_v2_compat_session_for_installed_front(
        run_id=case.run_id, project_root=case.project, scratchpad=case.root,
    )
    request.addfinalizer(session.close)
    monkeypatch.setattr(D, "_POSIX_COMPAT_V2_PROCESS_MARKER", D._POSIX_COMPAT_V2_MARKER_TOKEN)
    monkeypatch.setattr(D, "_POSIX_COMPAT_V2_SESSION_AUTHORITY", session)
    original_which = compat.shutil.which
    monkeypatch.setattr(
        compat.shutil, "which",
        lambda name, *args, **kwargs: (
            str(binary) if name == "codex" else original_which(name, *args, **kwargs)
        ),
    )
    monkeypatch.setattr(
        compat, "_load_ambient_codex_auth",
        lambda: ("PRIVATE_AUTH_JSON_COPY", b'{"tokens":{}}\n', "c" * 64),
    )
    assert D._run_one_codex_exec(
        prompt="Write the assigned harmless zero-active report fixtures.\n",
        phase=phase, config=case.config, scratchpad=case.root, attempt=1,
        label="report_index", expected_outputs=[spec.path for spec in contract.outputs],
        timeout=float(launch.timeout_s), effective_model=launch.model,
        phase_io_contract=contract, phase_io_launch=launch,
    ) == 0
    return phase, contract, launch


@pytest.mark.parametrize("fault_point", (None, "after_publish:report_index.md"))
def test_core_policy_empty_reaches_report_child_and_canonical(
    core_report_prework, monkeypatch, request, fault_point,
):
    case = core_report_prework
    queue_before = {
        name: (case.root / name).read_bytes() if (case.root / name).is_file() else None
        for name in case.plan["public_output_denominator"]
    }
    phase, contract, launch = _run_report_child(case, monkeypatch, request)
    unit = read_artifact_ledger(case.root)["work_units"][contract.key]
    assert unit["semantic_status"] == "ACTIVE"
    assert unit["execution_state"] == "OUTPUT_COMMITTED"
    assert unit["execution_authority"]
    execution_authority = unit["execution_authority"]
    model_bytes = {
        spec.path: (case.root / spec.path).read_bytes() for spec in contract.outputs
    }

    def no_worker_relaunch(*args, **kwargs):
        pytest.fail("canonical recovery must not relaunch the report worker")

    monkeypatch.setattr(D, "_run_one_codex_exec", no_worker_relaunch)
    if fault_point is not None:
        fired = []

        def crash(point):
            if point == fault_point:
                fired.append(point)
                raise RuntimeError("canonical publication interrupted")

        with pytest.raises(RuntimeError, match="canonical publication interrupted"):
            D._run_report_index_canonicalization_transaction(
                phase, case.root, case.config, fault_inject=crash,
            )
        assert fired == [fault_point]
        assert (case.root / "report_index.md").read_bytes() != model_bytes["report_index.md"]
        assert (case.root / "report_coverage.md").read_bytes() == model_bytes["report_coverage.md"]
        interrupted = read_artifact_ledger(case.root)["work_units"]
        canonical = [row for key, row in interrupted.items() if key.endswith("/report_index/canonicalize")]
        assert len(canonical) == 1
        assert canonical[0]["execution_state"] == "INPUTS_BOUND_PREEXECUTION"
        assert canonical[0]["semantic_status"] == "INPUTS_BOUND"

    assert D._run_report_index_canonicalization_transaction(phase, case.root, case.config) == []
    assert D._run_report_index_canonicalization_transaction(phase, case.root, case.config) == []
    assert D._validate_report_coverage_accounting(case.root) == []
    coverage = (case.root / "report_coverage.md").read_text()
    assert all(identity in coverage for identity in ("INV-1", "INV-2", "INV-3", "H-1"))
    assert "HUMAN_REVIEW_DELIVERED" in coverage
    assert (case.root / "report_dropout_retention.json").is_file()
    assert {
        name: (case.root / name).read_bytes() if (case.root / name).is_file() else None
        for name in queue_before
    } == queue_before
    assert validate_live_verify_queue_publication(
        scratchpad=case.root, project_root=case.project, plan=case.plan, run_id=case.run_id,
    )["safe_to_consume"] is True
    final_units = read_artifact_ledger(case.root)["work_units"]
    assert final_units[contract.key]["execution_authority"] == execution_authority
    assert [key for key in final_units if "/report_index/model" in key] == [contract.key]
