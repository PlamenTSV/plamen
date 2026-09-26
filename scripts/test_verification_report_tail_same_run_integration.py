"""Same-run SC queue conservation and blocked-report debt integration.

The semantic payload is deliberately tiny, but the authority path is not: a
real audit snapshot and durable Checkpoint enter the production verification
queue boundary, its T0--T9 publication feeds the production dynamic verifier,
and a failed external verifier is retained by the production aggregate.  The
test proves that unresolved work cannot become report authority and that the
report prework remains non-consumable until the intervening R10 producer has
committed. Initially Low cases check Core's policy exclusions and exercise a
harmless real verifier child in Thorough mode through aggregation. No case is
a positive queue-to-final-report acceptance test or semantic audit proof.
Queue, PhaseIO, verifier, aggregate, report, and replay validators remain
production code.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
from typing import Any, Callable, Mapping

import pytest


SCRIPTS = Path(__file__).resolve().parent
IMPLEMENTATION_ROOT = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(IMPLEMENTATION_ROOT))

from artifact_ledger import read_artifact_ledger  # noqa: E402
from audit_snapshot import build_audit_snapshot  # noqa: E402
import plamen_driver as driver  # noqa: E402
import plamen_validators as validator  # noqa: E402
import test_live_verify_queue_driver_adapter_cutover as ADAPTER  # noqa: E402
import test_live_verify_queue_main_boundary_a0 as QUEUE  # noqa: E402
import test_live_verify_queue_semantic_success_paths as SEMANTIC  # noqa: E402
import test_r10_demotion_gate as R10  # noqa: E402
from verify_queue_transaction import (  # noqa: E402
    validate_live_verify_queue_publication,
)


def _same_run_verifier_binary(root: Path) -> Path:
    # Runtime doubles are test infrastructure, never audit target inputs.
    return root.parent.parent / "fixture-codex-same-run-verifier"


def _patch_compat_codex_lookup(
    monkeypatch: pytest.MonkeyPatch, binary: Path,
) -> None:
    """Route only this runtime's provider lookup, not shared tool discovery."""
    import posix_v2_compat_runtime as compat

    original_tools = compat.shutil

    def which(name: str, *args: Any, **kwargs: Any) -> str | None:
        if name == "codex":
            return str(binary)
        return original_tools.which(name, *args, **kwargs)

    monkeypatch.setattr(
        compat, "shutil", SimpleNamespace(**{**vars(original_tools), "which": which})
    )


def _inventory_bytes(*, severity: str = "High") -> bytes:
    text = SEMANTIC._inventory(
        ("INV-1", severity),
        ("INV-2", severity),
        ("INV-3", severity),
    )
    # The live prequeue floor requires both three parseable blocks and a
    # meaningful byte floor.  Padding remains inside the last prose block.
    return (text + "\n" + ("same-run evidence context " * 32) + "\n").encode()


def _install_supported_queue_seed(
    monkeypatch: pytest.MonkeyPatch,
    *,
    severity: str = "High",
    mode: str | None = None,
) -> None:
    """Upgrade only the existing queue test builders to genuine inputs."""

    original_dimensions = ADAPTER._dimensions
    original_claim_group = ADAPTER._claim_group
    original_chain_pair = QUEUE._claim_chain_model_pair

    def dimensions(**kwargs: Any) -> dict[str, Any]:
        config = original_dimensions(**kwargs)
        if mode is not None:
            # Select the initial audit scope before snapshot capture or any
            # producer claim; never mutate a published queue's policy.
            config["mode"] = mode
        # QUEUE._seed later writes this exact context file.  It is part of the
        # complete project-context denominator even though `.unit` is not an
        # EVM production suffix, so it must exist before initial snapshot
        # capture; the later byte-identical write cannot cause input drift.
        context = Path(kwargs["project"]) / "src" / "main.unit"
        context.parent.mkdir(parents=True, exist_ok=True)
        context.write_bytes(b"// bounded main-boundary context\n")
        config["_audit_snapshot"] = build_audit_snapshot(
            config, IMPLEMENTATION_ROOT
        )
        return config

    def claim_group(**kwargs: Any) -> None:
        if kwargs.get("work_unit_id") == "final_mutable_roots":
            Path(kwargs["root"], "findings_inventory.md").write_bytes(
                _inventory_bytes(severity=severity)
            )
        original_claim_group(**kwargs)

    def claim_chain_pair(**kwargs: Any) -> None:
        root = Path(kwargs["root"])
        (root / "hypotheses.md").write_text(
            "# Hypotheses\n\n"
            "| Hypothesis ID | Severity | Title | Constituent Findings |\n"
            "|---|---|---|---|\n"
            f"| H-1 | {severity} | Same-run state integrity | "
            "INV-1, INV-2, INV-3 |\n",
            encoding="utf-8",
        )
        (root / "finding_mapping.md").write_text(
            "# Finding Mapping\n\n"
            "| Finding ID | Hypothesis ID | Mapping Status |\n"
            "|---|---|---|\n"
            "| INV-1 | H-1 | GROUPED |\n"
            "| INV-2 | H-1 | GROUPED |\n"
            "| INV-3 | H-1 | GROUPED |\n",
            encoding="utf-8",
        )
        (root / "enabler_results.md").write_text(
            "# Enabler Results\n\n"
            "H-1 retains the exact three-candidate denominator.\n",
            encoding="utf-8",
        )
        original_chain_pair(**kwargs)

    monkeypatch.setattr(ADAPTER, "_dimensions", dimensions)
    monkeypatch.setattr(ADAPTER, "_claim_group", claim_group)
    monkeypatch.setattr(QUEUE, "_claim_chain_model_pair", claim_chain_pair)


def _unit_by_suffix(ledger: Mapping[str, Any], suffix: str) -> Mapping[str, Any]:
    matches = [
        unit
        for key, unit in ledger["work_units"].items()
        if key.endswith(suffix)
    ]
    assert len(matches) == 1, (suffix, matches)
    return matches[0]


def _active_unit(ledger: Mapping[str, Any], suffix: str) -> Mapping[str, Any]:
    unit = _unit_by_suffix(ledger, suffix)
    assert unit["semantic_status"] == "ACTIVE"
    assert unit["execution_state"] == "OUTPUT_COMMITTED"
    return unit


def _low_verifier_bytes(work_id: str) -> bytes:
    """Return deterministic prose satisfying the shared execution policy."""

    return (
        f"# Verification: {work_id}\n\n"
        f"**Finding ID**: {work_id}\n\n"
        "**Severity**: Low\n\n"
        "**Verdict**: CONTESTED\n\n"
        "**Location**: `src/Unit.sol:L1`\n\n"
        "**Evidence Tag**: [CODE-TRACE]\n\n"
        "The bounded source trace retains the candidate but cannot establish "
        "an executable harm. The remaining likelihood premise depends on an "
        "external best-case condition. [EXTERNAL-ASSUMPTION: fixture condition]\n\n"
        "**PoC Class**: structural\n\n"
        "### PoC Attempt\n"
        "- PoC Required: YES\n"
        "- Attempted: YES\n"
        "- Test File: `src/Unit.sol`\n"
        "- Command: `test -s src/Unit.sol`\n\n"
        "### Execution Result\n"
        "- Compiled: YES\n"
        "- Result: PASS\n"
    ).encode("utf-8")


def _run_same_run_harmless_verifier(
    *,
    root: Path,
    config: dict[str, Any],
    checkpoint: Any,
    phases: list[Any],
    monkeypatch: pytest.MonkeyPatch,
    after_run: Callable[[], None] | None = None,
    expected_incomplete_phase: str | None = None,
) -> None:
    """Run one fake Codex executable through the real verifier transaction."""

    if os.name != "posix":
        pytest.skip("harmless verifier child requires the POSIX runtime")
    import posix_v2_compat_runtime as compat

    planner = next(
        phase for phase in phases if phase.name == "sc_verify_crithigh"
    )
    outcome = driver._prepare_dynamic_verifier_roster(root, config, planner)
    assert outcome.debts == ()
    assert outcome.roster is not None
    assert len(outcome.roster.work_units) == 1
    unit = outcome.roster.work_units[0]
    assert unit.tier_pool == "low_info"
    items = {
        item.work_item_id: item
        for item in driver._read_typed_queue_work_items(
            root / "verification_queue.md"
        )
    }
    binary = _same_run_verifier_binary(root)
    real_codex_execute = driver._run_one_codex_exec
    verifier_phase_name = driver._dynamic_verifier_coordinator_map(config)[
        unit.tier_pool
    ]

    def execute_after_dispatch(*args: Any, **kwargs: Any) -> Any:
        contract = kwargs.get("phase_io_contract")
        phase = kwargs.get("phase")
        if not (
            getattr(phase, "name", "") == verifier_phase_name
            and str(getattr(contract, "key", "")).endswith(
                f"/method_model.{unit.work_unit_id}"
            )
        ):
            return real_codex_execute(*args, **kwargs)
        payloads: dict[str, bytes] = {}
        for work_id in unit.ordered_work_item_ids:
            payloads[f"verify_{work_id}.md"] = _low_verifier_bytes(work_id)
            payloads[f"verify_{work_id}.severity_proposal.json"] = (
                R10._r10_low_external_severity_proposal(items[work_id])
            )
            R10._write_r10_operator_application(
                root, unit.work_unit_id, work_id
            )
            application = root / f"verify_{work_id}.operator_application.json"
            payloads[application.name] = application.read_bytes()
            application.unlink()
        encoded = {
            name: base64.b64encode(raw).decode("ascii")
            for name, raw in payloads.items()
        }
        banner = (
            "OpenAI Codex v0.test\n--------\nworkdir: /fixture\n"
            f"model: {kwargs['effective_model']}\nprovider: openai\n"
            "--------\nuser\n"
        )
        binary.write_text(
            f"#!{sys.executable} -B\n"
            "import base64,json,re,sys\n"
            "from pathlib import Path\n"
            "if sys.argv[1:] == ['--version']:\n"
            " print('codex-cli same-run-fixture'); raise SystemExit(0)\n"
            "prompt=sys.stdin.buffer.read().decode('utf-8')\n"
            f"sys.stderr.write({banner!r})\n"
            "routes=json.loads(re.findall(r'```json\\n(.*?)\\n```',prompt,re.S)[-1])['output_routes']\n"
            f"payloads={encoded!r}\n"
            "for route in routes:\n"
            " target=Path(route['path']); target.parent.mkdir(parents=True,exist_ok=True)\n"
            " target.write_bytes(base64.b64decode(payloads[Path(route['canonical_path']).name]))\n"
            "Path(sys.argv[sys.argv.index('-o')+1]).write_text('complete\\n')\n"
            "print(json.dumps({'type':'turn.completed'},sort_keys=True))\n",
            encoding="utf-8",
        )
        binary.chmod(0o755)
        return real_codex_execute(*args, **kwargs)

    session = compat.issue_posix_v2_compat_session_for_installed_front(
        run_id=config["_run_id"], project_root=root.parent, scratchpad=root
    )
    try:
        with monkeypatch.context() as runtime_patch:
            runtime_patch.setattr(
                driver,
                "_POSIX_COMPAT_V2_PROCESS_MARKER",
                driver._POSIX_COMPAT_V2_MARKER_TOKEN,
            )
            runtime_patch.setattr(
                driver, "_POSIX_COMPAT_V2_SESSION_AUTHORITY", session
            )
            runtime_patch.setattr(
                driver, "_run_one_codex_exec", execute_after_dispatch
            )
            _patch_compat_codex_lookup(runtime_patch, binary)
            runtime_patch.setattr(
                compat,
                "_load_ambient_codex_auth",
                lambda: ("PRIVATE_AUTH_JSON_COPY", b'{"tokens":{}}\n', "c" * 64),
            )
            for phase_name in driver._dynamic_verifier_coordinator_map(
                config
            ).values():
                phase = next(item for item in phases if item.name == phase_name)
                try:
                    assert driver._handle_dynamic_verifier_phase(
                        phase,
                        checkpoint,
                        root,
                        config,
                        phases,
                        phase_idx=phases.index(phase),
                        total_active=len(phases),
                    ) is True
                except SystemExit as exc:
                    if phase.name != expected_incomplete_phase:
                        raise
                    assert exc.code == driver.EXIT_DEGRADED
                    assert checkpoint.phase_commits[phase.name].state == "INCOMPLETE_WITH_DEBT"
                    break
                if phase.name == expected_incomplete_phase:
                    pytest.fail("incomplete verifier authority did not halt progression")
            if after_run is not None:
                after_run()
    finally:
        session.close()


def test_same_run_queue_verifier_debt_is_retained_at_blocked_report_prework(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    (project / "src").mkdir(parents=True)
    (project / "src" / "Unit.sol").write_text(
        "pragma solidity ^0.8.20; contract Unit { uint256 public value; }\n",
        encoding="utf-8",
    )
    _install_supported_queue_seed(monkeypatch)
    root, config, run_id = QUEUE._seed(
        project,
        pipeline="sc",
        backend="codex",
        preseed_adapter_successors=False,
    )
    phase, phases = QUEUE._phase_and_graph("sc")
    checkpoint = QUEUE._checkpoint(root, config, run_id)
    snapshot_digest = config["_audit_snapshot"]["snapshot_digest"]
    checkpoint_before = (root / "_v2_checkpoint.json").read_bytes()

    outcome = QUEUE._invoke(
        boundary=QUEUE._boundary(),
        phase=phase,
        checkpoint=checkpoint,
        root=root,
        config=config,
        phases=phases,
    )
    assert outcome["state"] == "COMMITTED", outcome
    assert outcome["safe_to_continue"] is True
    assert phase.name in checkpoint.completed
    checkpoint_after_queue = (root / "_v2_checkpoint.json").read_bytes()
    assert checkpoint_after_queue != checkpoint_before

    plan = outcome["cutover_result"]["plan"]
    publication = validate_live_verify_queue_publication(
        scratchpad=root,
        project_root=project,
        plan=plan,
        run_id=run_id,
    )
    assert publication["safe_to_consume"] is True
    queue_rows = validator.parse_verification_queue_rows(root)
    queue_ids = [row["finding id"] for row in queue_rows]
    # The chain-pair projection is deliberately advisory in this genuine
    # fixture: absent an authorized evidence projection, T0 conservatively
    # preserves all three inventory candidates instead of trusting H-1 as a
    # destructive grouping instruction.
    assert queue_ids == ["INV-1", "INV-2", "INV-3"]

    provider_calls = 0

    def failed_verifier_executor(*_args: Any, **_kwargs: Any) -> int:
        nonlocal provider_calls
        provider_calls += 1
        # A deterministic nonzero provider result produces typed verifier
        # debt.  It writes no plausible verification prose and therefore
        # cannot manufacture proof authority.
        return 17

    monkeypatch.setattr(
        driver, "_execute_dynamic_verifier_launch", failed_verifier_executor
    )
    verifier_phase = next(
        candidate for candidate in phases
        if candidate.name == "sc_verify_crithigh"
    )
    assert driver._handle_dynamic_verifier_phase(
        verifier_phase,
        checkpoint,
        root,
        config,
        phases,
        phase_idx=phases.index(verifier_phase),
        total_active=len(phases),
    ) is True

    roster_outcome = driver._prepare_dynamic_verifier_roster(
        root, config, verifier_phase
    )
    assert roster_outcome.debts == ()
    assert roster_outcome.roster is not None
    pending_units = [
        unit for unit in roster_outcome.roster.work_units
        if unit.ordered_work_item_ids
    ]
    assert len(pending_units) == 1
    unit = pending_units[0]
    receipt = json.loads(
        driver._dynamic_verifier_unit_paths(root, unit.work_unit_id)[
            "receipt"
        ].read_text(encoding="utf-8")
    )
    assert receipt["status"] == "DEBT"
    assert receipt["reason_class"] == "WORKER_EXECUTION_DEBT"
    assert list(unit.ordered_work_item_ids) == queue_ids
    assert provider_calls == 1
    assert not list(root.glob("verify_*.md"))

    aggregate_phase = next(
        candidate for candidate in phases
        if candidate.name == "sc_verify_aggregate"
    )
    aggregate_issues, pending = driver._dynamic_verifier_aggregate_issues(
        root, config
    )
    assert aggregate_issues
    assert list(pending) == queue_ids
    driver._retain_dynamic_verification_debt(
        root, config, aggregate_issues, pending
    )
    aggregate_sentinel = root / f"{aggregate_phase.name}.degraded"
    aggregate_sentinel.write_text(
        "Dynamic verifier children remain unresolved; the aggregate was not "
        "allowed to synthesize proof or invoke legacy recovery/stubs.\n"
        + "\n".join(f"- {issue}" for issue in aggregate_issues)
        + "\n",
        encoding="utf-8",
    )
    for issue in aggregate_issues:
        driver._append_phase_io_debt(
            root,
            aggregate_phase.name,
            "DYNAMIC_VERIFIER_AGGREGATE_DEBT",
            issue,
        )
    aggregate_commit = driver._commit_phase_from_disk_debt(
        aggregate_phase,
        checkpoint,
        root,
        config,
        phases,
        clean_transients=False,
    )
    assert aggregate_commit.state == "COMPLETED_WITH_DEBT"
    checkpoint_after_aggregate = (root / "_v2_checkpoint.json").read_bytes()
    assert checkpoint_after_aggregate != checkpoint_after_queue

    debt = json.loads(
        (root / driver._DYNAMIC_VERIFIER_DEBT_NAME).read_text(
            encoding="utf-8"
        )
    )
    assert debt["pending_work_item_ids"] == queue_ids
    assert debt["proof_authority"] == "NONE"
    assert debt["verifier_status"] == "UNRESOLVED"
    assert debt["report_verification_projection"] == "CONTESTED"
    assert validator._validate_report_verification_denominator(root) == []
    assert validator._expected_report_index_statuses(root) == {
        finding_id: "CONTESTED" for finding_id in queue_ids
    }
    assert set(validator._expected_report_index_severities(root)) == set(
        queue_ids
    )

    candidates = validator._report_candidate_rows_for_validator(root)
    assert [str(row["finding id"]) for row in candidates] == queue_ids
    # Candidate rows supply the queue denominator; verification status comes
    # from the separately authenticated status projection, not a queue column.
    candidate_statuses = validator._expected_report_index_statuses(root)
    assert {
        candidate_statuses[str(row["finding id"])] for row in candidates
    } == {"CONTESTED"}

    # This fixture intentionally stops before the intervening R10 DRIVER
    # producer.  Report prework must therefore remain non-consumable instead
    # of treating typed verifier debt as sufficient report authority.  A
    # repeated readiness check may replay deterministic validation, but it
    # must not implicitly relaunch the failed verifier child or emit report
    # artifacts.
    ready, prework_issues = driver._run_report_index_prework_transaction(
        root, config
    )
    assert ready is False
    assert len(prework_issues) == 1
    assert prework_issues[0].startswith(
        "report-index prework PhaseIO prebind failed: ValueError: "
        "R10 report prework requires its mandatory committed compute "
        "receipt: FileNotFoundError:"
    )
    assert "external_assumption_undemotion_compute.json" in prework_issues[0]
    assert driver._run_report_index_prework_transaction(root, config) == (
        False,
        prework_issues,
    )
    assert provider_calls == 1
    assert not (root / "report_records.json").exists()
    assert not (root / "body_manifests").exists()
    assert not (root / "report_index.md").exists()
    assert not (root / "report_index_coverage_seed.md").exists()
    assert not (root / "severity_binding.md").exists()
    assert not (root / "status_binding.md").exists()

    ledger = read_artifact_ledger(root)
    t9 = _active_unit(ledger, "/t9.live_receipt_last_cas")
    assert t9["run_id"] == run_id
    assert not any(
        key.endswith("/report_index/prework")
        for key in ledger["work_units"]
    )
    assert config["_audit_snapshot"]["snapshot_digest"] == snapshot_digest
    assert checkpoint.run_id == run_id
    assert checkpoint.audit_snapshot["snapshot_digest"] == snapshot_digest
    assert (root / "_v2_checkpoint.json").read_bytes() == (
        checkpoint_after_aggregate
    )


@pytest.mark.parametrize("mode", ("core", "thorough"))
def test_same_run_low_queue_respects_mode_and_retains_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str,
) -> None:
    """Preserve policy exclusions or queued work under the initial mode.

    Low is the initial severity, never a later downgrade. Core excludes these
    rows; only Thorough enters the nonempty harmless verifier transaction and
    its execution-policy-required structural attempt ledger.
    This is not semantic audit proof, PoC execution, R10, or final report
    acceptance. All production verification obligations remain enforced.
    """
    if os.name != "posix":
        pytest.skip("harmless verifier child requires the POSIX runtime")
    project = tmp_path / "positive-project"
    (project / "src").mkdir(parents=True)
    (project / "src" / "Unit.sol").write_text(
        "pragma solidity ^0.8.20; contract Unit { uint256 public value; }\n",
        encoding="utf-8",
    )
    _install_supported_queue_seed(monkeypatch, severity="Low", mode=mode)
    root, config, run_id = QUEUE._seed(
        project, pipeline="sc", backend="codex", preseed_adapter_successors=False,
    )
    assert config["mode"] == mode
    queue_phase, phases = QUEUE._phase_and_graph("sc")
    checkpoint = QUEUE._checkpoint(root, config, run_id)
    outcome = QUEUE._invoke(
        boundary=QUEUE._boundary(), phase=queue_phase, checkpoint=checkpoint,
        root=root, config=config, phases=phases,
    )
    assert outcome["state"] == "COMMITTED", outcome
    assert outcome["safe_to_continue"] is True
    plan = outcome["cutover_result"]["plan"]

    def publication():
        return validate_live_verify_queue_publication(
            scratchpad=root, project_root=project, plan=plan, run_id=run_id,
        )

    assert publication()["safe_to_consume"] is True
    queue_projection = [
        (row["finding id"], row["severity"])
        for row in validator.parse_verification_queue_rows(root)
    ]
    expected = [(f"INV-{number}", "Low") for number in (1, 2, 3)]
    assert queue_projection == (expected if mode == "thorough" else [])
    excluded = json.loads(
        (root / "verification_queue_evidence_excluded.json").read_text()
    )["rows"]
    assert [(row["finding id"], row["severity"]) for row in excluded] == (
        expected if mode == "core" else []
    )
    if mode == "core":
        # T9 normalizes public exclusions to an authority code. The detailed
        # mode decision is retained by the validated T2 policy transaction.
        assert all(row["exclusion reason"] == "AUTHORIZED_EXCLUDED" for row in excluded)
        policy = json.loads((root / "_live_verify_queue_transaction" / "t2" /
                             "policy_disposition.json").read_text())
        assert policy["mode"] == "core"
        assert policy["base_record_set_digest"] == policy["excluded_record_set_digest"]
        policy_rows = json.loads(base64.b64decode(
            policy["projection_files"]["verification_queue_evidence_excluded.json"]
            ["content_b64"]
        ))["rows"]
        assert [(row["finding id"], row["severity"]) for row in policy_rows] == expected
        assert all("core mode" in row["exclusion reason"] for row in policy_rows)

    def retained_queue_state():
        state = read_artifact_ledger(root)
        return (
            {
                name: (root / name).read_bytes() if (root / name).is_file() else None
                for name in plan["public_output_denominator"]
            },
            json.dumps({
                child["work_unit_id"]: _unit_by_suffix(state, "/" + child["work_unit_id"])
                for child in plan["children"]
            }, sort_keys=True),
            json.dumps({
                name: state["artifact_bindings"].get(f"scratchpad:{name}")
                for name in plan["public_output_denominator"]
            }, sort_keys=True),
        )

    before = retained_queue_state()
    if mode == "core":
        assert publication()["safe_to_consume"] is True
        assert retained_queue_state() == before
        assert checkpoint.run_id == run_id
        return
    aggregate_after_run: list[tuple[list[str], tuple[str, ...]]] = []

    def capture_same_run_aggregate() -> None:
        aggregate_after_run.append(
            driver._dynamic_verifier_aggregate_issues(root, config)
        )

    _run_same_run_harmless_verifier(
        root=root, config=config, checkpoint=checkpoint, phases=phases,
        monkeypatch=monkeypatch,
        after_run=capture_same_run_aggregate,
    )
    assert aggregate_after_run == [([], ())]
    assert set(driver._dynamic_verifier_coordinator_map(config).values()).issubset(
        checkpoint.completed
    )
    assert retained_queue_state() == before
    assert [
        (row["finding id"], row["severity"])
        for row in validator.parse_verification_queue_rows(root)
    ] == queue_projection
    assert publication()["safe_to_consume"] is True
    assert checkpoint.run_id == run_id
