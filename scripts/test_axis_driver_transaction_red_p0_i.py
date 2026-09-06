"""Independent RED specification for the P0-I axis driver transaction.

This file deliberately tests the *driver boundary*, not the standalone v2
reconciler and not only the PhaseIO resolver shapes.  It pins the production
properties that are easiest to lose while wiring the otherwise-correct
deterministic core:

* planning and exact-empty authority exist before a model can be launched;
* accepted model bytes commit before deterministic reconciliation;
* repair is conditional but its DRIVER receipt is unconditional and bounded;
* final reconciliation precedes receipt-driven promotion;
* typed CLEAR rows, rather than Markdown safe-language, enter the negative
  challenge denominator;
* canonical refresh and parent commit happen only after finalization;
* resume replays the complete authority chain and does not rerun good model
  work merely because a deterministic descendant needs repair;
* Claude/Codex share one semantic contract; and
* only smart-contract Thorough schedules this integration.

No model, subprocess, network request, install, audit, or production mutation
is performed by these fixtures.
"""
from __future__ import annotations

import ast
import hashlib
import inspect
import json
from pathlib import Path
from typing import Any, Iterable, Mapping

import pytest

import axis_disposition as AXIS
import enumeration_gate as ENUMERATION
import plamen_driver as DRIVER
from artifact_ledger import read_artifact_ledger
from plamen_types import L1_PHASES, SC_PHASES, Phase
from test_axis_population_provider_p0_i import (
    _project as _population_project,
    _write_graph,
)


RUN_ID = "a1f92547-9973-4e98-8b0b-1efcb2b3b2b2"

_PLANNING_OUTPUTS = (
    "axis_disposition_worklist.json",
    "axis_execution_evidence_authority.json",
)
_BASE_OUTPUTS = (
    "axis_coverage_findings.md",
    "axis_coverage_dispositions.json",
)
_INITIAL_OUTPUTS = (
    "axis_disposition_initial_receipt.json",
    "axis_repair_plan.json",
)
_REPAIR_OUTPUTS = (
    "axis_coverage_repair_findings.md",
    "axis_coverage_repair_dispositions.json",
)
_FINAL_OUTPUTS = (
    "axis_repair_execution_receipt.json",
    "axis_disposition_receipt.json",
    "axis_repair_work.json",
    "axis_assurance_debt.json",
    "axis_assurance_limitations.md",
    "axis_coverage_promotion_receipt.json",
)


def _axis_phase() -> Phase:
    return next(phase for phase in SC_PHASES if phase.name == "axis_coverage")


def _config(
    project: Path,
    *,
    backend: str = "claude",
    pipeline: str = "sc",
    mode: str = "thorough",
    language: str = "evm",
) -> dict[str, Any]:
    return {
        "project_root": str(project),
        "pipeline": pipeline,
        "mode": mode,
        "language": language,
        "cli_backend": backend,
        "_run_id": RUN_ID,
    }


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _write_json(path: Path, value: object) -> None:
    path.write_bytes(_canonical(value))


def _one_item_authority(
    tmp_path: Path,
    *,
    backend: str = "claude",
) -> tuple[Path, Path, dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Create strict v2 planning outputs without claiming PhaseIO ownership."""

    project, scratchpad = _population_project(tmp_path / backend)
    _write_graph(
        scratchpad,
        {
            "Unit.quiet(uint256)": {
                "bare": "quiet",
                "loc": "contracts/Unit.sol:L2",
                "callers": ["one", "two"],
            }
        },
    )
    population = ENUMERATION.compute_axis_population(
        scratchpad,
        run_id=RUN_ID,
    )
    assert population["denominator_status"] == "EXACT"
    assert population["gaps"]
    matrix_raw = _canonical(population)
    worklist = AXIS.compile_axis_worklist_v2(
        population,
        matrix_raw=matrix_raw,
        production_root=project,
        population_authority=population,
        run_id=RUN_ID,
    )
    evidence = AXIS.build_axis_execution_evidence_authority(
        run_id=RUN_ID,
        receipt_bindings=(),
    )
    _write_json(scratchpad / "axis_disposition_worklist.json", worklist)
    _write_json(
        scratchpad / "axis_execution_evidence_authority.json",
        evidence,
    )
    (scratchpad / "findings_inventory.md").write_text(
        "# Findings Inventory\n\nNo candidates yet.\n",
        encoding="utf-8",
    )
    return project, scratchpad, _config(project, backend=backend), worklist, evidence


def _sidecar(
    worklist: Mapping[str, Any],
    rows: list[dict[str, Any]],
) -> bytes:
    unsigned = {
        "schema_version": AXIS.MODEL_DISPOSITIONS_SCHEMA,
        "run_id": RUN_ID,
        "worklist_hash": worklist["worklist_hash"],
        "producer": "MODEL",
        "items": rows,
    }
    return _canonical(
        {
            **unsigned,
            "sidecar_digest": _sha(_canonical(unsigned)),
        }
    )


def _source_clear(item: Mapping[str, Any]) -> dict[str, str]:
    return {
        "kind": "SOURCE_LOCUS",
        "source_relpath": str(item["source_relpath"]),
        "source_locus": str(item["source_locus"]),
        "source_hash": str(item["source_hash"]),
    }


def _call_name(node: ast.Call) -> str:
    function = node.func
    if isinstance(function, ast.Name):
        return function.id
    if isinstance(function, ast.Attribute):
        return function.attr
    return ""


def _calls(node: ast.AST, name: str) -> list[ast.Call]:
    return [
        child
        for child in ast.walk(node)
        if isinstance(child, ast.Call) and _call_name(child) == name
    ]


def _statement_lists(node: ast.AST) -> Iterable[list[ast.stmt]]:
    for _field, value in ast.iter_fields(node):
        if isinstance(value, list) and all(
            isinstance(item, ast.stmt) for item in value
        ):
            yield value
            for item in value:
                yield from _statement_lists(item)
        elif isinstance(value, ast.AST):
            yield from _statement_lists(value)


def _phase_name_test(node: ast.AST, expected: str) -> bool:
    """Recognize ``phase.name == expected`` on either side of a comparison."""

    if not isinstance(node, ast.Compare) or len(node.ops) != 1:
        return False
    if not isinstance(node.ops[0], ast.Eq) or len(node.comparators) != 1:
        return False
    values = (node.left, node.comparators[0])
    has_phase_name = any(
        isinstance(value, ast.Attribute)
        and isinstance(value.value, ast.Name)
        and value.value.id == "phase"
        and value.attr == "name"
        for value in values
    )
    has_expected = any(
        isinstance(value, ast.Constant) and value.value == expected
        for value in values
    )
    return has_phase_name and has_expected


def _assert_driver_surface() -> None:
    required = (
        "_axis_disposition_contract_and_launch",
        "_axis_disposition_exact_inputs",
        "_axis_execution_evidence_authority",
        "_prepare_axis_disposition_worklist",
        "_compile_axis_coverage_model_prompt",
        "_reconcile_axis_dispositions",
        "_run_axis_disposition_repair",
        "_promote_axis_disposition_actions",
        "_axis_disposition_resume_issues",
        "_finalize_axis_coverage_boundary",
        "_axis_coverage_has_no_obligations",
    )
    missing = [name for name in required if not callable(getattr(DRIVER, name, None))]
    assert not missing, "P0-I driver transaction API is missing: " + ", ".join(missing)


def _prepare(
    phase: Phase,
    config: dict[str, Any],
    scratchpad: Path,
) -> tuple[dict[str, Any], list[str]]:
    _assert_driver_surface()
    result = DRIVER._prepare_axis_disposition_worklist(
        phase=phase,
        config=config,
        scratchpad=scratchpad,
    )
    assert isinstance(result, tuple) and len(result) == 2
    worklist, issues = result
    assert isinstance(worklist, Mapping)
    assert isinstance(issues, list)
    return dict(worklist), [str(value) for value in issues]


def _finalize(
    phase: Phase,
    config: dict[str, Any],
    scratchpad: Path,
) -> list[str]:
    _assert_driver_surface()
    result = DRIVER._finalize_axis_coverage_boundary(
        phase=phase,
        config=config,
        scratchpad=scratchpad,
    )
    if isinstance(result, tuple):
        issues = result[-1]
    elif isinstance(result, list):
        issues = result
    elif result is None:
        issues = []
    else:
        raise AssertionError(
            "axis finalizer must return issues or (authority, issues), got "
            f"{type(result).__name__}"
        )
    assert isinstance(issues, list)
    return [str(value) for value in issues]


def _semantic_contract(contract: Any) -> dict[str, Any]:
    return {
        "phase": contract.phase,
        "work_unit_id": contract.work_unit_id,
        "model_invoked": contract.model_invoked,
        "inputs": tuple(
            identity.split(":", 1)
            for identity in (
                *contract.immutable_inputs,
                *contract.bounded_lookup_inputs,
            )
        ),
        "outputs": tuple(
            sorted(
                (
                    output.root,
                    output.path,
                    output.artifact_class,
                    output.writer,
                    output.write_mode,
                    output.schema_version,
                )
                for output in contract.outputs
            )
        ),
    }


def test_axis_driver_exposes_v2_transaction_and_retires_v1_live_paths() -> None:
    _assert_driver_surface()
    assert not hasattr(DRIVER, "_axis_coverage_has_no_gaps"), (
        "the list-returning legacy predicate can convert provider failure into "
        "a clean model skip"
    )
    validator_source = inspect.getsource(DRIVER._run_phase_validators)
    assert "promote_axis_findings_to_inventory" not in validator_source
    assert "_validate_axis_coverage" not in validator_source
    assert "axis_coverage_promotion_receipt.md" not in validator_source


def test_exact_zero_planning_commits_worklist_and_evidence_sidecar(
    tmp_path: Path,
) -> None:
    project, scratchpad = _population_project(tmp_path)
    _write_graph(
        scratchpad,
        {
            "Unit.quiet(uint256)": {
                "bare": "quiet",
                "loc": "contracts/Unit.sol:L2",
                "callers": [],
            }
        },
    )
    phase = _axis_phase()
    config = _config(project)

    worklist, issues = _prepare(phase, config, scratchpad)

    assert issues == []
    assert worklist["schema_version"] == AXIS.WORKLIST_V2_SCHEMA
    assert worklist["denominator_status"] == "EXACT"
    assert worklist["count"] == 0
    assert worklist["clean_empty"] is True
    assert worklist["requires_execution"] is False
    evidence = json.loads(
        (scratchpad / "axis_execution_evidence_authority.json").read_text(
            encoding="utf-8",
            errors="strict",
        )
    )
    assert evidence["schema_version"] == AXIS.EXECUTION_EVIDENCE_AUTHORITY_SCHEMA
    assert evidence["state"] == "EXACT"
    assert evidence["boundary"] == "PRE_AXIS"
    assert evidence["receipt_count"] == 0
    assert evidence["exact_zero"] is True
    assert DRIVER._axis_coverage_has_no_obligations(scratchpad) is True
    ledger = read_artifact_ledger(scratchpad)
    key = "sc/thorough/evm/claude/axis_disposition/planning"
    assert ledger["work_units"][key]["execution_state"] == "OUTPUT_COMMITTED"


def test_provider_failure_is_unknown_debt_never_a_clean_empty_skip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, scratchpad = _population_project(tmp_path)

    def explode(*_args: object, **_kwargs: object) -> dict[str, Any]:
        raise RuntimeError("fixture provider failure")

    monkeypatch.setattr(ENUMERATION, "compute_axis_population", explode)
    if hasattr(DRIVER, "compute_axis_population"):
        monkeypatch.setattr(DRIVER, "compute_axis_population", explode)
    phase = _axis_phase()
    worklist, issues = _prepare(phase, _config(project), scratchpad)

    assert worklist["denominator_status"] == "UNKNOWN"
    assert worklist["clean_empty"] is False
    assert worklist["requires_execution"] is True
    assert issues
    assert any("provider" in issue.casefold() for issue in issues)
    assert DRIVER._axis_coverage_has_no_obligations(scratchpad) is False


@pytest.mark.parametrize("backend", ("claude", "codex"))
def test_axis_model_contract_binds_exact_worklist_evidence_and_source(
    tmp_path: Path,
    backend: str,
) -> None:
    project, scratchpad, config, worklist, _evidence = _one_item_authority(
        tmp_path,
        backend=backend,
    )
    phase = _axis_phase()

    contract, launch = DRIVER._typed_model_phase_contract_and_launch(
        phase, scratchpad, config
    )

    assert contract is not None and launch is not None
    assert contract.model_invoked is True
    inputs = {
        tuple(identity.split(":", 1))
        for identity in (
            *contract.immutable_inputs,
            *contract.bounded_lookup_inputs,
        )
    }
    assert ("scratchpad", "axis_disposition_worklist.json") in inputs
    assert ("scratchpad", "axis_execution_evidence_authority.json") in inputs
    assert ("project", worklist["items"][0]["source_relpath"]) in inputs
    outputs = {output.path: output.writer for output in contract.outputs}
    assert outputs == {
        "axis_coverage_findings.md": "MODEL",
        "axis_coverage_dispositions.json": "MODEL",
    }
    assert launch.backend == backend
    if backend == "claude":
        assert "axis_coverage" in DRIVER._CLAUDE_EXACT_CONSUMER_PHASES


def test_axis_model_contract_semantics_match_for_claude_and_codex(
    tmp_path: Path,
) -> None:
    contracts: dict[str, Any] = {}
    for backend in ("claude", "codex"):
        _project, scratchpad, config, _worklist, _evidence = (
            _one_item_authority(tmp_path, backend=backend)
        )
        contract, launch = DRIVER._typed_model_phase_contract_and_launch(
            _axis_phase(), scratchpad, config
        )
        assert contract is not None and launch is not None
        contracts[backend] = contract
    assert _semantic_contract(contracts["claude"]) == _semantic_contract(
        contracts["codex"]
    )


def test_axis_finalizer_has_one_nonlooping_repair_and_transaction_order() -> None:
    _assert_driver_surface()
    function = DRIVER._finalize_axis_coverage_boundary
    tree = ast.parse(inspect.getsource(function))
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
    ]
    named = [(node.lineno, _call_name(node)) for node in calls]

    def first(*names: str) -> int:
        matches = [line for line, name in named if name in set(names)]
        assert matches, f"axis finalizer is missing one of {names!r}"
        return min(matches)

    initial = first(
        "_reconcile_axis_dispositions",
        "reconcile_axis_dispositions_initial",
    )
    repair = first("_run_axis_disposition_repair")
    final = first("reconcile_axis_dispositions_final")
    promotion_lines = [
        line
        for line, name in named
        if name in {
            "_promote_axis_disposition_actions",
            "build_axis_promotion_authority",
        }
    ]
    assert promotion_lines
    fresh_promotions = [line for line in promotion_lines if line > final]
    assert fresh_promotions, (
        "fresh axis execution must promote only after final reconciliation"
    )
    assert initial < repair < final < min(fresh_promotions)
    recovery_promotions = [line for line in promotion_lines if line < initial]
    assert recovery_promotions, (
        "a previously committed immutable promotion plan must have a "
        "plan-first recovery arm"
    )

    repair_calls = _calls(tree, "_run_axis_disposition_repair")
    assert len(repair_calls) == 1, "repair must be attempted at most once"
    parent: dict[int, ast.AST] = {
        id(child): node
        for node in ast.walk(tree)
        for child in ast.iter_child_nodes(node)
    }
    ancestor = parent.get(id(repair_calls[0]))
    while ancestor is not None:
        assert not isinstance(ancestor, (ast.For, ast.AsyncFor, ast.While)), (
            "axis repair must not be enclosed by an unbounded loop"
        )
        ancestor = parent.get(id(ancestor))

    repair_source = inspect.getsource(DRIVER._run_axis_disposition_repair)
    assert "build_axis_repair_execution_receipt" in repair_source
    for state in ("NOT_REQUIRED", "EXECUTED", "FAILED", "OVERFLOW"):
        assert state in repair_source
    assert "axis_repair_execution_receipt.json" in (
        repair_source + inspect.getsource(function)
    )


def test_real_main_commits_model_before_axis_finalization_and_parent_after() -> None:
    _assert_driver_surface()
    tree = ast.parse(inspect.getsource(DRIVER.main))
    main = tree.body[0]
    assert isinstance(main, (ast.FunctionDef, ast.AsyncFunctionDef))
    axis_blocks = [
        node
        for node in ast.walk(main)
        if isinstance(node, ast.If)
        and _phase_name_test(node.test, "axis_coverage")
        and _calls(node, "_finalize_axis_coverage_boundary")
    ]
    assert len(axis_blocks) == 2, (
        "normal completion and artifact recovery must both finalize axis bytes"
    )
    for block in axis_blocks:
        enclosing = next(
            statements for statements in _statement_lists(main)
            if block in statements
        )
        block_index = enclosing.index(block)
        before = enclosing[:block_index]
        after = enclosing[block_index + 1 :]
        in_block_record = _calls(
            block, "_record_typed_model_phase_artifacts"
        )
        preceding_record = any(
            _calls(statement, "_record_typed_model_phase_artifacts")
            for statement in before
        )
        assert in_block_record or preceding_record, (
            "accepted axis MODEL bytes must commit before deterministic "
            "finalization"
        )
        finalize_line = _calls(
            block, "_finalize_axis_coverage_boundary"
        )[0].lineno
        if in_block_record:
            assert max(call.lineno for call in in_block_record) < finalize_line

        in_block_harvest = _calls(
            block, "_harvest_candidate_negative_phase"
        )
        following_harvest = any(
            _calls(statement, "_harvest_candidate_negative_phase")
            for statement in after
        )
        assert in_block_harvest or following_harvest, (
            "typed axis CLEAR proposals must be harvested after final "
            "reconciliation"
        )
        if in_block_harvest:
            assert min(call.lineno for call in in_block_harvest) > finalize_line
        assert any(
            _calls(statement, "_commit_phase_from_disk_debt")
            for statement in after
        ), "the parent phase must commit only after axis finalization"


def test_axis_typed_clear_adapter_uses_final_json_authority() -> None:
    _assert_driver_surface()
    assert "axis_coverage" in DRIVER._CANDIDATE_NEGATIVE_BASE_PHASES
    relevant: list[str] = []
    for name, value in vars(DRIVER).items():
        if (
            callable(value)
            and "axis" in name.casefold()
            and (
                "negative" in name.casefold()
                or "clear" in name.casefold()
                or "harvest" in name.casefold()
            )
        ):
            try:
                relevant.append(inspect.getsource(value))
            except (OSError, TypeError):
                continue
    relevant.append(inspect.getsource(DRIVER._harvest_candidate_negative_phase))
    source = "\n".join(relevant)
    assert (
        "axis_disposition_receipt.json" in source
        or "AXIS_APPLICATION_RECEIPT_NAME" in source
        or "APPLICATION_RECEIPT_V2_SCHEMA" in source
    )
    assert "work_item_id" in source
    assert "CLEAR" in source
    assert "application_record_complete" in source
    assert "axis_coverage_findings.md" not in (
        inspect.getsource(DRIVER._candidate_negative_phase_artifacts)
        if "axis_coverage" in inspect.getsource(
            DRIVER._candidate_negative_phase_artifacts
        )
        else ""
    ), "generic Markdown harvesting must not be axis CLEAR authority"


def test_axis_resume_dispatch_replays_v2_chain_not_soft_markdown_gate() -> None:
    _assert_driver_surface()
    source = inspect.getsource(DRIVER._resume_semantic_issues)
    assert "_axis_disposition_resume_issues" in source
    axis_branch = [
        node
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.If)
        and _phase_name_test(node.test, "axis_coverage")
    ]
    assert axis_branch
    branch_source = ast.unparse(axis_branch[0])
    assert "_validate_axis_coverage" not in branch_source
    resume_source = inspect.getsource(DRIVER._axis_disposition_resume_issues)
    for required in (
        "axis_disposition_worklist.json",
        "axis_execution_evidence_authority.json",
        "axis_repair_execution_receipt.json",
        "axis_disposition_receipt.json",
        "axis_coverage_promotion_receipt.json",
    ):
        assert required in resume_source
    assert (
        "validate_axis_disposition_authority_v2" in resume_source
        or "validate_axis_disposition_authority" in resume_source
    )
    assert "validate_axis_promotion_authority" in resume_source


def test_exact_zero_resume_is_idempotent_and_tamper_visible(
    tmp_path: Path,
) -> None:
    project, scratchpad = _population_project(tmp_path)
    _write_graph(
        scratchpad,
        {
            "Unit.quiet(uint256)": {
                "bare": "quiet",
                "loc": "contracts/Unit.sol:L2",
                "callers": [],
            }
        },
    )
    phase = _axis_phase()
    config = _config(project)
    worklist, issues = _prepare(phase, config, scratchpad)
    assert issues == [] and worklist["clean_empty"] is True
    before = {
        name: (scratchpad / name).read_bytes() for name in _PLANNING_OUTPUTS
    }

    resume = DRIVER._axis_disposition_resume_issues(
        scratchpad=scratchpad,
        project_root=project,
        pipeline="sc",
        mode="thorough",
        language="evm",
        backend="claude",
        run_id=RUN_ID,
    )
    assert resume == []
    assert all(
        (scratchpad / name).read_bytes() == raw
        for name, raw in before.items()
    )

    evidence = scratchpad / "axis_execution_evidence_authority.json"
    evidence.write_bytes(before[evidence.name] + b"\n")
    tamper = DRIVER._axis_disposition_resume_issues(
        scratchpad=scratchpad,
        project_root=project,
        pipeline="sc",
        mode="thorough",
        language="evm",
        backend="claude",
        run_id=RUN_ID,
    )
    assert tamper
    assert any(
        token in " ".join(tamper).casefold()
        for token in ("digest", "evidence", "phaseio", "authority")
    )


def test_clear_path_commits_model_then_finalizes_without_repair_worker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A valid CLEAR still becomes an independently challengeable proposal."""

    project, scratchpad, config, worklist, _evidence = _one_item_authority(
        tmp_path
    )
    phase = _axis_phase()
    _assert_driver_surface()
    # The helper above persisted strict bytes for contract-only fixtures.  This
    # end-to-end boundary instead exercises the real arm-before-write planning
    # transaction.
    for name in _PLANNING_OUTPUTS:
        (scratchpad / name).unlink()
    worklist, planning_issues = _prepare(phase, config, scratchpad)
    assert planning_issues == []
    assert worklist["count"] > 0

    assert DRIVER._bind_typed_model_phase_inputs(
        phase, scratchpad, config
    ) == []
    prompt_snapshot = scratchpad / "_prompt_axis_coverage.attempt1.md"
    prompt_snapshot.write_text("bounded axis fixture prompt\n", encoding="utf-8")
    boundary = DRIVER._prepare_claude_phase_tool_boundary(
        phase=phase,
        scratchpad=scratchpad,
        config=config,
        attempt=1,
        prompt_snapshot=prompt_snapshot,
    )
    assert boundary is not None
    policy_path = Path(str(boundary["policy_path"]))
    for index, name in enumerate(_BASE_OUTPUTS, 1):
        event = {
            "session_id": "axis-fixture",
            "tool_use_id": f"write-{index}",
            "cwd": str(project),
            "tool_name": "Write",
            "tool_input": {
                "file_path": str(scratchpad / name),
                "content": "fixture output",
            },
        }
        code, decision = DRIVER.claude_phase_tool_policy.run_hook(
            policy_path,
            json.dumps(event).encode("utf-8"),
        )
        assert code == 0
        assert (
            decision["hookSpecificOutput"]["permissionDecision"] == "allow"
        )
    item = worklist["items"][0]
    (scratchpad / "axis_coverage_findings.md").write_text(
        "# Axis Coverage\n\n"
        f"Assessed `{item['work_item_id']}` against its exact source locus.\n",
        encoding="utf-8",
    )
    (scratchpad / "axis_coverage_dispositions.json").write_bytes(
        _sidecar(
            worklist,
            [
                {
                    "work_item_id": row["work_item_id"],
                    "disposition": "CLEAR",
                    "action_id": "",
                    "evidence": [_source_clear(row)],
                    "rationale": "the exact current source guard closes this cell",
                }
                for row in worklist["items"]
            ],
        )
    )
    assert DRIVER._record_typed_model_phase_artifacts(
        phase, scratchpad, config
    ) == []

    repair_launches: list[object] = []
    original_run_phase = DRIVER.run_phase

    def no_repair_model(*args: object, **kwargs: object) -> int:
        repair_launches.append((args, kwargs))
        return original_run_phase(*args, **kwargs)

    monkeypatch.setattr(DRIVER, "run_phase", no_repair_model)
    issues = _finalize(phase, config, scratchpad)

    assert issues == []
    assert repair_launches == []
    for name in (*_INITIAL_OUTPUTS, *_FINAL_OUTPUTS):
        assert (scratchpad / name).is_file(), f"missing terminal artifact {name}"
    repair = json.loads(
        (scratchpad / "axis_repair_execution_receipt.json").read_text(
            encoding="utf-8",
            errors="strict",
        )
    )
    assert repair["state"] == "NOT_REQUIRED"
    final = json.loads(
        (scratchpad / "axis_disposition_receipt.json").read_text(
            encoding="utf-8",
            errors="strict",
        )
    )
    assert final["application_record_complete"] is True
    assert final["dispositions"][0]["work_item_id"] == item["work_item_id"]
    promotion = json.loads(
        (scratchpad / "axis_coverage_promotion_receipt.json").read_text(
            encoding="utf-8",
            errors="strict",
        )
    )
    assert promotion["action_count"] == 0
    assert promotion["status"] == "COMPLETE"
    assert DRIVER._harvest_candidate_negative_phase(
        phase, config, scratchpad
    ) == []
    negative = json.loads(
        (scratchpad / "candidate_negative_proposals_axis_coverage.json").read_text(
            encoding="utf-8",
            errors="strict",
        )
    )
    serialized = json.dumps(negative, sort_keys=True)
    assert item["work_item_id"] in serialized
    assert "CLEAR" in serialized
    DRIVER._write_canonical_finding_identity_map(
        scratchpad,
        phase_name=phase.name,
        pipeline="sc",
        mode="thorough",
    )
    assert (scratchpad / "_canonical_finding_ids.json").is_file()


@pytest.mark.parametrize(
    ("pipeline", "mode"),
    (
        ("sc", "light"),
        ("sc", "core"),
        ("l1", "light"),
        ("l1", "core"),
        ("l1", "thorough"),
    ),
)
def test_unscheduled_modes_create_no_axis_authority(
    tmp_path: Path,
    pipeline: str,
    mode: str,
) -> None:
    project, scratchpad = _population_project(tmp_path)
    phase = _axis_phase()
    config = _config(project, pipeline=pipeline, mode=mode)
    try:
        result = DRIVER._prepare_axis_disposition_worklist(
            phase=phase,
            config=config,
            scratchpad=scratchpad,
        )
    except (AttributeError, ValueError, RuntimeError):
        result = None
    if result is not None:
        assert isinstance(result, tuple)
        assert result[1], "an unscheduled direct call must return explicit debt"
    assert not any(
        (scratchpad / name).exists()
        for name in (*_PLANNING_OUTPUTS, *_BASE_OUTPUTS, *_FINAL_OUTPUTS)
    )
    axis = next(phase for phase in SC_PHASES if phase.name == "axis_coverage")
    assert axis.modes == {"thorough"}
    assert "axis_coverage" not in {phase.name for phase in L1_PHASES}
