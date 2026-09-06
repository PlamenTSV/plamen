"""Fixture-first inventory PhaseIO ordering and canonical aggregation."""
from __future__ import annotations

import ast
import copy
import concurrent.futures
from datetime import datetime, timedelta
import hashlib
import inspect
import json
import multiprocessing
from pathlib import Path
import sys
import textwrap
import uuid

import pytest


SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(ROOT))

import artifact_ledger as AL  # noqa: E402
from artifact_ledger import (  # noqa: E402
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
)
from phase_io_contracts import (  # noqa: E402
    DriverMergeEvent,
    LaunchSpec,
    resolve_phase_io_contract,
)
import inventory_id_ledger_merge as IM  # noqa: E402
from inventory_reemit_authority import INTENT_SCHEMA  # noqa: E402
import plamen_driver as D  # noqa: E402
import plamen_validators as V  # noqa: E402
from plamen_parsers import _title_hash  # noqa: E402
from plamen_types import SC_PHASES  # noqa: E402


def _phase(name: str):
    return next(row for row in SC_PHASES if row.name == name)


def _config(project: Path, scratch: Path, *, backend: str = "claude") -> dict:
    return {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": backend,
        "scratchpad": str(scratch),
        "project_root": str(project),
        "_run_id": str(uuid.uuid4()),
    }


def _successor_authority_pair(config: dict, unit: dict):
    manifest = unit["contract_manifest"]
    identities = [
        *manifest["immutable_inputs"],
        *manifest["bounded_lookup_inputs"],
    ]
    contract = resolve_phase_io_contract(
        pipeline=config["pipeline"],
        mode=config["mode"],
        ecosystem=config["language"],
        backend=config["cli_backend"],
        phase="inventory",
        work_unit_id="additive_reemit",
        exact_inputs=tuple(
            identity.split(":", 1)[1] for identity in identities
        ),
    )
    launch_manifest = unit["launch_manifest"]
    launch = LaunchSpec(
        work_unit_key=launch_manifest["work_unit_key"],
        pipeline=launch_manifest["pipeline"],
        mode=launch_manifest["mode"],
        ecosystem=launch_manifest["ecosystem"],
        backend=launch_manifest["backend"],
        model=launch_manifest["model"],
        timeout_s=launch_manifest["timeout_s"],
        exec_mode=launch_manifest["exec_mode"],
        tool_policy=tuple(launch_manifest["tool_policy"]),
        launch_version=launch_manifest["launch_version"],
    )
    assert contract.to_dict() == manifest
    assert launch.to_dict() == launch_manifest
    return contract, launch


def _reseal_recovery_history(unit: dict) -> None:
    prior_head = ""
    for ordinal, row in enumerate(
        unit["quarantine_recovery_history"], start=1
    ):
        row["ordinal"] = ordinal
        row["prior_recovery_authority_digest"] = prior_head
        unsigned = {
            key: value for key, value in row.items()
            if key != "authority_digest"
        }
        row["authority_digest"] = AL._canonical_json_digest(unsigned)
        prior_head = row["authority_digest"]
    unit["quarantine_recovery_history_count"] = len(
        unit["quarantine_recovery_history"]
    )
    unit["quarantine_recovery_history_head_digest"] = prior_head


def _resume_id_ledger_in_child(
    scratch: str,
    config: dict,
    timeout_s: int,
    result_queue,
) -> None:
    result_queue.put(
        D._run_inventory_id_ledger_merge_transaction(
            scratchpad=Path(scratch),
            config=config,
            timeout_s=timeout_s,
        )
    )


def _finding(fid: str, title: str, source_ids: tuple[str, ...]) -> str:
    return (
        f"### Finding [{fid}]: {title}\n"
        "**Severity**: Medium\n"
        "**Location**: src/Fixture.sol:L10\n"
        "**Preferred Tag**: [CODE-TRACE]\n"
        f"**Source IDs**: {', '.join(source_ids)}\n"
        "**Verdict**: NEEDS_VERIFICATION\n"
        f"**Root Cause**: mechanism for {title}\n"
        f"**Description**: description for {title}\n"
        f"**Impact**: material effect for {title}\n\n"
    )


def _source(root: Path, name: str, fid: str, title: str) -> None:
    (root / name).write_text(
        "# Findings\n\n"
        + _finding(fid, title, ())
        .replace("**Source IDs**: \n", ""),
        encoding="utf-8",
    )


def _manifest(root: Path, phase_name: str, sources: tuple[str, ...]) -> None:
    lines = [
        f"# {phase_name} manifest",
        "",
        f"Assigned files: {len(sources)}",
        "",
        "| File |",
        "|---|",
        *(f"| {name} |" for name in sources),
        "",
    ]
    (root / f"{phase_name}.manifest.md").write_text(
        "\n".join(lines), encoding="utf-8"
    )


def _chunk_text(rows: tuple[tuple[str, str, tuple[str, ...]], ...]) -> str:
    if not rows:
        return (
            "# Inventory Chunk: N/A\n\n"
            "## Source Summary\n\n0 assigned sources.\n\n"
            "## Master Table\n\n_No findings._\n\n"
            "## Per-Finding Detail\n\n_No findings._\n"
        )
    return (
        "# Inventory Chunk\n\n"
        "## Source Summary\n\nAll assigned sources reviewed.\n\n"
        "## Master Table\n\n"
        "| ID | Title |\n|---|---|\n"
        + "".join(f"| {fid} | {title} |\n" for fid, title, _ in rows)
        + "\n## Per-Finding Detail\n\n"
        + "".join(_finding(fid, title, sources) for fid, title, sources in rows)
    )


def _seed_active_chunk(
    project: Path,
    scratch: Path,
    config: dict,
    phase_name: str,
    *,
    rows: tuple[tuple[str, str, tuple[str, ...]], ...],
    sources: tuple[str, ...],
    attempt: int = 1,
) -> str:
    _manifest(scratch, phase_name, sources)
    exact_inputs = (f"{phase_name}.manifest.md", *sources)
    output = f"findings_{phase_name}.md"
    contract = resolve_phase_io_contract(
        pipeline=config["pipeline"],
        mode=config["mode"],
        ecosystem=config["language"],
        backend=config["cli_backend"],
        phase=phase_name,
        work_unit_id=f"model.attempt{attempt:04d}",
        exact_inputs=exact_inputs,
        exact_outputs=(output,),
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="fixture-model",
        timeout_s=60,
        exec_mode="headless",
        tool_policy=("filesystem",),
    )
    record_work_unit_inputs(
        scratch, project, contract, launch, run_id=config["_run_id"]
    )
    (scratch / output).write_text(_chunk_text(rows), encoding="utf-8")
    record_work_unit_artifacts(
        scratch,
        project,
        contract,
        launch,
        run_id=config["_run_id"],
        actor="MODEL",
    )
    unit = read_artifact_ledger(scratch)["work_units"][contract.key]
    assert unit["semantic_status"] == "ACTIVE"
    assert unit["execution_state"] == "OUTPUT_COMMITTED"
    return contract.key


def _fixture(tmp_path: Path, *, backend: str = "claude") -> tuple[Path, Path, dict]:
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    return project, scratch, _config(project, scratch, backend=backend)


def test_inventory_chunk_validator_is_pure_and_writes_no_sidecars(
    tmp_path: Path,
) -> None:
    _project, scratch, _cfg = _fixture(tmp_path)
    _source(scratch, "analysis_a.md", "A-01", "candidate a")
    _manifest(scratch, "inventory_chunk_a", ("analysis_a.md",))
    chunk = scratch / "findings_inventory_chunk_a.md"
    chunk.write_text(
        _chunk_text((("CC-01", "candidate a", ("A-01",)),)),
        encoding="utf-8",
    )
    before = chunk.read_bytes()

    V._validate_inventory_chunk_structure(scratch, "inventory_chunk_a")

    assert chunk.read_bytes() == before
    assert not (scratch / "inventory_chunk_a.reconciliation.json").exists()
    assert not (scratch / "inventory_chunk_a.human_review.md").exists()
    assert not (scratch / "findings_inventory.md").exists()


def test_chunk_reconciliation_requires_active_model_and_no_final_inventory(
    tmp_path: Path,
) -> None:
    project, scratch, config = _fixture(tmp_path)
    _source(scratch, "analysis_a.md", "A-01", "candidate a")
    model_key = _seed_active_chunk(
        project,
        scratch,
        config,
        "inventory_chunk_a",
        rows=(("CC-01", "candidate a", ("A-01",)),),
        sources=("analysis_a.md",),
    )

    assert D._record_inventory_reconciliation_phase_io_named(
        scratchpad=scratch,
        config=config,
        phase_name="inventory_chunk_a",
        timeout_s=60,
    ) == []
    assert not (scratch / "findings_inventory.md").exists()
    unit = read_artifact_ledger(scratch)["work_units"][
        "sc/thorough/evm/claude/inventory_chunk_a/exact_reconciliation"
    ]
    binding = unit["input_bindings"][
        "scratchpad:findings_inventory_chunk_a.md"
    ]
    assert binding["producer_work_unit_key"] == model_key
    assert binding["producer_contract_digest"]
    assert binding["sha256"] == hashlib.sha256(
        (scratch / "findings_inventory_chunk_a.md").read_bytes()
    ).hexdigest()


def test_chunk_reconciliation_rejects_additive_reemit_refresh(
    tmp_path: Path,
) -> None:
    project, scratch, config = _fixture(tmp_path)
    _source(scratch, "analysis_a.md", "A-01", "candidate a")
    _seed_active_chunk(
        project,
        scratch,
        config,
        "inventory_chunk_a",
        rows=(("CC-01", "candidate a", ("A-01",)),),
        sources=("analysis_a.md",),
    )

    issues = D._record_inventory_reconciliation_phase_io_named(
        scratchpad=scratch,
        config=config,
        phase_name="inventory_chunk_a",
        timeout_s=60,
        refresh_reemit_owner=True,
    )

    assert any("chunk" in issue.lower() and "reemit" in issue.lower() for issue in issues)
    assert not (scratch / "inventory_reemit_intent.json").exists()
    assert not (scratch / "inventory_reemit_receipt.json").exists()


def test_unowned_chunk_cannot_mint_reconciliation_authority(
    tmp_path: Path,
) -> None:
    _project, scratch, config = _fixture(tmp_path)
    _source(scratch, "analysis_a.md", "A-01", "candidate a")
    _manifest(scratch, "inventory_chunk_a", ("analysis_a.md",))
    (scratch / "findings_inventory_chunk_a.md").write_text(
        _chunk_text((("CC-01", "candidate a", ("A-01",)),)),
        encoding="utf-8",
    )

    issues = D._record_inventory_reconciliation_phase_io_named(
        scratchpad=scratch,
        config=config,
        phase_name="inventory_chunk_a",
        timeout_s=60,
    )

    assert issues
    assert any(
        "producer" in issue.lower()
        or "unowned" in issue.lower()
        or "authority" in issue.lower()
        for issue in issues
    )


def test_chunk_model_contract_is_backend_neutral_and_attempt_scoped() -> None:
    contracts = {}
    for backend in ("claude", "codex"):
        contracts[backend] = resolve_phase_io_contract(
            pipeline="sc",
            mode="thorough",
            ecosystem="evm",
            backend=backend,
            phase="inventory_chunk_a",
            work_unit_id="model.attempt0002",
            exact_inputs=(
                "inventory_chunk_a.manifest.md",
                "analysis_a.md",
            ),
            exact_outputs=("findings_inventory_chunk_a.md",),
        )
    assert contracts["claude"].work_unit_id == "model.attempt0002"
    assert contracts["codex"].work_unit_id == "model.attempt0002"
    assert contracts["claude"].immutable_inputs == contracts["codex"].immutable_inputs
    assert tuple(
        (row.path, row.writer, row.minimum_gate)
        for row in contracts["claude"].outputs
    ) == tuple(
        (row.path, row.writer, row.minimum_gate)
        for row in contracts["codex"].outputs
    )
    assert contracts["claude"].key != contracts["codex"].key


def _seed_for_aggregate(
    project: Path,
    scratch: Path,
    config: dict,
    kind: str,
) -> None:
    if kind == "multi_shard":
        for letter in ("a", "b"):
            source = f"analysis_{letter}.md"
            source_id = f"{letter.upper()}-01"
            _source(scratch, source, source_id, f"candidate {letter}")
            _seed_active_chunk(
                project,
                scratch,
                config,
                f"inventory_chunk_{letter}",
                rows=((f"CC-{letter.upper()}1", f"candidate {letter}", (source_id,)),),
                sources=(source,),
            )
    elif kind == "single_shard":
        _source(scratch, "analysis_a.md", "A-01", "candidate a")
        _seed_active_chunk(
            project,
            scratch,
            config,
            "inventory_chunk_a",
            rows=(("CC-A1", "candidate a", ("A-01",)),),
            sources=("analysis_a.md",),
        )
    elif kind == "typed_empty":
        _seed_active_chunk(
            project,
            scratch,
            config,
            "inventory_chunk_a",
            rows=(),
            sources=(),
        )
    elif kind == "floor_reconstruction":
        _source(scratch, "analysis_a.md", "A-01", "candidate a")
        _seed_active_chunk(
            project,
            scratch,
            config,
            "inventory_chunk_a",
            rows=(),
            sources=("analysis_a.md",),
        )
    else:
        raise AssertionError(kind)


@pytest.mark.parametrize(
    "kind,expected_count",
    [
        ("multi_shard", 2),
        ("single_shard", 1),
        ("typed_empty", 0),
        ("floor_reconstruction", 1),
    ],
)
def test_canonical_aggregate_routes_all_derivation_kinds(
    tmp_path: Path,
    kind: str,
    expected_count: int,
) -> None:
    project, scratch, config = _fixture(tmp_path)
    _seed_for_aggregate(project, scratch, config, kind)

    result, issues = D._run_inventory_canonical_aggregate_transaction(
        scratchpad=scratch,
        config=config,
        phase=_phase("inventory"),
        derivation_kind=kind,
    )

    assert issues == []
    assert result["derivation_kind"] == kind
    assert result["finding_count"] == expected_count
    assert result["consumed_chunk_count"] == (
        2 if kind == "multi_shard" else 1
    )
    for name in (
        "findings_inventory.md",
        "finding_records.json",
        "inventory_merge_receipt.md",
        "_id_ledger.json",
        "inventory_aggregate_derivation.json",
    ):
        assert (scratch / name).is_file(), name
    unit = read_artifact_ledger(scratch)["work_units"][
        "sc/thorough/evm/claude/inventory/canonical_aggregate"
    ]
    assert unit["semantic_status"] == "ACTIVE"
    assert unit["execution_state"] == "OUTPUT_COMMITTED"


def test_late_chunk_change_invalidates_canonical_aggregate(tmp_path: Path) -> None:
    project, scratch, config = _fixture(tmp_path)
    _seed_for_aggregate(project, scratch, config, "single_shard")
    _result, issues = D._run_inventory_canonical_aggregate_transaction(
        scratchpad=scratch,
        config=config,
        phase=_phase("inventory"),
        derivation_kind="single_shard",
    )
    assert issues == []
    with (scratch / "findings_inventory_chunk_a.md").open("ab") as handle:
        handle.write(b"\nlate chunk drift\n")

    issues = D._validate_inventory_canonical_aggregate_phase_io(
        scratchpad=scratch,
        config=config,
        phase=_phase("inventory"),
    )

    assert issues
    assert any("drift" in issue.lower() or "differ" in issue.lower() for issue in issues)


@pytest.mark.parametrize(
    "failpoint",
    [
        "after_inventory",
        "after_finding_records.json",
        "after_inventory_merge_receipt.md",
        "after_inventory_id_allocation_delta.json",
    ],
)
def test_canonical_aggregate_crash_resume_is_byte_identical(
    tmp_path: Path,
    failpoint: str,
) -> None:
    project, scratch, config = _fixture(tmp_path)
    _seed_for_aggregate(project, scratch, config, "single_shard")
    config["_inventory_aggregate_failpoint"] = failpoint

    _result, issues = D._run_inventory_canonical_aggregate_transaction(
        scratchpad=scratch,
        config=config,
        phase=_phase("inventory"),
        derivation_kind="single_shard",
    )
    assert issues
    plan = json.loads(
        (scratch / "inventory_aggregate_derivation.json").read_text(
            encoding="utf-8"
        )
    )
    planned = dict(plan["output_sha256"])

    config.pop("_inventory_aggregate_failpoint")
    result, issues = D._run_inventory_canonical_aggregate_transaction(
        scratchpad=scratch,
        config=config,
        phase=_phase("inventory"),
        derivation_kind="single_shard",
    )

    assert issues == []
    assert result["output_sha256"] == planned
    for name, digest in planned.items():
        assert hashlib.sha256((scratch / name).read_bytes()).hexdigest() == digest


def test_additive_reemit_requires_active_canonical_aggregate(
    tmp_path: Path,
) -> None:
    project, scratch, config = _fixture(tmp_path)
    _source(scratch, "analysis_a.md", "A-01", "candidate a")
    _manifest(scratch, "inventory_chunk_a", ("analysis_a.md",))
    (scratch / "findings_inventory_chunk_a.md").write_text(
        _chunk_text((("CC-A1", "candidate a", ("A-01",)),)),
        encoding="utf-8",
    )
    (scratch / "findings_inventory.md").write_text(
        "# Finding Inventory\n\n## Findings\n\n"
        + _finding("INV-001", "candidate a", ("A-01", "CC-A1")),
        encoding="utf-8",
    )

    issues = D._record_inventory_reemit_phase_io(
        scratchpad=scratch,
        project_root=project,
        config=config,
        run_id=config["_run_id"],
    )

    assert issues
    assert any(
        "canonical aggregate" in issue.lower()
        or "producer authority" in issue.lower()
        for issue in issues
    )


@pytest.mark.parametrize(
    "dimension,value",
    [("cli_backend", "codex"), ("mode", "core")],
)
def test_canonical_aggregate_rejects_backend_or_mode_switch(
    tmp_path: Path,
    dimension: str,
    value: str,
) -> None:
    project, scratch, config = _fixture(tmp_path)
    _seed_for_aggregate(project, scratch, config, "single_shard")
    switched = dict(config)
    switched[dimension] = value

    _result, issues = D._run_inventory_canonical_aggregate_transaction(
        scratchpad=scratch,
        config=switched,
        phase=_phase("inventory"),
        derivation_kind="single_shard",
    )

    assert issues
    assert any(
        "producer" in issue.lower()
        or "authority" in issue.lower()
        for issue in issues
    )
    assert not any(
        key.startswith(
            f"sc/{switched['mode']}/evm/{switched['cli_backend']}/inventory/"
        )
        and key.endswith("/canonical_aggregate")
        and row.get("semantic_status") == "ACTIVE"
        for key, row in read_artifact_ledger(scratch)["work_units"].items()
    )


@pytest.mark.parametrize(
    "drift_artifact",
    ["analysis_a.md", "findings_inventory_chunk_a.md"],
)
def test_canonical_aggregate_rejects_late_chunk_input_or_output_drift(
    tmp_path: Path,
    drift_artifact: str,
) -> None:
    project, scratch, config = _fixture(tmp_path)
    _seed_for_aggregate(project, scratch, config, "single_shard")
    with (scratch / drift_artifact).open("ab") as handle:
        handle.write(b"\nlate producer drift\n")

    _result, issues = D._run_inventory_canonical_aggregate_transaction(
        scratchpad=scratch,
        config=config,
        phase=_phase("inventory"),
        derivation_kind="single_shard",
    )

    assert issues
    assert any(
        "changed" in issue.lower()
        or "producer" in issue.lower()
        or "authority" in issue.lower()
        for issue in issues
    )
    assert not (scratch / "findings_inventory.md").exists()


def test_canonical_aggregate_does_not_overwrite_unowned_final_inventory(
    tmp_path: Path,
) -> None:
    project, scratch, config = _fixture(tmp_path)
    _seed_for_aggregate(project, scratch, config, "single_shard")
    inventory = scratch / "findings_inventory.md"
    inventory.write_text("unowned final inventory\n", encoding="utf-8")
    before = inventory.read_bytes()

    _result, issues = D._run_inventory_canonical_aggregate_transaction(
        scratchpad=scratch,
        config=config,
        phase=_phase("inventory"),
        derivation_kind="single_shard",
    )

    assert issues
    assert inventory.read_bytes() == before
    unit = read_artifact_ledger(scratch)["work_units"][
        "sc/thorough/evm/claude/inventory/canonical_aggregate"
    ]
    assert unit["semantic_status"] == "INPUT_DEBT"
    assert unit["execution_state"] == "INPUTS_BOUND_PREEXECUTION"


def _seed_canonical_with_one_omitted_candidate(
    project: Path,
    scratch: Path,
    config: dict,
) -> None:
    (scratch / "analysis_a.md").write_text(
        "# Findings\n\n"
        + _finding("A-01", "candidate a", ()).replace(
            "**Source IDs**: \n", ""
        )
        + _finding("A-02", "candidate omitted", ()).replace(
            "**Source IDs**: \n", ""
        ),
        encoding="utf-8",
    )
    _seed_active_chunk(
        project,
        scratch,
        config,
        "inventory_chunk_a",
        rows=(("CC-1", "candidate a", ("A-01",)),),
        sources=("analysis_a.md",),
    )
    _result, issues = D._run_inventory_canonical_aggregate_transaction(
        scratchpad=scratch,
        config=config,
        phase=_phase("inventory"),
        derivation_kind="single_shard",
    )
    assert issues == []
    prestate = D._reconcile_exact_inventory(scratch, persist=False)
    assert prestate["summary"] == {
        "AUTHORIZED_MERGE": 0,
        "AUTHORIZED_REFUTATION": 0,
        "HUMAN_REVIEW_DEBT": 1,
        "RETAINED": 1,
        "TOTAL": 2,
    }
    dispositions = {
        row["source_finding_id"]: row["disposition"]
        for row in prestate["candidates"]
    }
    assert dispositions == {
        "A-01": "RETAINED",
        "A-02": "HUMAN_REVIEW_DEBT",
    }


def _assert_mixed_invalid_source_reference_remains_debt(root: Path) -> None:
    project, scratch, config = _fixture(root)
    (scratch / "analysis_a.md").write_text(
        "# Findings\n\n"
        + _finding("A-01", "candidate a", ()).replace(
            "**Source IDs**: \n", ""
        )
        + _finding("A-02", "candidate omitted", ()).replace(
            "**Source IDs**: \n", ""
        ),
        encoding="utf-8",
    )
    _seed_active_chunk(
        project,
        scratch,
        config,
        "inventory_chunk_a",
        rows=(("CC-A1", "candidate a", ("A-01",)),),
        sources=("analysis_a.md",),
    )
    _result, issues = D._run_inventory_canonical_aggregate_transaction(
        scratchpad=scratch,
        config=config,
        phase=_phase("inventory"),
        derivation_kind="single_shard",
    )
    assert issues == []
    poisoned = D._reconcile_exact_inventory(scratch, persist=False)
    assert poisoned["summary"]["RETAINED"] == 0
    assert poisoned["summary"]["HUMAN_REVIEW_DEBT"] == 2
    assert {
        row["source_finding_id"]: row["disposition"]
        for row in poisoned["candidates"]
    } == {
        "A-01": "HUMAN_REVIEW_DEBT",
        "A-02": "HUMAN_REVIEW_DEBT",
    }


def test_additive_reemit_reserves_sparse_retained_id_ledger_allocations(
    tmp_path: Path,
) -> None:
    """A durable allocation may outlive its old inventory projection.

    Additive repair must reserve that identity rather than silently assigning
    it to a different semantic finding and retaining the old allocation row.
    """

    project, scratch, config = _fixture(tmp_path)
    _write_legacy_id_ledger(
        scratch,
        [_legacy_allocation("INV-002", "unrelated retained mechanism")],
    )
    (scratch / "analysis_a.md").write_text(
        "# Findings\n\n"
        + _finding("A-01", "candidate a", ()).replace(
            "**Source IDs**: \n", ""
        )
        + _finding("A-02", "candidate omitted two", ()).replace(
            "**Source IDs**: \n", ""
        )
        + _finding("A-03", "candidate omitted three", ()).replace(
            "**Source IDs**: \n", ""
        ),
        encoding="utf-8",
    )
    _seed_active_chunk(
        project,
        scratch,
        config,
        "inventory_chunk_a",
        rows=(("CC-1", "candidate a", ("A-01",)),),
        sources=("analysis_a.md",),
    )
    _result, issues = D._run_inventory_canonical_aggregate_transaction(
        scratchpad=scratch,
        config=config,
        phase=_phase("inventory"),
        derivation_kind="single_shard",
    )
    assert issues == []

    prestate = D._reconcile_exact_inventory(scratch, persist=False)
    assert prestate["summary"] == {
        "AUTHORIZED_MERGE": 0,
        "AUTHORIZED_REFUTATION": 0,
        "HUMAN_REVIEW_DEBT": 2,
        "RETAINED": 1,
        "TOTAL": 3,
    }
    assert {
        row["source_finding_id"]: (
            row["disposition"],
            row["target_inventory_id"],
        )
        for row in prestate["candidates"]
    } == {
        "A-01": ("RETAINED", "INV-001"),
        "A-02": ("HUMAN_REVIEW_DEBT", ""),
        "A-03": ("HUMAN_REVIEW_DEBT", ""),
    }

    issues = D._record_inventory_reemit_phase_io(
        scratchpad=scratch,
        project_root=project,
        config=config,
        run_id=config["_run_id"],
    )

    assert issues == []
    intent = json.loads(
        (scratch / "inventory_reemit_intent.json").read_text(
            encoding="utf-8"
        )
    )
    assert intent["reserved_inventory_ids"] == ["INV-001", "INV-002"]
    assert [
        (row["source_finding_id"], row["target_finding_id"])
        for row in intent["rows"]
    ] == [
        ("A-03", "INV-003"),
        ("A-02", "INV-004"),
    ]
    inventory, records, ledger_ids = _projected_inventory_ids(scratch)
    assert inventory == records == {"INV-001", "INV-003", "INV-004"}
    assert ledger_ids == {"INV-001", "INV-002", "INV-003", "INV-004"}
    allocations = {
        str(row["id"]).upper(): row
        for row in json.loads(
            (scratch / "_id_ledger.json").read_text(encoding="utf-8")
        )["allocations"]
    }
    assert allocations["INV-002"]["title_hash"] == _title_hash(
        "unrelated retained mechanism"
    )
    records_by_id = {
        str(row["inventory_id"]).upper(): row
        for row in json.loads(
            (scratch / "finding_records.json").read_text(encoding="utf-8")
        )["records"]
    }
    for finding_id in ("INV-003", "INV-004"):
        assert allocations[finding_id]["title_hash"] == _title_hash(
            str(records_by_id[finding_id]["title"])
        )
        assert allocations[finding_id]["owner_phase"] == "inventory"
        assert (
            allocations[finding_id]["owning_artifact"]
            == "findings_inventory.md"
        )


def _projected_inventory_ids(scratch: Path) -> tuple[set[str], set[str], set[str]]:
    inventory = {
        match.group(1).upper()
        for match in __import__("re").finditer(
            r"(?im)^###\s+Finding\s+\[(INV-\d+)\]",
            (scratch / "findings_inventory.md").read_text(encoding="utf-8"),
        )
    }
    records_payload = json.loads(
        (scratch / "finding_records.json").read_text(encoding="utf-8")
    )
    records = {
        str(row.get("inventory_id") or "").upper()
        for row in records_payload["records"]
    }
    ledger_payload = json.loads(
        (scratch / "_id_ledger.json").read_text(encoding="utf-8")
    )
    ledger = {
        str(row.get("id") or "").upper()
        for row in ledger_payload["allocations"]
        if str(row.get("id") or "").upper().startswith("INV-")
    }
    return inventory, records, ledger


def test_additive_reemit_advances_inventory_records_and_id_ledger(
    tmp_path: Path,
) -> None:
    _assert_mixed_invalid_source_reference_remains_debt(
        tmp_path / "mixed-invalid"
    )
    project, scratch, config = _fixture(tmp_path)
    _seed_canonical_with_one_omitted_candidate(
        project, scratch, config
    )

    issues = D._record_inventory_reemit_phase_io(
        scratchpad=scratch,
        project_root=project,
        config=config,
        run_id=config["_run_id"],
    )

    assert issues == []
    inventory, records, ledger_ids = _projected_inventory_ids(scratch)
    assert inventory == records == ledger_ids == {"INV-001", "INV-002"}
    ledger = read_artifact_ledger(scratch)
    unit = ledger["work_units"][
        "sc/thorough/evm/claude/inventory/additive_reemit"
    ]
    assert unit["semantic_status"] == "ACTIVE"
    assert unit["execution_state"] == "OUTPUT_COMMITTED"
    assert "quarantine_recovery_history" not in unit
    intent = json.loads(
        (scratch / "inventory_reemit_intent.json").read_text(
            encoding="utf-8"
        )
    )
    intent_record = unit["artifacts"][
        "scratchpad:inventory_reemit_intent.json"
    ]
    intent_contract = next(
        row
        for row in unit["contract_manifest"]["outputs"]
        if row["identity"]
        == "scratchpad:inventory_reemit_intent.json"
    )
    assert intent["schema_version"] == INTENT_SCHEMA
    assert intent_record["schema_version"] == INTENT_SCHEMA
    assert intent_contract["schema_version"] == INTENT_SCHEMA
    for name in (
        "findings_inventory.md",
        "finding_records.json",
        "_id_ledger.json",
    ):
        binding = ledger["artifact_bindings"][f"scratchpad:{name}"]
        assert binding["owner_key"] == unit["work_unit_key"]
        assert binding["status"] == "ACTIVE"

    assert D._record_inventory_reconciliation_phase_io(
        scratchpad=scratch,
        config=config,
        phase=_phase("inventory"),
    ) == []
    final = ledger = read_artifact_ledger(scratch)
    exact = final["work_units"][
        "sc/thorough/evm/claude/inventory/exact_reconciliation"
    ]
    assert exact["semantic_status"] == "ACTIVE"
    assert exact["execution_state"] == "OUTPUT_COMMITTED"


@pytest.mark.parametrize(
    "failpoint,expected_counts",
    [
        ("after_apply", (2, 1, 1)),
        ("after_records", (2, 2, 1)),
        ("after_id_ledger", (2, 2, 2)),
    ],
)
def test_additive_reemit_partial_output_resume_is_exact(
    tmp_path: Path,
    failpoint: str,
    expected_counts: tuple[int, int, int],
) -> None:
    project, scratch, config = _fixture(tmp_path)
    _seed_canonical_with_one_omitted_candidate(
        project, scratch, config
    )
    config["_inventory_reemit_failpoint"] = failpoint

    issues = D._record_inventory_reemit_phase_io(
        scratchpad=scratch,
        project_root=project,
        config=config,
        run_id=config["_run_id"],
    )

    assert issues
    assert tuple(
        len(ids) for ids in _projected_inventory_ids(scratch)
    ) == expected_counts
    unit = read_artifact_ledger(scratch)["work_units"][
        "sc/thorough/evm/claude/inventory/additive_reemit"
    ]
    assert unit["semantic_status"] == "INPUTS_BOUND"
    assert unit["execution_state"] == "INPUTS_BOUND_PREEXECUTION"
    config.pop("_inventory_reemit_failpoint")

    issues = D._record_inventory_reemit_phase_io(
        scratchpad=scratch,
        project_root=project,
        config=config,
        run_id=config["_run_id"],
    )

    assert issues == []
    inventory, records, ledger_ids = _projected_inventory_ids(scratch)
    assert inventory == records == ledger_ids == {"INV-001", "INV-002"}
    unit = read_artifact_ledger(scratch)["work_units"][
        "sc/thorough/evm/claude/inventory/additive_reemit"
    ]
    assert unit["semantic_status"] == "ACTIVE"
    assert unit["execution_state"] == "OUTPUT_COMMITTED"


def test_additive_reemit_durably_publishes_each_output_before_applied(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, scratch, config = _fixture(tmp_path)
    _seed_canonical_with_one_omitted_candidate(
        project, scratch, config
    )
    ordering: list[tuple[str, object]] = []
    real_replace = D._durable_driver_replace
    real_complete = D.complete_driver_successor_step

    def _replace(source: Path, destination: Path) -> None:
        real_replace(source, destination)
        ordering.append(("published", Path(destination).name))

    def _complete(*args, **kwargs):
        result = real_complete(*args, **kwargs)
        ordering.append(("applied", int(kwargs["ordinal"])))
        return result

    monkeypatch.setattr(D, "_durable_driver_replace", _replace)
    monkeypatch.setattr(D, "complete_driver_successor_step", _complete)

    assert D._record_inventory_reemit_phase_io(
        scratchpad=scratch,
        project_root=project,
        config=config,
        run_id=config["_run_id"],
    ) == []

    names = (
        "inventory_reemit_intent.json",
        "findings_inventory.md",
        "inventory_reemit_receipt.json",
        "finding_records.json",
        "_id_ledger.json",
    )
    for ordinal, name in enumerate(names, start=1):
        assert ordering.index(("published", name)) < ordering.index(
            ("applied", ordinal)
        )


def test_applied_progress_with_lost_output_fails_closed_then_recovers(
    tmp_path: Path,
) -> None:
    project, scratch, config = _fixture(tmp_path)
    _seed_canonical_with_one_omitted_candidate(
        project, scratch, config
    )
    config["_inventory_reemit_failpoint"] = "after_output_1"
    assert D._record_inventory_reemit_phase_io(
        scratchpad=scratch,
        project_root=project,
        config=config,
        run_id=config["_run_id"],
    )
    (scratch / "inventory_reemit_intent.json").unlink()
    config.pop("_inventory_reemit_failpoint")

    lost = D._record_inventory_reemit_phase_io(
        scratchpad=scratch,
        project_root=project,
        config=config,
        run_id=config["_run_id"],
    )

    assert lost
    key = "sc/thorough/evm/claude/inventory/additive_reemit"
    assert read_artifact_ledger(scratch)["work_units"][key][
        "semantic_status"
    ] == "QUARANTINED"

    assert D._record_inventory_reemit_phase_io(
        scratchpad=scratch,
        project_root=project,
        config=config,
        run_id=config["_run_id"],
    ) == []
    unit = read_artifact_ledger(scratch)["work_units"][key]
    assert unit["semantic_status"] == "ACTIVE"
    assert unit["commit_authority"]["attempt_ordinal"] == 2
    recovery = unit["quarantine_recovery_history"]
    rebind = unit["successor_physical_rebind_history"]
    assert len(recovery) == 1
    assert rebind == []
    assert recovery[0]["prior_commit_authority"]["attempt_ordinal"] == 1
    assert AL._active_commit_receipt_is_valid(
        unit,
        work_unit_key=key,
        run_id=config["_run_id"],
    )
    for field, value in (
        ("prior_artifacts_sha256", "f" * 64),
        (
            "recovered_at",
            (
                datetime.fromisoformat(recovery[0]["recovered_at"])
                + timedelta(seconds=1)
            ).isoformat(),
        ),
    ):
        coherent = copy.deepcopy(unit)
        coherent["quarantine_recovery_history"][0][field] = value
        _reseal_recovery_history(coherent)
        assert AL._validated_quarantine_recovery_history(
            coherent,
            work_unit_key=key,
            run_id=config["_run_id"],
        ) == coherent["quarantine_recovery_history"]
        assert not AL._active_commit_receipt_is_valid(
            coherent,
            work_unit_key=key,
            run_id=config["_run_id"],
        )
        assert AL._replay_output_commit_authority(
            scratch,
            project,
            coherent,
            require_live_bytes=False,
        )


def test_additive_reemit_driver_recovers_quarantined_merge_transaction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, scratch, config = _fixture(tmp_path)
    _seed_canonical_with_one_omitted_candidate(
        project, scratch, config
    )
    real_commit = D._commit_deterministic_driver_work_unit
    corrupted_once = False

    def _commit_with_one_bad_merge(**kwargs):
        nonlocal corrupted_once
        events = kwargs.get("merge_events")
        if (
            not corrupted_once
            and kwargs["contract"].work_unit_id == "additive_reemit"
            and isinstance(events, dict)
        ):
            corrupted_once = True
            changed = dict(events)
            identity = "scratchpad:findings_inventory.md"
            event = changed[identity]
            changed[identity] = DriverMergeEvent(
                work_unit_key=event.work_unit_key,
                contract_digest=event.contract_digest,
                artifact_identity=event.artifact_identity,
                before_sha256=event.before_sha256,
                after_sha256=event.after_sha256,
                source_identities=event.source_identities,
                identities_before=event.identities_before,
                identities_after=(
                    *event.identities_after,
                    "FORGED-IDENTITY",
                ),
            )
            kwargs["merge_events"] = changed
        return real_commit(**kwargs)

    monkeypatch.setattr(
        D,
        "_commit_deterministic_driver_work_unit",
        _commit_with_one_bad_merge,
    )
    first = D._record_inventory_reemit_phase_io(
        scratchpad=scratch,
        project_root=project,
        config=config,
        run_id=config["_run_id"],
    )
    assert first
    unit = read_artifact_ledger(scratch)["work_units"][
        "sc/thorough/evm/claude/inventory/additive_reemit"
    ]
    assert unit["semantic_status"] == "QUARANTINED"

    second = D._record_inventory_reemit_phase_io(
        scratchpad=scratch,
        project_root=project,
        config=config,
        run_id=config["_run_id"],
    )

    assert second == []
    inventory, records, ledger_ids = _projected_inventory_ids(scratch)
    assert inventory == records == ledger_ids == {"INV-001", "INV-002"}
    unit = read_artifact_ledger(scratch)["work_units"][
        "sc/thorough/evm/claude/inventory/additive_reemit"
    ]
    assert unit["semantic_status"] == "ACTIVE"
    assert unit["execution_state"] == "OUTPUT_COMMITTED"
    assert unit["commit_authority"]["attempt_ordinal"] == 2
    recovery = unit["quarantine_recovery_history"]
    assert len(recovery) == 1
    assert recovery[0]["prior_commit_authority"]["attempt_ordinal"] == 1
    rebinds = unit["successor_physical_rebind_history"]
    assert len(rebinds) == 1
    assert rebinds[0]["quarantined_commit_attempt_ordinal"] == 1
    assert set(rebinds[0]["rebindings"]) == {
        "scratchpad:findings_inventory.md",
        "scratchpad:finding_records.json",
        "scratchpad:_id_ledger.json",
    }


def test_additive_reemit_recovery_rejects_rebind_history_tamper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, scratch, config = _fixture(tmp_path)
    _seed_canonical_with_one_omitted_candidate(
        project, scratch, config
    )
    real_commit = D._commit_deterministic_driver_work_unit
    corrupted_once = False

    def _commit_with_one_bad_merge(**kwargs):
        nonlocal corrupted_once
        events = kwargs.get("merge_events")
        if (
            not corrupted_once
            and kwargs["contract"].work_unit_id == "additive_reemit"
            and isinstance(events, dict)
        ):
            corrupted_once = True
            changed = dict(events)
            identity = "scratchpad:findings_inventory.md"
            event = changed[identity]
            changed[identity] = DriverMergeEvent(
                work_unit_key=event.work_unit_key,
                contract_digest=event.contract_digest,
                artifact_identity=event.artifact_identity,
                before_sha256=event.before_sha256,
                after_sha256=event.after_sha256,
                source_identities=event.source_identities,
                identities_before=event.identities_before,
                identities_after=(
                    *event.identities_after,
                    "FORGED-IDENTITY",
                ),
            )
            kwargs["merge_events"] = changed
        return real_commit(**kwargs)

    monkeypatch.setattr(
        D,
        "_commit_deterministic_driver_work_unit",
        _commit_with_one_bad_merge,
    )
    first = D._record_inventory_reemit_phase_io(
        scratchpad=scratch,
        project_root=project,
        config=config,
        run_id=config["_run_id"],
    )
    assert first
    ledger = read_artifact_ledger(scratch)
    key = "sc/thorough/evm/claude/inventory/additive_reemit"
    unit = ledger["work_units"][key]
    assert D._recover_quarantined_inventory_reemit_transaction(
        scratchpad=scratch,
        project_root=project,
        config=config,
        run_id=config["_run_id"],
        unit=unit,
    ) == []

    ledger = read_artifact_ledger(scratch)
    clean_ledger = copy.deepcopy(ledger)
    clean_unit = clean_ledger["work_units"][key]
    contract, launch = _successor_authority_pair(config, clean_unit)
    assert AL._replay_driver_successor_authority(
        scratch,
        project,
        clean_ledger,
        clean_unit,
        contract,
        launch,
        run_id=config["_run_id"],
    )
    history = ledger["work_units"][key][
        "successor_physical_rebind_history"
    ]
    history[0]["rebindings"][
        "scratchpad:findings_inventory.md"
    ]["replacement_physical_identity"] = "file:forged:identity"
    AL.write_artifact_ledger(scratch, ledger)

    issues = D._record_inventory_reemit_phase_io(
        scratchpad=scratch,
        project_root=project,
        config=config,
        run_id=config["_run_id"],
    )
    assert any(
        "physical-rebind authority does not replay" in issue
        for issue in issues
    )

    # A valid rebind substitutes only the directory-entry identity.  Current
    # predecessor bytes remain mandatory, and another identical replacement
    # is not accepted until a causal recovery row records it.
    AL.write_artifact_ledger(scratch, clean_ledger)
    target = scratch / "findings_inventory.md"
    original = target.read_bytes()
    recorded_physical = AL._physical_file_identity(target)
    target.write_bytes(original + b"\nforged-live-byte\n")
    assert AL._physical_file_identity(target) == recorded_physical
    with pytest.raises(
        AL.ArtifactLedgerError,
        match="historical producer does not replay",
    ):
        AL._replay_driver_successor_authority(
            scratch,
            project,
            clean_ledger,
            clean_unit,
            contract,
            launch,
            run_id=config["_run_id"],
        )
    target.write_bytes(original)
    assert AL._physical_file_identity(target) == recorded_physical
    assert AL._replay_driver_successor_authority(
        scratch,
        project,
        clean_ledger,
        clean_unit,
        contract,
        launch,
        run_id=config["_run_id"],
    )
    replacement = scratch / "replacement_inventory.md"
    replacement.write_bytes(original)
    replacement.replace(target)
    assert AL._physical_file_identity(target) != recorded_physical
    with pytest.raises(
        AL.ArtifactLedgerError,
        match="historical producer does not replay",
    ):
        AL._replay_driver_successor_authority(
            scratch,
            project,
            clean_ledger,
            clean_unit,
            contract,
            launch,
            run_id=config["_run_id"],
        )


def test_additive_reemit_two_quarantines_chain_recovery_attempts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, scratch, config = _fixture(tmp_path)
    _seed_canonical_with_one_omitted_candidate(
        project, scratch, config
    )
    real_commit = D._commit_deterministic_driver_work_unit
    corruptions = 0

    def _commit_with_two_bad_merges(**kwargs):
        nonlocal corruptions
        events = kwargs.get("merge_events")
        if (
            corruptions < 2
            and kwargs["contract"].work_unit_id == "additive_reemit"
            and isinstance(events, dict)
        ):
            corruptions += 1
            changed = dict(events)
            identity = "scratchpad:findings_inventory.md"
            event = changed[identity]
            changed[identity] = DriverMergeEvent(
                work_unit_key=event.work_unit_key,
                contract_digest=event.contract_digest,
                artifact_identity=event.artifact_identity,
                before_sha256=event.before_sha256,
                after_sha256=event.after_sha256,
                source_identities=event.source_identities,
                identities_before=event.identities_before,
                identities_after=(
                    *event.identities_after,
                    f"FORGED-{corruptions}",
                ),
            )
            kwargs["merge_events"] = changed
        return real_commit(**kwargs)

    monkeypatch.setattr(
        D,
        "_commit_deterministic_driver_work_unit",
        _commit_with_two_bad_merges,
    )
    first = D._record_inventory_reemit_phase_io(
        scratchpad=scratch,
        project_root=project,
        config=config,
        run_id=config["_run_id"],
    )
    second = D._record_inventory_reemit_phase_io(
        scratchpad=scratch,
        project_root=project,
        config=config,
        run_id=config["_run_id"],
    )
    third = D._record_inventory_reemit_phase_io(
        scratchpad=scratch,
        project_root=project,
        config=config,
        run_id=config["_run_id"],
    )

    assert first and second
    assert third == []
    unit = read_artifact_ledger(scratch)["work_units"][
        "sc/thorough/evm/claude/inventory/additive_reemit"
    ]
    assert unit["semantic_status"] == "ACTIVE"
    assert unit["commit_authority"]["attempt_ordinal"] == 3
    history = unit["successor_physical_rebind_history"]
    assert [row["ordinal"] for row in history] == [1, 2]
    assert [
        row["quarantined_commit_attempt_ordinal"] for row in history
    ] == [1, 2]
    assert history[1]["prior_rebind_authority_digest"] == history[0][
        "authority_digest"
    ]
    recovery = unit["quarantine_recovery_history"]
    assert [
        row["prior_commit_authority"]["attempt_ordinal"]
        for row in recovery
    ] == [1, 2]
    assert AL._validated_quarantine_recovery_history(
        unit,
        work_unit_key=unit["work_unit_key"],
        run_id=config["_run_id"],
    ) == recovery
    assert AL._active_commit_receipt_is_valid(
        unit,
        work_unit_key=unit["work_unit_key"],
        run_id=config["_run_id"],
    )

    malformed = copy.deepcopy(unit)
    malformed["quarantine_recovery_history"] = {}
    cross_run = copy.deepcopy(unit)
    cross_run["quarantine_recovery_history"][0][
        "prior_commit_authority"
    ]["run_id"] = str(uuid.uuid4())
    nonmonotonic = copy.deepcopy(unit)
    nonmonotonic["quarantine_recovery_history"].reverse()
    receipt_tamper = copy.deepcopy(unit)
    receipt_tamper["quarantine_recovery_history"][0][
        "prior_commit_authority"
    ]["reason_codes"] = []
    digest_tamper = copy.deepcopy(unit)
    digest_tamper["quarantine_recovery_history"][0][
        "prior_artifacts_sha256"
    ] = "invalid"
    valid_digest_tamper = copy.deepcopy(unit)
    valid_digest_tamper["quarantine_recovery_history"][0][
        "prior_artifacts_sha256"
    ] = "f" * 64
    valid_timestamp_tamper = copy.deepcopy(unit)
    valid_timestamp_tamper["quarantine_recovery_history"][0][
        "recovered_at"
    ] = (
        datetime.fromisoformat(recovery[0]["recovered_at"])
        + timedelta(microseconds=1)
    ).isoformat()
    for candidate in (
        malformed,
        cross_run,
        nonmonotonic,
        receipt_tamper,
        digest_tamper,
        valid_digest_tamper,
        valid_timestamp_tamper,
    ):
        with pytest.raises(AL.ArtifactLedgerError):
            AL._validated_quarantine_recovery_history(
                candidate,
                work_unit_key=unit["work_unit_key"],
                run_id=config["_run_id"],
            )
        assert not AL._active_commit_receipt_is_valid(
            candidate,
            work_unit_key=unit["work_unit_key"],
            run_id=config["_run_id"],
        )

    authority = unit["successor_consumption_authority"]
    assert AL._validated_driver_successor_physical_rebind_history(
        scratch,
        unit,
        authority,
        require_live_prestate=False,
    )[0] == history

    for field, value in (
        ("prior_artifacts_sha256", "f" * 64),
        (
            "recovered_at",
            (
                datetime.fromisoformat(recovery[1]["recovered_at"])
                + timedelta(microseconds=1)
            ).isoformat(),
        ),
    ):
        coherent = copy.deepcopy(unit)
        coherent["quarantine_recovery_history"][1][field] = value
        _reseal_recovery_history(coherent)
        assert AL._validated_quarantine_recovery_history(
            coherent,
            work_unit_key=unit["work_unit_key"],
            run_id=config["_run_id"],
        ) == coherent["quarantine_recovery_history"]
        assert not AL._active_commit_receipt_is_valid(
            coherent,
            work_unit_key=unit["work_unit_key"],
            run_id=config["_run_id"],
        )
        with pytest.raises(AL.ArtifactLedgerError):
            AL._validated_driver_successor_physical_rebind_history(
                scratch,
                coherent,
                authority,
                require_live_prestate=False,
            )

    def _reseal_rebind(candidate: dict, ordinal: int) -> None:
        row = candidate["successor_physical_rebind_history"][ordinal]
        unsigned = {
            key: value for key, value in row.items()
            if key != "authority_digest"
        }
        row["authority_digest"] = AL._canonical_json_digest(unsigned)
        AL._write_once_authority_cas(
            scratch,
            directory_name=(
                AL._DRIVER_SUCCESSOR_PHYSICAL_REBIND_CAS_DIRECTORY
            ),
            authority_digest=row["authority_digest"],
            unsigned_authority=unsigned,
            label="driver successor physical rebind",
        )

    recovery_short = copy.deepcopy(unit)
    recovery_short["quarantine_recovery_history"].pop()
    foreign_receipt = copy.deepcopy(unit)
    foreign_receipt["successor_physical_rebind_history"][1][
        "quarantined_commit_receipt_digest"
    ] = recovery[0]["prior_commit_authority"]["receipt_digest"]
    foreign_receipt["successor_physical_rebind_history"][1][
        "quarantined_commit_attempt_ordinal"
    ] = recovery[0]["prior_commit_authority"]["attempt_ordinal"]
    _reseal_rebind(foreign_receipt, 1)
    empty = copy.deepcopy(unit)
    empty["successor_physical_rebind_history"][1]["rebindings"] = {}
    _reseal_rebind(empty, 1)
    alias = copy.deepcopy(unit)
    alias_row = alias["successor_physical_rebind_history"][1]
    identity = next(iter(alias_row["rebindings"]))
    alias_row["rebindings"][identity.upper()] = copy.deepcopy(
        alias_row["rebindings"][identity]
    )
    _reseal_rebind(alias, 1)
    stale_head = copy.deepcopy(unit)
    stale_binding = next(iter(
        stale_head["successor_physical_rebind_history"][1][
            "rebindings"
        ].values()
    ))
    stale_binding["prior_physical_identity"] = "file:stale:head"
    _reseal_rebind(stale_head, 1)
    for candidate in (
        recovery_short,
        foreign_receipt,
        empty,
        alias,
        stale_head,
    ):
        with pytest.raises(AL.ArtifactLedgerError):
            AL._validated_driver_successor_physical_rebind_history(
                scratch,
                candidate,
                authority,
                require_live_prestate=False,
            )


def test_successor_exact_noop_preserves_physical_identity(
    tmp_path: Path,
) -> None:
    target = tmp_path / "_id_ledger.json"
    raw = b'{"allocations":[],"schema_version":"v2"}\n'
    target.write_bytes(raw)
    before = target.stat()

    assert D._materialize_driver_successor_bytes(target, raw) is False

    after = target.stat()
    assert (after.st_dev, after.st_ino) == (
        before.st_dev,
        before.st_ino,
    )
    assert target.read_bytes() == raw
    loop_source = inspect.getsource(D._record_inventory_reemit_phase_io)
    assert "_materialize_driver_successor_bytes(output_path, raw)" in (
        loop_source
    )


def test_additive_reemit_resume_rejects_bound_source_drift(
    tmp_path: Path,
) -> None:
    project, scratch, config = _fixture(tmp_path)
    _seed_canonical_with_one_omitted_candidate(
        project, scratch, config
    )
    config["_inventory_reemit_failpoint"] = "after_apply"
    issues = D._record_inventory_reemit_phase_io(
        scratchpad=scratch,
        project_root=project,
        config=config,
        run_id=config["_run_id"],
    )
    assert issues
    with (scratch / "analysis_a.md").open("ab") as handle:
        handle.write(b"\nlate source drift\n")
    config.pop("_inventory_reemit_failpoint")

    issues = D._record_inventory_reemit_phase_io(
        scratchpad=scratch,
        project_root=project,
        config=config,
        run_id=config["_run_id"],
    )

    assert issues
    assert any(
        "input" in issue.lower()
        or "hash" in issue.lower()
        or "drift" in issue.lower()
        for issue in issues
    )
    inventory, records, ledger_ids = _projected_inventory_ids(scratch)
    assert inventory == {"INV-001", "INV-002"}
    assert records == ledger_ids == {"INV-001"}
    unit = read_artifact_ledger(scratch)["work_units"][
        "sc/thorough/evm/claude/inventory/additive_reemit"
    ]
    assert unit["semantic_status"] == "INPUTS_BOUND"
    assert unit["execution_state"] == "INPUTS_BOUND_PREEXECUTION"


def _write_legacy_id_ledger(
    scratch: Path,
    allocations: list[dict],
    *,
    newline: str = "\n",
) -> bytes:
    raw = (
        json.dumps(
            {
                "schema_version": "plamen.id_ledger.v1",
                "allocations": allocations,
            },
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        )
        + "\n"
    ).replace("\n", newline).encode("utf-8")
    (scratch / "_id_ledger.json").write_bytes(raw)
    return raw


def _legacy_allocation(fid: str, title: str) -> dict:
    return {
        "id": fid,
        "prefix": fid.rsplit("-", 1)[0] + "-",
        "owner_phase": "legacy_phase",
        "owner_attempt": 1,
        "owning_artifact": "legacy.md",
        "title_hash": _title_hash(title),
        "title_preview": title,
        "allocated_at": "2026-01-01T00:00:00+00:00",
    }


def _id_merge_receipt(scratch: Path) -> dict:
    return json.loads(
        (scratch / "inventory_id_ledger_merge_receipt.json").read_text(
            encoding="utf-8"
        )
    )


def test_id_ledger_merge_creates_from_absent_empty_base(tmp_path: Path) -> None:
    project, scratch, config = _fixture(tmp_path)
    _seed_for_aggregate(project, scratch, config, "single_shard")

    _result, issues = D._run_inventory_canonical_aggregate_transaction(
        scratchpad=scratch,
        config=config,
        phase=_phase("inventory"),
        derivation_kind="single_shard",
    )

    assert issues == []
    assert (scratch / "inventory_id_allocation_delta.json").is_file()
    assert _id_merge_receipt(scratch)["status"] == "EMPTY_BASE_CREATED"
    assert _projected_inventory_ids(scratch)[2] == {"INV-001"}


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_id_ledger_merge_preserves_valid_untyped_non_inventory_rows(
    tmp_path: Path,
    newline: str,
) -> None:
    project, scratch, config = _fixture(tmp_path)
    before = _write_legacy_id_ledger(
        scratch,
        [_legacy_allocation("GRP-009", "legacy group")],
        newline=newline,
    )
    _seed_for_aggregate(project, scratch, config, "single_shard")

    _result, issues = D._run_inventory_canonical_aggregate_transaction(
        scratchpad=scratch,
        config=config,
        phase=_phase("inventory"),
        derivation_kind="single_shard",
    )

    assert issues == []
    receipt = _id_merge_receipt(scratch)
    assert receipt["status"] == "PREEXISTING_UNTYPED_PRESERVED"
    assert receipt["before_sha256"] == hashlib.sha256(before).hexdigest()
    ledger = json.loads(
        (scratch / "_id_ledger.json").read_text(encoding="utf-8")
    )
    assert {row["id"] for row in ledger["allocations"]} == {
        "GRP-009",
        "INV-001",
    }


def test_id_ledger_merge_accepts_compatible_existing_inventory_id(
    tmp_path: Path,
) -> None:
    project, scratch, config = _fixture(tmp_path)
    original = _legacy_allocation("INV-001", "candidate a")
    _write_legacy_id_ledger(scratch, [original])
    _seed_for_aggregate(project, scratch, config, "single_shard")

    _result, issues = D._run_inventory_canonical_aggregate_transaction(
        scratchpad=scratch,
        config=config,
        phase=_phase("inventory"),
        derivation_kind="single_shard",
    )

    assert issues == []
    ledger = json.loads(
        (scratch / "_id_ledger.json").read_text(encoding="utf-8")
    )
    assert ledger["allocations"] == [original]
    assert _id_merge_receipt(scratch)["compatible_reuse_ids"] == [
        "INV-001"
    ]


def test_id_ledger_merge_rejects_semantic_inventory_collision(
    tmp_path: Path,
) -> None:
    project, scratch, config = _fixture(tmp_path)
    before = _write_legacy_id_ledger(
        scratch,
        [_legacy_allocation("INV-001", "different mechanism")],
    )
    _seed_for_aggregate(project, scratch, config, "single_shard")

    _result, issues = D._run_inventory_canonical_aggregate_transaction(
        scratchpad=scratch,
        config=config,
        phase=_phase("inventory"),
        derivation_kind="single_shard",
    )

    assert issues
    assert any("collision" in issue.lower() for issue in issues)
    assert (scratch / "_id_ledger.json").read_bytes() == before
    assert _id_merge_receipt(scratch)["status"] == "IDENTITY_COLLISION_DEBT"
    ledger = read_artifact_ledger(scratch)
    unit = ledger["work_units"][
        "sc/thorough/evm/claude/inventory/id_ledger_merge"
    ]
    assert unit["semantic_status"] == "QUARANTINED"
    binding = ledger["artifact_bindings"].get(
        "scratchpad:_id_ledger.json"
    )
    assert not isinstance(binding, dict) or binding.get("status") != "ACTIVE"


def test_id_ledger_merge_preserves_malformed_legacy_bytes_as_debt(
    tmp_path: Path,
) -> None:
    project, scratch, config = _fixture(tmp_path)
    ledger_path = scratch / "_id_ledger.json"
    ledger_path.write_bytes(b"{malformed legacy bytes\r\n")
    before = ledger_path.read_bytes()
    _seed_for_aggregate(project, scratch, config, "single_shard")

    _result, issues = D._run_inventory_canonical_aggregate_transaction(
        scratchpad=scratch,
        config=config,
        phase=_phase("inventory"),
        derivation_kind="single_shard",
    )

    assert issues
    assert ledger_path.read_bytes() == before
    assert not (
        scratch / "inventory_id_ledger_merge_receipt.json"
    ).exists()
    unit = read_artifact_ledger(scratch)["work_units"][
        "sc/thorough/evm/claude/inventory/id_ledger_merge"
    ]
    prestate = unit["output_prestates"]["scratchpad:_id_ledger.json"]
    assert unit["semantic_status"] == "INPUT_DEBT"
    assert prestate["status"] == "EXTERNAL_PREIMAGE_VALIDATION_DEBT"
    assert prestate["external_preimage_validation_error"]
    assert "scratchpad:_id_ledger.json" not in read_artifact_ledger(scratch)[
        "artifact_bindings"
    ]


def test_canonical_debt_boundary_forbids_model_fallback_and_preserves_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, scratch, config = _fixture(tmp_path)
    ledger_path = scratch / "_id_ledger.json"
    ledger_path.write_bytes(b"{malformed legacy bytes\r\n")
    _seed_for_aggregate(project, scratch, config, "single_shard")
    _result, issues = D._run_inventory_canonical_aggregate_transaction(
        scratchpad=scratch,
        config=config,
        phase=_phase("inventory"),
        derivation_kind="single_shard",
    )
    assert issues
    preserved = {
        name: (scratch / name).read_bytes()
        for name in (
            "inventory_aggregate_derivation.json",
            "findings_inventory.md",
            "finding_records.json",
            "inventory_id_allocation_delta.json",
            "_id_ledger.json",
        )
    }
    model_launches: list[str] = []
    monkeypatch.setattr(
        D,
        "run_phase",
        lambda phase, _config, _attempt: model_launches.append(phase.name),
    )

    class _Checkpoint:
        saved = False

        def save(self, root: Path) -> None:
            assert root == scratch
            self.saved = True

    checkpoint = _Checkpoint()
    with pytest.raises(SystemExit) as stopped:
        D._enforce_canonical_inventory_debt_boundary(
            scratchpad=scratch,
            config=config,
            checkpoint=checkpoint,
        )

    assert stopped.value.code == D.EXIT_DEGRADED
    assert checkpoint.saved is True
    assert model_launches == []
    assert {
        name: (scratch / name).read_bytes() for name in preserved
    } == preserved
    tree = ast.parse(textwrap.dedent(inspect.getsource(D.main)))
    inventory_branches = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.If)
        and any(
            isinstance(part, ast.Constant)
            and part.value == "inventory"
            for part in ast.walk(node.test)
        )
    ]
    assert any(
        isinstance(call.func, ast.Name)
        and call.func.id
        == "_enforce_canonical_inventory_debt_boundary"
        for branch in inventory_branches
        for statement in branch.body
        for call in ast.walk(statement)
        if isinstance(call, ast.Call)
    )


@pytest.mark.parametrize(
    "failpoint",
    ["after_arm", "after_receipt", "after_write"],
)
def test_id_ledger_merge_crash_resume_is_exact(
    tmp_path: Path,
    failpoint: str,
) -> None:
    project, scratch, config = _fixture(tmp_path)
    _seed_for_aggregate(project, scratch, config, "single_shard")
    config["_inventory_id_ledger_merge_failpoint"] = failpoint

    _result, issues = D._run_inventory_canonical_aggregate_transaction(
        scratchpad=scratch,
        config=config,
        phase=_phase("inventory"),
        derivation_kind="single_shard",
    )
    assert issues
    config.pop("_inventory_id_ledger_merge_failpoint")

    result, issues = D._run_inventory_canonical_aggregate_transaction(
        scratchpad=scratch,
        config=config,
        phase=_phase("inventory"),
        derivation_kind="single_shard",
    )

    assert issues == []
    assert result["finding_count"] == 1
    inventory, records, ledger_ids = _projected_inventory_ids(scratch)
    assert inventory == records == ledger_ids == {"INV-001"}
    unit = read_artifact_ledger(scratch)["work_units"][
        "sc/thorough/evm/claude/inventory/id_ledger_merge"
    ]
    assert unit["semantic_status"] == "ACTIVE"
    assert unit["execution_state"] == "OUTPUT_COMMITTED"
    assert unit["commit_authority"]["attempt_ordinal"] == 1
    assert unit.get("semantic_reexecution_history", []) == []
    assert unit.get("quarantine_recovery_history", []) == []
    journal = json.loads(
        (scratch / AL._OUTPUT_AUTHORITY_LEDGER_NAME).read_text(
            encoding="utf-8"
        )
    )
    issued = [
        row
        for row in journal["authorities"].values()
        if row.get("run_id") == config["_run_id"]
        and row.get("work_unit_key")
        == "sc/thorough/evm/claude/inventory/id_ledger_merge"
    ]
    assert [row["attempt_ordinal"] for row in issued] == [1]
    contract, launch = D._inventory_id_ledger_contract_and_launch(
        config=config,
        timeout_s=_phase("inventory").base_timeout_s,
    )
    assert AL.validate_work_unit_artifacts(
        scratch,
        project,
        contract,
        launch,
        run_id=config["_run_id"],
        actor="DRIVER",
    ) == []


def test_id_ledger_merge_resume_rejects_third_state_drift(
    tmp_path: Path,
) -> None:
    project, scratch, config = _fixture(tmp_path)
    _seed_for_aggregate(project, scratch, config, "single_shard")
    config["_inventory_id_ledger_merge_failpoint"] = "after_arm"
    _result, issues = D._run_inventory_canonical_aggregate_transaction(
        scratchpad=scratch,
        config=config,
        phase=_phase("inventory"),
        derivation_kind="single_shard",
    )
    assert issues
    (scratch / "_id_ledger.json").write_text(
        '{"schema_version":"plamen.id_ledger.v1","allocations":[]}\n',
        encoding="utf-8",
    )
    drift = (scratch / "_id_ledger.json").read_bytes()
    config.pop("_inventory_id_ledger_merge_failpoint")

    _result, issues = D._run_inventory_canonical_aggregate_transaction(
        scratchpad=scratch,
        config=config,
        phase=_phase("inventory"),
        derivation_kind="single_shard",
    )

    assert issues
    assert any(
        "third-state" in issue.lower()
        or "cas" in issue.lower()
        or "drift" in issue.lower()
        for issue in issues
    )
    assert (scratch / "_id_ledger.json").read_bytes() == drift


def test_id_ledger_merge_exact_replay_is_read_only(tmp_path: Path) -> None:
    project, scratch, config = _fixture(tmp_path)
    _seed_for_aggregate(project, scratch, config, "single_shard")
    result, issues = D._run_inventory_canonical_aggregate_transaction(
        scratchpad=scratch,
        config=config,
        phase=_phase("inventory"),
        derivation_kind="single_shard",
    )
    assert issues == []
    names = (
        "findings_inventory.md",
        "finding_records.json",
        "inventory_id_allocation_delta.json",
        "_id_ledger.json",
        "inventory_id_ledger_merge_receipt.json",
    )
    before = {name: (scratch / name).read_bytes() for name in names}

    replay, issues = D._run_inventory_canonical_aggregate_transaction(
        scratchpad=scratch,
        config=config,
        phase=_phase("inventory"),
        derivation_kind="single_shard",
    )

    assert issues == []
    assert replay == result
    assert {name: (scratch / name).read_bytes() for name in names} == before


def test_id_ledger_merge_concurrent_resume_commits_one_exact_successor(
    tmp_path: Path,
) -> None:
    project, scratch, config = _fixture(tmp_path)
    _seed_for_aggregate(project, scratch, config, "single_shard")
    config["_inventory_id_ledger_merge_failpoint"] = "after_arm"
    _result, issues = D._run_inventory_canonical_aggregate_transaction(
        scratchpad=scratch,
        config=config,
        phase=_phase("inventory"),
        derivation_kind="single_shard",
    )
    assert issues
    config.pop("_inventory_id_ledger_merge_failpoint")

    def resume() -> list[str]:
        return D._run_inventory_id_ledger_merge_transaction(
            scratchpad=scratch,
            config=config,
            timeout_s=_phase("inventory").base_timeout_s,
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _index: resume(), range(2)))

    assert results == [[], []]
    inventory, records, ledger_ids = _projected_inventory_ids(scratch)
    assert inventory == records == ledger_ids == {"INV-001"}
    ledger = json.loads(
        (scratch / "_id_ledger.json").read_text(encoding="utf-8")
    )
    assert [row["id"] for row in ledger["allocations"]] == ["INV-001"]
    unit = read_artifact_ledger(scratch)["work_units"][
        "sc/thorough/evm/claude/inventory/id_ledger_merge"
    ]
    assert unit["semantic_status"] == "ACTIVE"
    assert unit["execution_state"] == "OUTPUT_COMMITTED"


def test_id_ledger_merge_cross_process_resume_issues_one_attempt(
    tmp_path: Path,
) -> None:
    project, scratch, config = _fixture(tmp_path)
    _seed_for_aggregate(project, scratch, config, "single_shard")
    config["_inventory_id_ledger_merge_failpoint"] = "after_arm"
    _result, issues = D._run_inventory_canonical_aggregate_transaction(
        scratchpad=scratch,
        config=config,
        phase=_phase("inventory"),
        derivation_kind="single_shard",
    )
    assert issues
    config.pop("_inventory_id_ledger_merge_failpoint")

    context = multiprocessing.get_context("spawn")
    result_queue = context.Queue()
    processes = [
        context.Process(
            target=_resume_id_ledger_in_child,
            args=(
                str(scratch),
                config,
                _phase("inventory").base_timeout_s,
                result_queue,
            ),
        )
        for _index in range(2)
    ]
    for process in processes:
        process.start()
    results = [result_queue.get(timeout=120) for _process in processes]
    for process in processes:
        process.join(timeout=120)
        assert process.exitcode == 0

    assert results == [[], []]
    key = "sc/thorough/evm/claude/inventory/id_ledger_merge"
    unit = read_artifact_ledger(scratch)["work_units"][key]
    assert unit["commit_authority"]["attempt_ordinal"] == 1
    assert unit.get("semantic_reexecution_history", []) == []
    assert unit.get("quarantine_recovery_history", []) == []
    journal = json.loads(
        (scratch / AL._OUTPUT_AUTHORITY_LEDGER_NAME).read_text(
            encoding="utf-8"
        )
    )
    issued = [
        row
        for row in journal["authorities"].values()
        if row.get("run_id") == config["_run_id"]
        and row.get("work_unit_key") == key
    ]
    assert [row["attempt_ordinal"] for row in issued] == [1]


def test_canonical_allocation_preserves_full_hash_for_long_title(
    tmp_path: Path,
) -> None:
    project, scratch, config = _fixture(tmp_path)
    title = "long canonical finding title " + ("x" * 180)
    _source(scratch, "analysis_a.md", "A-01", title)
    _seed_active_chunk(
        project,
        scratch,
        config,
        "inventory_chunk_a",
        rows=(("CC-A1", title, ("A-01",)),),
        sources=("analysis_a.md",),
    )

    _result, issues = D._run_inventory_canonical_aggregate_transaction(
        scratchpad=scratch,
        config=config,
        phase=_phase("inventory"),
        derivation_kind="single_shard",
    )

    assert issues == []
    delta = json.loads(
        (scratch / "inventory_id_allocation_delta.json").read_text(
            encoding="utf-8"
        )
    )
    allocation = delta["allocations"][0]
    assert allocation["title_hash"] == _title_hash(title)
    assert allocation["title_preview"] == title[:120]


@pytest.mark.parametrize("failpoint", ["after_receipt", "after_write"])
def test_id_ledger_merge_resume_rejects_tampered_partial_receipt(
    tmp_path: Path,
    failpoint: str,
) -> None:
    project, scratch, config = _fixture(tmp_path)
    _seed_for_aggregate(project, scratch, config, "single_shard")
    config["_inventory_id_ledger_merge_failpoint"] = failpoint
    _result, issues = D._run_inventory_canonical_aggregate_transaction(
        scratchpad=scratch,
        config=config,
        phase=_phase("inventory"),
        derivation_kind="single_shard",
    )
    assert issues
    ledger_before_resume = (
        (scratch / "_id_ledger.json").read_bytes()
        if (scratch / "_id_ledger.json").is_file()
        else b""
    )
    receipt_path = scratch / "inventory_id_ledger_merge_receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["status"] = "TYPED_PREIMAGE_MERGED"
    receipt["preexisting_authority"] = "TYPED_ACTIVE"
    receipt["receipt_digest"] = IM._digest(receipt, "receipt_digest")
    receipt_path.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    config.pop("_inventory_id_ledger_merge_failpoint")

    _result, issues = D._run_inventory_canonical_aggregate_transaction(
        scratchpad=scratch,
        config=config,
        phase=_phase("inventory"),
        derivation_kind="single_shard",
    )

    assert issues
    assert any(
        "receipt" in issue.lower()
        or "re-derivation" in issue.lower()
        for issue in issues
    )
    live = (
        (scratch / "_id_ledger.json").read_bytes()
        if (scratch / "_id_ledger.json").is_file()
        else b""
    )
    assert live == ledger_before_resume
