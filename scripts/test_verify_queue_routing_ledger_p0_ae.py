"""Red fixtures for typed verify-queue routing artifact ownership.

The queue builders already emit three projections per queue/shard.  These
acceptance tests require the mechanical SC and L1 routing transactions to bind
every projection to one exact driver-owned work unit before checkpointing.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from artifact_ledger import (
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
)
from phase_io_contracts import (
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    canonical_work_unit_key,
    resolve_phase_io_contract,
)
import plamen_driver as D
import plamen_parsers as P
from plamen_types import L1_VERIFY_SHARD_MANIFESTS, SC_VERIFY_SHARD_MANIFESTS
from queue_work_items import queue_records_to_json


CASES = (
    ("l1", "verify_queue", L1_VERIFY_SHARD_MANIFESTS),
    ("sc", "sc_verify_queue", SC_VERIFY_SHARD_MANIFESTS),
)

QUEUE_ROUTING_BASE_INPUTS = (
    "findings_inventory.md",
    "hypotheses.md",
    "finding_mapping.md",
    "chain_grouping_relations.json",
    "chain_anti_absorption_applied_receipt.json",
    "chain_equivalence_proposals.json",
    "chain_composition_verification_candidates.json",
)
QUEUE_ROUTING_MANDATORY_INPUTS = (
    "findings_inventory.md",
    "preverify_inventory_successor.json",
    "finding_delivery_successor.json",
)
QUEUE_ROUTING_INPUTS = (
    *QUEUE_ROUTING_MANDATORY_INPUTS,
    *(relative for relative in QUEUE_ROUTING_BASE_INPUTS if relative != "findings_inventory.md"),
)


def _config(tmp_path: Path, pipeline: str, *, backend: str = "claude") -> dict:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir(parents=True, exist_ok=True)
    return {
        "pipeline": pipeline,
        "mode": "thorough",
        "language": "rust" if pipeline == "l1" else "evm",
        "cli_backend": backend,
        "scratchpad": str(scratchpad),
        "project_root": str(tmp_path),
        "_run_id": f"typed-{pipeline}-queue-routing-test",
    }


def _projection_triplet(markdown_path: str) -> tuple[str, str, str]:
    path = Path(markdown_path)
    return (
        path.as_posix(),
        path.with_suffix(".json").as_posix(),
        path.with_suffix(".work_items.json").as_posix(),
    )


def _exact_outputs(manifests: dict[str, str]) -> tuple[str, ...]:
    markdown_paths = {"verification_queue.md", *manifests.values()}
    outputs = {
        relative
        for markdown_path in markdown_paths
        for relative in _projection_triplet(markdown_path)
    }
    outputs.add("verification_queue.work_plan.json")
    outputs.update({
        "compound_candidates.json",
        "compound_verification_work_plan.json",
        "mandatory_reverification_denominator.json",
        "mandatory_reverification_routing.json",
        "verification_context_packets.json",
        "verification_methodology_reachability.json",
        "verify_queue_context_input_status.json",
    })
    return tuple(sorted(outputs))


def _seed_inputs(scratchpad: Path, config: dict) -> None:
    # Publish the mutable inventory through a current-run producer, then use
    # the public provider to freeze its exact inventory/records pair.  Bare
    # handwritten finding_records.json is no longer capture authority.
    owner = canonical_work_unit_key(
        str(config["pipeline"]),
        str(config["mode"]),
        str(config["language"]),
        str(config["cli_backend"]),
        "inventory",
        "routing_fixture_source",
    )
    contract = PhaseIOContract(
        pipeline=str(config["pipeline"]),
        mode=str(config["mode"]),
        ecosystem=str(config["language"]),
        backend=str(config["cli_backend"]),
        phase="inventory",
        work_unit_id="routing_fixture_source",
        outputs=(
            ArtifactSpec(
                root="scratchpad",
                path="findings_inventory.md",
                owner_key=owner,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="CREATE",
                schema_version="unstructured.v1",
                minimum_gate="FIXTURE_FINAL_INVENTORY",
            ),
        ),
        model_invoked=False,
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="fixture-driver",
        timeout_s=30,
        exec_mode="python",
        tool_policy=("filesystem",),
    )
    record_work_unit_inputs(
        scratchpad,
        Path(config["project_root"]),
        contract,
        launch,
        run_id=str(config["_run_id"]),
    )
    (scratchpad / "findings_inventory.md").write_text(
        "# Source Authority\n",
        encoding="utf-8",
    )
    record_work_unit_artifacts(
        scratchpad,
        Path(config["project_root"]),
        contract,
        launch,
        run_id=str(config["_run_id"]),
        actor="DRIVER",
    )
    phase_name = (
        "verify_queue"
        if config["pipeline"] == "l1"
        else "sc_verify_queue"
    )
    frozen = D.prepare_preverify_frozen_projection(
        scratchpad=scratchpad,
        project_root=Path(config["project_root"]),
        pipeline=str(config["pipeline"]),
        mode=str(config["mode"]),
        ecosystem=str(config["language"]),
        backend=str(config["cli_backend"]),
        phase_name=phase_name,
        run_id=str(config["_run_id"]),
    )
    assert D._finalize_preverify_inventory_successors(
        scratchpad,
        config,
        phase_name=phase_name,
        frozen_projection=frozen,
    ) == []
    # Optional routing context is intentionally non-authoritative here.  The
    # closed-policy selector must omit it with visible safe-base debt rather
    # than adopt fixture bytes.
    for relative in QUEUE_ROUTING_BASE_INPUTS:
        if relative == "findings_inventory.md":
            continue
        path = scratchpad / relative
        content = "# Source Authority\n" if path.suffix == ".md" else "{}\n"
        path.write_text(content, encoding="utf-8")


def _seed_outputs(scratchpad: Path, manifests: dict[str, str]) -> tuple[str, ...]:
    outputs = _exact_outputs(manifests)
    for relative in outputs:
        if relative in {
            "verification_context_packets.json",
            "verification_methodology_reachability.json",
            "verify_queue_context_input_status.json",
        }:
            continue
        path = scratchpad / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if relative == "verification_queue.work_items.json":
            content = queue_records_to_json(()) + "\n"
        elif path.suffix == ".md":
            content = "# Verification Queue Manifest\n"
        else:
            content = "{}\n"
        path.write_text(content, encoding="utf-8")
    return outputs


def _tree_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _contract(config: dict, phase_name: str, outputs: tuple[str, ...]):
    scratchpad = Path(config["scratchpad"])
    unit_key = "/".join((
        config["pipeline"],
        config["mode"],
        config["language"],
        config["cli_backend"],
        phase_name,
        "routing",
    ))
    try:
        unit = read_artifact_ledger(scratchpad).get("work_units", {}).get(
            unit_key, {}
        )
    except Exception:
        unit = {}
    bound = unit.get("input_bindings") if isinstance(unit, dict) else None
    if isinstance(bound, dict):
        inputs = tuple(sorted(
            identity.split(":", 1)[1]
            for identity in bound
            if isinstance(identity, str) and identity.startswith("scratchpad:")
        ))
    else:
        inputs = QUEUE_ROUTING_MANDATORY_INPUTS
    return resolve_phase_io_contract(
        pipeline=config["pipeline"],
        mode=config["mode"],
        ecosystem=config["language"],
        backend=config["cli_backend"],
        phase=phase_name,
        work_unit_id="routing",
        exact_inputs=inputs,
        exact_outputs=outputs,
    )


@pytest.mark.parametrize(
    "pipeline,project",
    (("l1", P.compute_verify_shards), ("sc", P.compute_sc_verify_shards)),
)
def test_unarmed_runtime_projection_cannot_materialize_queue_sidecar(
    tmp_path: Path,
    pipeline: str,
    project,
) -> None:
    config = _config(tmp_path, pipeline)
    scratchpad = Path(config["scratchpad"])
    queue = scratchpad / "verification_queue.md"
    queue.write_text(
        "# Verification Queue Manifest\n"
        "| Queue # | Finding ID | Expected Output File | Severity | Title | "
        "Bug Class | Preferred Tag | Location | Primary Artifact | PoC Class |\n"
        "|---|---|---|---|---|---|---|---|---|---|\n"
        "| 1 | H-1 | verify_H-1.md | High | A | state | CODE-TRACE | "
        "a.sol:1 | depth.md | integration |\n",
        encoding="utf-8",
    )
    before = _tree_bytes(scratchpad)

    shards = project(scratchpad)

    assert not (scratchpad / "verification_queue.work_items.json").exists()
    assert _tree_bytes(scratchpad) == before
    assert any(
        row.get("finding id") == "H-1"
        for shard_rows in shards.values()
        for row in shard_rows
    )


@pytest.mark.parametrize(
    "pipeline,ensure",
    (
        ("l1", P.ensure_verify_shard_manifests),
        ("sc", P.ensure_sc_verify_shard_manifests),
    ),
)
def test_routing_manifest_writer_requires_preexisting_typed_queue_authority(
    tmp_path: Path,
    pipeline: str,
    ensure,
) -> None:
    config = _config(tmp_path, pipeline)
    scratchpad = Path(config["scratchpad"])
    (scratchpad / "verification_queue.md").write_text(
        "# Verification Queue Manifest\n"
        "| Queue # | Finding ID | Expected Output File | Severity | Title | "
        "Bug Class | Preferred Tag | Location | Primary Artifact | PoC Class |\n"
        "|---|---|---|---|---|---|---|---|---|---|\n"
        "| 1 | H-1 | verify_H-1.md | High | A | state | CODE-TRACE | "
        "a.sol:1 | depth.md | integration |\n",
        encoding="utf-8",
    )
    before = _tree_bytes(scratchpad)

    with pytest.raises(FileNotFoundError, match="typed queue authority.*missing"):
        ensure(scratchpad)

    assert not (scratchpad / "verification_queue.work_items.json").exists()
    assert _tree_bytes(scratchpad) == before


@pytest.mark.parametrize(
    "pipeline,ensure",
    (
        ("l1", P.ensure_verify_shard_manifests),
        ("sc", P.ensure_sc_verify_shard_manifests),
    ),
)
def test_routing_manifest_writer_never_migrates_legacy_typed_queue_authority(
    tmp_path: Path,
    pipeline: str,
    ensure,
) -> None:
    config = _config(tmp_path, pipeline)
    scratchpad = Path(config["scratchpad"])
    queue = scratchpad / "verification_queue.md"
    P._write_queue_subset_manifest(
        queue,
        [{
            "queue #": "1",
            "finding id": "H-1",
            "severity": "High",
            "title": "A",
            "bug class": "state",
            "preferred tag": "CODE-TRACE",
            "location": "a.sol:1",
            "primary artifact": "depth.md",
            "poc class": "integration",
        }],
    )
    typed = queue.with_suffix(".work_items.json")
    payload = json.loads(typed.read_text(encoding="utf-8"))
    payload["schema_version"] = "plamen.queue_work_items.v2"
    typed.write_text(
        json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    before = _tree_bytes(scratchpad)

    with pytest.raises(ValueError, match="canonical typed queue schema"):
        ensure(scratchpad)

    assert _tree_bytes(scratchpad) == before


def test_queue_routing_contract_binds_grouping_and_composition_inputs() -> None:
    exact_inputs = QUEUE_ROUTING_INPUTS
    contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="sc_verify_queue",
        work_unit_id="routing",
        exact_inputs=exact_inputs,
        exact_outputs=("verification_queue.md",),
    )

    assert set(contract.immutable_inputs) == {
        f"scratchpad:{path}" for path in exact_inputs
    }


@pytest.mark.parametrize("pipeline,phase_name,manifests", CASES)
def test_verify_queue_routing_contract_is_exact_driver_owned_and_glob_free(
    tmp_path: Path,
    pipeline: str,
    phase_name: str,
    manifests: dict[str, str],
):
    config = _config(tmp_path, pipeline)
    outputs = _exact_outputs(manifests)
    contract = _contract(config, phase_name, outputs)

    assert {spec.path for spec in contract.outputs} == set(outputs)
    assert {spec.writer for spec in contract.outputs} == {"DRIVER"}
    assert {spec.artifact_class for spec in contract.outputs} == {
        "DRIVER_GENERATED"
    }
    assert contract.model_invoked is False
    assert all("*" not in spec.path for spec in contract.outputs)
    assert {
        "verification_queue.md",
        "verification_queue.json",
        "verification_queue.work_items.json",
        "verification_queue.work_plan.json",
    } <= {spec.path for spec in contract.outputs}
    for markdown_path in set(manifests.values()):
        assert set(_projection_triplet(markdown_path)) <= {
            spec.path for spec in contract.outputs
        }


@pytest.mark.parametrize("pipeline,phase_name,manifests", CASES)
def test_live_queue_routing_helper_records_every_projection_with_run_backend_binding(
    tmp_path: Path,
    pipeline: str,
    phase_name: str,
    manifests: dict[str, str],
):
    config = _config(tmp_path, pipeline, backend="claude")
    scratchpad = Path(config["scratchpad"])
    _seed_inputs(scratchpad, config)
    execute, arm_issues = D._arm_typed_verify_queue_routing_artifacts(
        phase_name, scratchpad, config
    )
    assert arm_issues == []
    assert execute is True
    outputs = _seed_outputs(scratchpad, manifests)

    issues = D._record_typed_verify_queue_routing_artifacts(
        phase_name, scratchpad, config
    )

    assert issues == []
    contract = _contract(config, phase_name, outputs)
    ledger = read_artifact_ledger(scratchpad)
    unit = ledger["work_units"][contract.key]
    assert unit["work_unit_key"] == (
        f"{pipeline}/thorough/{config['language']}/claude/{phase_name}/routing"
    )
    assert unit["run_id"] == config["_run_id"]
    assert unit["contract_digest"] == contract.digest
    assert unit["model_invoked"] is False
    assert set(unit["input_bindings"]) == {
        *contract.immutable_inputs
    }
    assert set(unit["artifacts"]) == {
        f"scratchpad:{relative}" for relative in outputs
    }
    for identity, record in unit["artifacts"].items():
        assert record["identity"] == identity
        assert record["owner_key"] == contract.key
        assert record["run_id"] == config["_run_id"]
        assert record["writer"] == "DRIVER"
        assert record["artifact_class"] == "DRIVER_GENERATED"
        assert record["status"] == "ACTIVE"


def test_missing_typed_shard_sidecar_is_in_denominator_and_returns_debt(tmp_path: Path):
    config = _config(tmp_path, "sc")
    scratchpad = Path(config["scratchpad"])
    _seed_inputs(scratchpad, config)
    execute, arm_issues = D._arm_typed_verify_queue_routing_artifacts(
        "sc_verify_queue", scratchpad, config
    )
    assert arm_issues == []
    assert execute is True
    outputs = _seed_outputs(scratchpad, SC_VERIFY_SHARD_MANIFESTS)
    one_shard = sorted(set(SC_VERIFY_SHARD_MANIFESTS.values()))[0]
    missing = Path(one_shard).with_suffix(".work_items.json").as_posix()
    (scratchpad / missing).unlink()

    issues = D._record_typed_verify_queue_routing_artifacts(
        "sc_verify_queue", scratchpad, config
    )

    assert any(
        f"scratchpad:{missing}" in issue and "required output missing" in issue
        for issue in issues
    )
    contract = _contract(config, "sc_verify_queue", outputs)
    unit = read_artifact_ledger(scratchpad)["work_units"][contract.key]
    record = unit["artifacts"][f"scratchpad:{missing}"]
    assert record["writer"] == "DRIVER"
    assert record["artifact_class"] == "DRIVER_GENERATED"
    assert record["status"] == "MISSING"


@pytest.mark.parametrize(
    "pipeline,_case_label,_ensure_label,phase_name",
    (
        (
            "l1",
            "# v2.4.1: SC verify queue",
            "ensure_verify_shard_manifests(",
            "verify_queue",
        ),
        (
            "sc",
            "# v2.4.1→v2.4.3: SC verify aggregate",
            "ensure_sc_verify_shard_manifests(",
            "sc_verify_queue",
        ),
    ),
)
def test_mechanical_queue_branch_records_typed_routing_before_checkpoint_completion(
    tmp_path: Path,
    pipeline: str,
    _case_label: str,
    _ensure_label: str,
    phase_name: str,
):
    # The source markers above are retained only as stable case labels for the
    # legacy SC/L1 names.  Runtime order is proven behaviorally: routing debt
    # must be observed and persisted before the phase-commit authority runs.
    phase = SimpleNamespace(name=phase_name)
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    events: list[str] = []

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(
            D,
            "read_queue_work_plan",
            lambda _root: SimpleNamespace(ordered_work_item_ids=()),
        )
        monkeypatch.setattr(
            D,
            "_record_typed_verify_queue_routing_artifacts",
            lambda *_args, **_kwargs: (
                events.append("routing") or ["routing debt"]
            ),
        )
        monkeypatch.setattr(
            D,
            "_append_phase_io_debt",
            lambda *_args, **_kwargs: events.append("debt"),
        )
        monkeypatch.setattr(
            D,
            "_commit_phase_from_disk_debt",
            lambda *_args, **_kwargs: events.append("commit") or "committed",
        )
        result = D._commit_verification_transaction(
            phase,
            object(),
            scratchpad,
            {
                "pipeline": pipeline,
                "mode": "thorough",
                "language": "rust" if pipeline == "l1" else "evm",
                "cli_backend": "claude",
                "project_root": str(tmp_path),
                "_run_id": f"fixture-{pipeline}",
            },
            [phase],
            clean_transients=True,
        )

    assert result == "committed"
    assert events == ["routing", "debt", "commit"]
