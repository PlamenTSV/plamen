"""Driver-boundary tests for primary verifier BB policy delivery.

The fixtures never launch Claude or Codex.  They exercise the exact public
driver construction, PhaseIO ownership, model-output denominator, driver
receipt, and completed-unit resume gate.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import uuid

import pytest


SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(ROOT))

import bb_verification_policy as BB  # noqa: E402
import plamen_driver as D  # noqa: E402
from artifact_ledger import (  # noqa: E402
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
)
from phase_io_contracts import ArtifactSpec, LaunchSpec, PhaseIOContract  # noqa: E402
from test_bb_verification_policy_ingress import (  # noqa: E402
    _canonical_bytes,
    _rule,
    _write_source,
)
from test_dynamic_verifier_runtime_integration_p0_ak import (  # noqa: E402
    _write_operator_application,
)
from test_verifier_output_receipt_runtime_p0_aj import (  # noqa: E402
    _ignore_poc_gate,
    _proposal_bytes,
    _setup_plan,
    _verify_bytes,
)
from verifier_work_roster import (  # noqa: E402
    build_verifier_runtime_policy,
    build_verifier_work_roster,
)


NORMATIVE_SENTINEL = "PRIVATE_NORMATIVE_SENTINEL_DO_NOT_INLINE"


def _application_for(work: dict) -> dict:
    unsigned = {
        "schema": BB.APPLICATION_SCHEMA,
        "consumer_work_unit_id": work["consumer_work_unit_id"],
        "work_projection_sha256": work["projection_sha256"],
        "work_items": [
            {
                "work_item_id": item["work_item_id"],
                "rule_applications": [
                    {
                        "rule_id": rule["rule_id"],
                        "rule_digest": rule["rule_digest"],
                        "proposed_disposition": "UNRESOLVED",
                        "evidence_refs": [],
                    }
                    for rule in item["applicable_rules"]
                ],
            }
            for item in work["work_items"]
        ],
    }
    return {
        **unsigned,
        "proposal_sha256": hashlib.sha256(
            _canonical_bytes(unsigned)
        ).hexdigest(),
    }


def _bind_shared_context_producer(
    *,
    scratchpad: Path,
    project_root: Path,
    items,
    pipeline: str,
    backend: str,
    language: str,
    run_id: str,
) -> None:
    """Bind the queue-owned shared context without invoking queue phases."""

    inventory = scratchpad / "findings_inventory.md"
    inventory.write_text(
        "# Findings Inventory\n\nFixture-only primary-verifier input.\n",
        encoding="utf-8",
    )
    payload = D.build_verification_context_packets(
        rows=[item.to_dict() for item in items],
        scratchpad=scratchpad,
        project_root=project_root.resolve(),
    )
    queue_phase = "verify_queue" if pipeline == "l1" else "sc_verify_queue"
    owner_key = (
        f"{pipeline}/thorough/{language}/{backend}/{queue_phase}/routing"
    )
    contract = PhaseIOContract(
        pipeline=pipeline,
        mode="thorough",
        ecosystem=language,
        backend=backend,
        phase=queue_phase,
        work_unit_id="routing",
        outputs=(
            ArtifactSpec(
                root="scratchpad",
                path="verification_context_packets.json",
                owner_key=owner_key,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="CREATE",
                schema_version="fixture.verification_context_packets.v1",
                minimum_gate="FIXTURE_EXACT_CONTEXT_PACKET_BINDING",
            ),
        ),
        immutable_inputs=("scratchpad:findings_inventory.md",),
        model_invoked=False,
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=pipeline,
        mode="thorough",
        ecosystem=language,
        backend=backend,
        model="driver",
        timeout_s=60,
        exec_mode="python",
    )
    record_work_unit_inputs(
        scratchpad, project_root, contract, launch, run_id=run_id
    )
    D.write_or_validate_context_packets(
        scratchpad / "verification_context_packets.json", payload
    )
    record_work_unit_artifacts(
        scratchpad,
        project_root,
        contract,
        launch,
        run_id=run_id,
        actor="DRIVER",
    )


def _runtime_fixture(
    tmp_path: Path,
    *,
    pipeline: str,
    backend: str,
    with_bb: bool,
):
    scratchpad, phase_name, items, plan = _setup_plan(
        tmp_path, pipeline, finding_ids=("H-01",)
    )
    language = "rust-l1" if pipeline == "l1" else "evm"
    transport = "pty" if backend == "claude" else "exec"
    runtime = build_verifier_runtime_policy(
        backend=backend,
        model="claude-opus-5" if backend == "claude" else "gpt-5.4",
        transport=transport,
        timeout_seconds=60,
        source_root=str(tmp_path.resolve()),
    )
    roster = build_verifier_work_roster(
        plan,
        pipeline=pipeline,
        ecosystem=language,
        mode="thorough",
        runtime_policy=runtime,
        method_registry_digest="1" * 64,
        context_packet_digest="2" * 64,
    )
    unit = roster.work_units[0]
    phase_table = D.L1_PHASES if pipeline == "l1" else D.SC_PHASES
    phase = next(row for row in phase_table if row.name == phase_name)
    run_id = str(uuid.uuid4())
    config = {
        "pipeline": pipeline,
        "mode": "thorough",
        "language": language,
        "cli_backend": backend,
        "claude_exec_mode": "pty",
        "project_root": str(tmp_path.resolve()),
        "scratchpad": str(scratchpad),
        "_run_id": run_id,
    }
    if with_bb:
        rule = _rule(1, text=NORMATIVE_SENTINEL)
        operator = __import__(
            "test_bb_verification_policy_ingress"
        )._operator_projection([rule])
        bb_config, _source = _write_source(
            tmp_path / "bb-authority",
            operator,
            family=(
                "blockchain_dlt"
                if pipeline == "l1"
                else "smart_contract"
            ),
        )
        config.update(bb_config)
        D._bind_bb_verification_policy_ingress(scratchpad, config)
    _bind_shared_context_producer(
        scratchpad=scratchpad,
        project_root=tmp_path,
        items=items,
        pipeline=pipeline,
        backend=backend,
        language=language,
        run_id=run_id,
    )
    return scratchpad, phase, items, roster, unit, config


def _rewrite_context_as_live_t7(
    path: Path,
    *,
    project_root: str = "project::",
    scratchpad_root: str = "scratchpad::",
    mutate_packet_count: bool = False,
) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["project_root"] = project_root
    payload["scratchpad"] = scratchpad_root
    if mutate_packet_count:
        payload["packet_count"] = int(payload["packet_count"]) + 1
    unsigned = {
        key: value for key, value in payload.items()
        if key != "context_digest"
    }
    payload["context_digest"] = D.verification_method_stable_digest(unsigned)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return payload


def test_dynamic_dispatch_accepts_exact_live_t7_symbolic_context_roots(
    tmp_path: Path,
) -> None:
    scratchpad, _phase, _items, _roster, unit, config = _runtime_fixture(
        tmp_path, pipeline="sc", backend="codex", with_bb=False
    )
    paths = D._dynamic_verifier_unit_paths(scratchpad, unit.work_unit_id)
    D._materialize_dynamic_verifier_manifest(
        scratchpad, unit, paths["manifest"]
    )
    expected = _rewrite_context_as_live_t7(
        scratchpad / "verification_context_packets.json"
    )

    dispatch = D._compile_dynamic_verifier_method_dispatch(
        scratchpad,
        config,
        unit,
        manifest_path=paths["manifest"],
    )

    assert dispatch["rows"]
    assert json.loads(
        (scratchpad / "verification_context_packets.json").read_text(
            encoding="utf-8"
        )
    ) == expected


@pytest.mark.parametrize(
    ("project_root", "scratchpad_root", "mutate_packet_count"),
    [
        ("project::src", "scratchpad::", False),
        ("project::", "scratchpad::nested", False),
        ("project::", "scratchpad::", True),
    ],
)
def test_dynamic_dispatch_rejects_noncanonical_or_content_drifted_t7_context(
    tmp_path: Path,
    project_root: str,
    scratchpad_root: str,
    mutate_packet_count: bool,
) -> None:
    scratchpad, _phase, _items, _roster, unit, config = _runtime_fixture(
        tmp_path, pipeline="sc", backend="codex", with_bb=False
    )
    paths = D._dynamic_verifier_unit_paths(scratchpad, unit.work_unit_id)
    D._materialize_dynamic_verifier_manifest(
        scratchpad, unit, paths["manifest"]
    )
    _rewrite_context_as_live_t7(
        scratchpad / "verification_context_packets.json",
        project_root=project_root,
        scratchpad_root=scratchpad_root,
        mutate_packet_count=mutate_packet_count,
    )

    with pytest.raises(
        D.VerificationMethodError,
        match="existing context packets differ from current graph/rows",
    ):
        D._compile_dynamic_verifier_method_dispatch(
            scratchpad,
            config,
            unit,
            manifest_path=paths["manifest"],
        )


def test_non_bb_primary_policy_hook_is_exact_noop(tmp_path: Path) -> None:
    scratchpad, _phase, _items, _roster, unit, config = _runtime_fixture(
        tmp_path, pipeline="sc", backend="claude", with_bb=False
    )
    before = {
        path.relative_to(scratchpad).as_posix(): path.read_bytes()
        for path in scratchpad.rglob("*")
        if path.is_file()
    }
    assert D._expected_dynamic_verifier_bb_policy(
        scratchpad, config, unit
    ) is None
    assert D._prepare_dynamic_verifier_bb_policy(
        scratchpad, config, unit
    ) is None
    after = {
        path.relative_to(scratchpad).as_posix(): path.read_bytes()
        for path in scratchpad.rglob("*")
        if path.is_file()
    }
    assert after == before
    paths = D._dynamic_verifier_unit_paths(scratchpad, unit.work_unit_id)
    assert not paths["bb_policy_work"].exists()
    assert not paths["bb_policy_application"].exists()
    assert not paths["bb_policy_receipt"].exists()


@pytest.mark.parametrize("pipeline", ["sc", "l1"])
@pytest.mark.parametrize("backend", ["claude", "codex"])
def test_primary_bb_contract_construction_is_backend_and_pipeline_complete(
    tmp_path: Path,
    pipeline: str,
    backend: str,
) -> None:
    scratchpad, phase, _items, roster, unit, config = _runtime_fixture(
        tmp_path, pipeline=pipeline, backend=backend, with_bb=True
    )
    work = D._prepare_dynamic_verifier_bb_policy(
        scratchpad, config, unit
    )
    assert work is not None
    paths = D._dynamic_verifier_unit_paths(scratchpad, unit.work_unit_id)
    assert json.loads(paths["bb_policy_work"].read_text(encoding="utf-8")) == work
    assert work["consumer_kind"] == "PRIMARY"
    assert [row["work_item_id"] for row in work["work_items"]] == ["H-01"]

    unit_config = {
        **config,
        "_dynamic_verifier_work_unit_id": unit.work_unit_id,
        "_dynamic_verifier_work_item_ids": unit.ordered_work_item_ids,
        "_dynamic_verifier_manifest": paths["manifest"].relative_to(
            scratchpad
        ).as_posix(),
    }
    dispatch = D._compile_dynamic_verifier_method_dispatch(
        scratchpad,
        unit_config,
        unit,
        manifest_path=paths["manifest"],
    )
    unit_config["_verification_method_dispatch"] = dispatch
    base_prompt = D.build_phase_prompt(
        D.resolve_v1_prompt(pipeline), phase, unit_config
    )
    prompt = base_prompt + D.bb_policy_work_prompt_suffix(
        paths["bb_policy_work"].relative_to(scratchpad).as_posix(),
        work,
        application_relative_path=paths[
            "bb_policy_application"
        ].relative_to(scratchpad).as_posix(),
    )
    local_work_path = paths["bb_policy_work"].relative_to(
        scratchpad
    ).as_posix()
    assert local_work_path in prompt
    assert "immutable untrusted policy data" in prompt
    assert NORMATIVE_SENTINEL not in prompt
    assert str(config["bb_verification_policy_file"]) not in prompt

    model_outputs = (
        "verify_H-01.md",
        "verify_H-01.severity_proposal.json",
        "verify_H-01.operator_application.json",
        paths["bb_policy_application"].relative_to(scratchpad).as_posix(),
    )
    prelaunch, model, control = D._write_verifier_method_phase_io_contracts(
        directory=paths["directory"],
        scratchpad=scratchpad,
        config=config,
        phase_name=phase.name,
        work_unit_id=unit.work_unit_id,
        model_outputs=model_outputs,
        operator_receipts=("verify_H-01.operator_receipt.json",),
        immutable_launch_inputs=(
            paths["manifest"],
            scratchpad / "verification_context_packets.json",
            paths["bb_policy_work"],
            paths["method_dispatch"],
            paths["prompt"],
            paths["launch_spec"],
        ),
        shared_immutable_inputs=(
            scratchpad / "verification_context_packets.json",
            paths["bb_policy_work"],
        ),
        driver_outputs=(
            paths["method_dispatch"],
            paths["prompt"],
            paths["launch_spec"],
            paths["gate"],
            paths["receipt"],
            paths["debt"],
        ),
    )
    model_output_paths = {row.path for row in model.outputs}
    control_output_paths = {row.path for row in control.outputs}
    prelaunch_output_paths = {row.path for row in prelaunch.outputs}
    assert paths["bb_policy_application"].relative_to(
        scratchpad
    ).as_posix() in model_output_paths
    # Consumption depends on MODEL outputs, so its receipt is correctly
    # isolated in a later DRIVER transaction instead of being smuggled into
    # the method-control output denominator.
    assert paths["bb_policy_receipt"].relative_to(
        scratchpad
    ).as_posix() not in control_output_paths
    consumption, _launch = D._p1dm_contract_and_launch(
        scratchpad,
        config,
        phase_name="bb_policy",
        work_unit_id=f"consumption.{unit.work_unit_id}",
        exact_inputs=(
            paths["bb_policy_work"].relative_to(scratchpad).as_posix(),
            paths["bb_policy_application"].relative_to(
                scratchpad
            ).as_posix(),
            paths["method_dispatch"].relative_to(scratchpad).as_posix(),
            paths["launch_spec"].relative_to(scratchpad).as_posix(),
            "verify_H-01.md",
        ),
        exact_outputs=(
            paths["bb_policy_receipt"].relative_to(
                scratchpad
            ).as_posix(),
        ),
        actor="DRIVER",
    )
    assert {
        row.path for row in consumption.outputs
    } == {
        paths["bb_policy_receipt"].relative_to(scratchpad).as_posix()
    }
    assert all(row.writer == "DRIVER" for row in consumption.outputs)
    assert paths["bb_policy_work"].relative_to(
        scratchpad
    ).as_posix() not in prelaunch_output_paths
    assert roster.runtime_policy.backend == backend


def test_primary_bb_run_binds_model_application_driver_receipt_and_resume_gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad, phase, items, roster, unit, config = _runtime_fixture(
        tmp_path, pipeline="sc", backend="claude", with_bb=True
    )
    paths = D._dynamic_verifier_unit_paths(scratchpad, unit.work_unit_id)
    captured: dict[str, object] = {}
    by_id = {item.work_item_id: item for item in items}

    def fake_execute(spec, **kwargs):
        prompt = Path(kwargs["prompt_path"]).read_text(encoding="utf-8")
        captured["prompt"] = prompt
        captured["model_contract"] = kwargs["model_io_contract"]
        assert NORMATIVE_SENTINEL not in prompt
        assert (
            paths["bb_policy_work"].relative_to(scratchpad).as_posix()
            in prompt
        )
        for work_id in unit.ordered_work_item_ids:
            (scratchpad / f"verify_{work_id}.md").write_bytes(
                _verify_bytes(work_id)
            )
            (
                scratchpad
                / f"verify_{work_id}.severity_proposal.json"
            ).write_bytes(_proposal_bytes(by_id[work_id]))
            _write_operator_application(
                scratchpad, unit.work_unit_id, work_id
            )
        work = json.loads(
            paths["bb_policy_work"].read_text(encoding="utf-8")
        )
        paths["bb_policy_application"].write_bytes(
            _canonical_bytes(_application_for(work)) + b"\n"
        )
        return 0

    monkeypatch.setattr(D, "_execute_dynamic_verifier_launch", fake_execute)
    _ignore_poc_gate(monkeypatch)
    assert D._run_dynamic_verifier_unit(
        phase, scratchpad, config, roster, unit
    ) == []

    application = json.loads(
        paths["bb_policy_application"].read_text(encoding="utf-8")
    )
    work = json.loads(paths["bb_policy_work"].read_text(encoding="utf-8"))
    assert application["consumer_work_unit_id"] == unit.work_unit_id
    assert application["work_projection_sha256"] == work["projection_sha256"]
    receipt = BB.validate_consumption_receipt(
        json.loads(paths["bb_policy_receipt"].read_text(encoding="utf-8"))
    )
    assert receipt["consumer_identity"] == {
        "consumer_work_unit_id": unit.work_unit_id,
        "consumer_kind": "PRIMARY",
    }
    assert receipt["non_verification_consumers"] == []

    model_contract = captured["model_contract"]
    assert paths["bb_policy_application"].relative_to(
        scratchpad
    ).as_posix() in {row.path for row in model_contract.outputs}
    control_contract = json.loads(
        (
            paths["directory"] / "phase_io_control_contract.json"
        ).read_text(encoding="utf-8")
    )
    assert paths["bb_policy_receipt"].relative_to(
        scratchpad
    ).as_posix() not in {
        row["identity"].removeprefix("scratchpad:")
        for row in control_contract["outputs"]
    }

    ledger = read_artifact_ledger(scratchpad)
    work_identity = (
        "scratchpad:"
        + paths["bb_policy_work"].relative_to(scratchpad).as_posix()
    )
    producer = ledger["artifact_bindings"][work_identity]
    assert producer["owner_key"].endswith(
        f"/bb_policy/projection.{unit.work_unit_id}"
    )
    prelaunch_key = next(
        key for key in ledger["work_units"]
        if key.endswith(f"/method_context.{unit.work_unit_id}")
    )
    model_key = next(
        key for key in ledger["work_units"]
        if key.endswith(f"/method_model.{unit.work_unit_id}")
    )
    assert work_identity not in ledger["work_units"][prelaunch_key]["artifacts"]
    assert (
        ledger["work_units"][model_key]["input_bindings"][work_identity][
            "producer_work_unit_key"
        ]
        == producer["owner_key"]
    )
    receipt_identity = (
        "scratchpad:"
        + paths["bb_policy_receipt"].relative_to(scratchpad).as_posix()
    )
    receipt_producer = ledger["artifact_bindings"][receipt_identity]
    assert receipt_producer["writer"] == "DRIVER"
    assert receipt_producer["owner_key"].endswith(
        f"/bb_policy/consumption.{unit.work_unit_id}"
    )
    assert D._dynamic_verifier_unit_gate_issues(
        scratchpad, phase.name, roster, unit, config
    ) == []

    baseline = {
        key: path.read_bytes()
        for key, path in paths.items()
        if key in {
            "bb_policy_work",
            "bb_policy_application",
            "bb_policy_receipt",
            "gate",
        }
    }
    # Isolate each semantic resume check from the generic ledger byte check.
    monkeypatch.setattr(
        D,
        "_record_verifier_method_phase_io_authority",
        lambda **_kwargs: [],
    )
    monkeypatch.setattr(
        D,
        "_bb_policy_consumption_phaseio_issues",
        lambda **_kwargs: [],
    )

    def rejected_after(key: str, mutate) -> str:
        for name, raw in baseline.items():
            paths[name].write_bytes(raw)
        mutate(paths[key])
        issues = D._dynamic_verifier_unit_gate_issues(
            scratchpad, phase.name, roster, unit, config
        )
        assert issues
        return " ".join(issues)

    assert "projection is absent" in rejected_after(
        "bb_policy_work", lambda path: path.unlink()
    )

    def stale_work(path: Path) -> None:
        stale = BB.build_work_projection(
            D._load_bound_bb_policy_ingress(
                scratchpad,
                D.build_bb_policy_ingress_payload(
                    config, driver_run_id=config["_run_id"]
                ),
            ),
            consumer_work_unit_id=unit.work_unit_id,
            consumer_kind="PRIMARY",
            work_items=[
                {
                    "work_item_id": "H-01",
                    "severity": "low",
                    "impact_ids": [],
                }
            ],
        )
        path.write_bytes(_canonical_bytes(stale) + b"\n")

    assert "projection is stale" in rejected_after(
        "bb_policy_work", stale_work
    )
    rejected_after("bb_policy_application", lambda path: path.unlink())

    def stale_application(path: Path) -> None:
        proposal = json.loads(path.read_text(encoding="utf-8"))
        proposal["work_items"][0]["rule_applications"][0][
            "proposed_disposition"
        ] = "SATISFIED"
        unsigned = {
            key: value
            for key, value in proposal.items()
            if key != "proposal_sha256"
        }
        proposal["proposal_sha256"] = hashlib.sha256(
            _canonical_bytes(unsigned)
        ).hexdigest()
        path.write_bytes(_canonical_bytes(proposal) + b"\n")

    rejected_after("bb_policy_application", stale_application)
    rejected_after("bb_policy_receipt", lambda path: path.unlink())
    rejected_after(
        "bb_policy_receipt",
        lambda path: path.write_bytes(path.read_bytes() + b" "),
    )
    assert "gate receipt bytes changed" in rejected_after(
        "gate", lambda path: path.write_bytes(path.read_bytes() + b" ")
    )
