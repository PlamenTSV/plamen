"""RED contracts for the preverify-successor/T0 publication boundary.

These tests deliberately distinguish two layers:

* the mature successor resolver, which already proves one exact frozen capture;
* the live T0-T9 boundary, which must not treat successor-finalization debt as
  advisory and then publish against an older or malformed ACTIVE projection.

No production behavior is mocked after T0.  The live adapter, semantic executor,
and T9 publication remain real.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import sys
from typing import Any

import pytest


SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(ROOT))

from artifact_ledger import (  # noqa: E402
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
)
from finding_producer_registry import (  # noqa: E402
    parse_application_skeptic_proposal_projection,
)
from preverify_projection_authority import (  # noqa: E402
    resolve_current_preverify_projection,
)
import plamen_driver as DRIVER  # noqa: E402
from phase_io_contracts import (  # noqa: E402
    ArtifactSpec,
    DriverMergeEvent,
    LaunchSpec,
    PhaseIOContract,
    canonical_work_unit_key,
)
import test_live_verify_queue_driver_adapter_cutover as ADAPTER_FIXTURE  # noqa: E402
import test_live_verify_queue_main_boundary_a0 as MAIN  # noqa: E402
import test_preverify_capture_pair_contract as CAPTURE_FIXTURE  # noqa: E402
import test_preverify_inventory_successor_p0_al as SUCCESSOR_FIXTURE  # noqa: E402


ROUTING_KEY = "sc/thorough/evm/claude/sc_verify_queue/routing"
STABLE_PAIR = (
    "preverify_inventory_successor.json",
    "finding_delivery_successor.json",
)


def _old_frozen_projection(
    *,
    root: Path,
    project: Path,
    config: dict[str, Any],
    run_id: str,
) -> dict[str, Any]:
    pipeline = str(config["pipeline"])
    phase_name = "sc_verify_queue" if pipeline == "sc" else "verify_queue"
    chain_pair = None
    if pipeline == "sc":
        chain_pair = DRIVER.prepare_preverify_chain_pair_projection(
            scratchpad=root,
            project_root=project,
            pipeline=pipeline,
            mode=str(config["mode"]),
            ecosystem=str(config["ecosystem"]),
            backend=str(config["backend"]),
            phase_name=phase_name,
            run_id=run_id,
        )
    return DRIVER.prepare_preverify_frozen_projection(
        scratchpad=root,
        project_root=project,
        pipeline=pipeline,
        mode=str(config["mode"]),
        ecosystem=str(config["ecosystem"]),
        backend=str(config["backend"]),
        phase_name=phase_name,
        run_id=run_id,
        chain_pair_projection=chain_pair,
    )


def _replace_inventory_with_authorized_generation(
    *,
    root: Path,
    project: Path,
    run_id: str,
) -> None:
    # The live recall-floor boundary deliberately rejects a semantic virtual
    # producer because it lacks the full owner/writer/run/contract/launch
    # tuple.  Publish this changed generation through a real PhaseIO
    # transaction so the fixture exercises the intended downstream failure,
    # not an earlier strict-prebind rejection.
    owner = canonical_work_unit_key(
        "l1",
        "thorough",
        "rust",
        "claude",
        "preverify_adapter_fixture",
        "changed_generation_upstream",
    )
    contract = PhaseIOContract(
        pipeline="l1",
        mode="thorough",
        ecosystem="rust",
        backend="claude",
        phase="preverify_adapter_fixture",
        work_unit_id="changed_generation_upstream",
        outputs=(
            ArtifactSpec(
                root="scratchpad",
                path="findings_inventory.md",
                owner_key=owner,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="MERGE",
                schema_version="fixture.changed_generation.v1",
                minimum_gate="FIXTURE_EXACT_BYTES",
                consumers=("verify_queue/t0.live_upstream_authority",),
            ),
        ),
        immutable_inputs=("scratchpad:config.json",),
        bounded_lookup_inputs=(),
        model_invoked=False,
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline="l1",
        mode="thorough",
        ecosystem="rust",
        backend="claude",
        model="fixture-driver",
        timeout_s=60,
        exec_mode="python",
        tool_policy=("filesystem",),
    )
    record_work_unit_inputs(
        root,
        project,
        contract,
        launch,
        run_id=run_id,
    )
    inventory_path = root / "findings_inventory.md"
    before_raw = inventory_path.read_bytes()
    after_raw = (
        before_raw
        + b"\n"
        + SUCCESSOR_FIXTURE._inventory(
            "changed frozen generation"
        ).encode("utf-8")
    )
    inventory_path.write_bytes(after_raw)
    event = DriverMergeEvent(
        work_unit_key=contract.key,
        contract_digest=contract.digest,
        artifact_identity="scratchpad:findings_inventory.md",
        before_sha256=hashlib.sha256(before_raw).hexdigest(),
        after_sha256=hashlib.sha256(after_raw).hexdigest(),
        source_identities=("scratchpad:config.json",),
        identities_before=(),
        identities_after=("INV-001",),
    )
    record_work_unit_artifacts(
        root,
        project,
        contract,
        launch,
        run_id=run_id,
        actor="DRIVER",
        merge_events={event.artifact_identity: event},
    )


def _invoke_live_boundary(
    *,
    project: Path,
    root: Path,
    config: dict[str, Any],
    run_id: str,
    failpoint,
) -> dict[str, Any]:
    pipeline = str(config["pipeline"])
    phase, phases = MAIN._phase_and_graph(pipeline)
    checkpoint = MAIN._checkpoint(root, config, run_id)
    return dict(
        MAIN._invoke(
            boundary=MAIN._boundary(),
            phase=phase,
            checkpoint=checkpoint,
            root=root,
            config=config,
            phases=phases,
            failpoint=failpoint,
        )
    )


def test_changed_frozen_generation_and_finalize_failure_never_arm_t0(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An older ACTIVE successor cannot outlive a failed new capture."""

    project = tmp_path / "changed-generation"
    project.mkdir()
    root, config, run_id = MAIN._seed(project, pipeline="l1")
    old_frozen = _old_frozen_projection(
        root=root,
        project=project,
        config=config,
        run_id=run_id,
    )
    ledger = read_artifact_ledger(root)
    upstream_owner = (
        "l1/thorough/rust/claude/"
        "preverify_adapter_fixture/current_run_upstream"
    )
    old_owner = ledger["work_units"][upstream_owner]
    assert all(
        old_owner["artifacts"][f"scratchpad:{relative}"]["status"]
        == "ACTIVE"
        for relative in STABLE_PAIR
    )

    _replace_inventory_with_authorized_generation(
        root=root,
        project=project,
        run_id=run_id,
    )
    MAIN._patch_prequeue_producers(monkeypatch, [], pipeline="l1")
    observed_frozen: list[dict[str, Any]] = []
    real_prepare = DRIVER.prepare_preverify_frozen_projection

    def observe_prepare(*args: Any, **kwargs: Any) -> dict[str, Any]:
        projection = real_prepare(*args, **kwargs)
        observed_frozen.append(projection)
        return projection

    monkeypatch.setattr(
        DRIVER,
        "prepare_preverify_frozen_projection",
        observe_prepare,
    )
    monkeypatch.setattr(
        DRIVER,
        "_finalize_preverify_inventory_successors",
        lambda *_args, **_kwargs: [
            "fixture forced new successor capture failure"
        ],
    )
    labels: list[str] = []
    before_public = MAIN._public_bytes(root, "l1")

    outcome = _invoke_live_boundary(
        project=project,
        root=root,
        config=config,
        run_id=run_id,
        failpoint=labels.append,
    )

    assert len(observed_frozen) == 1
    assert (
        observed_frozen[0]["generation_digest"]
        != old_frozen["generation_digest"]
    )
    assert outcome["state"] == "INCOMPLETE_WITH_DEBT"
    assert outcome["safe_to_continue"] is False
    debt = (root / "verify_queue.degraded").read_text(
        encoding="utf-8",
        errors="replace",
    )
    assert "fixture forced new successor capture failure" in debt
    assert ADAPTER_FIXTURE.PLAN_FAILPOINT not in labels
    assert "after_t0_arm" not in labels
    assert "after_t9_commit" not in labels
    assert MAIN._public_bytes(root, "l1") == before_public


@pytest.mark.parametrize(
    "pair_state",
    ("malformed-active", "partial", "stale"),
)
def test_no_proposal_rows_do_not_exempt_invalid_successor_pair_from_t0(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pair_state: str,
) -> None:
    """Malformed, partial, and stale pairs reject even for an empty queue."""

    project = tmp_path / pair_state
    project.mkdir()
    root, config, run_id = MAIN._seed(project, pipeline="l1")
    assert parse_application_skeptic_proposal_projection(
        root / "application_skeptic_proposals.md"
    ) == []
    assert parse_application_skeptic_proposal_projection(
        root / "candidate_negative_skeptic_proposals.md"
    ) == []
    real_finalizer = DRIVER._finalize_preverify_inventory_successors
    MAIN._patch_prequeue_producers(monkeypatch, [], pipeline="l1")
    monkeypatch.setattr(
        DRIVER,
        "_finalize_preverify_inventory_successors",
        real_finalizer,
    )

    if pair_state == "partial":
        (root / "finding_delivery_successor.json").unlink()
    elif pair_state == "stale":
        (root / "preverify_inventory_successor.json").write_text(
            json.dumps(
                {
                    "schema_version":
                        "plamen.preverify_inventory_successor.v1",
                    "run_id": "foreign-stale-run",
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

    labels: list[str] = []
    outcome = _invoke_live_boundary(
        project=project,
        root=root,
        config=config,
        run_id=run_id,
        failpoint=labels.append,
    )

    assert outcome["state"] == "INCOMPLETE_WITH_DEBT"
    assert outcome["safe_to_continue"] is False
    assert ADAPTER_FIXTURE.PLAN_FAILPOINT not in labels
    assert "after_t0_arm" not in labels
    assert "after_t9_commit" not in labels
    assert not MAIN._public_bytes(root, "l1")


def test_exact_current_pair_and_capture_resume_idempotently(
    tmp_path: Path,
) -> None:
    root, config, run_id, frozen, before_ledger, _bindings = (
        CAPTURE_FIXTURE._live_authority_fixture(tmp_path)
    )
    before_pair = {
        relative: (root / relative).read_bytes()
        for relative in STABLE_PAIR
    }
    before_generations = sorted(
        (root / "_preverify_successors").glob("generation_*.json")
    )
    first = resolve_current_preverify_projection(
        root,
        expected_run_id=run_id,
        expected_consumer_work_unit_key=ROUTING_KEY,
    )

    assert DRIVER._finalize_preverify_inventory_successors(
        root,
        config,
        phase_name="sc_verify_queue",
        frozen_projection=frozen,
    ) == []
    execute, issues = DRIVER._arm_typed_verify_queue_routing_artifacts(
        "sc_verify_queue",
        root,
        config,
    )
    assert execute is True
    assert issues == []

    second = resolve_current_preverify_projection(
        root,
        expected_run_id=run_id,
        expected_consumer_work_unit_key=ROUTING_KEY,
    )
    assert {
        relative: (root / relative).read_bytes()
        for relative in STABLE_PAIR
    } == before_pair
    assert sorted(
        (root / "_preverify_successors").glob("generation_*.json")
    ) == before_generations
    assert second["generation_digest"] == first["generation_digest"]
    assert (
        second["frozen_generation_digest"]
        == first["frozen_generation_digest"]
    )
    after_ledger = read_artifact_ledger(root)
    assert set(after_ledger["work_units"]) == set(
        before_ledger["work_units"]
    )


def test_stable_pair_routing_and_capture_share_one_frozen_generation(
    tmp_path: Path,
) -> None:
    root, _config, run_id, frozen, ledger, _bindings = (
        CAPTURE_FIXTURE._live_authority_fixture(tmp_path)
    )
    resolved = resolve_current_preverify_projection(
        root,
        expected_run_id=run_id,
        expected_consumer_work_unit_key=ROUTING_KEY,
    )
    routing = ledger["work_units"][ROUTING_KEY]
    stable_payloads = {
        relative: json.loads((root / relative).read_text(encoding="utf-8"))
        for relative in STABLE_PAIR
    }

    stable_owners = {
        routing["input_bindings"][f"scratchpad:{relative}"][
            "producer_work_unit_key"
        ]
        for relative in STABLE_PAIR
    }
    assert stable_owners == {resolved["owner_key"]}
    assert (
        resolved["frozen_generation_digest"]
        == frozen["generation_digest"]
    )
    frozen_root = (
        f"_preverify_frozen/generation_"
        f"{resolved['frozen_generation_digest']}"
    )
    assert (
        PurePosixPath(resolved["inventory_source_artifact"]).parent.as_posix()
        == frozen_root
    )
    assert (
        PurePosixPath(resolved["records_source_artifact"]).parent.as_posix()
        == frozen_root
    )
    assert resolved["capture_owner_key"].endswith(
        f"/preverify_capture.{resolved['generation_digest']}"
    )
    generation = resolved["generation_payload"]
    assert generation["final_payload"] == stable_payloads[STABLE_PAIR[0]]
    assert generation["delivery_payload"] == stable_payloads[STABLE_PAIR[1]]
    assert {
        resolved["inventory_source_artifact"],
        resolved["records_source_artifact"],
        resolved["frozen_receipt_artifact"],
    }.issubset(set(generation["capture_plan"]["exact_inputs"]))
