"""Red-first authority contract for live T0 and SC dynamic inputs.

This fixture is deliberately generic.  It does not name an audited protocol,
enumerate the live filesystem, or grant status JSON any authority.  It proves
two missing preconditions:

* T0's declared producer-binding policy must reject raw bytes without an exact
  current-run artifact-ledger producer.
* SC candidate-selected fact inputs must be resolved before T0 arm through a
  content-addressed manifest.  The manifest retains the full referenced
  identity denominator; T0 binds the manifest, the canonical identity
  denominator, and every selected source as exact producer-owned inputs.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

import pytest

from artifact_ledger import (
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
    write_artifact_ledger,
)
from phase_io_contracts import (
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    canonical_work_unit_key,
)
from verify_queue_phaseio_authority import arm_transaction_unit
import verify_queue_transaction as TRANSACTION
import test_live_verify_queue_transaction_semantic_closure as LIVE


RUN_ID = "t0-authority-current-run"
SOURCE = "generic_upstream_authority.json"
STATUS = "_live_verify_queue_transaction/t0/status.json"
MANIFEST_PATH = "prearm_content_addressed_inputs.json"
IDENTITY_PATH = "_canonical_finding_ids.json"
CANDIDATE_PATH = "arm_before_trust_compound_candidates.json"
DYNAMIC_SOURCES = (
    "fact_authority/source-a.json",
    "fact_authority/source-b.json",
)


def _canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _digest_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _stable_digest(value: Any, *, omit: str = "") -> str:
    payload = (
        {key: item for key, item in value.items() if key != omit}
        if isinstance(value, Mapping) and omit
        else value
    )
    return _digest_bytes(_canonical_bytes(payload))


def _t0_plan_and_unit() -> tuple[dict[str, Any], dict[str, Any]]:
    plan = {
        "pipeline": "sc",
        "mode": "thorough",
        "ecosystem": "evm",
        "backend": "claude",
        "phase_name": "sc_verify_queue",
        "run_id": RUN_ID,
    }
    owner = canonical_work_unit_key(
        "sc",
        "thorough",
        "evm",
        "claude",
        "sc_verify_queue",
        "t0.live_upstream_authority",
    )
    unit = {
        "work_unit_id": "t0.live_upstream_authority",
        "exact_inputs": [SOURCE],
        "declared_input_denominator": [SOURCE],
        "required_inputs": [SOURCE],
        "presence_roster": [],
        "outputs": [{
            "path": STATUS,
            "root": "scratchpad",
            "artifact_class": "DRIVER_GENERATED",
            "writer": "DRIVER",
            "write_mode": "CREATE",
            "owner_key": owner,
        }],
        "producer_binding_policy": {
            "owner": True,
            "writer": True,
            "run_id": True,
            "contract_digest": True,
            "launch_digest": True,
            "sha256": True,
            "size": True,
            "explicit_absence": True,
        },
    }
    return plan, unit


def _producer(
    root: Path,
    project: Path,
    *,
    run_id: str,
    raw: bytes = b'{"producer":"exact"}\n',
) -> tuple[PhaseIOContract, LaunchSpec]:
    owner = canonical_work_unit_key(
        "sc", "thorough", "evm", "claude", "inventory", "generic_source"
    )
    contract = PhaseIOContract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="inventory",
        work_unit_id="generic_source",
        outputs=(ArtifactSpec(
            root="scratchpad",
            path=SOURCE,
            owner_key=owner,
            artifact_class="DRIVER_GENERATED",
            writer="DRIVER",
            write_mode="CREATE",
            schema_version="fixture.generic-source.v1",
            minimum_gate="STRUCTURAL",
            consumers=("sc_verify_queue/t0.live_upstream_authority",),
        ),),
        immutable_inputs=(),
        bounded_lookup_inputs=(),
        model_invoked=False,
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="driver",
        timeout_s=60,
        exec_mode="python",
        tool_policy=("filesystem",),
    )
    record_work_unit_inputs(root, project, contract, launch, run_id=run_id)
    (root / SOURCE).write_bytes(raw)
    record_work_unit_artifacts(
        root,
        project,
        contract,
        launch,
        run_id=run_id,
        actor="DRIVER",
    )
    return contract, launch


def _arm(root: Path, project: Path) -> tuple[bool, list[str]]:
    plan, unit = _t0_plan_and_unit()
    execute, issues, _contract, _launch = arm_transaction_unit(
        scratchpad=root,
        project_root=project,
        plan=plan,
        unit=unit,
        run_id=RUN_ID,
    )
    return execute, issues


def test_t0_rejects_raw_required_bytes_without_current_run_producer(
    tmp_path: Path,
) -> None:
    root = tmp_path / ".scratchpad"
    root.mkdir()
    (root / SOURCE).write_bytes(b'{"raw":"not-authority"}\n')

    execute, issues = _arm(root, tmp_path)

    assert execute is False
    assert issues
    assert any(
        "producer" in issue.lower() or "ancestry" in issue.lower()
        for issue in issues
    )


def test_t0_accepts_exact_current_run_owner_writer_and_digest_bindings(
    tmp_path: Path,
) -> None:
    root = tmp_path / ".scratchpad"
    root.mkdir()
    producer_contract, producer_launch = _producer(
        root, tmp_path, run_id=RUN_ID
    )

    execute, issues = _arm(root, tmp_path)

    assert execute is True
    assert issues == []
    ledger = read_artifact_ledger(root)
    binding = ledger["artifact_bindings"]["scratchpad:" + SOURCE]
    assert binding["owner_key"] == producer_contract.key
    assert binding["writer"] == "DRIVER"
    assert binding["run_id"] == RUN_ID
    assert binding["contract_digest"] == producer_contract.digest
    assert binding["launch_digest"] == producer_launch.digest
    assert binding["sha256"] == _digest_bytes((root / SOURCE).read_bytes())
    assert binding["size"] == (root / SOURCE).stat().st_size


@pytest.mark.parametrize(
    "ancestry",
    ("cross-run", "forged-binding", "status-only"),
)
def test_t0_rejects_foreign_forged_or_status_only_ancestry(
    tmp_path: Path,
    ancestry: str,
) -> None:
    root = tmp_path / ".scratchpad"
    root.mkdir()
    if ancestry == "cross-run":
        _producer(root, tmp_path, run_id="foreign-run")
    elif ancestry == "forged-binding":
        _producer(root, tmp_path, run_id=RUN_ID)
        ledger = read_artifact_ledger(root)
        binding = ledger["artifact_bindings"]["scratchpad:" + SOURCE]
        binding["owner_key"] = (
            "sc/thorough/evm/claude/inventory/forged-owner"
        )
        write_artifact_ledger(root, ledger)
    else:
        (root / SOURCE).write_bytes(b'{"raw":"status-cannot-certify"}\n')
        (root / "generic_upstream_authority.status.json").write_bytes(
            _canonical_bytes({
                "state": "OUTPUT_COMMITTED",
                "safe_to_consume": True,
                "run_id": RUN_ID,
                "sha256": _digest_bytes((root / SOURCE).read_bytes()),
            })
        )

    execute, issues = _arm(root, tmp_path)

    assert execute is False
    assert issues


def _manifest(*, omit: str = "") -> dict[str, Any]:
    reference_identities = list(DYNAMIC_SOURCES)
    entries = [
        {
            "identity": "scratchpad:" + path,
            "sha256": _digest_bytes(
                _canonical_bytes({"generic_fact_source": path})
            ),
            "size": len(_canonical_bytes({"generic_fact_source": path})),
        }
        for path in DYNAMIC_SOURCES
        if path != omit
    ]
    unsigned = {
        "schema_version": (
            "plamen.prearm_content_addressed_input_manifest.v1"
        ),
        "pipeline": "sc",
        "run_id": "live-sc-claude",
        "manifest_identity": "scratchpad:" + MANIFEST_PATH,
        "selection_authority": {
            "identity": "scratchpad:" + CANDIDATE_PATH,
            "sha256": "1" * 64,
            "size": 1,
        },
        "identity_denominator": {
            "identity": "scratchpad:" + IDENTITY_PATH,
            "sha256": "2" * 64,
            "size": 1,
        },
        "referenced_source_identities": [
            "scratchpad:" + path for path in reference_identities
        ],
        "referenced_source_identity_digest": _stable_digest(
            ["scratchpad:" + path for path in reference_identities]
        ),
        "entries": entries,
        "entry_count": len(entries),
        "entry_identity_digest": _stable_digest([
            str(row["identity"]) for row in entries
        ]),
        "content_addressed": True,
        "live_glob_allowed": False,
        "live_read_after_arm_allowed": False,
    }
    return {
        **unsigned,
        "manifest_digest": _stable_digest(unsigned),
    }


def _resolve_sc_with_manifest(manifest: Mapping[str, Any]) -> Mapping[str, Any]:
    upstream = {
        *LIVE._upstream_inputs("sc"),
        MANIFEST_PATH,
        IDENTITY_PATH,
        *DYNAMIC_SOURCES,
    }
    return TRANSACTION.resolve_live_verify_queue_transaction_plan(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase_name="sc_verify_queue",
        run_id="live-sc-claude",
        upstream_inputs=tuple(sorted(upstream)),
        runtime_authority=LIVE._runtime_authority("sc", "claude"),
        shard_manifests=LIVE._shard_manifests("sc"),
        context_capture=LIVE.CONTEXT_CAPTURE,
        prearm_input_manifest=dict(manifest),
        preverify_frozen_projection=LIVE._frozen_projection(
            "sc", "claude"
        ),
        preverify_chain_pair_projection=LIVE._chain_pair_projection(
            "sc", "claude"
        ),
    )


def test_sc_t0_does_not_require_identity_when_prearm_is_not_resolved() -> None:
    plan = LIVE._plan("sc", "claude")
    t0 = LIVE._child_map(plan)[LIVE.CHILD_IDS[0]]

    assert IDENTITY_PATH not in set(map(str, t0["exact_inputs"]))
    assert IDENTITY_PATH not in set(map(str, t0["required_inputs"]))


def test_sc_t0_freezes_identity_and_every_dynamic_source_via_manifest() -> None:
    plan = _resolve_sc_with_manifest(_manifest())
    t0 = LIVE._child_map(plan)[LIVE.CHILD_IDS[0]]
    inputs = set(map(str, t0["exact_inputs"]))
    metadata = t0.get("prearm_content_addressed_input_manifest")

    assert IDENTITY_PATH in inputs
    assert MANIFEST_PATH in inputs
    assert set(DYNAMIC_SOURCES) <= inputs
    assert isinstance(metadata, Mapping)
    assert metadata["manifest_identity"] == "scratchpad:" + MANIFEST_PATH
    assert metadata["manifest_digest"] == _manifest()["manifest_digest"]
    assert metadata["entry_count"] == len(DYNAMIC_SOURCES)
    assert metadata["content_addressed"] is True
    assert metadata["live_glob_allowed"] is False
    assert metadata["live_read_after_arm_allowed"] is False
    assert {
        row["identity"] for row in metadata["entries"]
    } == {"scratchpad:" + path for path in DYNAMIC_SOURCES}


def test_sc_manifest_rejects_an_omitted_candidate_referenced_source() -> None:
    with pytest.raises(
        (TRANSACTION.VerifyQueueTransactionError, ValueError),
        match="referenced|denominator|manifest|source",
    ):
        _resolve_sc_with_manifest(_manifest(omit=DYNAMIC_SOURCES[-1]))


def test_l1_plan_is_unaffected_by_sc_prearm_manifest_contract() -> None:
    plan = LIVE._plan("l1", "claude")
    t0 = LIVE._child_map(plan)[LIVE.CHILD_IDS[0]]

    assert IDENTITY_PATH not in set(map(str, t0["exact_inputs"]))
    assert "prearm_content_addressed_input_manifest" not in t0
    assert set(t0["exact_inputs"]) == set(LIVE._upstream_inputs("l1"))
