"""Fixture-only acceptance contract for the live verify-queue driver adapter.

The semantic transaction deliberately does not infer driver state.  Production
therefore needs one narrow adapter which derives all pre-arm authority from an
already seeded current-run scratchpad and then executes and validates the live
T0--T9 transaction exactly once.

Required production module/API
------------------------------

``live_verify_queue_driver_adapter.py`` must export:

``LiveVerifyQueueDriverAdapterError``
    Raised before public mutation when current-run authority or the frozen
    runtime tuple cannot be established.

``run_live_verify_queue_driver_cutover(*, scratchpad, project_root, config,
run_id, failpoint=None)``
    The sole driver-facing entrypoint.  No upstream roster, digest, context
    capture, plan, or semantic executor is caller-supplied.  The helper must:

    1. derive the fixed pipeline roster;
    2. run the SC dynamic pre-arm resolver (or produce L1 NOT_APPLICABLE);
    3. commit a content-addressed presence authority over present and absent
       roster members;
    4. derive the audit snapshot, trusted-code, scoped producer-ledger, and
       methodology digests with replayable evidence;
    5. derive the bounded context-capture denominator and live plan;
    6. revalidate the frozen runtime/config tuple;
    7. execute T0--T9 once; and
    8. validate publication before returning ``safe_to_consume=True``.

The adapter failpoint must forward transaction labels and additionally emit
``after_live_adapter_plan_resolved`` immediately after plan resolution but
before the final tuple revalidation and transaction arm.  This is a test and
fault-injection seam, not an authority input.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import inspect
import json
from pathlib import Path
import re
import sys
from typing import Any, Callable, Mapping, Sequence

import pytest

from artifact_ledger import (
    _active_commit_receipt_is_valid,
    _pure_active_output_authority_binding_is_valid,
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
)
from finding_producer_registry import (
    write_application_skeptic_proposal_projection,
)
from phase_io_contracts import (
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    canonical_work_unit_key,
)
import plamen_driver as DRIVER
import test_live_verify_queue_transaction_semantic_closure as LIVE


SCRIPTS = Path(__file__).resolve().parent
SUT_PATH = SCRIPTS / "live_verify_queue_driver_adapter.py"
PUBLIC_ENTRYPOINT = "run_live_verify_queue_driver_cutover"
ERROR_NAME = "LiveVerifyQueueDriverAdapterError"
SC_DYNAMIC_CANDIDATE = "arm_before_trust_compound_candidates.json"
PRESENCE_FILE = "prearm_presence_authority.json"
PLAN_FAILPOINT = "after_live_adapter_plan_resolved"
HEX64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)


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


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _load_sut():
    assert SUT_PATH.is_file(), (
        "production must add scripts/live_verify_queue_driver_adapter.py"
    )
    name = "_plamen_live_verify_queue_driver_adapter_acceptance"
    cached = sys.modules.get(name)
    if cached is not None:
        return cached
    spec = importlib.util.spec_from_file_location(name, SUT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _entrypoint() -> Callable[..., Mapping[str, Any]]:
    candidate = getattr(_load_sut(), PUBLIC_ENTRYPOINT, None)
    assert callable(candidate), (
        f"production must expose {PUBLIC_ENTRYPOINT}"
    )
    return candidate


def _error_type() -> type[BaseException]:
    candidate = getattr(_load_sut(), ERROR_NAME, None)
    assert isinstance(candidate, type) and issubclass(
        candidate, BaseException
    ), f"production must expose {ERROR_NAME}"
    return candidate


def _dimensions(
    *,
    pipeline: str,
    backend: str,
    project: Path,
    root: Path,
    run_id: str,
) -> dict[str, Any]:
    ecosystem = "evm" if pipeline == "sc" else "rust"
    phase_name = "sc_verify_queue" if pipeline == "sc" else "verify_queue"
    snapshot = "a" * 64
    return {
        "pipeline": pipeline,
        "mode": "thorough",
        "language": ecosystem,
        "ecosystem": ecosystem,
        "cli_backend": backend,
        "backend": backend,
        "phase_name": phase_name,
        "project_root": str(project),
        "scratchpad": str(root),
        "_run_id": run_id,
        "_audit_snapshot": {"snapshot_digest": snapshot},
    }


def _claim_group(
    *,
    root: Path,
    project: Path,
    config: Mapping[str, Any],
    run_id: str,
    paths: Sequence[str],
    work_unit_id: str,
    phase: str = "preverify_adapter_fixture",
    writer: str = "DRIVER",
) -> None:
    if not paths:
        return
    pipeline = str(config["pipeline"])
    mode = str(config["mode"])
    ecosystem = str(config["ecosystem"])
    backend = str(config["backend"])
    owner = canonical_work_unit_key(
        pipeline,
        mode,
        ecosystem,
        backend,
        phase,
        work_unit_id,
    )
    postimage = {
        relative: (root / relative).read_bytes()
        for relative in sorted(paths)
    }
    for relative in postimage:
        (root / relative).unlink()
    contract = PhaseIOContract(
        pipeline=pipeline,
        mode=mode,
        ecosystem=ecosystem,
        backend=backend,
        phase=phase,
        work_unit_id=work_unit_id,
        outputs=tuple(
            ArtifactSpec(
                root="scratchpad",
                path=relative,
                owner_key=owner,
                artifact_class=(
                    "REQUIRED" if writer == "MODEL" else "DRIVER_GENERATED"
                ),
                writer=writer,
                write_mode="CREATE",
                schema_version="fixture.live-adapter-upstream.v1",
                minimum_gate="FIXTURE_EXACT_BYTES",
                consumers=(
                    (
                        "sc_verify_queue"
                        if pipeline == "sc"
                        else "verify_queue"
                    )
                    + "/t0.live_upstream_authority",
                    "sc_verify_queue/prearm_dynamic_inputs",
                    (
                        "sc_verify_queue"
                        if pipeline == "sc"
                        else "verify_queue"
                    )
                    + "/prearm_presence_authority",
                ),
            )
            for relative in sorted(paths)
        ),
        immutable_inputs=(),
        bounded_lookup_inputs=(),
        model_invoked=writer == "MODEL",
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=pipeline,
        mode=mode,
        ecosystem=ecosystem,
        backend=backend,
        model=("fixture-model" if writer == "MODEL" else "fixture-driver"),
        timeout_s=60,
        exec_mode=("pty" if writer == "MODEL" else "python"),
        tool_policy=("filesystem",),
    )
    record_work_unit_inputs(
        root,
        project,
        contract,
        launch,
        run_id=run_id,
    )
    for relative, raw in postimage.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    record_work_unit_artifacts(
        root,
        project,
        contract,
        launch,
        run_id=run_id,
        actor=writer,
    )


def _seed(
    project: Path,
    *,
    pipeline: str,
    backend: str,
    absent: Sequence[str] = (),
    foreign_required: str = "",
) -> tuple[Path, dict[str, Any], str]:
    root = project / ".scratchpad"
    root.mkdir(parents=True)
    run_id = f"driver-adapter-{pipeline}-{backend}"
    config = _dimensions(
        pipeline=pipeline,
        backend=backend,
        project=project,
        root=root,
        run_id=run_id,
    )
    roster = set(LIVE._base_upstream_inputs(pipeline))
    absent_set = set(absent)
    # A candidate-free SC run is an authoritative NOT_TRIGGERED dynamic-input
    # path, not a malformed typed-candidate debt path.
    if pipeline == "sc":
        absent_set.add(SC_DYNAMIC_CANDIDATE)
    required = {
        *LIVE.REQUIRED_UPSTREAM,
        "findings_inventory.md",
    }
    assert not (absent_set & required)

    (root / "findings_inventory.md").write_text(
        "# Findings Inventory\n",
        encoding="utf-8",
    )
    source_roster = {"findings_inventory.md"}
    chain_model_roster: set[str] = set()
    if pipeline == "sc":
        chain_model_roster.update({
            "hypotheses.md",
            "finding_mapping.md",
            "enabler_results.md",
        })
        for relative in sorted(chain_model_roster - absent_set):
            path = root / relative
            if not path.exists():
                path.write_text(
                    f"# Current-run {relative}\n",
                    encoding="utf-8",
                )
    if "application_skeptic_proposals.md" not in absent_set:
        write_application_skeptic_proposal_projection(root, [])
    if "candidate_negative_skeptic_proposals.md" not in absent_set:
        write_application_skeptic_proposal_projection(
            root,
            [],
            projection_name="candidate_negative_skeptic_proposals.md",
        )
    (root / "config.json").write_bytes(_canonical_bytes(config))
    for relative in sorted(roster - absent_set):
        if relative == (
            "live_verify_queue_methodology_projection.receipt.json"
        ):
            # Solely produced by the live methodology projection provider.
            continue
        path = root / relative
        if path.exists():
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = (
            b"# Current-run adapter fixture\n"
            if path.suffix == ".md"
            else _canonical_bytes({"artifact": relative})
        )
        path.write_bytes(raw)

    present = sorted(
        relative
        for relative in (roster | source_roster)
        if relative not in chain_model_roster
        if (root / relative).is_file()
    )
    if foreign_required:
        assert foreign_required in required
        assert foreign_required in present
        present.remove(foreign_required)
    _claim_group(
        root=root,
        project=project,
        config=config,
        run_id=run_id,
        paths=present,
        work_unit_id="current_run_upstream",
    )
    if foreign_required:
        _claim_group(
            root=root,
            project=project,
            config=config,
            run_id="foreign-run",
            paths=(foreign_required,),
            work_unit_id="foreign_required_upstream",
        )
    # ``chain/model`` is one atomic output contract.  A fixture that omits
    # either canonical pair member must not pre-register a smaller contract
    # under the same work-unit key; the later canonical-pair publisher owns
    # the complete trio in one commit.
    if chain_model_roster and all(
        (root / relative).is_file()
        for relative in chain_model_roster
    ):
        _claim_group(
            root=root,
            project=project,
            config=config,
            run_id=run_id,
            paths=tuple(sorted(
                relative
                for relative in chain_model_roster
                if (root / relative).is_file()
            )),
            phase="chain",
            work_unit_id="model",
            writer="MODEL",
        )

    for relative in LIVE.CONTEXT_INPUTS:
        if relative.startswith("project::"):
            path = project / relative[len("project::"):]
            raw = b"// bounded adapter context\n"
        elif relative in {
            "methodology_registry.json",
            "methodology_reachability_manifest.json",
        }:
            # The live methodology projection provider is the sole authority
            # for these artifacts; arbitrary fixture placeholders would be an
            # intentionally rejected external preimage.
            continue
        else:
            path = root / relative
            raw = _canonical_bytes({"artifact": relative})
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    return root, config, run_id


def _invoke(
    root: Path,
    project: Path,
    config: Mapping[str, Any],
    run_id: str,
    *,
    failpoint: Callable[[str], None] | None = None,
) -> Mapping[str, Any]:
    return _entrypoint()(
        scratchpad=root,
        project_root=project,
        config=config,
        run_id=run_id,
        failpoint=failpoint,
    )


def _assert_digest_evidence(
    result: Mapping[str, Any],
    root: Path,
    project: Path,
) -> None:
    authority = result["runtime_authority"]
    evidence = result["runtime_authority_evidence"]
    assert set(authority) == {
        "audit_snapshot_digest",
        "trusted_queue_code_digest",
        "producer_ledger_digest",
        "methodology_digest",
        "pipeline",
        "mode",
        "ecosystem",
        "backend",
        "run_id",
    }
    assert all(
        HEX64.fullmatch(str(authority[key]))
        for key in (
            "audit_snapshot_digest",
            "trusted_queue_code_digest",
            "producer_ledger_digest",
            "methodology_digest",
        )
    )
    assert evidence["audit_snapshot"]["digest"] == authority[
        "audit_snapshot_digest"
    ]
    assert evidence["audit_snapshot"]["source"] == (
        "config._audit_snapshot.snapshot_digest"
    )
    groups = (
        ("trusted_queue_code", "trusted_queue_code_digest"),
        ("producer_ledger", "producer_ledger_digest"),
        ("methodology", "methodology_digest"),
    )
    for group, authority_key in groups:
        payload = evidence[group]
        rows = payload["rows"]
        assert isinstance(rows, list) and rows
        assert payload["digest"] == _sha(_canonical_bytes(rows))
        assert payload["digest"] == authority[authority_key]
        for row in rows:
            assert set(row) >= {"identity", "sha256", "size"}
            assert HEX64.fullmatch(str(row["sha256"]))
            assert isinstance(row["size"], int) and row["size"] >= 0
            identity = str(row["identity"])
            if identity.startswith("scratchpad:"):
                path = root / identity[len("scratchpad:"):]
                if path.is_file():
                    raw = path.read_bytes()
                    assert row["sha256"] == _sha(raw)
                    assert row["size"] == len(raw)
            elif identity.startswith("project::"):
                path = project / identity[len("project::"):]
                raw = path.read_bytes()
                assert row["sha256"] == _sha(raw)
                assert row["size"] == len(raw)


def _assert_success(
    result: Mapping[str, Any],
    *,
    root: Path,
    project: Path,
    pipeline: str,
    backend: str,
    run_id: str,
) -> None:
    assert result["schema_version"] == (
        "plamen.live_verify_queue_driver_cutover.v1"
    )
    assert result["state"] == "OUTPUT_COMMITTED"
    assert result["safe_to_consume"] is True
    assert result["pipeline"] == pipeline
    assert result["backend"] == backend
    assert result["run_id"] == run_id
    assert result["resume_state"] in {"FRESH_COMMIT", "REPLAYED_COMMIT"}
    plan = result["plan"]
    execution = result["execution"]
    validation = result["publication_validation"]
    assert execution["state"] == "OUTPUT_COMMITTED"
    assert execution["safe_to_consume"] is True
    assert validation["safe_to_consume"] is True
    assert validation["plan_digest"] == plan["plan_digest"]
    assert plan["runtime_authority"] == result["runtime_authority"]

    static = set(result["static_upstream_roster"])
    effective = set(result["effective_upstream_roster"])
    assert static == set(LIVE._base_upstream_inputs(pipeline))
    assert static <= effective
    presence = result["prearm_presence"]
    assert presence["authority_path"] == PRESENCE_FILE
    assert set(presence["authority"]["roster_identities"]) == {
        "scratchpad:" + relative for relative in effective
    }
    assert PRESENCE_FILE in plan["external_input_denominator"]
    dynamic = result["dynamic_prearm"]
    if pipeline == "sc":
        assert dynamic["state"] in {
            "NOT_TRIGGERED",
            "RESOLVED",
            "COMPLETED_WITH_DEBT",
        }
    else:
        assert dynamic["state"] == "NOT_APPLICABLE"
    capture = result["context_capture"]
    assert set(capture["exact_inputs"]) == {
        *LIVE.CONTEXT_INPUTS,
        *result["preverify_frozen_projection"]["required_paths"],
    }
    assert set(capture["exact_inputs"]) <= set(
        plan["external_input_denominator"]
    )
    _assert_digest_evidence(result, root, project)


def _public_bytes(root: Path, pipeline: str) -> dict[str, bytes]:
    return {
        relative: (root / relative).read_bytes()
        for relative in LIVE._pipeline_public(pipeline)
        if (root / relative).is_file()
    }


def test_driver_adapter_exports_one_narrow_noninjectable_api() -> None:
    module = _load_sut()
    entry = _entrypoint()
    _error_type()
    signature = inspect.signature(entry)

    assert tuple(signature.parameters) == (
        "scratchpad",
        "project_root",
        "config",
        "run_id",
        "failpoint",
    )
    assert all(
        name not in signature.parameters
        for name in (
            "upstream_inputs",
            "runtime_authority",
            "context_capture",
            "plan",
            "semantic_executor",
            "semantic_executor_factory",
        )
    )
    assert callable(getattr(module, PUBLIC_ENTRYPOINT))


@pytest.mark.parametrize(
    "pipeline,backend",
    (
        ("sc", "claude"),
        ("sc", "codex"),
        ("l1", "claude"),
        ("l1", "codex"),
    ),
)
def test_adapter_prepares_executes_and_validates_backend_neutral_cutover(
    tmp_path: Path,
    pipeline: str,
    backend: str,
) -> None:
    root, config, run_id = _seed(
        tmp_path,
        pipeline=pipeline,
        backend=backend,
    )
    observed = False

    def failpoint(label: str) -> None:
        nonlocal observed
        if label == "after_t8_commit":
            observed = True
            assert all(
                not (root / relative).exists()
                for relative in LIVE._pipeline_public(pipeline)
            )

    result = _invoke(
        root,
        tmp_path,
        config,
        run_id,
        failpoint=failpoint,
    )

    assert observed is True
    assert result["resume_state"] == "FRESH_COMMIT"
    _assert_success(
        result,
        root=root,
        project=tmp_path,
        pipeline=pipeline,
        backend=backend,
        run_id=run_id,
    )

    ledger = read_artifact_ledger(root)
    parent_rows = [
        row
        for key, row in ledger["work_units"].items()
        if key.endswith("/routing.live_parent_commit")
    ]
    assert len(parent_rows) == 1
    parent = parent_rows[0]
    parent_key = parent["work_unit_key"]
    parent_commit = parent["commit_authority"]
    assert parent["contract_manifest"]["model_invoked"] is False
    assert parent["contract_manifest"]["outputs"] == []
    assert parent["artifacts"] == {}
    assert parent_commit["expected_output_records"] == {}
    assert parent_commit["recorded_output_identities"] == []
    assert parent_commit["output_authority_actor"] == "DRIVER"
    assert _active_commit_receipt_is_valid(
        parent,
        work_unit_key=parent_key,
        run_id=run_id,
    )

    if pipeline == "sc" and backend == "claude":
        def pure(candidate: Mapping[str, Any]) -> bool:
            return _pure_active_output_authority_binding_is_valid(
                candidate,
                candidate["commit_authority"],
                candidate["artifacts"],
            )

        for mutate in (
            lambda row: row["contract_manifest"].__setitem__(
                "model_invoked", True
            ),
            lambda row: row["contract_manifest"]["outputs"].append({
                "identity": "scratchpad:unexpected.json",
                "writer": "DRIVER",
            }),
            lambda row: row["commit_authority"].__setitem__(
                "recorded_output_identities",
                ["scratchpad:unexpected.json"],
            ),
            lambda row: row["commit_authority"].__setitem__(
                "output_authority_actor", "MODEL"
            ),
        ):
            tampered = copy.deepcopy(parent)
            mutate(tampered)
            assert pure(tampered) is False

        for mutate in (
            lambda row: row.__setitem__("run_id", "foreign-run"),
            lambda row: row.__setitem__(
                "work_unit_key", "foreign/work-unit"
            ),
            lambda row: row["commit_authority"].__setitem__(
                "attempt_ordinal",
                row["commit_authority"]["attempt_ordinal"] + 1,
            ),
            lambda row: row.__setitem__(
                "semantic_reexecution_history", [{}]
            ),
            lambda row: row["commit_authority"].__setitem__(
                "receipt_digest", "0" * 64
            ),
            lambda row: row["input_bindings"].__setitem__(
                "scratchpad:unexpected.json", {}
            ),
            lambda row: row["launch_manifest"].__setitem__(
                "run_id", "foreign-run"
            ),
        ):
            tampered = copy.deepcopy(parent)
            mutate(tampered)
            assert _active_commit_receipt_is_valid(
                tampered,
                work_unit_key=parent_key,
                run_id=run_id,
            ) is False


def test_adapter_uses_legacy_claude_default_when_backend_is_omitted(
    tmp_path: Path,
) -> None:
    """Legacy driver configs without an explicit backend remain resumable."""

    root, config, run_id = _seed(
        tmp_path,
        pipeline="l1",
        backend="claude",
    )
    config.pop("backend", None)
    config.pop("cli_backend", None)

    result = _invoke(root, tmp_path, config, run_id)

    _assert_success(
        result,
        root=root,
        project=tmp_path,
        pipeline="l1",
        backend="claude",
        run_id=run_id,
    )


@pytest.mark.parametrize(
    "pipeline,backend",
    (("sc", "claude"), ("l1", "codex")),
)
def test_adapter_resume_replays_same_plan_without_second_t0_t9_execution(
    tmp_path: Path,
    pipeline: str,
    backend: str,
) -> None:
    root, config, run_id = _seed(
        tmp_path,
        pipeline=pipeline,
        backend=backend,
    )
    first = _invoke(root, tmp_path, config, run_id)
    public_before = _public_bytes(root, pipeline)
    status_before = {
        relative: (root / relative).read_bytes()
        for relative in LIVE.STATUS_PATHS
        if (root / relative).is_file()
    }
    labels: list[str] = []
    second = _invoke(
        root,
        tmp_path,
        config,
        run_id,
        failpoint=labels.append,
    )

    assert first["plan"]["plan_digest"] == second["plan"]["plan_digest"]
    assert first["runtime_authority"] == second["runtime_authority"]
    assert second["resume_state"] == "REPLAYED_COMMIT"
    assert _public_bytes(root, pipeline) == public_before
    assert {
        relative: (root / relative).read_bytes()
        for relative in LIVE.STATUS_PATHS
        if (root / relative).is_file()
    } == status_before
    assert "after_t8_commit" not in labels
    _assert_success(
        second,
        root=root,
        project=tmp_path,
        pipeline=pipeline,
        backend=backend,
        run_id=run_id,
    )


@pytest.mark.parametrize(
    "pipeline,backend,missing",
    (
        ("sc", "codex", "chain_grouping_relations.json"),
        ("l1", "claude", "l1_composition_model_dispositions.json"),
    ),
)
def test_missing_optional_input_is_explicit_absence_not_false_failure(
    tmp_path: Path,
    pipeline: str,
    backend: str,
    missing: str,
) -> None:
    root, config, run_id = _seed(
        tmp_path,
        pipeline=pipeline,
        backend=backend,
        absent=(missing,),
    )

    result = _invoke(root, tmp_path, config, run_id)

    rows = {
        str(row["identity"]): row
        for row in result["prearm_presence"]["authority"]["entries"]
    }
    assert rows["scratchpad:" + missing] == {
        "identity": "scratchpad:" + missing,
        "state": "ABSENT",
    }
    assert missing in result["static_upstream_roster"]
    assert not (root / missing).exists()
    _assert_success(
        result,
        root=root,
        project=tmp_path,
        pipeline=pipeline,
        backend=backend,
        run_id=run_id,
    )


@pytest.mark.parametrize(
    "pipeline,backend",
    (("sc", "claude"), ("l1", "codex")),
)
def test_invalid_required_producer_authority_blocks_before_publication(
    tmp_path: Path,
    pipeline: str,
    backend: str,
) -> None:
    root, config, run_id = _seed(
        tmp_path,
        pipeline=pipeline,
        backend=backend,
        foreign_required="findings_inventory.md",
    )

    with pytest.raises(
        _error_type(),
        match="producer|run|authority|required|presence",
    ):
        _invoke(root, tmp_path, config, run_id)

    assert all(
        not (root / relative).exists()
        for relative in LIVE._pipeline_public(pipeline)
    )


@pytest.mark.parametrize(
    "mutation",
    ("snapshot", "backend"),
)
def test_snapshot_or_runtime_tuple_drift_after_plan_blocks_arm(
    tmp_path: Path,
    mutation: str,
) -> None:
    root, config, run_id = _seed(
        tmp_path,
        pipeline="sc",
        backend="claude",
    )

    def drift(label: str) -> None:
        if label != PLAN_FAILPOINT:
            return
        if mutation == "snapshot":
            config["_audit_snapshot"]["snapshot_digest"] = "f" * 64
        else:
            config["backend"] = "codex"
            config["cli_backend"] = "codex"

    with pytest.raises(
        _error_type(),
        match="snapshot|runtime|tuple|backend|drift",
    ):
        _invoke(
            root,
            tmp_path,
            config,
            run_id,
            failpoint=drift,
        )

    assert all(
        not (root / relative).exists()
        for relative in LIVE._pipeline_public("sc")
    )


def test_driver_cutover_delegates_both_queue_phases_through_one_call() -> None:
    main_source = inspect.getsource(DRIVER.main)
    boundary = inspect.getsource(
        DRIVER._run_live_verify_queue_phase_boundary
    )

    assert main_source.count(
        "_run_live_verify_queue_phase_boundary("
    ) == 1
    assert PUBLIC_ENTRYPOINT + "(" not in main_source
    assert boundary.count(PUBLIC_ENTRYPOINT + "(") == 1
