"""Regression fixtures for JSON boolean/integer authority boundaries.

Python deliberately makes ``bool`` a subclass of ``int``.  Persisted control
artifacts must not inherit that language quirk: JSON booleans are not JSON
integers, even when a receipt is re-digested after the type substitution.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

import audit_snapshot as snapshot
import plamen_driver as driver
from artifact_ledger import ArtifactLedgerError
from phase_io_contracts import LaunchSpec, resolve_phase_io_contract
from program_facts_types import canonical_file_bytes
import test_typed_worker_output_authority_p0 as typed_fixtures
import test_worker_execution_receipts as worker_fixtures
import typed_worker_output_authority as typed_output
import worker_execution_receipts as worker_receipts


def _zero_one_integer_leaf_paths(
    value: object,
    prefix: tuple[object, ...] = (),
) -> list[tuple[object, ...]]:
    paths: list[tuple[object, ...]] = []
    if type(value) is int and value in {0, 1}:
        return [prefix]
    if isinstance(value, dict):
        for key, child in value.items():
            paths.extend(
                _zero_one_integer_leaf_paths(child, (*prefix, key))
            )
    elif isinstance(value, list):
        for index, child in enumerate(value):
            paths.extend(
                _zero_one_integer_leaf_paths(child, (*prefix, index))
            )
    return paths


def _replace_path(value: object, path: tuple[object, ...], replacement: object) -> None:
    cursor = value
    for component in path[:-1]:
        cursor = cursor[component]  # type: ignore[index]
    cursor[path[-1]] = replacement  # type: ignore[index]


def _single_byte_digest(_path: Path, raw: bytes) -> str:
    if raw != b"x":
        raise ValueError("fixture output must be exactly one byte")
    return worker_receipts._digest_bytes(raw)


def _run_staged_worker(
    tmp_path: Path,
    *,
    one_byte_output: bool = False,
    one_byte_context: bool = False,
    one_byte_prompt: bool = False,
    bind_prompt_stdin: bool = False,
    stream_limit_bytes: int | None = None,
    publish_canonical: bool = False,
):
    bindings = worker_fixtures._bindings(tmp_path)
    if one_byte_context:
        (tmp_path / "launch-inputs" / "context.md").write_bytes(b"x")
    if one_byte_prompt:
        (tmp_path / "launch-inputs" / "prompt.md").write_bytes(b"x")
    if one_byte_output:
        script = (
            "from pathlib import Path; "
            "p=Path('worker-out/result.bin'); "
            "p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(b'x')"
        )
        expected = (
            worker_receipts.ExpectedOutput(
                "finding-H-01", "result.bin", "canonical/result.bin"
            ),
        )
        parser = _single_byte_digest
    else:
        script = worker_fixtures._script_for("worker-out/result.json")
        expected = (
            worker_receipts.ExpectedOutput(
                "finding-H-01", "result.json", "canonical/result.json"
            ),
        )
        parser = worker_fixtures.strict_json_digest
    kwargs: dict[str, object] = {}
    if stream_limit_bytes is not None:
        kwargs.update({
            "stdout_limit_bytes": stream_limit_bytes,
            "stderr_limit_bytes": stream_limit_bytes,
        })
    completed = worker_receipts.run_observed_worker(
        scratchpad=tmp_path,
        bindings=bindings,
        argv=[worker_fixtures.sys.executable, "-c", script],
        cwd=tmp_path,
        output_scope_relative="worker-out",
        expected_outputs=expected,
        parser_digest=parser,
        environment={},
        environment_allowlist=(),
        stdin_input=bindings.prompt if bind_prompt_stdin else None,
        timeout_seconds=10,
        publish_canonical=publish_canonical,
        **kwargs,
    )
    return completed, parser


def _reseal_hashed_json(
    path: Path,
    *,
    prefix: str,
    digest_field: str,
    payload: dict[str, object],
) -> tuple[Path, str]:
    unsigned = {
        key: value for key, value in payload.items() if key != digest_field
    }
    digest = worker_receipts._digest_json(unsigned)
    payload[digest_field] = digest
    resealed = path.with_name(f"{prefix}_{digest}.json")
    resealed.write_bytes(worker_receipts._canonical_json(payload))
    return resealed, digest


def _reseal_completion(
    completed,
    mutate,
) -> tuple[Path, str]:
    payload = json.loads(
        Path(completed.receipt_path).read_text(encoding="utf-8")
    )
    mutate(payload)
    return _reseal_hashed_json(
        Path(completed.receipt_path),
        prefix="completion",
        digest_field="completion_sha256",
        payload=payload,
    )


def _reseal_arm_and_completion(
    completed,
    mutate_arm,
) -> tuple[Path, str]:
    arm = json.loads(Path(completed.arm_path).read_text(encoding="utf-8"))
    mutate_arm(arm)
    arm_path, arm_digest = _reseal_hashed_json(
        Path(completed.arm_path),
        prefix="arm",
        digest_field="arm_sha256",
        payload=arm,
    )

    def mutate_completion(completion: dict[str, object]) -> None:
        completion["arm_relative_path"] = arm_path.name
        completion["arm_sha256"] = arm_digest

    return _reseal_completion(completed, mutate_completion)


def _validate_staged(
    tmp_path: Path,
    *,
    receipt_path: Path,
    completion_sha256: str,
    parser,
) -> None:
    worker_receipts.validate_staged_execution(
        scratchpad=tmp_path,
        receipt_path=receipt_path,
        parser_digest=parser,
        expected_completion_sha256=completion_sha256,
    )


def _reseal_publication(
    completed,
    *,
    document: str,
    mutate,
) -> tuple[Path, str]:
    publish_path = Path(completed.publish_receipt_path)
    publish = json.loads(publish_path.read_text(encoding="utf-8"))
    arm_path = publish_path.parent / publish["publish_arm_relative_path"]
    arm = json.loads(arm_path.read_text(encoding="utf-8"))
    if document == "publish_arm":
        mutate(arm)
        arm_path, arm_digest = _reseal_hashed_json(
            arm_path,
            prefix="publish_arm",
            digest_field="publish_arm_sha256",
            payload=arm,
        )
        publish["publish_arm_relative_path"] = arm_path.name
        publish["publish_arm_sha256"] = arm_digest
    elif document == "publish":
        mutate(publish)
    else:
        raise AssertionError(f"unsupported publication fixture: {document}")
    return _reseal_hashed_json(
        publish_path,
        prefix="publish",
        digest_field="publish_sha256",
        payload=publish,
    )


def _validate_published(
    tmp_path: Path,
    *,
    completed,
    publish_path: Path,
    publish_sha256: str,
    parser,
) -> None:
    worker_receipts.validate_completed_execution(
        scratchpad=tmp_path,
        receipt_path=completed.receipt_path,
        publish_receipt_path=publish_path,
        parser_digest=parser,
        expected_completion_sha256=completed.completion_sha256,
        expected_publish_sha256=publish_sha256,
    )


@pytest.mark.parametrize(
    ("reader", "config"),
    (
        (
            lambda root, config: driver._report_index_model_attempt_ordinal(
                root, config
            ),
            {"_phase_io_model_attempts": {"report_index": True}},
        ),
        (
            lambda _root, config: (
                driver._report_index_summary_parity_attempt_ordinal(config)
            ),
            {"_phase_io_model_attempts": {"report_index": True}},
        ),
        (
            lambda _root, config: driver._instantiate_attempt_ordinal(config),
            {"_active_model_attempts": {"instantiate": True}},
        ),
    ),
)
def test_persisted_attempt_maps_reject_boolean_ordinals(
    tmp_path: Path,
    reader,
    config: dict[str, object],
) -> None:
    with pytest.raises(ArtifactLedgerError, match="attempt.*integer|integer.*attempt"):
        reader(tmp_path, config)


def test_attempt_map_validation_rejects_unselected_boolean_debt(
    tmp_path: Path,
) -> None:
    config = {
        "_phase_io_model_attempts": {
            "report_index": 2,
            "inventory_chunk_a": True,
        }
    }
    with pytest.raises(ArtifactLedgerError, match="exact nonnegative integers"):
        driver._report_index_model_attempt_ordinal(tmp_path, config)


def test_run_phase_persists_attempt_schema_debt_without_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    phase = driver.Phase(
        name="fixture_phase",
        section_markers=[],
        expected_artifacts=[],
        base_timeout_s=1,
    )
    config = {
        "scratchpad": str(tmp_path),
        "_active_model_attempts": {"fixture_phase": True},
    }

    def _unexpected_launch(*_args, **_kwargs):
        raise AssertionError("persisted schema debt reached worker launch")

    monkeypatch.setattr(driver.subprocess, "Popen", _unexpected_launch)

    assert driver.run_phase(phase, config, 1) == driver.EXIT_ERROR
    debt = (tmp_path / "fixture_phase.degraded").read_text(encoding="utf-8")
    assert "[PERSISTED_ATTEMPT_STATE_SCHEMA_DEBT]" in debt
    assert "exact nonnegative integers" in debt


def test_exact_attempt_maps_preserve_valid_ordinals(tmp_path: Path) -> None:
    config = {
        "_phase_io_model_attempts": {"report_index": 2},
        "_active_model_attempts": {"instantiate": 3},
    }

    assert driver._report_index_model_attempt_ordinal(tmp_path, config) == 2
    assert driver._report_index_summary_parity_attempt_ordinal(config) == 2
    assert driver._instantiate_attempt_ordinal(config) == 3


def test_quarantined_inventory_launch_rejects_boolean_timeout_before_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = {
        "pipeline": "sc",
        "mode": "core",
        "language": "evm",
        "cli_backend": "claude",
    }
    contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="core",
        ecosystem="evm",
        backend="claude",
        phase="inventory",
        work_unit_id="additive_reemit",
        exact_inputs=("seed.json",),
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="driver",
        timeout_s=1,
        exec_mode="python",
        tool_policy=("filesystem",),
    )
    launch_manifest = launch.to_dict()
    launch_manifest["timeout_s"] = True
    unit = {
        "run_id": "run-1",
        "semantic_status": "QUARANTINED",
        "execution_state": "OUTPUT_QUARANTINED",
        "contract_manifest": contract.to_dict(),
        "launch_manifest": launch_manifest,
        "contract_digest": contract.digest,
        "launch_digest": launch.digest,
    }
    downstream_reached = False

    def _unexpected_downstream(_plan):
        nonlocal downstream_reached
        downstream_reached = True
        raise RuntimeError("sentinel-after-timeout-validation")

    monkeypatch.setattr(
        driver, "planned_inventory_output_bytes", _unexpected_downstream
    )
    monkeypatch.setattr(driver, "_load_inventory_aggregate_plan", lambda _root: {})

    issues = driver._recover_quarantined_inventory_reemit_transaction(
        scratchpad=tmp_path,
        project_root=tmp_path,
        config=config,
        run_id="run-1",
        unit=unit,
    )

    assert downstream_reached is False
    assert any("timeout_s" in issue and "integer" in issue for issue in issues)


@pytest.mark.parametrize(
    "field",
    (
        "pid",
        "launch_requested_unix_ns",
        "observed_start_unix_ns",
        "observed_exit_unix_ns",
    ),
)
def test_redigested_worker_completion_rejects_boolean_process_integers(
    tmp_path: Path,
    field: str,
) -> None:
    completed = worker_fixtures._run(tmp_path)
    original_path = Path(completed.receipt_path)
    payload = json.loads(original_path.read_text(encoding="utf-8"))
    payload["process_observation"][field] = True
    unsigned = {
        key: value
        for key, value in payload.items()
        if key != "completion_sha256"
    }
    digest = worker_receipts._digest_json(unsigned)
    payload["completion_sha256"] = digest
    mutated_path = original_path.with_name(f"completion_{digest}.json")
    mutated_path.write_bytes(worker_receipts._canonical_json(payload))

    with pytest.raises(
        worker_receipts.WorkerExecutionError,
        match="PID|process (?:launch request|start|exit) observation",
    ):
        worker_receipts.validate_completed_execution(
            scratchpad=tmp_path,
            receipt_path=mutated_path,
            publish_receipt_path=completed.publish_receipt_path,
            parser_digest=worker_fixtures.strict_json_digest,
            expected_completion_sha256=digest,
            expected_publish_sha256=completed.publish_sha256,
        )


@pytest.mark.parametrize("field", ("stdout_blob", "stderr_blob"))
@pytest.mark.parametrize(
    ("persisted_size", "rejected"),
    ((False, True), (0, False)),
)
def test_resealed_zero_length_stream_blob_requires_exact_integer_size(
    tmp_path: Path,
    field: str,
    persisted_size: object,
    rejected: bool,
) -> None:
    completed, parser = _run_staged_worker(tmp_path)

    def mutate(payload: dict[str, object]) -> None:
        payload[field]["size"] = persisted_size  # type: ignore[index]

    receipt_path, digest = _reseal_completion(completed, mutate)
    if rejected:
        with pytest.raises(
            worker_receipts.WorkerExecutionError,
            match="blob size.*exact nonnegative integer|exact nonnegative integer.*blob size",
        ):
            _validate_staged(
                tmp_path,
                receipt_path=receipt_path,
                completion_sha256=digest,
                parser=parser,
            )
    else:
        _validate_staged(
            tmp_path,
            receipt_path=receipt_path,
            completion_sha256=digest,
            parser=parser,
        )


@pytest.mark.parametrize("field", ("cas_blob", "raw_size"))
@pytest.mark.parametrize(
    ("persisted_size", "rejected"),
    ((True, True), (1, False)),
)
def test_resealed_one_byte_output_requires_exact_integer_sizes(
    tmp_path: Path,
    field: str,
    persisted_size: object,
    rejected: bool,
) -> None:
    completed, parser = _run_staged_worker(tmp_path, one_byte_output=True)

    def mutate(payload: dict[str, object]) -> None:
        output = payload["outputs"][0]  # type: ignore[index]
        if field == "cas_blob":
            output["cas_blob"]["size"] = persisted_size
        else:
            output["raw_size"] = persisted_size

    receipt_path, digest = _reseal_completion(completed, mutate)
    if rejected:
        with pytest.raises(
            worker_receipts.WorkerExecutionError,
            match="size.*exact nonnegative integer|exact nonnegative integer.*size",
        ):
            _validate_staged(
                tmp_path,
                receipt_path=receipt_path,
                completion_sha256=digest,
                parser=parser,
            )
    else:
        _validate_staged(
            tmp_path,
            receipt_path=receipt_path,
            completion_sha256=digest,
            parser=parser,
        )


@pytest.mark.parametrize("target", ("semantic_input", "stdin"))
@pytest.mark.parametrize(
    ("persisted_size", "rejected"),
    ((True, True), (1, False)),
)
def test_resealed_one_byte_arm_input_requires_exact_integer_sizes(
    tmp_path: Path,
    target: str,
    persisted_size: object,
    rejected: bool,
) -> None:
    completed, parser = _run_staged_worker(
        tmp_path,
        one_byte_context=target == "semantic_input",
        one_byte_prompt=target == "stdin",
        bind_prompt_stdin=target == "stdin",
    )

    def mutate(arm: dict[str, object]) -> None:
        if target == "semantic_input":
            arm["bindings"]["inputs"]["context"]["size"] = persisted_size
        else:
            arm["process_intent"]["stdin"]["size"] = persisted_size

    receipt_path, digest = _reseal_arm_and_completion(completed, mutate)
    if rejected:
        with pytest.raises(
            worker_receipts.WorkerExecutionError,
            match="size.*exact nonnegative integer|exact nonnegative integer.*size",
        ):
            _validate_staged(
                tmp_path,
                receipt_path=receipt_path,
                completion_sha256=digest,
                parser=parser,
            )
    else:
        _validate_staged(
            tmp_path,
            receipt_path=receipt_path,
            completion_sha256=digest,
            parser=parser,
        )


@pytest.mark.parametrize(
    ("path", "boolean_value"),
    (
        (("stream_limits", "stdout_bytes"), True),
        (("stream_limits", "stderr_bytes"), True),
        (("process_observation", "stream_limits", "stdout_bytes"), True),
        (("process_observation", "stream_limits", "stderr_bytes"), True),
        (("stream_observation", "stdout_captured_size"), False),
        (("stream_observation", "stderr_captured_size"), False),
        (
            (
                "process_observation",
                "stream_observation",
                "stdout_captured_size",
            ),
            False,
        ),
        (
            (
                "process_observation",
                "stream_observation",
                "stderr_captured_size",
            ),
            False,
        ),
    ),
)
@pytest.mark.parametrize("use_boolean", (True, False))
def test_resealed_stream_mirror_scalars_require_independent_exact_types(
    tmp_path: Path,
    path: tuple[str, ...],
    boolean_value: bool,
    use_boolean: bool,
) -> None:
    completed, parser = _run_staged_worker(
        tmp_path,
        stream_limit_bytes=1,
    )
    value: object = boolean_value if use_boolean else int(boolean_value)

    def mutate(payload: dict[str, object]) -> None:
        cursor = payload
        for component in path[:-1]:
            cursor = cursor[component]  # type: ignore[assignment,index]
        cursor[path[-1]] = value

    receipt_path, digest = _reseal_completion(completed, mutate)
    if use_boolean:
        with pytest.raises(
            worker_receipts.WorkerExecutionError,
            match="integer|malformed|ceiling",
        ):
            _validate_staged(
                tmp_path,
                receipt_path=receipt_path,
                completion_sha256=digest,
                parser=parser,
            )
    else:
        _validate_staged(
            tmp_path,
            receipt_path=receipt_path,
            completion_sha256=digest,
            parser=parser,
        )


@pytest.mark.parametrize("document", ("publish_arm", "publish"))
@pytest.mark.parametrize("field", ("raw_size", "source_blob_size"))
@pytest.mark.parametrize("use_boolean", (True, False))
def test_resealed_publication_size_copies_require_independent_exact_types(
    tmp_path: Path,
    document: str,
    field: str,
    use_boolean: bool,
) -> None:
    completed, parser = _run_staged_worker(
        tmp_path,
        one_byte_output=True,
        publish_canonical=True,
    )
    value: object = True if use_boolean else 1

    def mutate(payload: dict[str, object]) -> None:
        row = payload["destinations"][0]  # type: ignore[index]
        if field == "source_blob_size":
            row["source_blob"]["size"] = value
        else:
            row[field] = value

    publish_path, publish_digest = _reseal_publication(
        completed,
        document=document,
        mutate=mutate,
    )
    if use_boolean:
        with pytest.raises(
            worker_receipts.WorkerExecutionError,
            match="publish.*size.*exact nonnegative integer|exact nonnegative integer.*publish.*size",
        ):
            _validate_published(
                tmp_path,
                completed=completed,
                publish_path=publish_path,
                publish_sha256=publish_digest,
                parser=parser,
            )
    else:
        _validate_published(
            tmp_path,
            completed=completed,
            publish_path=publish_path,
            publish_sha256=publish_digest,
            parser=parser,
        )


@pytest.mark.parametrize(
    "path",
    (
        ("root_index",),
        ("limit_bytes",),
        ("raw_size",),
        ("cas_blob", "size"),
    ),
)
@pytest.mark.parametrize("use_boolean", (True, False))
def test_redigested_completed_evidence_copies_require_independent_exact_types(
    tmp_path: Path,
    path: tuple[str, ...],
    use_boolean: bool,
) -> None:
    shard = tmp_path / "shard"
    blobs = shard / "blobs"
    blobs.mkdir(parents=True)
    blob = worker_receipts._persist_blob(blobs, "evidence", b"x")
    armed = [{
        "evidence_id": "transcript",
        "root_index": 1,
        "relative_path": "session.jsonl",
        "limit_bytes": 1,
        "pre_state": "ABSENT",
    }]
    completed_row = {
        **armed[0],
        "post_state": "PRESENT",
        "raw_sha256": worker_receipts._digest_bytes(b"x"),
        "raw_size": 1,
        "cas_blob": blob,
    }
    assert set(_zero_one_integer_leaf_paths(completed_row)) == {
        ("root_index",),
        ("limit_bytes",),
        ("raw_size",),
        ("cas_blob", "size"),
    }
    _replace_path(completed_row, path, True if use_boolean else 1)
    receipt, digest = _reseal_hashed_json(
        shard / "completion_seed.json",
        prefix="completion",
        digest_field="completion_sha256",
        payload={
            "schema_version": worker_receipts.COMPLETION_SCHEMA,
            "completion_evidence": [completed_row],
        },
    )
    payload, replayed_digest = worker_receipts._load_hashed_json(
        receipt,
        prefix="completion",
        digest_field="completion_sha256",
        schema=worker_receipts.COMPLETION_SCHEMA,
    )
    assert replayed_digest == digest
    if use_boolean:
        with pytest.raises(
            worker_receipts.WorkerExecutionError,
            match="completed evidence.*(?:integer|ceiling)|(?:integer|ceiling).*completed evidence",
        ):
            worker_receipts._replay_completed_evidence_rows(
                payload["completion_evidence"],
                armed=armed,
                shard_dir=shard,
            )
    else:
        rows, exact = worker_receipts._replay_completed_evidence_rows(
            payload["completion_evidence"],
            armed=armed,
            shard_dir=shard,
        )
        cursor: object = rows[0]
        for component in path:
            cursor = cursor[component]  # type: ignore[index]
        assert cursor == 1
        assert exact == {"transcript": b"x"}


def test_recursive_completion_zero_one_matrix_rejects_boolean_substitution(
    tmp_path: Path,
) -> None:
    completed, parser = _run_staged_worker(
        tmp_path,
        one_byte_output=True,
        stream_limit_bytes=1,
    )
    base = json.loads(Path(completed.receipt_path).read_text(encoding="utf-8"))
    paths = _zero_one_integer_leaf_paths(base)
    assert len(paths) >= 13
    for path in paths:
        mutated = copy.deepcopy(base)
        cursor: object = mutated
        for component in path:
            cursor = cursor[component]  # type: ignore[index]
        _replace_path(mutated, path, bool(cursor))
        receipt_path, digest = _reseal_hashed_json(
            Path(completed.receipt_path),
            prefix="completion",
            digest_field="completion_sha256",
            payload=mutated,
        )
        with pytest.raises(worker_receipts.WorkerExecutionError):
            _validate_staged(
                tmp_path,
                receipt_path=receipt_path,
                completion_sha256=digest,
                parser=parser,
            )


@pytest.mark.parametrize("document", ("publish_arm", "publish"))
def test_recursive_publication_zero_one_matrix_rejects_boolean_substitution(
    tmp_path: Path,
    document: str,
) -> None:
    completed, parser = _run_staged_worker(
        tmp_path,
        one_byte_output=True,
        publish_canonical=True,
    )
    publish_path = Path(completed.publish_receipt_path)
    publish = json.loads(publish_path.read_text(encoding="utf-8"))
    source_path = (
        publish_path.parent / publish["publish_arm_relative_path"]
        if document == "publish_arm"
        else publish_path
    )
    base = json.loads(source_path.read_text(encoding="utf-8"))
    paths = _zero_one_integer_leaf_paths(base)
    assert {
        ("destinations", 0, "raw_size"),
        ("destinations", 0, "source_blob", "size"),
    }.issubset(set(paths))
    for path in paths:
        cursor: object = base
        for component in path:
            cursor = cursor[component]  # type: ignore[index]

        def mutate(payload: dict[str, object], *, selected=path, prior=cursor) -> None:
            _replace_path(payload, selected, bool(prior))

        resealed_path, digest = _reseal_publication(
            completed,
            document=document,
            mutate=mutate,
        )
        with pytest.raises(worker_receipts.WorkerExecutionError):
            _validate_published(
                tmp_path,
                completed=completed,
                publish_path=resealed_path,
                publish_sha256=digest,
                parser=parser,
            )


@pytest.mark.parametrize(
    ("persisted_size", "rejected"),
    (
        (True, True),
        ("1", True),
        (1.0, True),
        ([], True),
        ({}, True),
        (None, True),
        (1, False),
    ),
)
def test_provisional_output_snapshot_has_closed_exact_scalar_schema(
    persisted_size: object,
    rejected: bool,
) -> None:
    row = [{
        "assignment_id": "finding-H-01",
        "relative_path": "result.json",
        "raw_sha256": "0" * 64,
        "raw_size": persisted_size,
    }]
    if rejected:
        with pytest.raises(worker_receipts.WorkerExecutionError):
            worker_receipts._provisional_output_snapshot_binding(row)
    else:
        assert worker_receipts._provisional_output_snapshot_binding(row) == row


_INVALID_PERSISTED_TIMESTAMPS = (
    True,
    False,
    "1",
    None,
    [],
    {},
    0,
    -1,
)


@pytest.mark.parametrize(
    "field",
    (
        "armed_at_unix_ns",
        "completed_at_unix_ns",
        "published_at_unix_ns",
    ),
)
def test_floating_timestamp_cannot_enter_content_addressed_json(
    tmp_path: Path,
    field: str,
) -> None:
    with pytest.raises(
        worker_receipts.WorkerExecutionError,
        match="floating-point",
    ):
        _reseal_hashed_json(
            tmp_path / "seed.json",
            prefix="completion",
            digest_field="completion_sha256",
            payload={
                "schema_version": worker_receipts.COMPLETION_SCHEMA,
                field: 1.0,
            },
        )


@pytest.mark.parametrize(
    "document",
    ("arm", "completion", "publish_arm", "publish"),
)
def test_resealed_receipt_timestamps_require_exact_positive_integers(
    tmp_path: Path,
    document: str,
) -> None:
    published = document.startswith("publish")
    completed, parser = _run_staged_worker(
        tmp_path,
        publish_canonical=published,
    )

    for invalid in _INVALID_PERSISTED_TIMESTAMPS:
        if document == "arm":
            receipt_path, digest = _reseal_arm_and_completion(
                completed,
                lambda payload, value=invalid: payload.__setitem__(
                    "armed_at_unix_ns", value
                ),
            )
            with pytest.raises(
                worker_receipts.WorkerExecutionError,
                match="timestamp.*positive integer|positive integer.*timestamp",
            ):
                _validate_staged(
                    tmp_path,
                    receipt_path=receipt_path,
                    completion_sha256=digest,
                    parser=parser,
                )
        elif document == "completion":
            receipt_path, digest = _reseal_completion(
                completed,
                lambda payload, value=invalid: payload.__setitem__(
                    "completed_at_unix_ns", value
                ),
            )
            with pytest.raises(
                worker_receipts.WorkerExecutionError,
                match="timestamp.*positive integer|positive integer.*timestamp",
            ):
                _validate_staged(
                    tmp_path,
                    receipt_path=receipt_path,
                    completion_sha256=digest,
                    parser=parser,
                )
        else:
            field = (
                "armed_at_unix_ns"
                if document == "publish_arm"
                else "published_at_unix_ns"
            )
            publish_path, publish_digest = _reseal_publication(
                completed,
                document=document,
                mutate=lambda payload, value=invalid: payload.__setitem__(
                    field, value
                ),
            )
            with pytest.raises(
                worker_receipts.WorkerExecutionError,
                match="timestamp.*positive integer|positive integer.*timestamp",
            ):
                _validate_published(
                    tmp_path,
                    completed=completed,
                    publish_path=publish_path,
                    publish_sha256=publish_digest,
                    parser=parser,
                )

    if document == "arm":
        receipt_path, digest = _reseal_arm_and_completion(
            completed,
            lambda payload: payload.__setitem__("armed_at_unix_ns", 1),
        )
        _validate_staged(
            tmp_path,
            receipt_path=receipt_path,
            completion_sha256=digest,
            parser=parser,
        )
    elif document == "completion":
        receipt_path, digest = _reseal_completion(
            completed,
            lambda payload: payload.__setitem__("completed_at_unix_ns", 1),
        )
        _validate_staged(
            tmp_path,
            receipt_path=receipt_path,
            completion_sha256=digest,
            parser=parser,
        )
    else:
        field = (
            "armed_at_unix_ns"
            if document == "publish_arm"
            else "published_at_unix_ns"
        )
        publish_path, publish_digest = _reseal_publication(
            completed,
            document=document,
            mutate=lambda payload: payload.__setitem__(field, 1),
        )
        _validate_published(
            tmp_path,
            completed=completed,
            publish_path=publish_path,
            publish_sha256=publish_digest,
            parser=parser,
        )


def test_redigested_typed_incorporation_member_rejects_boolean_index(
    tmp_path: Path,
) -> None:
    fixture = typed_fixtures.build_typed_fixture(tmp_path)
    member_path = (
        Path(fixture.incorporation.incorporation_path).parent
        / "member-0000.json"
    )
    member = json.loads(member_path.read_text(encoding="utf-8"))
    member["index"] = False
    member = typed_fixtures._resign(member, "member_digest")
    typed_fixtures._write_mutable(member_path, canonical_file_bytes(member))

    with pytest.raises(
        typed_output.TypedWorkerOutputAuthorityError,
        match="incorporation.*index|index.*integer",
    ):
        typed_output.replay_typed_worker_output(fixture.witness)


def test_backend_runtime_contract_rejects_boolean_byte_count(
    tmp_path: Path,
) -> None:
    backend = "claude"
    candidates = tuple(snapshot._BACKEND_RUNTIME_CANDIDATES[backend])
    assert candidates
    contract = {
        "schema": snapshot._BACKEND_RUNTIME_CONTRACT_SCHEMA,
        "backend": backend,
        "project_root_sha256": snapshot._project_identity(tmp_path),
        "isolation_mode": (
            "EXACT_OWNED_PATH_FALLBACK"
            if candidates[1:]
            else "NO_EPHEMERAL_PATHS"
        ),
        "ephemeral_paths": list(candidates[1:]),
        "preexisting_bound_inputs": [
            {
                "path": candidates[0],
                "bytes": True,
                "sha256": "0" * 64,
            }
        ],
    }
    config = {
        "cli_backend": backend,
        "_backend_runtime_contract": contract,
    }

    with pytest.raises(snapshot.SnapshotInputError, match="preexisting-input row"):
        snapshot._validated_backend_runtime_contract(config, tmp_path)
