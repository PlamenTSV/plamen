"""Independent negative-closure/read-set contracts for report canonicalization.

The canonical report-index transaction may bind only the typed provider graph
reachable from provider bundle roots.  Directory membership is not semantic
authority: unrelated files and unrelated worker receipts must not alter the
contract.  Conversely, every pre-existing staged file read by deterministic
derivation must be present in the authenticated PhaseIO denominator or be an
authenticated output prestate.

This module is test-only and never launches a model or network request.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
from typing import Any
from unittest.mock import patch

import pytest

# Initialize the supported lazy-import order used by the report pipeline.
import plamen_mechanical as _mechanical  # noqa: F401
import closure_broker_v2 as CLOSURE
import plamen_driver as DRIVER
from artifact_ledger import (
    read_artifact_ledger,
    record_work_unit_inputs,
    validate_work_unit_inputs,
)
import test_negative_closure_broker_live_cutover as NEGATIVE
import test_report_index_canonical_successor_a0_blocking as CANONICAL


_CLOSURE_ROOTS = (
    "negative_closure_provider_bundles",
    "closure-inputs",
    "closure-provider-output",
    "closure-runtime",
    ".worker_execution_receipts",
)


def _scratchpad_inputs(contract: Any) -> set[str]:
    return {
        str(identity).split(":", 1)[1]
        for identity in (
            *contract.immutable_inputs,
            *contract.bounded_lookup_inputs,
        )
        if str(identity).startswith("scratchpad:")
    }


def _closure_paths(values: set[str]) -> set[str]:
    return {
        value
        for value in values
        if any(
            value == root or value.startswith(root + "/")
            for root in _CLOSURE_ROOTS
        )
    }


def _config_and_bundle(tmp_path: Path) -> tuple[dict[str, Any], Path]:
    config = CANONICAL._config(tmp_path)
    root = Path(config["scratchpad"])
    NEGATIVE._materialize_exhaustive_provider_bundle(root)
    return config, root


def _typed_provider_read_set(root: Path) -> set[str]:
    """Observe the validated graph walk, excluding its rebuilt projection."""

    observed: set[str] = set()
    original_read_bytes = Path.read_bytes
    original_read_text = Path.read_text
    resolved_root = root.resolve()

    def remember(path: Path) -> None:
        try:
            relative = Path(path).resolve().relative_to(resolved_root)
        except (OSError, ValueError):
            return
        observed.add(relative.as_posix())

    def read_bytes(path: Path) -> bytes:
        remember(path)
        return original_read_bytes(path)

    def read_text(path: Path, *args: Any, **kwargs: Any) -> str:
        remember(path)
        return original_read_text(path, *args, **kwargs)

    with (
        patch.object(Path, "read_bytes", read_bytes),
        patch.object(Path, "read_text", read_text),
    ):
        decision = CLOSURE.write_central_negative_closure_authority(
            root
        ).resolve(
            work_item=NEGATIVE._work(),
            requested_effect=CLOSURE.REFUTED_FULL,
        )
    assert decision["status"] == CLOSURE.AUTHORIZED
    # The stage deliberately rebuilds this root-addressed projection from the
    # provider graph.  It is not an input to itself.
    observed.discard("negative_closure_broker_authority.json")
    return _closure_paths(observed)


def test_negative_closure_denominator_equals_typed_provider_read_graph(
    tmp_path: Path,
) -> None:
    config, root = _config_and_bundle(tmp_path)
    referenced = _typed_provider_read_set(root)

    contract, _launch = (
        DRIVER._report_index_canonical_contract_and_launch(root, config)
    )

    assert _closure_paths(_scratchpad_inputs(contract)) == referenced


@pytest.mark.parametrize(
    ("relative", "payload"),
    (
        (
            "negative_closure_provider_bundles/operator-notes.tmp",
            b"not a typed provider bundle\n",
        ),
        ("closure-inputs/unreferenced.bin", b"not referenced by a manifest\n"),
        (
            "closure-provider-output/unreferenced.json",
            b'{"schema_version":"unreferenced.output.v1"}\n',
        ),
        (
            "closure-runtime/unreferenced.bin",
            b"not an authenticated runtime output\n",
        ),
        (
            ".worker_execution_receipts/unrelated-worker/diagnostic.log",
            b"unrelated worker diagnostic\n",
        ),
    ),
    ids=(
        "provider-bundle-directory",
        "provider-input-directory",
        "provider-output-directory",
        "provider-runtime-directory",
        "worker-receipt-directory",
    ),
)
def test_unreferenced_directory_member_is_not_canonical_input(
    tmp_path: Path,
    relative: str,
    payload: bytes,
) -> None:
    config, root = _config_and_bundle(tmp_path)
    before, _launch = (
        DRIVER._report_index_canonical_contract_and_launch(root, config)
    )
    referenced = _typed_provider_read_set(root)

    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    after, _launch = (
        DRIVER._report_index_canonical_contract_and_launch(root, config)
    )

    assert relative not in _scratchpad_inputs(after), (
        "recursive directory membership expanded the canonical semantic "
        f"denominator: {relative}; before={before.digest}; "
        f"after={after.digest}"
    )
    assert _closure_paths(_scratchpad_inputs(after)) == referenced
    assert after.digest == before.digest, (
        f"unreferenced file staled canonical contract: {relative}; "
        f"before={before.digest}; after={after.digest}"
    )


def test_unrelated_valid_worker_receipt_does_not_stale_armed_transaction(
    tmp_path: Path,
) -> None:
    config, root = _config_and_bundle(tmp_path)
    contract, launch = (
        DRIVER._report_index_canonical_contract_and_launch(root, config)
    )
    record_work_unit_inputs(
        root,
        tmp_path,
        contract,
        launch,
        run_id=config["_run_id"],
    )
    assert validate_work_unit_inputs(
        root,
        tmp_path,
        contract,
        launch,
        run_id=config["_run_id"],
    ) == []

    completion = next(
        (root / ".worker_execution_receipts").rglob("completion_*.json")
    )
    unrelated = (
        root
        / ".worker_execution_receipts"
        / "unrelated-valid-worker"
        / completion.name
    )
    unrelated.parent.mkdir(parents=True)
    shutil.copyfile(completion, unrelated)
    relative = unrelated.relative_to(root).as_posix()

    reconstructed, _launch = (
        DRIVER._report_index_canonical_contract_and_launch(root, config)
    )
    assert relative not in _scratchpad_inputs(reconstructed), (
        "a valid but unreferenced worker receipt became report semantics; "
        f"before={contract.digest}; after={reconstructed.digest}"
    )
    assert reconstructed.digest == contract.digest
    assert validate_work_unit_inputs(
        root,
        tmp_path,
        contract,
        launch,
        run_id=config["_run_id"],
    ) == []


def _record_stage_read(
    *,
    path: Path,
    raw: bytes,
    stage: Path,
    trace: dict[str, set[str]],
) -> None:
    try:
        relative = path.resolve().relative_to(stage.resolve()).as_posix()
    except (OSError, ValueError):
        return
    trace.setdefault(relative, set()).add(
        hashlib.sha256(raw).hexdigest()
    )


def test_canonical_derivation_read_trace_closes_over_authenticated_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Actual staged reads must reconcile to input bindings/output prestates."""

    # Negative-closure graph closure is exercised independently above.  Keep
    # this derivation trace free of worker-receipt atomic-write races so a
    # failure identifies an undeclared semantic read rather than directory
    # enumeration.
    config = CANONICAL._config(tmp_path)
    root = Path(config["scratchpad"])
    CANONICAL._prepare_model_attempt(
        config,
        CANONICAL._report_index_bytes(
            medium_summary=1,
            medium_master=2,
        ),
    )
    contract, _launch = (
        DRIVER._report_index_canonical_contract_and_launch(root, config)
    )
    stage = (
        DRIVER._report_index_canonical_recovery_dir(root, contract)
        / "staged_target"
    )
    trace: dict[str, set[str]] = {}
    original_read_bytes = Path.read_bytes
    original_read_text = Path.read_text

    def read_bytes(path: Path) -> bytes:
        raw = original_read_bytes(path)
        _record_stage_read(path=Path(path), raw=raw, stage=stage, trace=trace)
        return raw

    def read_text(path: Path, *args: Any, **kwargs: Any) -> str:
        text = original_read_text(path, *args, **kwargs)
        try:
            raw = original_read_bytes(path)
        except OSError:
            # Atomic implementation temporaries can disappear immediately
            # after a successful text read.  They are write mechanics, not
            # stable semantic inputs, and therefore are not trace rows.
            return text
        _record_stage_read(path=Path(path), raw=raw, stage=stage, trace=trace)
        return text

    monkeypatch.setattr(Path, "read_bytes", read_bytes)
    monkeypatch.setattr(Path, "read_text", read_text)
    issues = DRIVER._run_report_index_canonicalization_transaction(
        CANONICAL._phase(),
        root,
        config,
    )
    assert issues == []

    unit = read_artifact_ledger(root)["work_units"][contract.key]
    bindings = unit["input_bindings"]
    output_paths = {item.path for item in contract.outputs}
    generated_control = {
        DRIVER._REPORT_INDEX_CANONICAL_JOURNAL,
        # Generated after the canonical input arm from the strictly replayed
        # live ledger; its digest is committed in the canonical journal below.
        "_artifact_state.json",
    }
    undeclared = (
        set(trace)
        - _scratchpad_inputs(contract)
        - output_paths
        - generated_control
    )
    trace_rows = [
        {"path": path, "sha256": digest}
        for path, digests in sorted(trace.items())
        for digest in sorted(digests)
    ]
    trace_digest = hashlib.sha256(
        json.dumps(
            trace_rows,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    assert undeclared == set(), (
        "canonical derivation read undeclared staged semantics: "
        f"{sorted(undeclared)}; trace_sha256={trace_digest}"
    )
    journal = json.loads(
        (root / DRIVER._REPORT_INDEX_CANONICAL_JOURNAL).read_text(
            encoding="utf-8"
        )
    )
    projected_ledger = journal["producer_ledger_projection"]
    expected_projection = DRIVER._canonical_json_bytes(
        DRIVER._report_verifier_phaseio_authority_projection(root)
    )
    assert projected_ledger == {
        "status": "ACTIVE",
        "sha256": hashlib.sha256(expected_projection).hexdigest(),
        "size": len(expected_projection),
    }
    for relative, digests in trace.items():
        if relative in output_paths or relative in generated_control:
            continue
        binding = bindings.get("scratchpad:" + relative)
        assert isinstance(binding, dict), (
            f"read trace lacks authenticated binding: {relative}; "
            f"trace_sha256={trace_digest}"
        )
        assert binding.get("sha256") in digests, (
            f"read bytes differ from authenticated binding: {relative}; "
            f"trace_sha256={trace_digest}"
        )
