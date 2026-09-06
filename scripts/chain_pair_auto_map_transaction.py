"""Journaled paired successor for the final chain auto-map repair.

The repair is derived without mutating ``hypotheses.md`` or
``finding_mapping.md``.  Both postimages are first published as one
content-addressed staging generation, then one DRIVER PhaseIO successor is
armed over the pair.  A small pending pointer is written before either mutable
root changes.  Recovery accepts only the receipt-bound before or after bytes
for each member and completes the pair; an arbitrary third state is preserved
as debt and is never certified.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
from typing import Any, Callable, Mapping, Sequence
import uuid

from artifact_ledger import (
    ArtifactLedgerError,
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
    semantic_import_authority,
    validate_work_unit_artifacts,
    validate_work_unit_inputs,
)
from bounded_artifact_io import read_bounded_regular_bytes
from phase_io_contracts import (
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    canonical_work_unit_key,
)


SCHEMA = "plamen.chain_pair_auto_map_transaction.v1"
RECEIPT_SCHEMA = "plamen.chain_pair_auto_map_receipt.v1"
ROOT = "_chain_pair_auto_map"
PENDING = f"{ROOT}/pending.json"
HYPOTHESES = "hypotheses.md"
MAPPING = "finding_mapping.md"
PAIR = (HYPOTHESES, MAPPING)
ENABLER = "enabler_results.md"
MODEL_BUNDLE = (*PAIR, ENABLER)
MAX_BYTES = 64 * 1024 * 1024
_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)


class ChainPairAutoMapTransactionError(RuntimeError):
    """The paired repair could not be derived, recovered, or committed."""


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


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


def _digest(value: Mapping[str, Any]) -> str:
    return _sha(_canonical_bytes(value))


def _binding(raw: bytes) -> dict[str, Any]:
    return {"sha256": _sha(raw), "size": len(raw)}


def _read(root: Path, relative: str) -> bytes:
    return read_bounded_regular_bytes(
        root.joinpath(*PurePosixPath(relative).parts),
        MAX_BYTES,
    )


def _atomic_bytes(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0),
            0o600,
        )
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _dimensions(config: Mapping[str, Any], run_id: str) -> dict[str, str]:
    result = {
        "pipeline": str(config.get("pipeline") or "sc").strip().lower(),
        "mode": str(config.get("mode") or "core").strip().lower(),
        "ecosystem": str(
            config.get("ecosystem") or config.get("language") or ""
        ).strip().lower(),
        "backend": str(
            config.get("backend") or config.get("cli_backend") or "claude"
        ).strip().lower(),
        "phase_name": "chain",
        "run_id": str(run_id or "").strip(),
    }
    if (
        result["pipeline"] != "sc"
        or not result["mode"]
        or not result["ecosystem"]
        or result["backend"] not in {"claude", "codex"}
        or not result["run_id"]
    ):
        raise ChainPairAutoMapTransactionError(
            "chain pair auto-map run tuple is invalid"
        )
    return result


def _contract(
    dimensions: Mapping[str, str],
    *,
    generation: str,
    stage: bool,
    exact_inputs: Sequence[str],
) -> tuple[PhaseIOContract, LaunchSpec]:
    work_id = (
        f"final_pair_auto_map_stage.{generation}"
        if stage
        else f"final_pair_auto_map_apply.{generation}"
    )
    owner = canonical_work_unit_key(
        dimensions["pipeline"],
        dimensions["mode"],
        dimensions["ecosystem"],
        dimensions["backend"],
        "chain",
        work_id,
    )
    generation_root = f"{ROOT}/generation_{generation}"
    output_paths = (
        (
            f"{generation_root}/{HYPOTHESES}",
            f"{generation_root}/{MAPPING}",
            f"{generation_root}/receipt.json",
        )
        if stage
        else MODEL_BUNDLE
    )
    contract = PhaseIOContract(
        pipeline=dimensions["pipeline"],
        mode=dimensions["mode"],
        ecosystem=dimensions["ecosystem"],
        backend=dimensions["backend"],
        phase="chain",
        work_unit_id=work_id,
        outputs=tuple(
            ArtifactSpec(
                root="scratchpad",
                path=path,
                owner_key=owner,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="CREATE" if stage else "REPLACE",
                schema_version=(
                    RECEIPT_SCHEMA
                    if stage and path.endswith("/receipt.json")
                    else "unstructured.v1"
                ),
                minimum_gate=(
                    "CONTENT_ADDRESSED_PAIRED_POSTIMAGE"
                    if stage
                    else "JOURNALED_PAIRED_ROOT_SUCCESSOR"
                ),
                consumers=(
                    ("chain/final_pair_auto_map_apply",)
                    if stage
                    else ("sc_verify_queue/preverify_chain_pair",)
                ),
            )
            for path in output_paths
        ),
        immutable_inputs=tuple(
            "scratchpad:" + str(path) for path in sorted(set(exact_inputs))
        ),
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
        timeout_s=120,
        exec_mode="python",
        tool_policy=("filesystem",),
    )
    return contract, launch


def _publish_stage(
    root: Path,
    *,
    generation: str,
    outputs: Mapping[str, bytes],
) -> None:
    parent = root / ROOT
    final = parent / f"generation_{generation}"
    expected = {
        final / HYPOTHESES: outputs[HYPOTHESES],
        final / MAPPING: outputs[MAPPING],
        final / "receipt.json": outputs["receipt.json"],
    }
    if final.is_dir():
        for path, raw in expected.items():
            if _read(root, path.relative_to(root).as_posix()) != raw:
                raise ChainPairAutoMapTransactionError(
                    "existing chain auto-map stage has foreign bytes"
                )
        return
    if final.exists():
        raise ChainPairAutoMapTransactionError(
            "chain auto-map generation path is not a directory"
        )
    parent.mkdir(parents=True, exist_ok=True)
    staging = parent / f".s_{generation[:12]}_{uuid.uuid4().hex[:12]}"
    staging.mkdir()
    try:
        for name in (*PAIR, "receipt.json"):
            _atomic_bytes(staging / name, outputs[name])
        os.replace(staging, final)
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def _receipt(
    root: Path,
    dimensions: Mapping[str, str],
    *,
    mapped_ids: Sequence[str],
    postimages: Mapping[str, bytes],
    depth_inputs: Sequence[str],
    source_authorities: Mapping[str, Mapping[str, Any]],
) -> tuple[str, dict[str, Any], dict[str, bytes]]:
    before = {relative: _read(root, relative) for relative in MODEL_BUNDLE}
    after = {
        relative: bytes(postimages.get(relative, before[relative]))
        for relative in MODEL_BUNDLE
    }
    core = {
        "schema_version": RECEIPT_SCHEMA,
        **dict(dimensions),
        "before": {
            relative: _binding(before[relative]) for relative in MODEL_BUNDLE
        },
        "after": {
            relative: _binding(after[relative]) for relative in MODEL_BUNDLE
        },
        "mapped_ids": sorted(set(str(value) for value in mapped_ids)),
        "depth_inputs": list(sorted(set(depth_inputs))),
        "source_authorities": {
            relative: dict(source_authorities[relative])
            for relative in sorted(source_authorities)
        },
        "deriver_code_sha256": _sha(
            Path(__file__).with_name("plamen_validators.py").read_bytes()
        ),
        "transaction_code_sha256": _sha(Path(__file__).read_bytes()),
        "candidate_disposition": "ADDITIVE_PRESERVE_ALL",
        "proof_authority": "NONE",
    }
    generation = _digest(core)
    unsigned = {
        **core,
        "generation_digest": generation,
        "publication_order": list(MODEL_BUNDLE),
        "recovery_policy": "EACH_MEMBER_MUST_MATCH_BEFORE_OR_AFTER",
    }
    receipt = {**unsigned, "receipt_digest": _digest(unsigned)}
    return generation, receipt, {
        HYPOTHESES: after[HYPOTHESES],
        MAPPING: after[MAPPING],
        "receipt.json": _canonical_bytes(receipt),
    }


def _validated_source_authorities(
    root: Path,
    project: Path,
    *,
    run_id: str,
    depth_inputs: Sequence[str],
) -> dict[str, dict[str, Any]]:
    """Require one exact chain MODEL pair plus exact same-run depth inputs."""

    authorities: dict[str, dict[str, Any]] = {}
    for relative in (*MODEL_BUNDLE, *depth_inputs):
        try:
            authority = semantic_import_authority(
                root,
                project,
                "scratchpad:" + relative,
                run_id=run_id,
            )
        except (ArtifactLedgerError, OSError, TypeError, ValueError) as exc:
            raise ChainPairAutoMapTransactionError(
                f"{relative}: exact current-run source authority is "
                f"unavailable: {type(exc).__name__}: {exc}"
            ) from exc
        if (
            authority.get("authority_kind") != "EXACT_PHASE_IO_PRODUCER"
            or authority.get("identity") != "scratchpad:" + relative
            or authority.get("run_id") != run_id
        ):
            raise ChainPairAutoMapTransactionError(
                f"{relative}: source is not an exact current-run PhaseIO "
                "producer"
            )
        raw = _read(root, relative)
        if (
            authority.get("source_sha256") != _sha(raw)
            or authority.get("source_size") != len(raw)
        ):
            raise ChainPairAutoMapTransactionError(
                f"{relative}: source authority does not bind the live bytes"
            )
        authorities[relative] = dict(authority)

    bundle_owners = {
        str(authorities[relative].get("producer_work_unit_key") or "")
        for relative in MODEL_BUNDLE
    }
    bundle_contracts = {
        str(authorities[relative].get("producer_contract_digest") or "")
        for relative in MODEL_BUNDLE
    }
    if len(bundle_owners) != 1 or len(bundle_contracts) != 1:
        raise ChainPairAutoMapTransactionError(
            "final chain model bundle does not share one exact producer "
            "generation"
        )
    owner = next(iter(bundle_owners))
    if not owner.endswith("/chain/model"):
        raise ChainPairAutoMapTransactionError(
            "final chain model bundle producer is not the registered "
            "chain/model unit"
        )
    return authorities


def _load_receipt(root: Path, generation: str) -> dict[str, Any]:
    if not _HEX64.fullmatch(generation):
        raise ChainPairAutoMapTransactionError(
            "pending chain auto-map generation is invalid"
        )
    raw = _read(root, f"{ROOT}/generation_{generation}/receipt.json")
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ChainPairAutoMapTransactionError(
            "pending chain auto-map receipt is malformed"
        ) from exc
    unsigned = {
        key: item for key, item in value.items()
        if key != "receipt_digest"
    }
    if (
        value.get("schema_version") != RECEIPT_SCHEMA
        or value.get("generation_digest") != generation
        or value.get("receipt_digest") != _digest(unsigned)
    ):
        raise ChainPairAutoMapTransactionError(
            "pending chain auto-map receipt digest is invalid"
        )
    return value


def _apply_or_recover(
    root: Path,
    project: Path,
    dimensions: Mapping[str, str],
    *,
    generation: str,
    receipt: Mapping[str, Any],
    failpoint: Callable[[str], None] | None,
) -> tuple[bool, list[str]]:
    stage_receipt = f"{ROOT}/generation_{generation}/receipt.json"
    contract, launch = _contract(
        dimensions,
        generation=generation,
        stage=False,
        exact_inputs=(stage_receipt,),
    )
    run_id = dimensions["run_id"]
    ledger = read_artifact_ledger(root)
    existing = ledger.get("work_units", {}).get(contract.key)
    if not isinstance(existing, Mapping):
        record_work_unit_inputs(
            root, project, contract, launch, run_id=run_id
        )
    input_issues = validate_work_unit_inputs(
        root, project, contract, launch, run_id=run_id
    )
    if input_issues:
        return False, list(input_issues)

    pointer = {
        "schema_version": SCHEMA,
        "run_id": run_id,
        "generation_digest": generation,
        "apply_work_unit_key": contract.key,
    }
    _atomic_bytes(root / PENDING, _canonical_bytes(pointer))
    if failpoint is not None:
        failpoint("after_chain_pair_pending_write")

    member_states: dict[str, str] = {}
    for relative in MODEL_BUNDLE:
        current = _read(root, relative)
        before = receipt["before"][relative]
        after = receipt["after"][relative]
        current_binding = _binding(current)
        if current_binding == after:
            member_states[relative] = "after"
        elif current_binding == before:
            member_states[relative] = "before"
        else:
            raise ChainPairAutoMapTransactionError(
                f"{relative}: arbitrary third state during paired recovery"
            )

    # Validate the complete three-member lattice before the first root write.
    # In particular, the unchanged enabler member is not an afterthought: a
    # foreign mutation there vetoes pair roll-forward without partially
    # applying the mapping member first.
    for relative in MODEL_BUNDLE:
        if member_states[relative] == "before":
            before = receipt["before"][relative]
            after = receipt["after"][relative]
            if before == after:
                continue
            staged = _read(
                root,
                f"{ROOT}/generation_{generation}/{relative}",
            )
            if _binding(staged) != after:
                raise ChainPairAutoMapTransactionError(
                    f"{relative}: staged postimage differs from receipt"
                )
            _atomic_bytes(root / relative, staged)
        if failpoint is not None:
            failpoint(f"after_chain_pair_apply_{relative}")

    record_work_unit_artifacts(
        root,
        project,
        contract,
        launch,
        run_id=run_id,
        actor="DRIVER",
    )
    output_issues = validate_work_unit_artifacts(
        root,
        project,
        contract,
        launch,
        run_id=run_id,
        actor="DRIVER",
    )
    if output_issues:
        return False, list(output_issues)
    (root / PENDING).unlink(missing_ok=True)
    return True, []


def _recover_pending(
    root: Path,
    project: Path,
    dimensions: Mapping[str, str],
    *,
    failpoint: Callable[[str], None] | None,
) -> dict[str, Any] | None:
    path = root / PENDING
    if not path.is_file():
        return None
    try:
        pointer = json.loads(
            read_bounded_regular_bytes(path, 64 * 1024).decode(
                "utf-8", errors="strict"
            )
        )
        generation = str(pointer.get("generation_digest") or "")
        if (
            pointer.get("schema_version") != SCHEMA
            or pointer.get("run_id") != dimensions["run_id"]
        ):
            raise ChainPairAutoMapTransactionError(
                "pending chain auto-map pointer belongs to another run"
            )
        receipt = _load_receipt(root, generation)
        if any(
            receipt.get(key) != value
            for key, value in dimensions.items()
        ):
            raise ChainPairAutoMapTransactionError(
                "pending chain auto-map receipt run tuple drifted"
            )
        committed, issues = _apply_or_recover(
            root,
            project,
            dimensions,
            generation=generation,
            receipt=receipt,
            failpoint=failpoint,
        )
        return {
            "schema_version": SCHEMA,
            "state": (
                "OUTPUT_COMMITTED" if committed else "RECOVERY_DEBT"
            ),
            "safe_to_project": committed,
            "recovered": True,
            "mapped_ids": list(receipt.get("mapped_ids") or []),
            "generation_digest": generation,
            "issues": issues,
        }
    except (
        ArtifactLedgerError,
        OSError,
        TypeError,
        ValueError,
        ChainPairAutoMapTransactionError,
    ) as exc:
        return {
            "schema_version": SCHEMA,
            "state": "RECOVERY_DEBT",
            "safe_to_project": False,
            "recovered": True,
            "mapped_ids": [],
            "generation_digest": None,
            "issues": [f"{type(exc).__name__}: {exc}"],
        }


def run_chain_pair_auto_map_transaction(
    *,
    scratchpad: Path,
    project_root: Path,
    config: Mapping[str, Any],
    run_id: str,
    derive: Callable[[Path], tuple[list[str], Mapping[str, bytes]]],
    failpoint: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Recover any pending pair, otherwise derive and commit one successor."""

    root = Path(scratchpad)
    project = Path(project_root)
    dimensions = _dimensions(config, run_id)
    recovered = _recover_pending(
        root,
        project,
        dimensions,
        failpoint=failpoint,
    )
    if recovered is not None:
        return recovered

    mapped_ids, derived = derive(root)
    if not derived:
        return {
            "schema_version": SCHEMA,
            "state": "NOT_REQUIRED",
            "safe_to_project": True,
            "recovered": False,
            "mapped_ids": list(mapped_ids),
            "generation_digest": None,
            "issues": [],
        }
    depth_inputs = tuple(sorted(
        path.relative_to(root).as_posix()
        for path in root.glob("depth_*_findings.md")
        if path.is_file() and not path.is_symlink()
    ))
    try:
        source_authorities = _validated_source_authorities(
            root,
            project,
            run_id=dimensions["run_id"],
            depth_inputs=depth_inputs,
        )
    except (
        ArtifactLedgerError,
        OSError,
        TypeError,
        ValueError,
        ChainPairAutoMapTransactionError,
    ) as exc:
        return {
            "schema_version": SCHEMA,
            "state": "STAGE_DEBT",
            "safe_to_project": False,
            "recovered": False,
            "mapped_ids": [],
            "generation_digest": None,
            "issues": [f"{type(exc).__name__}: {exc}"],
        }
    generation, receipt, outputs = _receipt(
        root,
        dimensions,
        mapped_ids=mapped_ids,
        postimages=derived,
        depth_inputs=depth_inputs,
        source_authorities=source_authorities,
    )
    stage_inputs = (*MODEL_BUNDLE, *depth_inputs)
    stage_contract, stage_launch = _contract(
        dimensions,
        generation=generation,
        stage=True,
        exact_inputs=stage_inputs,
    )
    try:
        record_work_unit_inputs(
            root,
            project,
            stage_contract,
            stage_launch,
            run_id=dimensions["run_id"],
        )
        stage_input_issues = validate_work_unit_inputs(
            root,
            project,
            stage_contract,
            stage_launch,
            run_id=dimensions["run_id"],
        )
        if stage_input_issues:
            raise ChainPairAutoMapTransactionError(
                "chain auto-map stage input authority failed: "
                + "; ".join(stage_input_issues)
            )
        _publish_stage(
            root,
            generation=generation,
            outputs=outputs,
        )
        record_work_unit_artifacts(
            root,
            project,
            stage_contract,
            stage_launch,
            run_id=dimensions["run_id"],
            actor="DRIVER",
        )
        stage_output_issues = validate_work_unit_artifacts(
            root,
            project,
            stage_contract,
            stage_launch,
            run_id=dimensions["run_id"],
            actor="DRIVER",
        )
        if stage_output_issues:
            raise ChainPairAutoMapTransactionError(
                "chain auto-map stage output authority failed: "
                + "; ".join(stage_output_issues)
            )
        committed, issues = _apply_or_recover(
            root,
            project,
            dimensions,
            generation=generation,
            receipt=receipt,
            failpoint=failpoint,
        )
        return {
            "schema_version": SCHEMA,
            "state": (
                "OUTPUT_COMMITTED" if committed else "APPLY_DEBT"
            ),
            "safe_to_project": committed,
            "recovered": False,
            "mapped_ids": list(mapped_ids),
            "generation_digest": generation,
            "issues": issues,
        }
    except (
        ArtifactLedgerError,
        OSError,
        RuntimeError,
        TypeError,
        ValueError,
    ) as exc:
        # No untracked fallback writes: the original pair remains visible and
        # the baseline gate debt preserves every missing candidate for review.
        return {
            "schema_version": SCHEMA,
            "state": "STAGE_DEBT",
            "safe_to_project": False,
            "recovered": False,
            "mapped_ids": [],
            "generation_digest": generation,
            "issues": [f"{type(exc).__name__}: {exc}"],
        }


__all__ = [
    "ChainPairAutoMapTransactionError",
    "ENABLER",
    "HYPOTHESES",
    "MAPPING",
    "MODEL_BUNDLE",
    "PENDING",
    "ROOT",
    "SCHEMA",
    "run_chain_pair_auto_map_transaction",
]
