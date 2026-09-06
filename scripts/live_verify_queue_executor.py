"""Ledger-backed execution for the production verify-queue transaction.

This module deliberately owns execution rather than topology.  The resolved
plan is data, the injected semantic executor may derive only private T0..T8
postimages, and this module alone performs the T9 public receipt-last
compare-and-swap publication.

The PhaseIO helpers are kept in a separate module so both the legacy
transaction scaffold and the live cutover use the same non-self-certifying
authority boundary.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any, Callable, Mapping, Sequence

import rooted_path_io as _rooted_io
from phase_io_contracts import ConditionalOutputReceipt
from verify_queue_phaseio_authority import (
    arm_transaction_unit,
    commit_transaction_unit,
    validate_transaction_authority,
)
from live_verify_queue_prearm_inputs import (
    PRESENCE_AUTHORITY_FILE,
    validate_prearm_presence_authority,
)


LIVE_PLAN_SCHEMA = "plamen.live_verify_queue_plan.v1"
LIVE_RECEIPT_SCHEMA = "plamen.live_verify_queue_receipt.v1"
LIVE_BUNDLE_SCHEMA = "plamen.live_verify_queue_publication_bundle.v1"
FINAL_RECEIPT = "verify_queue_transaction.receipt.json"
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)


class LiveVerifyQueueError(RuntimeError):
    """The live queue transaction cannot be completed without losing authority."""

    def __init__(
        self,
        message: str,
        *,
        durability_debt: Mapping[str, Any] | None = None,
    ) -> None:
        self.durability_debt = (
            dict(durability_debt) if durability_debt is not None else None
        )
        super().__init__(message)


class LiveVerifyQueueInjectedFailure(RuntimeError):
    """A deterministic test/diagnostic failpoint."""


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


def _stable_digest(value: Any) -> str:
    return _digest_bytes(_canonical_bytes(value))


def _safe_relative(value: Any) -> str:
    text = str(value or "").strip().replace("\\", "/")
    path = PurePosixPath(text)
    if (
        not text
        or path.is_absolute()
        or re.match(r"^[A-Za-z]:", text)
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(token in text for token in "*?[")
    ):
        raise LiveVerifyQueueError(f"unsafe live verify-queue path: {value!r}")
    return path.as_posix()


def _path_for(
    scratchpad: Path,
    project_root: Path,
    relative: str,
) -> Path:
    token = str(relative)
    if token.startswith("project::"):
        return project_root / _safe_relative(token[len("project::"):])
    return scratchpad / _safe_relative(token)


def _status_path(unit: Mapping[str, Any]) -> str:
    matches = [
        str(row.get("path") or "")
        for row in unit.get("outputs", ())
        if isinstance(row, Mapping)
        and str(row.get("path") or "").endswith("/status.json")
    ]
    if len(matches) != 1:
        raise LiveVerifyQueueError(
            f"{unit.get('work_unit_id')}: exact status output is absent"
        )
    return _safe_relative(matches[0])


def _effective_inputs(
    scratchpad: Path,
    unit: Mapping[str, Any],
) -> tuple[str, ...]:
    values = [str(value) for value in unit.get("exact_inputs", ())]
    conditional = unit.get("delivery_state_exact_inputs")
    if isinstance(conditional, Mapping):
        # Compatibility for the first transaction scaffold.  The live plan
        # closes its conditionals in T5/T8 and does not use this branch.
        status = json.loads(
            (scratchpad / "_verify_queue_transaction/t4/status.json")
            .read_text(encoding="utf-8", errors="strict")
        )
        selected = conditional.get(str(status.get("state") or ""))
        if not isinstance(selected, Sequence) or isinstance(
            selected, (str, bytes)
        ):
            raise LiveVerifyQueueError(
                f"{unit.get('work_unit_id')}: conditional input state is absent"
            )
        values.extend(str(value) for value in selected)
    return tuple(dict.fromkeys(values))


def _read_frozen_inputs(
    *,
    scratchpad: Path,
    project_root: Path,
    inputs: Sequence[str],
) -> tuple[dict[str, bytes], dict[str, str]]:
    frozen: dict[str, bytes] = {}
    digests: dict[str, str] = {}
    for relative in inputs:
        path = _path_for(scratchpad, project_root, str(relative))
        if not path.is_file() or path.is_symlink():
            raise LiveVerifyQueueError(
                f"required live verify-queue input unavailable: {relative}"
            )
        raw = path.read_bytes()
        frozen[str(relative)] = raw
        digests[str(relative)] = _digest_bytes(raw)
    return frozen, dict(sorted(digests.items()))


def _contract_input_paths(contract: Any) -> tuple[str, ...]:
    """Project canonical PhaseIO identities back into executor path tokens."""

    values: list[str] = []
    for identity in contract.immutable_inputs:
        root, relative = str(identity).split(":", 1)
        if root == "scratchpad":
            values.append(relative)
        elif root == "project":
            values.append("project::" + relative)
        else:
            raise LiveVerifyQueueError(
                f"unsupported PhaseIO input root: {root!r}"
            )
    return tuple(values)


def _status_payload(
    *,
    unit: Mapping[str, Any],
    run_id: str,
    plan_digest: str,
    state: str,
    input_digests: Mapping[str, str],
    output_digests: Mapping[str, str],
    conditional_states: Mapping[str, str],
) -> dict[str, Any]:
    unsigned = {
        "schema_version": "plamen.live_verify_queue_child_status.v1",
        "work_unit_id": str(unit["work_unit_id"]),
        "run_id": run_id,
        "plan_digest": plan_digest,
        "state": state,
        "safe_to_consume": state in {
            "COMMITTED_APPLIED",
            "COMMITTED_CLEAN_NOOP",
            "COMMITTED_DEBT_SAFE_BASE",
        },
        "proof_authority": "NONE",
        "input_digests": dict(sorted(input_digests.items())),
        "output_digests": dict(sorted(output_digests.items())),
        "conditional_states": dict(sorted(conditional_states.items())),
    }
    return {**unsigned, "status_digest": _stable_digest(unsigned)}


def _validate_plan(plan: Mapping[str, Any], run_id: str) -> None:
    if plan.get("schema_version") != LIVE_PLAN_SCHEMA:
        raise LiveVerifyQueueError("live verify-queue plan schema mismatch")
    supplied = str(plan.get("plan_digest") or "")
    unsigned = {key: value for key, value in plan.items() if key != "plan_digest"}
    if not _DIGEST_RE.fullmatch(supplied) or supplied != _stable_digest(unsigned):
        raise LiveVerifyQueueError("live verify-queue plan digest mismatch")
    if plan.get("run_id") != run_id:
        raise LiveVerifyQueueError("live verify-queue plan run mismatch")
    children = plan.get("children")
    if (
        not isinstance(children, Sequence)
        or isinstance(children, (str, bytes))
        or len(children) != 10
    ):
        raise LiveVerifyQueueError("live verify-queue child denominator is not T0..T9")


def _output_rows(unit: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    rows = unit.get("outputs")
    if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes)):
        raise LiveVerifyQueueError(
            f"{unit.get('work_unit_id')}: output denominator is malformed"
        )
    result: dict[str, Mapping[str, Any]] = {}
    for value in rows:
        if not isinstance(value, Mapping):
            raise LiveVerifyQueueError(
                f"{unit.get('work_unit_id')}: output row is malformed"
            )
        path = _safe_relative(value.get("path"))
        if path in result:
            raise LiveVerifyQueueError(
                f"{unit.get('work_unit_id')}: duplicate output {path}"
            )
        result[path] = value
    return result


def _normalize_semantic_result(
    *,
    unit: Mapping[str, Any],
    result: Mapping[str, Any],
    run_id: str,
    plan_digest: str,
    input_digests: Mapping[str, str],
) -> tuple[dict[str, bytes], dict[str, str], str]:
    state = str(result.get("state") or "")
    if state not in {
        "COMMITTED_APPLIED",
        "COMMITTED_CLEAN_NOOP",
        "COMMITTED_DEBT_SAFE_BASE",
    }:
        raise LiveVerifyQueueError(
            f"{unit.get('work_unit_id')}: invalid semantic terminal state {state!r}"
        )
    supplied = result.get("outputs")
    if not isinstance(supplied, Mapping):
        raise LiveVerifyQueueError(
            f"{unit.get('work_unit_id')}: semantic output bundle is absent"
        )
    outputs: dict[str, bytes] = {}
    for relative, raw in supplied.items():
        path = _safe_relative(relative)
        if not isinstance(raw, (bytes, bytearray)):
            raise LiveVerifyQueueError(
                f"{unit.get('work_unit_id')}: non-byte output {path}"
            )
        outputs[path] = bytes(raw)
    rows = _output_rows(unit)
    status_path = _status_path(unit)
    unknown = set(outputs) - (set(rows) - {status_path})
    if unknown:
        raise LiveVerifyQueueError(
            f"{unit.get('work_unit_id')}: undeclared outputs "
            + ", ".join(sorted(unknown))
        )
    conditional_states_raw = result.get("conditional_states") or {}
    if not isinstance(conditional_states_raw, Mapping):
        raise LiveVerifyQueueError(
            f"{unit.get('work_unit_id')}: conditional-state mapping malformed"
        )
    conditional_states = {
        _safe_relative(key): str(value).strip().upper()
        for key, value in conditional_states_raw.items()
    }
    required: set[str] = set()
    for path, row in rows.items():
        if path == status_path:
            continue
        if str(row.get("artifact_class") or "") != "CONDITIONAL":
            required.add(path)
            continue
        disposition = conditional_states.get(path)
        if disposition not in {"PRODUCED", "NOT_TRIGGERED", "TRIGGERED_EMPTY"}:
            raise LiveVerifyQueueError(
                f"{unit.get('work_unit_id')}: conditional state absent for {path}"
            )
        if (path in outputs) != (disposition == "PRODUCED"):
            raise LiveVerifyQueueError(
                f"{unit.get('work_unit_id')}: conditional bytes/state mismatch "
                f"for {path}"
            )
    if not required.issubset(outputs):
        raise LiveVerifyQueueError(
            f"{unit.get('work_unit_id')}: required output denominator incomplete"
        )
    output_digests = {
        path: _digest_bytes(raw) for path, raw in sorted(outputs.items())
    }
    status = _status_payload(
        unit=unit,
        run_id=run_id,
        plan_digest=plan_digest,
        state=state,
        input_digests=input_digests,
        output_digests=output_digests,
        conditional_states=conditional_states,
    )
    outputs[status_path] = _canonical_bytes(status)
    return outputs, conditional_states, state


def _cas_create_or_exact(path: Path, raw: bytes) -> None:
    """Publish an absent postimage or accept the exact crash-resume postimage.

    ``os.replace`` is intentionally forbidden here: a path that appears after
    PhaseIO recorded an absent prestate is foreign unless it is byte-exactly
    the already-derived postimage.
    """

    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        _rooted_io.durable_write_once_bytes(path, raw)
    except FileExistsError:
        raise LiveVerifyQueueError(
            f"CAS destination contains foreign bytes: {path.name}"
        )
    except _rooted_io.RootedPathIOError as exc:
        raise LiveVerifyQueueError(
            f"CAS destination cannot be published safely: {path.name}: {exc}",
            durability_debt=getattr(exc, "durability_debt", None),
        ) from exc


def _conditional_receipts(
    *,
    contract: Any,
    unit: Mapping[str, Any],
    conditional_states: Mapping[str, str],
) -> dict[str, ConditionalOutputReceipt]:
    receipts: dict[str, ConditionalOutputReceipt] = {}
    for path, row in _output_rows(unit).items():
        if str(row.get("artifact_class") or "") != "CONDITIONAL":
            continue
        identity = "scratchpad:" + path
        state = conditional_states.get(path, "")
        condition_id = str(row.get("condition_id") or "")
        if state == "PRODUCED":
            receipt_state = "PRODUCED"
            expected = 1
            produced = (identity,)
        elif state == "TRIGGERED_EMPTY":
            receipt_state = "TRIGGERED_EMPTY"
            expected = 0
            produced = ()
        else:
            receipt_state = "NOT_TRIGGERED"
            expected = 0
            produced = ()
        receipts[identity] = ConditionalOutputReceipt(
            work_unit_key=contract.key,
            contract_digest=contract.digest,
            artifact_identity=identity,
            condition_id=condition_id,
            state=receipt_state,
            expected_denominator=expected,
            produced_identities=produced,
        )
    return receipts


def _materialize_private_outputs(
    *,
    scratchpad: Path,
    outputs: Mapping[str, bytes],
    failpoint: Callable[[str], None] | None,
    index: int,
) -> None:
    for relative, raw in sorted(outputs.items()):
        _cas_create_or_exact(scratchpad / relative, raw)
    if failpoint is not None:
        failpoint(f"after_t{index}_materialize")


def _validate_t0_prearm_presence(
    *,
    scratchpad: Path,
    project_root: Path,
    plan: Mapping[str, Any],
    unit: Mapping[str, Any],
) -> None:
    authority = unit.get("prearm_presence_authority")
    if authority is None:
        return
    if not isinstance(authority, Mapping):
        raise LiveVerifyQueueError(
            "T0 prearm presence authority metadata is malformed"
        )
    issues = validate_prearm_presence_authority(
        scratchpad=scratchpad,
        project_root=project_root,
        pipeline=str(plan.get("pipeline") or ""),
        mode=str(plan.get("mode") or ""),
        ecosystem=str(plan.get("ecosystem") or ""),
        backend=str(plan.get("backend") or ""),
        phase_name=str(plan.get("phase_name") or ""),
        run_id=str(plan.get("run_id") or ""),
        authority_identity="scratchpad:" + PRESENCE_AUTHORITY_FILE,
        authority=authority,
    )
    if issues:
        raise LiveVerifyQueueError(
            "T0 prearm presence authority invalid: " + "; ".join(issues)
        )


def _bundle_payload(
    scratchpad: Path,
    bundle_path: str,
    plan: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, bytes], list[str]]:
    try:
        bundle = json.loads(
            (scratchpad / bundle_path).read_text(
                encoding="utf-8", errors="strict"
            )
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LiveVerifyQueueError("T8 publication bundle is unreadable") from exc
    if not isinstance(bundle, dict) or bundle.get("schema_version") != LIVE_BUNDLE_SCHEMA:
        raise LiveVerifyQueueError("T8 publication bundle schema mismatch")
    if bundle.get("plan_digest") != plan.get("plan_digest"):
        raise LiveVerifyQueueError("T8 publication bundle plan mismatch")
    public = {
        _safe_relative(value)
        for value in plan.get("public_output_denominator", ())
    }
    if set(bundle.get("public_output_denominator") or ()) != public:
        raise LiveVerifyQueueError("T8 public output denominator mismatch")
    files = bundle.get("files")
    if not isinstance(files, Mapping):
        raise LiveVerifyQueueError("T8 publication files mapping malformed")
    decoded: dict[str, bytes] = {}
    for raw_path, record in files.items():
        path = _safe_relative(raw_path)
        if path not in public or not isinstance(record, Mapping):
            raise LiveVerifyQueueError("T8 bundle contains undeclared public output")
        try:
            value = base64.b64decode(
                str(record.get("content_b64") or ""), validate=True
            )
        except (ValueError, TypeError) as exc:
            raise LiveVerifyQueueError(
                f"T8 bundle has invalid bytes for {path}"
            ) from exc
        if (
            record.get("sha256") != _digest_bytes(value)
            or record.get("size") != len(value)
        ):
            raise LiveVerifyQueueError(
                f"T8 bundle digest/size mismatch for {path}"
            )
        decoded[path] = value
    active = {_safe_relative(value) for value in bundle.get(
        "active_output_denominator", ()
    )}
    if active != set(decoded) or not active.issubset(public):
        raise LiveVerifyQueueError("T8 active publication denominator mismatch")
    order = [_safe_relative(value) for value in bundle.get("publication_order", ())]
    if set(order) != active or len(order) != len(active):
        raise LiveVerifyQueueError("T8 publication order is not an exact permutation")
    if not order or order[-1] != FINAL_RECEIPT:
        raise LiveVerifyQueueError("T8 publication receipt is not last")
    return bundle, decoded, order


def _active_public_conditional_states(
    unit: Mapping[str, Any],
    active: set[str],
) -> dict[str, str]:
    result: dict[str, str] = {}
    for path, row in _output_rows(unit).items():
        if str(row.get("artifact_class") or "") == "CONDITIONAL":
            result[path] = "PRODUCED" if path in active else "NOT_TRIGGERED"
    return result


def execute_live_transaction(
    *,
    scratchpad: Path,
    project_root: Path,
    plan: Mapping[str, Any],
    run_id: str,
    semantic_executor: Callable[..., Mapping[str, Any]],
    failpoint: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Execute the live private DAG, publish T9, and commit the parent."""

    root = Path(scratchpad)
    project = Path(project_root)
    root.mkdir(parents=True, exist_ok=True)
    run = str(run_id or "").strip()
    if not run:
        raise LiveVerifyQueueError("live verify-queue run_id is absent")
    if not callable(semantic_executor):
        raise LiveVerifyQueueError("live semantic executor is not callable")
    _validate_plan(plan, run)
    children = list(plan["children"])

    for index, unit in enumerate(children[:9]):
        if index == 0:
            _validate_t0_prearm_presence(
                scratchpad=root,
                project_root=project,
                plan=plan,
                unit=unit,
            )
        execute, issues, contract, launch = arm_transaction_unit(
            scratchpad=root,
            project_root=project,
            plan=plan,
            unit=unit,
            run_id=run,
        )
        if issues:
            raise LiveVerifyQueueError("; ".join(issues))
        if not execute:
            continue
        inputs = _contract_input_paths(contract)
        frozen, input_digests = _read_frozen_inputs(
            scratchpad=root,
            project_root=project,
            inputs=inputs,
        )
        if failpoint is not None:
            failpoint(f"after_t{index}_arm")
        if index == 0:
            _validate_t0_prearm_presence(
                scratchpad=root,
                project_root=project,
                plan=plan,
                unit=unit,
            )
        result = semantic_executor(unit=unit, frozen_inputs=frozen)
        if not isinstance(result, Mapping):
            raise LiveVerifyQueueError(
                f"{unit.get('work_unit_id')}: semantic executor returned no mapping"
            )
        outputs, conditional_states, _state = _normalize_semantic_result(
            unit=unit,
            result=result,
            run_id=run,
            plan_digest=str(plan["plan_digest"]),
            input_digests=input_digests,
        )
        _materialize_private_outputs(
            scratchpad=root,
            outputs=outputs,
            failpoint=failpoint,
            index=index,
        )
        if index == 0:
            _validate_t0_prearm_presence(
                scratchpad=root,
                project_root=project,
                plan=plan,
                unit=unit,
            )
        commit_issues = commit_transaction_unit(
            scratchpad=root,
            project_root=project,
            run_id=run,
            contract=contract,
            launch=launch,
            conditional_states=conditional_states,
        )
        if commit_issues:
            raise LiveVerifyQueueError("; ".join(commit_issues))
        if failpoint is not None:
            failpoint(f"after_t{index}_commit")

    t8 = children[8]
    t8_bundle_path = str(
        t8.get("bundle", {}).get("path")
        or next(
            (
                row["path"] for row in t8["outputs"]
                if str(row["path"]).endswith("validated_publication.bundle.json")
            ),
            "",
        )
    )
    _bundle, public_bytes, active_publication_order = _bundle_payload(
        root, t8_bundle_path, plan
    )

    t9 = children[9]
    execute_t9, t9_issues, t9_contract, t9_launch = arm_transaction_unit(
        scratchpad=root,
        project_root=project,
        plan=plan,
        unit=t9,
        run_id=run,
    )
    if t9_issues:
        raise LiveVerifyQueueError("; ".join(t9_issues))
    if execute_t9:
        t9_inputs = _contract_input_paths(t9_contract)
        _frozen_t9, t9_input_digests = _read_frozen_inputs(
            scratchpad=root,
            project_root=project,
            inputs=t9_inputs,
        )
        if failpoint is not None:
            failpoint("after_t9_arm")
        declared_publication_order = [
            _safe_relative(value)
            for value in t9.get("publication", {}).get("order", ())
        ]
        declared_public = {
            _safe_relative(value)
            for value in plan.get("public_output_denominator", ())
        }
        if (
            set(declared_publication_order) != declared_public
            or len(declared_publication_order) != len(declared_public)
            or not declared_publication_order
            or declared_publication_order[-1] != FINAL_RECEIPT
        ):
            raise LiveVerifyQueueError(
                "T9 declared publication order is not an exact receipt-last "
                "public denominator"
            )
        if [
            path for path in declared_publication_order if path in public_bytes
        ] != active_publication_order:
            raise LiveVerifyQueueError(
                "T8 active publication order disagrees with T9 order"
            )
        for relative in declared_publication_order:
            if failpoint is not None:
                failpoint(f"before_t9_replace:{relative}")
            if relative in public_bytes:
                _cas_create_or_exact(root / relative, public_bytes[relative])
            elif (root / relative).exists():
                raise LiveVerifyQueueError(
                    f"inactive T9 conditional acquired bytes: {relative}"
                )
            if failpoint is not None:
                failpoint(f"after_t9_replace:{relative}")
        # Re-read the complete active denominator before the status or ledger
        # can assert commit.  An inactive conditional must remain absent.
        for relative, expected in public_bytes.items():
            path = root / relative
            if not path.is_file() or path.read_bytes() != expected:
                raise LiveVerifyQueueError(
                    f"T9 public postimage changed before commit: {relative}"
                )
        conditional_states = _active_public_conditional_states(
            t9, set(public_bytes)
        )
        output_digests = {
            path: _digest_bytes(raw) for path, raw in sorted(public_bytes.items())
        }
        status_path = _status_path(t9)
        status = _status_payload(
            unit=t9,
            run_id=run,
            plan_digest=str(plan["plan_digest"]),
            state="COMMITTED_APPLIED",
            input_digests=t9_input_digests,
            output_digests=output_digests,
            conditional_states=conditional_states,
        )
        _cas_create_or_exact(root / status_path, _canonical_bytes(status))
        t9_commit_issues = commit_transaction_unit(
            scratchpad=root,
            project_root=project,
            run_id=run,
            contract=t9_contract,
            launch=t9_launch,
            conditional_states=conditional_states,
        )
        if t9_commit_issues:
            raise LiveVerifyQueueError("; ".join(t9_commit_issues))
        if failpoint is not None:
            failpoint("after_t9_commit")

    parent = plan.get("parent")
    if not isinstance(parent, Mapping):
        raise LiveVerifyQueueError("live verify-queue parent plan is absent")
    parent_inputs = tuple(str(value) for value in parent.get("exact_inputs", ()))
    execute_parent, parent_issues, parent_contract, parent_launch = (
        arm_transaction_unit(
            scratchpad=root,
            project_root=project,
            plan=plan,
            unit=parent,
            run_id=run,
            effective_inputs=parent_inputs,
        )
    )
    if parent_issues:
        raise LiveVerifyQueueError("; ".join(parent_issues))
    if execute_parent:
        parent_commit_issues = commit_transaction_unit(
            scratchpad=root,
            project_root=project,
            run_id=run,
            contract=parent_contract,
            launch=parent_launch,
            conditional_states={},
        )
        if parent_commit_issues:
            raise LiveVerifyQueueError("; ".join(parent_commit_issues))

    issues = validate_transaction_authority(
        scratchpad=root,
        project_root=project,
        plan=plan,
        run_id=run,
        require_parent_commit=True,
    )
    if issues:
        raise LiveVerifyQueueError("; ".join(issues))
    return {
        "schema_version": "plamen.live_verify_queue_execution.v1",
        "pipeline": plan["pipeline"],
        "mode": plan["mode"],
        "ecosystem": plan["ecosystem"],
        "backend": plan["backend"],
        "phase_name": plan["phase_name"],
        "run_id": run,
        "plan_digest": plan["plan_digest"],
        "state": "OUTPUT_COMMITTED",
        "safe_to_consume": True,
        "parent_commit": {
            "work_unit_id": parent["work_unit_id"],
            "state": "OUTPUT_COMMITTED",
            "outputs": [],
            "read_only": True,
        },
    }


def validate_live_publication(
    *,
    scratchpad: Path,
    project_root: Path,
    plan: Mapping[str, Any],
    run_id: str,
) -> dict[str, Any]:
    """Return a downstream admission decision rooted in PhaseIO, not prose."""

    root = Path(scratchpad)
    issues = validate_transaction_authority(
        scratchpad=root,
        project_root=Path(project_root),
        plan=plan,
        run_id=run_id,
        require_parent_commit=True,
    )
    if not issues:
        receipt = root / FINAL_RECEIPT
        if not receipt.is_file():
            issues.append("final transaction receipt is absent")
        else:
            try:
                payload = json.loads(
                    receipt.read_text(encoding="utf-8", errors="strict")
                )
            except (OSError, UnicodeError, json.JSONDecodeError):
                issues.append("final transaction receipt is unreadable")
            else:
                if (
                    payload.get("schema_version") != LIVE_RECEIPT_SCHEMA
                    or payload.get("run_id") != run_id
                    or payload.get("plan_digest") != plan.get("plan_digest")
                    or payload.get("state") != "OUTPUT_COMMITTED"
                ):
                    issues.append("final transaction receipt authority mismatch")
    return {
        "schema_version": "plamen.live_verify_queue_publication_validation.v1",
        "safe_to_consume": not issues,
        "t9_execution_state": (
            "OUTPUT_COMMITTED" if not issues else "NOT_COMMITTED"
        ),
        "issues": list(dict.fromkeys(issues)),
        "proof_authority": "NONE",
    }


__all__ = [
    "LiveVerifyQueueError",
    "LiveVerifyQueueInjectedFailure",
    "execute_live_transaction",
    "validate_live_publication",
]
