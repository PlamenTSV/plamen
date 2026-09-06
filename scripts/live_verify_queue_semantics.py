"""Pure semantic implementation for the live T0--T8 verify-queue DAG.

The transaction executor in :mod:`live_verify_queue_executor` owns PhaseIO
and T9 publication.  This module owns only deterministic semantic postimages.
It never writes the caller's scratchpad or project tree.  Filesystem-oriented
legacy helpers run, when needed, in a fresh temporary directory populated
solely from the frozen child-input denominator.

There are two intentionally important boundaries:

* T0 records the complete frozen upstream bytes.  Later children may only
  recover upstream artifacts from that content-addressed bundle.
* A legacy journal is never copied into the isolated workspace and is never
  treated as authority.  Proposal adapters consume final frozen producer
  artifacts; T9/PhaseIO supplies publication authority.

The callable is state-free across children.  Every semantic dependency is
carried by an exact child output, which makes resume replay and backend parity
observable rather than dependent on process memory.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tempfile
from typing import Any, Iterable, Mapping, Sequence

import chain_tail_authority as _chain_tail
from compound_plan_adapter import (
    adapt_chain_composition_candidates,
    adapt_chain_hypotheses,
)
import l1_composition_queue_runtime as _l1
import l1_composition_runtime as _l1_runtime
import mandatory_reverification as _mandatory
import p0af_v2_queue_adapter as _p0af
import p0af_v2_queue_runtime as _p0af_runtime
import plamen_mechanical as _mechanical
import plamen_parsers as _parsers
from plamen_types import L1_VERIFY_SHARD_MANIFESTS, SC_VERIFY_SHARD_MANIFESTS
import plamen_validators as _validators
from queue_work_items import (
    QueueWorkItem,
    build_queue_work_plan,
    queue_record_set_digest,
    queue_records_from_json,
    queue_records_to_json,
    validate_queue_work_items,
)
from verification_method_compiler import (
    build_verification_context_packets,
    stable_digest as _method_digest,
)


SEMANTICS_SCHEMA = "plamen.live_verify_queue_semantics.v1"
INPUT_BUNDLE_SCHEMA = "plamen.live_verify_queue_frozen_inputs.v1"
PUBLICATION_BUNDLE_SCHEMA = "plamen.live_verify_queue_publication_bundle.v1"
FINAL_RECEIPT = "verify_queue_transaction.receipt.json"

_PRIVATE_ROOT = "_live_verify_queue_transaction"
_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_JOURNAL_NAMES = frozenset({
    _mandatory.QUEUE_TRANSACTION_JOURNAL_FILE,
    _l1.DELIVERY_JOURNAL_NAME,
    _p0af_runtime.JOURNAL_FILE,
})


class LiveVerifyQueueSemanticError(ValueError):
    """A frozen semantic denominator cannot be replayed without guessing."""


def live_verify_queue_semantic_gap_map(
    plan: Mapping[str, Any],
) -> dict[str, Any]:
    """Return explicit integration prerequisites not owned by this module.

    The map is deliberately machine-readable and is embedded in T0 context
    selection.  A safe-base transaction may still complete with one of these
    rows, but callers must not describe that run as full legacy semantic
    parity until its closure predicate is true.
    """

    pipeline = str(plan.get("pipeline") or "").lower()
    external = set(map(str, plan.get("external_input_denominator") or ()))
    children = plan.get("children")
    t0 = next(
        (
            child
            for child in children
            if isinstance(child, Mapping)
            and str(child.get("work_unit_id") or "")
            == "t0.live_upstream_authority"
        ),
        {},
    ) if isinstance(children, Sequence) else {}
    prearm_manifest = (
        t0.get("prearm_content_addressed_input_manifest")
        if isinstance(t0, Mapping)
        else None
    )
    rows: list[dict[str, Any]] = []
    if pipeline == "sc" and _p0af.IDENTITY_DENOMINATOR_FILE not in external:
        rows.append({
            "code": "SC_P0AF_IDENTITY_DENOMINATOR_NOT_FROZEN",
            "stage": "T4",
            "effect": (
                "P0-AF v2 cannot authenticate candidate identity collisions; "
                "the composition delta closes as visible debt."
            ),
            "required_plan_change": (
                f"add {_p0af.IDENTITY_DENOMINATOR_FILE} as an exact "
                "producer-bound T0 input"
            ),
            "precision_safety": "NO_SYNTHETIC_DENOMINATOR",
        })
    if pipeline == "sc" and not isinstance(prearm_manifest, Mapping):
        rows.append({
            "code": "SC_P0AF_DYNAMIC_FACT_SOURCES_NOT_ENUMERATED",
            "stage": "T0/T4",
            "effect": (
                "candidate-referenced fact-authority source files cannot be "
                "replayed unless T0 resolves them before arm"
            ),
            "required_plan_change": (
                "pre-resolve every source_artifact named by the frozen P0-AF "
                "candidate authority and add the exact paths to T0"
            ),
            "precision_safety": "NO_LATE_GLOB_OR_LIVE_READ",
        })
    rows.append({
        "code": "LEGACY_BRANCH_VALIDATOR_CUTOVER_REQUIRED",
        "stage": "DOWNSTREAM",
        "effect": (
            "legacy P0-AF/L1 validators expect their old nested PhaseIO work "
            "units and cannot authorize the new T4 child by filename alone"
        ),
        "required_plan_change": (
            "downstream external-ID/parity consumers must validate the "
            "committed live T4/T9 authority instead of old inner journals"
        ),
        "precision_safety": "NO_STATUS_JSON_SELF_CERTIFICATION",
    })
    rows.append({
        "code": "T0_PRODUCER_ANCESTRY_ENFORCED_BY_PHASEIO",
        "stage": "T0",
        "effect": (
            "the semantic executor records frozen bytes but cannot certify "
            "their producer owner/writer/run/contract/launch ancestry"
        ),
        "required_plan_change": (
            "the transaction PhaseIO boundary must enforce T0's declared "
            "producer_binding_policy before invoking this executor"
        ),
        "precision_safety": "EXTERNAL_NON_SELF_CERTIFYING_PREREQUISITE",
    })
    unsigned = {
        "schema_version": "plamen.live_verify_queue_semantic_gap_map.v1",
        "pipeline": pipeline,
        "run_id": str(plan.get("run_id") or ""),
        "full_legacy_semantic_parity": not rows,
        "safe_base_execution_supported": True,
        "rows": rows,
    }
    return {**unsigned, "gap_map_digest": _digest(unsigned)}


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


def _digest(value: Any) -> str:
    return _sha(_canonical_bytes(value))


def _field_digest(value: Mapping[str, Any], field: str) -> str:
    return hashlib.sha256(
        json.dumps(
            {key: item for key, item in value.items() if key != field},
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _safe_relative(value: Any) -> str:
    text = str(value or "").strip().replace("\\", "/")
    pure = PurePosixPath(text)
    if (
        not text
        or pure.is_absolute()
        or re.match(r"^[A-Za-z]:", text)
        or any(part in {"", ".", ".."} for part in pure.parts)
        or any(token in text for token in "*?[")
    ):
        raise LiveVerifyQueueSemanticError(
            f"unsafe live semantic path: {value!r}"
        )
    return pure.as_posix()


def _json(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise LiveVerifyQueueSemanticError(f"{label} is not strict JSON") from exc
    if not isinstance(value, dict):
        raise LiveVerifyQueueSemanticError(f"{label} must contain an object")
    return value


def _output_paths(unit: Mapping[str, Any]) -> tuple[str, ...]:
    rows = unit.get("outputs")
    if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes)):
        raise LiveVerifyQueueSemanticError("child output denominator is malformed")
    paths: list[str] = []
    for row in rows:
        if not isinstance(row, Mapping):
            raise LiveVerifyQueueSemanticError("child output row is malformed")
        path = _safe_relative(row.get("path"))
        if path.endswith("/status.json"):
            continue
        paths.append(path)
    if len(paths) != len(set(paths)):
        raise LiveVerifyQueueSemanticError("child output denominator is duplicated")
    return tuple(paths)


def _one_path(
    unit: Mapping[str, Any],
    suffix: str,
    *,
    required: bool = True,
) -> str:
    matches = [
        path for path in _output_paths(unit)
        if path.endswith("/" + suffix) or path == suffix
    ]
    if len(matches) != 1:
        if not required and not matches:
            return ""
        raise LiveVerifyQueueSemanticError(
            f"{unit.get('work_unit_id')}: output {suffix!r} is not unique"
        )
    return matches[0]


def _input_by_suffix(
    frozen: Mapping[str, bytes],
    suffix: str,
    *,
    required: bool = True,
) -> bytes:
    matches = [
        raw for path, raw in frozen.items()
        if str(path).endswith("/" + suffix) or str(path) == suffix
    ]
    if len(matches) != 1:
        if not required and not matches:
            return b""
        raise LiveVerifyQueueSemanticError(
            f"frozen input {suffix!r} is not unique"
        )
    return matches[0]


def _recordset_bytes(items: Iterable[QueueWorkItem]) -> bytes:
    return (queue_records_to_json(tuple(items)) + "\n").encode("utf-8")


def _recordset(raw: bytes, label: str) -> tuple[QueueWorkItem, ...]:
    try:
        return queue_records_from_json(raw.decode("utf-8", errors="strict"))
    except (UnicodeError, TypeError, ValueError) as exc:
        raise LiveVerifyQueueSemanticError(
            f"{label} is not a canonical typed queue record set"
        ) from exc


def _bytes_row(raw: bytes) -> dict[str, Any]:
    return {
        "content_b64": base64.b64encode(raw).decode("ascii"),
        "sha256": _sha(raw),
        "size": len(raw),
    }


def _decode_bytes_row(value: Any, label: str) -> bytes:
    if not isinstance(value, Mapping):
        raise LiveVerifyQueueSemanticError(f"{label} byte row is malformed")
    try:
        raw = base64.b64decode(value.get("content_b64"), validate=True)
    except (TypeError, ValueError) as exc:
        raise LiveVerifyQueueSemanticError(
            f"{label} byte row is not canonical base64"
        ) from exc
    if value.get("sha256") != _sha(raw) or value.get("size") != len(raw):
        raise LiveVerifyQueueSemanticError(f"{label} byte row digest mismatch")
    return raw


def _bundle_from_frozen(
    frozen: Mapping[str, bytes],
    *,
    unit: Mapping[str, Any],
    plan: Mapping[str, Any],
) -> dict[str, Any]:
    files: dict[str, Any] = {}
    forbidden = set(plan.get("non_authorizing_legacy_journals") or ())
    aliases_raw = unit.get("logical_input_aliases") or {}
    if not isinstance(aliases_raw, Mapping):
        raise LiveVerifyQueueSemanticError(
            "T0 logical input alias map is malformed"
        )
    aliases = {
        _safe_relative(logical): _safe_relative(physical)
        for logical, physical in aliases_raw.items()
    }
    if len(set(aliases.values())) != len(aliases):
        raise LiveVerifyQueueSemanticError(
            "T0 logical input alias map is not one-to-one"
        )
    physical_to_logical = {
        physical: logical for logical, physical in aliases.items()
    }
    for raw_path, raw in sorted(frozen.items()):
        path = _safe_relative(raw_path)
        if path in _JOURNAL_NAMES or path in forbidden:
            raise LiveVerifyQueueSemanticError(
                f"legacy journal entered the frozen authority denominator: {path}"
            )
        staged_path = physical_to_logical.get(path, path)
        if staged_path in files:
            raise LiveVerifyQueueSemanticError(
                f"T0 logical alias collides with another input: {staged_path}"
            )
        files[staged_path] = _bytes_row(bytes(raw))
    unsigned = {
        "schema_version": INPUT_BUNDLE_SCHEMA,
        "semantics_schema": SEMANTICS_SCHEMA,
        "pipeline": str(plan.get("pipeline") or ""),
        "mode": str(plan.get("mode") or ""),
        "ecosystem": str(plan.get("ecosystem") or ""),
        "backend": str(plan.get("backend") or ""),
        "run_id": str(plan.get("run_id") or ""),
        "work_unit_id": str(unit.get("work_unit_id") or ""),
        "runtime_authority": dict(plan.get("runtime_authority") or {}),
        "logical_input_aliases": dict(sorted(aliases.items())),
        "files": files,
    }
    return {**unsigned, "bundle_digest": _digest(unsigned)}


def _load_input_bundle(frozen: Mapping[str, bytes]) -> dict[str, Any]:
    value = _json(
        _input_by_suffix(frozen, "input_bundle.json"),
        "T0 input bundle",
    )
    supplied = value.get("bundle_digest")
    unsigned = {key: item for key, item in value.items() if key != "bundle_digest"}
    if (
        value.get("schema_version") != INPUT_BUNDLE_SCHEMA
        or not isinstance(supplied, str)
        or supplied != _digest(unsigned)
        or not isinstance(value.get("files"), Mapping)
    ):
        raise LiveVerifyQueueSemanticError("T0 input bundle authority mismatch")
    return value


def _stage_bundle(
    root: Path,
    bundle: Mapping[str, Any],
    *,
    include_project: bool = False,
) -> Path:
    project = root / "_project"
    project.mkdir(parents=True, exist_ok=True)
    files = bundle.get("files")
    if not isinstance(files, Mapping):
        raise LiveVerifyQueueSemanticError("T0 file denominator is malformed")
    for raw_path, row in files.items():
        path = str(raw_path)
        is_project = path.startswith("project::")
        if is_project and not include_project:
            continue
        relative = (
            _safe_relative(path[len("project::"):])
            if is_project else _safe_relative(path)
        )
        if PurePosixPath(relative).name in _JOURNAL_NAMES:
            continue
        destination = (project if is_project else root).joinpath(
            *PurePosixPath(relative).parts
        )
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(_decode_bytes_row(row, path))
    return project


def _write(root: Path, relative: str, raw: bytes) -> None:
    path = root.joinpath(*PurePosixPath(_safe_relative(relative)).parts)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)


def _projection_bytes(
    items: Sequence[QueueWorkItem],
    *,
    kind: str = "active",
) -> dict[str, bytes]:
    with tempfile.TemporaryDirectory(prefix="plamen-live-projection-") as temp:
        root = Path(temp)
        name = (
            "verification_queue.md"
            if kind == "active"
            else "verification_queue_evidence_excluded.md"
        )
        if kind == "active":
            _parsers._write_queue_work_item_records_manifest(root / name, items)
        else:
            rows = [
                {
                    **_parsers._typed_queue_item_legacy_row(item),
                    "exclusion reason": "AUTHORIZED_EXCLUDED",
                }
                for item in items
            ]
            _parsers._write_queue_excluded_manifest(root / name, rows)
        result = {
            name: (root / name).read_bytes(),
            Path(name).with_suffix(".json").as_posix():
                (root / Path(name).with_suffix(".json")).read_bytes(),
        }
        if kind == "active":
            result[
                Path(name).with_suffix(".work_items.json").as_posix()
            ] = (root / Path(name).with_suffix(".work_items.json")).read_bytes()
        return result


def _projection_map(value: Mapping[str, Any], label: str) -> dict[str, bytes]:
    rows = value.get("projection_files")
    if not isinstance(rows, Mapping):
        raise LiveVerifyQueueSemanticError(f"{label} projection map is absent")
    return {
        _safe_relative(path): _decode_bytes_row(row, f"{label}:{path}")
        for path, row in rows.items()
    }


def _validate_prearm_manifest_frozen_bytes(
    unit: Mapping[str, Any],
    frozen: Mapping[str, bytes],
) -> str:
    """Replay every pre-arm dynamic binding from T0's frozen denominator."""

    metadata = unit.get("prearm_content_addressed_input_manifest")
    if metadata is None:
        return ""
    if not isinstance(metadata, Mapping):
        raise LiveVerifyQueueSemanticError(
            "T0 prearm content-addressed manifest metadata is malformed"
        )
    identity = str(metadata.get("manifest_identity") or "")
    if not identity.startswith("scratchpad:"):
        raise LiveVerifyQueueSemanticError(
            "T0 prearm manifest identity is not scratchpad-relative"
        )
    manifest_path = _safe_relative(identity[len("scratchpad:"):])
    raw_manifest = frozen.get(manifest_path)
    if raw_manifest is None:
        raise LiveVerifyQueueSemanticError(
            "T0 prearm manifest is absent from the frozen denominator"
        )
    manifest = _json(raw_manifest, "T0 prearm input manifest")
    if manifest != dict(metadata):
        raise LiveVerifyQueueSemanticError(
            "T0 prearm manifest bytes differ from the resolved plan"
        )
    digest = str(manifest.get("manifest_digest") or "")
    unsigned = {
        key: item for key, item in manifest.items()
        if key != "manifest_digest"
    }
    if not _HEX64.fullmatch(digest) or digest != _digest(unsigned):
        raise LiveVerifyQueueSemanticError(
            "T0 prearm manifest digest is malformed or stale"
        )
    rows: list[Mapping[str, Any]] = []
    for field in ("selection_authority", "identity_denominator"):
        row = manifest.get(field)
        if not isinstance(row, Mapping):
            raise LiveVerifyQueueSemanticError(
                f"T0 prearm {field} authority is malformed"
            )
        rows.append(row)
    entries = manifest.get("entries")
    if not isinstance(entries, list) or any(
        not isinstance(row, Mapping) for row in entries
    ):
        raise LiveVerifyQueueSemanticError(
            "T0 prearm source entry denominator is malformed"
        )
    rows.extend(entries)
    for row in rows:
        bound_identity = str(row.get("identity") or "")
        if not bound_identity.startswith("scratchpad:"):
            raise LiveVerifyQueueSemanticError(
                "T0 prearm bound identity is not scratchpad-relative"
            )
        relative = _safe_relative(
            bound_identity[len("scratchpad:"):]
        )
        raw = frozen.get(relative)
        if raw is None:
            raise LiveVerifyQueueSemanticError(
                f"T0 prearm referenced source is not frozen: {relative}"
            )
        if (
            row.get("sha256") != _sha(raw)
            or row.get("size") != len(raw)
        ):
            raise LiveVerifyQueueSemanticError(
                f"T0 prearm referenced source binding drifted: {relative}"
            )
    return digest


def _validate_prearm_presence_frozen_bytes(
    unit: Mapping[str, Any],
    frozen: Mapping[str, bytes],
) -> str:
    authority_raw = unit.get("prearm_presence_authority")
    if authority_raw is None:
        return ""
    if not isinstance(authority_raw, Mapping):
        raise LiveVerifyQueueSemanticError(
            "T0 prearm presence authority metadata is malformed"
        )
    authority = dict(authority_raw)
    identity = str(authority.get("authority_identity") or "")
    if not identity.startswith("scratchpad:"):
        raise LiveVerifyQueueSemanticError(
            "T0 prearm presence authority identity is malformed"
        )
    authority_path = _safe_relative(identity[len("scratchpad:"):])
    raw = frozen.get(authority_path)
    if raw is None or raw != _canonical_bytes(authority):
        raise LiveVerifyQueueSemanticError(
            "T0 prearm presence authority bytes differ from the plan"
        )
    supplied_digest = str(authority.get("authority_digest") or "")
    unsigned = {
        key: item for key, item in authority.items()
        if key != "authority_digest"
    }
    if (
        not _HEX64.fullmatch(supplied_digest)
        or supplied_digest != _digest(unsigned)
    ):
        raise LiveVerifyQueueSemanticError(
            "T0 prearm presence authority digest is malformed or stale"
        )
    roster = authority.get("roster_identities")
    entries = authority.get("entries")
    if not isinstance(roster, list) or not isinstance(entries, list):
        raise LiveVerifyQueueSemanticError(
            "T0 prearm presence roster/entries are malformed"
        )
    expected_roster = sorted(
        "scratchpad:" + str(path)
        for path in unit.get("exact_inputs", ())
        if str(path) != authority_path
    )
    if roster != expected_roster or len(entries) != len(roster):
        raise LiveVerifyQueueSemanticError(
            "T0 prearm presence denominator differs from exact_inputs"
        )
    rows = {
        str(row.get("identity") or ""): row
        for row in entries
        if isinstance(row, Mapping)
    }
    if set(rows) != set(roster):
        raise LiveVerifyQueueSemanticError(
            "T0 prearm presence entry denominator is incomplete"
        )
    for bound_identity in roster:
        if not bound_identity.startswith("scratchpad:"):
            raise LiveVerifyQueueSemanticError(
                "T0 prearm presence row is not scratchpad-relative"
            )
        relative = _safe_relative(
            bound_identity[len("scratchpad:"):]
        )
        row = rows[bound_identity]
        state = str(row.get("state") or "")
        current = frozen.get(relative)
        if state == "ABSENT":
            if current is not None:
                raise LiveVerifyQueueSemanticError(
                    f"T0 explicit absence drifted: {relative}"
                )
        elif state in {"PRESENT", "PRESENT_AUTHORIZED"}:
            if (
                current is None
                or row.get("sha256") != _sha(current)
                or row.get("size") != len(current)
            ):
                raise LiveVerifyQueueSemanticError(
                    f"T0 explicit presence binding drifted: {relative}"
                )
        elif state == "PRESENT_UNAUTHORIZED_QUARANTINED":
            if current is not None:
                raise LiveVerifyQueueSemanticError(
                    f"T0 quarantined input entered semantics: {relative}"
                )
        else:
            raise LiveVerifyQueueSemanticError(
                f"T0 prearm presence state is invalid: {relative}"
            )
    return supplied_digest


def _t0(
    unit: Mapping[str, Any],
    frozen: Mapping[str, bytes],
    plan: Mapping[str, Any],
) -> Mapping[str, Any]:
    prearm_presence_digest = _validate_prearm_presence_frozen_bytes(
        unit, frozen
    )
    prearm_manifest_digest = _validate_prearm_manifest_frozen_bytes(
        unit, frozen
    )
    bundle = _bundle_from_frozen(frozen, unit=unit, plan=plan)
    presence_roster = set(map(str, unit.get("presence_roster") or ()))
    presence_authority = unit.get("prearm_presence_authority")
    presence_entries = (
        presence_authority.get("entries", ())
        if isinstance(presence_authority, Mapping)
        else ()
    )
    explicit_absence = sorted(
        str(row.get("identity") or "")[len("scratchpad:"):]
        for row in presence_entries
        if isinstance(row, Mapping)
        and row.get("state") == "ABSENT"
        and str(row.get("identity") or "").startswith("scratchpad:")
    )
    quarantined = sorted(
        str(row.get("identity") or "")[len("scratchpad:"):]
        for row in presence_entries
        if isinstance(row, Mapping)
        and row.get("state") == "PRESENT_UNAUTHORIZED_QUARANTINED"
        and str(row.get("identity") or "").startswith("scratchpad:")
    )
    roster = {
        "schema_version": "plamen.live_verify_queue_presence_roster.v1",
        "required": list(unit.get("required_inputs") or ()),
        "present": sorted(frozen),
        "presence_roster": sorted(presence_roster),
        "explicit_absence": explicit_absence,
        "quarantined": quarantined,
        "prearm_manifest_digest": prearm_manifest_digest,
        "prearm_presence_authority_digest": prearm_presence_digest,
        "proof_authority": "NONE",
    }
    context = {
        "schema_version": "plamen.live_verify_queue_context_selection.v1",
        "pipeline": plan["pipeline"],
        "mode": plan["mode"],
        "ecosystem": plan["ecosystem"],
        "backend": plan["backend"],
        "run_id": plan["run_id"],
        "runtime_authority": dict(plan.get("runtime_authority") or {}),
        "semantic_gap_map": live_verify_queue_semantic_gap_map(plan),
        "proof_authority": "NONE",
    }
    return {
        "state": "COMMITTED_APPLIED",
        "outputs": {
            _one_path(unit, "input_bundle.json"): _canonical_bytes(bundle),
            _one_path(unit, "input_presence_roster.json"):
                _canonical_bytes(roster),
            _one_path(unit, "context_selection.json"): _canonical_bytes(context),
            _one_path(unit, "resolved_plan.json"): _canonical_bytes(plan),
        },
        "conditional_states": {},
    }


def _t1(
    unit: Mapping[str, Any],
    frozen: Mapping[str, bytes],
) -> Mapping[str, Any]:
    bundle = _load_input_bundle(frozen)
    with tempfile.TemporaryDirectory(prefix="plamen-live-t1-") as temp:
        root = Path(temp)
        _stage_bundle(root, bundle)
        _parsers._write_mechanical_verification_queue_from_inventory(
            root, pipeline=str(bundle.get("pipeline") or "")
        )
        queue = root / "verification_queue.md"
        outputs = {
            _one_path(unit, "base_queue.md"): queue.read_bytes(),
            _one_path(unit, "base_queue.json"):
                queue.with_suffix(".json").read_bytes(),
            _one_path(unit, "base_queue.work_items.json"):
                queue.with_suffix(".work_items.json").read_bytes(),
        }
    return {
        "state": "COMMITTED_APPLIED",
        "outputs": outputs,
        "conditional_states": {},
    }


def _empty_evidence_debt() -> dict[str, Any]:
    return {
        "schema_version": "plamen.verification_queue_evidence_debt.v1",
        "authority": "ADVISORY_REPAIR_ONLY",
        "row_count": 0,
        "rows": [],
    }


def _t2(
    unit: Mapping[str, Any],
    frozen: Mapping[str, bytes],
) -> Mapping[str, Any]:
    bundle = _load_input_bundle(frozen)
    pipeline = str(bundle.get("pipeline") or "").lower()
    mode = str(bundle.get("mode") or "").lower()
    base_md = _input_by_suffix(frozen, "base_queue.md")
    base_json = _input_by_suffix(frozen, "base_queue.json")
    base_typed = _input_by_suffix(frozen, "base_queue.work_items.json")
    base_items = _recordset(base_typed, "T1 base queue")
    with tempfile.TemporaryDirectory(prefix="plamen-live-t2-") as temp:
        root = Path(temp)
        _stage_bundle(root, bundle)
        _write(root, "verification_queue.md", base_md)
        _write(root, "verification_queue.json", base_json)
        _write(root, "verification_queue.work_items.json", base_typed)
        # The legacy SC policy performs hypothesis grouping before the
        # mode/evidence filters.  L1 has no hypothesis-collapse pass here.
        if pipeline == "sc":
            _parsers._dedup_queue_by_hypothesis(root)
            _parsers._filter_sc_verification_queue_by_mode(root, mode)
            _validators._filter_verification_queue_by_evidence(root)
        elif pipeline == "l1":
            _validators._filter_verification_queue_by_evidence(root)
            _parsers._filter_verification_queue_by_mode(
                root, mode, pipeline_label="L1"
            )
        else:
            raise LiveVerifyQueueSemanticError(f"unsupported pipeline {pipeline!r}")
        _mechanical.backfill_unrouted_inventory_into_queue(
            root,
            authenticated_inventory_text=(
                root / "findings_inventory.md"
            ).read_text(encoding="utf-8", errors="strict"),
        )

        queue = root / "verification_queue.md"
        excluded_path = root / "verification_queue_evidence_excluded.md"
        if not excluded_path.is_file():
            _parsers._write_queue_excluded_manifest(excluded_path, [])
        active_items = _parsers._read_typed_queue_work_items(queue)
        excluded_rows = _parsers._read_queue_json_sidecar(
            excluded_path
        )
        excluded_items = _parsers._typed_queue_items_from_rows(excluded_rows)
        debt_json_path = root / "verification_queue_evidence_debt.json"
        debt_md_path = root / "verification_queue_evidence_debt.md"
        debt = (
            _json(debt_json_path.read_bytes(), "evidence debt")
            if debt_json_path.is_file() else _empty_evidence_debt()
        )
        if not debt_md_path.is_file():
            _validators._write_verification_queue_evidence_debt(root, [])
        projection = {
            "verification_queue.md": queue.read_bytes(),
            "verification_queue.json": queue.with_suffix(".json").read_bytes(),
            "verification_queue.work_items.json":
                queue.with_suffix(".work_items.json").read_bytes(),
            "verification_queue_evidence_excluded.md":
                excluded_path.read_bytes(),
            "verification_queue_evidence_excluded.json":
                (root / "verification_queue_evidence_excluded.json").read_bytes(),
            "verification_queue_evidence_debt.md":
                (root / "verification_queue_evidence_debt.md").read_bytes(),
            "verification_queue_evidence_debt.json":
                (root / "verification_queue_evidence_debt.json").read_bytes(),
        }

    active_ids = {item.work_item_id for item in active_items}
    excluded_ids = {item.work_item_id for item in excluded_items}
    base_ids = {item.work_item_id for item in base_items}
    unaccounted = sorted(base_ids - active_ids - excluded_ids)
    duplicated = sorted(active_ids & excluded_ids)
    accounting = {
        "schema_version": "plamen.live_queue_identity_accounting.v1",
        "base_ids": sorted(base_ids),
        "active_ids": sorted(active_ids),
        "authorized_excluded_ids": sorted(excluded_ids),
        "visible_debt_ids": unaccounted,
        "duplicate_partition_ids": duplicated,
        # Visible debt is a terminal, non-proof disposition rather than a
        # disappearance.  Exactness therefore means the full base denominator
        # is represented once across the three closed outcomes.
        "exact_partition": (
            base_ids == active_ids | excluded_ids | set(unaccounted)
            and not (active_ids & excluded_ids)
            and not duplicated
        ),
        "proof_authority": "NONE",
    }
    disposition = {
        "schema_version": "plamen.live_queue_policy_disposition.v1",
        "pipeline": pipeline,
        "mode": mode,
        "projection_files": {
            path: _bytes_row(raw) for path, raw in sorted(projection.items())
        },
        "base_record_set_digest": queue_record_set_digest(base_items),
        "active_record_set_digest": queue_record_set_digest(active_items),
        "excluded_record_set_digest": queue_record_set_digest(excluded_items),
        "identity_accounting_digest": _digest(accounting),
        "proof_authority": "NONE",
    }
    outputs = {
        _one_path(unit, "active_queue.work_items.json"):
            _recordset_bytes(active_items),
        _one_path(unit, "evidence_excluded.work_items.json"):
            _recordset_bytes(excluded_items),
        _one_path(unit, "evidence_debt.json"): _canonical_bytes(debt),
        _one_path(unit, "identity_accounting.json"):
            _canonical_bytes(accounting),
        _one_path(unit, "policy_disposition.json"):
            _canonical_bytes(disposition),
    }
    return {
        "state": (
            "COMMITTED_APPLIED"
            if accounting["exact_partition"]
            else "COMMITTED_DEBT_SAFE_BASE"
        ),
        "outputs": outputs,
        "conditional_states": {},
    }


def _restore_policy_workspace(
    root: Path,
    frozen: Mapping[str, bytes],
) -> tuple[dict[str, Any], tuple[QueueWorkItem, ...]]:
    bundle = _load_input_bundle(frozen)
    _stage_bundle(root, bundle)
    active = _recordset(
        _input_by_suffix(frozen, "active_queue.work_items.json"),
        "T2 active queue",
    )
    excluded_raw = _input_by_suffix(
        frozen, "evidence_excluded.work_items.json", required=False
    )
    excluded = (
        _recordset(excluded_raw, "T2 excluded queue")
        if excluded_raw else ()
    )
    # T3/T4 deliberately do not consume the policy disposition sidecar.  The
    # exact typed active/excluded postimages are sufficient to reconstruct the
    # lossy compatibility views in the isolated workspace.
    projections = {
        **_projection_bytes(active, kind="active"),
        **_projection_bytes(excluded, kind="excluded"),
    }
    for path, raw in projections.items():
        _write(root, path, raw)
    if _parsers._read_typed_queue_work_items(
        root / "verification_queue.md"
    ) != active:
        raise LiveVerifyQueueSemanticError(
            "T2 active projection differs from typed authority"
        )
    return bundle, active


def _debt_authority(
    *,
    schema: str,
    run_id: str,
    code: str,
    detail: str,
) -> dict[str, Any]:
    unsigned = {
        "schema_version": schema,
        "run_id": run_id,
        "status": "COMPLETED_WITH_DEBT",
        "code": code,
        "detail": detail[:2000],
        "proof_authority": "NONE",
    }
    return {**unsigned, "payload_digest": _digest(unsigned)}


def _t3(
    unit: Mapping[str, Any],
    frozen: Mapping[str, bytes],
) -> Mapping[str, Any]:
    with tempfile.TemporaryDirectory(prefix="plamen-live-t3-") as temp:
        root = Path(temp)
        bundle, before = _restore_policy_workspace(root, frozen)
        run_id = str(bundle.get("run_id") or "")
        issues: list[str] = []
        try:
            denominator = _mandatory.compile_primary_reopen_denominator(
                root,
                run_id=run_id,
                trusted_frozen_transaction_input=True,
            )
            _mandatory.write_or_validate_mandatory_artifact(
                root / _mandatory.DENOMINATOR_FILE, denominator
            )
            routing = _mandatory.apply_primary_reopens_to_queue(
                root, denominator
            )
            after = _parsers._read_typed_queue_work_items(
                root / "verification_queue.md"
            )
            before_by_id = {item.work_item_id: item for item in before}
            delta = tuple(
                item for item in after
                if item.work_item_id not in before_by_id
            )
            changed = [
                item.work_item_id for item in after
                if item.work_item_id in before_by_id
                and item != before_by_id[item.work_item_id]
            ]
            if changed:
                raise LiveVerifyQueueSemanticError(
                    "mandatory reopen changed existing work: "
                    + ", ".join(changed)
                )
            compatibility = {
                name: _bytes_row((root / name).read_bytes())
                for name in (
                    _mandatory.DENOMINATOR_FILE,
                    _mandatory.ROUTING_FILE,
                    _mandatory.QUEUE_TRANSACTION_RECEIPT_FILE,
                )
                if (root / name).is_file()
            }
            disposition = {
                "schema_version":
                    "plamen.live_mandatory_reverification_disposition.v1",
                "status": "APPLIED" if delta else "CLEAN_NO_OP",
                "run_id": run_id,
                "before_record_set_digest": queue_record_set_digest(before),
                "after_record_set_digest": queue_record_set_digest(after),
                "delta_ids": sorted(item.work_item_id for item in delta),
                "compatibility_artifacts": compatibility,
                "issues": [],
                "proof_authority": "NONE",
            }
            denominator_raw = (root / _mandatory.DENOMINATOR_FILE).read_bytes()
            routing_raw = (root / _mandatory.ROUTING_FILE).read_bytes()
        except Exception as exc:
            issues.append(f"{type(exc).__name__}:{exc}")
            delta = ()
            denominator = _debt_authority(
                schema="plamen.live_mandatory_denominator_debt.v1",
                run_id=run_id,
                code="MANDATORY_DENOMINATOR_UNAVAILABLE",
                detail=issues[0],
            )
            routing = _debt_authority(
                schema="plamen.live_mandatory_routing_debt.v1",
                run_id=run_id,
                code="MANDATORY_ROUTING_UNAVAILABLE",
                detail=issues[0],
            )
            denominator_raw = _canonical_bytes(denominator)
            routing_raw = _canonical_bytes(routing)
            disposition = {
                "schema_version":
                    "plamen.live_mandatory_reverification_disposition.v1",
                "status": "COMPLETED_WITH_DEBT_SAFE_BASE",
                "run_id": run_id,
                "before_record_set_digest": queue_record_set_digest(before),
                "after_record_set_digest": queue_record_set_digest(before),
                "delta_ids": [],
                "compatibility_artifacts": {},
                "issues": issues,
                "proof_authority": "NONE",
            }
    outputs = {
        _one_path(unit, "queue_delta.work_items.json"):
            _recordset_bytes(delta),
        _one_path(unit, "mandatory_reverification_denominator.json"):
            denominator_raw,
        _one_path(unit, "mandatory_reverification_routing.json"):
            routing_raw,
        _one_path(unit, "mandatory_reverification_disposition.json"):
            _canonical_bytes(disposition),
    }
    return {
        "state": (
            "COMMITTED_DEBT_SAFE_BASE" if issues else "COMMITTED_APPLIED"
        ),
        "outputs": outputs,
        "conditional_states": {},
    }


def _inactive_p0af(active: str) -> dict[str, Any]:
    # The runtime's inactive companion is compatibility metadata, never a
    # second semantic successor.
    return _p0af_runtime._inactive(active)


def _l1_plan_from_frozen(
    root: Path,
    bundle: Mapping[str, Any],
    before: tuple[QueueWorkItem, ...],
) -> tuple[
    tuple[QueueWorkItem, ...],
    dict[str, Any],
    dict[str, Any],
    list[str],
]:
    runtime = _json(
        (root / _l1_runtime.RUNTIME_NAME).read_bytes(), "L1 composition runtime"
    )
    dispositions = _json(
        (root / _l1_runtime.MODEL_DISPOSITIONS_NAME).read_bytes(),
        "L1 composition dispositions",
    )
    receipt = _json(
        (root / _l1_runtime.RECEIPT_NAME).read_bytes(),
        "L1 composition receipt",
    )
    receipt_issues = _l1_runtime.validate_l1_composition_receipt(
        receipt, runtime, dispositions
    )
    if receipt_issues:
        raise LiveVerifyQueueSemanticError(
            "L1 frozen composition receipt invalid: "
            + "; ".join(receipt_issues)
        )
    ordinary = list(before)
    by_id = {item.work_item_id: item for item in ordinary}
    priority = max((item.queue_priority for item in ordinary), default=0)
    delivered: list[QueueWorkItem] = []
    issues: list[str] = []
    for handoff in receipt.get("compound_handoffs") or ():
        priority += 1
        try:
            item = _l1._queue_item(handoff, priority=priority)
        except Exception as exc:
            issues.append(
                "HANDOFF_NOT_DELIVERABLE:"
                + str(handoff.get("proposal_id") or "unknown")
                + f":{type(exc).__name__}:{exc}"
            )
            continue
        if item.work_item_id in by_id:
            issues.append(f"QUEUE_IDENTITY_COLLISION:{item.work_item_id}")
            continue
        by_id[item.work_item_id] = item
        delivered.append(item)
    after = validate_queue_work_items((*ordinary, *delivered))
    delivery = _l1._signed({
        "schema_version": _l1.DELIVERY_SCHEMA,
        "run_id": str(receipt.get("run_id") or bundle.get("run_id") or ""),
        "runtime_digest": str(receipt.get("runtime_digest") or ""),
        "composition_receipt_digest": str(receipt.get("receipt_digest") or ""),
        "status": "DELIVERED" if delivered else "COMPLETE_NO_DELIVERY",
        "authorized_work_item_ids":
            sorted(item.work_item_id for item in delivered),
        "owned_work_item_digests": {
            item.work_item_id: item.digest
            for item in sorted(delivered, key=lambda row: row.work_item_id)
        },
        "ordinary_queue_digest": queue_record_set_digest(before),
        "successor_queue_digest": queue_record_set_digest(after),
        "issues": sorted(set(issues)),
        "proof_authority": "NONE",
        "terminal_authority": False,
        "delivery_digest": "",
    }, "delivery_digest")
    debt = _l1._signed({
        "schema_version": _l1.DEBT_SCHEMA,
        "run_id": delivery["run_id"],
        "composition_receipt_digest": delivery["composition_receipt_digest"],
        "issues": sorted(set(issues)),
        "delivery_blocked": bool(issues),
        "proof_authority": "NONE",
        "debt_digest": "",
    }, "debt_digest")
    return after, delivery, debt, issues


def _t4(
    unit: Mapping[str, Any],
    frozen: Mapping[str, bytes],
) -> Mapping[str, Any]:
    with tempfile.TemporaryDirectory(prefix="plamen-live-t4-") as temp:
        root = Path(temp)
        bundle, before = _restore_policy_workspace(root, frozen)
        pipeline = str(bundle.get("pipeline") or "").lower()
        run_id = str(bundle.get("run_id") or "")
        before_digest = queue_record_set_digest(before)
        issues: list[str] = []
        if pipeline == "sc":
            delivery = _p0af.plan_p0af_v2_queue_delivery(root, before)
            after = tuple(delivery.queue_items)
            if delivery.receipt is not None:
                receipt = dict(delivery.receipt)
                debt = _inactive_p0af(_p0af_runtime.RECEIPT_FILE)
                selected = "RECEIPT"
            else:
                debt = dict(delivery.debt or {})
                receipt = _inactive_p0af(_p0af_runtime.DEBT_FILE)
                selected = "DEBT"
                issues.append(
                    str(debt.get("error_code") or "P0_AF_V2_DELIVERY_DEBT")
                )
            queue_input_name = "p0af_queue_input.work_items.json"
            receipt_name = "p0af_delivery_receipt.json"
            debt_name = "p0af_delivery_debt.json"
            status_name = "p0af_delivery_status.json"
        elif pipeline == "l1":
            try:
                after, receipt, debt, issues = _l1_plan_from_frozen(
                    root, bundle, before
                )
                selected = "RECEIPT" if not issues else "DEBT"
            except Exception as exc:
                after = before
                issues = [f"{type(exc).__name__}:{exc}"]
                receipt = {
                    "schema_version": _l1.DELIVERY_SCHEMA,
                    "status": "NOT_SELECTED",
                    "proof_authority": "NONE",
                }
                debt = _l1._signed({
                    "schema_version": _l1.DEBT_SCHEMA,
                    "run_id": run_id,
                    "composition_receipt_digest": "",
                    "issues": issues,
                    "delivery_blocked": True,
                    "proof_authority": "NONE",
                    "debt_digest": "",
                }, "debt_digest")
                selected = "DEBT"
            queue_input_name = "l1_queue_input.work_items.json"
            receipt_name = "l1_delivery_receipt.json"
            debt_name = "l1_delivery_debt.json"
            status_name = "l1_delivery_status.json"
        else:
            raise LiveVerifyQueueSemanticError(f"unsupported pipeline {pipeline!r}")

    before_by_id = {item.work_item_id: item for item in before}
    changed = [
        item.work_item_id for item in after
        if item.work_item_id in before_by_id
        and item != before_by_id[item.work_item_id]
    ]
    if changed:
        raise LiveVerifyQueueSemanticError(
            "pipeline composition changed ordinary work: "
            + ", ".join(changed)
        )
    delta = tuple(
        item for item in after if item.work_item_id not in before_by_id
    )
    after_digest = queue_record_set_digest(after)
    disposition = {
        "schema_version": "plamen.live_pipeline_composition_disposition.v1",
        "pipeline": pipeline,
        "selected_successor": selected,
        "delta_ids": sorted(item.work_item_id for item in delta),
        "before_record_set_digest": before_digest,
        "after_record_set_digest": after_digest,
        "issues": sorted(set(issues)),
        "proof_authority": "NONE",
    }
    status = {
        "schema_version": "plamen.live_pipeline_composition_status.v1",
        "pipeline": pipeline,
        "state": "COMMITTED" if not issues else "COMPLETED_WITH_DEBT",
        "run_id": run_id,
        "before_queue_digest": before_digest,
        "after_queue_digest": after_digest,
        "active_successor": selected,
        "safe_to_shard": True,
        "issues": sorted(set(issues)),
        "proof_authority": "NONE",
    }
    outputs = {
        _one_path(unit, "queue_delta.work_items.json"):
            _recordset_bytes(delta),
        _one_path(unit, "composition_disposition.json"):
            _canonical_bytes(disposition),
        _one_path(unit, queue_input_name): _recordset_bytes(before),
        _one_path(unit, receipt_name): _canonical_bytes(receipt),
        _one_path(unit, debt_name): _canonical_bytes(debt),
        _one_path(unit, status_name): _canonical_bytes(status),
    }
    return {
        "state": (
            "COMMITTED_DEBT_SAFE_BASE" if issues else "COMMITTED_APPLIED"
        ),
        "outputs": outputs,
        "conditional_states": {},
    }


def _generic_compound_item(
    work: Mapping[str, Any],
    candidates: Mapping[str, Any],
    *,
    priority: int,
) -> QueueWorkItem:
    subject = str(work["subject_id"]).upper()
    constituents = [str(value).upper() for value in work["constituent_ids"]]
    claim_digest = str(work["candidate_digest"])
    claim_pointer = (
        f"{candidates['source_artifact']}#candidate={subject}"
        f"&claim_sha256={claim_digest}"
    )
    evidence = re.sub(
        r"\s+", " ", str(work.get("combined_impact_claim") or "")
    ).strip()
    row = {
        "queue #": str(priority),
        "finding id": subject,
        "candidate identity": subject,
        "severity": str(work["proposed_severity"]),
        "title": f"Independent verification of composed candidate {subject}",
        "evidence class": "chain-composition",
        "bug class": "chain-composition",
        "preferred tag": "CODE-TRACE",
        "location": claim_pointer,
        "primary artifact": str(candidates["source_artifact"]),
        "poc class": "sequence",
        "constituents": ",".join(constituents),
        "evidence debt": (
            "UNVERIFIED_COMPOSITION: discovery evidence has no proof "
            "authority; ordinary independent verification is mandatory; "
            f"constituents={','.join(constituents)}; exact_evidence={evidence}"
        ),
        "effective evidence scope": "ANALYTICAL",
        "effective proof scope": "NONE",
        "effective harm scope": "UNPROVEN",
    }
    return QueueWorkItem.from_legacy_row(row)


def _compound_delivery_digest(value: Mapping[str, Any]) -> str:
    unsigned = {
        key: item for key, item in value.items() if key != "receipt_digest"
    }
    return hashlib.sha256(
        json.dumps(
            unsigned,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _t5(
    unit: Mapping[str, Any],
    frozen: Mapping[str, bytes],
) -> Mapping[str, Any]:
    bundle = _load_input_bundle(frozen)
    pipeline = str(bundle.get("pipeline") or "").upper()
    mode = str(bundle.get("mode") or "").lower()
    before = _recordset(
        _input_by_suffix(frozen, "active_queue.work_items.json"),
        "T2 active queue",
    )
    files = bundle.get("files") or {}
    issues: list[str] = []
    try:
        if pipeline == "L1":
            if (
                "chain_composition_verification_candidates.json" in files
                or "chain_hypotheses.md" in files
            ):
                raise LiveVerifyQueueSemanticError(
                    "L1 cannot consume foreign SC chain authority"
                )
            compiled = adapt_chain_hypotheses(
                "",
                (item.work_item_id for item in before),
                pipeline="L1",
                mode=mode,
            )
        elif pipeline == "SC" and mode == "thorough":
            raw = _decode_bytes_row(
                files.get("chain_composition_verification_candidates.json"),
                "chain composition candidates",
            )
            payload = _json(raw, "chain composition candidates")
            snapshot = _json(
                _decode_bytes_row(
                    files.get("chain_tail_terminal_snapshot.json"),
                    "chain-tail terminal snapshot",
                ),
                "chain-tail terminal snapshot",
            )
            semantic_ledger = snapshot.get("semantic_ledger")
            _chain_tail._terminal_snapshot_generation(snapshot)
            if (
                snapshot.get("schema_version")
                != _chain_tail.TERMINAL_SNAPSHOT_SCHEMA
                or snapshot.get("snapshot_sha256")
                != _field_digest(snapshot, "snapshot_sha256")
                or not isinstance(semantic_ledger, Mapping)
                or payload.get("manifest_sha256")
                != snapshot.get("manifest_sha256")
                or payload.get("ledger_sha256")
                != semantic_ledger.get("ledger_sha256")
            ):
                raise LiveVerifyQueueSemanticError(
                    "chain candidate authority is not bound to the frozen "
                    "terminal snapshot"
                )
            compiled = adapt_chain_composition_candidates(
                payload,
                (item.work_item_id for item in before),
                {
                    item.work_item_id: item.severity_proposal.level
                    for item in before
                },
                pipeline="SC",
                mode=mode,
            )
        elif pipeline == "SC":
            raw = _decode_bytes_row(
                files.get("chain_hypotheses.md"), "chain hypotheses"
            )
            compiled = adapt_chain_hypotheses(
                raw.decode("utf-8", errors="strict"),
                (item.work_item_id for item in before),
                pipeline="SC",
                mode=mode,
            )
        else:
            raise LiveVerifyQueueSemanticError(
                f"unsupported compound pipeline/mode {pipeline}/{mode}"
            )
        candidates = json.loads(compiled.compound_candidates_json)
        work_plan = json.loads(compiled.compound_work_plan_json)
        plan_body = work_plan["compound_work_plan"]
        blocked = list(plan_body.get("blocked_candidates") or ())
        adapter_issues = list(work_plan.get("adapter_issues") or ())
        plan_issues = list(plan_body.get("issues") or ())
        if blocked or adapter_issues or plan_issues:
            raise LiveVerifyQueueSemanticError(
                "compound work is not wholly deliverable: "
                + json.dumps(
                    {
                        "blocked": blocked,
                        "adapter_issues": adapter_issues,
                        "plan_issues": plan_issues,
                    },
                    sort_keys=True,
                )
            )
        by_id = {item.work_item_id: item for item in before}
        priority = max((item.queue_priority for item in before), default=0)
        delta: list[QueueWorkItem] = []
        for work in plan_body.get("work_items") or ():
            if work.get("readiness") != "READY":
                continue
            priority += 1
            item = _generic_compound_item(
                work, candidates, priority=priority
            )
            if item.work_item_id in by_id:
                raise LiveVerifyQueueSemanticError(
                    f"compound delivery identity collision: {item.work_item_id}"
                )
            by_id[item.work_item_id] = item
            delta.append(item)
        after = validate_queue_work_items((*before, *delta))
        receipt: dict[str, Any] = {
            "schema_version": "plamen.compound_verification_delivery.v1",
            "status": "DELIVERED" if delta else "CLEAN_NO_OP",
            "source_artifact": str(candidates["source_artifact"]),
            "source_sha256": str(candidates["source_digest"]),
            "compound_candidates_digest": candidates["payload_digest"],
            "compound_work_plan_digest": work_plan["payload_digest"],
            "delivered_work_item_ids":
                sorted(item.work_item_id for item in delta),
            "ordinary_verification_required": bool(delta),
            "proof_authority": "NONE",
            "queue_work_items_sha256": _sha(_recordset_bytes(after)),
            "owned_work_item_digests": {
                item.work_item_id: item.digest
                for item in sorted(delta, key=lambda row: row.work_item_id)
            },
        }
        receipt["receipt_digest"] = _compound_delivery_digest(receipt)
        selected_path = _one_path(unit, "compound_delivery_receipt.json")
        unselected_path = _one_path(unit, "compound_delivery_debt.json")
        selected = receipt
        selected_kind = "RECEIPT"
    except Exception as exc:
        issues.append(f"{type(exc).__name__}:{exc}")
        delta = []
        # Even on debt the candidates/work-plan outputs are deterministic and
        # schema-bearing.  They do not acquire delivery authority.
        if "candidates" not in locals():
            empty = adapt_chain_hypotheses(
                "",
                (item.work_item_id for item in before),
                pipeline=pipeline or "SC",
                mode=mode or "thorough",
            )
            candidates = json.loads(empty.compound_candidates_json)
            work_plan = json.loads(empty.compound_work_plan_json)
        debt = {
            "schema_version":
                "plamen.compound_verification_delivery_debt.v1",
            "status": "COMPLETED_WITH_DEBT",
            "source_artifact": str(
                candidates.get("source_artifact")
                or "chain_composition_verification_candidates.json"
            ),
            "source_sha256": str(
                candidates.get("source_digest") or _sha(b"")
            ),
            "ordinary_verification_delivery_complete": False,
            "proof_authority": "NONE",
            "error_class": type(exc).__name__,
            "error": str(exc)[:2000],
        }
        debt["receipt_digest"] = _compound_delivery_digest(debt)
        selected_path = _one_path(unit, "compound_delivery_debt.json")
        unselected_path = _one_path(unit, "compound_delivery_receipt.json")
        selected = debt
        selected_kind = "DEBT"

    disposition = {
        "schema_version": "plamen.live_compound_delivery_disposition.v1",
        "selected_successor": selected_kind,
        "selected_path": selected_path,
        "unselected_path": unselected_path,
        "delta_ids": sorted(item.work_item_id for item in delta),
        "issues": issues,
        "proof_authority": "NONE",
    }
    outputs = {
        _one_path(unit, "compound_candidates.json"):
            _canonical_bytes(candidates),
        _one_path(unit, "compound_verification_work_plan.json"):
            _canonical_bytes(work_plan),
        _one_path(unit, "queue_delta.work_items.json"):
            _recordset_bytes(delta),
        _one_path(unit, "compound_delivery_disposition.json"):
            _canonical_bytes(disposition),
        selected_path: _canonical_bytes(selected),
    }
    return {
        "state": (
            "COMMITTED_DEBT_SAFE_BASE"
            if selected_kind == "DEBT" else "COMMITTED_APPLIED"
        ),
        "outputs": outputs,
        "conditional_states": {
            selected_path: "PRODUCED",
            unselected_path: "NOT_TRIGGERED",
        },
    }


def _t6(
    unit: Mapping[str, Any],
    frozen: Mapping[str, bytes],
) -> Mapping[str, Any]:
    active = _recordset(
        _input_by_suffix(frozen, "active_queue.work_items.json"),
        "T2 active queue",
    )
    excluded = _recordset(
        _input_by_suffix(frozen, "evidence_excluded.work_items.json"),
        "T2 excluded queue",
    )
    policy_accounting = _json(
        _input_by_suffix(frozen, "identity_accounting.json"),
        "T2 identity accounting",
    )
    if (
        policy_accounting.get("schema_version")
        != "plamen.live_queue_identity_accounting.v1"
        or policy_accounting.get("exact_partition") is not True
    ):
        raise LiveVerifyQueueSemanticError(
            "T6 policy identity accounting is not an exact closed partition"
        )
    policy_base_ids = set(map(
        str, policy_accounting.get("base_ids") or ()
    ))
    policy_active_ids = set(map(
        str, policy_accounting.get("active_ids") or ()
    ))
    policy_excluded_ids = set(map(
        str,
        policy_accounting.get("authorized_excluded_ids") or (),
    ))
    policy_visible_ids = set(map(
        str, policy_accounting.get("visible_debt_ids") or ()
    ))
    if (
        policy_active_ids
        != {item.work_item_id for item in active}
        or policy_excluded_ids
        != {item.work_item_id for item in excluded}
        or policy_base_ids
        != policy_active_ids | policy_excluded_ids | policy_visible_ids
        or policy_active_ids & policy_excluded_ids
        or policy_active_ids & policy_visible_ids
        or policy_excluded_ids & policy_visible_ids
    ):
        raise LiveVerifyQueueSemanticError(
            "T6 policy record sets differ from their identity accounting"
        )
    source_suffixes = (
        "mandatory_reverification/queue_delta.work_items.json",
        "composition_delivery/queue_delta.work_items.json",
        "compound_projection/queue_delta.work_items.json",
    )
    # Work-unit names may evolve while the output leaf stays stable.  Select
    # the three non-T2 queue deltas by their owning /t3,/t4,/t5 prefixes.
    del source_suffixes
    deltas: dict[str, tuple[QueueWorkItem, ...]] = {}
    for stage, label in (("/t3/", "mandatory"), ("/t4/", "pipeline"), ("/t5/", "compound")):
        matches = [
            raw for path, raw in frozen.items()
            if stage in str(path)
            and str(path).endswith("/queue_delta.work_items.json")
        ]
        if len(matches) != 1:
            raise LiveVerifyQueueSemanticError(
                f"T6 {label} delta denominator is not exact"
            )
        deltas[label] = _recordset(matches[0], f"T6 {label} delta")

    final_by_id = {item.work_item_id: item for item in active}
    excluded_ids_at_merge = {item.work_item_id for item in excluded}
    reactivated_excluded_ids: set[str] = set()
    source_rows: list[dict[str, Any]] = [
        {
            "source": "policy_active",
            "work_item_id": item.work_item_id,
            "work_item_digest": item.digest,
            "disposition": "ACTIVE",
            "delivery_kind": "PRIMARY",
        }
        for item in active
    ]
    source_rows.extend({
        "source": "policy_excluded",
        "work_item_id": item.work_item_id,
        "work_item_digest": item.digest,
        "disposition": "AUTHORIZED_EXCLUDED",
        "delivery_kind": "POLICY_DISPOSITION",
    } for item in excluded)
    source_rows.extend({
        "source": "policy_debt",
        "work_item_id": work_id,
        "work_item_digest": "",
        "disposition": "VISIBLE_DEBT",
        "delivery_kind": "POLICY_DELIVERY_DEBT",
    } for work_id in sorted(policy_visible_ids))
    collision_debts: list[dict[str, Any]] = []
    for source, rows in deltas.items():
        for item in rows:
            prior = final_by_id.get(item.work_item_id)
            if prior is None:
                final_by_id[item.work_item_id] = item
                disposition = "ACTIVE"
                delivery_kind = "ADDITIVE"
                if item.work_item_id in excluded_ids_at_merge:
                    reactivated_excluded_ids.add(item.work_item_id)
            elif prior.digest == item.digest:
                disposition = "ACTIVE"
                delivery_kind = "EXACT_DUPLICATE"
            else:
                disposition = "VISIBLE_DEBT"
                delivery_kind = "IDENTITY_COLLISION"
                collision_debts.append({
                    "work_item_id": item.work_item_id,
                    "source": source,
                    "existing_digest": prior.digest,
                    "incoming_digest": item.digest,
                    "reason": "ADDITIVE_IDENTITY_COLLISION",
                })
            source_rows.append({
                "source": source,
                "work_item_id": item.work_item_id,
                "work_item_digest": item.digest,
                "disposition": disposition,
                "delivery_kind": delivery_kind,
            })
    active_ids = set(final_by_id)
    invalid_excluded_overlap = sorted(
        (active_ids & excluded_ids_at_merge) - reactivated_excluded_ids
    )
    if invalid_excluded_overlap:
        collision_debts.extend({
            "work_item_id": work_id,
            "source": "policy_excluded",
            "existing_digest": final_by_id[work_id].digest,
            "incoming_digest": next(
                item.digest for item in excluded
                if item.work_item_id == work_id
            ),
            "reason": "ACTIVE_EXCLUDED_PARTITION_COLLISION",
        } for work_id in invalid_excluded_overlap)
    if active_ids & excluded_ids_at_merge:
        excluded = tuple(
            item for item in excluded if item.work_item_id not in active_ids
        )
    final = validate_queue_work_items(final_by_id.values())
    policy_debt = _json(
        _input_by_suffix(frozen, "evidence_debt.json"), "T2 evidence debt"
    )
    evidence_debt = {
        "schema_version": "plamen.live_final_evidence_debt.v1",
        "policy_evidence_debt": policy_debt,
        "merge_collision_count": len(collision_debts),
        "merge_collisions": collision_debts,
        "proof_authority": "NONE",
    }
    accounting = {
        "schema_version": "plamen.live_source_obligation_accounting.v1",
        "rows": source_rows,
        "source_obligation_count": len(source_rows),
        "source_obligation_digest": _digest(source_rows),
        "active_ids": sorted(item.work_item_id for item in final),
        "authorized_excluded_ids":
            sorted(item.work_item_id for item in excluded),
        "visible_debt_ids":
            sorted({
                *policy_visible_ids,
                *{
                    str(row["work_item_id"])
                    for row in collision_debts
                },
            }),
        "exact_partition": all(
            row["disposition"] in {
                "ACTIVE", "AUTHORIZED_EXCLUDED", "VISIBLE_DEBT"
            }
            for row in source_rows
        ) and len(source_rows) == (
            len(active)
            + len(excluded_ids_at_merge)
            + len(policy_visible_ids)
            + sum(len(rows) for rows in deltas.values())
        ),
        "proof_authority": "NONE",
    }
    projections = {
        **_projection_bytes(final, kind="active"),
        **_projection_bytes(excluded, kind="excluded"),
    }
    # Render the advisory debt as both compatibility JSON and Markdown.
    public_debt_json = _canonical_bytes(evidence_debt)
    debt_lines = [
        "# Verification Queue Evidence Debt",
        "",
        "Every item remains visible; this artifact grants no exclusion authority.",
        "",
        "| Work Item ID | Source | Reason |",
        "|--------------|--------|--------|",
    ]
    for row in collision_debts:
        debt_lines.append(
            f"| {row['work_item_id']} | {row['source']} | {row['reason']} |"
        )
    debt_lines.extend(("", f"Total: {len(collision_debts)}", ""))
    projections["verification_queue_evidence_debt.json"] = public_debt_json
    projections["verification_queue_evidence_debt.md"] = (
        "\n".join(debt_lines).encode("utf-8")
    )
    publication = {
        "schema_version": "plamen.live_final_publication_plan.v1",
        "final_record_set_digest": queue_record_set_digest(final),
        "projection_files": {
            path: _bytes_row(raw) for path, raw in sorted(projections.items())
        },
        "conditional_compound_successor": _json(
            _input_by_suffix(
                frozen, "compound_delivery_disposition.json"
            ),
            "T5 compound disposition",
        ).get("selected_successor"),
        "proof_authority": "NONE",
    }
    outputs = {
        _one_path(unit, "final_work_items.json"): _recordset_bytes(final),
        _one_path(unit, "final_excluded_work_items.json"):
            _recordset_bytes(excluded),
        _one_path(unit, "final_evidence_debt.json"):
            _canonical_bytes(evidence_debt),
        _one_path(unit, "source_obligation_accounting.json"):
            _canonical_bytes(accounting),
        _one_path(unit, "final_publication_plan.json"):
            _canonical_bytes(publication),
    }
    return {
        "state": (
            "COMMITTED_DEBT_SAFE_BASE"
            if (
                collision_debts
                or policy_visible_ids
                or not accounting["exact_partition"]
            )
            else "COMMITTED_APPLIED"
        ),
        "outputs": outputs,
        "conditional_states": {},
    }


def _validate_t8_source_obligation_fixed_point(
    frozen: Mapping[str, bytes],
    final: Sequence[QueueWorkItem],
) -> None:
    """Replay T2/T3/T4/T5 -> T6 conservation before public publication."""

    active = _recordset(
        _input_by_suffix(frozen, "active_queue.work_items.json"),
        "T8 T2 active queue",
    )
    excluded_at_policy = _recordset(
        _input_by_suffix(frozen, "evidence_excluded.work_items.json"),
        "T8 T2 excluded queue",
    )
    policy = _private_json_by_suffix(frozen, "identity_accounting.json")
    final_excluded = _recordset(
        _input_by_suffix(frozen, "final_excluded_work_items.json"),
        "T8 final excluded queue",
    )
    accounting = _private_json_by_suffix(
        frozen, "source_obligation_accounting.json"
    )
    if (
        policy.get("schema_version")
        != "plamen.live_queue_identity_accounting.v1"
        or policy.get("exact_partition") is not True
        or accounting.get("schema_version")
        != "plamen.live_source_obligation_accounting.v1"
        or accounting.get("exact_partition") is not True
    ):
        raise LiveVerifyQueueSemanticError(
            "T8 source-obligation accounting is not exact"
        )

    expected_rows: list[tuple[str, str, str]] = [
        ("policy_active", item.work_item_id, item.digest)
        for item in active
    ]
    expected_rows.extend(
        ("policy_excluded", item.work_item_id, item.digest)
        for item in excluded_at_policy
    )
    expected_rows.extend(
        ("policy_debt", str(work_id), "")
        for work_id in sorted(
            map(str, policy.get("visible_debt_ids") or ())
        )
    )
    for stage, source in (
        ("/t3/", "mandatory"),
        ("/t4/", "pipeline"),
        ("/t5/", "compound"),
    ):
        matches = [
            raw
            for path, raw in frozen.items()
            if stage in str(path)
            and str(path).endswith("/queue_delta.work_items.json")
        ]
        if len(matches) != 1:
            raise LiveVerifyQueueSemanticError(
                f"T8 {source} source delta denominator is not exact"
            )
        expected_rows.extend(
            (source, item.work_item_id, item.digest)
            for item in _recordset(matches[0], f"T8 {source} delta")
        )

    observed_raw = accounting.get("rows")
    if not isinstance(observed_raw, list) or any(
        not isinstance(row, Mapping) for row in observed_raw
    ):
        raise LiveVerifyQueueSemanticError(
            "T8 source-obligation rows are malformed"
        )
    observed_rows = [
        (
            str(row.get("source") or ""),
            str(row.get("work_item_id") or ""),
            str(row.get("work_item_digest") or ""),
        )
        for row in observed_raw
    ]
    allowed = {"ACTIVE", "AUTHORIZED_EXCLUDED", "VISIBLE_DEBT"}
    if (
        sorted(observed_rows) != sorted(expected_rows)
        or len(observed_rows) != len(set(observed_rows))
        or any(
            str(row.get("disposition") or "") not in allowed
            for row in observed_raw
        )
        or accounting.get("source_obligation_count")
        != len(observed_raw)
        or accounting.get("source_obligation_digest")
        != _digest(observed_raw)
    ):
        raise LiveVerifyQueueSemanticError(
            "T8 source-obligation occurrence denominator drifted"
        )

    final_ids = {item.work_item_id for item in final}
    final_excluded_ids = {
        item.work_item_id for item in final_excluded
    }
    debt = _private_json_by_suffix(frozen, "final_evidence_debt.json")
    collision_ids = {
        str(row.get("work_item_id") or "")
        for row in debt.get("merge_collisions") or ()
        if isinstance(row, Mapping)
    }
    expected_visible = {
        *map(str, policy.get("visible_debt_ids") or ()),
        *collision_ids,
    }
    if (
        set(map(str, accounting.get("active_ids") or ())) != final_ids
        or set(map(
            str,
            accounting.get("authorized_excluded_ids") or (),
        )) != final_excluded_ids
        or set(map(
            str, accounting.get("visible_debt_ids") or ()
        )) != expected_visible
        or final_ids & final_excluded_ids
    ):
        raise LiveVerifyQueueSemanticError(
            "T8 final active/excluded/debt partition drifted"
        )


def _normalize_context_paths(payload: Mapping[str, Any]) -> dict[str, Any]:
    value = json.loads(json.dumps(payload))
    value["project_root"] = "project::"
    value["scratchpad"] = "scratchpad::"
    unsigned = {key: item for key, item in value.items() if key != "context_digest"}
    value["context_digest"] = _method_digest(unsigned)
    return value


def _t7(
    unit: Mapping[str, Any],
    frozen: Mapping[str, bytes],
    plan: Mapping[str, Any],
) -> Mapping[str, Any]:
    final = _recordset(
        _input_by_suffix(frozen, "final_work_items.json"),
        "T6 final queue",
    )
    capture = unit.get("dynamic_input_capture")
    if not isinstance(capture, Mapping):
        raise LiveVerifyQueueSemanticError("T7 dynamic capture is absent")
    exact_context = tuple(map(str, capture.get("exact_inputs") or ()))
    context_raw = {
        path: frozen[path] for path in exact_context if path in frozen
    }
    if set(context_raw) != set(exact_context):
        raise LiveVerifyQueueSemanticError(
            "T7 exact context input denominator is incomplete"
        )
    with tempfile.TemporaryDirectory(prefix="plamen-live-t7-") as temp:
        root = Path(temp)
        project = root / "_project"
        project.mkdir()
        for path, raw in context_raw.items():
            if path.startswith("project::"):
                relative = _safe_relative(path[len("project::"):])
                destination = project.joinpath(*PurePosixPath(relative).parts)
            else:
                relative = _safe_relative(path)
                destination = root.joinpath(*PurePosixPath(relative).parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(raw)
        packets = _normalize_context_paths(build_verification_context_packets(
            rows=[item.to_dict() for item in final],
            scratchpad=root,
            project_root=project,
        ))

        pipeline = str(plan.get("pipeline") or "")
        manifests = (
            SC_VERIFY_SHARD_MANIFESTS
            if pipeline == "sc" else L1_VERIFY_SHARD_MANIFESTS
        )
        # Compute directly from the authenticated typed records.  Re-parsing the
        # human Markdown projection here loses executable fields that Markdown
        # cannot represent (multi-location records, rationale, and lineage).
        shards = _parsers.compute_verify_shards_from_typed(
            final,
            pipeline=pipeline,
        )
        if set(shards) != set(manifests):
            raise LiveVerifyQueueSemanticError(
                "T7 shard planner did not cover every configured shard"
            )
        shard_files: dict[str, bytes] = {}
        for shard_id, rows in shards.items():
            manifest = manifests[shard_id]
            _parsers._write_queue_subset_manifest(root / manifest, rows)
            for suffix in (".md", ".json", ".work_items.json"):
                path = str(Path(manifest).with_suffix(suffix))
                shard_files[path] = (root / path).read_bytes()
        work_plan = build_queue_work_plan(
            final,
            {
                shard_id: tuple(
                    str(row.get("finding id") or "") for row in rows
                )
                for shard_id, rows in shards.items()
            },
            planner_version=_parsers.VERIFY_WORK_PLAN_PLANNER_VERSION,
        )
        work_plan.validate_against(final)
    assignments = [
        {"work_item_id": work_id, "shard_id": shard.shard_id}
        for shard in work_plan.shards
        for work_id in shard.ordered_work_item_ids
    ]
    final_ids = {item.work_item_id for item in final}
    packet_ids = {
        str(row.get("work_item_id") or "") for row in packets["packets"]
    }
    assigned_ids = [str(row["work_item_id"]) for row in assignments]
    if packet_ids != final_ids or set(assigned_ids) != final_ids or (
        len(assigned_ids) != len(set(assigned_ids))
    ):
        raise LiveVerifyQueueSemanticError(
            "T7 context/shard coverage is not exact"
        )
    roster = {
        "schema_version": "plamen.live_context_input_roster.v1",
        "inputs": [
            {
                "path": path,
                "sha256": _sha(raw),
                "size": len(raw),
            }
            for path, raw in sorted(context_raw.items())
        ],
        "proof_authority": "NONE",
    }
    capture_payload = {
        "schema_version": "plamen.live_context_input_capture.v1",
        "dynamic_input_capture": dict(capture),
        "roster_digest": _digest(roster),
        "proof_authority": "NONE",
    }
    reachability_source = _json(
        context_raw[str(capture["methodology_reachability"])],
        "methodology reachability",
    )
    reachability = {
        "schema_version": "plamen.live_methodology_reachability.v1",
        "source": reachability_source,
        "source_sha256": _sha(
            context_raw[str(capture["methodology_reachability"])]
        ),
        "registry_sha256": _sha(
            context_raw[str(capture["methodology_registry"])]
        ),
        "proof_authority": "NONE",
    }
    shard_plan = {
        "schema_version": "plamen.live_verify_shard_plan.v1",
        "pipeline": plan["pipeline"],
        "work_plan": json.loads(work_plan.to_json()),
        "assignments": assignments,
        "projection_files": {
            path: _bytes_row(raw) for path, raw in sorted(shard_files.items())
        },
        "exact_work_item_ids": sorted(final_ids),
        "proof_authority": "NONE",
    }
    outputs = {
        _one_path(unit, "context_input_capture.json"):
            _canonical_bytes(capture_payload),
        _one_path(unit, "context_input_roster.json"):
            _canonical_bytes(roster),
        _one_path(unit, "verification_context_packets.json"):
            _canonical_bytes(packets),
        _one_path(unit, "verification_methodology_reachability.json"):
            _canonical_bytes(reachability),
        _one_path(unit, "shard_plan.json"): _canonical_bytes(shard_plan),
    }
    return {
        "state": "COMMITTED_APPLIED",
        "outputs": outputs,
        "conditional_states": {},
    }


def _private_json_by_suffix(
    frozen: Mapping[str, bytes],
    suffix: str,
) -> dict[str, Any]:
    return _json(_input_by_suffix(frozen, suffix), suffix)


def _t8(
    unit: Mapping[str, Any],
    frozen: Mapping[str, bytes],
    plan: Mapping[str, Any],
) -> Mapping[str, Any]:
    final = _recordset(
        _input_by_suffix(frozen, "final_work_items.json"),
        "T6 final queue",
    )
    _validate_t8_source_obligation_fixed_point(frozen, final)
    final_ids = {item.work_item_id for item in final}
    packets = _private_json_by_suffix(
        frozen, "verification_context_packets.json"
    )
    shard_plan = _private_json_by_suffix(frozen, "shard_plan.json")
    packet_ids = {
        str(row.get("work_item_id") or "")
        for row in packets.get("packets") or ()
        if isinstance(row, Mapping)
    }
    assigned = [
        str(row.get("work_item_id") or "")
        for row in shard_plan.get("assignments") or ()
        if isinstance(row, Mapping)
    ]
    if (
        packet_ids != final_ids
        or set(assigned) != final_ids
        or len(assigned) != len(set(assigned))
    ):
        raise LiveVerifyQueueSemanticError(
            "T8 semantic replay found context/shard coverage drift"
        )

    public: dict[str, bytes] = {}
    publication = _private_json_by_suffix(
        frozen, "final_publication_plan.json"
    )
    public.update(_projection_map(publication, "T6 publication"))
    public["verification_queue.work_plan.json"] = _canonical_bytes(
        shard_plan["work_plan"]
    )
    public["verification_context_packets.json"] = _canonical_bytes(packets)
    public["verification_methodology_reachability.json"] = _input_by_suffix(
        frozen, "verification_methodology_reachability.json"
    )
    public["verify_queue_context_input_status.json"] = _canonical_bytes({
        "schema_version": "plamen.verify_queue_context_input_status.v1",
        "state": "COMMITTED_CLEAN_NOOP",
        "safe_to_consume": True,
        "safe_base_routing": True,
        "proof_authority": "NONE",
        "accepted_artifacts": _private_json_by_suffix(
            frozen, "context_input_roster.json"
        ).get("inputs", []),
        "omitted_artifacts": [],
    })
    public.update(_projection_map(shard_plan, "T7 shard"))

    # T3 mandatory compatibility.
    mandatory_disposition = _private_json_by_suffix(
        frozen, "mandatory_reverification_disposition.json"
    )
    mandatory_compat = mandatory_disposition.get("compatibility_artifacts")
    if isinstance(mandatory_compat, Mapping):
        for path, row in mandatory_compat.items():
            public[_safe_relative(path)] = _decode_bytes_row(
                row, f"T3 compatibility:{path}"
            )
    public.setdefault(
        _mandatory.DENOMINATOR_FILE,
        _input_by_suffix(frozen, "mandatory_reverification_denominator.json"),
    )
    public.setdefault(
        _mandatory.ROUTING_FILE,
        _input_by_suffix(frozen, "mandatory_reverification_routing.json"),
    )
    public.setdefault(
        _mandatory.QUEUE_TRANSACTION_RECEIPT_FILE,
        _canonical_bytes({
            "schema_version":
                "plamen.mandatory_reverification_queue_transaction_receipt.v1",
            "state": "COMPLETED_WITH_DEBT",
            "terminal_negative_authority": False,
            "proof_authority": "NONE",
            "reason": "exact legacy receipt unavailable; live T9 owns publication",
        }),
    )

    # T5 generic compound compatibility and exact conditional selection.
    compound_disposition = _private_json_by_suffix(
        frozen, "compound_delivery_disposition.json"
    )
    selected_kind = str(
        compound_disposition.get("selected_successor") or ""
    )
    public["compound_candidates.json"] = _input_by_suffix(
        frozen, "compound_candidates.json"
    )
    public["compound_verification_work_plan.json"] = _input_by_suffix(
        frozen, "compound_verification_work_plan.json"
    )
    public["compound_verification_delivery_disposition.json"] = (
        _canonical_bytes(compound_disposition)
    )
    if selected_kind == "RECEIPT":
        compound_public_selected = "compound_verification_delivery_receipt.json"
        compound_private_selected = "compound_delivery_receipt.json"
        compound_public_inactive = "compound_verification_delivery_debt.json"
    elif selected_kind == "DEBT":
        compound_public_selected = "compound_verification_delivery_debt.json"
        compound_private_selected = "compound_delivery_debt.json"
        compound_public_inactive = "compound_verification_delivery_receipt.json"
    else:
        raise LiveVerifyQueueSemanticError(
            "T8 compound conditional selection is not closed"
        )
    public[compound_public_selected] = _input_by_suffix(
        frozen, compound_private_selected
    )

    # T4 branch compatibility.
    pipeline = str(plan.get("pipeline") or "")
    if pipeline == "sc":
        mapping = {
            _p0af_runtime.INPUT_SNAPSHOT_FILE:
                "p0af_queue_input.work_items.json",
            _p0af_runtime.RECEIPT_FILE: "p0af_delivery_receipt.json",
            _p0af_runtime.DEBT_FILE: "p0af_delivery_debt.json",
            _p0af_runtime.STATUS_FILE: "p0af_delivery_status.json",
        }
    else:
        mapping = {
            _l1.QUEUE_INPUT_NAME: "l1_queue_input.work_items.json",
            _l1.DELIVERY_RECEIPT_NAME: "l1_delivery_receipt.json",
            _l1.DELIVERY_DEBT_NAME: "l1_delivery_debt.json",
            _l1.DELIVERY_STATUS_NAME: "l1_delivery_status.json",
        }
    for public_path, private_suffix in mapping.items():
        public[public_path] = _input_by_suffix(frozen, private_suffix)

    denominator = set(map(str, plan.get("public_output_denominator") or ()))
    active = denominator - {compound_public_inactive}
    final_receipt = {
        "schema_version": "plamen.live_verify_queue_receipt.v1",
        "state": "OUTPUT_COMMITTED",
        "run_id": plan["run_id"],
        "plan_digest": plan["plan_digest"],
        "pipeline": plan["pipeline"],
        "mode": plan["mode"],
        "ecosystem": plan["ecosystem"],
        "backend": plan["backend"],
        "proof_authority": "NONE",
        "active_output_denominator": sorted(active),
        "inactive_conditionals": [compound_public_inactive],
    }
    public[FINAL_RECEIPT] = _canonical_bytes(final_receipt)
    missing = sorted(active - set(public))
    extra = sorted(set(public) - active)
    if missing or extra:
        raise LiveVerifyQueueSemanticError(
            "T8 public publication denominator mismatch; "
            f"missing={missing!r}; extra={extra!r}"
        )
    order = [*sorted(active - {FINAL_RECEIPT}), FINAL_RECEIPT]
    file_rows = {
        path: _bytes_row(raw) for path, raw in sorted(public.items())
    }
    bundle = {
        "schema_version": PUBLICATION_BUNDLE_SCHEMA,
        "plan_digest": plan["plan_digest"],
        "public_output_denominator": sorted(denominator),
        "active_output_denominator": sorted(active),
        "selected_conditionals": {
            "compound_delivery": compound_public_selected,
        },
        "publication_order": order,
        "files": file_rows,
    }
    receipt = {
        "schema_version": "plamen.live_verify_queue_validation_receipt.v1",
        "plan_digest": plan["plan_digest"],
        "final_record_set_digest": queue_record_set_digest(final),
        "context_work_item_ids": sorted(packet_ids),
        "shard_work_item_ids": sorted(assigned),
        "public_file_digests": {
            path: row["sha256"] for path, row in sorted(file_rows.items())
        },
        "selected_conditionals": bundle["selected_conditionals"],
        "semantic_replay": "PASS",
        "proof_authority": "NONE",
    }
    receipt["receipt_digest"] = _digest(receipt)
    outer = {
        "schema_version": "plamen.live_verify_queue_outer_denominator.v1",
        "input_paths": sorted(frozen),
        "input_digests": {
            path: _sha(raw) for path, raw in sorted(frozen.items())
        },
        "conditional_selection": bundle["selected_conditionals"],
        "proof_authority": "NONE",
    }
    outputs = {
        _one_path(unit, "outer_denominator.json"): _canonical_bytes(outer),
        _one_path(unit, "validated_publication.bundle.json"):
            _canonical_bytes(bundle),
        _one_path(unit, "validation_receipt.json"):
            _canonical_bytes(receipt),
    }
    return {
        "state": "COMMITTED_APPLIED",
        "outputs": outputs,
        "conditional_states": {},
    }


class LiveVerifyQueueSemanticExecutor:
    """Deterministic callable for the resolved production T0--T8 plan."""

    def __init__(self, plan: Mapping[str, Any]) -> None:
        if not isinstance(plan, Mapping):
            raise TypeError("live semantic executor requires a resolved plan")
        self.plan = dict(plan)
        supplied = str(self.plan.get("plan_digest") or "")
        unsigned = {
            key: value for key, value in self.plan.items()
            if key != "plan_digest"
        }
        if (
            not _HEX64.fullmatch(supplied)
            or supplied != _digest(unsigned)
        ):
            raise LiveVerifyQueueSemanticError(
                "live semantic executor plan digest mismatch"
            )

    def __call__(
        self,
        *,
        unit: Mapping[str, Any],
        frozen_inputs: Mapping[str, bytes],
    ) -> Mapping[str, Any]:
        if not isinstance(unit, Mapping) or not isinstance(
            frozen_inputs, Mapping
        ):
            raise TypeError("semantic unit and frozen_inputs must be mappings")
        frozen = {
            str(path): bytes(raw) for path, raw in frozen_inputs.items()
            if isinstance(raw, (bytes, bytearray))
        }
        if len(frozen) != len(frozen_inputs):
            raise LiveVerifyQueueSemanticError(
                "semantic frozen denominator contains non-byte content"
            )
        work_id = str(unit.get("work_unit_id") or "")
        expected = {
            f"t{index}.": index for index in range(9)
        }
        stage = next(
            (index for prefix, index in expected.items() if work_id.startswith(prefix)),
            None,
        )
        if stage is None:
            raise LiveVerifyQueueSemanticError(
                f"semantic executor refuses non-T0--T8 unit {work_id!r}"
            )
        handlers = (
            lambda: _t0(unit, frozen, self.plan),
            lambda: _t1(unit, frozen),
            lambda: _t2(unit, frozen),
            lambda: _t3(unit, frozen),
            lambda: _t4(unit, frozen),
            lambda: _t5(unit, frozen),
            lambda: _t6(unit, frozen),
            lambda: _t7(unit, frozen, self.plan),
            lambda: _t8(unit, frozen, self.plan),
        )
        return handlers[stage]()


def build_live_verify_queue_semantic_executor(
    plan: Mapping[str, Any],
) -> LiveVerifyQueueSemanticExecutor:
    """Return the production callable accepted by ``execute_live_transaction``."""

    return LiveVerifyQueueSemanticExecutor(plan)


__all__ = [
    "LiveVerifyQueueSemanticError",
    "LiveVerifyQueueSemanticExecutor",
    "build_live_verify_queue_semantic_executor",
    "live_verify_queue_semantic_gap_map",
]
