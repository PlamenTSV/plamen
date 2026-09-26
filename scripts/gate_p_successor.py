"""Recoverable Gate-P publication as one coupled canonical successor.

Gate P is evaluated in an isolated directory.  Its exact source preimages and
planned canonical postimages are first sealed in an immutable PhaseIO artifact;
only then may the canonical ID ledger, record projection, and inventory be
published under one ordered driver-successor transaction.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tempfile
from typing import Any, Callable, Mapping, Sequence
import re

from artifact_ledger import (
    ArtifactLedgerError,
    begin_driver_successor_step,
    complete_driver_successor_step,
    load_driver_successor_plan,
    plan_driver_successor_transaction,
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
    validate_work_unit_artifacts,
    validate_work_unit_inputs,
)
from driver_successor_io import (
    canonicalize_trusted_driver_temporary_directory,
    materialize_driver_successor_transition,
)
from phase_io_contracts import LaunchSpec, PhaseIOContract, resolve_phase_io_contract


PLAN_NAME = "gate_p_successor_plan.json"
RECEIPT_NAME = "gate_p_successor_receipt.json"
CANONICAL_NAMES = (
    "_id_ledger.json",
    "finding_records.json",
    "findings_inventory.md",
)
_DERIVED_NAMES = (
    "promotion_coverage_seed.md",
    "promotion_orphans.md",
    "promotion_routing.md",
    "promotion_orphans_appendix_c.md",
    "promotion_orphans_appendix_a.md",
    "promotion_gate_receipt.md",
)
_PUBLISHED_DIAGNOSTIC_NAMES = tuple(
    name for name in _DERIVED_NAMES
    if name != "promotion_coverage_seed.md"
)
SUCCESSOR_OUTPUTS = (
    *CANONICAL_NAMES,
    *_PUBLISHED_DIAGNOSTIC_NAMES,
    RECEIPT_NAME,
)
PLAN_SCHEMA = "plamen.gate_p_successor_plan.v1"
RECEIPT_SCHEMA = "plamen.gate_p_successor_receipt.v1"
_MAX_SOURCES = 256
_MAX_SOURCE_BYTES = 64 * 1024 * 1024
# ``_artifact_state.json`` is required inside Gate P's disposable stage so
# registered-delivery validators can replay the exact producer lineage that
# existed when the plan was evaluated.  It is nevertheless the PhaseIO
# transaction journal: arming ``gate_p.source_capture`` necessarily rewrites
# it.  Treating the whole journal as an immutable semantic input therefore
# creates a self-invalidating transaction.  It remains hash-sealed in the
# Gate-P plan and is checked before the capture work unit is armed, but is not
# part of that work unit's post-arm CAS denominator.
_VOLATILE_CONTROL_WITNESS_NAMES = frozenset({"_artifact_state.json"})
_STRUCTURED_ID_RE = re.compile(
    r"(?<![A-Za-z0-9_-])([A-Za-z][A-Za-z0-9]*(?:[_-][A-Za-z0-9]+)*-\d+)"
    r"(?![A-Za-z0-9_-])"
)


class GatePSuccessorError(RuntimeError):
    """A Gate-P plan or transaction failed closed."""


def _json_bytes(payload: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(
            payload,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _digest(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(_json_bytes(payload)).hexdigest()


def _byte_row(name: str, raw: bytes, *, content: bool) -> dict[str, Any]:
    row: dict[str, Any] = {
        "path": name,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
    }
    if content:
        row["content_b64"] = base64.b64encode(raw).decode("ascii")
    return row


def _decode_row(row: Mapping[str, Any]) -> bytes:
    try:
        raw = base64.b64decode(str(row["content_b64"]), validate=True)
        size = int(row["size"])
        digest = str(row["sha256"])
    except (KeyError, TypeError, ValueError) as exc:
        raise GatePSuccessorError("Gate-P byte row is malformed") from exc
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
        raise GatePSuccessorError("Gate-P byte row digest differs")
    return raw


def _safe_source_name(value: str) -> str:
    name = str(value or "")
    candidate = PurePosixPath(name)
    if (
        not name
        or candidate.is_absolute()
        or len(candidate.parts) != 1
        or candidate.name != name
        or name in {PLAN_NAME, RECEIPT_NAME}
    ):
        raise GatePSuccessorError(f"invalid Gate-P source path: {name!r}")
    return name


def gate_p_source_names(scratchpad: Path) -> tuple[str, ...]:
    """Return the exact bounded top-level denominator read by Gate P."""

    from plamen_mechanical import _PROMO_EXCLUDE_NAMES, _PROMO_FEEDER_GLOBS

    root = Path(scratchpad)
    names: set[str] = set()
    mandatory = (*CANONICAL_NAMES, "promotion_coverage_seed.md")
    for name in mandatory:
        if not (root / name).is_file():
            raise GatePSuccessorError(f"required Gate-P source is absent: {name}")
        names.add(name)
    for name in (
        "finding_mapping.md",
        "inventory_reconciliation.json",
        "report_index_coverage_seed.md",
        "promotion_gate_receipt.md",
    ):
        if (root / name).is_file():
            names.add(name)
    for pattern in _PROMO_FEEDER_GLOBS:
        for path in root.glob(pattern):
            if (
                path.name not in _PROMO_EXCLUDE_NAMES
                and path.parent == root
                and path.is_file()
                and not path.is_symlink()
            ):
                names.add(path.name)
    from finding_producer_registry import (
        registered_delivery_scratchpad_authority_files,
    )

    names.update(registered_delivery_scratchpad_authority_files(root))
    ordered = tuple(sorted(names, key=lambda item: (item.casefold(), item)))
    if len(ordered) > _MAX_SOURCES:
        raise GatePSuccessorError("Gate-P source denominator exceeds hard bound")
    return ordered


def _safe_project_relative(value: str) -> str:
    relative = str(value or "")
    path = PurePosixPath(relative)
    if (
        not relative
        or "\\" in relative
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.as_posix() != relative
    ):
        raise GatePSuccessorError(
            f"invalid Gate-P project source path: {relative!r}"
        )
    return relative


def _registered_delivery_project_source_rows(
    root: Path,
) -> tuple[dict[str, Any], ...]:
    """Capture project inputs already bound by enumgap reconciliation."""

    state_path = Path(root) / "_artifact_state.json"
    obligation_path = Path(root) / "exploration_clear_obligations.json"
    if not obligation_path.is_file():
        return ()
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise GatePSuccessorError(
            f"registered-delivery PhaseIO state is unavailable: {exc}"
        ) from exc
    bindings = state.get("artifact_bindings")
    units = state.get("work_units")
    output = (
        bindings.get("scratchpad:enumgap_disposition_receipt.json")
        if isinstance(bindings, Mapping) else None
    )
    owner = str(output.get("owner_key") or "") if isinstance(output, Mapping) else ""
    unit = units.get(owner) if isinstance(units, Mapping) else None
    input_bindings = unit.get("input_bindings") if isinstance(unit, Mapping) else None
    if not isinstance(input_bindings, Mapping):
        # No terminal enumgap authority exists yet.  The staged registered
        # projection will retain the obligations as visible debt.
        return ()
    project = Path(root).parent
    rows: list[dict[str, Any]] = []
    for identity, binding in sorted(input_bindings.items()):
        if not str(identity).startswith("project:"):
            continue
        if not isinstance(binding, Mapping):
            raise GatePSuccessorError(
                f"Gate-P project input binding is malformed: {identity}"
            )
        relative = _safe_project_relative(str(identity).split(":", 1)[1])
        raw = _read_regular_project_source(project, relative)
        if (
            binding.get("status") != "ACTIVE"
            or binding.get("sha256") != hashlib.sha256(raw).hexdigest()
            or binding.get("size") != len(raw)
        ):
            raise GatePSuccessorError(
                f"Gate-P project input differs from enumgap authority: {relative}"
            )
        rows.append(_byte_row(relative, raw, content=False))
    return tuple(rows)


def _read_regular_project_source(project: Path, relative: str) -> bytes:
    path = Path(project).joinpath(*PurePosixPath(relative).parts)
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise GatePSuccessorError(
            f"Gate-P project source is unreadable: {relative}"
        ) from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or int(getattr(metadata, "st_nlink", 1) or 1) != 1
        or int(metadata.st_size) > _MAX_SOURCE_BYTES
    ):
        raise GatePSuccessorError(
            f"Gate-P project source is not an admitted regular file: {relative}"
        )
    raw = path.read_bytes()
    confirmed = os.lstat(path)
    if (
        int(confirmed.st_dev) != int(metadata.st_dev)
        or int(confirmed.st_ino) != int(metadata.st_ino)
        or int(confirmed.st_size) != int(metadata.st_size)
        or int(confirmed.st_mtime_ns) != int(metadata.st_mtime_ns)
    ):
        raise GatePSuccessorError(
            f"Gate-P project source changed while captured: {relative}"
        )
    return raw


def write_promotion_coverage_seed(scratchpad: Path) -> int:
    """Write the structured identities/subjects already retained pre-Gate-P."""

    from plamen_mechanical import promotion_reconciled_subjects
    from plamen_parsers import parse_finding_mapping_rows

    root = Path(scratchpad)
    ids: set[str] = set()
    try:
        subjects = set(promotion_reconciled_subjects(root))
    except Exception:
        subjects = set()
    inventory = root / "findings_inventory.md"
    if inventory.is_file():
        text = inventory.read_text(encoding="utf-8", errors="replace")
        for match in re.finditer(
            r"(?im)^\s*#{2,4}\s+Finding\s+\[([^\]\r\n]+)\]", text
        ):
            identity = match.group(1).strip().upper()
            if _STRUCTURED_ID_RE.fullmatch(identity):
                ids.add(identity)
        for match in re.finditer(
            r"(?im)^\s*(?:[-*]\s*)?(?:\*\*)?Source\s+IDs?(?:\*\*)?\s*:\s*([^\r\n]+)",
            text,
        ):
            ids.update(item.group(1).upper() for item in _STRUCTURED_ID_RE.finditer(match.group(1)))
        subjects.update(re.findall(
            r"(?im)^\s*\*\*Promotion Subject SHA256\*\*:\s*([0-9a-f]{64})\s*$",
            text,
        ))
    mapping = root / "finding_mapping.md"
    if mapping.is_file():
        try:
            for row in parse_finding_mapping_rows(mapping.read_text(encoding="utf-8", errors="replace")):
                ids.update(str(item).upper() for item in row.get("source_ids", []))
                ids.update(str(item).upper() for item in row.get("hypothesis_ids", []))
        except Exception:
            pass
    try:
        from semantic_dedup_authority import load_applied_aliases

        for absorbed, info in load_applied_aliases(root).items():
            ids.add(str(absorbed).upper())
            survivor = str((info or {}).get("survivor") or "").upper()
            if survivor:
                ids.add(survivor)
    except Exception:
        pass
    ids = {identity for identity in ids if _STRUCTURED_ID_RE.fullmatch(identity)}
    lines = [
        "# Promotion Coverage Seed", "", "**Status**: DRIVER_ENUMERATED_PREVERIFY", "",
        "Exact structured identities already retained before the verification queue freezes. Gate P uses this only as a coverage denominator.",
        "", "| Finding/Hyp ID | Expected Severity | Verdict | Mapped Hypothesis | Dedup Relation |",
        "|---|---|---|---|---|",
        *(f"| {identity} | | RETAINED | | |" for identity in sorted(ids)),
    ]
    if not ids:
        lines.append("| (none) | | | | no structured identities found |")
    lines.extend([
        "", "## Delivered Promotion Subjects", "",
        "Full cryptographic subjects already materialized in the canonical inventory. Producer-local IDs and location similarity are not subject identity.",
        "", "| Subject SHA256 | Status |", "|---|---|",
        *(f"| {subject} | DELIVERED |" for subject in sorted(subjects)),
    ])
    if not subjects:
        lines.append("| (none) | no delivered promotion subjects |")
    materialize_driver_successor_transition(
        root / "promotion_coverage_seed.md", ("\n".join(lines) + "\n").encode("utf-8")
    )
    return len(ids)


def _read_regular_source(root: Path, name: str) -> bytes:
    path = root / _safe_source_name(name)
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise GatePSuccessorError(f"Gate-P source is unreadable: {name}") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or int(getattr(metadata, "st_nlink", 1) or 1) != 1
        or int(metadata.st_size) > _MAX_SOURCE_BYTES
    ):
        raise GatePSuccessorError(f"Gate-P source is not an admitted regular file: {name}")
    raw = path.read_bytes()
    confirmed = os.lstat(path)
    if (
        int(confirmed.st_dev) != int(metadata.st_dev)
        or int(confirmed.st_ino) != int(metadata.st_ino)
        or int(confirmed.st_size) != int(metadata.st_size)
        or int(confirmed.st_mtime_ns) != int(metadata.st_mtime_ns)
    ):
        raise GatePSuccessorError(f"Gate-P source changed while captured: {name}")
    return raw


def _default_evaluator(stage: Path) -> Mapping[str, Any]:
    from plamen_mechanical import compute_promotion_orphans, route_promotion_orphans

    orphans = compute_promotion_orphans(stage)
    return route_promotion_orphans(stage, orphans)


def build_gate_p_plan(
    scratchpad: Path,
    *,
    run_id: str,
    dimensions: Mapping[str, str],
    source_names: Sequence[str],
    evaluator: Callable[[Path], Mapping[str, Any]] | None = None,
) -> bytes:
    """Evaluate Gate P off-line and return its self-authenticating plan bytes."""

    root = Path(scratchpad)
    ordered = tuple(_safe_source_name(name) for name in source_names)
    if (
        not ordered
        or len(ordered) != len(set(ordered))
        or len(ordered) > _MAX_SOURCES
        or not set(CANONICAL_NAMES).issubset(ordered)
    ):
        raise GatePSuccessorError("Gate-P exact source denominator is invalid")
    sources: list[dict[str, Any]] = []
    preimages: dict[str, dict[str, Any]] = {}
    project_sources = _registered_delivery_project_source_rows(root)
    with tempfile.TemporaryDirectory(prefix="plamen-gate-p-") as temporary:
        project_stage = Path(temporary) / "project"
        stage = project_stage / ".scratchpad"
        stage.mkdir(parents=True)
        stage = canonicalize_trusted_driver_temporary_directory(stage)
        for name in ordered:
            raw = _read_regular_source(root, name)
            sources.append(_byte_row(name, raw, content=False))
            (stage / name).write_bytes(raw)
            if name in CANONICAL_NAMES:
                preimages[name] = _byte_row(name, raw, content=True)
        for row in project_sources:
            relative = _safe_project_relative(str(row["path"]))
            raw = _read_regular_project_source(root.parent, relative)
            target = project_stage.joinpath(*PurePosixPath(relative).parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        result = dict((evaluator or _default_evaluator)(stage))
        # Gate P and the verification queue share one exact registered-action
        # denominator.  Prove the producer postcondition inside disposable
        # staging before sealing or publishing any canonical postimage; a
        # lossy/capped promotion can no longer commit and surprise a later
        # phase boundary.
        from plamen_validators import registered_finding_delivery_projection

        delivery = registered_finding_delivery_projection(stage)
        residual = [str(row) for row in delivery.get("residual_debt") or ()]
        if delivery.get("status") != "CLEAN" or residual:
            preview = "; ".join(residual[:6]) or "unknown delivery debt"
            raise GatePSuccessorError(
                "Gate-P staged registered-action postcondition is not clean: "
                + preview
            )
        postimages: dict[str, dict[str, Any]] = {}
        for name in CANONICAL_NAMES:
            raw = _read_regular_source(stage, name)
            postimages[name] = _byte_row(name, raw, content=True)
        derived: list[dict[str, Any]] = []
        for name in _DERIVED_NAMES:
            path = stage / name
            if path.is_file() and not path.is_symlink():
                derived.append(_byte_row(name, path.read_bytes(), content=True))
    unsigned = {
        "schema_version": PLAN_SCHEMA,
        "run_id": str(run_id),
        "dimensions": {
            key: str(dimensions[key])
            for key in ("pipeline", "mode", "ecosystem", "backend")
        },
        "source_preimages": sources,
        "project_source_preimages": list(project_sources),
        "canonical_preimages": preimages,
        "canonical_postimages": postimages,
        "derived_diagnostics": derived,
        "result": result,
    }
    return _json_bytes({**unsigned, "plan_sha256": _digest(unsigned)})


def load_gate_p_plan(raw: bytes) -> dict[str, Any]:
    try:
        payload = json.loads(raw.decode("utf-8", errors="strict"))
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise GatePSuccessorError("Gate-P plan is not canonical JSON") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != PLAN_SCHEMA:
        raise GatePSuccessorError("Gate-P plan schema differs")
    unsigned = dict(payload)
    supplied = str(unsigned.pop("plan_sha256", ""))
    if supplied != _digest(unsigned):
        raise GatePSuccessorError("Gate-P plan digest differs")
    sources = payload.get("source_preimages")
    project_sources = payload.get("project_source_preimages")
    preimages = payload.get("canonical_preimages")
    postimages = payload.get("canonical_postimages")
    derived = payload.get("derived_diagnostics")
    if (
        not isinstance(sources, list)
        or not isinstance(project_sources, list)
        or not isinstance(preimages, dict)
        or not isinstance(postimages, dict)
        or not isinstance(derived, list)
        or set(preimages) != set(CANONICAL_NAMES)
        or set(postimages) != set(CANONICAL_NAMES)
    ):
        raise GatePSuccessorError("Gate-P plan denominator differs")
    source_names = [str(row.get("path", "")) for row in sources if isinstance(row, dict)]
    if (
        len(source_names) != len(sources)
        or len(source_names) != len(set(source_names))
        or any(_safe_source_name(name) != name for name in source_names)
    ):
        raise GatePSuccessorError("Gate-P source rows differ")
    project_names = [
        str(row.get("path", ""))
        for row in project_sources
        if isinstance(row, dict)
    ]
    if (
        len(project_names) != len(project_sources)
        or len(project_names) != len(set(project_names))
        or any(_safe_project_relative(name) != name for name in project_names)
    ):
        raise GatePSuccessorError("Gate-P project source rows differ")
    for row in project_sources:
        if "content_b64" in row:
            raise GatePSuccessorError(
                "Gate-P project preimage unexpectedly embeds content"
            )
        if (
            type(row.get("size")) is not int
            or int(row["size"]) < 0
            or not re.fullmatch(r"[0-9a-f]{64}", str(row.get("sha256") or ""))
        ):
            raise GatePSuccessorError("Gate-P project source row is malformed")
    for name in CANONICAL_NAMES:
        if str(preimages[name].get("path", "")) != name:
            raise GatePSuccessorError("Gate-P canonical preimage identity differs")
        if str(postimages[name].get("path", "")) != name:
            raise GatePSuccessorError("Gate-P canonical postimage identity differs")
        _decode_row(preimages[name])
        _decode_row(postimages[name])
    derived_names = [
        str(row.get("path", ""))
        for row in derived
        if isinstance(row, dict)
    ]
    if (
        len(derived_names) != len(derived)
        or set(derived_names) != set(_DERIVED_NAMES)
        or len(derived_names) != len(set(derived_names))
    ):
        missing = sorted(set(_DERIVED_NAMES) - set(derived_names))
        extra = sorted(set(derived_names) - set(_DERIVED_NAMES))
        raise GatePSuccessorError(
            "Gate-P derived diagnostic denominator differs "
            f"(missing={missing}, extra={extra})"
        )
    for row in derived:
        _decode_row(row)
    return payload


def _contract_pair(
    dimensions: Mapping[str, str],
    *,
    work_unit_id: str,
    exact_inputs: Sequence[str],
    exact_outputs: Sequence[str],
) -> tuple[PhaseIOContract, LaunchSpec]:
    contract = resolve_phase_io_contract(
        pipeline=str(dimensions["pipeline"]),
        mode=str(dimensions["mode"]),
        ecosystem=str(dimensions["ecosystem"]),
        backend=str(dimensions["backend"]),
        phase="inventory",
        work_unit_id=work_unit_id,
        exact_inputs=tuple(exact_inputs),
        exact_outputs=tuple(exact_outputs),
    )
    return contract, LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="driver",
        timeout_s=120,
        exec_mode="python",
        tool_policy=(),
    )


def _source_cas(
    root: Path,
    payload: Mapping[str, Any],
    *,
    include_volatile_control: bool = False,
) -> list[str]:
    issues: list[str] = []
    for row in payload["source_preimages"]:
        name = str(row["path"])
        if (
            not include_volatile_control
            and name in _VOLATILE_CONTROL_WITNESS_NAMES
        ):
            continue
        try:
            raw = _read_regular_source(root, name)
        except GatePSuccessorError as exc:
            issues.append(str(exc))
            continue
        if len(raw) != row["size"] or hashlib.sha256(raw).hexdigest() != row["sha256"]:
            issues.append(f"Gate-P source changed after planning: {name}")
    for row in payload.get("project_source_preimages", ()):
        name = str(row["path"])
        try:
            raw = _read_regular_project_source(root.parent, name)
        except GatePSuccessorError as exc:
            issues.append(str(exc))
            continue
        if len(raw) != row["size"] or hashlib.sha256(raw).hexdigest() != row["sha256"]:
            issues.append(f"Gate-P project source changed after planning: {name}")
    return issues


def _capture_plan(
    root: Path,
    project: Path,
    *,
    run_id: str,
    dimensions: Mapping[str, str],
    plan_raw: bytes,
    payload: Mapping[str, Any],
    failpoint: Callable[[str], None] | None,
) -> None:
    source_names = tuple(str(row["path"]) for row in payload["source_preimages"])
    semantic_source_names = tuple(
        name
        for name in source_names
        if name not in _VOLATILE_CONTROL_WITNESS_NAMES
    )
    contract, launch = _contract_pair(
        dimensions,
        work_unit_id="gate_p.source_capture",
        exact_inputs=semantic_source_names,
        exact_outputs=(PLAN_NAME,),
    )
    ledger = read_artifact_ledger(root)
    prior = ledger.get("work_units", {}).get(contract.key)
    if prior is None:
        if (root / PLAN_NAME).exists() or (root / PLAN_NAME).is_symlink():
            raise GatePSuccessorError("unowned Gate-P plan already exists")
        # Close the build->arm race over every staged witness, including the
        # live PhaseIO journal.  The journal is expected to change *because*
        # of the following arm, so later CAS checks deliberately cover only
        # semantic sources and project inputs.
        drift = _source_cas(
            root, payload, include_volatile_control=True
        )
        if drift:
            raise GatePSuccessorError("; ".join(drift))
        record_work_unit_inputs(root, project, contract, launch, run_id=run_id)
    elif not isinstance(prior, Mapping):
        raise GatePSuccessorError("Gate-P capture work unit is malformed")
    issues = validate_work_unit_inputs(root, project, contract, launch, run_id=run_id)
    if issues:
        raise GatePSuccessorError("; ".join(issues))
    if prior is not None and prior.get("execution_state") == "OUTPUT_COMMITTED":
        issues = validate_work_unit_artifacts(
            root, project, contract, launch, run_id=run_id, actor="DRIVER"
        )
        if issues or (root / PLAN_NAME).read_bytes() != plan_raw:
            raise GatePSuccessorError("; ".join(issues or ["committed Gate-P plan differs"]))
        return
    drift = _source_cas(root, payload)
    if drift:
        raise GatePSuccessorError("; ".join(drift))
    if failpoint is not None:
        failpoint("capture:before_publish")
    target = root / PLAN_NAME
    if target.is_file():
        if target.read_bytes() != plan_raw:
            raise GatePSuccessorError("uncommitted Gate-P plan bytes differ")
    else:
        materialize_driver_successor_transition(target, plan_raw)
    if failpoint is not None:
        failpoint("capture:after_publish")
    record_work_unit_artifacts(
        root, project, contract, launch, run_id=run_id, actor="DRIVER"
    )
    issues = validate_work_unit_artifacts(
        root, project, contract, launch, run_id=run_id, actor="DRIVER"
    )
    if issues:
        raise GatePSuccessorError("; ".join(issues))


def _receipt_bytes(payload: Mapping[str, Any]) -> bytes:
    return _json_bytes({
        "schema_version": RECEIPT_SCHEMA,
        "plan_sha256": payload["plan_sha256"],
        "run_id": payload["run_id"],
        "canonical_preimages": payload["canonical_preimages"],
        "canonical_postimages": payload["canonical_postimages"],
        "result": payload.get("result", {}),
        "status": "FINALIZED",
    })


def _assert_live_preimages(root: Path, payload: Mapping[str, Any]) -> None:
    for name in CANONICAL_NAMES:
        expected = _decode_row(payload["canonical_preimages"][name])
        try:
            live = _read_regular_source(root, name)
        except GatePSuccessorError as exc:
            raise GatePSuccessorError(f"Gate-P predecessor invalid: {name}") from exc
        if live != expected:
            raise GatePSuccessorError(f"Gate-P predecessor changed: {name}")


def run_gate_p_coupled_successor(
    scratchpad: Path,
    project_root: Path,
    *,
    run_id: str,
    dimensions: Mapping[str, str],
    source_names: Sequence[str] | None = None,
    evaluator: Callable[[Path], Mapping[str, Any]] | None = None,
    failpoint: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Publish Gate P's canonical triplet and return consumption authority."""

    root = Path(scratchpad)
    project = Path(project_root)
    if not str(run_id or "").strip():
        raise GatePSuccessorError("Gate-P successor run_id is absent")
    successor_contract, successor_launch = _contract_pair(
        dimensions,
        work_unit_id="gate_p_successor",
        exact_inputs=(PLAN_NAME,),
        exact_outputs=SUCCESSOR_OUTPUTS,
    )
    prior = read_artifact_ledger(root).get("work_units", {}).get(successor_contract.key)
    successor_armed = isinstance(prior, Mapping) and (
        "successor_consumption_authority" in prior
        or prior.get("execution_state") == "OUTPUT_COMMITTED"
    )

    plan_path = root / PLAN_NAME
    if plan_path.is_file():
        plan_raw = plan_path.read_bytes()
        payload = load_gate_p_plan(plan_raw)
    else:
        if successor_armed:
            raise GatePSuccessorError("armed Gate-P successor lost its immutable plan")
        names = tuple(source_names or gate_p_source_names(root))
        plan_raw = build_gate_p_plan(
            root,
            run_id=run_id,
            dimensions=dimensions,
            source_names=names,
            evaluator=evaluator,
        )
        payload = load_gate_p_plan(plan_raw)
    if payload.get("run_id") != run_id or payload.get("dimensions") != {
        key: str(dimensions[key])
        for key in ("pipeline", "mode", "ecosystem", "backend")
    }:
        raise GatePSuccessorError("Gate-P plan run or dimensions differ")

    if not successor_armed:
        _capture_plan(
            root,
            project,
            run_id=run_id,
            dimensions=dimensions,
            plan_raw=plan_raw,
            payload=payload,
            failpoint=failpoint,
        )
        if failpoint is not None:
            failpoint("after_capture")
        _assert_live_preimages(root, payload)

    planned = {
        **{
            f"scratchpad:{name}": _decode_row(payload["canonical_postimages"][name])
            for name in CANONICAL_NAMES
        },
        **{
            f"scratchpad:{str(row['path'])}": _decode_row(row)
            for row in payload["derived_diagnostics"]
            if str(row["path"]) in _PUBLISHED_DIAGNOSTIC_NAMES
        },
        f"scratchpad:{RECEIPT_NAME}": _receipt_bytes(payload),
    }
    if successor_armed:
        transaction = load_driver_successor_plan(
            root,
            project,
            successor_contract,
            successor_launch,
            run_id=run_id,
        )
        expected = {
            identity: {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}
            for identity, raw in planned.items()
        }
        if transaction.expected_output_records != expected:
            raise GatePSuccessorError("Gate-P armed plan postimages differ")
    else:
        transaction = plan_driver_successor_transaction(
            root,
            project,
            successor_contract,
            successor_launch,
            run_id=run_id,
            planned_output_bytes=planned,
            merge_events={},
        )
        if failpoint is not None:
            failpoint("after_plan")
        record_work_unit_inputs(
            root,
            project,
            successor_contract,
            successor_launch,
            run_id=run_id,
            successor_plan=transaction,
        )
        issues = validate_work_unit_inputs(
            root, project, successor_contract, successor_launch, run_id=run_id
        )
        if issues:
            raise GatePSuccessorError("; ".join(issues))
        if failpoint is not None:
            failpoint("after_arm")

    committed_issues = validate_work_unit_artifacts(
        root,
        project,
        successor_contract,
        successor_launch,
        run_id=run_id,
        actor="DRIVER",
        require_live_input_authority=False,
    )
    unit = read_artifact_ledger(root).get("work_units", {}).get(successor_contract.key)
    already_committed = (
        isinstance(unit, Mapping)
        and unit.get("semantic_status") == "ACTIVE"
        and unit.get("execution_state") == "OUTPUT_COMMITTED"
        and not committed_issues
    )
    if not already_committed:
        for transition in transaction.transitions:
            ordinal = int(transition.ordinal)
            identity = str(transition.artifact_identity)
            progress = begin_driver_successor_step(
                root,
                project,
                successor_contract,
                successor_launch,
                run_id=run_id,
                ordinal=ordinal,
            )
            if progress.get("state") != "STEP_APPLIED":
                name = identity.split(":", 1)[1]
                materialize_driver_successor_transition(root / name, planned[identity])
                if failpoint is not None:
                    failpoint(f"after_replace_{ordinal}")
                complete_driver_successor_step(
                    root,
                    project,
                    successor_contract,
                    successor_launch,
                    run_id=run_id,
                    ordinal=ordinal,
                )
            if failpoint is not None:
                failpoint(f"after_output_{ordinal}")
        if failpoint is not None:
            failpoint("before_commit")
        record_work_unit_artifacts(
            root,
            project,
            successor_contract,
            successor_launch,
            run_id=run_id,
            actor="DRIVER",
            expected_output_records=transaction.expected_output_records,
        )
        if failpoint is not None:
            failpoint("after_commit")

    issues = validate_work_unit_artifacts(
        root,
        project,
        successor_contract,
        successor_launch,
        run_id=run_id,
        actor="DRIVER",
        require_live_input_authority=False,
    )
    if issues:
        raise GatePSuccessorError("; ".join(issues))
    return {
        "status": "FINALIZED",
        "safe_to_consume": True,
        "issues": [],
        "result": dict(payload.get("result") or {}),
        "work_unit_key": successor_contract.key,
        "reused": bool(successor_armed or already_committed),
    }


__all__ = [
    "CANONICAL_NAMES",
    "GatePSuccessorError",
    "PLAN_NAME",
    "RECEIPT_NAME",
    "SUCCESSOR_OUTPUTS",
    "build_gate_p_plan",
    "gate_p_source_names",
    "load_gate_p_plan",
    "run_gate_p_coupled_successor",
    "write_promotion_coverage_seed",
]
