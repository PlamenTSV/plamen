"""Select or replay the immutable initial severity source transaction.

This driver-side selector publishes the empty or nonempty initial source exactly
once.  After a severity bind has started it never re-derives the nonempty
aggregate from the mutable decision files; it accepts only the shared bind
runner's authenticated resume view and the retained initial snapshot. The
resume validator is a concrete read-only API in ``severity_bind_transaction``;
no external design note or existence-only source adoption is authoritative.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Callable, Mapping

from artifact_ledger import ArtifactLedgerError, read_artifact_ledger
from phase_io_contracts import canonical_work_unit_key
import rooted_path_io as rooted
from severity_bind_transaction import validate_severity_bind_resume_state
from severity_empty_source import run_empty_severity_source
from severity_planning_inputs import (
    SOURCE_LEDGER_INPUT,
    validate_initial_severity_source_input,
)
from severity_source_aggregate import run_severity_source_aggregate


_SCHEMA = "plamen.severity-initial-source-selection.v1"
_SOURCE_PHASE = "severity_adjudication_shadow"
_SOURCE_KINDS = ("source_empty", "source_aggregate")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        dict(value), ensure_ascii=False, allow_nan=False,
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _dimensions(config: Mapping[str, Any]) -> tuple[str, str, str, str, str]:
    run_id = config.get("_run_id")
    pipeline = config.get("pipeline")
    mode = config.get("mode") or "core"
    ecosystem = config.get("language") or config.get("ecosystem") or "unknown"
    backend = config.get("cli_backend") or config.get("backend") or "claude"
    if (
        not isinstance(run_id, str) or not run_id
        or run_id != run_id.strip()
        or pipeline not in {"sc", "l1"}
        or not all(
            isinstance(value, str) and value and value == value.strip()
            for value in (mode, ecosystem, backend)
        )
    ):
        raise ArtifactLedgerError("severity source selection dimensions are invalid")
    return run_id, pipeline, mode, ecosystem, backend


def _source_keys(config: Mapping[str, Any]) -> dict[str, str]:
    _run_id, pipeline, mode, ecosystem, backend = _dimensions(config)
    return {
        kind: canonical_work_unit_key(
            pipeline, mode, ecosystem, backend, _SOURCE_PHASE, kind,
        )
        for kind in _SOURCE_KINDS
    }


def _present_source(
    ledger: Mapping[str, Any], keys: Mapping[str, str],
) -> str | None:
    units = ledger.get("work_units")
    if not isinstance(units, Mapping):
        raise ArtifactLedgerError("severity source work-unit ledger is absent")
    present = tuple(kind for kind, key in keys.items() if isinstance(units.get(key), Mapping))
    if len(present) > 1:
        raise ArtifactLedgerError("severity source has conflicting empty and aggregate owners")
    return present[0] if present else None


def _bind_unit_present(
    ledger: Mapping[str, Any], config: Mapping[str, Any],
) -> bool:
    _run_id, pipeline, mode, ecosystem, backend = _dimensions(config)
    prefix = canonical_work_unit_key(
        pipeline, mode, ecosystem, backend, _SOURCE_PHASE,
        "bind.0001.placeholder",
    ).rsplit("bind.0001.placeholder", 1)[0] + "bind."
    folded_prefix = prefix.casefold()
    units = ledger.get("work_units")
    if not isinstance(units, Mapping):
        raise ArtifactLedgerError("severity source work-unit ledger is absent")
    return any(
        isinstance(key, str) and key.casefold().startswith(folded_prefix)
        for key in units
    )


def _selection(
    *, kind: str, owner_key: str, raw: bytes, binding: Mapping[str, Any],
    bind_view: Mapping[str, Any] | None,
) -> dict[str, Any]:
    bind_authority = (
        None if bind_view is None else bind_view.get("authority_digest")
    )
    armed_candidate = (
        None if bind_view is None else bind_view.get("armed_candidate_id")
    )
    if bind_view is not None and (
        bind_view.get("source_owner_key") != owner_key
        or bind_view.get("source_ledger_sha256") != _sha(raw)
        or bind_view.get("source_ledger_size") != len(raw)
        or _HEX64.fullmatch(str(bind_authority or "")) is None
        or (armed_candidate is not None and not isinstance(armed_candidate, str))
    ):
        raise ArtifactLedgerError("severity bind resume view differs from initial source")
    core = {
        "schema": _SCHEMA,
        "source_kind": kind,
        "source_owner_key": owner_key,
        "source_ledger_path": SOURCE_LEDGER_INPUT,
        "source_ledger_sha256": _sha(raw),
        "source_ledger_size": len(raw),
        "source_binding": {
            field: binding.get(field)
            for field in (
                "owner_key", "writer", "run_id", "contract_digest",
                "launch_digest", "sha256", "size",
            )
        },
        "bind_resume_authority_digest": bind_authority,
        "armed_bind_candidate_id": armed_candidate,
    }
    return {**core, "authority_sha256": _sha(_canonical(core))}


def select_severity_initial_source(
    *,
    scratchpad: Path,
    project_root: Path,
    config: Mapping[str, Any],
    fault_hook: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Publish/replay one source and return its immutable authority receipt.

    A fresh invocation may publish.  Once any bind unit exists, this function
    is read-only and relies on the shared bind-resume validator; source
    aggregate derivation is intentionally forbidden in that state.
    """

    root = rooted.checked_directory(scratchpad, label="severity source selector root")
    project = rooted.checked_directory(
        project_root, label="severity source selector project",
    )
    configured_root = rooted.checked_directory(
        str(config.get("scratchpad") or ""),
        label="configured severity source selector root",
    )
    configured_project = rooted.checked_directory(
        str(config.get("project_root") or ""),
        label="configured severity source selector project",
    )
    if configured_root != root or configured_project != project:
        raise ArtifactLedgerError("severity source selector roots differ")
    keys = _source_keys(config)
    ledger = read_artifact_ledger(root)
    kind = _present_source(ledger, keys)
    binds_started = _bind_unit_present(ledger, config)

    if kind is None:
        if binds_started:
            raise ArtifactLedgerError("severity binds exist without an initial source")
        if run_empty_severity_source(
            scratchpad=root, project_root=project, config=config,
            fault_hook=fault_hook,
        ):
            kind = "source_empty"
        elif run_severity_source_aggregate(
            scratchpad=root, project_root=project, config=config,
            fault_hook=fault_hook,
        ):
            kind = "source_aggregate"
        else:
            raise ArtifactLedgerError("severity source denominator selected no producer")
        ledger = read_artifact_ledger(root)
        if _present_source(ledger, keys) != kind or _bind_unit_present(ledger, config):
            raise ArtifactLedgerError("severity source publication changed its denominator")
    elif kind == "source_empty":
        if binds_started:
            raise ArtifactLedgerError("empty severity source cannot have bind successors")
        if not run_empty_severity_source(
            scratchpad=root, project_root=project, config=config,
            fault_hook=fault_hook,
        ):
            raise ArtifactLedgerError("committed empty source no longer proves emptiness")
    elif not binds_started:
        if not run_severity_source_aggregate(
            scratchpad=root, project_root=project, config=config,
            fault_hook=fault_hook,
        ):
            raise ArtifactLedgerError("committed aggregate source became empty")

    owner_key = keys[kind]
    bind_view: Mapping[str, Any] | None = None
    if kind == "source_aggregate" and binds_started:
        # Required shared extraction from severity_bind_transaction.  It must
        # validate a contiguous committed prefix plus at most one exact armed
        # next bind, including stored plan/CAS/progress and registered source
        # histories, without publishing or re-deriving aggregate bytes.
        bind_view = validate_severity_bind_resume_state(root, project, config)
        raw = bind_view.get("source_ledger_bytes")
        binding = bind_view.get("source_binding")
        if type(raw) is not bytes or not isinstance(binding, Mapping):
            raise ArtifactLedgerError("severity bind resume source view is malformed")
    else:
        raw, binding = validate_initial_severity_source_input(
            root, project, config=config,
        )
    if binding.get("owner_key") != owner_key:
        raise ArtifactLedgerError("severity source snapshot owner differs from selection")

    result = _selection(
        kind=kind, owner_key=owner_key, raw=raw, binding=binding,
        bind_view=bind_view,
    )
    if kind == "source_aggregate" and binds_started:
        final_view = validate_severity_bind_resume_state(root, project, config)
        if final_view != bind_view:
            raise ArtifactLedgerError("severity bind resume authority changed during replay")
    else:
        final_raw, final_binding = validate_initial_severity_source_input(
            root, project, config=config,
        )
        if final_raw != raw or final_binding != binding:
            raise ArtifactLedgerError("severity source selection changed during replay")
    if _present_source(read_artifact_ledger(root), keys) != kind:
        raise ArtifactLedgerError("severity source owner changed during replay")
    return result


__all__ = ["select_severity_initial_source"]
