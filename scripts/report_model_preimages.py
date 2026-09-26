"""Durable original bytes for report MODEL execution lineage."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
from types import MappingProxyType
from typing import Any, Mapping

from artifact_ledger import (
    read_artifact_ledger,
    stored_committed_work_unit_authority_issues,
)
import rooted_path_io as rooted
from worker_transaction import (
    WorkerTransactionError,
    replay_worker_execution_preimage_authority,
    validate_worker_execution_authority,
)
from phase_io_contracts import parse_report_body_attempt_work_unit


_STORE = "_report_model_preimages"
_MAX_PREIMAGE_BYTES = 16 * 1024 * 1024


class ReportModelPreimageError(ValueError):
    """The retained report MODEL preimage cannot be authenticated."""


@dataclass(frozen=True)
class ReportModelPreimages:
    preimages: Mapping[str, bytes]
    read_set: tuple[str, ...]
    execution_authority_digest: str


def _expected_identities(contract: Any, launch: Any) -> tuple[str, ...]:
    pipeline = getattr(contract, "pipeline", None)
    phase = getattr(contract, "phase", None)
    work_unit_id = getattr(contract, "work_unit_id", None)
    body_attempt = parse_report_body_attempt_work_unit(work_unit_id)
    if phase == "report_body":
        if body_attempt is not None and body_attempt[0] == "model":
            names = (f"{body_attempt[1]}.md",)
            report_model_id = True
        else:
            names = ()
            report_model_id = False
    elif phase == "report_index":
        names = (
            ("report_index.md", "report_coverage.md")
            if pipeline == "sc"
            else ("report_index.md", "report_coverage.md", "report_records.json")
            if pipeline == "l1"
            else ()
        )
        report_model_id = bool(
            work_unit_id == "model"
            or (
                isinstance(work_unit_id, str)
                and re.fullmatch(r"model\.attempt-[0-9]{4}", work_unit_id)
                and int(work_unit_id.rsplit("-", 1)[1]) >= 2
            )
        )
    else:
        names = ()
        report_model_id = False
    expected = tuple(f"scratchpad:{name}" for name in names)
    outputs = tuple(getattr(contract, "outputs", ()))
    if (
        phase not in {"report_index", "report_body"}
        or (phase == "report_index" and not names)
        or not report_model_id
        or tuple(item.identity for item in outputs) != expected
        or any(
            getattr(item, "writer", None) != "MODEL"
            or getattr(item, "root", None) != "scratchpad"
            or getattr(item, "owner_key", None) != getattr(contract, "key", None)
            for item in outputs
        )
        or getattr(launch, "work_unit_key", None) != getattr(contract, "key", None)
    ):
        raise ReportModelPreimageError(
            "report MODEL contract/launch denominator is unsupported"
        )
    return expected


def _authority(
    root: Path, *, contract: Any, launch: Any, run_id: str,
):
    expected = _expected_identities(contract, launch)
    try:
        ledger = read_artifact_ledger(root)
        unit = ledger.get("work_units", {}).get(contract.key)
        if not isinstance(unit, Mapping):
            raise ReportModelPreimageError("report MODEL work unit is absent")
        issues = stored_committed_work_unit_authority_issues(
            ledger, work_unit_key=contract.key, run_id=run_id,
            expected_artifact_identities=expected,
        )
        execution = unit.get("execution_authority")
        commit = unit.get("commit_authority")
        if issues:
            raise ReportModelPreimageError("; ".join(issues))
        if (
            unit.get("run_id") != run_id
            or unit.get("contract_digest") != contract.digest
            or unit.get("launch_digest") != launch.digest
            or unit.get("contract_manifest") != contract.to_dict()
            or unit.get("launch_manifest") != launch.to_dict()
        ):
            raise ReportModelPreimageError(
                "report MODEL stored contract/launch differs"
            )
        if (
            not isinstance(execution, Mapping)
            or not isinstance(commit, Mapping)
            or commit.get("execution_authority") != dict(execution)
        ):
            raise ReportModelPreimageError(
                "report MODEL commit/execution authority differs"
            )
        replay = replay_worker_execution_preimage_authority(
            scratchpad=root, authority=execution, contract=contract,
            launch=launch, run_id=run_id,
        )
        projected = {
            row.canonical_identity: (row.sha256, row.size)
            for row in replay.projected_members
        }
        artifacts = unit.get("artifacts")
        if not isinstance(artifacts, Mapping) or set(projected) != set(expected):
            raise ReportModelPreimageError(
                "report MODEL original output denominator differs"
            )
        if any(
            not isinstance(artifacts.get(identity), Mapping)
            or projected[identity] != (
                artifacts[identity].get("sha256"),
                artifacts[identity].get("size"),
            )
            for identity in expected
        ):
            raise ReportModelPreimageError(
                "report MODEL original artifact projection differs"
            )
        return unit, replay, projected
    except ReportModelPreimageError:
        raise
    except (OSError, TypeError, ValueError, WorkerTransactionError) as exc:
        raise ReportModelPreimageError(
            f"report MODEL preimage authority failed: {type(exc).__name__}: {exc}"
        ) from exc


def _stored_relative(digest: str, identity: str) -> str:
    relative = identity.removeprefix("scratchpad:")
    return f"{_STORE}/{digest}/{relative}"


def capture_report_model_preimages(
    root: Path, *, contract: Any, launch: Any, run_id: str,
) -> tuple[str, ...]:
    """Persist exact live MODEL bytes after strict worker replay."""

    try:
        base = rooted.checked_directory(root, label="report MODEL preimage root")
    except (OSError, ValueError, rooted.RootedPathIOError) as exc:
        raise ReportModelPreimageError(
            f"report MODEL preimage root failed: {type(exc).__name__}: {exc}"
        ) from exc
    unit, replay, projected = _authority(
        base, contract=contract, launch=launch, run_id=run_id
    )
    try:
        validate_worker_execution_authority(
            scratchpad=base, authority=unit["execution_authority"],
            contract=contract, launch=launch, run_id=run_id,
        )
        digest = replay.normalized_authority["authority_digest"]
        store = rooted.ensure_directory(
            base / _STORE / digest, mode=0o700,
            label="report MODEL preimage store",
        )
        stored: list[str] = []
        for identity in sorted(projected):
            relative = identity.removeprefix("scratchpad:")
            source = rooted.safe_descendant(
                base, relative, allow_missing=False,
                label="report MODEL live preimage",
            )
            raw = rooted.read_bytes(
                source, label="report MODEL live preimage",
                require_single_link=True, max_bytes=_MAX_PREIMAGE_BYTES,
            )
            sha256, size = projected[identity]
            if len(raw) != size or hashlib.sha256(raw).hexdigest() != sha256:
                raise ReportModelPreimageError(
                    f"{identity}: report MODEL live preimage changed"
                )
            destination = rooted.safe_descendant(
                store, relative, allow_missing=True,
                label="report MODEL persisted preimage",
            )
            rooted.ensure_directory(
                destination.parent, mode=0o700,
                label="report MODEL persisted preimage parent",
            )
            rooted.durable_write_once_bytes(destination, raw)
            stored.append(_stored_relative(digest, identity))
        return tuple(sorted((*stored, *replay.record_relative_paths)))
    except ReportModelPreimageError:
        raise
    except (OSError, TypeError, ValueError, rooted.RootedPathIOError,
            WorkerTransactionError) as exc:
        raise ReportModelPreimageError(
            f"report MODEL preimage capture failed: {type(exc).__name__}: {exc}"
        ) from exc


def read_report_model_preimages(
    root: Path, *, contract: Any, launch: Any, run_id: str,
) -> ReportModelPreimages:
    """Read authenticated original MODEL bytes without inspecting successors."""

    try:
        base = rooted.checked_directory(root, label="report MODEL preimage root")
    except (OSError, ValueError, rooted.RootedPathIOError) as exc:
        raise ReportModelPreimageError(
            f"report MODEL preimage root failed: {type(exc).__name__}: {exc}"
        ) from exc
    _unit, replay, projected = _authority(
        base, contract=contract, launch=launch, run_id=run_id
    )
    digest = replay.normalized_authority["authority_digest"]
    preimages: dict[str, bytes] = {}
    stored: list[str] = []
    try:
        for identity in sorted(projected):
            relative = _stored_relative(digest, identity)
            path = rooted.safe_descendant(
                base, relative, allow_missing=False,
                label="report MODEL persisted preimage",
            )
            raw = rooted.read_bytes(
                path, label="report MODEL persisted preimage",
                require_single_link=True, max_bytes=_MAX_PREIMAGE_BYTES,
            )
            sha256, size = projected[identity]
            if len(raw) != size or hashlib.sha256(raw).hexdigest() != sha256:
                raise ReportModelPreimageError(
                    f"{identity}: persisted report MODEL preimage differs"
                )
            preimages[identity] = raw
            stored.append(relative)
    except ReportModelPreimageError:
        raise
    except (OSError, TypeError, ValueError, rooted.RootedPathIOError) as exc:
        raise ReportModelPreimageError(
            f"report MODEL preimage read failed: {type(exc).__name__}: {exc}"
        ) from exc
    return ReportModelPreimages(
        preimages=MappingProxyType(preimages),
        read_set=tuple(sorted((*stored, *replay.record_relative_paths))),
        execution_authority_digest=digest,
    )


__all__ = [
    "ReportModelPreimageError", "ReportModelPreimages",
    "capture_report_model_preimages", "read_report_model_preimages",
]
