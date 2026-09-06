"""Pre-arm authority for SC verify-queue dynamic P0-AF inputs.

The live T0 transaction must know its complete immutable denominator before
it arms.  This module resolves candidate-referenced fact sources from the
typed P0-AF candidate authority, requires exact current-run producer ancestry
for every positive source, and commits either a content-addressed manifest or
bounded visible debt through one PhaseIO work unit.

No directory enumeration or globbing is performed.  Invalid optional inputs
degrade to debt and never become positive authority.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
from typing import Any, Mapping, Sequence

from artifact_ledger import (
    ArtifactLedgerError,
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
    semantic_input_prebind_producer_authority_issues,
    validate_work_unit_artifacts,
)
from bounded_artifact_io import read_bounded_regular_bytes
import p0af_v2_queue_adapter as _p0af
from phase_io_contracts import (
    ArtifactSpec,
    ConditionalOutputReceipt,
    LaunchSpec,
    PhaseIOContract,
    canonical_artifact_identity,
    canonical_work_unit_key,
)


MANIFEST_FILE = "prearm_content_addressed_inputs.json"
DEBT_FILE = "prearm_content_addressed_inputs.debt.json"
RECEIPT_FILE = "prearm_content_addressed_inputs.receipt.json"
WORK_UNIT_ID = "prearm_dynamic_inputs"
PRESENCE_AUTHORITY_FILE = "prearm_presence_authority.json"
PRESENCE_WORK_UNIT_ID = "prearm_presence_authority"

_RECEIPT_SCHEMA = "plamen.prearm_dynamic_input_resolution.v1"
_DEBT_SCHEMA = "plamen.prearm_dynamic_input_resolution_debt.v1"
_MANIFEST_SCHEMA = "plamen.prearm_content_addressed_input_manifest.v1"
_MAX_DEBT_BYTES = 64 * 1024
_MAX_DEBT_ISSUES = 32
_MAX_DEBT_DETAIL = 512
_MAX_PRESENCE_MEMBER_BYTES = 64 * 1024 * 1024
_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)


class LiveVerifyQueuePrearmInputError(ValueError):
    """The pre-arm resolver itself cannot establish safe output authority."""


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


def _payload_digest(value: Mapping[str, Any]) -> str:
    unsigned = {
        key: item for key, item in value.items() if key != "payload_digest"
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


def _stable_digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _safe_relative(value: Any) -> str:
    text = str(value or "").strip().replace("\\", "/")
    path = PurePosixPath(text)
    if (
        not text
        or path.is_absolute()
        or re.match(r"^[A-Za-z]:", text)
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(token in text for token in "*?[")
        or ":" in text
    ):
        raise ValueError(f"unsafe prearm source artifact: {value!r}")
    return path.as_posix()


def _authority_relative(identity: Any) -> str:
    text = str(identity or "").strip().replace("\\", "/")
    if not text.startswith("scratchpad:"):
        raise ValueError("prearm presence authority must be scratchpad-owned")
    return _safe_relative(text[len("scratchpad:"):])


def _presence_dimensions(
    *,
    pipeline: str,
    mode: str,
    ecosystem: str,
    backend: str,
    phase_name: str,
    run_id: str,
) -> dict[str, str]:
    values = {
        "pipeline": str(pipeline or "").strip().lower(),
        "mode": str(mode or "").strip().lower(),
        "ecosystem": str(ecosystem or "").strip().lower(),
        "backend": str(backend or "").strip().lower(),
        "phase_name": str(phase_name or "").strip().lower(),
        "run_id": str(run_id or "").strip(),
    }
    expected_phase = (
        "sc_verify_queue" if values["pipeline"] == "sc" else "verify_queue"
    )
    if (
        values["pipeline"] not in {"sc", "l1"}
        or values["phase_name"] != expected_phase
        or values["backend"] not in {"claude", "codex"}
        or not all(values.values())
    ):
        raise ValueError("prearm presence execution identity is invalid")
    return values


def presence_directory_roster(
    identities: Sequence[str],
) -> list[dict[str, Any]]:
    """Derive the exact directory denominator from canonical identities."""

    directory_members: dict[str, list[str]] = {}
    for identity in identities:
        text = str(identity or "").strip().replace("\\", "/")
        if not text.startswith("scratchpad:"):
            raise ValueError(
                "prearm presence directory member is not scratchpad-owned"
            )
        relative = _safe_relative(text[len("scratchpad:"):])
        canonical = canonical_artifact_identity("scratchpad", relative)
        if canonical != text:
            raise ValueError(
                "prearm presence directory member is noncanonical"
            )
        parent = PurePosixPath(relative).parent.as_posix()
        if parent == ".":
            parent = ""
        directory_members.setdefault(parent, []).append(canonical)
    return [
        {
            "root": "scratchpad",
            "directory": directory,
            "member_identities": sorted(members),
            "member_identity_digest": _stable_digest(sorted(members)),
        }
        for directory, members in sorted(directory_members.items())
    ]


def capture_prearm_presence_authority(
    *,
    scratchpad: Path,
    project_root: Path,
    pipeline: str,
    mode: str,
    ecosystem: str,
    backend: str,
    phase_name: str,
    run_id: str,
    roster: Sequence[str],
    authority_identity: str,
    required_roster: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Capture a caller-supplied exact roster without enumerating live state."""

    dimensions = _presence_dimensions(
        pipeline=pipeline,
        mode=mode,
        ecosystem=ecosystem,
        backend=backend,
        phase_name=phase_name,
        run_id=run_id,
    )
    if not isinstance(roster, Sequence) or isinstance(roster, (str, bytes)):
        raise ValueError("prearm presence roster must be an exact sequence")
    relative_roster = tuple(_safe_relative(value) for value in roster)
    if len(set(relative_roster)) != len(roster) or not relative_roster:
        raise ValueError(
            "prearm presence roster is empty, duplicated, or noncanonical"
        )
    authority_path = _authority_relative(authority_identity)
    if authority_path in relative_roster:
        raise ValueError("prearm presence authority cannot include itself")
    root = Path(scratchpad)
    project = Path(project_root)
    ledger = read_artifact_ledger(root)
    tri_state = required_roster is not None
    required = {
        _safe_relative(value) for value in (required_roster or ())
    }
    if not required <= set(relative_roster):
        raise ValueError(
            "prearm required roster escapes the exact presence roster"
        )
    entries: list[dict[str, Any]] = []
    for relative in relative_roster:
        identity = canonical_artifact_identity("scratchpad", relative)
        path = root.joinpath(*PurePosixPath(relative).parts)
        try:
            path.lstat()
        except FileNotFoundError:
            historical = ledger.get("artifact_bindings", {}).get(identity)
            if (
                isinstance(historical, Mapping)
                and historical.get("status") == "ACTIVE"
            ):
                raise ValueError(
                    f"{identity}: producer claims ACTIVE bytes that are absent"
                )
            entries.append({"identity": identity, "state": "ABSENT"})
            continue
        raw = read_bounded_regular_bytes(
            path, _MAX_PRESENCE_MEMBER_BYTES
        )
        producer_issues = semantic_input_prebind_producer_authority_issues(
            root,
            project,
            (identity,),
            run_id=dimensions["run_id"],
        )
        if producer_issues:
            if relative in required or not tri_state:
                raise ValueError("; ".join(producer_issues))
            entries.append({
                "identity": identity,
                "state": "PRESENT_UNAUTHORIZED_QUARANTINED",
                "issues": sorted({
                    str(issue)[:_MAX_DEBT_DETAIL]
                    for issue in producer_issues
                    if str(issue)
                })[:_MAX_DEBT_ISSUES],
            })
            continue
        binding = ledger.get("artifact_bindings", {}).get(identity)
        if not isinstance(binding, Mapping):
            if relative in required or not tri_state:
                raise ValueError(f"{identity}: producer binding is absent")
            entries.append({
                "identity": identity,
                "state": "PRESENT_UNAUTHORIZED_QUARANTINED",
                "issues": ["producer binding is absent"],
            })
            continue
        row = {
            "identity": identity,
            "state": (
                "PRESENT_AUTHORIZED" if tri_state else "PRESENT"
            ),
            "sha256": _sha(raw),
            "size": len(raw),
            "producer": {
                key: binding.get(key)
                for key in (
                    "owner_key",
                    "writer",
                    "run_id",
                    "contract_digest",
                    "launch_digest",
                )
            },
        }
        if tri_state:
            row["owner_key"] = str(binding.get("owner_key") or "")
        entries.append(row)
    roster_identities = sorted([
        canonical_artifact_identity("scratchpad", relative)
        for relative in relative_roster
    ])
    directory_roster = presence_directory_roster(roster_identities)
    unsigned: dict[str, Any] = {
        "schema_version": "plamen.prearm_presence_authority.v1",
        **dimensions,
        "authority_identity": "scratchpad:" + authority_path,
        "content_addressed": True,
        "caller_supplied_exact_roster": True,
        "live_glob_allowed": False,
        "live_directory_enumeration_allowed": False,
        "roster_count": len(roster_identities),
        "roster_identities": roster_identities,
        "roster_identity_digest": _stable_digest(roster_identities),
        "directory_roster": directory_roster,
        "directory_roster_digest": _stable_digest(directory_roster),
        "entries": entries,
    }
    return {**unsigned, "authority_digest": _stable_digest(unsigned)}


def validate_prearm_presence_authority(
    *,
    scratchpad: Path,
    project_root: Path,
    pipeline: str,
    mode: str,
    ecosystem: str,
    backend: str,
    phase_name: str,
    run_id: str,
    authority_identity: str,
    authority: Mapping[str, Any],
) -> list[str]:
    """Revalidate manifest ownership and every PRESENT/ABSENT roster row."""

    issues: list[str] = []
    try:
        dimensions = _presence_dimensions(
            pipeline=pipeline,
            mode=mode,
            ecosystem=ecosystem,
            backend=backend,
            phase_name=phase_name,
            run_id=run_id,
        )
        authority_path = _authority_relative(authority_identity)
        if not isinstance(authority, Mapping):
            raise ValueError("prearm presence authority is not an object")
        payload = dict(authority)
        expected_keys = {
            "schema_version",
            *dimensions,
            "authority_identity",
            "content_addressed",
            "caller_supplied_exact_roster",
            "live_glob_allowed",
            "live_directory_enumeration_allowed",
            "roster_count",
            "roster_identities",
            "roster_identity_digest",
            "directory_roster",
            "directory_roster_digest",
            "entries",
            "authority_digest",
        }
        if set(payload) != expected_keys:
            raise ValueError("prearm presence authority fields mismatch")
        unsigned = {
            key: item for key, item in payload.items()
            if key != "authority_digest"
        }
        if (
            payload.get("schema_version")
            != "plamen.prearm_presence_authority.v1"
            or any(payload.get(key) != value for key, value in dimensions.items())
            or payload.get("authority_identity")
            != "scratchpad:" + authority_path
            or payload.get("content_addressed") is not True
            or payload.get("caller_supplied_exact_roster") is not True
            or payload.get("live_glob_allowed") is not False
            or payload.get("live_directory_enumeration_allowed") is not False
            or payload.get("authority_digest") != _stable_digest(unsigned)
        ):
            raise ValueError(
                "prearm presence authority identity/digest/policy mismatch"
            )
        roster = payload.get("roster_identities")
        entries = payload.get("entries")
        directories = payload.get("directory_roster")
        if (
            not isinstance(roster, list)
            or roster != sorted(set(roster))
            or payload.get("roster_count") != len(roster)
            or payload.get("roster_identity_digest") != _stable_digest(roster)
            or not isinstance(entries, list)
            or len(entries) != len(roster)
            or not isinstance(directories, list)
            or directories != presence_directory_roster(roster)
            or payload.get("directory_roster_digest")
            != _stable_digest(directories)
        ):
            raise ValueError(
                "prearm presence roster/directory denominator mismatch"
            )
        rows: dict[str, Mapping[str, Any]] = {}
        for row in entries:
            if not isinstance(row, Mapping):
                raise ValueError("prearm presence entry is malformed")
            identity = str(row.get("identity") or "")
            if identity in rows:
                raise ValueError("prearm presence entry is duplicated")
            rows[identity] = row
        if set(rows) != set(roster):
            raise ValueError("prearm presence entry identity denominator drift")
        root = Path(scratchpad)
        project = Path(project_root)
        ledger = read_artifact_ledger(root)
        for identity in roster:
            if not str(identity).startswith("scratchpad:"):
                issues.append(f"{identity}: presence identity is not scratchpad")
                continue
            relative = _safe_relative(str(identity)[len("scratchpad:"):])
            path = root.joinpath(*PurePosixPath(relative).parts)
            row = rows[str(identity)]
            state = str(row.get("state") or "")
            if state == "ABSENT":
                if set(row) != {"identity", "state"}:
                    issues.append(f"{identity}: ABSENT row is malformed")
                    continue
                try:
                    path.lstat()
                except FileNotFoundError:
                    continue
                except OSError as exc:
                    issues.append(
                        f"{identity}: absence revalidation failed:{exc}"
                    )
                else:
                    issues.append(
                        f"{identity}: explicit ABSENT presence drift; file appeared"
                    )
                continue
            if state == "PRESENT_UNAUTHORIZED_QUARANTINED":
                if (
                    set(row) != {"identity", "state", "issues"}
                    or not isinstance(row.get("issues"), list)
                    or not row.get("issues")
                ):
                    issues.append(
                        f"{identity}: quarantined presence row is malformed"
                    )
                # Quarantined bytes are deliberately outside the semantic
                # denominator.  Their continued presence or mutation cannot
                # self-authorize them and must not halt a recall-safe queue.
                continue
            expected_present_fields = {
                "identity", "state", "sha256", "size", "producer"
            }
            if state == "PRESENT_AUTHORIZED":
                expected_present_fields.add("owner_key")
            if state not in {"PRESENT", "PRESENT_AUTHORIZED"} or set(row) != (
                expected_present_fields
            ):
                issues.append(f"{identity}: PRESENT row is malformed")
                continue
            try:
                raw = read_bounded_regular_bytes(
                    path, _MAX_PRESENCE_MEMBER_BYTES
                )
            except (OSError, ValueError) as exc:
                issues.append(
                    f"{identity}: present input missing/unsafe/drift:{exc}"
                )
                continue
            if row.get("sha256") != _sha(raw) or row.get("size") != len(raw):
                issues.append(f"{identity}: present hash/size drift")
            producer_issues = (
                semantic_input_prebind_producer_authority_issues(
                    root,
                    project,
                    (identity,),
                    run_id=dimensions["run_id"],
                )
            )
            issues.extend(producer_issues)
            binding = ledger.get("artifact_bindings", {}).get(identity)
            producer = row.get("producer")
            if not isinstance(binding, Mapping) or not isinstance(
                producer, Mapping
            ):
                issues.append(f"{identity}: producer authority is absent")
            elif dict(producer) != {
                key: binding.get(key)
                for key in (
                    "owner_key",
                    "writer",
                    "run_id",
                    "contract_digest",
                    "launch_digest",
                )
            }:
                issues.append(f"{identity}: producer authority drift")
            elif (
                state == "PRESENT_AUTHORIZED"
                and row.get("owner_key") != binding.get("owner_key")
            ):
                issues.append(f"{identity}: authorized owner key drift")
        raw_authority = read_bounded_regular_bytes(
            Path(scratchpad) / authority_path,
            _MAX_PRESENCE_MEMBER_BYTES,
        )
        if raw_authority != _canonical_bytes(payload):
            issues.append("prearm presence authority bytes differ from payload")
        authority_producer_issues = (
            semantic_input_prebind_producer_authority_issues(
                Path(scratchpad),
                Path(project_root),
                ("scratchpad:" + authority_path,),
                run_id=dimensions["run_id"],
            )
        )
        issues.extend(
            "prearm presence authority producer/run invalid: " + issue
            for issue in authority_producer_issues
        )
    except (
        ArtifactLedgerError,
        OSError,
        TypeError,
        UnicodeError,
        ValueError,
    ) as exc:
        issues.append(
            f"prearm presence authority invalid:{type(exc).__name__}:{exc}"
        )
    return list(dict.fromkeys(str(issue) for issue in issues if str(issue)))


def prearm_effective_input_paths(
    authority: Mapping[str, Any],
) -> tuple[str, ...]:
    """Return exact present paths plus the committed authority manifest."""

    if not isinstance(authority, Mapping):
        raise ValueError("prearm presence authority is not an object")
    authority_path = _authority_relative(authority.get("authority_identity"))
    entries = authority.get("entries")
    if not isinstance(entries, list):
        raise ValueError("prearm presence entries are malformed")
    present: list[str] = []
    for row in entries:
        if not isinstance(row, Mapping):
            raise ValueError("prearm presence entry is malformed")
        if row.get("state") in {"PRESENT", "PRESENT_AUTHORIZED"}:
            identity = str(row.get("identity") or "")
            if not identity.startswith("scratchpad:"):
                raise ValueError("prearm PRESENT identity is malformed")
            present.append(_safe_relative(identity[len("scratchpad:"):]))
        elif row.get("state") not in {
            "ABSENT",
            "PRESENT_UNAUTHORIZED_QUARANTINED",
        }:
            raise ValueError("prearm presence state is unsupported")
    return tuple([*dict.fromkeys(present), authority_path])


def _bounded_json(path: Path, *, label: str) -> tuple[bytes, Mapping[str, Any]]:
    raw = read_bounded_regular_bytes(path, _p0af.MAX_AUTHORITY_BYTES)
    try:
        payload = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not strict UTF-8 JSON") from exc
    if not isinstance(payload, Mapping):
        raise ValueError(f"{label} is not a JSON object")
    return raw, payload


def _bounded_issues(values: Sequence[Any]) -> list[str]:
    normalized = sorted({
        str(value).strip()[:_MAX_DEBT_DETAIL]
        for value in values
        if str(value).strip()
    })
    return normalized[:_MAX_DEBT_ISSUES]


def _manifest(
    *,
    run_id: str,
    candidate_raw: bytes,
    identity_raw: bytes,
    sources: Mapping[str, bytes],
) -> dict[str, Any]:
    identities = ["scratchpad:" + path for path in sorted(sources)]
    entries = [
        {
            "identity": "scratchpad:" + path,
            "sha256": _sha(sources[path]),
            "size": len(sources[path]),
        }
        for path in sorted(sources)
    ]
    unsigned: dict[str, Any] = {
        "schema_version": _MANIFEST_SCHEMA,
        "pipeline": "sc",
        "run_id": run_id,
        "manifest_identity": "scratchpad:" + MANIFEST_FILE,
        "selection_authority": {
            "identity": "scratchpad:" + _p0af.CANDIDATE_FILE,
            "sha256": _sha(candidate_raw),
            "size": len(candidate_raw),
        },
        "identity_denominator": {
            "identity": "scratchpad:" + _p0af.IDENTITY_DENOMINATOR_FILE,
            "sha256": _sha(identity_raw),
            "size": len(identity_raw),
        },
        "referenced_source_identities": identities,
        "referenced_source_identity_digest": _stable_digest(identities),
        "entries": entries,
        "entry_count": len(entries),
        "entry_identity_digest": _stable_digest(
            [row["identity"] for row in entries]
        ),
        "content_addressed": True,
        "live_glob_allowed": False,
        "live_read_after_arm_allowed": False,
    }
    return {**unsigned, "manifest_digest": _stable_digest(unsigned)}


def _receipt(
    *,
    run_id: str,
    state: str,
    selected: str,
    dynamic_sources: Sequence[str],
    issues: Sequence[str],
    manifest_digest: str = "",
) -> dict[str, Any]:
    unsigned: dict[str, Any] = {
        "schema_version": _RECEIPT_SCHEMA,
        "pipeline": "sc",
        "run_id": run_id,
        "state": state,
        "selected_conditional": selected,
        "dynamic_source_paths": sorted(set(map(str, dynamic_sources))),
        "issue_count": len(issues),
        "issue_digest": _stable_digest(list(issues)),
        "manifest_digest": manifest_digest,
        "proof_authority": "NONE",
    }
    return {**unsigned, "payload_digest": _payload_digest(unsigned)}


def _debt(*, run_id: str, issues: Sequence[str]) -> dict[str, Any]:
    bounded = _bounded_issues(issues) or ["PREARM_DYNAMIC_INPUT_UNRESOLVED"]
    unsigned: dict[str, Any] = {
        "schema_version": _DEBT_SCHEMA,
        "pipeline": "sc",
        "run_id": run_id,
        "state": "COMPLETED_WITH_DEBT",
        "issue_count": len(bounded),
        "issues": bounded,
        "proof_authority": "NONE",
    }
    result = {**unsigned, "payload_digest": _payload_digest(unsigned)}
    if len(_canonical_bytes(result)) > _MAX_DEBT_BYTES:
        raise LiveVerifyQueuePrearmInputError(
            "bounded prearm debt unexpectedly exceeds its byte limit"
        )
    return result


def _contract_and_launch(
    *,
    config: Mapping[str, Any],
    immutable_inputs: Sequence[str],
) -> tuple[PhaseIOContract, LaunchSpec]:
    pipeline = str(config.get("pipeline") or "").strip().lower()
    mode = str(config.get("mode") or "").strip().lower()
    ecosystem = str(config.get("ecosystem") or "").strip().lower()
    backend = str(config.get("backend") or "").strip().lower()
    phase = str(config.get("phase_name") or "").strip().lower()
    if (
        pipeline != "sc"
        or not mode
        or not ecosystem
        or backend not in {"claude", "codex"}
        or phase != "sc_verify_queue"
    ):
        raise LiveVerifyQueuePrearmInputError(
            "SC prearm execution identity is invalid"
        )
    owner = canonical_work_unit_key(
        pipeline, mode, ecosystem, backend, phase, WORK_UNIT_ID
    )
    outputs = (
        ArtifactSpec(
            root="scratchpad",
            path=MANIFEST_FILE,
            owner_key=owner,
            artifact_class="CONDITIONAL",
            writer="DRIVER",
            write_mode="CREATE",
            schema_version=_MANIFEST_SCHEMA,
            minimum_gate="STRUCTURAL",
            consumers=("sc_verify_queue/t0.live_upstream_authority",),
            condition_id="manifest_resolved",
        ),
        ArtifactSpec(
            root="scratchpad",
            path=DEBT_FILE,
            owner_key=owner,
            artifact_class="CONDITIONAL",
            writer="DRIVER",
            write_mode="CREATE",
            schema_version=_DEBT_SCHEMA,
            minimum_gate="STRUCTURAL",
            consumers=("sc_verify_queue/t0.live_upstream_authority",),
            condition_id="debt_selected",
        ),
        ArtifactSpec(
            root="scratchpad",
            path=RECEIPT_FILE,
            owner_key=owner,
            artifact_class="DRIVER_GENERATED",
            writer="DRIVER",
            write_mode="CREATE",
            schema_version=_RECEIPT_SCHEMA,
            minimum_gate="STRUCTURAL",
            consumers=("sc_verify_queue/t0.live_upstream_authority",),
        ),
    )
    contract = PhaseIOContract(
        pipeline=pipeline,
        mode=mode,
        ecosystem=ecosystem,
        backend=backend,
        phase=phase,
        work_unit_id=WORK_UNIT_ID,
        outputs=outputs,
        immutable_inputs=tuple(sorted({
            canonical_artifact_identity("scratchpad", path)
            for path in immutable_inputs
        })),
        bounded_lookup_inputs=(),
        model_invoked=False,
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=pipeline,
        mode=mode,
        ecosystem=ecosystem,
        backend=backend,
        model="driver",
        timeout_s=300,
        exec_mode="python",
        tool_policy=("filesystem",),
    )
    return contract, launch


def _presence_contract_and_launch(
    *,
    config: Mapping[str, Any],
    authority: Mapping[str, Any],
) -> tuple[PhaseIOContract, LaunchSpec]:
    pipeline = str(config.get("pipeline") or "").strip().lower()
    mode = str(config.get("mode") or "").strip().lower()
    ecosystem = str(config.get("ecosystem") or "").strip().lower()
    backend = str(config.get("backend") or "").strip().lower()
    phase = str(config.get("phase_name") or "").strip().lower()
    expected_phase = "sc_verify_queue" if pipeline == "sc" else "verify_queue"
    if (
        pipeline not in {"sc", "l1"}
        or phase != expected_phase
        or backend not in {"claude", "codex"}
        or not mode
        or not ecosystem
    ):
        raise LiveVerifyQueuePrearmInputError(
            "prearm presence execution identity is invalid"
        )
    owner = canonical_work_unit_key(
        pipeline,
        mode,
        ecosystem,
        backend,
        phase,
        PRESENCE_WORK_UNIT_ID,
    )
    entries = authority.get("entries")
    if not isinstance(entries, list):
        raise LiveVerifyQueuePrearmInputError(
            "prearm presence authority entries are malformed"
        )
    present = tuple(
        str(row.get("identity") or "")
        for row in entries
        if isinstance(row, Mapping)
        and row.get("state") in {"PRESENT", "PRESENT_AUTHORIZED"}
    )
    contract = PhaseIOContract(
        pipeline=pipeline,
        mode=mode,
        ecosystem=ecosystem,
        backend=backend,
        phase=phase,
        work_unit_id=PRESENCE_WORK_UNIT_ID,
        outputs=(ArtifactSpec(
            root="scratchpad",
            path=PRESENCE_AUTHORITY_FILE,
            owner_key=owner,
            artifact_class="DRIVER_GENERATED",
            writer="DRIVER",
            write_mode="CREATE",
            schema_version="plamen.prearm_presence_authority.v1",
            minimum_gate="EXACT_ROSTER_PRESENCE_AND_PRODUCER_AUTHORITY",
            consumers=(f"{phase}/t0.live_upstream_authority",),
        ),),
        immutable_inputs=present,
        bounded_lookup_inputs=(),
        model_invoked=False,
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=pipeline,
        mode=mode,
        ecosystem=ecosystem,
        backend=backend,
        model="driver",
        timeout_s=300,
        exec_mode="python",
        tool_policy=("filesystem",),
    )
    return contract, launch


def prepare_prearm_presence_authority(
    *,
    scratchpad: Path,
    project_root: Path,
    config: Mapping[str, Any],
    run_id: str,
    roster: Sequence[str],
    required_roster: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Capture and PhaseIO-commit the complete pre-T0 presence roster."""

    dimensions = _presence_dimensions(
        pipeline=str(config.get("pipeline") or ""),
        mode=str(config.get("mode") or ""),
        ecosystem=str(config.get("ecosystem") or ""),
        backend=str(config.get("backend") or ""),
        phase_name=str(config.get("phase_name") or ""),
        run_id=run_id,
    )
    root = Path(scratchpad)
    project = Path(project_root)
    root.mkdir(parents=True, exist_ok=True)
    authority = capture_prearm_presence_authority(
        scratchpad=root,
        project_root=project,
        **dimensions,
        roster=roster,
        authority_identity="scratchpad:" + PRESENCE_AUTHORITY_FILE,
        required_roster=required_roster,
    )
    contract, launch = _presence_contract_and_launch(
        config=config,
        authority=authority,
    )
    try:
        prior = record_work_unit_inputs(
            root,
            project,
            contract,
            launch,
            run_id=dimensions["run_id"],
        )
    except (ArtifactLedgerError, OSError, TypeError, ValueError) as exc:
        raise LiveVerifyQueuePrearmInputError(
            f"prearm presence PhaseIO arm failed:{type(exc).__name__}:{exc}"
        ) from exc
    expected = _canonical_bytes(authority)
    if (
        isinstance(prior, Mapping)
        and prior.get("semantic_status") == "ACTIVE"
        and prior.get("execution_state") == "OUTPUT_COMMITTED"
    ):
        validation = validate_work_unit_artifacts(
            root,
            project,
            contract,
            launch,
            run_id=dimensions["run_id"],
            actor="DRIVER",
        )
        if validation:
            raise LiveVerifyQueuePrearmInputError(
                "prearm presence resume authority invalid: "
                + "; ".join(validation)
            )
        path = root / PRESENCE_AUTHORITY_FILE
        if not path.is_file() or path.read_bytes() != expected:
            raise LiveVerifyQueuePrearmInputError(
                "prearm presence resume postimage drifted"
            )
    else:
        _cas_exact(root / PRESENCE_AUTHORITY_FILE, expected)
        try:
            record_work_unit_artifacts(
                root,
                project,
                contract,
                launch,
                run_id=dimensions["run_id"],
                actor="DRIVER",
            )
        except (ArtifactLedgerError, OSError, TypeError, ValueError) as exc:
            raise LiveVerifyQueuePrearmInputError(
                f"prearm presence PhaseIO commit failed:"
                f"{type(exc).__name__}:{exc}"
            ) from exc
    issues = validate_prearm_presence_authority(
        scratchpad=root,
        project_root=project,
        **dimensions,
        authority_identity="scratchpad:" + PRESENCE_AUTHORITY_FILE,
        authority=authority,
    )
    if issues:
        raise LiveVerifyQueuePrearmInputError(
            "prearm presence validation failed: " + "; ".join(issues)
        )
    return {
        "schema_version": "plamen.prearm_presence_preparation.v1",
        "authority_path": PRESENCE_AUTHORITY_FILE,
        "authority": authority,
        "effective_input_paths": list(
            prearm_effective_input_paths(authority)
        ),
        "phase_io_owner_key": contract.key,
        "status_json_is_authority": False,
    }


def _cas_exact(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0),
            0o600,
        )
    except FileExistsError:
        if path.read_bytes() != raw:
            raise LiveVerifyQueuePrearmInputError(
                f"prearm output contains foreign bytes: {path.name}"
            )
        return
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _conditional_receipts(
    contract: PhaseIOContract,
    *,
    selected: str,
) -> dict[str, ConditionalOutputReceipt]:
    states = {
        MANIFEST_FILE: (
            "PRODUCED" if selected == MANIFEST_FILE else "NOT_TRIGGERED"
        ),
        DEBT_FILE: "PRODUCED" if selected == DEBT_FILE else "NOT_TRIGGERED",
    }
    result: dict[str, ConditionalOutputReceipt] = {}
    for spec in contract.outputs:
        if spec.artifact_class != "CONDITIONAL":
            continue
        state = states[spec.path]
        result[spec.identity] = ConditionalOutputReceipt(
            work_unit_key=contract.key,
            contract_digest=contract.digest,
            artifact_identity=spec.identity,
            condition_id=spec.condition_id,
            state=state,
            expected_denominator=1 if state == "PRODUCED" else 0,
            produced_identities=(spec.identity,) if state == "PRODUCED" else (),
        )
    return result


def _outcome(
    *,
    state: str,
    dynamic_sources: Sequence[str],
    manifest: Mapping[str, Any] | None,
) -> dict[str, Any]:
    selected = (
        MANIFEST_FILE
        if state == "RESOLVED"
        else DEBT_FILE
        if state == "COMPLETED_WITH_DEBT"
        else "NONE"
    )
    additional = [RECEIPT_FILE]
    if selected != "NONE":
        additional.append(selected)
    if state == "RESOLVED":
        # The canonical identity denominator is dynamic control authority, not
        # a static queue input.  It enters T0 only through the manifest branch
        # that cryptographically binds its bytes.
        additional.append(_p0af.IDENTITY_DENOMINATOR_FILE)
        additional.extend(sorted(set(map(str, dynamic_sources))))
    result: dict[str, Any] = {
        "schema_version": _RECEIPT_SCHEMA,
        "state": state,
        "receipt_path": RECEIPT_FILE,
        "active_conditional_path": selected,
        "t0_additional_inputs": sorted(set(additional)),
        "dynamic_source_paths": sorted(set(map(str, dynamic_sources))),
        "manifest": dict(manifest) if manifest is not None else None,
        "phase_io_owner_key": "",
        "status_json_is_authority": False,
        "live_glob_allowed": False,
        "live_read_after_arm_allowed": False,
    }
    return result


def prepare_sc_prearm_dynamic_inputs(
    *,
    scratchpad: Path,
    project_root: Path,
    config: Mapping[str, Any],
    run_id: str,
) -> dict[str, Any]:
    """Resolve and commit the SC dynamic input manifest or bounded debt."""

    pipeline = str(config.get("pipeline") or "").strip().lower()
    if pipeline == "l1":
        return {
            "schema_version": _RECEIPT_SCHEMA,
            "state": "NOT_APPLICABLE",
            "receipt_path": "",
            "active_conditional_path": "NONE",
            "t0_additional_inputs": [],
            "dynamic_source_paths": [],
            "manifest": None,
            "phase_io_owner_key": "",
            "status_json_is_authority": False,
            "live_glob_allowed": False,
            "live_read_after_arm_allowed": False,
        }
    if pipeline != "sc":
        raise LiveVerifyQueuePrearmInputError(
            "prearm dynamic inputs require pipeline sc or l1"
        )
    run = str(run_id or "").strip()
    if not run:
        raise LiveVerifyQueuePrearmInputError("prearm run_id is absent")
    root = Path(scratchpad)
    project = Path(project_root)
    root.mkdir(parents=True, exist_ok=True)

    state = "NOT_TRIGGERED"
    selected = "NONE"
    issues: list[str] = []
    manifest: dict[str, Any] | None = None
    dynamic_sources: tuple[str, ...] = ()
    trusted_inputs: list[str] = []
    candidate_path = root / _p0af.CANDIDATE_FILE
    try:
        candidate_path.lstat()
        candidate_present = True
    except FileNotFoundError:
        candidate_present = False
    except OSError as exc:
        candidate_present = True
        issues.append(
            f"candidate presence check failed:{type(exc).__name__}:{exc}"
        )

    candidate_raw = b""
    identity_raw = b""
    source_bytes: dict[str, bytes] = {}
    if candidate_present and not issues:
        try:
            candidate_raw, candidate_payload = _bounded_json(
                candidate_path, label="P0-AF candidate authority"
            )
            identity_raw, identity_payload = _bounded_json(
                root / _p0af.IDENTITY_DENOMINATOR_FILE,
                label="canonical finding identity denominator",
            )
            if (
                candidate_payload.get("identity_denominator_digest")
                != _sha(identity_raw)
                or identity_payload.get("schema_version")
                != "plamen.canonical_finding_ids.v1"
            ):
                raise ValueError(
                    "candidate/canonical identity denominator binding drift"
                )
            dynamic_sources = tuple(
                _safe_relative(path)
                for path in _p0af.enumerate_p0af_v2_dynamic_source_artifacts(
                    candidate_payload
                )
            )
            if len(set(dynamic_sources)) != len(dynamic_sources):
                raise ValueError("dynamic source denominator contains duplicates")
            for relative in dynamic_sources:
                raw, payload = _bounded_json(
                    root / relative,
                    label=f"P0-AF fact authority {relative}",
                )
                authority_digest = str(payload.get("authority_digest") or "")
                semantic = {
                    key: item for key, item in payload.items()
                    if key != "authority_digest"
                }
                if (
                    not _HEX64.fullmatch(authority_digest)
                    or authority_digest
                    != hashlib.sha256(
                        json.dumps(
                            semantic,
                            ensure_ascii=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        ).encode("utf-8")
                    ).hexdigest()
                ):
                    raise ValueError(
                        f"P0-AF fact authority digest is invalid: {relative}"
                    )
                source_bytes[relative] = raw
        except (
            ArtifactLedgerError,
            OSError,
            TypeError,
            UnicodeError,
            ValueError,
            _p0af.P0AFV2AdapterError,
        ) as exc:
            issues.append(
                f"PREARM_DYNAMIC_INPUT_INVALID:{type(exc).__name__}:"
                f"{str(exc)[:_MAX_DEBT_DETAIL]}"
            )

    if candidate_present:
        ancestry_candidates = [
            _p0af.CANDIDATE_FILE,
            _p0af.IDENTITY_DENOMINATOR_FILE,
            *dynamic_sources,
        ]
        for relative in ancestry_candidates:
            identity = canonical_artifact_identity("scratchpad", relative)
            authority_issues = (
                semantic_input_prebind_producer_authority_issues(
                    root,
                    project,
                    (identity,),
                    run_id=run,
                )
            )
            if authority_issues:
                issues.extend(authority_issues)
            else:
                trusted_inputs.append(relative)

    if candidate_present and not issues:
        manifest = _manifest(
            run_id=run,
            candidate_raw=candidate_raw,
            identity_raw=identity_raw,
            sources=source_bytes,
        )
        state = "RESOLVED"
        selected = MANIFEST_FILE
    elif candidate_present:
        state = "COMPLETED_WITH_DEBT"
        selected = DEBT_FILE

    bounded = _bounded_issues(issues)
    receipt = _receipt(
        run_id=run,
        state=state,
        selected=selected,
        dynamic_sources=dynamic_sources if state == "RESOLVED" else (),
        issues=bounded,
        manifest_digest=(
            str(manifest.get("manifest_digest") or "") if manifest else ""
        ),
    )
    debt = _debt(run_id=run, issues=bounded) if selected == DEBT_FILE else None
    contract, launch = _contract_and_launch(
        config=config,
        immutable_inputs=trusted_inputs,
    )

    try:
        prior = record_work_unit_inputs(
            root, project, contract, launch, run_id=run
        )
    except (ArtifactLedgerError, OSError, TypeError, ValueError) as exc:
        raise LiveVerifyQueuePrearmInputError(
            f"prearm PhaseIO arm failed:{type(exc).__name__}:{exc}"
        ) from exc

    expected_bytes = {RECEIPT_FILE: _canonical_bytes(receipt)}
    if manifest is not None:
        expected_bytes[MANIFEST_FILE] = _canonical_bytes(manifest)
    if debt is not None:
        expected_bytes[DEBT_FILE] = _canonical_bytes(debt)
    if (
        isinstance(prior, Mapping)
        and prior.get("semantic_status") == "ACTIVE"
        and prior.get("execution_state") == "OUTPUT_COMMITTED"
    ):
        validation = validate_work_unit_artifacts(
            root,
            project,
            contract,
            launch,
            run_id=run,
            actor="DRIVER",
        )
        if validation:
            raise LiveVerifyQueuePrearmInputError(
                "prearm resume authority is invalid: " + "; ".join(validation)
            )
        for relative, raw in expected_bytes.items():
            path = root / relative
            if not path.is_file() or path.read_bytes() != raw:
                raise LiveVerifyQueuePrearmInputError(
                    f"prearm resume postimage drifted: {relative}"
                )
    else:
        for relative, raw in expected_bytes.items():
            _cas_exact(root / relative, raw)
        receipts = _conditional_receipts(contract, selected=selected)
        try:
            record_work_unit_artifacts(
                root,
                project,
                contract,
                launch,
                run_id=run,
                actor="DRIVER",
                conditional_receipts=receipts,
            )
        except (ArtifactLedgerError, OSError, TypeError, ValueError) as exc:
            raise LiveVerifyQueuePrearmInputError(
                f"prearm PhaseIO commit failed:{type(exc).__name__}:{exc}"
            ) from exc
        validation = validate_work_unit_artifacts(
            root,
            project,
            contract,
            launch,
            run_id=run,
            actor="DRIVER",
        )
        if validation:
            raise LiveVerifyQueuePrearmInputError(
                "prearm output authority is invalid: " + "; ".join(validation)
            )

    outcome = _outcome(
        state=state,
        dynamic_sources=dynamic_sources if state == "RESOLVED" else (),
        manifest=manifest,
    )
    outcome["phase_io_owner_key"] = contract.key
    return outcome


__all__ = [
    "DEBT_FILE",
    "LiveVerifyQueuePrearmInputError",
    "MANIFEST_FILE",
    "PRESENCE_AUTHORITY_FILE",
    "PRESENCE_WORK_UNIT_ID",
    "RECEIPT_FILE",
    "WORK_UNIT_ID",
    "capture_prearm_presence_authority",
    "prepare_sc_prearm_dynamic_inputs",
    "prepare_prearm_presence_authority",
    "prearm_effective_input_paths",
    "validate_prearm_presence_authority",
]
