"""Exact final-inventory and registered-delivery successor receipts.

The discovery producers remain immutable.  Additive pre-verification repair
steps may advance ``findings_inventory.md`` several times, so no producer-local
receipt is allowed to become queue authority.  This provider is deliberately
pure: it builds and validates the two receipts from the final bytes, while the
driver owns PhaseIO prebinding, materialization, and commit.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any, Mapping, Sequence


FINAL_SCHEMA = "plamen.preverify_inventory_successor.v1"
DELIVERY_SCHEMA = "plamen.finding_delivery_successor.v1"
GENERATION_SCHEMA = "plamen.preverify_successor_generation.v2"
CAPTURE_PLAN_SCHEMA = "plamen.preverify_capture_plan.v1"
FINAL_RECEIPT_NAME = "preverify_inventory_successor.json"
DELIVERY_RECEIPT_NAME = "finding_delivery_successor.json"
GENERATION_DIRECTORY = "_preverify_successors"
_DELIVERY_PAYLOAD_SCHEMA = "plamen.finding_delivery.v2"
_SHA_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)


class PreverifyInventorySuccessorError(ValueError):
    """The final inventory/delivery successor chain is not exact."""


@dataclass(frozen=True)
class PreverifyCapturePlan:
    """Exact preimage and absence denominator for one capture generation.

    ``exact_inputs`` is the PhaseIO file denominator.  The presence rows bind
    the fixed candidate roster as well, so a file appearing between preflight
    and commit changes the plan even though absent files cannot themselves be
    ordinary PhaseIO inputs.  The caller must also re-enumerate registered
    producers before commit; a new registry match then changes
    ``producer_artifacts`` and therefore the plan digest.
    """

    payload: Mapping[str, Any]

    @property
    def digest(self) -> str:
        return str(self.payload.get("plan_digest") or "")

    @property
    def exact_inputs(self) -> tuple[str, ...]:
        values = self.payload.get("exact_inputs")
        if not isinstance(values, list):
            return ()
        return tuple(str(value) for value in values)


def _canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise PreverifyInventorySuccessorError(
            f"value is not canonical JSON: {exc}"
        ) from exc


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _digest_without(payload: Mapping[str, Any], field: str) -> str:
    unsigned = dict(payload)
    unsigned.pop(field, None)
    return _sha(_canonical_json_bytes(unsigned))


def _safe_relative_name(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise PreverifyInventorySuccessorError(
            f"{label} must be a canonical relative POSIX path"
        )
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or value != path.as_posix()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise PreverifyInventorySuccessorError(
            f"{label} must be a canonical relative POSIX path"
        )
    return value


def _artifact_binding(root: Path, name: str) -> dict[str, Any]:
    relative = _safe_relative_name(name, label="producer artifact")
    path = Path(root) / Path(*PurePosixPath(relative).parts)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise PreverifyInventorySuccessorError(
            f"producer artifact is unavailable: {relative}"
        ) from exc
    return {
        "artifact": relative,
        "size_bytes": len(raw),
        "sha256": _sha(raw),
    }


def _presence_binding(
    base: Path,
    name: str,
    *,
    label: str,
) -> dict[str, Any]:
    relative = _safe_relative_name(name, label=label)
    path = Path(base) / Path(*PurePosixPath(relative).parts)
    if not path.is_file():
        return {
            "artifact": relative,
            "status": "ABSENT",
            "size_bytes": 0,
            "sha256": "",
        }
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise PreverifyInventorySuccessorError(
            f"{label} is unreadable: {relative}"
        ) from exc
    return {
        "artifact": relative,
        "status": "PRESENT",
        "size_bytes": len(raw),
        "sha256": _sha(raw),
    }


def _normalize_names(
    names: Sequence[str],
    *,
    label: str,
) -> tuple[str, ...]:
    normalized = tuple(
        sorted(_safe_relative_name(str(value), label=label) for value in names)
    )
    if len(normalized) != len(set(normalized)):
        raise PreverifyInventorySuccessorError(
            f"{label} denominator contains duplicate artifacts"
        )
    return normalized


def build_preverify_capture_plan(
    scratchpad: Path,
    *,
    run_id: str,
    producer_artifacts: Sequence[str],
    mutation_authority_candidates: Sequence[str],
    control_artifact_candidates: Sequence[str],
    registry_digest: str,
    trusted_code_digest: str,
    project_input_candidates: Sequence[str] = (),
    inventory_source_artifact: str = "findings_inventory.md",
    records_source_artifact: str = "finding_records.json",
    evidence_source_artifact: str = "",
) -> PreverifyCapturePlan:
    """Build the pre-arm/pre-commit denominator without writing anything."""

    root = Path(scratchpad)
    run = str(run_id or "").strip()
    if not run:
        raise PreverifyInventorySuccessorError("run_id must be non-empty")
    registry = str(registry_digest or "").removeprefix("sha256:")
    code = str(trusted_code_digest or "").removeprefix("sha256:")
    if not _SHA_RE.fullmatch(registry):
        raise PreverifyInventorySuccessorError(
            "capture plan registry digest is invalid"
        )
    if not _SHA_RE.fullmatch(code):
        raise PreverifyInventorySuccessorError(
            "capture plan trusted-code digest is invalid"
        )

    producers = _normalize_names(
        producer_artifacts, label="producer artifact"
    )
    mutation_candidates = _normalize_names(
        mutation_authority_candidates,
        label="mutation authority candidate",
    )
    control_candidates = _normalize_names(
        control_artifact_candidates,
        label="control artifact candidate",
    )
    project_candidates = _normalize_names(
        project_input_candidates,
        label="project input candidate",
    )
    inventory_source = _safe_relative_name(
        inventory_source_artifact,
        label="inventory source artifact",
    )
    records_source = _safe_relative_name(
        records_source_artifact,
        label="finding-record source artifact",
    )
    evidence_source = (
        _safe_relative_name(
            evidence_source_artifact,
            label="evidence source artifact",
        )
        if evidence_source_artifact
        else ""
    )
    scratch_candidates = tuple(sorted({
        inventory_source,
        records_source,
        *({evidence_source} if evidence_source else set()),
        *producers,
        *mutation_candidates,
        *control_candidates,
    }))
    scratch_presence = [
        _presence_binding(
            root, name, label="scratchpad capture candidate"
        )
        for name in scratch_candidates
    ]
    project_presence = [
        _presence_binding(
            root.parent, name, label="project capture candidate"
        )
        for name in project_candidates
    ]
    missing_producers = [
        row["artifact"]
        for row in scratch_presence
        if row["artifact"] in producers and row["status"] != "PRESENT"
    ]
    if missing_producers:
        raise PreverifyInventorySuccessorError(
            "capture plan producer artifact is unavailable: "
            + ", ".join(missing_producers)
        )
    inventory = next(
        row
        for row in scratch_presence
        if row["artifact"] == inventory_source
    )
    if inventory["status"] != "PRESENT":
        raise PreverifyInventorySuccessorError(
            "capture plan final inventory is unavailable"
        )
    records = next(
        row
        for row in scratch_presence
        if row["artifact"] == records_source
    )
    if records["status"] != "PRESENT":
        raise PreverifyInventorySuccessorError(
            "capture plan paired finding-record projection is unavailable"
        )
    try:
        records_payload = json.loads(
            root.joinpath(
                *PurePosixPath(records_source).parts
            ).read_text(
                encoding="utf-8", errors="strict"
            )
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PreverifyInventorySuccessorError(
            "capture plan paired finding-record projection is malformed"
        ) from exc
    if not (
        isinstance(records_payload, Mapping)
        and records_payload.get("schema_version")
        == "plamen.finding_records.v2"
        and records_payload.get("source") == "findings_inventory.md"
        and records_payload.get("source_sha256") == inventory["sha256"]
        and isinstance(records_payload.get("records"), list)
    ):
        raise PreverifyInventorySuccessorError(
            "capture plan paired finding-record projection is stale or invalid"
        )
    if evidence_source:
        evidence = next(
            row
            for row in scratch_presence
            if row["artifact"] == evidence_source
        )
        if evidence["status"] != "PRESENT":
            raise PreverifyInventorySuccessorError(
                "capture plan evidence projection is unavailable"
            )

    exact_inputs = sorted(
        [
            str(row["artifact"])
            for row in scratch_presence
            if row["status"] == "PRESENT"
        ]
        + [
            "project::" + str(row["artifact"])
            for row in project_presence
            if row["status"] == "PRESENT"
        ]
    )
    unsigned: dict[str, Any] = {
        "schema_version": CAPTURE_PLAN_SCHEMA,
        "run_id": run,
        "registry_digest": registry,
        "trusted_code_digest": code,
        "producer_artifacts": list(producers),
        "mutation_authority_candidates": list(mutation_candidates),
        "control_artifact_candidates": list(control_candidates),
        "project_input_candidates": list(project_candidates),
        "scratchpad_presence": scratch_presence,
        "project_presence": project_presence,
        "exact_inputs": exact_inputs,
    }
    if (
        inventory_source != "findings_inventory.md"
        or records_source != "finding_records.json"
        or evidence_source
    ):
        unsigned["source_projection"] = {
            "inventory": inventory_source,
            "records": records_source,
            "evidence": evidence_source,
        }
    payload = {
        **unsigned,
        "plan_digest": _sha(_canonical_json_bytes(unsigned)),
    }
    return PreverifyCapturePlan(payload=payload)


def validate_preverify_capture_plan(
    scratchpad: Path,
    plan: Mapping[str, Any] | PreverifyCapturePlan,
    *,
    expected_plan: Mapping[str, Any] | PreverifyCapturePlan | None = None,
) -> PreverifyCapturePlan:
    """Recompute a capture plan and reject stale, partial, or changed rosters."""

    payload = plan.payload if isinstance(plan, PreverifyCapturePlan) else plan
    required = {
        "schema_version",
        "run_id",
        "registry_digest",
        "trusted_code_digest",
        "producer_artifacts",
        "mutation_authority_candidates",
        "control_artifact_candidates",
        "project_input_candidates",
        "scratchpad_presence",
        "project_presence",
        "exact_inputs",
        "plan_digest",
    }
    allowed = required | {"source_projection"}
    if (
        not isinstance(payload, Mapping)
        or frozenset(payload) not in {
            frozenset(required),
            frozenset(allowed),
        }
        or payload.get("schema_version") != CAPTURE_PLAN_SCHEMA
        or payload.get("plan_digest")
        != _digest_without(payload, "plan_digest")
    ):
        raise PreverifyInventorySuccessorError(
            "preverify capture plan schema or digest is invalid"
        )
    sequence_fields = (
        "producer_artifacts",
        "mutation_authority_candidates",
        "control_artifact_candidates",
        "project_input_candidates",
    )
    if any(not isinstance(payload.get(field), list) for field in sequence_fields):
        raise PreverifyInventorySuccessorError(
            "preverify capture plan denominator is malformed"
        )
    source_projection = payload.get("source_projection")
    if source_projection is None:
        inventory_source = "findings_inventory.md"
        records_source = "finding_records.json"
        evidence_source = ""
    elif (
        not isinstance(source_projection, Mapping)
        or set(source_projection) != {"inventory", "records", "evidence"}
    ):
        raise PreverifyInventorySuccessorError(
            "preverify capture plan source projection is malformed"
        )
    else:
        inventory_source = str(source_projection.get("inventory") or "")
        records_source = str(source_projection.get("records") or "")
        evidence_source = str(source_projection.get("evidence") or "")
    rebuilt = build_preverify_capture_plan(
        Path(scratchpad),
        run_id=str(payload.get("run_id") or ""),
        producer_artifacts=payload["producer_artifacts"],
        mutation_authority_candidates=payload[
            "mutation_authority_candidates"
        ],
        control_artifact_candidates=payload[
            "control_artifact_candidates"
        ],
        registry_digest=str(payload.get("registry_digest") or ""),
        trusted_code_digest=str(payload.get("trusted_code_digest") or ""),
        project_input_candidates=payload["project_input_candidates"],
        inventory_source_artifact=inventory_source,
        records_source_artifact=records_source,
        evidence_source_artifact=evidence_source,
    )
    if dict(payload) != dict(rebuilt.payload):
        raise PreverifyInventorySuccessorError(
            "preverify capture plan source denominator drifted"
        )
    if expected_plan is not None:
        expected_payload = (
            expected_plan.payload
            if isinstance(expected_plan, PreverifyCapturePlan)
            else expected_plan
        )
        if dict(payload) != dict(expected_payload):
            raise PreverifyInventorySuccessorError(
                "preverify capture plan differs from the re-enumerated "
                "producer/control denominator"
            )
    return rebuilt


def _normalize_bindings(
    root: Path,
    names: Sequence[str],
    *,
    label: str,
) -> list[dict[str, Any]]:
    normalized = tuple(sorted(str(value) for value in names))
    if len(normalized) != len(set(normalized)):
        raise PreverifyInventorySuccessorError(
            f"{label} denominator contains duplicate artifacts"
        )
    return [_artifact_binding(root, name) for name in normalized]


def _validate_delivery_payload(
    payload: Mapping[str, Any],
    *,
    inventory_sha256: str,
    producer_bindings: Sequence[Mapping[str, Any]],
) -> None:
    if (
        not isinstance(payload, Mapping)
        or payload.get("schema_version") != _DELIVERY_PAYLOAD_SCHEMA
        or payload.get("inventory_artifact") != "findings_inventory.md"
        or payload.get("inventory_sha256") != "sha256:" + inventory_sha256
        or payload.get("receipt_digest")
        != _digest_without(payload, "receipt_digest")
        or not isinstance(payload.get("artifacts"), list)
        or not isinstance(payload.get("actions"), list)
        or not isinstance(payload.get("residual_debt"), list)
    ):
        raise PreverifyInventorySuccessorError(
            "delivery payload inventory binding or digest is invalid"
        )
    expected = {
        str(row["artifact"]): "sha256:" + str(row["sha256"])
        for row in producer_bindings
    }
    observed: dict[str, str] = {}
    for row in payload["artifacts"]:
        if not isinstance(row, Mapping):
            raise PreverifyInventorySuccessorError(
                "delivery payload producer binding is malformed"
            )
        name = _safe_relative_name(
            row.get("artifact"), label="delivery producer artifact"
        )
        if name in observed:
            raise PreverifyInventorySuccessorError(
                "delivery payload producer binding is duplicated"
            )
        observed[name] = str(row.get("sha256") or "")
    if observed != expected:
        raise PreverifyInventorySuccessorError(
            "delivery payload producer denominator differs from final "
            "registered producer bindings"
        )


def build_preverify_successor_payloads(
    scratchpad: Path,
    *,
    run_id: str,
    delivery_payload: Mapping[str, Any],
    producer_artifacts: Sequence[str],
    mutation_authority_artifacts: Sequence[str] = (),
    inventory_source_artifact: str = "findings_inventory.md",
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build the exact successor chain without mutating disk."""

    root = Path(scratchpad)
    run = str(run_id or "").strip()
    if not run:
        raise PreverifyInventorySuccessorError("run_id must be non-empty")
    inventory_source = _safe_relative_name(
        inventory_source_artifact,
        label="inventory source artifact",
    )
    inventory_path = root.joinpath(*PurePosixPath(inventory_source).parts)
    try:
        inventory_raw = inventory_path.read_bytes()
    except OSError as exc:
        raise PreverifyInventorySuccessorError(
            "final inventory is unavailable"
        ) from exc
    inventory_sha = _sha(inventory_raw)
    producers = _normalize_bindings(
        root, producer_artifacts, label="producer artifact"
    )
    mutation_authorities = _normalize_bindings(
        root,
        mutation_authority_artifacts,
        label="mutation authority artifact",
    )
    _validate_delivery_payload(
        delivery_payload,
        inventory_sha256=inventory_sha,
        producer_bindings=producers,
    )
    unsigned_final: dict[str, Any] = {
        "schema_version": FINAL_SCHEMA,
        "run_id": run,
        "inventory_artifact": "findings_inventory.md",
        "inventory_size_bytes": len(inventory_raw),
        "inventory_sha256": inventory_sha,
        "producer_artifact_count": len(producers),
        "producer_artifact_digest": _sha(_canonical_json_bytes(producers)),
        "producer_artifacts": producers,
        "mutation_authority_count": len(mutation_authorities),
        "mutation_authority_digest": _sha(
            _canonical_json_bytes(mutation_authorities)
        ),
        "mutation_authorities": mutation_authorities,
    }
    final_payload = {
        **unsigned_final,
        "receipt_digest": _sha(_canonical_json_bytes(unsigned_final)),
    }
    delivery_copy = json.loads(
        _canonical_json_bytes(delivery_payload).decode("utf-8")
    )
    unsigned_delivery: dict[str, Any] = {
        "schema_version": DELIVERY_SCHEMA,
        "run_id": run,
        "final_inventory_receipt_artifact": FINAL_RECEIPT_NAME,
        "final_inventory_receipt_digest": final_payload["receipt_digest"],
        "inventory_artifact": "findings_inventory.md",
        "inventory_sha256": inventory_sha,
        "registry_digest": str(delivery_copy.get("registry_digest") or ""),
        "delivery_payload_digest": _sha(
            _canonical_json_bytes(delivery_copy)
        ),
        "delivery_payload": delivery_copy,
    }
    delivery_successor = {
        **unsigned_delivery,
        "receipt_digest": _sha(_canonical_json_bytes(unsigned_delivery)),
    }
    return final_payload, delivery_successor


def _validate_binding_rows(
    root: Path,
    rows: object,
    *,
    label: str,
    validate_current_sources: bool = True,
) -> list[dict[str, Any]]:
    if not isinstance(rows, list):
        raise PreverifyInventorySuccessorError(f"{label} rows are malformed")
    normalized: list[dict[str, Any]] = []
    last_name = ""
    for raw in rows:
        if not isinstance(raw, Mapping) or set(raw) != {
            "artifact",
            "size_bytes",
            "sha256",
        }:
            raise PreverifyInventorySuccessorError(
                f"{label} binding row is malformed"
            )
        name = _safe_relative_name(raw.get("artifact"), label=label)
        if name <= last_name:
            raise PreverifyInventorySuccessorError(
                f"{label} bindings are duplicated or unsorted"
            )
        last_name = name
        if (
            not isinstance(raw.get("size_bytes"), int)
            or int(raw["size_bytes"]) < 0
            or not isinstance(raw.get("sha256"), str)
            or _SHA_RE.fullmatch(str(raw["sha256"])) is None
        ):
            raise PreverifyInventorySuccessorError(
                f"{label} binding row is malformed"
            )
        if validate_current_sources:
            expected = _artifact_binding(root, name)
            if dict(raw) != expected:
                raise PreverifyInventorySuccessorError(
                    f"{label} is stale: {name}"
                )
        normalized.append(dict(raw))
    return normalized


def validate_preverify_successor_payloads(
    scratchpad: Path,
    *,
    final_payload: Mapping[str, Any],
    delivery_payload: Mapping[str, Any],
    run_id: str,
    validate_current_sources: bool = True,
    inventory_source_artifact: str = "findings_inventory.md",
) -> None:
    """Reject any stale/tampered successor generation."""

    root = Path(scratchpad)
    expected_final_fields = {
        "schema_version",
        "run_id",
        "inventory_artifact",
        "inventory_size_bytes",
        "inventory_sha256",
        "producer_artifact_count",
        "producer_artifact_digest",
        "producer_artifacts",
        "mutation_authority_count",
        "mutation_authority_digest",
        "mutation_authorities",
        "receipt_digest",
    }
    run = str(run_id or "").strip()
    inventory_source = _safe_relative_name(
        inventory_source_artifact,
        label="inventory source artifact",
    )
    inventory_raw = b""
    if validate_current_sources:
        try:
            inventory_raw = root.joinpath(
                *PurePosixPath(inventory_source).parts
            ).read_bytes()
        except OSError as exc:
            raise PreverifyInventorySuccessorError(
                "final inventory is unavailable"
            ) from exc
    if (
        not isinstance(final_payload, Mapping)
        or set(final_payload) != expected_final_fields
        or final_payload.get("schema_version") != FINAL_SCHEMA
        or final_payload.get("run_id") != run
        or final_payload.get("inventory_artifact") != "findings_inventory.md"
        or final_payload.get("receipt_digest")
        != _digest_without(final_payload, "receipt_digest")
    ):
        raise PreverifyInventorySuccessorError(
            "final inventory successor schema or digest is invalid"
        )
    if validate_current_sources:
        if (
            final_payload.get("inventory_size_bytes") != len(inventory_raw)
            or final_payload.get("inventory_sha256") != _sha(inventory_raw)
        ):
            raise PreverifyInventorySuccessorError(
                "final inventory successor is stale"
            )
    elif (
        not isinstance(final_payload.get("inventory_size_bytes"), int)
        or int(final_payload["inventory_size_bytes"]) < 0
        or not isinstance(final_payload.get("inventory_sha256"), str)
        or _SHA_RE.fullmatch(str(final_payload["inventory_sha256"])) is None
    ):
        raise PreverifyInventorySuccessorError(
            "final inventory successor inventory binding is malformed"
        )
    producers = _validate_binding_rows(
        root,
        final_payload.get("producer_artifacts"),
        label="producer artifact",
        validate_current_sources=validate_current_sources,
    )
    mutations = _validate_binding_rows(
        root,
        final_payload.get("mutation_authorities"),
        label="mutation authority artifact",
        validate_current_sources=validate_current_sources,
    )
    if (
        final_payload.get("producer_artifact_count") != len(producers)
        or final_payload.get("producer_artifact_digest")
        != _sha(_canonical_json_bytes(producers))
        or final_payload.get("mutation_authority_count") != len(mutations)
        or final_payload.get("mutation_authority_digest")
        != _sha(_canonical_json_bytes(mutations))
    ):
        raise PreverifyInventorySuccessorError(
            "final inventory successor denominator digest is invalid"
        )

    expected_delivery_fields = {
        "schema_version",
        "run_id",
        "final_inventory_receipt_artifact",
        "final_inventory_receipt_digest",
        "inventory_artifact",
        "inventory_sha256",
        "registry_digest",
        "delivery_payload_digest",
        "delivery_payload",
        "receipt_digest",
    }
    if (
        not isinstance(delivery_payload, Mapping)
        or set(delivery_payload) != expected_delivery_fields
        or delivery_payload.get("schema_version") != DELIVERY_SCHEMA
        or delivery_payload.get("run_id") != run
        or delivery_payload.get("final_inventory_receipt_artifact")
        != FINAL_RECEIPT_NAME
        or delivery_payload.get("final_inventory_receipt_digest")
        != final_payload.get("receipt_digest")
        or delivery_payload.get("inventory_artifact")
        != "findings_inventory.md"
        or delivery_payload.get("inventory_sha256")
        != final_payload.get("inventory_sha256")
        or delivery_payload.get("receipt_digest")
        != _digest_without(delivery_payload, "receipt_digest")
        or delivery_payload.get("delivery_payload_digest")
        != _sha(_canonical_json_bytes(delivery_payload.get("delivery_payload")))
    ):
        raise PreverifyInventorySuccessorError(
            "registered delivery successor schema or digest is invalid"
        )
    embedded = delivery_payload.get("delivery_payload")
    if not isinstance(embedded, Mapping):
        raise PreverifyInventorySuccessorError(
            "registered delivery successor payload is malformed"
        )
    _validate_delivery_payload(
        embedded,
        inventory_sha256=str(final_payload["inventory_sha256"]),
        producer_bindings=producers,
    )
    if delivery_payload.get("registry_digest") != embedded.get(
        "registry_digest"
    ):
        raise PreverifyInventorySuccessorError(
            "registered delivery successor registry binding is stale"
        )


def encode_successor_payload(payload: Mapping[str, Any]) -> bytes:
    """Canonical pretty JSON bytes for driver-owned materialization."""

    return (
        json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            indent=2,
        )
        + "\n"
    ).encode("utf-8")


def build_successor_generation_payload(
    *,
    run_id: str,
    final_payload: Mapping[str, Any],
    delivery_payload: Mapping[str, Any],
    capture_plan: Mapping[str, Any] | PreverifyCapturePlan,
) -> tuple[str, dict[str, Any]]:
    """Create one content-addressed, provenance-bound capture generation."""

    run = str(run_id or "").strip()
    capture_payload = (
        capture_plan.payload
        if isinstance(capture_plan, PreverifyCapturePlan)
        else capture_plan
    )
    if (
        not run
        or final_payload.get("run_id") != run
        or delivery_payload.get("run_id") != run
        or not isinstance(capture_payload, Mapping)
        or capture_payload.get("run_id") != run
        or capture_payload.get("schema_version") != CAPTURE_PLAN_SCHEMA
        or capture_payload.get("plan_digest")
        != _digest_without(capture_payload, "plan_digest")
    ):
        raise PreverifyInventorySuccessorError(
            "successor generation run binding is invalid"
        )
    unsigned = {
        "schema_version": GENERATION_SCHEMA,
        "run_id": run,
        "capture_plan": json.loads(
            _canonical_json_bytes(capture_payload).decode("utf-8")
        ),
        "final_payload": json.loads(
            _canonical_json_bytes(final_payload).decode("utf-8")
        ),
        "delivery_payload": json.loads(
            _canonical_json_bytes(delivery_payload).decode("utf-8")
        ),
    }
    digest = _sha(_canonical_json_bytes(unsigned))
    payload = {**unsigned, "generation_digest": digest}
    return (
        f"{GENERATION_DIRECTORY}/generation_{digest}.json",
        payload,
    )


def validate_successor_generation_payload(
    scratchpad: Path,
    *,
    payload: Mapping[str, Any],
    artifact_name: str,
    expected_capture_plan: (
        Mapping[str, Any] | PreverifyCapturePlan | None
    ) = None,
    validate_current_sources: bool = True,
) -> None:
    """Validate the content address, provenance plan, and embedded receipts."""

    expected_fields = {
        "schema_version",
        "run_id",
        "capture_plan",
        "final_payload",
        "delivery_payload",
        "generation_digest",
    }
    if (
        not isinstance(payload, Mapping)
        or set(payload) != expected_fields
        or payload.get("schema_version") != GENERATION_SCHEMA
        or payload.get("generation_digest")
        != _digest_without(payload, "generation_digest")
    ):
        raise PreverifyInventorySuccessorError(
            "preverify successor generation schema or digest is invalid"
        )
    expected_name = (
        f"{GENERATION_DIRECTORY}/generation_"
        f"{payload['generation_digest']}.json"
    )
    if artifact_name != expected_name:
        raise PreverifyInventorySuccessorError(
            "preverify successor generation content address is invalid"
        )
    final_payload = payload.get("final_payload")
    delivery_payload = payload.get("delivery_payload")
    capture_plan = payload.get("capture_plan")
    if not isinstance(final_payload, Mapping) or not isinstance(
        delivery_payload, Mapping
    ) or not isinstance(
        capture_plan, Mapping
    ):
        raise PreverifyInventorySuccessorError(
            "preverify successor generation payload is malformed"
        )
    if capture_plan.get("run_id") != payload.get("run_id"):
        raise PreverifyInventorySuccessorError(
            "preverify successor generation capture-plan run mismatch"
        )
    source_projection = capture_plan.get("source_projection")
    inventory_source = (
        str(source_projection.get("inventory") or "")
        if isinstance(source_projection, Mapping)
        else "findings_inventory.md"
    )
    if validate_current_sources:
        validate_preverify_capture_plan(
            Path(scratchpad),
            capture_plan,
            expected_plan=expected_capture_plan,
        )
        validate_preverify_successor_payloads(
            Path(scratchpad),
            final_payload=final_payload,
            delivery_payload=delivery_payload,
            run_id=str(payload.get("run_id") or ""),
            validate_current_sources=True,
            inventory_source_artifact=inventory_source,
        )
    elif (
        capture_plan.get("schema_version") != CAPTURE_PLAN_SCHEMA
        or capture_plan.get("plan_digest")
        != _digest_without(capture_plan, "plan_digest")
    ):
        raise PreverifyInventorySuccessorError(
            "preverify successor generation capture-plan digest is invalid"
        )
    else:
        validate_preverify_successor_payloads(
            Path(scratchpad),
            final_payload=final_payload,
            delivery_payload=delivery_payload,
            run_id=str(payload.get("run_id") or ""),
            validate_current_sources=False,
            inventory_source_artifact=inventory_source,
        )


__all__ = [
    "CAPTURE_PLAN_SCHEMA",
    "DELIVERY_RECEIPT_NAME",
    "DELIVERY_SCHEMA",
    "GENERATION_DIRECTORY",
    "GENERATION_SCHEMA",
    "FINAL_RECEIPT_NAME",
    "FINAL_SCHEMA",
    "PreverifyCapturePlan",
    "PreverifyInventorySuccessorError",
    "build_preverify_capture_plan",
    "build_preverify_successor_payloads",
    "build_successor_generation_payload",
    "encode_successor_payload",
    "validate_preverify_capture_plan",
    "validate_preverify_successor_payloads",
    "validate_successor_generation_payload",
]
