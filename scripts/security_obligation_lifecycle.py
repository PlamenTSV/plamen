"""Driver-owned lifecycle authority for exact post-depth security aliases.

The post-depth security-obligation authority proves that a methodology
question was enumerated and, sometimes, that a depth worker proposed a
finding.  It does not prove that the candidate reached the verifier or that a
negative verifier verdict is safe.  This module keeps those facts separate in
one deterministic row per ``SOT-*`` alias.

Only the exact mandatory-reverification denominator -> routing -> assignment
-> completion chain, replayed against the current typed queue/work plan and
verifier output receipt/bytes, can create a verified state.  A negative
verdict remains visible unless the loader-owned central negative-closure
broker authorizes the same alias and assigned work item.  Missing, stale, or
malformed inputs only reopen visible debt.
"""
from __future__ import annotations

import hashlib
import json
import os
from collections import Counter
from pathlib import Path
import re
import tempfile
from typing import Any, Mapping, Sequence

from closure_broker_v2 import (
    AUTHORIZED,
    CENTRAL_BUNDLE_DIR,
    CENTRAL_DECISION_SCHEMA,
    CENTRAL_LEDGER_NAME,
    REFUTED_FULL,
    load_central_negative_closure_authority,
    resolve_central_negative_closure,
)
from mandatory_reverification import (
    ASSIGNMENT_FILE as MANDATORY_ASSIGNMENT_FILE,
    COMPLETION_FILE as MANDATORY_COMPLETION_FILE,
    DENOMINATOR_FILE as MANDATORY_DENOMINATOR_FILE,
    ROUTING_FILE as MANDATORY_ROUTING_FILE,
    _validate_assignment,
    _validate_completion,
    _validate_routing,
    validate_mandatory_reverification_denominator,
)
from plamen_parsers import read_queue_work_plan
from queue_work_items import QueueWorkItem, queue_records_from_json
from security_obligation_authority import (
    AUTHORITY_FILE as SOURCE_AUTHORITY_FILE,
    OBLIGATION_SCHEMA,
    POST_DEPTH_STAGE,
    security_obligation_input_artifacts,
    validate_security_obligation_authority,
)
from verifier_work_roster import VerifierWorkRoster


SCHEMA_VERSION = "plamen.security_obligation_lifecycle.v1"
AUTHORITY_FILE = "security_obligation_lifecycle.json"
PROJECTION_FILE = "security_obligation_lifecycle.md"
REPORT_RETENTION_FILE = "security_obligation_report_retention.md"

QUEUE_ITEMS_FILE = "verification_queue.work_items.json"
QUEUE_WORK_PLAN_FILE = "verification_queue.work_plan.json"
VERIFIER_ROSTER_FILE = "verification_runtime_roster.json"

OPEN_REPAIR = "OPEN_REPAIR"
VERIFY_PENDING = "VERIFY_PENDING"
VERIFICATION_DEBT = "VERIFICATION_DEBT"
VERIFIED_CONFIRMED = "VERIFIED_CONFIRMED"
VERIFIED_CONTESTED = "VERIFIED_CONTESTED"
NEGATIVE_PROPOSAL_RETAINED = "NEGATIVE_PROPOSAL_RETAINED"
AUTHORIZED_NEGATIVE = "AUTHORIZED_NEGATIVE"
CONFLICTED_REVIEW = "CONFLICTED_REVIEW"

STATES = frozenset(
    {
        OPEN_REPAIR,
        VERIFY_PENDING,
        VERIFICATION_DEBT,
        VERIFIED_CONFIRMED,
        VERIFIED_CONTESTED,
        NEGATIVE_PROPOSAL_RETAINED,
        AUTHORIZED_NEGATIVE,
        CONFLICTED_REVIEW,
    }
)

_NEGATIVE_VERDICTS = frozenset(
    {
        "APPENDIX_ONLY",
        "DROP_FALSE_POSITIVE",
        "DROP_NON_SECURITY",
        "DROP_DESIGN_CONFIRMATION",
        "DROP_UNACTIONABLE_SPECULATION",
        "FALSE_POSITIVE",
        "REFUTED",
        "INFEASIBLE",
        "SCHEMA_INVALID",
        "LOCATION_INVALID",
    }
)
_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_ALIAS = re.compile(r"^SOT-[0-9A-Fa-f]{24}$", re.ASCII)
_ARTIFACT_ROLES = {
    "security_authority": SOURCE_AUTHORITY_FILE,
    "mandatory_denominator": MANDATORY_DENOMINATOR_FILE,
    "mandatory_routing": MANDATORY_ROUTING_FILE,
    "mandatory_assignment": MANDATORY_ASSIGNMENT_FILE,
    "mandatory_completion": MANDATORY_COMPLETION_FILE,
    "queue_items": QUEUE_ITEMS_FILE,
    "queue_work_plan": QUEUE_WORK_PLAN_FILE,
    "verifier_roster": VERIFIER_ROSTER_FILE,
    "central_closure_ledger": CENTRAL_LEDGER_NAME,
}

_ROW_FIELDS = frozenset(
    {
        "alias_id",
        "parent_obligation_id",
        "display_id",
        "subject_id",
        "relation_id",
        "object_id",
        "symbol",
        "source_state",
        "source_receipt_ids",
        "mandatory_obligation_id",
        "candidate_id",
        "candidate_packet_sha256",
        "assigned_work_item_id",
        "verifier_output_sha256",
        "verifier_receipt_sha256",
        "verifier_authority_digest",
        "verifier_verdict",
        "central_resolution_digest",
        "state",
        "retention",
        "terminal_negative_authority",
        "debt_reasons",
        "row_digest",
    }
)
_AUTHORITY_FIELDS = frozenset(
    {
        "schema_version",
        "run_id",
        "source_authority_digest",
        "source_stage",
        "input_bindings",
        "denominator_complete",
        "status",
        "row_count",
        "state_counts",
        "terminal_negative_count",
        "rows",
        "issues",
        "authority_digest",
    }
)


class SecurityObligationLifecycleError(ValueError):
    """A persisted lifecycle artifact cannot be replayed exactly."""


def _canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise SecurityObligationLifecycleError(
            f"lifecycle value is not canonical JSON: {exc}"
        ) from exc


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _strict_json(path: Path) -> tuple[dict[str, Any], bytes]:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise SecurityObligationLifecycleError(
                    f"{path.name} contains duplicate field {key!r}"
                )
            result[key] = value
        return result

    raw = path.read_bytes()
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(
                SecurityObligationLifecycleError(
                    f"{path.name} contains invalid constant {token}"
                )
            ),
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SecurityObligationLifecycleError(
            f"{path.name} is unreadable: {type(exc).__name__}: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise SecurityObligationLifecycleError(
            f"{path.name} must contain a JSON object"
        )
    return value, raw


def _artifact_names(overrides: Mapping[str, str] | None) -> dict[str, str]:
    names = dict(_ARTIFACT_ROLES)
    if overrides is None:
        return names
    if not isinstance(overrides, Mapping) or not set(overrides) <= set(names):
        raise SecurityObligationLifecycleError(
            "artifact_names contains an unknown lifecycle role"
        )
    for role, value in overrides.items():
        if (
            not isinstance(value, str)
            or not value
            or value != Path(value).name
            or value in {".", ".."}
            or ":" in value
        ):
            raise SecurityObligationLifecycleError(
                f"artifact name for {role} is not one safe basename"
            )
        names[role] = value
    if len({name.casefold() for name in names.values()}) != len(names):
        raise SecurityObligationLifecycleError(
            "lifecycle artifact basenames collide by case"
        )
    # These readers replay live, code-owned paths internally. Only the four
    # mandatory transaction artifacts may use immutable staged basenames.
    fixed = {
        "security_authority": SOURCE_AUTHORITY_FILE,
        "queue_items": QUEUE_ITEMS_FILE,
        "queue_work_plan": QUEUE_WORK_PLAN_FILE,
        "verifier_roster": VERIFIER_ROSTER_FILE,
        "central_closure_ledger": CENTRAL_LEDGER_NAME,
    }
    if any(names[role] != expected for role, expected in fixed.items()):
        raise SecurityObligationLifecycleError(
            "source and typed verifier authority filenames are code-owned"
        )
    return names


def _expected_digests(
    value: Mapping[str, str] | None, names: Mapping[str, str]
) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise SecurityObligationLifecycleError(
            "expected_input_sha256 must be a mapping"
        )
    normalized: dict[str, str] = {}
    for key, digest in value.items():
        if not isinstance(key, str) or not key or key != key.strip():
            raise SecurityObligationLifecycleError(
                "expected_input_sha256 contains an unsafe artifact"
            )
        if not isinstance(digest, str) or not _HEX64.fullmatch(digest):
            raise SecurityObligationLifecycleError(
                f"expected digest for {key} is not lowercase SHA-256"
            )
        artifact = names[key] if key in names else key.replace("\\", "/")
        candidate = Path(artifact)
        if (
            candidate.is_absolute()
            or artifact.startswith("/")
            or any(
                part in {"", ".", ".."} or ":" in part
                for part in artifact.split("/")
            )
        ):
            raise SecurityObligationLifecycleError(
                f"expected digest artifact is unsafe: {key}"
            )
        prior = normalized.get(artifact)
        if prior is not None and prior != digest:
            raise SecurityObligationLifecycleError(
                f"conflicting expected digests for {artifact}"
            )
        normalized[artifact] = digest
    return normalized


def _binding(
    root: Path,
    *,
    role: str,
    name: str,
    expected: str | None,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    path = root / name
    if not path.is_file():
        return (
            {
                "role": role,
                "artifact": name,
                "present": False,
                "sha256": None,
                "size_bytes": None,
                "expected_sha256": expected,
                "binding_state": "MISSING",
            },
            None,
        )
    if path.is_symlink() or _is_reparse(path):
        return (
            {
                "role": role,
                "artifact": name,
                "present": True,
                "sha256": None,
                "size_bytes": None,
                "expected_sha256": expected,
                "binding_state": "UNSAFE",
            },
            None,
        )
    try:
        value, raw = _strict_json(path)
    except Exception:
        try:
            raw = path.read_bytes()
        except OSError:
            raw = b""
        return (
            {
                "role": role,
                "artifact": name,
                "present": True,
                "sha256": _sha256(raw),
                "size_bytes": len(raw),
                "expected_sha256": expected,
                "binding_state": "MALFORMED",
            },
            None,
        )
    actual = _sha256(raw)
    state = "CURRENT" if expected in {None, actual} else "DIGEST_MISMATCH"
    return (
        {
            "role": role,
            "artifact": name,
            "present": True,
            "sha256": actual,
            "size_bytes": len(raw),
            "expected_sha256": expected,
            "binding_state": state,
        },
        value if state == "CURRENT" else None,
    )


def _raw_binding(
    root: Path,
    *,
    role: str,
    name: str,
    expected: str | None = None,
) -> dict[str, Any]:
    """Bind one arbitrary semantic input as safe raw bytes.

    Dynamic children include Markdown verifier outputs and source projections;
    JSON decoding belongs only to fixed typed-authority roles.
    """

    path = root / name
    if not path.is_file():
        return {
            "role": role,
            "artifact": name,
            "present": False,
            "sha256": None,
            "size_bytes": None,
            "expected_sha256": expected,
            "binding_state": "MISSING",
        }
    if not _safe_current_file(root, path):
        return {
            "role": role,
            "artifact": name,
            "present": True,
            "sha256": None,
            "size_bytes": None,
            "expected_sha256": expected,
            "binding_state": "UNSAFE",
        }
    try:
        raw = path.read_bytes()
    except OSError:
        raw = b""
        state = "UNREADABLE"
    else:
        actual = _sha256(raw)
        state = "CURRENT" if expected in {None, actual} else "DIGEST_MISMATCH"
    actual = _sha256(raw) if state != "UNREADABLE" else None
    return {
        "role": role,
        "artifact": name,
        "present": True,
        "sha256": actual,
        "size_bytes": len(raw) if state != "UNREADABLE" else None,
        "expected_sha256": expected,
        "binding_state": state,
    }


def _is_reparse(path: Path) -> bool:
    try:
        return bool(getattr(path.lstat(), "st_file_attributes", 0) & 0x400)
    except OSError:
        return False


def _safe_current_file(root: Path, path: Path) -> bool:
    """Reject symlink/reparse traversal for one current authority input."""

    try:
        resolved_root = root.resolve(strict=True)
        path.relative_to(root)
    except (OSError, ValueError):
        return False
    cursor = root
    try:
        relative = path.relative_to(root)
    except ValueError:
        return False
    if cursor.is_symlink() or _is_reparse(cursor):
        return False
    for part in relative.parts:
        cursor = cursor / part
        if cursor.is_symlink() or _is_reparse(cursor):
            return False
    try:
        resolved = cursor.resolve(strict=True)
        resolved.relative_to(resolved_root)
    except (OSError, ValueError):
        return False
    return cursor.is_file()


def _verifier_authority_paths_safe(
    root: Path, *, work_item_id: str, runtime_work_unit_id: str
) -> bool:
    unit_dir = root / "_verifier_runtime_units" / runtime_work_unit_id
    paths = [
        root / f"verify_{work_item_id}.md",
        root / f"verify_{work_item_id}.identity.json",
        root / f"verify_{work_item_id}.receipt.json",
        root / f"verify_{work_item_id}.severity_proposal.json",
        unit_dir / "launch_spec.json",
        unit_dir / "unit_receipt.json",
        unit_dir / "gate_receipt.json",
    ]
    successor = root / f"verify_{work_item_id}.mechanical_successor.receipt.json"
    if successor.exists():
        paths.append(successor)
    # Unknown sibling receipt names are not selected authority and must never
    # be guessed into the replay.  The exact base receipt and the one
    # code-owned append-only successor receipt are the only accepted names.
    allowed = {
        f"verify_{work_item_id}.receipt.json",
        f"verify_{work_item_id}.mechanical_successor.receipt.json",
    }
    variants = {f"verify_{work_item_id}.receipt.json"}
    variants.update(
        path.name
        for path in root.glob(f"verify_{work_item_id}.*.receipt.json")
    )
    return variants <= allowed and all(_safe_current_file(root, path) for path in paths)


def _current_verifier_bytes(
    root: Path,
    item: QueueWorkItem,
) -> tuple[str, Any, bytes, bytes] | tuple[None, None, None, None]:
    """Read the exact current verifier chain after full authority replay.

    The original verifier receipt authenticates the model-owned prefix.  A
    mechanical successor may only append a separately receipted transform;
    it cannot replace that proof or silently become a second verifier.
    """

    output_path = root / item.expected_output_file
    receipt_path = root / f"verify_{item.work_item_id}.receipt.json"
    proposal_path = root / f"verify_{item.work_item_id}.severity_proposal.json"
    try:
        from mechanical_successor_receipts import MechanicalSuccessorReceipt
        from queue_work_items import VerifierOutputReceipt

        current = output_path.read_bytes()
        proposal = proposal_path.read_bytes()
        receipt = VerifierOutputReceipt.from_json(
            receipt_path.read_text(encoding="utf-8", errors="strict")
        )
        original = current
        successor_path = (
            root / f"verify_{item.work_item_id}.mechanical_successor.receipt.json"
        )
        if successor_path.is_file():
            successor = MechanicalSuccessorReceipt.from_json(
                successor_path.read_text(encoding="utf-8", errors="strict")
            )
            original = current[: successor.original_output_size_bytes]
        plan = read_queue_work_plan(root)
        receipt.validate_against(
            item,
            plan,
            original,
            severity_proposal=proposal,
            launch_digest=receipt.launch_digest,
            verifier_backend=receipt.verifier_backend,
        )
        text = original.decode("utf-8", errors="strict")
        verdict = None
        for token in (
            "CONFIRMED", "CONTESTED", "APPENDIX_ONLY", "DROP_FALSE_POSITIVE",
            "DROP_NON_SECURITY", "DROP_DESIGN_CONFIRMATION",
            "DROP_UNACTIONABLE_SPECULATION", "FALSE_POSITIVE", "REFUTED",
            "INFEASIBLE", "SCHEMA_INVALID", "LOCATION_INVALID", "DUPLICATE",
            "CONSOLIDATED",
        ):
            if re.search(rf"\bVerdict\s*\*?\*?\s*:\s*{re.escape(token)}\b", text, re.I):
                verdict = token
                break
        if verdict is None:
            return None, None, None, None
        return verdict, receipt, original, current
    except (OSError, UnicodeError, ValueError, TypeError):
        return None, None, None, None


def _verifier_gate_receipt_issues(
    root: Path,
    *,
    work_item_id: str,
    runtime_work_unit_id: str,
    roster: VerifierWorkRoster,
) -> list[str]:
    """Replay the code-owned unit gate shape selected by one work item."""

    unit = next(
        (
            candidate
            for candidate in roster.work_units
            if candidate.work_unit_id == runtime_work_unit_id
        ),
        None,
    )
    if unit is None or work_item_id not in unit.ordered_work_item_ids:
        return ["selected verifier unit is absent from the current roster"]
    unit_dir = root / "_verifier_runtime_units" / runtime_work_unit_id
    gate_path = unit_dir / "gate_receipt.json"
    launch_path = unit_dir / "launch_spec.json"
    unit_receipt_path = unit_dir / "unit_receipt.json"
    dispatch_path = unit_dir / "method_dispatch.json"
    exact_fields = {
        "schema_version", "state", "work_unit_id", "work_unit_resume_digest",
        "roster_digest", "launch_spec_digest", "method_dispatch_id",
        "method_dispatch_sha256", "ordered_work_item_ids",
        "operator_receipt_digests", "output_sha256",
    }
    try:
        from verifier_work_roster import VerifierLaunchSpec, VerifierUnitReceipt

        gate, _ = _strict_json(gate_path)
        dispatch, _ = _strict_json(dispatch_path)
        launch = VerifierLaunchSpec.from_json(
            launch_path.read_text(encoding="utf-8", errors="strict")
        )
        unit_receipt = VerifierUnitReceipt.from_json(
            unit_receipt_path.read_text(encoding="utf-8", errors="strict")
        )
        if set(gate) != exact_fields:
            raise SecurityObligationLifecycleError(
                "unit gate receipt fields are not exact"
            )
        if (
            gate.get("schema_version") != "plamen.verifier_unit_gate_receipt.v1"
            or gate.get("state") != "CLEAN"
            or gate.get("work_unit_id") != unit.work_unit_id
            or gate.get("work_unit_resume_digest") != unit.resume_digest
            or gate.get("roster_digest") != roster.digest
            or gate.get("launch_spec_digest") != launch.digest
            or unit_receipt.launch_spec_digest != launch.digest
            or gate.get("method_dispatch_id") != dispatch.get("dispatch_id")
            or gate.get("method_dispatch_sha256")
            != _sha256(dispatch_path.read_bytes())
            or gate.get("ordered_work_item_ids")
            != list(unit.ordered_work_item_ids)
        ):
            raise SecurityObligationLifecycleError(
                "unit gate receipt binding mismatch"
            )
        expected_outputs = {}
        for name in unit.expected_output_files:
            expected_sha = _sha256((root / name).read_bytes())
            matched_id = next(
                (
                    candidate_id
                    for candidate_id in unit.ordered_work_item_ids
                    if name == f"verify_{candidate_id}.md"
                ),
                None,
            )
            if matched_id:
                successor_path = (
                    root / f"verify_{matched_id}.mechanical_successor.receipt.json"
                )
                if successor_path.is_file():
                    from mechanical_successor_receipts import MechanicalSuccessorReceipt

                    successor = MechanicalSuccessorReceipt.from_json(
                        successor_path.read_text(encoding="utf-8", errors="strict")
                    )
                    expected_sha = successor.original_output_sha256
            expected_outputs[name] = expected_sha
        if gate.get("output_sha256") != expected_outputs:
            raise SecurityObligationLifecycleError(
                "unit gate output denominator changed"
            )
        operator_digests = gate.get("operator_receipt_digests")
        if (
            not isinstance(operator_digests, list)
            or len(operator_digests) != len(unit.ordered_work_item_ids)
        ):
            raise SecurityObligationLifecycleError(
                "unit gate operator denominator is malformed"
            )
        actual = [
            _sha256((root / f"verify_{candidate_id}.operator_receipt.json").read_bytes())
            for candidate_id in unit.ordered_work_item_ids
        ]
        if operator_digests != actual:
            raise SecurityObligationLifecycleError(
                "unit gate operator receipt bytes changed"
            )
    except Exception as exc:
        return [f"{type(exc).__name__}: {exc}"]
    return []


def _selected_verifier_phaseio_projection(
    root: Path,
    *,
    work_item_id: str,
    queue_shard_id: str,
    runtime_work_unit_id: str,
    successor_original_sha256: str | None = None,
) -> dict[str, Any]:
    """Return the exact ledger slice consumed for one verified lifecycle row.

    Binding the entire mutable ledger would cause unrelated workers to
    invalidate this terminal boundary.  This projection contains only the
    selected model/control transactions and their exact owned artifacts.
    """

    from artifact_ledger import read_artifact_ledger

    ledger = read_artifact_ledger(root)
    output_identity = f"scratchpad:verify_{work_item_id}.md"
    output_binding = ledger.get("artifact_bindings", {}).get(output_identity)
    if not isinstance(output_binding, Mapping):
        raise SecurityObligationLifecycleError(
            "selected verifier output lacks PhaseIO ownership"
        )
    model_owner = str(output_binding.get("owner_key") or "")
    expected_model_suffix = (
        f"/{queue_shard_id}/method_model.{runtime_work_unit_id}"
    )
    if not model_owner.endswith(expected_model_suffix):
        raise SecurityObligationLifecycleError(
            "selected verifier model ownership is stale"
        )
    unit_base = f"_verifier_runtime_units/{runtime_work_unit_id}"
    control_identities = (
        f"scratchpad:{unit_base}/gate_receipt.json",
        f"scratchpad:{unit_base}/unit_receipt.json",
    )
    control_owners = {
        str((ledger.get("artifact_bindings", {}).get(identity) or {}).get("owner_key") or "")
        for identity in control_identities
    }
    if len(control_owners) != 1 or not next(iter(control_owners)).endswith(
        f"/{queue_shard_id}/method_receipt.{runtime_work_unit_id}"
    ):
        raise SecurityObligationLifecycleError(
            "selected verifier control ownership is stale"
        )
    control_owner = next(iter(control_owners))
    work_units = ledger.get("work_units", {})
    model_unit = work_units.get(model_owner)
    control_unit = work_units.get(control_owner)
    if not isinstance(model_unit, Mapping) or not isinstance(control_unit, Mapping):
        raise SecurityObligationLifecycleError(
            "selected verifier PhaseIO transaction is missing"
        )
    manifest = model_unit.get("contract_manifest")
    artifacts = model_unit.get("artifacts")
    if not isinstance(manifest, Mapping) or not isinstance(artifacts, Mapping):
        raise SecurityObligationLifecycleError(
            "selected verifier model transaction is malformed"
        )
    for spec in manifest.get("outputs") or []:
        if not isinstance(spec, Mapping) or spec.get("writer") != "MODEL":
            raise SecurityObligationLifecycleError(
                "selected verifier model output schema is invalid"
            )
        identity = str(spec.get("identity") or "")
        record = artifacts.get(identity)
        live = ledger.get("artifact_bindings", {}).get(identity)
        if not isinstance(record, Mapping) or not isinstance(live, Mapping):
            raise SecurityObligationLifecycleError(
                "selected verifier model output is unowned"
            )
        root_name, relative = identity.split(":", 1)
        base = root if root_name == "scratchpad" else root.parent
        expected_sha = _sha256((base / relative).read_bytes())
        if identity == output_identity and successor_original_sha256:
            expected_sha = successor_original_sha256
        if (
            record.get("status") != "ACTIVE"
            or live.get("status") != "ACTIVE"
            or record.get("owner_key") != model_owner
            or live.get("owner_key") != model_owner
            or record.get("sha256") != expected_sha
            or live.get("sha256") != expected_sha
        ):
            raise SecurityObligationLifecycleError(
                "selected verifier model output authority is stale"
            )
    for identity, input_binding in (model_unit.get("input_bindings") or {}).items():
        if not isinstance(input_binding, Mapping):
            raise SecurityObligationLifecycleError(
                "selected verifier model input binding is malformed"
            )
        root_name, relative = str(identity).split(":", 1)
        base = root if root_name == "scratchpad" else root.parent
        path = base / relative
        if (
            input_binding.get("status") != "ACTIVE"
            or not path.is_file()
            or input_binding.get("sha256") != _sha256(path.read_bytes())
        ):
            raise SecurityObligationLifecycleError(
                "selected verifier model semantic input is stale"
            )
    identities = set(control_identities)
    for unit in (model_unit, control_unit):
        for identity in (unit.get("artifacts") or {}):
            identities.add(str(identity))
    bindings: dict[str, Any] = {}
    for identity in sorted(identities):
        binding = ledger.get("artifact_bindings", {}).get(identity)
        if not isinstance(binding, Mapping):
            raise SecurityObligationLifecycleError(
                f"selected verifier artifact is unowned: {identity}"
            )
        bindings[identity] = dict(binding)
    return {
        "schema_version": "plamen.security_obligation_lifecycle.verifier_projection.v1",
        "work_item_id": work_item_id,
        "queue_shard_id": queue_shard_id,
        "runtime_work_unit_id": runtime_work_unit_id,
        "model_owner_key": model_owner,
        "control_owner_key": control_owner,
        "work_units": {
            model_owner: dict(model_unit),
            control_owner: dict(control_unit),
        },
        "artifact_bindings": bindings,
    }


def _row_digest(row: Mapping[str, Any]) -> str:
    return _digest({key: value for key, value in row.items() if key != "row_digest"})


def _authority_digest(authority: Mapping[str, Any]) -> str:
    return _digest(
        {
            key: value
            for key, value in authority.items()
            if key != "authority_digest"
        }
    )


def _base_row(
    obligation: Mapping[str, Any], alias: Mapping[str, Any]
) -> dict[str, Any]:
    alias_id = str(alias.get("alias_id") or "")
    receipts = [
        receipt
        for receipt in obligation.get("receipts") or []
        if isinstance(receipt, Mapping)
        and alias_id in {str(item) for item in receipt.get("covered_alias_ids") or []}
    ]
    pending = any(
        receipt.get("pending_independent_verification") is True
        for receipt in receipts
    )
    conflicted = bool(obligation.get("conflict_ids"))
    reasons: list[str] = []
    if conflicted:
        reasons.append("SOURCE_APPLICABILITY_CONFLICT")
    elif pending:
        reasons.append("MANDATORY_VERIFICATION_NOT_YET_BOUND")
    else:
        reasons.append("APPLICATION_REPAIR_NOT_YET_ROUTED")
    unsigned = {
        "alias_id": alias_id,
        "parent_obligation_id": str(obligation.get("obligation_id") or ""),
        "display_id": str(obligation.get("display_id") or ""),
        "subject_id": str(alias.get("subject_id") or ""),
        "relation_id": str(alias.get("relation_id") or ""),
        "object_id": str(alias.get("object_id") or ""),
        "symbol": str(alias.get("symbol") or ""),
        "source_state": str(obligation.get("state") or ""),
        "source_receipt_ids": sorted(
            str(receipt.get("receipt_id") or "") for receipt in receipts
        ),
        "mandatory_obligation_id": None,
        "candidate_id": None,
        "candidate_packet_sha256": None,
        "assigned_work_item_id": None,
        "verifier_output_sha256": None,
        "verifier_receipt_sha256": None,
        "verifier_authority_digest": None,
        "verifier_verdict": None,
        "central_resolution_digest": None,
        "state": CONFLICTED_REVIEW if conflicted else (
            VERIFY_PENDING if pending else OPEN_REPAIR
        ),
        "retention": "RETAIN",
        "terminal_negative_authority": False,
        "debt_reasons": reasons,
    }
    return {**unsigned, "row_digest": _digest(unsigned)}


def _set_row(row: Mapping[str, Any], **changes: Any) -> dict[str, Any]:
    updated = {key: value for key, value in row.items() if key != "row_digest"}
    updated.update(changes)
    updated["debt_reasons"] = sorted(set(updated.get("debt_reasons") or []))
    return {**updated, "row_digest": _digest(updated)}


def _debt(row: Mapping[str, Any], *reasons: str) -> dict[str, Any]:
    return _set_row(
        row,
        state=VERIFICATION_DEBT,
        retention="RETAIN",
        terminal_negative_authority=False,
        central_resolution_digest=None,
        debt_reasons=[*(row.get("debt_reasons") or []), *reasons],
    )


def _central_authorizes(
    decision: Mapping[str, Any],
    *,
    alias_id: str,
    work_item_id: str,
    candidate_content_sha256: str,
) -> bool:
    if (
        decision.get("schema_version") != CENTRAL_DECISION_SCHEMA
        or decision.get("status") != AUTHORIZED
        or decision.get("outcome") != REFUTED_FULL
        or decision.get("requested_effect") != REFUTED_FULL
        or decision.get("candidate_id") != alias_id
        or decision.get("work_item_id") != work_item_id
        or decision.get("candidate_content_sha256") != candidate_content_sha256
        or decision.get("reopen_required") is not False
        or decision.get("debt_reasons") != []
    ):
        return False
    declared = decision.get("resolution_digest")
    return isinstance(declared, str) and _HEX64.fullmatch(declared) is not None and (
        declared
        == _digest(
            {
                key: value
                for key, value in decision.items()
                if key != "resolution_digest"
            }
        )
    )


def _source_rows(
    root: Path, source: Mapping[str, Any], issues: list[str]
) -> tuple[list[dict[str, Any]], bool]:
    if (
        source.get("schema_version") != OBLIGATION_SCHEMA
        or source.get("stage") != POST_DEPTH_STAGE
        or str(source.get("authority_digest") or "").casefold()
        != _digest(
            {
                key: value
                for key, value in source.items()
                if key != "authority_digest"
            }
        )
        or not isinstance(source.get("obligations"), list)
    ):
        issues.append("security_authority: schema, stage, digest, or rows invalid")
        return [], False
    replay_issues = validate_security_obligation_authority(
        root, stage=POST_DEPTH_STAGE
    )
    if replay_issues:
        issues.extend(f"security_authority: {issue}" for issue in replay_issues)
        return [], False
    rows: list[dict[str, Any]] = []
    non_alias_debt = False
    for obligation in source["obligations"]:
        if not isinstance(obligation, Mapping):
            issues.append("security_authority: malformed obligation row")
            non_alias_debt = True
            continue
        aliases = obligation.get("trigger_aliases")
        if not isinstance(aliases, list):
            issues.append(
                f"security_authority: {obligation.get('display_id')} alias denominator malformed"
            )
            non_alias_debt = True
            continue
        if not aliases:
            # SO-000 and any future rule-owned non-alias debt stay visible in
            # the source authority; this alias lifecycle cannot invent an ID.
            if obligation.get("state") not in {"ACCOUNTED"}:
                non_alias_debt = True
                issues.append(
                    "security_authority: non-alias obligation remains outside exact lifecycle rows: "
                    + str(obligation.get("display_id") or "UNKNOWN")
                )
            continue
        for alias in aliases:
            if not isinstance(alias, Mapping) or not _ALIAS.fullmatch(
                str(alias.get("alias_id") or "")
            ):
                issues.append("security_authority: malformed exact alias row")
                non_alias_debt = True
                continue
            rows.append(_base_row(obligation, alias))
    rows.sort(key=lambda row: row["alias_id"])
    duplicates = {
        alias for alias, count in Counter(row["alias_id"] for row in rows).items()
        if count > 1
    }
    if duplicates:
        issues.append(
            "security_authority: duplicate aliases in denominator: "
            + ",".join(sorted(duplicates))
        )
        rows = [
            _set_row(
                row,
                state=CONFLICTED_REVIEW,
                debt_reasons=[
                    *(row["debt_reasons"]),
                    "DUPLICATE_SOURCE_ALIAS_IDENTITY",
                ],
            )
            if row["alias_id"] in duplicates
            else row
            for row in rows
        ]
    return rows, not non_alias_debt and not duplicates


def _load_typed_verifier_context(
    root: Path,
    *,
    names: Mapping[str, str],
    assignment: Mapping[str, Any],
) -> tuple[
    dict[str, QueueWorkItem] | None,
    Any | None,
    VerifierWorkRoster | None,
    str | None,
]:
    try:
        items = queue_records_from_json(
            (root / names["queue_items"]).read_text(
                encoding="utf-8", errors="strict"
            )
        )
        # The public reader also replays the plan against the current typed
        # queue. Code-owned names are enforced by ``_artifact_names``.
        plan = read_queue_work_plan(root)
        roster = VerifierWorkRoster.from_json(
            (root / names["verifier_roster"]).read_text(
                encoding="utf-8", errors="strict"
            )
        )
        if (
            plan.digest != assignment.get("queue_work_plan_digest")
            or roster.digest != assignment.get("verifier_roster_digest")
            or roster.parent_queue_work_plan_digest != plan.digest
            or tuple(roster.ordered_work_item_ids)
            != tuple(plan.ordered_work_item_ids)
        ):
            raise SecurityObligationLifecycleError(
                "typed queue/work-plan/roster chain differs from mandatory assignment"
            )
        return {item.work_item_id: item for item in items}, plan, roster, None
    except Exception as exc:
        return None, None, None, f"TYPED_VERIFIER_CONTEXT_INVALID_{type(exc).__name__.upper()}"


def security_obligation_lifecycle_input_artifacts(
    scratchpad: str | Path,
) -> tuple[str, ...]:
    """Enumerate every current scratchpad file consumed by lifecycle replay.

    The returned denominator is intentionally derived from code-owned typed
    parents (the mandatory assignment, verifier roster, central provider
    bundles, and applied-dedup receipts).  It never guesses children from
    Markdown. Missing children are represented as lifecycle debt; every child
    that *is* read is returned here so PhaseIO can bind its current bytes.
    """

    root = Path(scratchpad)
    names: set[str] = set()

    def safe_relative(value: Any) -> str | None:
        if not isinstance(value, str) or not value or value != value.strip():
            return None
        normalized = value.replace("\\", "/")
        candidate = Path(normalized)
        if (
            candidate.is_absolute()
            or normalized.startswith("/")
            or any(part in {"", ".", ".."} or ":" in part for part in normalized.split("/"))
        ):
            return None
        return normalized

    def add(value: Any) -> Path | None:
        relative = safe_relative(value)
        if relative is None:
            return None
        path = root / Path(relative)
        if _safe_current_file(root, path):
            names.add(relative)
            return path
        return None

    def load_object(value: Any) -> dict[str, Any] | None:
        path = add(value)
        if path is None:
            return None
        try:
            payload, _raw = _strict_json(path)
        except Exception:
            return None
        return payload

    for name in _ARTIFACT_ROLES.values():
        add(name)
    try:
        for name in security_obligation_input_artifacts(
            root, stage=POST_DEPTH_STAGE
        ):
            add(name)
    except Exception:
        # The source authority replay records the corresponding debt.  The
        # enumerator cannot safely guess children after a malformed parent.
        pass

    assignment = load_object(MANDATORY_ASSIGNMENT_FILE)
    roster_payload = load_object(VERIFIER_ROSTER_FILE)
    roster: VerifierWorkRoster | None = None
    if roster_payload is not None:
        try:
            roster = VerifierWorkRoster.from_json(
                json.dumps(roster_payload, sort_keys=True, separators=(",", ":"))
            )
        except Exception:
            roster = None
    selected_units: set[str] = set()
    selected_work: set[str] = set()
    if isinstance(assignment, Mapping):
        for row in assignment.get("assignments") or []:
            if not isinstance(row, Mapping):
                continue
            unit_id = str(row.get("runtime_work_unit_id") or "")
            work_id = str(row.get("assigned_work_item_id") or "")
            if unit_id:
                selected_units.add(unit_id)
            if work_id:
                selected_work.add(work_id)
    if roster is not None:
        for unit in roster.work_units:
            if unit.work_unit_id not in selected_units:
                continue
            selected_work.update(str(value) for value in unit.ordered_work_item_ids)
            unit_base = f"_verifier_runtime_units/{unit.work_unit_id}"
            for leaf in (
                "launch_spec.json", "method_dispatch.json",
                "unit_receipt.json", "gate_receipt.json",
            ):
                add(f"{unit_base}/{leaf}")
            for work_id in unit.ordered_work_item_ids:
                add(f"verify_{work_id}.operator_receipt.json")
    assigned_exact = {
        str(row.get("assigned_work_item_id") or "")
        for row in (assignment or {}).get("assignments", [])
        if isinstance(row, Mapping)
    }
    for work_id in sorted(selected_work):
        # Every receipt in a selected unit participates in the unit receipt
        # vector. Only the exact alias assignment's remaining artifacts are
        # semantically opened by _validated_verifier.
        add(f"verify_{work_id}.receipt.json")
        if work_id in assigned_exact:
            successor_name = f"verify_{work_id}.mechanical_successor.receipt.json"
            successor_path = root / successor_name
            # The model ledger owns the immutable original verifier bytes. A
            # valid append-only successor receipt content-addresses the current
            # transformed bytes, so the final consumer binds that receipt
            # instead of asking the original producer to own bytes it did not
            # write. Full replay below validates prefix and transformed hash.
            suffixes = ["identity.json", "severity_proposal.json"]
            if not _safe_current_file(root, successor_path):
                suffixes.insert(0, "md")
            for suffix in suffixes:
                add(f"verify_{work_id}.{suffix}")
            add(successor_name)

    # Bind the current semantic input bytes selected by each assigned model
    # transaction. The lifecycle authority separately embeds a digest of the
    # exact selected ledger slice, avoiding unrelated-ledger invalidation.
    try:
        from artifact_ledger import read_artifact_ledger

        ledger = read_artifact_ledger(root)
        for work_id in sorted(assigned_exact):
            output_identity = f"scratchpad:verify_{work_id}.md"
            output_binding = ledger.get("artifact_bindings", {}).get(output_identity)
            owner = (
                str(output_binding.get("owner_key") or "")
                if isinstance(output_binding, Mapping)
                else ""
            )
            unit = ledger.get("work_units", {}).get(owner)
            if not isinstance(unit, Mapping):
                continue
            for identity in (unit.get("input_bindings") or {}):
                identity_s = str(identity)
                if identity_s.startswith("scratchpad:"):
                    add(identity_s.split(":", 1)[1])
    except Exception:
        # Full per-row verifier replay records typed debt for missing/malformed
        # ledger authority; this enumerator never guesses through corruption.
        pass

    # The central loader replays its persisted projection, provider bundle
    # denominator, bundle-referenced manifests/evidence, and worker execution
    # receipt tree. Bind every current descendant it can open.
    bundle_root = root / CENTRAL_BUNDLE_DIR
    if bundle_root.is_dir() and not bundle_root.is_symlink() and not _is_reparse(bundle_root):
        for entry in sorted(bundle_root.iterdir(), key=lambda item: item.name):
            if entry.name.startswith(".bundle-") and entry.name.endswith(".tmp"):
                continue
            relative_bundle = f"{CENTRAL_BUNDLE_DIR}/{entry.name}"
            bundle = load_object(relative_bundle)
            if bundle is None:
                add(relative_bundle)
                continue
            referenced = [
                bundle.get("subject_relative_path"),
                bundle.get("evidence_manifest_relative_path"),
                bundle.get("provider_output_relative_path"),
                bundle.get("completion_receipt_relative_path"),
                bundle.get("publish_receipt_relative_path"),
            ]
            subject = load_object(bundle.get("subject_relative_path"))
            evidence = load_object(bundle.get("evidence_manifest_relative_path"))
            for payload in (subject, evidence):
                if not isinstance(payload, Mapping):
                    continue
                for field in ("current_artifacts", "artifacts"):
                    for row in payload.get(field) or []:
                        if isinstance(row, Mapping):
                            referenced.append(row.get("relative_path"))
            completion_path = add(bundle.get("completion_receipt_relative_path"))
            publish_path = add(bundle.get("publish_receipt_relative_path"))
            for value in referenced:
                add(value)
            # Execution validation replays the whole content-addressed shard:
            # arm/publish arms, stream/CAS blobs, and its exact output scope.
            for receipt_path in (completion_path, publish_path):
                if receipt_path is None:
                    continue
                shard_dir = receipt_path.parent
                try:
                    shard_dir.relative_to(root)
                except ValueError:
                    continue
                if shard_dir.is_dir() and not shard_dir.is_symlink() and not _is_reparse(shard_dir):
                    for child in sorted(shard_dir.rglob("*"), key=lambda item: item.as_posix()):
                        if child.is_file() and not child.is_symlink() and not _is_reparse(child):
                            add(child.relative_to(root).as_posix())

    # Applied-equivalence is a second central-provider adapter. Its exact
    # receipts select one canonical post-dedup artifact.
    try:
        from semantic_dedup_authority import (
            PRIMARY_RECEIPT_NAME,
            SUPPLEMENTAL_RECEIPT_NAME,
        )

        receipt_payloads = [
            payload
            for payload in (
                load_object(PRIMARY_RECEIPT_NAME),
                load_object(SUPPLEMENTAL_RECEIPT_NAME),
            )
            if payload is not None
        ]
        if receipt_payloads:
            phase = str(receipt_payloads[0].get("phase_name") or "")
            add(
                "findings_inventory.md"
                if phase == "sc_semantic_dedup"
                else "verification_queue.md"
            )
    except Exception:
        pass
    return tuple(sorted(names))


def build_security_obligation_lifecycle(
    scratchpad: str | Path,
    *,
    artifact_names: Mapping[str, str] | None = None,
    expected_input_sha256: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Reconcile one exact lifecycle row per current post-depth alias.

    ``artifact_names`` lets a future driver point at immutable staged copies
    without weakening identity: only the closed role set and safe basenames
    are accepted.  ``expected_input_sha256`` may bind either role names or
    those basenames.  A mismatch is debt, never a reason to trust current
    bytes.
    """

    root = Path(scratchpad)
    issues: list[str] = []
    try:
        names = _artifact_names(artifact_names)
        expected = _expected_digests(expected_input_sha256, names)
    except Exception as exc:
        names = dict(_ARTIFACT_ROLES)
        expected = {}
        issues.append(f"lifecycle_configuration: {type(exc).__name__}: {exc}")

    bindings: list[dict[str, Any]] = []
    payloads: dict[str, dict[str, Any] | None] = {}
    for role, name in names.items():
        binding, value = _binding(
            root, role=role, name=name, expected=expected.get(name)
        )
        bindings.append(binding)
        payloads[role] = value
    fixed_paths = set(names.values())
    try:
        dynamic_inputs = security_obligation_lifecycle_input_artifacts(root)
    except Exception as exc:
        dynamic_inputs = ()
        issues.append(
            "lifecycle_input_enumeration: "
            f"{type(exc).__name__}: {exc}"
        )
    for name in dynamic_inputs:
        if name in fixed_paths:
            continue
        bindings.append(_raw_binding(
            root,
            role=f"semantic_input:{name}",
            name=name,
            expected=expected.get(name),
        ))
    bindings.sort(key=lambda row: row["role"])
    binding_by_role = {str(row["role"]): row for row in bindings}

    source = payloads["security_authority"]
    source_digest = None
    run_id = ""
    source_stage = POST_DEPTH_STAGE
    rows: list[dict[str, Any]] = []
    denominator_complete = False
    if source is None:
        issues.append("security_authority: missing, malformed, or digest-mismatched")
    else:
        source_digest = str(source.get("authority_digest") or "") or None
        source_stage = str(source.get("stage") or "")
        run_binding = source.get("run_binding")
        if isinstance(run_binding, Mapping):
            run_id = str(run_binding.get("run_id") or "")
        rows, denominator_complete = _source_rows(root, source, issues)

    # Missing non-source inputs are added only when at least one alias could be
    # enumerated.  A missing mandatory denominator is an open repair boundary;
    # later missing artifacts become pending verification boundaries.
    for binding in bindings:
        if binding["role"] == "security_authority":
            continue
        if binding["binding_state"] in {"MALFORMED", "DIGEST_MISMATCH"}:
            issues.append(
                f"{binding['role']}: {binding['binding_state'].lower()}"
            )

    denominator: dict[str, Any] | None = None
    if payloads["mandatory_denominator"] is not None:
        try:
            denominator = validate_mandatory_reverification_denominator(
                payloads["mandatory_denominator"] or {}
            )
            if run_id and denominator["run_id"] != run_id:
                raise SecurityObligationLifecycleError(
                    "mandatory denominator run differs from security authority"
                )
        except Exception as exc:
            issues.append(
                f"mandatory_denominator: invalid or stale: {type(exc).__name__}: {exc}"
            )
            rows = [
                _debt(row, "MANDATORY_DENOMINATOR_INVALID") for row in rows
            ]
            denominator = None
    elif binding_by_role["mandatory_denominator"]["binding_state"] != "MISSING":
        rows = [
            _debt(row, "MANDATORY_DENOMINATOR_INVALID") for row in rows
        ]

    candidates_by_alias: dict[str, list[Mapping[str, Any]]] = {}
    if denominator is not None:
        for candidate in denominator["candidates"]:
            candidates_by_alias.setdefault(
                str(candidate.get("source_obligation_id") or ""), []
            ).append(candidate)
        known_aliases = {row["alias_id"] for row in rows}
        extras = sorted(set(candidates_by_alias) - known_aliases)
        if extras:
            issues.append(
                "mandatory_denominator: candidates outside current alias denominator: "
                + ",".join(extras)
            )

    candidate_by_alias: dict[str, Mapping[str, Any]] = {}
    for index, row in enumerate(rows):
        if row["state"] == CONFLICTED_REVIEW:
            continue
        matches = candidates_by_alias.get(row["alias_id"], [])
        if not matches:
            # A valid mandatory denominator that omits the alias is an
            # application repair gap, not proof of a clean zero denominator.
            if denominator is not None:
                rows[index] = _set_row(
                    row,
                    debt_reasons=[
                        *row["debt_reasons"],
                        "MANDATORY_DENOMINATOR_ALIAS_MISSING",
                    ],
                )
            continue
        if len(matches) != 1:
            rows[index] = _set_row(
                row,
                state=CONFLICTED_REVIEW,
                debt_reasons=[
                    *row["debt_reasons"],
                    "MANDATORY_ALIAS_CARDINALITY_INVALID",
                ],
            )
            continue
        candidate = matches[0]
        candidate_by_alias[row["alias_id"]] = candidate
        rows[index] = _set_row(
            row,
            mandatory_obligation_id=candidate["obligation_id"],
            candidate_id=candidate["candidate_id"],
            candidate_packet_sha256=candidate["candidate_packet_sha256"],
            state=VERIFY_PENDING,
            debt_reasons=["MANDATORY_ROUTE_NOT_YET_BOUND"],
        )

    denominator_complete = bool(
        denominator_complete
        and denominator is not None
        and rows
        and set(candidate_by_alias) == {row["alias_id"] for row in rows}
        and not (set(candidates_by_alias) - {row["alias_id"] for row in rows})
    )

    routing: dict[str, Any] | None = None
    if denominator is not None and payloads["mandatory_routing"] is not None:
        try:
            routing = _validate_routing(
                payloads["mandatory_routing"] or {}, denominator
            )
        except Exception as exc:
            issues.append(
                f"mandatory_routing: invalid or stale: {type(exc).__name__}: {exc}"
            )
            routing = None
            rows = [
                _debt(row, "MANDATORY_ROUTING_INVALID")
                if row["alias_id"] in candidate_by_alias
                else row
                for row in rows
            ]
    elif (
        denominator is not None
        and binding_by_role["mandatory_routing"]["binding_state"] != "MISSING"
    ):
        rows = [
            _debt(row, "MANDATORY_ROUTING_INVALID")
            if row["alias_id"] in candidate_by_alias
            else row
            for row in rows
        ]
    route_by_obligation = {
        str(route.get("obligation_id") or ""): route
        for route in (routing or {}).get("routes", [])
        if isinstance(route, Mapping)
    }

    route_by_alias: dict[str, Mapping[str, Any]] = {}
    for index, row in enumerate(rows):
        candidate = candidate_by_alias.get(row["alias_id"])
        if candidate is None or routing is None or row["state"] in {
            CONFLICTED_REVIEW,
            VERIFICATION_DEBT,
        }:
            continue
        route = route_by_obligation.get(str(candidate["obligation_id"]))
        if route is None:
            debt_match = any(
                isinstance(debt, Mapping)
                and debt.get("obligation_id") == candidate["obligation_id"]
                for debt in routing.get("debts", [])
            )
            rows[index] = (
                _debt(row, "MANDATORY_ROUTE_RECORDED_AS_DEBT")
                if debt_match
                else _debt(row, "MANDATORY_ROUTE_MISSING")
            )
            continue
        if (
            route.get("candidate_id") != candidate["candidate_id"]
            or route.get("candidate_packet_sha256")
            != candidate["candidate_packet_sha256"]
            or route.get("source_obligation_id") != row["alias_id"]
        ):
            rows[index] = _debt(row, "MANDATORY_ROUTE_ALIAS_BINDING_MISMATCH")
            continue
        route_by_alias[row["alias_id"]] = route
        rows[index] = _set_row(
            row,
            assigned_work_item_id=route["assigned_work_item_id"],
            state=VERIFY_PENDING,
            debt_reasons=["MANDATORY_ASSIGNMENT_NOT_YET_BOUND"],
        )

    assignment: dict[str, Any] | None = None
    if denominator is not None and payloads["mandatory_assignment"] is not None:
        try:
            assignment = _validate_assignment(
                payloads["mandatory_assignment"] or {}, denominator
            )
            if routing is None or assignment["routing_digest"] != routing["routing_digest"]:
                raise SecurityObligationLifecycleError(
                    "assignment does not bind the current mandatory routing"
                )
        except Exception as exc:
            issues.append(
                f"mandatory_assignment: invalid or stale: {type(exc).__name__}: {exc}"
            )
            assignment = None
            rows = [
                _debt(row, "MANDATORY_ASSIGNMENT_INVALID")
                if row["alias_id"] in route_by_alias
                else row
                for row in rows
            ]
    elif (
        denominator is not None
        and binding_by_role["mandatory_assignment"]["binding_state"] != "MISSING"
    ):
        rows = [
            _debt(row, "MANDATORY_ASSIGNMENT_INVALID")
            if row["alias_id"] in route_by_alias
            else row
            for row in rows
        ]
    assignment_by_obligation = {
        str(item.get("obligation_id") or ""): item
        for item in (assignment or {}).get("assignments", [])
        if isinstance(item, Mapping)
    }

    assignment_by_alias: dict[str, Mapping[str, Any]] = {}
    for index, row in enumerate(rows):
        candidate = candidate_by_alias.get(row["alias_id"])
        route = route_by_alias.get(row["alias_id"])
        if (
            candidate is None
            or route is None
            or assignment is None
            or row["state"] in {CONFLICTED_REVIEW, VERIFICATION_DEBT}
        ):
            continue
        bound = assignment_by_obligation.get(str(candidate["obligation_id"]))
        if bound is None:
            debt_match = any(
                isinstance(debt, Mapping)
                and debt.get("obligation_id") == candidate["obligation_id"]
                for debt in assignment.get("debts", [])
            )
            rows[index] = (
                _debt(row, "MANDATORY_ASSIGNMENT_RECORDED_AS_DEBT")
                if debt_match
                else _debt(row, "MANDATORY_ASSIGNMENT_MISSING")
            )
            continue
        if (
            bound.get("candidate_id") != candidate["candidate_id"]
            or bound.get("candidate_packet_sha256")
            != candidate["candidate_packet_sha256"]
            or bound.get("route_binding_digest") != route["route_binding_digest"]
            or bound.get("assigned_work_item_id")
            != route["assigned_work_item_id"]
            or type(bound.get("assignment_count")) is not int
            or bound.get("assignment_count") != 1
        ):
            rows[index] = _debt(
                row, "MANDATORY_ASSIGNMENT_ALIAS_BINDING_MISMATCH"
            )
            continue
        assignment_by_alias[row["alias_id"]] = bound
        rows[index] = _set_row(
            row,
            state=VERIFY_PENDING,
            debt_reasons=["MANDATORY_COMPLETION_NOT_YET_BOUND"],
        )

    completion: dict[str, Any] | None = None
    if denominator is not None and payloads["mandatory_completion"] is not None:
        try:
            completion = _validate_completion(
                payloads["mandatory_completion"], denominator
            )
            if completion is None:
                raise SecurityObligationLifecycleError("completion is absent")
            if (
                assignment is None
                or completion["assignment_authority_kind"] != "PRIMARY_QUEUE_ROSTER"
                or completion["assignment_receipt_digest"]
                != assignment["assignment_receipt_digest"]
            ):
                raise SecurityObligationLifecycleError(
                    "completion does not bind the current primary assignment"
                )
        except Exception as exc:
            issues.append(
                f"mandatory_completion: invalid or stale: {type(exc).__name__}: {exc}"
            )
            completion = None
            rows = [
                _debt(row, "MANDATORY_COMPLETION_INVALID")
                if row["alias_id"] in assignment_by_alias
                else row
                for row in rows
            ]
    elif (
        denominator is not None
        and binding_by_role["mandatory_completion"]["binding_state"] != "MISSING"
    ):
        rows = [
            _debt(row, "MANDATORY_COMPLETION_INVALID")
            if row["alias_id"] in assignment_by_alias
            else row
            for row in rows
        ]
    completion_by_obligation = {
        str(item.get("obligation_id") or ""): item
        for item in (completion or {}).get("rows", [])
        if isinstance(item, Mapping)
    }

    typed_items: dict[str, QueueWorkItem] | None = None
    plan: Any | None = None
    roster: VerifierWorkRoster | None = None
    typed_error: str | None = None
    if completion is not None and assignment is not None:
        typed_roles = ("queue_items", "queue_work_plan", "verifier_roster")
        unbound = [
            role
            for role in typed_roles
            if binding_by_role[role]["binding_state"] != "CURRENT"
        ]
        if unbound:
            typed_error = "TYPED_VERIFIER_AUTHORITY_UNBOUND_" + "_".join(
                role.upper() for role in unbound
            )
        else:
            typed_items, plan, roster, typed_error = _load_typed_verifier_context(
                root, names=names, assignment=assignment
            )
        if typed_error:
            issues.append(f"typed_verifier_context: {typed_error}")

    try:
        closure_authority: Any = load_central_negative_closure_authority(root)
        closure_error: str | None = None
    except Exception as exc:
        closure_authority = None
        closure_error = (
            "CENTRAL_NEGATIVE_CLOSURE_UNAVAILABLE_"
            + type(exc).__name__.upper()
        )

    for index, row in enumerate(rows):
        candidate = candidate_by_alias.get(row["alias_id"])
        route = route_by_alias.get(row["alias_id"])
        bound = assignment_by_alias.get(row["alias_id"])
        if (
            candidate is None
            or route is None
            or bound is None
            or completion is None
            or row["state"] in {CONFLICTED_REVIEW, VERIFICATION_DEBT}
        ):
            continue
        completed = completion_by_obligation.get(str(candidate["obligation_id"]))
        if completed is None:
            rows[index] = _debt(row, "MANDATORY_COMPLETION_ROW_MISSING")
            continue
        if (
            completed.get("candidate_id") != candidate["candidate_id"]
            or completed.get("candidate_packet_sha256")
            != candidate["candidate_packet_sha256"]
            or completed.get("assignment_binding_digest")
            != bound["assignment_binding_digest"]
            or completed.get("assigned_work_item_id")
            != bound["assigned_work_item_id"]
        ):
            rows[index] = _debt(
                row, "MANDATORY_COMPLETION_ALIAS_BINDING_MISMATCH"
            )
            continue
        if completed.get("completion_state") != "EXACTLY_COMPLETED":
            rows[index] = _debt(row, "MANDATORY_COMPLETION_RETRY_REQUIRED")
            continue
        if typed_items is None or plan is None or roster is None:
            rows[index] = _debt(
                row, typed_error or "TYPED_VERIFIER_CONTEXT_UNAVAILABLE"
            )
            continue
        work_id = str(bound["assigned_work_item_id"])
        item = typed_items.get(work_id)
        if item is None or item.digest != route.get("assigned_work_item_digest"):
            rows[index] = _debt(row, "TYPED_QUEUE_WORK_ITEM_BINDING_MISMATCH")
            continue
        plan_owners = [
            shard.shard_id
            for shard in plan.shards
            if work_id in shard.ordered_work_item_ids
        ]
        roster_owners = [
            unit.work_unit_id
            for unit in roster.work_units
            if work_id in unit.ordered_work_item_ids
        ]
        if (
            plan_owners != [bound["queue_shard_id"]]
            or roster_owners != [bound["runtime_work_unit_id"]]
        ):
            rows[index] = _debt(row, "TYPED_VERIFIER_OWNER_BINDING_MISMATCH")
            continue
        if not _verifier_authority_paths_safe(
            root,
            work_item_id=work_id,
            runtime_work_unit_id=str(bound["runtime_work_unit_id"]),
        ):
            rows[index] = _debt(row, "TYPED_VERIFIER_AUTHORITY_PATH_UNSAFE")
            continue
        gate_issues = _verifier_gate_receipt_issues(
            root,
            work_item_id=work_id,
            runtime_work_unit_id=str(bound["runtime_work_unit_id"]),
            roster=roster,
        )
        if gate_issues:
            issues.extend(
                f"verifier_gate:{work_id}: {issue}" for issue in gate_issues
            )
            rows[index] = _debt(row, "TYPED_VERIFIER_GATE_AUTHORITY_INVALID")
            continue
        try:
            # Replay the production verifier gate, including queue ownership,
            # roster/unit completion, exact PhaseIO output ownership, and all
            # current model semantic inputs.  The older receipt-only reader is
            # intentionally insufficient at this final boundary.
            from plamen_validators import _verifier_completion_authority_issues

            verifier_issues = _verifier_completion_authority_issues(
                root, work_id, min_bytes=100
            )
        except Exception as exc:
            verifier_issues = [
                "full verifier completion replay failed: "
                f"{type(exc).__name__}: {exc}"
            ]
        successor_original_sha256: str | None = None
        successor_path = (
            root / f"verify_{work_id}.mechanical_successor.receipt.json"
        )
        if successor_path.is_file():
            try:
                from mechanical_successor_receipts import MechanicalSuccessorReceipt

                successor_original_sha256 = MechanicalSuccessorReceipt.from_json(
                    successor_path.read_text(encoding="utf-8", errors="strict")
                ).original_output_sha256
            except Exception:
                successor_original_sha256 = None
        if verifier_issues:
            issues.extend(
                f"verifier_completion:{work_id}: {issue}"
                for issue in verifier_issues
            )
            rows[index] = _debt(
                row, "CURRENT_TYPED_VERIFIER_COMPLETION_AUTHORITY_INVALID"
            )
            continue
        verdict, receipt, original_output, current_output = _current_verifier_bytes(
            root, item
        )
        if (
            verdict is None
            or receipt is None
            or original_output is None
            or current_output is None
        ):
            rows[index] = _debt(row, "TYPED_VERIFIER_COMPLETION_INVALID")
            continue
        try:
            verifier_projection = _selected_verifier_phaseio_projection(
                root,
                work_item_id=work_id,
                queue_shard_id=str(bound["queue_shard_id"]),
                runtime_work_unit_id=str(bound["runtime_work_unit_id"]),
                successor_original_sha256=successor_original_sha256,
            )
            verifier_authority_digest = _digest(verifier_projection)
        except Exception as exc:
            issues.append(
                f"verifier_projection:{work_id}: {type(exc).__name__}: {exc}"
            )
            rows[index] = _debt(
                row, "SELECTED_VERIFIER_PHASEIO_PROJECTION_INVALID"
            )
            continue
        receipt_path = root / f"verify_{work_id}.receipt.json"
        receipt_sha = _sha256(receipt_path.read_bytes())
        if (
            completed.get("output_sha256") != _sha256(original_output)
            or completed.get("output_sha256") != receipt.output_sha256
            or completed.get("receipt_sha256") != receipt_sha
        ):
            rows[index] = _debt(row, "MANDATORY_TYPED_VERIFIER_DIGEST_MISMATCH")
            continue

        decision: Mapping[str, Any] = {}
        if closure_authority is not None:
            try:
                decision = resolve_central_negative_closure(
                    closure_authority,
                    work_item={
                        # Alias identity is deliberate. A finding- or group-
                        # scoped negative cannot close a sibling SOT row.
                        "candidate_negative_family_id": row["alias_id"],
                        "candidate_id": row["alias_id"],
                        "work_item_id": work_id,
                        "candidate_content_sha256": candidate[
                            "candidate_content_sha256"
                        ],
                    },
                    requested_effect=REFUTED_FULL,
                )
            except Exception:
                decision = {}
        central_authorized = _central_authorizes(
            decision,
            alias_id=row["alias_id"],
            work_item_id=work_id,
            candidate_content_sha256=candidate["candidate_content_sha256"],
        )
        common = {
            "verifier_output_sha256": _sha256(current_output),
            "verifier_receipt_sha256": receipt_sha,
            "verifier_authority_digest": verifier_authority_digest,
            "verifier_verdict": str(verdict),
        }
        if verdict == "CONFIRMED":
            if central_authorized:
                rows[index] = _set_row(
                    row,
                    **common,
                    central_resolution_digest=decision["resolution_digest"],
                    state=CONFLICTED_REVIEW,
                    retention="RETAIN",
                    terminal_negative_authority=False,
                    debt_reasons=["POSITIVE_VERDICT_CONFLICTS_WITH_NEGATIVE_AUTHORITY"],
                )
            else:
                rows[index] = _set_row(
                    row,
                    **common,
                    state=VERIFIED_CONFIRMED,
                    retention="RETAIN",
                    terminal_negative_authority=False,
                    debt_reasons=[],
                )
        elif verdict in _NEGATIVE_VERDICTS:
            if central_authorized:
                rows[index] = _set_row(
                    row,
                    **common,
                    central_resolution_digest=decision["resolution_digest"],
                    state=AUTHORIZED_NEGATIVE,
                    retention="AUTHORIZED_NEGATIVE",
                    terminal_negative_authority=True,
                    debt_reasons=[],
                )
            else:
                reasons = ["REFUTED_WITHOUT_TYPED_CENTRAL_NEGATIVE_CLOSURE"]
                if closure_error:
                    reasons.append(closure_error)
                for reason in decision.get("debt_reasons", []) if isinstance(decision, Mapping) else []:
                    reasons.append(str(reason))
                rows[index] = _set_row(
                    row,
                    **common,
                    state=NEGATIVE_PROPOSAL_RETAINED,
                    retention="RETAIN",
                    terminal_negative_authority=False,
                    debt_reasons=reasons,
                )
        else:
            reasons = []
            if verdict in {"DUPLICATE", "CONSOLIDATED"}:
                reasons.append("DUPLICATE_REQUIRES_EXACT_SURVIVOR_AUTHORITY")
            elif verdict != "CONTESTED":
                reasons.append("NONCONFIRMED_VERIFIER_RESULT_RETAINED")
            if central_authorized:
                reasons.append("NONNEGATIVE_VERDICT_CONFLICTS_WITH_NEGATIVE_AUTHORITY")
                state = CONFLICTED_REVIEW
            else:
                state = VERIFIED_CONTESTED
            rows[index] = _set_row(
                row,
                **common,
                central_resolution_digest=(
                    decision.get("resolution_digest") if central_authorized else None
                ),
                state=state,
                retention="RETAIN",
                terminal_negative_authority=False,
                debt_reasons=reasons,
            )

    rows.sort(key=lambda row: row["alias_id"])
    # Bindings for raw verifier outputs are row-local. The fixed input list
    # records the authorities whose exact denominators select those outputs.
    state_counts = {
        state: sum(row["state"] == state for row in rows)
        for state in sorted(STATES)
    }
    unresolved = {
        OPEN_REPAIR,
        VERIFY_PENDING,
        VERIFICATION_DEBT,
        NEGATIVE_PROPOSAL_RETAINED,
        CONFLICTED_REVIEW,
    }
    degraded = (
        bool(issues)
        or not denominator_complete
        or not rows
        or any(row["state"] in unresolved for row in rows)
    )
    unsigned = {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "source_authority_digest": source_digest,
        "source_stage": source_stage,
        "input_bindings": bindings,
        "denominator_complete": denominator_complete,
        "status": "DEGRADED_HUMAN_REVIEW" if degraded else "COMPLETE",
        "row_count": len(rows),
        "state_counts": state_counts,
        "terminal_negative_count": sum(
            row["terminal_negative_authority"] is True for row in rows
        ),
        "rows": rows,
        "issues": sorted(set(issues)),
    }
    return {**unsigned, "authority_digest": _digest(unsigned)}


def _escape(value: Any) -> str:
    text = "" if value is None else str(value)
    return (
        text.replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("\r", " ")
        .replace("\n", " ")
        .replace("`", "\\`")
    )


def render_security_obligation_lifecycle(authority: Mapping[str, Any]) -> str:
    """Render the exact human projection; JSON remains authoritative."""

    lines = [
        "# Security Obligation Lifecycle",
        "",
        f"**Schema**: `{_escape(authority.get('schema_version'))}`",
        f"**Status**: {_escape(authority.get('status'))}",
        f"**Run ID**: `{_escape(authority.get('run_id'))}`",
        f"**Exact alias denominator**: {int(authority.get('row_count') or 0)}",
        f"**Terminal negative authorities**: {int(authority.get('terminal_negative_count') or 0)}",
        "",
        "| Alias | Parent obligation | Source state | Candidate | Work item | Verifier verdict | Lifecycle state | Retention | Terminal negative | Debt |",
        "|---|---|---|---|---|---|---|---|---:|---|",
    ]
    for row in authority.get("rows") or []:
        if not isinstance(row, Mapping):
            continue
        lines.append(
            "| `{alias}` | `{parent}` | {source} | `{candidate}` | `{work}` | "
            "{verdict} | {state} | {retention} | {terminal} | {debt} |".format(
                alias=_escape(row.get("alias_id")),
                parent=_escape(row.get("parent_obligation_id")),
                source=_escape(row.get("source_state")),
                candidate=_escape(row.get("candidate_id")) or "-",
                work=_escape(row.get("assigned_work_item_id")) or "-",
                verdict=_escape(row.get("verifier_verdict")) or "-",
                state=_escape(row.get("state")),
                retention=_escape(row.get("retention")),
                terminal="yes" if row.get("terminal_negative_authority") is True else "no",
                debt=_escape(", ".join(str(item) for item in row.get("debt_reasons") or [])) or "-",
            )
        )
    issues = authority.get("issues") or []
    lines.extend(("", "## Authority issues", ""))
    if issues:
        lines.extend(f"- {_escape(issue)}" for issue in issues)
    else:
        lines.append("- None.")
    lines.extend(
        (
            "",
            "> Report delivery is not verification authority. Refuted rows remain retained unless the central typed broker authorizes the exact alias.",
            "",
        )
    )
    return "\n".join(lines)


def render_security_obligation_report_retention(
    authority: Mapping[str, Any],
) -> str:
    """Render the non-destructive report/human-review retention surface.

    The complete JSON remains the lifecycle authority. This projection omits
    only exact ``AUTHORIZED_NEGATIVE`` aliases; every other exact alias and all
    lifecycle debt remain actionable. It grants no finding, severity, proof,
    or negative authority.
    """

    retained = [
        row
        for row in authority.get("rows") or []
        if isinstance(row, Mapping)
        and row.get("state") != AUTHORIZED_NEGATIVE
    ]
    lines = [
        "# Security Obligation Report Retention",
        "",
        "This is a deterministic human-review retention projection, not a finding, severity, proof, or negative decision.",
        "",
        f"**Lifecycle status**: {_escape(authority.get('status'))}",
        f"**Retained exact aliases**: {len(retained)}",
        "",
    ]
    if retained:
        lines.extend((
            "| Exact alias | Relation | Symbol | State | Verifier verdict | Required retention | Debt |",
            "|---|---|---|---|---|---|---|",
        ))
        for row in retained:
            lines.append(
                "| `{alias}` | `{relation}` | `{symbol}` | {state} | {verdict} | HUMAN_REVIEW_OR_VERIFIED_BODY | {debt} |".format(
                    alias=_escape(row.get("alias_id")),
                    relation=_escape(row.get("relation_id")) or "-",
                    symbol=_escape(row.get("symbol")) or "-",
                    state=_escape(row.get("state")),
                    verdict=_escape(row.get("verifier_verdict")) or "-",
                    debt=_escape(
                        ", ".join(
                            str(item) for item in row.get("debt_reasons") or []
                        )
                    ) or "-",
                )
            )
    else:
        lines.append(
            "- No non-terminal-negative exact aliases require report retention."
        )
    issues = [str(issue) for issue in authority.get("issues") or []]
    lines.extend(("", "## Lifecycle debt", ""))
    if issues:
        lines.extend(f"- {_escape(issue)}" for issue in issues)
    else:
        lines.append("- None.")
    lines.extend((
        "",
        "> Exact centrally authorized negative aliases are deliberately absent from this actionable projection and remain auditable in the complete JSON lifecycle.",
        "",
    ))
    return "\n".join(lines)


def _validate_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _AUTHORITY_FIELDS:
        raise SecurityObligationLifecycleError(
            "lifecycle authority fields are not exact"
        )
    row_count = value.get("row_count")
    rows = value.get("rows")
    if (
        value.get("schema_version") != SCHEMA_VERSION
        or not isinstance(row_count, int)
        or isinstance(row_count, bool)
        or row_count < 0
        or not isinstance(rows, list)
        or row_count != len(rows)
        or value.get("status") not in {"COMPLETE", "DEGRADED_HUMAN_REVIEW"}
        or not isinstance(value.get("issues"), list)
        or value.get("issues") != sorted(set(value.get("issues") or []))
    ):
        raise SecurityObligationLifecycleError(
            "lifecycle authority header is invalid"
        )
    prior_alias = ""
    observed_counts = Counter()
    terminal = 0
    for raw in rows:
        if not isinstance(raw, Mapping) or set(raw) != _ROW_FIELDS:
            raise SecurityObligationLifecycleError(
                "lifecycle row fields are not exact"
            )
        alias = str(raw.get("alias_id") or "")
        if not _ALIAS.fullmatch(alias) or alias <= prior_alias:
            raise SecurityObligationLifecycleError(
                "lifecycle aliases are invalid, duplicated, or unsorted"
            )
        prior_alias = alias
        if raw.get("state") not in STATES:
            raise SecurityObligationLifecycleError("lifecycle row state is invalid")
        if not isinstance(raw.get("debt_reasons"), list) or raw.get(
            "debt_reasons"
        ) != sorted(set(raw.get("debt_reasons") or [])):
            raise SecurityObligationLifecycleError(
                "lifecycle row debt reasons are not canonical"
            )
        if raw.get("row_digest") != _row_digest(raw):
            raise SecurityObligationLifecycleError(
                "lifecycle row digest mismatch"
            )
        if (raw.get("state") == AUTHORIZED_NEGATIVE) != (
            raw.get("terminal_negative_authority") is True
        ):
            raise SecurityObligationLifecycleError(
                "terminal negative authority/state mismatch"
            )
        observed_counts[str(raw["state"])] += 1
        terminal += raw.get("terminal_negative_authority") is True
    expected_counts = {
        state: observed_counts[state] for state in sorted(STATES)
    }
    state_counts = value.get("state_counts")
    if (
        not isinstance(state_counts, Mapping)
        or set(state_counts) != set(expected_counts)
        or any(
            type(count) is not int or count < 0
            for count in state_counts.values()
        )
        or dict(state_counts) != expected_counts
    ):
        raise SecurityObligationLifecycleError("lifecycle state counts mismatch")
    terminal_negative_count = value.get("terminal_negative_count")
    if (
        type(terminal_negative_count) is not int
        or terminal_negative_count < 0
        or terminal_negative_count != terminal
    ):
        raise SecurityObligationLifecycleError(
            "lifecycle terminal-negative count mismatch"
        )
    if value.get("authority_digest") != _authority_digest(value):
        raise SecurityObligationLifecycleError(
            "lifecycle authority digest mismatch"
        )
    return dict(value)


def _atomic_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def write_security_obligation_lifecycle(
    scratchpad: str | Path,
    *,
    artifact_names: Mapping[str, str] | None = None,
    expected_input_sha256: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Atomically publish JSON authority followed by its exact projection."""

    root = Path(scratchpad)
    authority = build_security_obligation_lifecycle(
        root,
        artifact_names=artifact_names,
        expected_input_sha256=expected_input_sha256,
    )
    _validate_payload(authority)
    _atomic_text(
        root / AUTHORITY_FILE,
        json.dumps(authority, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )
    _atomic_text(
        root / PROJECTION_FILE,
        render_security_obligation_lifecycle(authority),
    )
    _atomic_text(
        root / REPORT_RETENTION_FILE,
        render_security_obligation_report_retention(authority),
    )
    return authority


def validate_security_obligation_lifecycle(
    scratchpad: str | Path,
    *,
    artifact_names: Mapping[str, str] | None = None,
    expected_input_sha256: Mapping[str, str] | None = None,
) -> list[str]:
    """Replay current inputs and compare both persisted lifecycle artifacts."""

    root = Path(scratchpad)
    issues: list[str] = []
    try:
        expected = build_security_obligation_lifecycle(
            root,
            artifact_names=artifact_names,
            expected_input_sha256=expected_input_sha256,
        )
        _validate_payload(expected)
    except Exception as exc:
        return [f"lifecycle re-derivation failed: {type(exc).__name__}: {exc}"]
    try:
        recorded, _raw = _strict_json(root / AUTHORITY_FILE)
        _validate_payload(recorded)
    except Exception as exc:
        issues.append(
            f"authority missing or invalid: {type(exc).__name__}: {exc}"
        )
    else:
        if recorded != expected:
            issues.append("authority differs from current lifecycle inputs")
    try:
        projection = (root / PROJECTION_FILE).read_text(
            encoding="utf-8", errors="strict"
        )
    except Exception as exc:
        issues.append(
            f"projection missing or invalid: {type(exc).__name__}: {exc}"
        )
    else:
        if projection != render_security_obligation_lifecycle(expected):
            issues.append("projection differs from typed lifecycle authority")
    try:
        retention = (root / REPORT_RETENTION_FILE).read_text(
            encoding="utf-8", errors="strict"
        )
    except Exception as exc:
        issues.append(
            f"report retention missing or invalid: {type(exc).__name__}: {exc}"
        )
    else:
        if retention != render_security_obligation_report_retention(expected):
            issues.append(
                "report retention differs from typed lifecycle authority"
            )
    return issues


__all__ = [
    "AUTHORIZED_NEGATIVE",
    "AUTHORITY_FILE",
    "CONFLICTED_REVIEW",
    "NEGATIVE_PROPOSAL_RETAINED",
    "OPEN_REPAIR",
    "PROJECTION_FILE",
    "REPORT_RETENTION_FILE",
    "SCHEMA_VERSION",
    "STATES",
    "VERIFICATION_DEBT",
    "VERIFIED_CONFIRMED",
    "VERIFIED_CONTESTED",
    "VERIFY_PENDING",
    "SecurityObligationLifecycleError",
    "build_security_obligation_lifecycle",
    "render_security_obligation_lifecycle",
    "render_security_obligation_report_retention",
    "security_obligation_lifecycle_input_artifacts",
    "validate_security_obligation_lifecycle",
    "write_security_obligation_lifecycle",
]
