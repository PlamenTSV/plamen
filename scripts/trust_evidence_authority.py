"""Typed, finding-bound authority for trusted-actor limitations.

Markdown trust labels are proposal signals only.  This module is the sole
mechanical discriminator for the two negative actions that a trusted-actor
claim can request: a severity reduction and a verification/PoC exemption.
An authorization is valid only when a distinct adjudicator binds an exact
finding and scope to current, hash-bound source and evidence artifacts in the
current run.  Every malformed, stale, missing, ambiguous, or self-adjudicated
state fails closed to retained upstream severity and retained verification.

The ledger is deliberately data-only.  It cannot delete a finding, change a
verdict, or supply proof-grade evidence; consumers may only ask whether one
exact trust limitation was independently authorized.

This release installs the fail-closed consumer boundary, not a new model
producer or cutover.  Unless an out-of-band independently governed authority
artifact is present, production behavior is retention plus review debt.  Any
future live producer must derive these records from the existing provider-bound
severity-adjudication/runtime evidence; a new self-authored model assertion is
not an acceptable authority source.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Mapping


TRUST_AUTHORITY_FILE = "trust_evidence_authority.json"
TRUST_AUTHORITY_SCHEMA = "plamen.trust_evidence_authority.v1"
TRUST_AUTHORITY_KIND = "INDEPENDENT_TRUST_ADJUDICATION"
TRUST_AUTHORITY_ROLE = "independent_trust_adjudicator"
AUTHORIZED_DECISION = "AUTHORIZED_TRUST_LIMITATION"
_DENIED_DECISIONS = frozenset({"REJECTED", "INSUFFICIENT_EVIDENCE"})
_EVIDENCE_KINDS = frozenset(
    {"USER_SCOPE_STATEMENT", "AUTHORITATIVE_PRIMARY_DOCUMENTATION"}
)
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_MAX_LEDGER_BYTES = 1_048_576
TRUST_DEBT_SCHEMA = "plamen.trust_evidence_debt.v2"
TRUST_DEBT_CONSUMERS = frozenset(
    {"severity_modifier", "verification_exemption"}
)
_TRUST_DEBT_FIELDS = frozenset(
    {
        "schema_version",
        "authority",
        "run_id",
        "provider_id",
        "finding_id",
        "consumer",
        "retained_severity",
        "resolution",
        "debt_digest",
    }
)
_TRUST_DEBT_RESOLUTION_FIELDS = frozenset(
    {
        "finding_id",
        "authorized",
        "state",
        "debts",
        "record_digest",
        "evidence_path",
        "evidence_sha256",
    }
)
_LEDGER_FIELDS = frozenset(
    {
        "schema_version",
        "authority",
        "run_id",
        "producer_role",
        "adjudicator_id",
        "records",
        "ledger_digest",
    }
)
_RECORD_FIELDS = frozenset(
    {
        "finding_id",
        "run_id",
        "source_artifact",
        "source_sha256",
        "source_provider_id",
        "actor",
        "capability",
        "action_scope",
        "asset_scope",
        "evidence_kind",
        "evidence_path",
        "evidence_sha256",
        "evidence_run_id",
        "decision",
        "adjudicator_id",
        "adjudication_basis_digest",
        "record_digest",
    }
)


def canonical_digest(value: Any) -> str:
    """Return the canonical SHA-256 used by all P0-H records."""
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _norm(value: object) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip()).casefold()


def _valid_scope_text(value: object) -> bool:
    if not isinstance(value, str):
        return False
    text = value.strip()
    return bool(text) and len(text) <= 512 and not any(
        ord(char) < 32 or ord(char) == 127 for char in text
    )


def _safe_relative(root: Path, value: object) -> Path | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    rel = Path(raw)
    if rel.is_absolute() or any(
        part in {"", ".", ".."} or ":" in part for part in rel.parts
    ):
        return None
    base = root.resolve()
    candidate = (base / rel).resolve()
    try:
        if os.path.commonpath((str(base), str(candidate))) != str(base):
            return None
    except ValueError:
        return None
    return candidate


def _relative_name(root: Path, value: str | Path) -> str | None:
    path = Path(value)
    try:
        if path.is_absolute():
            return path.resolve().relative_to(root.resolve()).as_posix()
        resolved = _safe_relative(root, path)
        if resolved is None:
            return None
        return resolved.relative_to(root.resolve()).as_posix()
    except (OSError, ValueError):
        return None


def current_run_id(scratchpad: str | Path) -> str:
    """Read the current run identity from the canonical checkpoint."""
    checkpoint = Path(scratchpad) / "_v2_checkpoint.json"
    try:
        payload = _strict_json_bytes(checkpoint.read_bytes())
    except (OSError, UnicodeError, ValueError, TypeError):
        return ""
    if not isinstance(payload, Mapping):
        return ""
    return str(payload.get("run_id") or "").strip()


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant {value!r}")


def _strict_json_bytes(raw: bytes) -> Any:
    if len(raw) > _MAX_LEDGER_BYTES:
        raise ValueError("trust authority JSON exceeds byte budget")
    return json.loads(
        raw.decode("utf-8", errors="strict"),
        object_pairs_hook=_strict_object,
        parse_constant=_reject_constant,
    )


def _atomic_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_file():
        try:
            if path.read_text(encoding="utf-8", errors="strict") == content:
                return
        except (OSError, UnicodeError):
            pass
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(content, encoding="utf-8", newline="\n")
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except OSError:
            pass


@dataclass(frozen=True)
class TrustEvidenceResolution:
    finding_id: str
    authorized: bool
    state: str
    debts: tuple[str, ...]
    record_digest: str = ""
    evidence_path: str = ""
    evidence_sha256: str = ""


def _resolution(
    finding_id: str,
    state: str,
    *debts: str,
    row: Mapping[str, Any] | None = None,
) -> TrustEvidenceResolution:
    return TrustEvidenceResolution(
        finding_id=finding_id,
        authorized=state == "AUTHORIZED",
        state=state,
        debts=tuple(dict.fromkeys(str(x) for x in debts if x)),
        record_digest=str((row or {}).get("record_digest") or ""),
        evidence_path=str((row or {}).get("evidence_path") or ""),
        evidence_sha256=str((row or {}).get("evidence_sha256") or ""),
    )


def _load_and_validate_ledger(
    scratchpad: Path,
    *,
    require_provider: bool = False,
) -> tuple[dict[str, Any] | None, tuple[str, ...]]:
    path = scratchpad / TRUST_AUTHORITY_FILE
    try:
        payload = _strict_json_bytes(path.read_bytes())
    except FileNotFoundError:
        return None, ("TRUST_AUTHORITY_MISSING",)
    except (OSError, UnicodeError, ValueError, TypeError):
        return None, ("TRUST_LEDGER_TAMPERED",)
    if not isinstance(payload, dict) or set(payload) != _LEDGER_FIELDS:
        return None, ("TRUST_LEDGER_TAMPERED",)
    unsigned = {k: v for k, v in payload.items() if k != "ledger_digest"}
    try:
        digest_valid = payload.get("ledger_digest") == canonical_digest(unsigned)
    except (TypeError, ValueError, UnicodeError):
        digest_valid = False
    if not digest_valid:
        return None, ("TRUST_LEDGER_TAMPERED",)
    if (
        payload.get("schema_version") != TRUST_AUTHORITY_SCHEMA
        or payload.get("authority") != TRUST_AUTHORITY_KIND
        or payload.get("producer_role") != TRUST_AUTHORITY_ROLE
    ):
        return None, ("TRUST_LEDGER_TAMPERED",)
    adjudicator = str(payload.get("adjudicator_id") or "").strip()
    if not _ID_RE.fullmatch(adjudicator):
        return None, ("TRUST_LEDGER_TAMPERED",)
    records = payload.get("records")
    if not isinstance(records, list):
        return None, ("TRUST_LEDGER_TAMPERED",)
    for row in records:
        if not isinstance(row, dict) or set(row) != _RECORD_FIELDS:
            return None, ("TRUST_LEDGER_TAMPERED",)
        unsigned_row = {k: v for k, v in row.items() if k != "record_digest"}
        try:
            row_digest_valid = row.get("record_digest") == canonical_digest(
                unsigned_row
            )
        except (TypeError, ValueError, UnicodeError):
            row_digest_valid = False
        if not row_digest_valid:
            return None, ("TRUST_LEDGER_TAMPERED",)
        if str(row.get("adjudicator_id") or "") != adjudicator:
            return None, ("TRUST_LEDGER_TAMPERED",)
        text_fields = (
            "finding_id",
            "run_id",
            "source_artifact",
            "source_provider_id",
            "actor",
            "capability",
            "action_scope",
            "asset_scope",
            "evidence_kind",
            "evidence_path",
            "evidence_run_id",
            "decision",
            "adjudicator_id",
        )
        if any(
            not isinstance(row.get(key), str) or not str(row.get(key)).strip()
            for key in text_fields
        ):
            return None, ("TRUST_LEDGER_TAMPERED",)
        if any(
            not _valid_scope_text(row.get(key))
            for key in ("actor", "capability", "action_scope", "asset_scope")
        ):
            return None, ("TRUST_LEDGER_TAMPERED",)
        if any(
            not _DIGEST_RE.fullmatch(str(row.get(key) or ""))
            for key in (
                "source_sha256",
                "evidence_sha256",
                "adjudication_basis_digest",
            )
        ):
            return None, ("TRUST_LEDGER_TAMPERED",)
        if (
            _safe_relative(scratchpad, row.get("source_artifact")) is None
            or _safe_relative(scratchpad, row.get("evidence_path")) is None
            or row.get("evidence_kind") not in _EVIDENCE_KINDS
            or row.get("decision")
            not in ({AUTHORIZED_DECISION} | _DENIED_DECISIONS)
        ):
            return None, ("TRUST_LEDGER_TAMPERED",)

    # Once the deterministic live provider has installed its receipt, it is a
    # consume-side ownership sentinel.  Re-derivation must still match before
    # any row can authorize a negative action.  Legacy/out-of-tree governed
    # ledgers remain supported when no provider receipt exists; the driver
    # cutover creates this receipt before claiming provider ownership.
    provider_receipt = scratchpad / "trust_evidence_provider_receipt.json"
    if require_provider and not provider_receipt.is_file():
        return None, ("TRUST_PROVIDER_REQUIRED",)
    if provider_receipt.is_file():
        try:
            from trust_evidence_provider import (
                validate_trust_evidence_provider_state,
            )

            if validate_trust_evidence_provider_state(scratchpad):
                return None, ("TRUST_LEDGER_TAMPERED",)
        except Exception:
            return None, ("TRUST_LEDGER_TAMPERED",)
    return payload, ()


def resolve_trust_evidence(
    scratchpad: str | Path,
    *,
    finding_id: str,
    source_artifact: str | Path,
    actor: str,
    capability: str,
    action_scope: str,
    asset_scope: str,
    run_id: str | None = None,
    require_provider: bool = True,
) -> TrustEvidenceResolution:
    """Resolve one exact trust limitation against current artifacts.

    Scope strings are selectors only: they cannot grant authority.  They must
    exactly select one independently adjudicated record whose source, evidence,
    finding identity, and current run all remain intact.
    """
    root = Path(scratchpad)
    fid = str(finding_id or "").strip()
    requested_run = str(run_id or current_run_id(root)).strip()
    current_run = current_run_id(root)
    requested_source = _relative_name(root, source_artifact)
    scope = {
        "actor": _norm(actor),
        "capability": _norm(capability),
        "action_scope": _norm(action_scope),
        "asset_scope": _norm(asset_scope),
    }
    raw_scope = (actor, capability, action_scope, asset_scope)
    if (
        not fid
        or not requested_source
        or not all(_valid_scope_text(value) for value in raw_scope)
        or not all(scope.values())
    ):
        return _resolution(fid, "UNRESOLVED", "TRUST_SCOPE_INCOMPLETE")
    if not current_run or not requested_run or requested_run != current_run:
        return _resolution(fid, "STALE", "TRUST_RUN_STALE")

    payload, ledger_debts = _load_and_validate_ledger(
        root, require_provider=require_provider
    )
    if payload is None:
        return _resolution(fid, "UNRESOLVED", *ledger_debts)
    if str(payload.get("run_id") or "") != current_run:
        return _resolution(fid, "STALE", "TRUST_RUN_STALE")

    all_rows = payload.get("records", [])
    finding_rows = [
        row for row in all_rows
        if str(row.get("finding_id") or "").strip() == fid
    ]
    if not finding_rows:
        return _resolution(fid, "UNRESOLVED", "TRUST_FINDING_UNBOUND")
    scope_rows = [
        row for row in finding_rows
        if all(_norm(row.get(key)) == value for key, value in scope.items())
    ]
    if not scope_rows:
        return _resolution(fid, "UNRESOLVED", "TRUST_SCOPE_MISMATCH")
    if len(scope_rows) != 1:
        return _resolution(fid, "AMBIGUOUS", "TRUST_AUTHORITY_AMBIGUOUS")
    row = scope_rows[0]

    if str(row.get("run_id") or "") != current_run or (
        str(row.get("evidence_run_id") or "") != current_run
    ):
        return _resolution(fid, "STALE", "TRUST_RUN_STALE", row=row)
    if str(row.get("source_artifact") or "").replace("\\", "/") != requested_source:
        return _resolution(fid, "UNRESOLVED", "TRUST_SOURCE_MISMATCH", row=row)
    source_path = _safe_relative(root, requested_source)
    if source_path is None or not source_path.is_file():
        return _resolution(fid, "STALE", "TRUST_SOURCE_STALE", row=row)
    try:
        if row.get("source_sha256") != _sha256(source_path):
            return _resolution(fid, "STALE", "TRUST_SOURCE_STALE", row=row)
    except OSError:
        return _resolution(fid, "STALE", "TRUST_SOURCE_STALE", row=row)

    evidence_path = _safe_relative(root, row.get("evidence_path"))
    if row.get("evidence_kind") not in _EVIDENCE_KINDS:
        return _resolution(fid, "UNRESOLVED", "TRUST_EVIDENCE_KIND_INVALID", row=row)
    if evidence_path is None or not evidence_path.is_file() or evidence_path == source_path:
        return _resolution(fid, "STALE", "TRUST_EVIDENCE_STALE", row=row)
    try:
        if row.get("evidence_sha256") != _sha256(evidence_path):
            return _resolution(fid, "STALE", "TRUST_EVIDENCE_STALE", row=row)
    except OSError:
        return _resolution(fid, "STALE", "TRUST_EVIDENCE_STALE", row=row)

    adjudicator = str(row.get("adjudicator_id") or "").strip()
    source_provider = str(row.get("source_provider_id") or "").strip()
    if (
        not _ID_RE.fullmatch(adjudicator)
        or not _ID_RE.fullmatch(source_provider)
        or adjudicator.casefold() == source_provider.casefold()
    ):
        return _resolution(
            fid,
            "UNRESOLVED",
            "TRUST_ADJUDICATOR_NOT_INDEPENDENT",
            row=row,
        )
    basis = str(row.get("adjudication_basis_digest") or "")
    if not _DIGEST_RE.fullmatch(basis):
        return _resolution(fid, "UNRESOLVED", "TRUST_ADJUDICATION_UNBOUND", row=row)
    decision = str(row.get("decision") or "").strip()
    if decision != AUTHORIZED_DECISION:
        debt = (
            "TRUST_NOT_AUTHORIZED"
            if decision in _DENIED_DECISIONS
            else "TRUST_ADJUDICATION_UNBOUND"
        )
        return _resolution(fid, "RETAIN", debt, row=row)
    return _resolution(fid, "AUTHORIZED", row=row)


def resolve_legacy_trust_evidence(
    scratchpad: str | Path,
    *,
    finding_id: str,
    source_artifact: str | Path,
    actor: str,
    capability: str,
    action_scope: str,
    asset_scope: str,
    run_id: str | None = None,
) -> TrustEvidenceResolution:
    """Explicit isolated opt-out for governed out-of-tree legacy ledgers.

    Driver/runtime consumers must use :func:`resolve_trust_evidence`, whose
    provider-required default prevents a future caller from accidentally
    omitting the P0-H application policy.
    """

    return resolve_trust_evidence(
        scratchpad,
        finding_id=finding_id,
        source_artifact=source_artifact,
        actor=actor,
        capability=capability,
        action_scope=action_scope,
        asset_scope=asset_scope,
        run_id=run_id,
        require_provider=False,
    )


def record_trust_review_debt(
    scratchpad: str | Path,
    *,
    resolution: TrustEvidenceResolution,
    consumer: str,
    retained_severity: str = "",
) -> Path:
    """Write an idempotent, finding-local human-review debt projection.

    A valid authorization removes an earlier debt.  No debt artifact has
    severity, verdict, report-disposition, or verification-exemption authority.
    """
    root = Path(scratchpad)
    safe_fid = re.sub(r"[^A-Za-z0-9_.-]+", "_", resolution.finding_id or "unknown")
    normalized_consumer = str(consumer or "").strip()
    if normalized_consumer not in TRUST_DEBT_CONSUMERS:
        raise ValueError("trust evidence debt consumer is not in the closed set")
    safe_consumer = re.sub(r"[^A-Za-z0-9_.-]+", "_", normalized_consumer)
    path = root / f"trust_evidence_debt_{safe_fid}_{safe_consumer}.json"
    markdown = root / f"trust_evidence_debt_{safe_fid}_{safe_consumer}.md"
    if resolution.authorized:
        for stale in (path, markdown):
            try:
                stale.unlink()
            except OSError:
                pass
        return path
    run_id = current_run_id(root)
    provider_id = ""
    provider_receipt_path = root / "trust_evidence_provider_receipt.json"
    if provider_receipt_path.is_file():
        try:
            provider_receipt = _strict_json_bytes(provider_receipt_path.read_bytes())
        except (OSError, UnicodeError, ValueError, TypeError):
            provider_receipt = {}
        if (
            isinstance(provider_receipt, Mapping)
            and str(provider_receipt.get("run_id") or "").strip() == run_id
        ):
            candidate_provider = str(
                provider_receipt.get("provider_id") or ""
            ).strip()
            if _ID_RE.fullmatch(candidate_provider):
                provider_id = candidate_provider
    unsigned = {
        "schema_version": TRUST_DEBT_SCHEMA,
        "authority": "HUMAN_REVIEW_ONLY",
        "run_id": run_id,
        "provider_id": provider_id,
        "finding_id": resolution.finding_id,
        "consumer": normalized_consumer,
        "retained_severity": str(retained_severity or ""),
        "resolution": asdict(resolution),
    }
    payload = {**unsigned, "debt_digest": canonical_digest(unsigned)}
    rendered = json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    try:
        _atomic_text(path, rendered)
    except OSError:
        # Haltless contract: a limitation projection failure never grants the
        # requested negative action and must not stop the audit.
        return path
    debt_text = ", ".join(resolution.debts) or resolution.state
    human = (
        "# Trust Evidence Review Debt\n\n"
        f"- Finding ID: `{resolution.finding_id}`\n"
        f"- Consumer: `{consumer}`\n"
        f"- Retained severity: `{retained_severity or 'unchanged'}`\n"
        f"- Debt: `{debt_text}`\n\n"
        "This is a human-review limitation only. It cannot lower severity, "
        "remove verification work, or change a finding disposition.\n"
    )
    try:
        _atomic_text(markdown, human)
    except OSError:
        pass
    return path


def read_trust_review_debt(
    path: str | Path,
    *,
    expected_run_id: str | None = None,
) -> dict[str, Any]:
    """Strictly replay one human-review-only trust debt projection.

    The sidecar is visibility evidence only.  Exact schema/digest/filename
    checks prevent a malformed or renamed file from silently entering the
    assurance denominator, and ``authorized`` must remain false.
    """

    debt_path = Path(path)
    payload = _strict_json_bytes(debt_path.read_bytes())
    if not isinstance(payload, dict) or set(payload) != _TRUST_DEBT_FIELDS:
        raise ValueError("trust evidence debt schema fields are invalid")
    unsigned = {key: value for key, value in payload.items() if key != "debt_digest"}
    if (
        payload.get("schema_version") != TRUST_DEBT_SCHEMA
        or payload.get("authority") != "HUMAN_REVIEW_ONLY"
        or payload.get("debt_digest") != canonical_digest(unsigned)
    ):
        raise ValueError("trust evidence debt authority or digest is invalid")
    finding_id = str(payload.get("finding_id") or "").strip()
    consumer = str(payload.get("consumer") or "").strip()
    run_id = str(payload.get("run_id") or "").strip()
    provider_id = str(payload.get("provider_id") or "").strip()
    if (
        not _ID_RE.fullmatch(finding_id)
        or consumer not in TRUST_DEBT_CONSUMERS
        or not run_id
        or (provider_id and not _ID_RE.fullmatch(provider_id))
    ):
        raise ValueError("trust evidence debt identity is invalid")
    if expected_run_id is not None and run_id != str(expected_run_id or "").strip():
        raise ValueError("trust evidence debt run_id is stale")
    if provider_id:
        receipt_path = debt_path.parent / "trust_evidence_provider_receipt.json"
        try:
            receipt = _strict_json_bytes(receipt_path.read_bytes())
        except (OSError, UnicodeError, ValueError, TypeError) as exc:
            raise ValueError("trust evidence debt provider receipt is unavailable") from exc
        if (
            not isinstance(receipt, Mapping)
            or str(receipt.get("run_id") or "").strip() != run_id
            or str(receipt.get("provider_id") or "").strip() != provider_id
        ):
            raise ValueError("trust evidence debt provider binding is stale")
    expected_name = (
        f"trust_evidence_debt_"
        f"{re.sub(r'[^A-Za-z0-9_.-]+', '_', finding_id)}_"
        f"{re.sub(r'[^A-Za-z0-9_.-]+', '_', consumer)}.json"
    )
    if debt_path.name != expected_name:
        raise ValueError("trust evidence debt filename/identity mismatch")
    resolution = payload.get("resolution")
    if (
        not isinstance(resolution, dict)
        or set(resolution) != _TRUST_DEBT_RESOLUTION_FIELDS
        or resolution.get("finding_id") != finding_id
        or resolution.get("authorized") is not False
        or not isinstance(resolution.get("debts"), list)
        or not all(
            isinstance(code, str) and code.strip()
            for code in resolution.get("debts") or []
        )
        or not str(resolution.get("state") or "").strip()
    ):
        raise ValueError("trust evidence debt resolution is invalid")
    if not isinstance(payload.get("retained_severity"), str):
        raise ValueError("trust evidence debt retained severity is invalid")
    return payload


__all__ = [
    "AUTHORIZED_DECISION",
    "TRUST_AUTHORITY_FILE",
    "TRUST_AUTHORITY_SCHEMA",
    "TRUST_DEBT_SCHEMA",
    "TRUST_DEBT_CONSUMERS",
    "TrustEvidenceResolution",
    "canonical_digest",
    "current_run_id",
    "record_trust_review_debt",
    "read_trust_review_debt",
    "resolve_trust_evidence",
    "resolve_legacy_trust_evidence",
]
