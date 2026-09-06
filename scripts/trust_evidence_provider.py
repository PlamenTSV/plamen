"""Fail-closed live provider for the P0-H trust-evidence authority boundary.

The trust consumer requires substantially more than a model's
``FULLY_TRUSTED_ACTOR`` modifier: exact actor/capability/action/asset scope, an
exact user-scope or authoritative-primary-document artifact, and a distinct
adjudicator that resolved that exact trust premise.  The current typed severity
transaction does not persist those facts.  In particular, its generic evidence
receipt contains a content digest but neither the provider record/path nor an
evidence kind, and its adjudication proposal resolves severity axes rather than
the trust modifier itself.

This provider therefore performs a useful, deliberately one-sided cutover:

* validate and enumerate current typed severity trust proposals;
* never inspect verifier prose to reconstruct missing trust facts;
* emit an exact empty ``trust_evidence_authority.json`` plus typed per-finding
  debt explaining why no negative action is authorized;
* bind every input and output so resume/tamper cannot silently turn debt into
  authority.

It is not a placeholder authorization mechanism.  ``negative_authority`` is
hard-coded to ``NONE`` and this version has no code path that emits a trust
record.  A later provider may do so only after the upstream provider schemas
persist the missing exact scope and source-provenance records.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Mapping

from severity_decision_ledger import load_severity_decision_ledger
from trust_evidence_authority import (
    TRUST_AUTHORITY_FILE,
    TRUST_AUTHORITY_KIND,
    TRUST_AUTHORITY_ROLE,
    TRUST_AUTHORITY_SCHEMA,
    canonical_digest,
    current_run_id,
)


PROVIDER_RECEIPT_FILE = "trust_evidence_provider_receipt.json"
PROVIDER_RECEIPT_SCHEMA = "plamen.trust_evidence_provider_receipt.v1"
PROVIDER_ROLE = "deterministic_trust_no_authority_reconciler"
PROVIDER_ID = "plamen-trust-provider-no-authority"
NEGATIVE_AUTHORITY = "NONE"
_LEDGER_NAME = "severity_decision_ledger.shadow.json"
_DECISION_SUFFIX = ".severity_decision.json"
_MAX_JSON_BYTES = 8_388_608
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Informational")


class TrustEvidenceProviderError(ValueError):
    """A provider input or persisted projection is malformed."""


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise TrustEvidenceProviderError(f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    raise TrustEvidenceProviderError(f"invalid JSON constant {value!r}")


def _strict_json(path: Path) -> Any:
    raw = path.read_bytes()
    if len(raw) > _MAX_JSON_BYTES:
        raise TrustEvidenceProviderError(f"{path.name} exceeds byte budget")
    try:
        return json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise TrustEvidenceProviderError(
            f"{path.name} is not strict JSON: {exc}"
        ) from exc


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _input_binding(root: Path, path: Path, kind: str) -> dict[str, str]:
    relative = path.resolve().relative_to(root.resolve()).as_posix()
    return {"path": relative, "sha256": _sha256(path), "kind": kind}


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    content = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        indent=2,
    ) + "\n"
    if path.is_file():
        try:
            if path.read_text(encoding="utf-8", errors="strict") == content:
                return
        except (OSError, UnicodeError):
            pass
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(content, encoding="utf-8", newline="\n")
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except OSError:
            pass


def _empty_authority(run_id: str) -> dict[str, Any]:
    unsigned = {
        "schema_version": TRUST_AUTHORITY_SCHEMA,
        "authority": TRUST_AUTHORITY_KIND,
        "run_id": run_id,
        "producer_role": TRUST_AUTHORITY_ROLE,
        "adjudicator_id": PROVIDER_ID,
        "records": [],
    }
    return {**unsigned, "ledger_digest": canonical_digest(unsigned)}


def _candidate_debt(
    decision: Mapping[str, Any],
    *,
    debt_codes: list[str],
    adjudication_state: str,
) -> dict[str, Any]:
    assessment = decision.get("assessment") or {}
    modifier = next(
        (
            row
            for row in assessment.get("modifiers") or []
            if isinstance(row, Mapping)
            and row.get("kind") == "FULLY_TRUSTED_ACTOR"
            and row.get("applies") is True
        ),
        {},
    )
    unsigned = {
        "finding_id": str(decision.get("candidate_id") or ""),
        "source_run_id": str(decision.get("run_id") or ""),
        "source_decision_digest": str(decision.get("decision_digest") or ""),
        "source_receipt_digest": str(
            decision.get("source_receipt_digest") or ""
        ),
        "modifier_evidence_ids": sorted(
            str(item) for item in modifier.get("evidence_ids") or []
        ),
        "modifier_proof_scope": str(modifier.get("proof_scope") or ""),
        "adjudication_state": adjudication_state,
        "debt_codes": sorted(set(debt_codes)),
        "retention_policy": "RETAIN_UPSTREAM_SEVERITY_AND_VERIFICATION",
    }
    return {**unsigned, "debt_digest": canonical_digest(unsigned)}


def _has_trust_modifier(decision: Mapping[str, Any]) -> bool:
    assessment = decision.get("assessment")
    if not isinstance(assessment, Mapping):
        return False
    return any(
        isinstance(row, Mapping)
        and row.get("kind") == "FULLY_TRUSTED_ACTOR"
        and row.get("applies") is True
        for row in assessment.get("modifiers") or []
    )


def _provider_adjudication_state(root: Path, decision: Mapping[str, Any]) -> str:
    """Classify provider ownership without deriving facts from model prose.

    The existing runtime validator replays the process-owning adjudicator
    worker receipt and exact proposal bytes.  It may hash verifier bytes while
    validating the upstream transaction, but this provider never parses those
    bytes or uses them as trust evidence.
    """

    history = decision.get("adjudication_history")
    if not isinstance(history, list) or not history:
        return "MISSING"
    if len(history) != 1:
        return "CONFLICTING"
    try:
        from severity_runtime import _validate_adjudication_receipt

        receipt = _validate_adjudication_receipt(root, decision)
        if receipt is None:
            return "MISSING"
    except Exception:
        return "PROVIDER_INVALID"
    return "PROVIDER_VALID_BUT_INSUFFICIENT"


def _load_valid_severity_state(
    root: Path,
    run_id: str,
) -> tuple[list[dict[str, Any]], list[dict[str, str]], list[str]]:
    """Load one exact aggregate/sidecar state or return fail-closed debt."""

    bindings: list[dict[str, str]] = []
    global_debts: list[str] = []
    ledger_path = root / _LEDGER_NAME
    if not ledger_path.is_file():
        return [], bindings, ["TRUST_SEVERITY_LEDGER_MISSING"]
    bindings.append(_input_binding(root, ledger_path, "SEVERITY_LEDGER"))
    try:
        raw = _strict_json(ledger_path)
        if not isinstance(raw, Mapping):
            raise TrustEvidenceProviderError("severity ledger is not an object")
        raw_rows = raw.get("decisions")
        if not isinstance(raw_rows, list):
            raise TrustEvidenceProviderError("severity decisions are unavailable")
        raw_run = str(raw.get("run_id") or "")
        if raw_run != run_id:
            return [], bindings, ["TRUST_SEVERITY_RUN_STALE"]
        source_digests: dict[str, str] = {}
        for row in raw_rows:
            if not isinstance(row, Mapping):
                raise TrustEvidenceProviderError("severity decision row malformed")
            candidate = str(row.get("candidate_id") or "")
            source_digest = str(row.get("source_receipt_digest") or "")
            if (
                not candidate
                or candidate in source_digests
                or not _HEX64_RE.fullmatch(source_digest)
            ):
                raise TrustEvidenceProviderError(
                    "severity candidate/source identity malformed"
                )
            source_digests[candidate] = source_digest
        ledger = load_severity_decision_ledger(
            ledger_path,
            expected_run_id=run_id,
            expected_source_receipt_digests=source_digests,
        )
        decisions = [dict(row) for row in ledger["decisions"]]
        expected_names = {
            f"verify_{row['candidate_id']}{_DECISION_SUFFIX}" for row in decisions
        }
        actual_paths = sorted(root.glob(f"verify_*{_DECISION_SUFFIX}"))
        actual_names = {path.name for path in actual_paths}
        if actual_names != expected_names:
            raise TrustEvidenceProviderError(
                "severity aggregate/sidecar denominator mismatch"
            )
        by_id = {str(row["candidate_id"]): row for row in decisions}
        for path in actual_paths:
            bindings.append(_input_binding(root, path, "SEVERITY_DECISION"))
            candidate = path.name[
                len("verify_") : -len(_DECISION_SUFFIX)
            ]
            if _strict_json(path) != by_id.get(candidate):
                raise TrustEvidenceProviderError(
                    f"{candidate} severity aggregate/sidecar mismatch"
                )
        return decisions, bindings, global_debts
    except Exception:
        # The raw invalid state is an input, but no row from it becomes even a
        # candidate-level trust fact.  This distinction prevents a malformed
        # severity artifact from manufacturing identities or scope.
        for path in sorted(root.glob(f"verify_*{_DECISION_SUFFIX}")):
            if path.is_file() and all(
                row["path"] != path.name for row in bindings
            ):
                try:
                    bindings.append(
                        _input_binding(root, path, "INVALID_SEVERITY_DECISION")
                    )
                except OSError:
                    pass
        return [], bindings, ["TRUST_SEVERITY_STATE_INVALID"]


def build_trust_evidence_provider_state(
    scratchpad: str | Path,
    *,
    run_id: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Derive the exact fail-closed authority ledger and provider receipt."""

    root = Path(scratchpad)
    # ``_v2_checkpoint.json`` is the live phase-progress journal.  Its run_id is
    # consulted on every derivation, but its whole-file digest is deliberately
    # not an immutable provider input: every later phase commit changes those
    # bytes and would otherwise stale a valid same-run no-authority sentinel.
    # A changed run_id still fails closed through the comparison below.
    current = current_run_id(root)
    requested = str(run_id or current).strip()
    effective_run = requested or "UNBOUND-RUN"
    if not current or requested != current:
        decisions: list[dict[str, Any]] = []
        bindings: list[dict[str, str]] = []
        global_debts = ["TRUST_PROVIDER_RUN_UNBOUND"]
    else:
        decisions, bindings, global_debts = _load_valid_severity_state(
            root, requested
        )

    candidate_debts: list[dict[str, Any]] = []
    adjudication_inputs_needed = False
    for decision in decisions:
        if not _has_trust_modifier(decision):
            continue
        state = _provider_adjudication_state(root, decision)
        if decision.get("adjudication_history"):
            adjudication_inputs_needed = True
        debt_codes = [
            "TRUST_EXACT_SCOPE_AUTHORITY_UNAVAILABLE",
            "TRUST_EVIDENCE_PROVENANCE_UNAVAILABLE",
            "TRUST_MODIFIER_RESOLUTION_UNAVAILABLE",
        ]
        if state == "MISSING":
            debt_codes.append("TRUST_INDEPENDENT_ADJUDICATION_MISSING")
        elif state in {"PROVIDER_INVALID", "CONFLICTING"}:
            debt_codes.append("TRUST_ADJUDICATION_PROVIDER_RECEIPT_INVALID")
        candidate_debts.append(
            _candidate_debt(
                decision,
                debt_codes=debt_codes,
                adjudication_state=state,
            )
        )

    if adjudication_inputs_needed:
        # The runtime replay may consult any of these exact transaction files.
        # Bind the complete bounded family instead of pretending the standalone
        # receipt is sufficient provenance.  None of these files is parsed for
        # trust-scope facts by this provider.
        bound_paths = {row["path"] for row in bindings}
        patterns = (
            "severity_adjudication_*.json",
            "severity_adjudication_*.md",
            "verify_*.severity_adjudication_proposal.json",
            "verify_*.severity_adjudication_receipt.json",
        )
        for pattern in patterns:
            for path in sorted(root.glob(pattern)):
                if not path.is_file() or path.name in bound_paths:
                    continue
                try:
                    bindings.append(
                        _input_binding(root, path, "ADJUDICATION_TRANSACTION")
                    )
                    bound_paths.add(path.name)
                except OSError:
                    global_debts.append("TRUST_ADJUDICATION_INPUT_UNREADABLE")

    bindings = sorted(bindings, key=lambda row: (row["path"], row["kind"]))
    candidate_debts.sort(key=lambda row: row["finding_id"])
    ledger = _empty_authority(effective_run)
    unsigned_receipt = {
        "schema_version": PROVIDER_RECEIPT_SCHEMA,
        "run_id": effective_run,
        "provider_role": PROVIDER_ROLE,
        "provider_id": PROVIDER_ID,
        "negative_authority": NEGATIVE_AUTHORITY,
        "authority_file": TRUST_AUTHORITY_FILE,
        "authority_ledger_digest": ledger["ledger_digest"],
        "authority_record_count": 0,
        "input_bindings": bindings,
        "candidate_debts": candidate_debts,
        "global_debts": sorted(set(global_debts)),
    }
    receipt = {
        **unsigned_receipt,
        "receipt_digest": canonical_digest(unsigned_receipt),
    }
    return ledger, receipt


def write_trust_evidence_provider_state(
    scratchpad: str | Path,
    *,
    run_id: str | None = None,
    planned_state: tuple[Mapping[str, Any], Mapping[str, Any]] | None = None,
) -> tuple[Path, Path]:
    """Persist an exact precomputed provider projection idempotently.

    The optional plan is used by the PhaseIO boundary after its input
    denominator is armed.  Re-deriving between prebind and write would create
    a TOCTOU window in which the bytes no longer correspond to the receipt.
    """

    root = Path(scratchpad)
    if planned_state is None:
        ledger, receipt = build_trust_evidence_provider_state(root, run_id=run_id)
    else:
        ledger, receipt = (dict(planned_state[0]), dict(planned_state[1]))
    ledger_path = root / TRUST_AUTHORITY_FILE
    receipt_path = root / PROVIDER_RECEIPT_FILE
    # Write the consume-side ownership sentinel first.  If either atomic write
    # fails, a driver consumer sees either an invalid receipt/ledger pair or a
    # missing provider receipt; both states deny negative authority.  Writing
    # the ledger first would leave a forged legacy ledger consumable when the
    # receipt write fails.
    _atomic_json(receipt_path, receipt)
    _atomic_json(ledger_path, ledger)
    return ledger_path, receipt_path


def constrain_trust_sensitive_report_projection(
    scratchpad: str | Path,
    *,
    decision: Mapping[str, Any],
    projection: Mapping[str, Any],
    run_id: str | None = None,
) -> dict[str, Any]:
    """Retain upstream severity for an unauthorized trust-based reduction.

    A report-authoritative severity transaction is not, by itself, authority
    for the distinct ``FULLY_TRUSTED_ACTOR`` premise.  Until the live provider
    can emit an exact independently governed trust record, its valid state is
    deliberately zero-authority.  Any applied trust modifier accompanying a
    lower projection therefore remains a terminal challenge and projects the
    upstream retention tier.  Non-trust decisions and non-negative changes are
    untouched.
    """

    result = dict(projection)
    assessment = decision.get("assessment")
    modifiers = (
        assessment.get("modifiers")
        if isinstance(assessment, Mapping)
        else []
    )
    trust_applied = any(
        isinstance(row, Mapping)
        and row.get("kind") == "FULLY_TRUSTED_ACTOR"
        and row.get("applies") is True
        for row in (modifiers or [])
    )
    retention = str(decision.get("retention_severity") or "")
    projected = str(result.get("severity") or "")
    if (
        not trust_applied
        or retention not in _SEVERITY_ORDER
        or projected not in _SEVERITY_ORDER
        or _SEVERITY_ORDER.index(projected) <= _SEVERITY_ORDER.index(retention)
    ):
        return result

    root = Path(scratchpad)
    effective_run = str(run_id or current_run_id(root)).strip()
    provider_issues = validate_trust_evidence_provider_state(
        root, run_id=effective_run
    )
    negative_authority = ""
    if not provider_issues:
        try:
            receipt = _strict_json(root / PROVIDER_RECEIPT_FILE)
            negative_authority = str(receipt.get("negative_authority") or "")
        except Exception:
            provider_issues = ("trust provider receipt is unreadable",)

    # The v1 live provider has no authorization code path.  Requiring an exact
    # non-NONE capability here makes a future schema expansion deliberate; a
    # prose label, generic severity adjudication, missing receipt, or tampered
    # provider state can never satisfy this branch.
    if negative_authority == NEGATIVE_AUTHORITY or provider_issues:
        result["severity"] = retention
        result["severity_status"] = "UNRESOLVED_TRUST_AUTHORITY"
        result["trust_authority_state"] = (
            "PROVIDER_INVALID" if provider_issues else "NO_NEGATIVE_AUTHORITY"
        )
    return result


def ensure_trust_evidence_provider_state(
    scratchpad: str | Path,
    *,
    run_id: str | None = None,
) -> tuple[tuple[Path, ...], tuple[str, ...]]:
    """Haltless driver boundary: write, re-derive, and expose exact debt."""

    root = Path(scratchpad)
    try:
        paths = write_trust_evidence_provider_state(root, run_id=run_id)
    except Exception as exc:
        return (), (
            "trust evidence provider write failed; negative authority remains "
            f"disabled: {type(exc).__name__}: {exc}",
        )
    issues = validate_trust_evidence_provider_state(root, run_id=run_id)
    if issues:
        return tuple(paths), tuple(issues)
    return tuple(paths), ()


def validate_trust_evidence_provider_state(
    scratchpad: str | Path,
    *,
    run_id: str | None = None,
) -> tuple[str, ...]:
    """Re-derive both files; persisted drift is visible and has no authority."""

    root = Path(scratchpad)
    expected_ledger, expected_receipt = build_trust_evidence_provider_state(
        root, run_id=run_id
    )
    issues: list[str] = []
    try:
        observed_ledger = _strict_json(root / TRUST_AUTHORITY_FILE)
        if observed_ledger != expected_ledger:
            issues.append("trust authority ledger differs from provider derivation")
    except Exception as exc:
        issues.append(f"trust authority ledger invalid: {type(exc).__name__}: {exc}")
    try:
        observed_receipt = _strict_json(root / PROVIDER_RECEIPT_FILE)
        if observed_receipt != expected_receipt:
            issues.append("trust provider receipt differs from exact derivation")
    except Exception as exc:
        issues.append(f"trust provider receipt invalid: {type(exc).__name__}: {exc}")
    return tuple(issues)


__all__ = [
    "NEGATIVE_AUTHORITY",
    "PROVIDER_RECEIPT_FILE",
    "PROVIDER_RECEIPT_SCHEMA",
    "TrustEvidenceProviderError",
    "build_trust_evidence_provider_state",
    "constrain_trust_sensitive_report_projection",
    "ensure_trust_evidence_provider_state",
    "validate_trust_evidence_provider_state",
    "write_trust_evidence_provider_state",
]
