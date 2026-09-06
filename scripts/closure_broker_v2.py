"""Closure-subject schemas and the central terminal-authority broker.

The original v2 observation object remains shadow-only. Production consumers
use the loader-owned central authority below, where a destructive closure
effect is bound to one canonical audit subject and a code-owned provider
contract. Observed providers register immutable completion/publish handles;
applied lossless equivalence is adapted from current semantic-dedup receipts.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import threading
from collections import OrderedDict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any


SUBJECT_SCHEMA = "plamen.closure_subject.v2"
PROVIDER_OUTPUT_SCHEMA = "plamen.closure_provider_output.v2"
PROVIDER_RECEIPT_SCHEMA = "plamen.closure_provider_execution_receipt.v2"
BROKER_MODE = "SHADOW_PROPOSAL_ONLY"
CENTRAL_BROKER_MODE = "LIVE_REPLAYED_PROVIDER_AUTHORITY"
CENTRAL_LEDGER_SCHEMA = "plamen.central_negative_closure_authority.v1"
CENTRAL_DECISION_SCHEMA = "plamen.central_negative_closure_decision.v1"
CENTRAL_LEDGER_NAME = "negative_closure_broker_authority.json"
CENTRAL_BUNDLE_DIR = "negative_closure_provider_bundles"
CENTRAL_SUBJECT_SCHEMA = "plamen.central_negative_closure_subject.v1"
CENTRAL_EVIDENCE_SCHEMA = "plamen.central_negative_closure_evidence_manifest.v1"
CENTRAL_BUNDLE_SCHEMA = "plamen.central_negative_closure_provider_bundle.v1"
_CENTRAL_BUNDLE_NAME_RE = re.compile(r"^bundle-[0-9a-f]{24}\.json$")
CENTRAL_APPLIED_EQUIVALENCE_PROVIDER = (
    "plamen.semantic-dedup-applied-equivalence.v1"
)

# Replay is intentionally expensive: it authenticates every provider-owned
# edge and then repeats the build to detect concurrent mutation.  Inventory
# reconciliation can ask the same authority about thousands of candidates in
# one immutable artifact-ledger revision, so doing that work per candidate is
# both unnecessary and (notably on Windows) prohibitive.  Cached projections
# remain process-local and are admitted only after an exact revision join; the
# implementation and entry type live below the central builder.
_CENTRAL_REPLAY_CACHE_LIMIT = 8
_CENTRAL_REPLAY_CACHE_LOCK = threading.RLock()
_CENTRAL_REPLAY_CACHE: "OrderedDict[str, _CentralReplayCacheEntry]" = OrderedDict()

_CENTRAL_SUBJECT_FIELDS = frozenset(
    {
        "schema_version",
        "run_id",
        "candidate_id",
        "work_item_id",
        "candidate_premise_ids",
        "candidate_content_sha256",
        "producer_identities",
        "producer_invocation_ids",
        "current_artifacts",
        "requested_effect",
        "subject_digest",
    }
)
_CENTRAL_ARTIFACT_FIELDS = frozenset(
    {"role", "relative_path", "sha256", "size_bytes"}
)
_CENTRAL_EVIDENCE_FIELDS = frozenset(
    {
        "schema_version",
        "subject_digest",
        "premise_ids",
        "domain_ids",
        "exhaustive",
        "artifacts",
        "manifest_digest",
    }
)
_CENTRAL_EVIDENCE_ARTIFACT_FIELDS = frozenset(
    {"evidence_id", "relative_path", "sha256", "size_bytes", "premise_ids"}
)
_CENTRAL_BUNDLE_FIELDS = frozenset(
    {
        "schema_version",
        "bundle_id",
        "subject_relative_path",
        "evidence_manifest_relative_path",
        "provider_output_relative_path",
        "completion_receipt_relative_path",
        "completion_sha256",
        "publish_receipt_relative_path",
        "publish_sha256",
        "bundle_digest",
    }
)

# Code-owned production registry.  A bundle cannot extend it, and the effective
# provider backend/model plus worker/reviewer identities are replayed from the
# provider-owned execution arm before any negative is terminal.
_CENTRAL_PROVIDER_REGISTRY = MappingProxyType(
    {
        "plamen.mechanical-scope-exclusion.v1": {
            "provider_version": "1.0.0",
            "authority_kind": "MECHANICAL_SCOPE_EXCLUSION",
            "worker_identity": "PLAMEN_MECHANICAL_SCOPE_PROVIDER",
            "reviewer_identity": "PLAMEN_MECHANICAL_SCOPE_REVIEWER",
        },
        "plamen.exhaustive-negative-execution.v1": {
            "provider_version": "1.0.0",
            "authority_kind": "AUTHENTICATED_EXHAUSTIVE_NEGATIVE_EXECUTION",
            "worker_identity": "PLAMEN_EXHAUSTIVE_NEGATIVE_PROVIDER",
            "reviewer_identity": "PLAMEN_EXHAUSTIVE_NEGATIVE_REVIEWER",
        },
    }
)

REFUTED_FULL = "REFUTED_FULL"
ZERO_HARM = "ZERO_HARM"
OUT_OF_SCOPE = "OUT_OF_SCOPE"
ALIAS_TO_SURVIVOR = "ALIAS_TO_SURVIVOR"
NO_AUTHORITY = "NO_AUTHORITY"

CLAIM_RESOLUTION = "CLAIM_RESOLUTION"
HARM_RESOLUTION = "HARM_RESOLUTION"
SCOPE_RESOLUTION = "SCOPE_RESOLUTION"
IDENTITY_RESOLUTION = "IDENTITY_RESOLUTION"

AUTHORIZED = "AUTHORIZED"
DEBT = "DEBT"
UNRESOLVED = "UNRESOLVED"

_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}$", re.ASCII)

_SUBJECT_FIELDS = frozenset(
    {
        "schema_version",
        "run_id",
        "audit_snapshot_sha256",
        "candidate_id",
        "source_id",
        "candidate_sha256",
        "source_sha256",
        "content_sha256",
        "claim_manifest_sha256",
        "premise_ids",
        "requested_effect",
    }
)
_OUTPUT_FIELDS = frozenset(
    {
        "schema_version",
        "provider_id",
        "provider_version",
        "authority_kind",
        "subject_sha256",
        "requested_effect",
        "outcome",
        "proof_scope",
        "exhaustive",
        "premise_ids",
        "audit_snapshot_sha256",
        "claim_manifest_sha256",
        "evidence_sha256",
        "survivor",
    }
)
_SURVIVOR_FIELDS = frozenset({"candidate_id", "identity_sha256", "state"})
_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "provider_id",
        "provider_version",
        "authority_kind",
        "invocation_id",
        "subject_sha256",
        "provider_input_sha256",
        "provider_output_sha256",
        "execution_status",
        "exit_code",
        "issuer_identity",
        "receipt_origin",
        "receipt_digest",
    }
)


class ClosureBrokerError(ValueError):
    """The v2 closure input is malformed, forged, stale, or non-canonical."""


@dataclass(frozen=True)
class _ProviderSpec:
    provider_version: str
    authority_kind: str
    effect: str
    proof_scope: str
    issuer_identity: str


@dataclass(frozen=True)
class _ObservedExecution:
    provider_output_sha256: str
    receipt_digest: str
    invocation_id: str
    provider_id: str
    subject_sha256: str


# This is code-owned on purpose.  A model/caller cannot supply or extend it at
# decision time.  Adding a provider is a reviewed code change with fixtures.
_PROVIDER_REGISTRY = MappingProxyType(
    {
        "plamen.claim-resolution.v2": _ProviderSpec(
            "2.0.0",
            CLAIM_RESOLUTION,
            REFUTED_FULL,
            "FULL_CLAIM",
            "PLAMEN_CLOSURE_PROVIDER_HOST",
        ),
        "plamen.harm-resolution.v2": _ProviderSpec(
            "2.0.0",
            HARM_RESOLUTION,
            ZERO_HARM,
            "HARM_ONLY",
            "PLAMEN_CLOSURE_PROVIDER_HOST",
        ),
        "plamen.scope-resolution.v2": _ProviderSpec(
            "2.0.0",
            SCOPE_RESOLUTION,
            OUT_OF_SCOPE,
            "EXACT_SCOPE",
            "PLAMEN_CLOSURE_PROVIDER_HOST",
        ),
        "plamen.identity-resolution.v2": _ProviderSpec(
            "2.0.0",
            IDENTITY_RESOLUTION,
            ALIAS_TO_SURVIVOR,
            "IDENTITY_ONLY",
            "PLAMEN_CLOSURE_PROVIDER_HOST",
        ),
    }
)

_EFFECTS = frozenset(
    {REFUTED_FULL, ZERO_HARM, OUT_OF_SCOPE, ALIAS_TO_SURVIVOR}
)
_AXIS_BY_EFFECT = {
    REFUTED_FULL: "claim_resolution",
    ZERO_HARM: "harm_resolution",
    OUT_OF_SCOPE: "scope_resolution",
    ALIAS_TO_SURVIVOR: "identity_resolution",
}


def _reject_constant(value: str) -> None:
    raise ClosureBrokerError(f"non-finite JSON number: {value}")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ClosureBrokerError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_nonfinite_tree(value: Any) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise ClosureBrokerError("non-finite JSON number")
    if isinstance(value, Mapping):
        for item in value.values():
            _reject_nonfinite_tree(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _reject_nonfinite_tree(item)


def strict_json_loads(raw: bytes | str) -> Any:
    """Parse JSON while rejecting duplicate keys, non-finite values and bad UTF-8."""

    try:
        text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
    except UnicodeDecodeError as exc:
        raise ClosureBrokerError("JSON is not UTF-8") from exc
    try:
        result = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except ClosureBrokerError:
        raise
    except (json.JSONDecodeError, TypeError) as exc:
        raise ClosureBrokerError(f"invalid JSON: {exc}") from exc
    _reject_nonfinite_tree(result)
    return result


def canonical_json_bytes(value: Any) -> bytes:
    """Return the only accepted byte representation of a JSON value."""

    _reject_nonfinite_tree(value)
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ClosureBrokerError(f"value is not canonical JSON: {exc}") from exc


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_object(raw: bytes | str, *, field: str) -> dict[str, Any]:
    value = strict_json_loads(raw)
    if not isinstance(value, dict):
        raise ClosureBrokerError(f"{field} must be an object")
    raw_bytes = raw.encode("utf-8") if isinstance(raw, str) else raw
    if raw_bytes != canonical_json_bytes(value):
        raise ClosureBrokerError(f"{field} is not canonical JSON")
    return value


def _exact_fields(
    value: Mapping[str, Any], expected: frozenset[str], *, field: str
) -> None:
    actual = set(value)
    if actual != expected:
        raise ClosureBrokerError(
            f"{field} schema mismatch "
            f"(missing={sorted(expected - actual)}, extra={sorted(actual - expected)})"
        )


def _token(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not _TOKEN.fullmatch(value):
        raise ClosureBrokerError(f"{field} is not a valid token")
    return value


def _hex64(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise ClosureBrokerError(f"{field} is not a SHA-256 digest")
    return value


def _premises(value: Any, *, field: str = "premise_ids") -> list[str]:
    if not isinstance(value, list) or not value:
        raise ClosureBrokerError(f"{field} must be a non-empty array")
    result = [_token(item, field=f"{field}[]") for item in value]
    if len(result) != len(set(result)):
        raise ClosureBrokerError(f"{field} contains duplicate IDs")
    if result != sorted(result):
        raise ClosureBrokerError(f"{field} must be canonically sorted")
    return result


def validate_subject_manifest(raw: bytes | str) -> dict[str, Any]:
    """Validate and return an exact canonical v2 closure subject manifest."""

    value = _canonical_object(raw, field="closure subject")
    _exact_fields(value, _SUBJECT_FIELDS, field="closure subject")
    if value["schema_version"] != SUBJECT_SCHEMA:
        raise ClosureBrokerError("closure subject schema mismatch")
    _token(value["run_id"], field="run_id")
    _hex64(value["audit_snapshot_sha256"], field="audit_snapshot_sha256")
    _token(value["candidate_id"], field="candidate_id")
    _token(value["source_id"], field="source_id")
    _hex64(value["candidate_sha256"], field="candidate_sha256")
    _hex64(value["source_sha256"], field="source_sha256")
    _hex64(value["content_sha256"], field="content_sha256")
    _hex64(value["claim_manifest_sha256"], field="claim_manifest_sha256")
    _premises(value["premise_ids"])
    if value["requested_effect"] not in _EFFECTS:
        raise ClosureBrokerError("requested_effect is not a v2 closure effect")
    return value


def subject_sha256(raw: bytes | str) -> str:
    """Return a subject digest only after exact v2 validation."""

    validate_subject_manifest(raw)
    return _sha256(raw.encode("utf-8") if isinstance(raw, str) else raw)


def provider_registry_snapshot() -> dict[str, dict[str, str]]:
    """Expose immutable registry facts for diagnostics, never for mutation."""

    return {
        provider_id: {
            "provider_version": spec.provider_version,
            "authority_kind": spec.authority_kind,
            "effect": spec.effect,
            "proof_scope": spec.proof_scope,
            "issuer_identity": spec.issuer_identity,
        }
        for provider_id, spec in sorted(_PROVIDER_REGISTRY.items())
    }


def _validate_output_shape(raw: bytes) -> tuple[dict[str, Any], _ProviderSpec]:
    output = _canonical_object(raw, field="provider output")
    _exact_fields(output, _OUTPUT_FIELDS, field="provider output")
    if output["schema_version"] != PROVIDER_OUTPUT_SCHEMA:
        raise ClosureBrokerError("provider output schema mismatch")
    provider_id = _token(output["provider_id"], field="provider_id")
    spec = _PROVIDER_REGISTRY.get(provider_id)
    if spec is None:
        raise ClosureBrokerError("provider is absent from code-owned registry")
    if output["provider_version"] != spec.provider_version:
        raise ClosureBrokerError("provider version mismatch")
    if output["authority_kind"] != spec.authority_kind:
        raise ClosureBrokerError("provider authority-kind mismatch")
    _hex64(output["subject_sha256"], field="subject_sha256")
    if output["requested_effect"] not in _EFFECTS:
        raise ClosureBrokerError("provider requested_effect is unsupported")
    if output["outcome"] not in _EFFECTS:
        raise ClosureBrokerError("provider outcome is unsupported")
    _token(output["proof_scope"], field="proof_scope")
    if output["exhaustive"] is not True:
        raise ClosureBrokerError("provider resolution is not exhaustive")
    _premises(output["premise_ids"])
    _hex64(output["audit_snapshot_sha256"], field="audit_snapshot_sha256")
    _hex64(output["claim_manifest_sha256"], field="claim_manifest_sha256")
    _hex64(output["evidence_sha256"], field="evidence_sha256")
    survivor = output["survivor"]
    if survivor is not None:
        if not isinstance(survivor, dict):
            raise ClosureBrokerError("survivor must be an object or null")
        _exact_fields(survivor, _SURVIVOR_FIELDS, field="survivor")
        _token(survivor["candidate_id"], field="survivor.candidate_id")
        _hex64(survivor["identity_sha256"], field="survivor.identity_sha256")
        if survivor["state"] != "LIVE":
            raise ClosureBrokerError("survivor is not live")
    return output, spec


def _validate_receipt(
    raw: bytes,
    *,
    output: Mapping[str, Any],
    output_bytes: bytes,
    spec: _ProviderSpec,
) -> dict[str, Any]:
    receipt = _canonical_object(raw, field="provider execution receipt")
    _exact_fields(receipt, _RECEIPT_FIELDS, field="provider execution receipt")
    if receipt["schema_version"] != PROVIDER_RECEIPT_SCHEMA:
        raise ClosureBrokerError("provider receipt schema mismatch")
    exact = {
        "provider_id": output["provider_id"],
        "provider_version": output["provider_version"],
        "authority_kind": output["authority_kind"],
        "subject_sha256": output["subject_sha256"],
        "provider_input_sha256": output["subject_sha256"],
        "provider_output_sha256": _sha256(output_bytes),
        "execution_status": "COMPLETE",
        "exit_code": 0,
        "issuer_identity": spec.issuer_identity,
        "receipt_origin": "DRIVER_OBSERVED_PROVIDER_EXECUTION",
    }
    for field, expected in exact.items():
        if field == "exit_code" and type(receipt[field]) is not int:
            raise ClosureBrokerError("provider receipt exit_code must be an integer")
        if receipt[field] != expected:
            if field == "issuer_identity":
                raise ClosureBrokerError("provider receipt issuer mismatch")
            raise ClosureBrokerError(f"provider receipt {field} mismatch")
    _token(receipt["invocation_id"], field="invocation_id")
    claimed = _hex64(receipt["receipt_digest"], field="receipt_digest")
    unsigned = dict(receipt)
    unsigned.pop("receipt_digest")
    if _sha256(canonical_json_bytes(unsigned)) != claimed:
        raise ClosureBrokerError("provider receipt digest mismatch")
    return receipt


def _base_result(
    *,
    status: str,
    outcome: str,
    subject_digest: str,
    requested_effect: str | None,
    debt_reasons: Sequence[str] = (),
    authorities: Sequence[Mapping[str, Any]] = (),
    conflicts: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    return {
        "schema_version": "plamen.closure_broker_resolution.v2",
        "status": status,
        "outcome": outcome,
        "subject_sha256": subject_digest,
        "requested_effect": requested_effect,
        "claim_resolution": UNRESOLVED,
        "harm_resolution": UNRESOLVED,
        "scope_resolution": UNRESOLVED,
        "identity_resolution": UNRESOLVED,
        "debt_reasons": sorted(set(debt_reasons)),
        "authorities": [dict(row) for row in authorities],
        "conflicts": [dict(row) for row in conflicts],
    }


class ClosureAuthorityBrokerV2:
    """Validate observed provider runs and resolve one exact v2 subject.

    The observed-execution map is the receipt replay seam.  It is concrete and
    broker-owned; `resolve` accepts neither a validator callback nor a provider
    registry supplied by its caller.
    """

    def __init__(self) -> None:
        self._observed: dict[str, _ObservedExecution] = {}

    def observe_provider_execution(
        self,
        *,
        provider_output_bytes: bytes,
        provider_receipt_bytes: bytes,
    ) -> str:
        """Record one exact driver-observed provider output/receipt pair."""

        output, spec = _validate_output_shape(provider_output_bytes)
        receipt = _validate_receipt(
            provider_receipt_bytes,
            output=output,
            output_bytes=provider_output_bytes,
            spec=spec,
        )
        output_digest = _sha256(provider_output_bytes)
        observed = _ObservedExecution(
            provider_output_sha256=output_digest,
            receipt_digest=receipt["receipt_digest"],
            invocation_id=receipt["invocation_id"],
            provider_id=output["provider_id"],
            subject_sha256=output["subject_sha256"],
        )
        previous = self._observed.get(output_digest)
        if previous is not None and previous != observed:
            raise ClosureBrokerError("provider output has conflicting observed receipts")
        self._observed[output_digest] = observed
        return receipt["receipt_digest"]

    def resolve(
        self,
        *,
        subject_manifest_bytes: bytes,
        provider_output_bytes: Sequence[bytes],
        live_survivors: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        """Resolve authority or return visible, non-destructive debt."""

        raw_subject_digest = _sha256(subject_manifest_bytes)
        try:
            raw_subject = _canonical_object(
                subject_manifest_bytes, field="closure subject"
            )
        except ClosureBrokerError:
            return _base_result(
                status=DEBT,
                outcome=NO_AUTHORITY,
                subject_digest=raw_subject_digest,
                requested_effect=None,
                debt_reasons=["INVALID_SUBJECT_MANIFEST"],
            )
        schema = raw_subject.get("schema_version")
        if schema != SUBJECT_SCHEMA:
            reason = (
                "SCHEMA_V1_NOT_LIVE_AUTHORITY"
                if isinstance(schema, str) and schema.endswith(".v1")
                else "SUBJECT_SCHEMA_MISMATCH"
            )
            return _base_result(
                status=DEBT,
                outcome=NO_AUTHORITY,
                subject_digest=raw_subject_digest,
                requested_effect=raw_subject.get("requested_effect"),
                debt_reasons=[reason],
            )
        try:
            subject = validate_subject_manifest(subject_manifest_bytes)
        except ClosureBrokerError:
            return _base_result(
                status=DEBT,
                outcome=NO_AUTHORITY,
                subject_digest=raw_subject_digest,
                requested_effect=raw_subject.get("requested_effect"),
                debt_reasons=["INVALID_SUBJECT_MANIFEST"],
            )

        requested = subject["requested_effect"]
        live = dict(live_survivors or {})
        accepted: list[dict[str, Any]] = []
        rejected_reasons: list[str] = []
        seen_outputs: set[str] = set()

        for raw_output in provider_output_bytes:
            output_digest = _sha256(raw_output)
            if output_digest in seen_outputs:
                continue
            seen_outputs.add(output_digest)
            observed = self._observed.get(output_digest)
            if observed is None:
                rejected_reasons.append("PROVIDER_EXECUTION_NOT_OBSERVED")
                continue
            try:
                output, spec = _validate_output_shape(raw_output)
            except ClosureBrokerError:
                rejected_reasons.append("INVALID_PROVIDER_OUTPUT")
                continue

            if output["subject_sha256"] != raw_subject_digest:
                rejected_reasons.append("SUBJECT_BINDING_MISMATCH")
                continue
            if (
                output["requested_effect"] != requested
                or output["outcome"] != requested
                or spec.effect != requested
                or output["proof_scope"] != spec.proof_scope
            ):
                rejected_reasons.append("EFFECT_KIND_MATRIX_MISMATCH")
                continue
            if output["premise_ids"] != subject["premise_ids"]:
                rejected_reasons.append("PREMISE_BINDING_MISMATCH")
                continue
            if output["audit_snapshot_sha256"] != subject["audit_snapshot_sha256"]:
                rejected_reasons.append("AUDIT_SNAPSHOT_BINDING_MISMATCH")
                continue
            if output["claim_manifest_sha256"] != subject["claim_manifest_sha256"]:
                rejected_reasons.append("CLAIM_MANIFEST_BINDING_MISMATCH")
                continue

            survivor = output["survivor"]
            if requested == ALIAS_TO_SURVIVOR:
                if survivor is None:
                    rejected_reasons.append("SURVIVOR_IDENTITY_MISSING")
                    continue
                survivor_id = survivor["candidate_id"]
                if survivor_id == subject["candidate_id"]:
                    rejected_reasons.append("SELF_ALIAS_FORBIDDEN")
                    continue
                live_digest = live.get(survivor_id)
                if live_digest is None:
                    rejected_reasons.append("SURVIVOR_NOT_LIVE")
                    continue
                if live_digest != survivor["identity_sha256"]:
                    rejected_reasons.append("SURVIVOR_IDENTITY_STALE")
                    continue
            elif survivor is not None:
                rejected_reasons.append("FOREIGN_IDENTITY_DETAIL")
                continue

            accepted.append(
                {
                    "provider_id": output["provider_id"],
                    "provider_output_sha256": output_digest,
                    "receipt_digest": observed.receipt_digest,
                    "invocation_id": observed.invocation_id,
                    "outcome": output["outcome"],
                    "proof_scope": output["proof_scope"],
                    "survivor_id": (
                        survivor["candidate_id"] if survivor is not None else None
                    ),
                    "survivor_identity_sha256": (
                        survivor["identity_sha256"] if survivor is not None else None
                    ),
                }
            )

        accepted.sort(key=lambda row: row["provider_output_sha256"])

        if not accepted:
            return _base_result(
                status=DEBT,
                outcome=NO_AUTHORITY,
                subject_digest=raw_subject_digest,
                requested_effect=requested,
                debt_reasons=rejected_reasons or ["NO_PROVIDER_AUTHORITY"],
            )

        semantic_keys = {
            (
                row["outcome"],
                row["proof_scope"],
                row["survivor_id"],
                row["survivor_identity_sha256"],
            )
            for row in accepted
        }
        # An observed-but-invalid authority alongside a valid authority is a
        # provider-plane contradiction, not harmless model noise.  Unobserved
        # garbage cannot veto an independently valid observed authority.
        observed_invalid = any(
            reason != "PROVIDER_EXECUTION_NOT_OBSERVED"
            for reason in rejected_reasons
        )
        if len(semantic_keys) != 1 or observed_invalid:
            reasons = ["CONFLICTING_AUTHORITIES", *rejected_reasons]
            return _base_result(
                status=DEBT,
                outcome=NO_AUTHORITY,
                subject_digest=raw_subject_digest,
                requested_effect=requested,
                debt_reasons=reasons,
                authorities=accepted,
                conflicts=accepted,
            )

        # This v2 object deliberately remains a schema/proposal broker.  Its
        # public observation API can validate self-consistent bytes, but it
        # cannot prove that those bytes came from a confined worker, replay an
        # evidence manifest, establish the complete provider-output
        # denominator, or source alias liveness from the lifecycle ledger.
        # Returning AUTHORIZED here would let an arbitrary in-process caller
        # mint a destructive decision.  A future live broker must consume the
        # provider-owned completion/publish chain and trusted lifecycle state;
        # there is intentionally no flag or constructor escape hatch that can
        # enable authority in this foundation.
        return _base_result(
            status=DEBT,
            outcome=NO_AUTHORITY,
            subject_digest=raw_subject_digest,
            requested_effect=requested,
            debt_reasons=["BROKER_V2_SHADOW_PROPOSAL_ONLY"],
            authorities=accepted,
        )


_CENTRAL_CONSTRUCTION_TOKEN = object()


class CentralNegativeClosureAuthority:
    """Opaque, replay-derived lookup consumed by all live negative paths.

    Instances are constructed only by :func:`load_central_negative_closure_authority`.
    A caller-supplied mapping, v1 authority, or shadow-broker result is never a
    substitute for this object.  The full provider-bundle replay is added below;
    even an empty denominator is represented as visible reopen debt.
    """

    __slots__ = ("_ledger", "_root")

    def __init__(
        self,
        ledger: Mapping[str, Any],
        *,
        root: Path,
        _token: object,
    ) -> None:
        if _token is not _CENTRAL_CONSTRUCTION_TOKEN:
            raise ClosureBrokerError("central closure authority is loader-owned")
        root_input = Path(root)
        if root_input.is_symlink() or _is_reparse(root_input):
            raise ClosureBrokerError(
                "central closure scratchpad cannot be a symlink/reparse point"
            )
        self._root = root_input.resolve(strict=True)
        self._ledger = json.loads(canonical_json_bytes(dict(ledger)).decode("utf-8"))

    @property
    def ledger(self) -> dict[str, Any]:
        # Diagnostics are current too.  An object retained across a filesystem
        # mutation must never keep presenting its construction-time snapshot as
        # live authority.
        try:
            ledger = _replay_central_ledger(self._root)
        except Exception:
            ledger = self._ledger
        return json.loads(canonical_json_bytes(ledger).decode("utf-8"))

    def resolve(
        self,
        *,
        work_item: Mapping[str, Any],
        requested_effect: str,
    ) -> dict[str, Any]:
        # The object is a locator/capability to replay, not an authority
        # snapshot.  Reconstruct the exact current denominator on every use so
        # a candidate/evidence/receipt mutation between load and consume can
        # only remove authority.
        try:
            ledger = _replay_central_ledger(self._root)
        except Exception as exc:
            return {
                "schema_version": CENTRAL_DECISION_SCHEMA,
                "status": DEBT,
                "outcome": NO_AUTHORITY,
                "requested_effect": requested_effect,
                "candidate_id": str(
                    work_item.get("candidate_negative_family_id")
                    or work_item.get("candidate_id")
                    or work_item.get("work_item_id")
                    or ""
                ),
                "work_item_id": str(work_item.get("work_item_id") or ""),
                "candidate_premise_ids": list(
                    work_item.get("candidate_premise_ids") or []
                ),
                "reopen_required": True,
                "debt_reasons": [
                    "CENTRAL_NEGATIVE_CLOSURE_REPLAY_FAILED_"
                    f"{type(exc).__name__.upper()}"
                ],
                "resolution_digest": "",
            }
        candidate_id = str(
            work_item.get("candidate_negative_family_id")
            or work_item.get("candidate_id")
            or work_item.get("work_item_id")
            or ""
        )
        work_item_id = str(work_item.get("work_item_id") or candidate_id)
        raw_premises = work_item.get("candidate_premise_ids")
        premises_bound = isinstance(raw_premises, list)
        premises = list(raw_premises) if premises_bound else []
        candidate_content_sha256 = str(
            work_item.get("candidate_content_sha256")
            or work_item.get("source_block_sha256")
            or ""
        )
        matches = [
            row
            for row in ledger.get("decisions", [])
            if isinstance(row, Mapping)
            and row.get("candidate_id") == candidate_id
            and row.get("requested_effect") == requested_effect
            and (
                (
                    row.get("provider_kind") == "APPLIED_LOSSLESS_EQUIVALENCE"
                    and bool(candidate_content_sha256)
                    and row.get("work_item_id") == work_item_id
                    and row.get("candidate_content_sha256")
                    == candidate_content_sha256
                )
                or (
                    row.get("work_item_id") == work_item_id
                    and (
                        row.get("candidate_premise_ids") == premises
                        if premises_bound
                        else bool(candidate_content_sha256)
                        and row.get("candidate_content_sha256")
                        == candidate_content_sha256
                    )
                )
            )
        ]
        debt = list(ledger.get("debt", []))
        if len(matches) != 1 or debt:
            reasons = [
                str(row.get("code") or "BROKER_REPLAY_DEBT")
                for row in debt
                if isinstance(row, Mapping)
            ]
            if len(matches) > 1:
                reasons.append("CONFLICTING_AUTHORITIES")
            elif not matches:
                reasons.append("NO_PROVIDER_AUTHORITY")
            return {
                "schema_version": CENTRAL_DECISION_SCHEMA,
                "status": DEBT,
                "outcome": NO_AUTHORITY,
                "requested_effect": requested_effect,
                "candidate_id": candidate_id,
                "work_item_id": work_item_id,
                "candidate_premise_ids": list(premises),
                "reopen_required": True,
                "debt_reasons": sorted(set(reasons)),
                "resolution_digest": "",
            }
        return dict(matches[0])


def _build_applied_equivalence_adapter(
    root: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, str]]]:
    """Adapt validated, actually-applied dedup receipts into broker decisions."""

    from semantic_dedup_authority import (
        PRIMARY_RECEIPT_NAME,
        SUPPLEMENTAL_RECEIPT_NAME,
        _extract_preserved_raw,
        extract_finding_records,
        load_applied_aliases,
    )

    receipt_paths = [
        root / PRIMARY_RECEIPT_NAME,
        root / SUPPLEMENTAL_RECEIPT_NAME,
    ]
    present = [path for path in receipt_paths if path.is_file()]
    if not present:
        return [], [], []
    denominator: list[dict[str, Any]] = []
    receipts: list[dict[str, Any]] = []
    try:
        for path in present:
            _safe_path, raw = _current_file(
                root,
                path.name,
                field="applied equivalence receipt",
            )
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (UnicodeError, json.JSONDecodeError) as exc:
                raise ClosureBrokerError(
                    f"applied equivalence receipt {path.name} is invalid JSON"
                ) from exc
            if not isinstance(payload, dict):
                raise ClosureBrokerError(
                    f"applied equivalence receipt {path.name} is not an object"
                )
            receipts.append(payload)
            denominator.append(
                {
                    "path": path.name,
                    "sha256": _sha256(raw),
                    "size_bytes": len(raw),
                }
            )
        aliases = load_applied_aliases(root)
        phase = str(receipts[0].get("phase_name") or "")
        canonical_name = (
            "findings_inventory.md"
            if phase == "sc_semantic_dedup"
            else "verification_queue.md"
        )
        canonical_path, canonical_raw = _current_file(
            root, canonical_name, field="applied equivalence canonical output"
        )
        denominator.append(
            {
                "path": canonical_path.relative_to(root.resolve(strict=True)).as_posix(),
                "sha256": _sha256(canonical_raw),
                "size_bytes": len(canonical_raw),
            }
        )
        current_records = extract_finding_records(canonical_raw.decode("utf-8"))
        accepted_by_member: dict[str, Mapping[str, Any]] = {}
        for receipt in receipts:
            for decision in receipt.get("decisions", []):
                if (
                    isinstance(decision, Mapping)
                    and decision.get("status") == "ACCEPTED"
                ):
                    accepted_by_member[str(decision.get("member_id") or "")] = decision
        chain_digest = _sha256(canonical_json_bytes(denominator))
        decisions: list[dict[str, Any]] = []
        for member in sorted(aliases):
            alias = aliases[member]
            survivor = str(alias.get("survivor") or "")
            accepted = accepted_by_member.get(member)
            if not isinstance(accepted, Mapping):
                raise ClosureBrokerError(
                    f"applied alias {member} has no accepted receipt decision"
                )
            preservation = accepted.get("field_preservation")
            if not isinstance(preservation, Mapping) or preservation.get("passed") is not True:
                raise ClosureBrokerError(
                    f"applied alias {member} lacks field-complete preservation"
                )
            absorbed_sha = str(preservation.get("absorbed_raw_sha256") or "")
            survivor_record = current_records.get(survivor)
            survivor_sha = str(
                (survivor_record or {}).get("raw_sha256")
                if isinstance(survivor_record, Mapping)
                else ""
            )
            if not _HEX64.fullmatch(absorbed_sha) or not _HEX64.fullmatch(
                survivor_sha
            ):
                raise ClosureBrokerError(
                    f"applied alias {member} content identity is incomplete"
                )
            recovered_raw, recovered_issues = _extract_preserved_raw(
                (
                    canonical_raw.decode("utf-8", errors="strict")
                    if not isinstance(survivor_record, Mapping)
                    or survivor_record.get("kind") == "row"
                    else str(survivor_record.get("raw") or "")
                ),
                member,
            )
            if (
                recovered_raw is None
                or recovered_issues
                or _sha256(recovered_raw.encode("utf-8")) != absorbed_sha
            ):
                raise ClosureBrokerError(
                    f"applied alias {member} preserved bytes do not replay"
                )
            # Inventory and lifecycle candidates bind finding blocks without
            # outer delimiter whitespace.  Derive that exact current-consumer
            # identity from the receipt-recovered original bytes while keeping
            # the byte-exact receipt digest in the subject below.
            candidate_content_sha = _sha256(
                recovered_raw.strip().encode("utf-8")
            )
            subject_digest = _sha256(
                canonical_json_bytes(
                    {
                        "candidate_id": member,
                        "candidate_content_sha256": absorbed_sha,
                        "consumer_candidate_content_sha256": candidate_content_sha,
                        "survivor_id": survivor,
                        "survivor_identity_sha256": survivor_sha,
                        "receipt_chain_sha256": chain_digest,
                    }
                )
            )
            unsigned = {
                "schema_version": CENTRAL_DECISION_SCHEMA,
                "status": AUTHORIZED,
                "outcome": ALIAS_TO_SURVIVOR,
                "requested_effect": ALIAS_TO_SURVIVOR,
                "candidate_id": member,
                "work_item_id": member,
                "candidate_premise_ids": [],
                "candidate_content_sha256": candidate_content_sha,
                "subject_digest": subject_digest,
                "evidence_manifest_digest": chain_digest,
                "provider_id": CENTRAL_APPLIED_EQUIVALENCE_PROVIDER,
                "provider_kind": "APPLIED_LOSSLESS_EQUIVALENCE",
                "provider_completion_sha256": chain_digest,
                "provider_publish_sha256": _sha256(canonical_raw),
                "bundle_digest": chain_digest,
                "survivor_id": survivor,
                "survivor_identity_sha256": survivor_sha,
                "reopen_required": False,
                "debt_reasons": [],
            }
            decisions.append(
                {
                    **unsigned,
                    "resolution_digest": _sha256(canonical_json_bytes(unsigned)),
                }
            )
        return decisions, denominator, []
    except Exception as exc:
        return (
            [],
            denominator,
            [
                {
                    "code": "APPLIED_EQUIVALENCE_REPLAY_FAILED",
                    "detail": f"{type(exc).__name__}: {exc}"[:4096],
                }
            ],
        )


def _payload_sha256(value: Mapping[str, Any], digest_field: str) -> str:
    unsigned = dict(value)
    unsigned.pop(digest_field, None)
    return _sha256(canonical_json_bytes(unsigned))


def _relative_path(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ClosureBrokerError(f"{field} must be a relative path")
    normalized = value.replace("\\", "/")
    candidate = Path(normalized)
    parts = normalized.split("/")
    if (
        candidate.is_absolute()
        or normalized.startswith("/")
        or any(part in {"", ".", ".."} or ":" in part for part in parts)
    ):
        raise ClosureBrokerError(f"{field} is unsafe")
    return normalized


def _is_reparse(path: Path) -> bool:
    try:
        return bool(getattr(path.lstat(), "st_file_attributes", 0) & 0x400)
    except OSError:
        return False


def _current_file(root: Path, relative: Any, *, field: str) -> tuple[Path, bytes]:
    rel = _relative_path(relative, field=field)
    current = root.resolve(strict=True)
    for part in rel.split("/"):
        current = current / part
        if not current.exists():
            raise ClosureBrokerError(f"{field} is missing")
        if current.is_symlink() or _is_reparse(current):
            raise ClosureBrokerError(f"{field} crosses a symlink/reparse point")
    resolved = current.resolve(strict=True)
    try:
        resolved.relative_to(root.resolve(strict=True))
    except ValueError as exc:
        raise ClosureBrokerError(f"{field} escapes the scratchpad") from exc
    if not resolved.is_file():
        raise ClosureBrokerError(f"{field} is not a regular file")
    return resolved, resolved.read_bytes()


def _canonical_file(root: Path, relative: Any, *, field: str) -> tuple[Path, bytes, dict[str, Any]]:
    path, raw = _current_file(root, relative, field=field)
    return path, raw, _canonical_object(raw, field=field)


def _tokens(value: Any, *, field: str, nonempty: bool = True) -> list[str]:
    if not isinstance(value, list) or (nonempty and not value):
        raise ClosureBrokerError(f"{field} must be a non-empty array")
    result = [_token(item, field=f"{field}[]") for item in value]
    if result != sorted(set(result)):
        raise ClosureBrokerError(f"{field} must be unique and canonically sorted")
    return result


def _validate_current_artifact_rows(
    root: Path,
    rows: Any,
    *,
    evidence: bool,
) -> list[dict[str, Any]]:
    if not isinstance(rows, list) or not rows:
        raise ClosureBrokerError("current artifact denominator must be non-empty")
    normalized: list[dict[str, Any]] = []
    identities: set[str] = set()
    paths: set[str] = set()
    covered: set[str] = set()
    for ordinal, raw in enumerate(rows):
        if not isinstance(raw, Mapping):
            raise ClosureBrokerError("current artifact row must be an object")
        expected = (
            _CENTRAL_EVIDENCE_ARTIFACT_FIELDS
            if evidence
            else _CENTRAL_ARTIFACT_FIELDS
        )
        _exact_fields(raw, expected, field=f"current artifact[{ordinal}]")
        identity_field = "evidence_id" if evidence else "role"
        identity = _token(raw[identity_field], field=identity_field)
        relative = _relative_path(raw["relative_path"], field="relative_path")
        if identity in identities or relative in paths:
            raise ClosureBrokerError("current artifact denominator is ambiguous")
        identities.add(identity)
        paths.add(relative)
        _path, current = _current_file(root, relative, field="current artifact")
        digest = _hex64(raw["sha256"], field="artifact sha256")
        size = raw["size_bytes"]
        if type(size) is not int or size < 0:
            raise ClosureBrokerError("artifact size is invalid")
        if digest != _sha256(current) or size != len(current):
            raise ClosureBrokerError("current artifact bytes are stale or altered")
        row = dict(raw)
        if evidence:
            premises = _tokens(row["premise_ids"], field="artifact premise_ids")
            covered.update(premises)
        normalized.append(row)
    if normalized != sorted(normalized, key=lambda row: str(row[identity_field])):
        raise ClosureBrokerError("current artifact denominator is not canonically sorted")
    return normalized


def validate_central_subject_manifest(
    root: str | Path, raw: bytes
) -> dict[str, Any]:
    scratchpad = Path(root)
    value = _canonical_object(raw, field="central closure subject")
    _exact_fields(value, _CENTRAL_SUBJECT_FIELDS, field="central closure subject")
    if value["schema_version"] != CENTRAL_SUBJECT_SCHEMA:
        raise ClosureBrokerError("central closure subject schema mismatch")
    _token(value["run_id"], field="run_id")
    _token(value["candidate_id"], field="candidate_id")
    _token(value["work_item_id"], field="work_item_id")
    _tokens(value["candidate_premise_ids"], field="candidate_premise_ids")
    content = _hex64(value["candidate_content_sha256"], field="candidate_content_sha256")
    _tokens(value["producer_identities"], field="producer_identities")
    _tokens(value["producer_invocation_ids"], field="producer_invocation_ids")
    if value["requested_effect"] not in {
        REFUTED_FULL,
        ZERO_HARM,
        OUT_OF_SCOPE,
    }:
        raise ClosureBrokerError("central closure requested effect is unsupported")
    artifacts = _validate_current_artifact_rows(
        scratchpad, value["current_artifacts"], evidence=False
    )
    roles = {str(row["role"]): row for row in artifacts}
    if set(roles) != {"CANDIDATE", "CLAIM_MANIFEST", "SOURCE"}:
        raise ClosureBrokerError("central closure subject artifact roles are incomplete")
    if roles["CANDIDATE"]["sha256"] != content:
        raise ClosureBrokerError("candidate content digest is not current candidate bytes")
    claimed = _hex64(value["subject_digest"], field="subject_digest")
    if claimed != _payload_sha256(value, "subject_digest"):
        raise ClosureBrokerError("central closure subject digest mismatch")
    return value


def validate_central_evidence_manifest(
    root: str | Path,
    raw: bytes,
    *,
    subject: Mapping[str, Any],
) -> dict[str, Any]:
    scratchpad = Path(root)
    value = _canonical_object(raw, field="central closure evidence manifest")
    _exact_fields(value, _CENTRAL_EVIDENCE_FIELDS, field="central closure evidence manifest")
    if value["schema_version"] != CENTRAL_EVIDENCE_SCHEMA:
        raise ClosureBrokerError("central closure evidence schema mismatch")
    if value["subject_digest"] != subject["subject_digest"]:
        raise ClosureBrokerError("central closure evidence subject mismatch")
    premises = _tokens(value["premise_ids"], field="evidence premise_ids")
    domains = _tokens(value["domain_ids"], field="evidence domain_ids")
    if premises != subject["candidate_premise_ids"] or domains != premises:
        raise ClosureBrokerError("evidence does not cover the exact premise/domain denominator")
    if value["exhaustive"] is not True:
        raise ClosureBrokerError("evidence denominator is not exhaustive")
    artifacts = _validate_current_artifact_rows(
        scratchpad, value["artifacts"], evidence=True
    )
    covered = {
        premise
        for row in artifacts
        for premise in row["premise_ids"]
    }
    if covered != set(premises):
        raise ClosureBrokerError("evidence artifacts do not cover every premise")
    claimed = _hex64(value["manifest_digest"], field="manifest_digest")
    if claimed != _payload_sha256(value, "manifest_digest"):
        raise ClosureBrokerError("central closure evidence manifest digest mismatch")
    return value


def central_closure_provider_output_digest(_path: Path, raw: bytes) -> str:
    """Strict WER parser for an exact v1 terminal provider output."""

    from negative_closure_evidence_authority import PROVIDER_OUTPUT_SCHEMA as V1_SCHEMA

    value = _canonical_object(raw, field="central closure provider output")
    if value.get("schema_version") != V1_SCHEMA:
        raise ClosureBrokerError("central closure provider output schema mismatch")
    return _sha256(canonical_json_bytes(value))


def _load_arm_bindings(root: Path, completion_path: Path, completion: Mapping[str, Any]) -> Mapping[str, Any]:
    arm_name = completion.get("arm_relative_path")
    if not isinstance(arm_name, str) or "/" in arm_name or "\\" in arm_name:
        raise ClosureBrokerError("provider completion arm path is invalid")
    arm_path = completion_path.parent / arm_name
    try:
        arm = json.loads(arm_path.read_text(encoding="utf-8", errors="strict"))
    except Exception as exc:
        raise ClosureBrokerError("provider execution arm is unreadable") from exc
    if not isinstance(arm, Mapping):
        raise ClosureBrokerError("provider execution arm is malformed")
    bindings = arm.get("bindings")
    if not isinstance(bindings, Mapping):
        raise ClosureBrokerError("provider execution bindings are malformed")
    return bindings


def _validate_central_bundle(root: Path, path: Path) -> dict[str, Any]:
    try:
        relative_bundle = path.relative_to(root).as_posix()
    except ValueError as exc:
        raise ClosureBrokerError("provider bundle escapes the scratchpad") from exc
    _bundle_path, raw = _current_file(
        root,
        relative_bundle,
        field="central closure provider bundle",
    )
    bundle = _canonical_object(raw, field="central closure provider bundle")
    _exact_fields(bundle, _CENTRAL_BUNDLE_FIELDS, field="central closure provider bundle")
    if bundle["schema_version"] != CENTRAL_BUNDLE_SCHEMA:
        raise ClosureBrokerError("central closure provider bundle schema mismatch")
    _token(bundle["bundle_id"], field="bundle_id")
    if bundle["bundle_digest"] != _payload_sha256(bundle, "bundle_digest"):
        raise ClosureBrokerError("central closure provider bundle digest mismatch")

    subject_path, subject_raw = _current_file(
        root, bundle["subject_relative_path"], field="subject manifest"
    )
    subject = validate_central_subject_manifest(root, subject_raw)
    evidence_path, evidence_raw = _current_file(
        root, bundle["evidence_manifest_relative_path"], field="evidence manifest"
    )
    evidence = validate_central_evidence_manifest(
        root, evidence_raw, subject=subject
    )
    output_path, output_raw = _current_file(
        root, bundle["provider_output_relative_path"], field="provider output"
    )
    output = _canonical_object(output_raw, field="provider output")

    provider_id = str(output.get("provider_id") or "")
    spec = _CENTRAL_PROVIDER_REGISTRY.get(provider_id)
    if spec is None:
        raise ClosureBrokerError("provider is absent from the central registry")
    if (
        output.get("provider_version") != spec["provider_version"]
        or output.get("authority_kind") != spec["authority_kind"]
    ):
        raise ClosureBrokerError("central provider version/kind mismatch")

    from negative_closure_evidence_authority import _validate_provider_output
    from worker_execution_receipts import validate_completed_execution

    binding = {
        "candidate_id": subject["candidate_id"],
        "work_item_id": subject["work_item_id"],
        "candidate_premise_ids": subject["candidate_premise_ids"],
    }
    kind, claims = _validate_provider_output(
        output,
        expected_binding=binding,
        trusted_providers={
            provider_id: (spec["provider_version"], spec["authority_kind"])
        },
        live_survivors={},
    )
    if kind == "MECHANICAL_SCOPE_EXCLUSION":
        if subject["requested_effect"] != OUT_OF_SCOPE:
            raise ClosureBrokerError("mechanical provider effect mismatch")
        if output["mechanical_scope"]["evaluated_subject_sha256"] != subject["subject_digest"]:
            raise ClosureBrokerError("mechanical provider evaluated a different subject")
        effect = OUT_OF_SCOPE
    elif kind == "AUTHENTICATED_EXHAUSTIVE_NEGATIVE_EXECUTION":
        proof_scope = output["negative_execution"]["proof_scope"]
        effect = REFUTED_FULL if proof_scope == "FULL" else ZERO_HARM
        if subject["requested_effect"] != effect:
            raise ClosureBrokerError("exhaustive provider proof-scope/effect mismatch")
    else:
        raise ClosureBrokerError("provider kind requires the applied-equivalence adapter")

    evidence_rows = {row["evidence_id"]: row for row in evidence["artifacts"]}
    if {row["evidence_id"] for row in claims} != set(evidence_rows):
        raise ClosureBrokerError("provider evidence denominator is incomplete")
    for claim in claims:
        evidence_row = evidence_rows[claim["evidence_id"]]
        if (
            claim["evidence_sha256"] != evidence_row["sha256"]
            or claim["premise_ids"] != evidence_row["premise_ids"]
        ):
            raise ClosureBrokerError("provider evidence claim is stale or mismatched")
    if kind == "AUTHENTICATED_EXHAUSTIVE_NEGATIVE_EXECUTION":
        bound_hashes = {row["sha256"] for row in evidence["artifacts"]}
        negative = output["negative_execution"]
        if {
            negative["execution_assessment_sha256"],
            negative["execution_receipt_sha256"],
        } - bound_hashes:
            raise ClosureBrokerError("negative execution evidence is absent from denominator")

    completion_path, _completion_raw = _current_file(
        root, bundle["completion_receipt_relative_path"], field="completion receipt"
    )
    publish_path, _publish_raw = _current_file(
        root, bundle["publish_receipt_relative_path"], field="publish receipt"
    )
    completion = validate_completed_execution(
        scratchpad=root,
        receipt_path=completion_path,
        publish_receipt_path=publish_path,
        parser_digest=central_closure_provider_output_digest,
        expected_completion_sha256=_hex64(
            bundle["completion_sha256"], field="completion_sha256"
        ),
        expected_publish_sha256=_hex64(
            bundle["publish_sha256"], field="publish_sha256"
        ),
    )
    outputs = completion.get("outputs")
    if (
        not isinstance(outputs, list)
        or len(outputs) != 1
        or outputs[0].get("publish_relative_path")
        != output_path.relative_to(root.resolve(strict=True)).as_posix()
        or outputs[0].get("raw_sha256") != _sha256(output_raw)
    ):
        raise ClosureBrokerError("provider output is outside the exact execution denominator")
    bindings = _load_arm_bindings(root, completion_path, completion)
    input_rows = bindings.get("inputs")
    if not isinstance(input_rows, Mapping):
        raise ClosureBrokerError("provider input denominator is malformed")
    bound_paths = {
        str(row.get("relative_path"))
        for row in input_rows.values()
        if isinstance(row, Mapping)
    }
    required_inputs = {
        subject_path.relative_to(root.resolve(strict=True)).as_posix(),
        evidence_path.relative_to(root.resolve(strict=True)).as_posix(),
    }
    if not required_inputs <= bound_paths:
        raise ClosureBrokerError("provider did not bind the subject/evidence manifests")
    worker = bindings.get("worker")
    assessors = bindings.get("assessors")
    if not isinstance(worker, Mapping) or not isinstance(assessors, list):
        raise ClosureBrokerError("provider principal denominator is malformed")
    if worker.get("identity") != spec["worker_identity"]:
        raise ClosureBrokerError("provider worker identity mismatch")
    assessor_identities = {
        str(row.get("identity"))
        for row in assessors
        if isinstance(row, Mapping)
    }
    if spec["reviewer_identity"] not in assessor_identities:
        raise ClosureBrokerError("independent provider reviewer is absent")
    expected_model = f"{provider_id}@{spec['provider_version']}"
    if (
        bindings.get("effective_backend") != "closure-provider"
        or bindings.get("effective_model") != expected_model
    ):
        raise ClosureBrokerError("provider backend/model binding mismatch")
    source_identities = {
        value.casefold() for value in subject["producer_identities"]
    }
    source_invocations = {
        value.casefold() for value in subject["producer_invocation_ids"]
    }
    principals = [worker, *[row for row in assessors if isinstance(row, Mapping)]]
    if any(
        str(row.get("identity") or "").casefold() in source_identities
        or str(row.get("invocation_id") or "").casefold() in source_invocations
        for row in principals
    ):
        raise ClosureBrokerError("negative provider is not independent of the source producer")

    unsigned = {
        "schema_version": CENTRAL_DECISION_SCHEMA,
        "status": AUTHORIZED,
        "outcome": effect,
        "requested_effect": effect,
        "candidate_id": subject["candidate_id"],
        "work_item_id": subject["work_item_id"],
        "candidate_premise_ids": subject["candidate_premise_ids"],
        "candidate_content_sha256": subject["candidate_content_sha256"],
        "subject_digest": subject["subject_digest"],
        "evidence_manifest_digest": evidence["manifest_digest"],
        "provider_id": provider_id,
        "provider_kind": kind,
        "provider_completion_sha256": bundle["completion_sha256"],
        "provider_publish_sha256": bundle["publish_sha256"],
        "bundle_digest": bundle["bundle_digest"],
        "survivor_id": None,
        "survivor_identity_sha256": None,
        "reopen_required": False,
        "debt_reasons": [],
    }
    return {
        **unsigned,
        "resolution_digest": _sha256(canonical_json_bytes(unsigned)),
    }


def central_negative_closure_provider_read_set(
    scratchpad: str | Path,
) -> tuple[str, ...]:
    """Return the validated transitive file graph behind central bundles.

    Only immutable, content-addressed bundle names are registry entries.
    Unrelated directory members are operational noise and cannot expand a
    downstream semantic denominator.  A registry-shaped entry is replayed
    completely and fails closed when any referenced node is missing, unsafe,
    stale, or malformed.
    """

    from worker_execution_receipts import (
        completed_execution_scratchpad_read_set,
    )

    root_input = Path(scratchpad)
    if root_input.is_symlink() or _is_reparse(root_input):
        raise ClosureBrokerError(
            "central closure scratchpad cannot be a symlink/reparse point"
        )
    root = root_input.resolve(strict=True)
    bundle_root = root / CENTRAL_BUNDLE_DIR
    if not bundle_root.exists():
        return ()
    if (
        bundle_root.is_symlink()
        or _is_reparse(bundle_root)
        or not bundle_root.is_dir()
    ):
        raise ClosureBrokerError("provider bundle directory is unsafe")

    result: set[str] = set()

    def add(relative: Any, *, field: str) -> tuple[Path, bytes]:
        path, raw = _current_file(root, relative, field=field)
        result.add(path.relative_to(root).as_posix())
        return path, raw

    for path in sorted(bundle_root.iterdir(), key=lambda item: item.name):
        if not _CENTRAL_BUNDLE_NAME_RE.fullmatch(path.name):
            continue
        if path.is_symlink() or _is_reparse(path) or not path.is_file():
            raise ClosureBrokerError(
                "registry-shaped provider bundle path is unsafe"
            )
        # Full replay is the admission check.  The explicit walk below exposes
        # the same persisted scratchpad read graph to PhaseIO consumers.
        _validate_central_bundle(root, path)
        bundle_path, bundle_raw = add(
            f"{CENTRAL_BUNDLE_DIR}/{path.name}",
            field="central closure provider bundle",
        )
        bundle = _canonical_object(
            bundle_raw, field="central closure provider bundle"
        )
        subject_path, subject_raw = add(
            bundle["subject_relative_path"], field="subject manifest"
        )
        subject = validate_central_subject_manifest(root, subject_raw)
        for row in subject["current_artifacts"]:
            add(row["relative_path"], field="subject current artifact")
        evidence_path, evidence_raw = add(
            bundle["evidence_manifest_relative_path"],
            field="evidence manifest",
        )
        evidence = validate_central_evidence_manifest(
            root, evidence_raw, subject=subject
        )
        for row in evidence["artifacts"]:
            add(row["relative_path"], field="evidence current artifact")
        add(bundle["provider_output_relative_path"], field="provider output")
        completion_path, _completion_raw = add(
            bundle["completion_receipt_relative_path"],
            field="completion receipt",
        )
        publish_path, _publish_raw = add(
            bundle["publish_receipt_relative_path"],
            field="publish receipt",
        )
        result.update(completed_execution_scratchpad_read_set(
            scratchpad=root,
            receipt_path=completion_path,
            publish_receipt_path=publish_path,
            parser_digest=central_closure_provider_output_digest,
            expected_completion_sha256=_hex64(
                bundle["completion_sha256"], field="completion_sha256"
            ),
            expected_publish_sha256=_hex64(
                bundle["publish_sha256"], field="publish_sha256"
            ),
        ))
        # Keep the variable intentionally live: resolving the bundle path above
        # proves the entry itself remained inside the authenticated root.
        if bundle_path.parent != bundle_root:
            raise ClosureBrokerError("provider bundle root changed during replay")
    return tuple(sorted(result))


def _build_central_ledger(root: Path) -> dict[str, Any]:
    bundle_root = root / CENTRAL_BUNDLE_DIR
    denominator: list[dict[str, Any]] = []
    debt: list[dict[str, str]] = []
    decisions: list[dict[str, Any]] = []
    if bundle_root.exists() and (
        bundle_root.is_symlink()
        or _is_reparse(bundle_root)
        or not bundle_root.is_dir()
    ):
        debt.append(
            {
                "code": "BUNDLE_DENOMINATOR_INVALID",
                "detail": f"{CENTRAL_BUNDLE_DIR} is not a directory",
            }
        )
    elif bundle_root.is_dir():
        entries = sorted(bundle_root.iterdir(), key=lambda item: item.name)
        for path in entries:
            # A pre-publish crash may leave only the broker's own hidden temp;
            # it never belongs to the authority denominator.  Every other
            # entry is either a canonical JSON bundle or visible debt.
            if path.name.startswith(".bundle-") and path.name.endswith(".tmp"):
                continue
            # Only content-addressed bundle names are registry entries.
            # Diagnostics and unrelated files cannot create semantic debt or
            # denial-of-service a valid provider denominator.
            if not _CENTRAL_BUNDLE_NAME_RE.fullmatch(path.name):
                continue
            if (
                path.is_symlink()
                or _is_reparse(path)
                or not path.is_file()
                or path.suffix.casefold() != ".json"
            ):
                debt.append(
                    {
                        "code": "BUNDLE_DENOMINATOR_UNEXPECTED_ENTRY",
                        "detail": path.name[:512],
                    }
                )
                continue
            try:
                _safe_path, raw = _current_file(
                    root,
                    f"{CENTRAL_BUNDLE_DIR}/{path.name}",
                    field="central closure provider bundle",
                )
            except OSError as exc:
                debt.append(
                    {
                        "code": "BUNDLE_UNREADABLE",
                        "detail": f"{path.name}: {type(exc).__name__}",
                    }
                )
                continue
            denominator.append(
                {
                    "path": f"{CENTRAL_BUNDLE_DIR}/{path.name}",
                    "sha256": _sha256(raw),
                    "size_bytes": len(raw),
                }
            )
            try:
                decisions.append(_validate_central_bundle(root, path))
            except Exception as exc:
                debt.append(
                    {
                        "code": "BUNDLE_REPLAY_FAILED",
                        "detail": f"{path.name}: {type(exc).__name__}: {exc}"[:4096],
                    }
                )
    alias_decisions, adapter_denominator, adapter_debt = (
        _build_applied_equivalence_adapter(root)
    )
    decisions.extend(alias_decisions)
    debt.extend(adapter_debt)
    semantic: dict[tuple[Any, ...], dict[str, Any]] = {}
    for row in decisions:
        key = (
            row["candidate_id"],
            row["work_item_id"],
            tuple(row["candidate_premise_ids"]),
            row["requested_effect"],
            row["outcome"],
            row["survivor_id"],
        )
        prior = semantic.get(key)
        if prior is None:
            semantic[key] = row
        elif prior["resolution_digest"] != row["resolution_digest"]:
            debt.append(
                {
                    "code": "CONFLICTING_AUTHORITIES",
                    "detail": f"conflicting provider bundles for {row['candidate_id']}",
                }
            )
    decisions = sorted(
        semantic.values(), key=lambda row: (row["candidate_id"], row["requested_effect"])
    )
    unsigned = {
        "schema_version": CENTRAL_LEDGER_SCHEMA,
        "policy_mode": CENTRAL_BROKER_MODE,
        "root_identity": _sha256(str(root.resolve()).encode("utf-8")),
        "bundle_denominator": denominator,
        "bundle_denominator_sha256": _sha256(canonical_json_bytes(denominator)),
        "adapter_denominator": adapter_denominator,
        "adapter_denominator_sha256": _sha256(
            canonical_json_bytes(adapter_denominator)
        ),
        "decisions": decisions,
        "debt": debt,
    }
    return {**unsigned, "ledger_digest": _sha256(canonical_json_bytes(unsigned))}


def _central_metadata_identity(metadata: os.stat_result) -> tuple[int, ...]:
    """Return a replacement-sensitive identity for one replay path."""

    return (
        int(metadata.st_mode),
        int(getattr(metadata, "st_dev", 0) or 0),
        int(getattr(metadata, "st_ino", 0) or 0),
        int(metadata.st_size),
        int(getattr(metadata, "st_mtime_ns", 0) or 0),
        int(getattr(metadata, "st_ctime_ns", 0) or 0),
        int(getattr(metadata, "st_nlink", 0) or 0),
        int(getattr(metadata, "st_file_attributes", 0) or 0),
    )


def _central_revision_file(
    root: Path,
    relative: str,
    *,
    allow_missing: bool,
) -> tuple[Any, ...]:
    """Capture stable bytes plus the physical path chain for a cache join.

    Content hashing catches same-size/same-timestamp edits; the final metadata
    and ancestor identities catch byte-identical replacement and directory
    retargeting.  Missing sentinels deliberately retain their existing parent
    chain so creation also invalidates the revision.
    """

    normalized = _relative_path(relative, field="central replay revision path")
    current = root
    chain: list[tuple[str, tuple[int, ...]]] = []
    parts = normalized.split("/")
    for ordinal, part in enumerate(parts):
        current = current / part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            if allow_missing and ordinal == len(parts) - 1:
                return ("MISSING", normalized, tuple(chain))
            raise ClosureBrokerError(
                f"central replay revision path is missing: {normalized}"
            )
        if stat.S_ISLNK(metadata.st_mode) or bool(
            int(getattr(metadata, "st_file_attributes", 0) or 0) & 0x400
        ):
            raise ClosureBrokerError(
                f"central replay revision path is unsafe: {normalized}"
            )
        identity = _central_metadata_identity(metadata)
        chain.append((part, identity))
        if ordinal < len(parts) - 1 and not stat.S_ISDIR(metadata.st_mode):
            raise ClosureBrokerError(
                f"central replay revision ancestor is not a directory: {normalized}"
            )
    if not stat.S_ISREG(metadata.st_mode):
        raise ClosureBrokerError(
            f"central replay revision path is not a regular file: {normalized}"
        )
    try:
        with open(current, "rb") as stream:
            opened_before = os.fstat(stream.fileno())
            raw = stream.read()
            opened_after = os.fstat(stream.fileno())
        final = current.lstat()
    except OSError as exc:
        raise ClosureBrokerError(
            f"central replay revision path is unreadable: {normalized}"
        ) from exc
    before_identity = _central_metadata_identity(opened_before)
    opened_physical = before_identity[:4]
    lexical_physical = chain[-1][1][:4]
    if (
        before_identity != _central_metadata_identity(opened_after)
        # Windows reports a different ``st_ctime_ns`` precision/source for
        # handle-based ``fstat`` and path-based ``lstat``.  Compare the exact
        # two observations within each API, then join them by physical
        # device/inode/size/mode identity.
        or _central_metadata_identity(final) != chain[-1][1]
        or opened_physical != lexical_physical
    ):
        raise ClosureBrokerError(
            f"central replay revision path changed while read: {normalized}"
        )
    return (
        "FILE",
        normalized,
        tuple(chain),
        len(raw),
        _sha256(raw),
    )


def _central_bundle_membership_revision(root: Path) -> tuple[Any, ...]:
    """Capture the exact registry-shaped bundle directory denominator."""

    bundle_root = root / CENTRAL_BUNDLE_DIR
    try:
        metadata = bundle_root.lstat()
    except FileNotFoundError:
        return ("MISSING", CENTRAL_BUNDLE_DIR)
    if (
        stat.S_ISLNK(metadata.st_mode)
        or bool(int(getattr(metadata, "st_file_attributes", 0) or 0) & 0x400)
        or not stat.S_ISDIR(metadata.st_mode)
    ):
        raise ClosureBrokerError("provider bundle directory is unsafe")
    names = tuple(
        sorted(
            entry.name
            for entry in bundle_root.iterdir()
            if _CENTRAL_BUNDLE_NAME_RE.fullmatch(entry.name)
        )
    )
    final = bundle_root.lstat()
    if _central_metadata_identity(metadata) != _central_metadata_identity(final):
        raise ClosureBrokerError("provider bundle directory changed during revision")
    return (
        "DIRECTORY",
        CENTRAL_BUNDLE_DIR,
        _central_metadata_identity(final),
        names,
    )


@dataclass(frozen=True)
class _CentralReplayCacheEntry:
    """One fully replayed projection bound to immutable current inputs."""

    root_identity: tuple[int, ...]
    bundle_membership: tuple[Any, ...]
    watched_paths: tuple[tuple[str, bool, tuple[Any, ...]], ...]
    ledger_bytes: bytes

    def is_current(self, root: Path) -> bool:
        try:
            root_metadata = root.lstat()
            if (
                stat.S_ISLNK(root_metadata.st_mode)
                or bool(
                    int(getattr(root_metadata, "st_file_attributes", 0) or 0)
                    & 0x400
                )
                or not stat.S_ISDIR(root_metadata.st_mode)
                or _central_metadata_identity(root_metadata) != self.root_identity
                or _central_bundle_membership_revision(root)
                != self.bundle_membership
            ):
                return False
            for relative, allow_missing, expected in self.watched_paths:
                if (
                    _central_revision_file(
                        root, relative, allow_missing=allow_missing
                    )
                    != expected
                ):
                    return False
        except (ClosureBrokerError, OSError):
            return False
        return True


def _central_cache_key(root: Path) -> str:
    return os.path.normcase(os.path.abspath(os.fspath(root)))


def _central_cache_lookup(root: Path) -> dict[str, Any] | None:
    key = _central_cache_key(root)
    with _CENTRAL_REPLAY_CACHE_LOCK:
        entry = _CENTRAL_REPLAY_CACHE.get(key)
    if entry is None or not entry.is_current(root):
        if entry is not None:
            with _CENTRAL_REPLAY_CACHE_LOCK:
                if _CENTRAL_REPLAY_CACHE.get(key) is entry:
                    _CENTRAL_REPLAY_CACHE.pop(key, None)
        return None
    with _CENTRAL_REPLAY_CACHE_LOCK:
        if _CENTRAL_REPLAY_CACHE.get(key) is entry:
            _CENTRAL_REPLAY_CACHE.move_to_end(key)
    return json.loads(entry.ledger_bytes.decode("utf-8", errors="strict"))


def _central_cache_store(root: Path, ledger: Mapping[str, Any]) -> None:
    """Publish a cache entry only for a completely replayable denominator."""

    # Debt projections are cheap failure observations, not immutable authority.
    # Replaying them preserves prompt recovery when a missing/malformed input is
    # repaired without touching the artifact ledger.
    if ledger.get("debt"):
        return
    try:
        from artifact_ledger import LEDGER_NAME as ARTIFACT_LEDGER_NAME
        from semantic_dedup_authority import (
            PRIMARY_RECEIPT_NAME,
            SUPPLEMENTAL_RECEIPT_NAME,
        )

        provider_paths = set(central_negative_closure_provider_read_set(root))
        adapter_paths = {
            str(row.get("path") or "")
            for row in ledger.get("adapter_denominator", [])
            if isinstance(row, Mapping) and str(row.get("path") or "")
        }
        required_paths = provider_paths | adapter_paths
        sentinel_paths = {
            ARTIFACT_LEDGER_NAME,
            CENTRAL_LEDGER_NAME,
            PRIMARY_RECEIPT_NAME,
            SUPPLEMENTAL_RECEIPT_NAME,
        }
        watched: list[tuple[str, bool, tuple[Any, ...]]] = []
        for relative in sorted(required_paths | sentinel_paths):
            allow_missing = relative in sentinel_paths and relative not in required_paths
            watched.append(
                (
                    relative,
                    allow_missing,
                    _central_revision_file(
                        root, relative, allow_missing=allow_missing
                    ),
                )
            )
        root_metadata = root.lstat()
        entry = _CentralReplayCacheEntry(
            root_identity=_central_metadata_identity(root_metadata),
            bundle_membership=_central_bundle_membership_revision(root),
            watched_paths=tuple(watched),
            ledger_bytes=canonical_json_bytes(dict(ledger)),
        )
        # Close the capture window before publishing.  A concurrent mutation
        # simply leaves the prior entry absent and forces another full replay.
        if not entry.is_current(root):
            return
    except (ClosureBrokerError, OSError, ValueError, TypeError):
        return
    key = _central_cache_key(root)
    with _CENTRAL_REPLAY_CACHE_LOCK:
        _CENTRAL_REPLAY_CACHE[key] = entry
        _CENTRAL_REPLAY_CACHE.move_to_end(key)
        while len(_CENTRAL_REPLAY_CACHE) > _CENTRAL_REPLAY_CACHE_LIMIT:
            _CENTRAL_REPLAY_CACHE.popitem(last=False)


# Tests and defensive callers sometimes instrument the builder to create a
# mutation inside the replay window.  Such instrumentation must exercise the
# replay itself, not be hidden by an entry created before instrumentation.
_CENTRAL_BUILD_IMPLEMENTATION = _build_central_ledger


def _replay_central_ledger(root: Path) -> dict[str, Any]:
    """Rebuild the current ledger and bind any persisted projection.

    This is intentionally shared by load and every resolution.  A persisted
    ledger is a projection, not a cache that can survive changes to its exact
    provider/adapter denominator.
    """

    root_input = Path(root)
    if root_input.is_symlink() or _is_reparse(root_input):
        raise ClosureBrokerError(
            "central closure scratchpad cannot be a symlink/reparse point"
        )
    resolved_root = root_input.resolve(strict=True)
    if not resolved_root.is_dir():
        raise ClosureBrokerError("central closure scratchpad is not a directory")
    if _build_central_ledger is _CENTRAL_BUILD_IMPLEMENTATION:
        cached = _central_cache_lookup(resolved_root)
        if cached is not None:
            return cached
    first = _build_central_ledger(resolved_root)
    ledger = _build_central_ledger(resolved_root)
    if first != ledger:
        # This cannot make a negative terminal: retain the second/current
        # observation but globally veto it with visible replay debt.  A later
        # stable call can recover without a halt.
        ledger = dict(ledger)
        ledger["debt"] = [
            *ledger["debt"],
            {
                "code": "CONCURRENT_DENOMINATOR_MUTATION",
                "detail": "central closure inputs changed during replay",
            },
        ]
        unsigned = {
            key: value for key, value in ledger.items() if key != "ledger_digest"
        }
        ledger["ledger_digest"] = _sha256(canonical_json_bytes(unsigned))
    persisted = resolved_root / CENTRAL_LEDGER_NAME
    if persisted.is_file():
        try:
            existing = _canonical_object(
                persisted.read_bytes(), field="persisted central closure ledger"
            )
        except Exception:
            existing = None
        if existing != ledger:
            ledger = dict(ledger)
            ledger["debt"] = [
                *ledger["debt"],
                {
                    "code": "PERSISTED_LEDGER_STALE_OR_TAMPERED",
                    "detail": CENTRAL_LEDGER_NAME,
                },
            ]
            unsigned = {
                key: value for key, value in ledger.items() if key != "ledger_digest"
            }
            ledger["ledger_digest"] = _sha256(canonical_json_bytes(unsigned))
    if _build_central_ledger is _CENTRAL_BUILD_IMPLEMENTATION:
        _central_cache_store(resolved_root, ledger)
    return ledger


def load_central_negative_closure_authority(
    scratchpad: str | Path,
) -> CentralNegativeClosureAuthority:
    root = Path(scratchpad)
    ledger = _replay_central_ledger(root)
    return CentralNegativeClosureAuthority(
        ledger,
        root=root,
        _token=_CENTRAL_CONSTRUCTION_TOKEN,
    )


def write_central_negative_closure_authority(
    scratchpad: str | Path,
) -> CentralNegativeClosureAuthority:
    """Replay and atomically publish the exact central ledger.

    A crash before ``os.replace`` leaves the prior ledger (or no ledger) and a
    temporary file.  The next call recomputes from immutable provider bundles;
    no partial ledger is ever treated as authority.
    """

    root = Path(scratchpad)
    if not root.is_dir():
        raise ClosureBrokerError("central closure scratchpad is not a directory")
    ledger = _build_central_ledger(root)
    raw = canonical_json_bytes(ledger)
    target = root / CENTRAL_LEDGER_NAME
    temporary = root / f".{CENTRAL_LEDGER_NAME}.{os.getpid()}.tmp"
    try:
        with open(temporary, "xb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    finally:
        try:
            temporary.unlink()
        except OSError:
            pass
    # Re-read the published projection and every current provider input before
    # returning a usable resolver.  This closes the publish-to-consume window.
    replayed = _replay_central_ledger(root)
    return CentralNegativeClosureAuthority(
        replayed,
        root=root,
        _token=_CENTRAL_CONSTRUCTION_TOKEN,
    )


def resolve_central_negative_closure(
    closure_authority: Any,
    *,
    work_item: Mapping[str, Any],
    requested_effect: str,
) -> dict[str, Any]:
    """Resolve only through the exact loader-owned central implementation.

    Exact type is necessary but not sufficient: the instance itself performs a
    fresh root-bound replay on every call.  Subclasses, duck-typed callbacks,
    mappings, and construction-time snapshots therefore cannot mint terminal
    negative state.
    """

    if type(closure_authority) is not CentralNegativeClosureAuthority:
        return {
            "schema_version": CENTRAL_DECISION_SCHEMA,
            "status": DEBT,
            "outcome": NO_AUTHORITY,
            "requested_effect": requested_effect,
            "candidate_id": str(
                work_item.get("candidate_negative_family_id")
                or work_item.get("candidate_id")
                or work_item.get("work_item_id")
                or ""
            ),
            "work_item_id": str(work_item.get("work_item_id") or ""),
            "candidate_premise_ids": list(
                work_item.get("candidate_premise_ids") or []
            ),
            "reopen_required": True,
            "debt_reasons": ["CENTRAL_NEGATIVE_CLOSURE_AUTHORITY_INVALID"],
            "resolution_digest": "",
        }
    return closure_authority.resolve(
        work_item=work_item,
        requested_effect=requested_effect,
    )


def register_completed_negative_closure_provider(
    scratchpad: str | Path,
    *,
    bundle_id: str,
    subject_relative_path: str,
    evidence_manifest_relative_path: str,
    provider_output_relative_path: str,
    completed_execution: Any,
) -> Path:
    """Register an already-observed provider completion for broker replay.

    This is the controlled creation path shared by mechanical-scope and
    exhaustive-negative providers.  It does not launch or trust a model and it
    cannot register prose: the opaque completion/publish handles must replay
    through :mod:`worker_execution_receipts` and the code-owned provider
    registry before the bundle is atomically published.  Consequently, the
    mere existence of this API does not make exhaustive closure operational;
    a driver-owned provider launch must first produce ``completed_execution``.
    """

    root = Path(scratchpad)
    if not root.is_dir():
        raise ClosureBrokerError("central closure scratchpad is not a directory")
    bundle_id = _token(bundle_id, field="bundle_id")
    completion_path = Path(getattr(completed_execution, "receipt_path", ""))
    publish_path = Path(
        getattr(completed_execution, "publish_receipt_path", "")
    )
    try:
        completion_relative = completion_path.resolve(strict=True).relative_to(
            root.resolve(strict=True)
        ).as_posix()
        publish_relative = publish_path.resolve(strict=True).relative_to(
            root.resolve(strict=True)
        ).as_posix()
    except (OSError, ValueError) as exc:
        raise ClosureBrokerError(
            "provider completion handles are outside the scratchpad"
        ) from exc
    unsigned = {
        "schema_version": CENTRAL_BUNDLE_SCHEMA,
        "bundle_id": bundle_id,
        "subject_relative_path": _relative_path(
            subject_relative_path, field="subject_relative_path"
        ),
        "evidence_manifest_relative_path": _relative_path(
            evidence_manifest_relative_path,
            field="evidence_manifest_relative_path",
        ),
        "provider_output_relative_path": _relative_path(
            provider_output_relative_path, field="provider_output_relative_path"
        ),
        "completion_receipt_relative_path": completion_relative,
        "completion_sha256": str(
            getattr(completed_execution, "completion_sha256", "")
        ),
        "publish_receipt_relative_path": publish_relative,
        "publish_sha256": str(
            getattr(completed_execution, "publish_sha256", "")
        ),
    }
    bundle = {
        **unsigned,
        "bundle_digest": _sha256(canonical_json_bytes(unsigned)),
    }
    bundle_root = root / CENTRAL_BUNDLE_DIR
    if bundle_root.exists() and (
        bundle_root.is_symlink()
        or _is_reparse(bundle_root)
        or not bundle_root.is_dir()
    ):
        raise ClosureBrokerError("provider bundle directory is unsafe")
    bundle_root.mkdir(parents=True, exist_ok=True)
    if bundle_root.is_symlink() or _is_reparse(bundle_root):
        raise ClosureBrokerError("provider bundle directory is unsafe")
    name = f"bundle-{_sha256(bundle_id.encode('utf-8'))[:24]}.json"
    destination = bundle_root / name
    raw = canonical_json_bytes(bundle)
    if destination.exists() and (
        destination.is_symlink()
        or _is_reparse(destination)
        or not destination.is_file()
    ):
        raise ClosureBrokerError("immutable provider bundle path is unsafe")
    if destination.is_file():
        if destination.read_bytes() == raw:
            _validate_central_bundle(root, destination)
            return destination
        raise ClosureBrokerError(
            f"immutable provider bundle conflict for {bundle_id}"
        )
    temporary = bundle_root / f".{name}.{os.getpid()}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    fd = os.open(str(temporary), flags, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=True) as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        # Replay before publication; a crash leaves only an ignored temp file.
        _validate_central_bundle(root, temporary)
        os.replace(temporary, destination)
    except Exception:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise
    return destination


__all__ = [
    "ALIAS_TO_SURVIVOR",
    "AUTHORIZED",
    "BROKER_MODE",
    "CENTRAL_BROKER_MODE",
    "CENTRAL_APPLIED_EQUIVALENCE_PROVIDER",
    "CENTRAL_BUNDLE_SCHEMA",
    "CENTRAL_BUNDLE_DIR",
    "CENTRAL_DECISION_SCHEMA",
    "CENTRAL_EVIDENCE_SCHEMA",
    "CENTRAL_LEDGER_NAME",
    "central_negative_closure_provider_read_set",
    "CENTRAL_LEDGER_SCHEMA",
    "CENTRAL_SUBJECT_SCHEMA",
    "CLAIM_RESOLUTION",
    "ClosureAuthorityBrokerV2",
    "ClosureBrokerError",
    "CentralNegativeClosureAuthority",
    "DEBT",
    "HARM_RESOLUTION",
    "IDENTITY_RESOLUTION",
    "NO_AUTHORITY",
    "OUT_OF_SCOPE",
    "PROVIDER_OUTPUT_SCHEMA",
    "PROVIDER_RECEIPT_SCHEMA",
    "REFUTED_FULL",
    "SCOPE_RESOLUTION",
    "SUBJECT_SCHEMA",
    "UNRESOLVED",
    "ZERO_HARM",
    "canonical_json_bytes",
    "central_closure_provider_output_digest",
    "provider_registry_snapshot",
    "register_completed_negative_closure_provider",
    "load_central_negative_closure_authority",
    "resolve_central_negative_closure",
    "strict_json_loads",
    "subject_sha256",
    "validate_central_evidence_manifest",
    "validate_central_subject_manifest",
    "validate_subject_manifest",
    "write_central_negative_closure_authority",
]
