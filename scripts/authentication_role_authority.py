"""Typed EVM-first arm-before-trust role and composition authority.

The module is deliberately isolated from scheduling, PhaseIO, and P0-AF.  It
accepts only a digest-bound typed operator trace as positive authority.  Regex
classification of prose is retained solely as a compatibility nominator and
can never satisfy a composition predicate.

An out-of-scope role remains externally unknown.  It creates a bounded,
candidate-scoped research obligation without asserting favorable or adverse
external semantics.  Non-EVM activation is explicitly held until governed
cross-ecosystem evidence exists.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


FACT_TRACE_SCHEMA = "plamen.authentication_role_fact_trace.v1"
FACT_AUTHORITY_SCHEMA = "plamen.authentication_role_fact_authority.v1"
COMPOSITION_SCHEMA = "plamen.arm_before_trust_composition_obligations.v1"
EXTERNAL_RESEARCH_SCHEMA = "plamen.authentication_external_research_obligations.v1"

TRACE_FILE = "authentication_role_facts.input.json"
AUTHORITY_FILE = "authentication_role_authority.json"
COMPOSITION_FILE = "arm_before_trust_composition_obligations.json"
EXTERNAL_RESEARCH_FILE = "authentication_external_research_obligations.json"
PROJECTION_FILE = "authentication_role_obligations.md"

_CHECKPOINT_FILE = "_v2_checkpoint.json"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_UUID4 = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_TRACE_KEYS = {
    "schema_version",
    "run_binding_digest",
    "ecosystem",
    "operator_id",
    "operator_digest",
    "facts",
    "payload_digest",
}
_FACT_KEYS = {
    "producer_fact_id",
    "role",
    "trust_domain_id",
    "polarity",
    "provenance",
    "anchor_identity",
    "anchor_default",
    "derived_identity",
    "degenerate_input_domain",
    "privileged_effect",
    "evidence",
    "external_dependency",
    "external_surface",
}
_EVIDENCE_KEYS = {"claim", "locus", "result"}
_ROLES = {"ANCHOR", "DERIVED_IDENTITY"}
_POLARITIES = {"POSITIVE", "REFUTED", "UNKNOWN"}
_PROVENANCE = {"IN_SCOPE", "EXTERNAL"}

_ANCHOR_REQUIRED = {
    "UNARMED_DEFAULT",
    "OPERATIONAL_WHILE_UNARMED",
    "PRIVILEGED_EFFECT_REACHABLE",
}
_DERIVED_REQUIRED = {
    "DEGENERATE_INPUT_IN_DOMAIN",
    "DERIVES_DEFAULT_IDENTITY",
    "DEFAULT_IDENTITY_ACCEPTED",
    "PRIVILEGED_EFFECT_REACHABLE",
}
_ANCHOR_REFUTATIONS = {
    "ATOMICALLY_ARMED",
    "INERT_UNTIL_ARMED",
    "NONZERO_REQUIRED",
    "DEARM_ATOMIC_OR_INERT",
}
_DERIVED_REFUTATIONS = {
    "DEGENERATE_INPUT_REJECTED",
    "DEFAULT_IDENTITY_REJECTED",
    "FAIL_CLOSED",
    "PRIVILEGED_EFFECT_UNREACHABLE",
}
_OPTIONAL_CLAIMS = {"DEARM_REACHES_UNARMED", "ARMING_PATH_EXISTS"}
_ALL_CLAIMS = (
    _ANCHOR_REQUIRED
    | _DERIVED_REQUIRED
    | _ANCHOR_REFUTATIONS
    | _DERIVED_REFUTATIONS
    | _OPTIONAL_CLAIMS
)
_IN_SCOPE_LOCUS = re.compile(
    r"^[A-Za-z0-9_./\\ -]+\.(?:sol|vy):L[1-9]\d*(?:-L?[1-9]\d*)?$"
)
_EXTERNAL_LOCUS = re.compile(r"^https?://\S+$|^[A-Za-z0-9_./\\ -]+:[Ll][1-9]\d*$")

_PROSE_ANCHOR = re.compile(
    r"\b(?:auth(?:entication|orization)?\s+)?(?:anchor|authority)|"
    r"\b(?:verifying|signer|guardian|committee|admin)\s+(?:key|set|root)",
    re.IGNORECASE,
)
_PROSE_UNARMED = re.compile(
    r"\b(?:defaults?\s+(?:to\s+)?(?:zero|empty|null)|unset|uninitialized|"
    r"uninitialised|unarmed)\b",
    re.IGNORECASE,
)
_PROSE_OPERATIONAL = re.compile(
    r"\b(?:remain(?:s)?\s+(?:operational|reachable)|"
    r"operations?\s+remain(?:s)?\s+reachable|still\s+(?:run|succeed|operate))\b",
    re.IGNORECASE,
)
_PROSE_DERIVED = re.compile(
    r"\b(?:degenerate|empty|zero[- ]length|all[- ]zero)\s+"
    r"(?:proof|signature|witness|input)|"
    r"\bderive[sd]?\b.{0,50}\b(?:zero|null|empty)\b",
    re.IGNORECASE,
)
_PROSE_ACCEPTED = re.compile(
    r"\b(?:accept(?:s|ed)?|authori[sz](?:e|es|ed)|passes?|succeed(?:s|ed)?)\b",
    re.IGNORECASE,
)


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _pretty_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")


def trace_payload_digest(payload: Mapping[str, Any]) -> str:
    return _sha256(
        {key: value for key, value in payload.items() if key != "payload_digest"}
    )


def _finalize(payload: dict[str, Any], field: str) -> dict[str, Any]:
    payload[field] = _sha256(
        {key: value for key, value in payload.items() if key != field}
    )
    return payload


def _normalize_ecosystem(value: object) -> str:
    return re.sub(r"[^a-z0-9_]+", "", str(value or "").strip().lower()) or "unknown"


def run_binding_digest(
    run_id: str,
    source_snapshot_digest: str,
    source_scope_digest: str,
    ecosystem: str,
    mode: str,
    pipeline: str,
) -> str:
    binding = {
        "run_id": str(run_id or "").strip().lower(),
        "source_snapshot_digest": str(source_snapshot_digest or "").strip().lower(),
        "source_scope_digest": str(source_scope_digest or "").strip().lower(),
        "ecosystem": _normalize_ecosystem(ecosystem),
        "mode": str(mode or "unknown").strip().lower(),
        "pipeline": str(pipeline or "unknown").strip().lower(),
    }
    return _sha256(binding)


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8", errors="strict"))


def _load_run_binding(
    root: Path,
    *,
    ecosystem: str = "",
    mode: str = "",
    run_id: str = "",
    source_snapshot_digest: str = "",
) -> tuple[dict[str, str], list[str]]:
    issues: list[str] = []
    checkpoint: Mapping[str, Any] = {}
    path = root / _CHECKPOINT_FILE
    if path.is_file():
        try:
            raw = _load_json(path)
            if isinstance(raw, Mapping):
                checkpoint = raw
            else:
                issues.append("checkpoint root is not an object")
        except Exception as exc:
            issues.append(f"checkpoint parse failed: {type(exc).__name__}")
    else:
        issues.append("checkpoint missing")
    config = checkpoint.get("config") if isinstance(checkpoint.get("config"), Mapping) else {}
    snapshot = checkpoint.get("audit_snapshot") if isinstance(checkpoint.get("audit_snapshot"), Mapping) else {}
    components = snapshot.get("components") if isinstance(snapshot.get("components"), Mapping) else {}
    source_scope = components.get("source_scope") if isinstance(components.get("source_scope"), Mapping) else {}

    checkpoint_run = str(checkpoint.get("run_id") or "").strip().lower()
    chosen_run = str(run_id or checkpoint_run).strip().lower()
    if run_id and checkpoint_run and chosen_run != checkpoint_run:
        issues.append("explicit run_id differs from checkpoint run_id")
    if not _UUID4.fullmatch(chosen_run):
        issues.append("run_id is missing or invalid")
    checkpoint_snapshot = str(snapshot.get("snapshot_digest") or "").strip().lower()
    chosen_snapshot = str(source_snapshot_digest or checkpoint_snapshot).strip().lower()
    if source_snapshot_digest and checkpoint_snapshot and chosen_snapshot != checkpoint_snapshot:
        issues.append("explicit source snapshot differs from checkpoint snapshot")
    if not _HEX64.fullmatch(chosen_snapshot):
        issues.append("source snapshot digest is missing or invalid")
    scope_digest = str(source_scope.get("digest") or "").strip().lower()
    if not _HEX64.fullmatch(scope_digest):
        issues.append("source scope digest is missing or invalid")
    binding: dict[str, str] = {
        "run_id": chosen_run,
        "source_snapshot_digest": chosen_snapshot,
        "source_scope_digest": scope_digest,
        "ecosystem": _normalize_ecosystem(ecosystem or config.get("language")),
        "mode": str(mode or config.get("mode") or "unknown").strip().lower(),
        "pipeline": str(config.get("pipeline") or "unknown").strip().lower(),
    }
    binding["binding_digest"] = run_binding_digest(
        binding["run_id"],
        binding["source_snapshot_digest"],
        binding["source_scope_digest"],
        binding["ecosystem"],
        binding["mode"],
        binding["pipeline"],
    )
    return binding, issues


def _binding(path: Path, role: str) -> dict[str, Any]:
    data = path.read_bytes()
    return {
        "artifact": path.name,
        "role": role,
        "sha256": hashlib.sha256(data).hexdigest(),
        "byte_count": len(data),
    }


def _clean(value: object, limit: int = 500) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()[:limit]


def _stable_id(prefix: str, value: object, length: int = 20) -> str:
    return f"{prefix}-{_sha256(value)[:length].upper()}"


def _boundary_kind(value: object) -> str:
    text = re.sub(r"[^a-z0-9]+", "", str(value or "").casefold())
    if not text:
        return ""
    if text in {
        "0",
        "zero",
        "null",
        "zeroaddress",
        "address0",
        "bytes320",
        "0x0",
        "0x0000000000000000000000000000000000000000",
    } or set(text.removeprefix("0x")) <= {"0"}:
        return "ZERO"
    if text in {"empty", "emptyset", "zerolength", "emptybytes"}:
        return "EMPTY"
    return ""


def _valid_locus(value: object, provenance: str) -> bool:
    text = str(value or "").strip()
    if provenance == "EXTERNAL":
        return bool(_EXTERNAL_LOCUS.fullmatch(text))
    return bool(_IN_SCOPE_LOCUS.fullmatch(text))


def nominate_compatibility_roles(text: str) -> list[str]:
    """Return recall-only prose nominations with no positive authority."""
    normalized = _clean(text, 4_000)
    roles: list[str] = []
    if (
        _PROSE_ANCHOR.search(normalized)
        and _PROSE_UNARMED.search(normalized)
        and _PROSE_OPERATIONAL.search(normalized)
    ):
        roles.append("ANCHOR")
    if _PROSE_DERIVED.search(normalized) and _PROSE_ACCEPTED.search(normalized):
        roles.append("DERIVED_IDENTITY")
    return roles


def _compatibility_nominations(
    entries: Sequence[Mapping[str, Any]] | None,
) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for index, entry in enumerate(entries or []):
        if not isinstance(entry, Mapping):
            continue
        candidate_id = _clean(entry.get("candidate_id")) or f"COMPAT-{index + 1}"
        text = _clean(entry.get("text"), 4_000)
        for role in nominate_compatibility_roles(text):
            rows.append(
                {
                    "nomination_id": _stable_id(
                        "AUTHNOM", {"candidate_id": candidate_id, "role": role}
                    ),
                    "candidate_id": candidate_id,
                    "role": role,
                    "authority": "NOMINATION_ONLY",
                    "reason": "legacy prose regex nomination requires typed operator application",
                }
            )
    return sorted(rows, key=lambda row: (row["candidate_id"], row["role"]))


def _normalize_evidence(
    raw: object, provenance: str
) -> tuple[list[dict[str, str]], list[str]]:
    issues: list[str] = []
    rows: list[dict[str, str]] = []
    if not isinstance(raw, list):
        return [], ["evidence is not an array"]
    for index, value in enumerate(raw):
        if not isinstance(value, Mapping) or set(value) != _EVIDENCE_KEYS:
            issues.append(f"evidence row {index} schema mismatch")
            continue
        claim = _clean(value.get("claim")).upper()
        locus = _clean(value.get("locus"))
        result = _clean(value.get("result"), 1_000)
        if claim not in _ALL_CLAIMS:
            issues.append(f"unknown evidence claim: {claim or '<empty>'}")
        if not _valid_locus(locus, provenance):
            issues.append(f"invalid {provenance.lower()} evidence locus: {locus or '<empty>'}")
        if not result or result.casefold() in {"none", "n/a", "unknown", "tbd", "-"}:
            issues.append(f"evidence result is missing for claim: {claim or '<empty>'}")
        rows.append({"claim": claim, "locus": locus, "result": result})
    rows.sort(key=lambda row: (row["claim"], row["locus"], row["result"]))
    return rows, issues


def _fact_identity(raw: Mapping[str, Any], operator_digest: str) -> str:
    role = _clean(raw.get("role")).upper()
    subject = (
        _clean(raw.get("anchor_identity"))
        if role == "ANCHOR"
        else _clean(raw.get("derived_identity"))
    )
    return _stable_id(
        "AUTHF",
        {
            "role": role,
            "trust_domain_id": _clean(raw.get("trust_domain_id")),
            "subject": subject,
            "privileged_effect": _clean(raw.get("privileged_effect")),
            "operator_id_namespace": operator_digest[:16],
        },
    )


def _normalize_fact(
    raw: Mapping[str, Any],
    *,
    operator_id: str,
    operator_digest: str,
    run_binding: Mapping[str, str],
    trace_valid: bool,
) -> dict[str, Any]:
    issues: list[str] = []
    if set(raw) != _FACT_KEYS:
        issues.append("fact schema fields mismatch")
    role = _clean(raw.get("role")).upper()
    polarity = _clean(raw.get("polarity")).upper()
    provenance = _clean(raw.get("provenance")).upper()
    if role not in _ROLES:
        issues.append("fact role is invalid")
    if polarity not in _POLARITIES:
        issues.append("fact polarity is invalid")
    if provenance not in _PROVENANCE:
        issues.append("fact provenance is invalid")
        provenance = "IN_SCOPE"
    trust_domain = _clean(raw.get("trust_domain_id"))
    effect = _clean(raw.get("privileged_effect"))
    anchor_identity = _clean(raw.get("anchor_identity"))
    anchor_default = _clean(raw.get("anchor_default"))
    derived_identity = _clean(raw.get("derived_identity"))
    degenerate_domain = _clean(raw.get("degenerate_input_domain"))
    if not trust_domain:
        issues.append("trust domain identity is missing")
    if not effect:
        issues.append("privileged effect identity is missing")
    if role == "ANCHOR":
        if not anchor_identity or not _boundary_kind(anchor_default):
            issues.append("anchor identity or zero/empty default is missing")
    elif role == "DERIVED_IDENTITY":
        if not _boundary_kind(derived_identity) or not degenerate_domain:
            issues.append("derived default identity or degenerate input domain is missing")
    external_dependency = _clean(raw.get("external_dependency"))
    external_surface = _clean(raw.get("external_surface"))
    if provenance == "EXTERNAL" and (not external_dependency or not external_surface):
        issues.append("external provenance lacks dependency or integration surface")
    if provenance == "IN_SCOPE" and (external_dependency or external_surface):
        issues.append("in-scope fact carries contradictory external provenance")

    evidence, evidence_issues = _normalize_evidence(raw.get("evidence"), provenance)
    issues.extend(evidence_issues)
    producer_claims = sorted({row["claim"] for row in evidence})
    required = _ANCHOR_REQUIRED if role == "ANCHOR" else _DERIVED_REQUIRED
    refutations = _ANCHOR_REFUTATIONS if role == "ANCHOR" else _DERIVED_REFUTATIONS
    positive_complete = required <= set(producer_claims)
    refutation_claims = sorted(set(producer_claims) & refutations)
    if not trace_valid or issues:
        authority_state = "UNMEASURABLE"
        positive_claims = []
        external_semantics = "UNKNOWN" if provenance == "EXTERNAL" else "NOT_APPLICABLE"
    elif provenance == "EXTERNAL":
        authority_state = "EXTERNAL_UNRESOLVED"
        positive_claims: list[str] = []
        external_semantics = "UNKNOWN"
    elif positive_complete and refutation_claims:
        authority_state = "CONFLICT"
        positive_claims = sorted(required)
        external_semantics = "NOT_APPLICABLE"
    elif polarity == "POSITIVE" and positive_complete:
        authority_state = "POSITIVE"
        positive_claims = sorted(required)
        external_semantics = "NOT_APPLICABLE"
    elif refutation_claims and polarity in {"REFUTED", "UNKNOWN"}:
        authority_state = "REFUTED"
        positive_claims = []
        external_semantics = "NOT_APPLICABLE"
    elif refutation_claims:
        authority_state = "CONFLICT"
        positive_claims = []
        external_semantics = "NOT_APPLICABLE"
    else:
        authority_state = "UNMEASURABLE"
        positive_claims = []
        external_semantics = "NOT_APPLICABLE"
        if not positive_complete:
            issues.append(
                "required positive claims missing: "
                + ", ".join(sorted(required - set(producer_claims)))
            )

    def selected(claims: set[str]) -> list[dict[str, str]]:
        return [row for row in evidence if row["claim"] in claims]

    fact = {
        "fact_id": _fact_identity(raw, operator_digest),
        "producer_fact_id": _clean(raw.get("producer_fact_id")),
        "role": role,
        "trust_domain_id": trust_domain,
        "polarity": polarity,
        "provenance": provenance,
        "authority_state": authority_state,
        "anchor_identity": anchor_identity,
        "anchor_default": anchor_default,
        "derived_identity": derived_identity,
        "degenerate_input_domain": degenerate_domain,
        "boundary_kind": _boundary_kind(anchor_default or derived_identity),
        "privileged_effect": effect,
        "operator_id": operator_id,
        "operator_digest": operator_digest,
        "run_binding_digest": str(run_binding.get("binding_digest") or ""),
        "producer_claims": producer_claims,
        "positive_claims": positive_claims,
        "refutation_claims": refutation_claims,
        "evidence": evidence,
        "operational_unarmed_evidence": selected({"OPERATIONAL_WHILE_UNARMED"}),
        "arming_evidence": selected(
            {"ARMING_PATH_EXISTS", "ATOMICALLY_ARMED", "INERT_UNTIL_ARMED", "NONZERO_REQUIRED"}
        ),
        "dearming_evidence": selected(
            {"DEARM_REACHES_UNARMED", "DEARM_ATOMIC_OR_INERT"}
        ),
        "fail_closed_evidence": selected(_DERIVED_REFUTATIONS),
        "derivation_evidence": selected(
            {
                "DEGENERATE_INPUT_IN_DOMAIN",
                "DERIVES_DEFAULT_IDENTITY",
                "DEFAULT_IDENTITY_ACCEPTED",
                "DEGENERATE_INPUT_REJECTED",
                "DEFAULT_IDENTITY_REJECTED",
            }
        ),
        "privileged_effect_evidence": selected(
            {"PRIVILEGED_EFFECT_REACHABLE", "PRIVILEGED_EFFECT_UNREACHABLE"}
        ),
        "external_dependency": external_dependency,
        "external_surface": external_surface,
        "external_semantics_asserted": external_semantics,
        "issues": sorted(set(issues)),
    }
    fact["fact_digest"] = _sha256(fact)
    return fact


def _validate_trace(
    payload: Mapping[str, Any] | None, run_binding: Mapping[str, str]
) -> tuple[bool, list[str]]:
    if payload is None:
        return False, ["typed authentication-role trace is missing"]
    issues: list[str] = []
    if set(payload) != _TRACE_KEYS:
        issues.append("typed trace schema fields mismatch")
    if payload.get("schema_version") != FACT_TRACE_SCHEMA:
        issues.append("typed trace schema version mismatch")
    if payload.get("payload_digest") != trace_payload_digest(payload):
        issues.append("typed trace payload digest mismatch")
    if str(payload.get("run_binding_digest") or "") != str(
        run_binding.get("binding_digest") or ""
    ):
        issues.append("typed trace run binding digest mismatch")
    if _normalize_ecosystem(payload.get("ecosystem")) != run_binding.get("ecosystem"):
        issues.append("typed trace ecosystem mismatch")
    if not _clean(payload.get("operator_id")):
        issues.append("operator identity is missing")
    operator_digest = _clean(payload.get("operator_digest")).lower()
    if not _HEX64.fullmatch(operator_digest):
        issues.append("operator digest is missing or invalid")
    if not isinstance(payload.get("facts"), list):
        issues.append("typed trace facts is not an array")
    return not issues, issues


def _debt(fact: Mapping[str, Any], kind: str, reason: str) -> dict[str, Any]:
    row = {
        "fact_id": str(fact.get("fact_id") or ""),
        "role": str(fact.get("role") or ""),
        "trust_domain_id": str(fact.get("trust_domain_id") or ""),
        "kind": kind,
        "reason": reason,
        "status": "OPEN",
    }
    row["debt_id"] = _stable_id("AUTHD", row)
    return row


def compose_arm_before_trust_obligations(
    authority: Mapping[str, Any]
) -> dict[str, Any]:
    activation = authority.get("activation") if isinstance(authority.get("activation"), Mapping) else {}
    run_binding = authority.get("run_binding") if isinstance(authority.get("run_binding"), Mapping) else {}
    if authority.get("status") == "NOT_TRIGGERED":
        return _finalize(
            {
                "schema_version": COMPOSITION_SCHEMA,
                "run_binding": dict(run_binding),
                "status": "NOT_TRIGGERED",
                "activation_state": str(activation.get("state") or "NOT_TRIGGERED"),
                "fact_authority_digest": str(authority.get("authority_digest") or ""),
                "proof_authority": "NONE",
                "obligation_count": 0,
                "debt_count": 0,
                "obligations": [],
                "debts": [],
            },
            "composition_digest",
        )

    facts = [row for row in authority.get("facts") or [] if isinstance(row, Mapping)]
    positives = [row for row in facts if row.get("authority_state") == "POSITIVE"]
    anchors = [row for row in positives if row.get("role") == "ANCHOR"]
    derived = [row for row in positives if row.get("role") == "DERIVED_IDENTITY"]
    groups: dict[tuple[str, str, str], dict[str, list[Mapping[str, Any]]]] = {}
    for fact in positives:
        key = (
            str(fact.get("trust_domain_id") or ""),
            str(fact.get("privileged_effect") or "").casefold(),
            str(fact.get("boundary_kind") or ""),
        )
        groups.setdefault(key, {"ANCHOR": [], "DERIVED_IDENTITY": []})[
            str(fact.get("role"))
        ].append(fact)
    obligations: list[dict[str, Any]] = []
    debts: list[dict[str, Any]] = []
    used: set[str] = set()
    ambiguous: set[str] = set()
    for key, roles in sorted(groups.items()):
        if not key[2] or not roles["ANCHOR"] or not roles["DERIVED_IDENTITY"]:
            continue
        if len(roles["ANCHOR"]) != 1 or len(roles["DERIVED_IDENTITY"]) != 1:
            for fact in [*roles["ANCHOR"], *roles["DERIVED_IDENTITY"]]:
                fact_id = str(fact.get("fact_id") or "")
                ambiguous.add(fact_id)
                debts.append(
                    _debt(
                        fact,
                        "AMBIGUOUS_TYPED_PAIR",
                        "multiple complementary facts share one exact trust/effect/default key",
                    )
                )
            continue
        anchor = roles["ANCHOR"][0]
        derivation = roles["DERIVED_IDENTITY"][0]
        fact_ids = sorted(
            [str(anchor.get("fact_id") or ""), str(derivation.get("fact_id") or "")]
        )
        used.update(fact_ids)
        obligation = {
            "obligation_id": _stable_id("MZO", fact_ids),
            "trust_domain_id": key[0],
            "boundary_kind": key[2],
            "privileged_effect": str(anchor.get("privileged_effect") or ""),
            "constituent_fact_ids": fact_ids,
            "anchor_fact_id": str(anchor.get("fact_id") or ""),
            "derived_identity_fact_id": str(derivation.get("fact_id") or ""),
            "proof_authority": "NONE",
            "route": "COMPOUND_ANALYSIS_REQUIRED",
            "question": (
                "Determine whether the typed operational-unarmed anchor and accepted "
                "default-derived identity compose into the cited privileged effect."
            ),
        }
        obligation["obligation_digest"] = _sha256(obligation)
        obligations.append(obligation)

    for fact in positives:
        fact_id = str(fact.get("fact_id") or "")
        if fact_id not in used and fact_id not in ambiguous:
            debts.append(
                _debt(
                    fact,
                    "UNMATCHED_TYPED_HALF",
                    "typed positive half has no exact complementary trust/effect/default fact",
                )
            )
    for fact in facts:
        state = str(fact.get("authority_state") or "UNMEASURABLE")
        if state == "POSITIVE":
            continue
        kind = {
            "CONFLICT": "CONFLICTED_TYPED_HALF",
            "REFUTED": "REFUTED_TYPED_HALF",
            "EXTERNAL_UNRESOLVED": "EXTERNAL_RESEARCH_REQUIRED",
            "UNMEASURABLE": "UNMEASURABLE_TYPED_HALF",
        }.get(state, "UNMEASURABLE_TYPED_HALF")
        debts.append(_debt(fact, kind, f"typed half authority state is {state}"))
    unique_debts = {str(row["debt_id"]): row for row in debts}
    obligations.sort(key=lambda row: str(row["obligation_id"]))
    debts = [unique_debts[key] for key in sorted(unique_debts)]
    if obligations and debts:
        status = "OBLIGATIONS_WITH_DEBT"
    elif obligations:
        status = "OBLIGATIONS_READY"
    elif debts:
        status = "DEBT"
    else:
        status = "CLEAN_NO_MATCH"
    return _finalize(
        {
            "schema_version": COMPOSITION_SCHEMA,
            "run_binding": dict(run_binding),
            "status": status,
            "activation_state": str(activation.get("state") or ""),
            "fact_authority_digest": str(authority.get("authority_digest") or ""),
            "proof_authority": "NONE",
            "obligation_count": len(obligations),
            "debt_count": len(debts),
            "obligations": obligations,
            "debts": debts,
        },
        "composition_digest",
    )


def _external_research_obligations(
    authority: Mapping[str, Any]
) -> dict[str, Any]:
    activation = authority.get("activation") if isinstance(authority.get("activation"), Mapping) else {}
    run_binding = authority.get("run_binding") if isinstance(authority.get("run_binding"), Mapping) else {}
    if authority.get("status") == "NOT_TRIGGERED":
        status = "NOT_TRIGGERED"
        obligations: list[dict[str, Any]] = []
    else:
        facts = [row for row in authority.get("facts") or [] if isinstance(row, Mapping)]
        obligations = []
        for fact in facts:
            if fact.get("authority_state") != "EXTERNAL_UNRESOLVED":
                continue
            same_scope = [
                str(row.get("fact_id") or "")
                for row in facts
                if row.get("trust_domain_id") == fact.get("trust_domain_id")
                and row.get("privileged_effect") == fact.get("privileged_effect")
            ]
            candidate_scope = _stable_id(
                "MZO-SCOPE",
                {
                    "trust_domain_id": fact.get("trust_domain_id"),
                    "privileged_effect": fact.get("privileged_effect"),
                    "boundary_kind": fact.get("boundary_kind"),
                },
                length=16,
            )
            obligation = {
                "obligation_id": _stable_id(
                    "AUTH-EXT", {"candidate_scope_id": candidate_scope, "fact_id": fact.get("fact_id")}
                ),
                "candidate_scope_id": candidate_scope,
                "fact_ids": sorted(set(same_scope)),
                "external_fact_id": str(fact.get("fact_id") or ""),
                "dependency": str(fact.get("external_dependency") or ""),
                "integration_surface": str(fact.get("external_surface") or ""),
                "asserted_external_state": "UNKNOWN",
                "research_question": (
                    "Determine the externally defined default, arming/de-arming, "
                    "operational reachability, degenerate-input, identity-derivation, "
                    "accept/reject, and privileged-effect semantics at this exact surface."
                ),
                "status": "NEEDS_DEPENDENCY_RESEARCH",
                "proof_authority": "NONE",
            }
            obligation["obligation_digest"] = _sha256(obligation)
            obligations.append(obligation)
        obligations.sort(key=lambda row: str(row["obligation_id"]))
        status = "OPEN" if obligations else "CLEAN_NO_EXTERNAL_PREMISE"
    return _finalize(
        {
            "schema_version": EXTERNAL_RESEARCH_SCHEMA,
            "run_binding": dict(run_binding),
            "status": status,
            "activation_state": str(activation.get("state") or ""),
            "fact_authority_digest": str(authority.get("authority_digest") or ""),
            "obligation_count": len(obligations),
            "obligations": obligations,
        },
        "research_digest",
    )


def _not_triggered_authority(
    run_binding: Mapping[str, str], state: str, nominations: list[dict[str, str]]
) -> dict[str, Any]:
    return _finalize(
        {
            "schema_version": FACT_AUTHORITY_SCHEMA,
            "run_binding": dict(run_binding),
            "ecosystem": str(run_binding.get("ecosystem") or "unknown"),
            "status": "NOT_TRIGGERED",
            "activation": {
                "state": state,
                "evm_active": False,
                "cross_ecosystem_activation_evidence_satisfied": False,
            },
            "operator_id": "",
            "operator_digest": "",
            "trace_payload_digest": "",
            "input_bindings": [],
            "fact_count": 0,
            "positive_fact_count": 0,
            "facts": [],
            "compatibility_nominations": nominations,
            "issues": [],
        },
        "authority_digest",
    )


def derive_authentication_role_authority(
    scratchpad: Path,
    *,
    trace_payload: Mapping[str, Any] | None = None,
    compatibility_entries: Sequence[Mapping[str, Any]] | None = None,
    triggered: bool = True,
    ecosystem: str = "",
    mode: str = "",
    run_id: str = "",
    source_snapshot_digest: str = "",
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], str]:
    root = Path(scratchpad)
    run_binding, binding_issues = _load_run_binding(
        root,
        ecosystem=ecosystem,
        mode=mode,
        run_id=run_id,
        source_snapshot_digest=source_snapshot_digest,
    )
    nominations = _compatibility_nominations(compatibility_entries)
    if run_binding["ecosystem"] != "evm":
        authority = _not_triggered_authority(
            run_binding, "NON_EVM_ACTIVATION_GATE_HELD", nominations
        )
        composition = compose_arm_before_trust_obligations(authority)
        research = _external_research_obligations(authority)
        return authority, composition, research, render_authentication_role_authority(
            authority, composition, research
        )
    if not triggered:
        authority = _not_triggered_authority(
            run_binding, "EVM_OPERATOR_NOT_SELECTED", nominations
        )
        composition = compose_arm_before_trust_obligations(authority)
        research = _external_research_obligations(authority)
        return authority, composition, research, render_authentication_role_authority(
            authority, composition, research
        )

    payload = trace_payload
    input_bindings: list[dict[str, Any]] = []
    if payload is None:
        trace_path = root / TRACE_FILE
        if trace_path.is_file():
            try:
                loaded = _load_json(trace_path)
                if isinstance(loaded, Mapping):
                    payload = loaded
                    input_bindings.append(_binding(trace_path, "TYPED_OPERATOR_TRACE"))
            except Exception:
                payload = None
    trace_valid, trace_issues = _validate_trace(payload, run_binding)
    all_issues = sorted(set(binding_issues + trace_issues))
    trace_valid = trace_valid and not binding_issues
    operator_id = _clean(payload.get("operator_id")) if payload else ""
    operator_digest = _clean(payload.get("operator_digest")).lower() if payload else ""
    facts: list[dict[str, Any]] = []
    raw_facts = payload.get("facts") if payload and isinstance(payload.get("facts"), list) else []
    for index, raw in enumerate(raw_facts):
        if not isinstance(raw, Mapping):
            all_issues.append(f"fact row {index} is not an object")
            continue
        facts.append(
            _normalize_fact(
                raw,
                operator_id=operator_id,
                operator_digest=operator_digest,
                run_binding=run_binding,
                trace_valid=trace_valid,
            )
        )
    duplicate_ids = {
        fact_id
        for fact_id in {str(row["fact_id"]) for row in facts}
        if sum(str(row["fact_id"]) == fact_id for row in facts) > 1
    }
    if duplicate_ids:
        trace_valid = False
        all_issues.append("duplicate canonical fact IDs: " + ", ".join(sorted(duplicate_ids)))
        for row in facts:
            reason = (
                "duplicate canonical fact identity"
                if str(row["fact_id"]) in duplicate_ids
                else "typed trace invalidated by duplicate canonical fact identity"
            )
            row["authority_state"] = "UNMEASURABLE"
            row["positive_claims"] = []
            row["issues"] = sorted(set([*row["issues"], reason]))
            row["fact_digest"] = _sha256(
                {key: value for key, value in row.items() if key != "fact_digest"}
            )
    facts.sort(key=lambda row: (str(row["role"]), str(row["fact_id"])))
    status = "ACTIVE" if trace_valid else "UNMEASURABLE"
    authority = _finalize(
        {
            "schema_version": FACT_AUTHORITY_SCHEMA,
            "run_binding": run_binding,
            "ecosystem": run_binding["ecosystem"],
            "status": status,
            "activation": {
                "state": "ACTIVE_EVM_ONLY",
                "evm_active": True,
                "cross_ecosystem_activation_evidence_satisfied": False,
            },
            "operator_id": operator_id,
            "operator_digest": operator_digest,
            "trace_payload_digest": str(payload.get("payload_digest") or "") if payload else "",
            "input_bindings": input_bindings,
            "fact_count": len(facts),
            "positive_fact_count": sum(row["authority_state"] == "POSITIVE" for row in facts),
            "facts": facts,
            "compatibility_nominations": nominations,
            "issues": sorted(set(all_issues)),
        },
        "authority_digest",
    )
    composition = compose_arm_before_trust_obligations(authority)
    research = _external_research_obligations(authority)
    return authority, composition, research, render_authentication_role_authority(
        authority, composition, research
    )


def _escape(value: object) -> str:
    return _clean(value, 2_000).replace("|", "/")


def render_authentication_role_authority(
    authority: Mapping[str, Any],
    composition: Mapping[str, Any],
    research: Mapping[str, Any],
) -> str:
    activation = authority.get("activation") if isinstance(authority.get("activation"), Mapping) else {}
    lines = [
        "# Authentication Role and Arm-Before-Trust Obligations",
        "",
        "Typed JSON is authoritative. Prose compatibility matches are nominations only and never positive facts.",
        "",
        f"**Status**: {_escape(authority.get('status'))}",
        f"**Activation**: {_escape(activation.get('state'))}",
        f"**Authority digest**: `{_escape(authority.get('authority_digest'))}`",
        f"**Composition status**: {_escape(composition.get('status'))}",
        f"**External research status**: {_escape(research.get('status'))}",
        "",
        "## Typed role facts",
        "",
        "| Fact ID | Role | Trust Domain | Authority State | Provenance | Boundary | Privileged Effect |",
        "|---|---|---|---|---|---|---|",
    ]
    facts = authority.get("facts") if isinstance(authority.get("facts"), list) else []
    if facts:
        for row in facts:
            lines.append(
                "| `{fact}` | {role} | `{domain}` | {state} | {provenance} | {boundary} | `{effect}` |".format(
                    fact=_escape(row.get("fact_id")),
                    role=_escape(row.get("role")),
                    domain=_escape(row.get("trust_domain_id")),
                    state=_escape(row.get("authority_state")),
                    provenance=_escape(row.get("provenance")),
                    boundary=_escape(row.get("boundary_kind")),
                    effect=_escape(row.get("privileged_effect")),
                )
            )
    else:
        lines.append("| n/a | n/a | n/a | n/a | n/a | n/a | n/a |")
    lines.extend(["", "## Composition obligations", ""])
    obligations = composition.get("obligations") if isinstance(composition.get("obligations"), list) else []
    if obligations:
        for row in obligations:
            lines.append(
                f"- `{_escape(row.get('obligation_id'))}`: {_escape(', '.join(row.get('constituent_fact_ids') or []))} -> {_escape(row.get('route'))}"
            )
    else:
        lines.append("- none")
    debts = composition.get("debts") if isinstance(composition.get("debts"), list) else []
    lines.extend(["", "## Open fact debt", ""])
    if debts:
        for row in debts:
            lines.append(
                f"- `{_escape(row.get('debt_id'))}` / `{_escape(row.get('fact_id'))}`: {_escape(row.get('kind'))}"
            )
    else:
        lines.append("- none")
    external = research.get("obligations") if isinstance(research.get("obligations"), list) else []
    lines.extend(["", "## External research obligations", ""])
    if external:
        for row in external:
            lines.append(
                f"- `{_escape(row.get('obligation_id'))}` / `{_escape(row.get('candidate_scope_id'))}`: asserted state `{_escape(row.get('asserted_external_state'))}`"
            )
    else:
        lines.append("- none")
    nominations = authority.get("compatibility_nominations") if isinstance(authority.get("compatibility_nominations"), list) else []
    if nominations:
        lines.extend(["", "## Compatibility nominations (no authority)", ""])
        for row in nominations:
            lines.append(
                f"- `{_escape(row.get('nomination_id'))}`: {_escape(row.get('candidate_id'))} / {_escape(row.get('role'))} / NOMINATION_ONLY"
            )
    return "\n".join(lines) + "\n"


def _atomic_write_if_changed(path: Path, data: bytes) -> None:
    try:
        if path.is_file() and path.read_bytes() == data:
            return
    except OSError:
        pass
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_bytes(data)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def write_authentication_role_authority(
    scratchpad: Path, **kwargs: Any
) -> dict[str, Any]:
    """Compatibility wrapper for callers that have not cut over to staged PhaseIO.

    Live driver code must use the two disjoint writers below so the fact-authority
    and composition work units cannot mutate one another's output sets.
    """
    authority = write_authentication_role_fact_authority(scratchpad, **kwargs)
    write_authentication_role_composition(scratchpad)
    return authority


def write_authentication_role_fact_authority(
    scratchpad: Path, **kwargs: Any
) -> dict[str, Any]:
    """Persist only the typed fact-authority output owned by its PhaseIO unit."""
    root = Path(scratchpad)
    root.mkdir(parents=True, exist_ok=True)
    authority, _composition, _research, _projection = (
        derive_authentication_role_authority(root, **kwargs)
    )
    _atomic_write_if_changed(root / AUTHORITY_FILE, _pretty_json(authority))
    return authority


def _load_valid_fact_authority(root: Path) -> dict[str, Any]:
    try:
        loaded = _load_json(root / AUTHORITY_FILE)
    except Exception as exc:
        raise ValueError(
            f"authentication fact authority unavailable: {type(exc).__name__}"
        ) from exc
    if not isinstance(loaded, dict):
        raise ValueError("authentication fact authority root is not an object")
    if loaded.get("schema_version") != FACT_AUTHORITY_SCHEMA:
        raise ValueError("authentication fact authority schema mismatch")
    expected_digest = _sha256(
        {key: value for key, value in loaded.items() if key != "authority_digest"}
    )
    if loaded.get("authority_digest") != expected_digest:
        raise ValueError("authentication fact authority digest mismatch")
    return loaded


def derive_authentication_role_composition(
    scratchpad: Path,
) -> tuple[dict[str, Any], dict[str, Any], str]:
    """Derive the composition unit solely from persisted typed fact authority."""
    root = Path(scratchpad)
    authority = _load_valid_fact_authority(root)
    composition = compose_arm_before_trust_obligations(authority)
    research = _external_research_obligations(authority)
    projection = render_authentication_role_authority(
        authority, composition, research
    )
    return composition, research, projection


def write_authentication_role_composition(
    scratchpad: Path,
) -> dict[str, Any]:
    """Persist only outputs owned by the composition PhaseIO work unit."""
    root = Path(scratchpad)
    root.mkdir(parents=True, exist_ok=True)
    composition, research, projection = derive_authentication_role_composition(root)
    _atomic_write_if_changed(root / COMPOSITION_FILE, _pretty_json(composition))
    _atomic_write_if_changed(root / EXTERNAL_RESEARCH_FILE, _pretty_json(research))
    _atomic_write_if_changed(root / PROJECTION_FILE, projection.encode("utf-8"))
    return composition


def validate_authentication_role_fact_authority(
    scratchpad: Path, **kwargs: Any
) -> list[str]:
    root = Path(scratchpad)
    expected, _composition, _research, _projection = (
        derive_authentication_role_authority(root, **kwargs)
    )
    try:
        actual = _load_json(root / AUTHORITY_FILE)
    except Exception as exc:
        return [f"{AUTHORITY_FILE} missing or malformed: {type(exc).__name__}"]
    if actual != expected:
        return [f"{AUTHORITY_FILE} differs from current typed inputs"]
    return []


def validate_authentication_role_composition(
    scratchpad: Path,
) -> list[str]:
    root = Path(scratchpad)
    try:
        composition, research, projection = derive_authentication_role_composition(root)
    except Exception as exc:
        return [f"authentication composition derivation failed: {exc}"]
    issues: list[str] = []
    for name, expected in (
        (COMPOSITION_FILE, composition),
        (EXTERNAL_RESEARCH_FILE, research),
    ):
        try:
            actual = _load_json(root / name)
        except Exception as exc:
            issues.append(f"{name} missing or malformed: {type(exc).__name__}")
            continue
        if actual != expected:
            issues.append(f"{name} differs from current typed authority")
    try:
        actual_projection = (root / PROJECTION_FILE).read_text(
            encoding="utf-8", errors="strict"
        )
    except Exception as exc:
        issues.append(f"{PROJECTION_FILE} missing or malformed: {type(exc).__name__}")
    else:
        if actual_projection != projection:
            issues.append(f"{PROJECTION_FILE} differs from current typed authority")
    return issues


def validate_authentication_role_authority(
    scratchpad: Path, **kwargs: Any
) -> list[str]:
    return [
        *validate_authentication_role_fact_authority(scratchpad, **kwargs),
        *validate_authentication_role_composition(scratchpad),
    ]


__all__ = [
    "AUTHORITY_FILE",
    "COMPOSITION_FILE",
    "EXTERNAL_RESEARCH_FILE",
    "FACT_AUTHORITY_SCHEMA",
    "FACT_TRACE_SCHEMA",
    "PROJECTION_FILE",
    "derive_authentication_role_authority",
    "derive_authentication_role_composition",
    "nominate_compatibility_roles",
    "run_binding_digest",
    "trace_payload_digest",
    "validate_authentication_role_authority",
    "validate_authentication_role_composition",
    "validate_authentication_role_fact_authority",
    "write_authentication_role_authority",
    "write_authentication_role_composition",
    "write_authentication_role_fact_authority",
]
