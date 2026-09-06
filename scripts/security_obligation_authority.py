"""Typed feature facts and rule-owned security obligations (P1-C).

The legacy generator flattened many Markdown artifacts and fired one broad
regular expression per security class.  A documentation-only word could
therefore schedule the same work as a code-derived program fact.  This module
keeps compatibility without retaining that authority model:

* code facts are derived from the mechanically bound graph or an explicitly
  typed recon-fact envelope;
* legacy Markdown is a source-locus-scoped compatibility fallback and must
  satisfy a multi-feature predicate within one line/context;
* every rule owns one stable obligation and multiple trigger paths become
  aliases, not duplicate work;
* current depth receipts are read only from the exact worker-pool contract;
* PRE derivation never consumes receipts, while POST reconciles only outputs
  whose real MODEL work units were pre-bound to the three PRE sidecars;
* every producer-authored disposition is non-terminal: an exact reported
  alias becomes pending independent verification, while dismissal/carry prose
  and unmatched reports remain repair work;
* JSON is authoritative and ``security_obligations.md`` is an exact view;
* missing, conflicting, malformed, or stale inputs create review work rather
  than a false all-clear.

The module creates analysis obligations only.  It never asserts a finding,
changes severity, or authorizes a safety verdict.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

try:
    import asset_representation_foundation as _asset_repr
except ImportError:  # pragma: no cover - package import path
    from . import asset_representation_foundation as _asset_repr


FEATURE_FACT_SCHEMA = "plamen.security_feature_fact_authority.v2"
OBLIGATION_SCHEMA = "plamen.security_obligation_authority.v2"
RECON_FEATURE_SCHEMA = "plamen.recon_feature_facts.v2"
LEGACY_RECON_FEATURE_SCHEMA = "plamen.recon_feature_facts.v1"
RECON_FEATURE_SCHEMA_V3 = _asset_repr.RECON_FEATURE_SCHEMA_V3
APPLICATION_RECEIPT_SCHEMA = "plamen.security_obligation_application_receipt.v1"
EVIDENCE_BINDING_SCHEMA = "plamen.security-obligation-evidence-binding.v1"
RULE_CATALOG_VERSION = "p1-c.6"
PRE_DEPTH_STAGE = "pre_depth"
POST_DEPTH_STAGE = "post_depth"
_STAGES = frozenset({PRE_DEPTH_STAGE, POST_DEPTH_STAGE})

FEATURE_FACT_FILE = "security_feature_facts.json"
AUTHORITY_FILE = "security_obligation_authority.json"
PROJECTION_FILE = "security_obligations.md"
RECON_FEATURE_FILE = "recon_feature_facts.json"
APPLICATION_RECEIPT_FILE = "security_obligation_application_receipt.json"

FEATURE_FACT_COVERAGE_QUESTION = (
    "Typed graph/recon feature facts are unavailable or invalid; inspect the "
    "feature substrate and retain unresolved methodology coverage for review."
)

_GRAPH_FILE = "_mechanical_graph.json"
_CHECKPOINT_FILE = "_v2_checkpoint.json"
_DEPTH_CONTRACT_FILE = "_depth_worker_pool_contract.json"
_ARTIFACT_LEDGER_FILE = "_artifact_state.json"
_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
_UUID4 = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_SOURCE_LOCUS_RE = re.compile(
    r"(?P<path>(?:[A-Za-z]:)?[A-Za-z0-9_@.+/\\-]+\."
    r"(?:sol|vy|rs|go|move|daml|proto))"
    r"(?:(?::[A-Za-z_]\w*)?:L?(?P<line>\d+))",
    re.IGNORECASE,
)
_RECEIPT_RE = re.compile(
    r"^\s*\[OBLIG:security_obligations\.md:(?P<display>SO-\d{3})\]"
    r"(?:\s+ALIAS:(?P<alias>SOT-[0-9A-Fa-f]{24}))?"
    r"\s+STATUS:(?P<status>[RDC])\s+KEY:(?P<key>.*?)\s+->\s+"
    r"(?P<target>\S(?:.*\S)?)\s*$",
    re.IGNORECASE,
)
_COMPLETE_MARKER_RE = re.compile(
    r"<!--\s*PLAMEN_STATUS\s*:\s*COMPLETE\s*-->", re.IGNORECASE
)
_PHASE_MARKER_RE = re.compile(
    r"<!--\s*PLAMEN_PHASE\s*:\s*depth\s*-->", re.IGNORECASE
)
_FINDING_REFERENT_RE = re.compile(
    r"(?im)^#{2,4}\s+Finding\s+\[(?P<id>[^\]\r\n]+)\]"
)
_MARKDOWN_HEADING_RE = re.compile(
    r"^(?P<hashes>#{1,6})[ \t]+(?P<title>.*?)[ \t]*#*[ \t]*$"
)
_FINDING_HEADING_TITLE_RE = re.compile(
    r"^Finding\s+\[(?P<id>[^\]\r\n]+)\](?:\s+.*)?$", re.IGNORECASE
)
_EVIDENCE_BINDING_RE = re.compile(
    r"^\s*<!--\s*PLAMEN_SECURITY_OBLIGATION_EVIDENCE:\s*"
    r"(?P<payload>\{.*\})\s*-->\s*$"
)
_SAFE_PATH_DRIVE = re.compile(r"^[A-Za-z]:")
_EVIDENCE_BINDING_KEYS = frozenset(
    {
        "schema_version",
        "alias_id",
        "subject_id",
        "relation_id",
        "object_id",
        "symbol",
    }
)

_FALLBACK_ARTIFACTS = (
    "external_interfaces.md",
    "integration_points.md",
    "contract_inventory.md",
    "function_summary.md",
    "caller_map.md",
    "callee_map.md",
    "state_write_map.md",
    "opengrep_findings.md",
    "dependency_audit_findings.md",
)

# Tokens are deliberately generic semantic primitives, not protocol answers.
# They classify code identities or a source-locus-scoped compatibility row;
# they are never searched over a flattened narrative corpus.
_CONCEPT_TOKENS: dict[str, frozenset[str]] = {
    "value_asset": frozenset(
        {"asset", "token", "coin", "amount", "balance", "fund", "funds", "value", "reserve", "supply", "debt"}
    ),
    "identity_binding": frozenset(
        {"recipient", "sender", "source", "target", "destination", "owner", "account", "address", "chainid", "nonce", "domain", "beneficiary"}
    ),
    "movement": frozenset(
        {"transfer", "send", "swap", "withdraw", "deposit", "mint", "burn", "route", "redeem", "claim"}
    ),
    "swap": frozenset({"swap", "exchange", "quote"}),
    "route_pool": frozenset({"router", "route", "pool", "pair", "path", "reserve", "quote"}),
    "constraint": frozenset(
        {"minout", "minimumamountout", "slippage", "limit", "approve", "allowance", "fee", "threshold"}
    ),
    "failure": frozenset({"revert", "rollback", "fail", "failed", "error", "abort"}),
    "recovery": frozenset({"refund", "recover", "recovery", "rescue", "fallback", "returnfunds"}),
    "cross_domain": frozenset(
        {"bridge", "gateway", "crosschain", "interchain", "xcall", "cpi", "crossdomain"}
    ),
    "message_schema": frozenset(
        {"message", "payload", "decode", "encode", "deserialize", "serialize", "schema", "packet"}
    ),
    "native_asset": frozenset({"native", "gastoken", "msgvalue"}),
    "wrapped_asset": frozenset({"wrapped", "wrap", "unwrap"}),
    # Opaque ``w...`` symbols are not wrapper authority.  This empty concept
    # is emitted only by the ambiguity classifier after same-subject native +
    # token-operation evidence is present; a typed BAKE/recon relation can
    # supersede it with ``wrapped_asset``.
    "wrapped_asset_ambiguous": frozenset(),
    # Emitted only by the deterministic proposal enumerator.  No token search
    # can mint this concept directly or certify that its work was applied.
    "asset_representation_boundary": frozenset(),
    "asset_representation_edge_repair": frozenset(),
    "token_operation": frozenset({"approve", "allowance", "transfer", "wrap", "unwrap"}),
    "external_interaction": frozenset(
        {"external", "callback", "hook", "receiver", "delegatecall", "staticcall", "call", "invoke", "cpi"}
    ),
    "callback_hook": frozenset({"callback", "hook", "receiver", "fallback", "oncall", "onreceive"}),
    "privilege": frozenset(
        {"admin", "owner", "governance", "role", "permission", "authority", "upgrade", "privileged"}
    ),
    "exit": frozenset({"withdraw", "sweep", "rescue", "emergency", "exit", "upgrade", "drain"}),
    "encoding": frozenset({"decode", "encode", "deserialize", "serialize", "cast", "abi"}),
    "shape": frozenset(
        {"schema", "struct", "layout", "width", "length", "bytes", "endianness", "writable", "signer", "permission"}
    ),
}

_TOKEN_ALIASES = {
    "decoded": "decode",
    "decoding": "decode",
    "encoded": "encode",
    "encoding": "encode",
    "deserialized": "deserialize",
    "serialized": "serialize",
    "refunded": "refund",
    "refunds": "refund",
    "recipients": "recipient",
    "senders": "sender",
    "transfers": "transfer",
    "transferred": "transfer",
    "withdrawal": "withdraw",
    "withdrawals": "withdraw",
    "deposits": "deposit",
    "callbacks": "callback",
    "permissions": "permission",
    "balances": "balance",
    "amounts": "amount",
    "assets": "asset",
    "tokens": "token",
    "messages": "message",
    "wrapper": "wrapped",
    "wrappers": "wrapped",
    "wrapping": "wrapped",
}

_RULES: tuple[dict[str, Any], ...] = (
    {
        "display_id": "SO-001",
        "rule_id": "security.asset_binding.v1",
        "rule_version": "1.0.0",
        "class": "asset_binding",
        "groups": (("value_asset",), ("identity_binding",), ("movement",)),
        "question": "Are asset-in, asset-out, recipient, and amount fields bound to trusted execution context before value moves?",
    },
    {
        "display_id": "SO-002",
        "rule_id": "security.swap_execution.v1",
        "rule_version": "1.0.0",
        "class": "swap_execution",
        "groups": (("swap",), ("route_pool",), ("value_asset", "constraint")),
        "question": "Can swap execution, pool selection, min-out checks, or approval/execution amounts diverge from the value path?",
    },
    {
        "display_id": "SO-003",
        "rule_id": "security.refund_revert.v1",
        "rule_version": "1.0.0",
        "class": "refund_revert",
        "groups": (("recovery",), ("failure",), ("identity_binding", "value_asset")),
        "question": "Is the refund recipient derived from authenticated source context and the original asset custody path?",
    },
    {
        "display_id": "SO-004",
        "rule_id": "security.cross_domain_message.v1",
        "rule_version": "1.0.0",
        "class": "cross_domain_message",
        "groups": (("cross_domain",), ("message_schema",), ("identity_binding",)),
        "question": "Are decoded message fields, source domain, and source sender authenticated before privileged state or value effects?",
    },
    {
        "display_id": "SO-005",
        "rule_id": "security.native_wrapped_asset.v1",
        "rule_version": "1.0.0",
        "class": "native_wrapped_asset",
        "groups": (("native_asset",), ("wrapped_asset",), ("token_operation",)),
        "question": "Are native-asset and token-contract branches separated so transfer, approval, wrapping, and accounting cannot mismatch?",
    },
    {
        "display_id": "SO-006",
        "rule_id": "security.external_call_surface.v1",
        "rule_version": "1.0.0",
        "class": "external_call_surface",
        "groups": (("external_interaction",), ("callback_hook",), ("call_edge",)),
        "question": "Can untrusted call targets, callbacks, hooks, or reentrant external effects violate state or value assumptions?",
    },
    {
        "display_id": "SO-007",
        "rule_id": "security.privileged_exit.v1",
        "rule_version": "1.0.0",
        "class": "privileged_exit",
        "groups": (("privilege",), ("exit",), ("value_asset",)),
        "question": "Are privileged exits, rescue paths, and upgrades access-controlled and constrained to intended assets and recipients?",
    },
    {
        "display_id": "SO-008",
        "rule_id": "security.encoding_schema.v1",
        "rule_version": "1.0.0",
        "class": "encoding_schema",
        "groups": (("encoding",), ("shape",), ("cross_domain", "external_interaction", "identity_binding")),
        "question": "Do encoded and decoded schemas preserve field widths, ordering, permissions, and identity formats across boundaries?",
    },
    {
        "display_id": "SO-009",
        "rule_id": "security.wrapped_asset_classification.v1",
        "rule_version": "1.0.0",
        "class": "wrapped_asset_classification",
        "groups": (("wrapped_asset_ambiguous",),),
        # Each unresolved object relation is separate application work even
        # when several symbols occur in one function or source locus.
        "alias_partition": "fact",
        "question": (
            "Does this opaque asset symbol denote a native/wrapped conversion "
            "relation? Resolve it from typed call, type, or BAKE evidence before "
            "closing native-asset methodology coverage."
        ),
    },
    {
        "display_id": "SO-010",
        "rule_id": "security.asset_representation_boundary.v1",
        "rule_version": "1.0.0",
        "class": "asset_representation_boundary",
        "groups": (("asset_representation_boundary",),),
        "alias_partition": "fact",
        "question": (
            "At this exact subject, are native-value and tokenized-asset "
            "representations separated and reconciled across calls, types, "
            "custody, and accounting?"
        ),
    },
    {
        "display_id": "SO-011",
        "rule_id": "security.asset_representation_edge_repair.v1",
        "rule_version": "1.0.0",
        "class": "asset_representation_edge_repair",
        "groups": (("asset_representation_edge_repair",),),
        "alias_partition": "fact",
        "question": (
            "Repair or independently re-enumerate this malformed typed "
            "asset-representation occurrence without discarding valid sibling evidence."
        ),
    },
)

_RULE_CATALOG_DIGEST = ""


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest().upper()


def _sha256_value(value: Any) -> str:
    return _sha256_bytes(_canonical_json(value).encode("utf-8"))


_RULE_CATALOG_DIGEST = _sha256_value(_RULES)


def _binding(path: Path, role: str) -> dict[str, Any]:
    data = path.read_bytes()
    return {
        "artifact": path.name,
        "role": role,
        "sha256": _sha256_bytes(data),
        "byte_count": len(data),
    }


def _safe_artifact_name(value: object) -> str | None:
    text = str(value or "").strip().replace("\\", "/")
    if not text or "/" in text or text in {".", ".."}:
        return None
    return text


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8", errors="strict"))


def _dynamic_input_name(value: object) -> str | None:
    """Return one safe dynamic child artifact, excluding the mutable ledger."""

    name = _safe_artifact_name(value)
    if not name or name == _ARTIFACT_LEDGER_FILE:
        return None
    return name


def _depth_contract_output_names(
    contract: Mapping[str, Any], issues: list[str] | None = None
) -> tuple[str, ...]:
    """Enumerate safe depth outputs without guessing through malformed fields."""

    names: set[str] = set()
    for field in ("canonical_outputs", "outputs"):
        raw_values = contract.get(field)
        if raw_values is None:
            continue
        if not isinstance(raw_values, list):
            if issues is not None:
                issues.append(f"depth worker contract {field} is not a list")
            continue
        for value in raw_values:
            name = _dynamic_input_name(value)
            if name:
                names.add(name)
            elif value and issues is not None:
                issues.append("depth worker contract contains unsafe output path")
    jobs = contract.get("jobs")
    if jobs is not None and not isinstance(jobs, list):
        if issues is not None:
            issues.append("depth worker contract jobs is not a list")
        return tuple(sorted(names))
    for index, job in enumerate(jobs or []):
        if not isinstance(job, Mapping):
            if issues is not None:
                issues.append(f"depth worker contract job {index} is malformed")
            continue
        value = job.get("output")
        name = _dynamic_input_name(value)
        if name:
            names.add(name)
        elif value and issues is not None:
            issues.append("depth worker contract contains unsafe output path")
    return tuple(sorted(names))


def _application_receipt_evidence_names(
    payload: Mapping[str, Any],
) -> tuple[str, ...]:
    """Enumerate only evidence children the receipt parser can attempt to read."""

    if payload.get("schema_version") != APPLICATION_RECEIPT_SCHEMA:
        return ()
    raw_receipts = payload.get("receipts")
    if not isinstance(raw_receipts, list):
        return ()
    names: set[str] = set()
    for raw in raw_receipts:
        if not isinstance(raw, Mapping):
            continue
        disposition = str(raw.get("disposition") or "").upper()
        reason = str(raw.get("reason") or "").strip()
        if disposition not in {"REPORTED", "DISMISSED_EVIDENCE", "CARRIED"} or not reason:
            continue
        evidence_bindings = raw.get("evidence_bindings")
        if not isinstance(evidence_bindings, list):
            continue
        for evidence in evidence_bindings:
            if not isinstance(evidence, Mapping):
                continue
            name = _dynamic_input_name(evidence.get("artifact"))
            claimed = str(evidence.get("sha256") or "")
            if name and _HEX64.fullmatch(claimed):
                names.add(name)
    return tuple(sorted(names))


def _application_receipt_matches_current_universe(
    root: Path, payload: Mapping[str, Any]
) -> bool:
    """Mirror the POST header gate before following receipt child artifacts."""

    try:
        _features, authority, _projection = derive_security_obligation_authority(
            root, stage=PRE_DEPTH_STAGE
        )
    except Exception:
        return False
    run_binding = authority.get("run_binding")
    if not isinstance(run_binding, Mapping):
        return False
    expected = {
        "run_id": run_binding.get("run_id", ""),
        "source_snapshot_digest": run_binding.get("source_snapshot_digest", ""),
        "authority_universe_digest": authority.get("authority_universe_digest", ""),
    }
    return all(
        str(payload.get(field) or "").casefold() == str(value or "").casefold()
        for field, value in expected.items()
    )


def security_obligation_input_artifacts(
    scratchpad: Path,
    *,
    stage: str = POST_DEPTH_STAGE,
) -> tuple[str, ...]:
    """Return the deterministic existing-file denominator for one derivation.

    Dynamic children are followed only through structurally valid, safe
    basename references in their bound parent contract/receipt.  Malformed
    parents remain in the denominator while their guessed children do not.
    The mutable whole-ledger ``_artifact_state.json`` is intentionally absent;
    POST authority binds selected ledger records inside its typed payload.
    """

    root = Path(scratchpad)
    stage_n = _normalized_stage(stage)
    names: set[str] = set()

    def add_existing(name: str) -> None:
        if name != _ARTIFACT_LEDGER_FILE and (root / name).is_file():
            names.add(name)

    for name in (
        _CHECKPOINT_FILE,
        _GRAPH_FILE,
        RECON_FEATURE_FILE,
        _asset_repr.OPERATOR_ATTESTATION_FILE,
        *_FALLBACK_ARTIFACTS,
    ):
        add_existing(name)
    if stage_n == PRE_DEPTH_STAGE:
        return tuple(sorted(names))

    contract_path = root / _DEPTH_CONTRACT_FILE
    if contract_path.is_file():
        names.add(_DEPTH_CONTRACT_FILE)
        try:
            contract = _load_json(contract_path)
        except Exception:
            contract = None
        if isinstance(contract, Mapping) and str(contract.get("phase") or "").lower() == "depth":
            for name in _depth_contract_output_names(contract):
                add_existing(name)

    receipt_path = root / APPLICATION_RECEIPT_FILE
    if receipt_path.is_file():
        names.add(APPLICATION_RECEIPT_FILE)
        try:
            receipt = _load_json(receipt_path)
        except Exception:
            receipt = None
        if isinstance(receipt, Mapping) and _application_receipt_matches_current_universe(
            root, receipt
        ):
            for name in _application_receipt_evidence_names(receipt):
                add_existing(name)
    return tuple(sorted(names))


def _normalized_ecosystem(value: object) -> str:
    return re.sub(r"[^a-z0-9_]+", "", str(value or "").strip().lower()) or "unknown"


def _normalized_stage(value: object) -> str:
    stage = str(value or POST_DEPTH_STAGE).strip().lower()
    if stage not in _STAGES:
        raise ValueError(
            "security obligation stage must be pre_depth or post_depth"
        )
    return stage


def _load_run_binding(
    root: Path,
    *,
    run_id: str = "",
    source_snapshot_digest: str = "",
    ecosystem: str = "",
    mode: str = "",
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
    snapshot = (
        checkpoint.get("audit_snapshot")
        if isinstance(checkpoint.get("audit_snapshot"), Mapping)
        else {}
    )
    components = snapshot.get("components") if isinstance(snapshot.get("components"), Mapping) else {}
    source_scope = (
        components.get("source_scope")
        if isinstance(components.get("source_scope"), Mapping)
        else {}
    )

    checkpoint_run = str(checkpoint.get("run_id") or "").strip().lower()
    chosen_run = str(run_id or checkpoint_run).strip().lower()
    if run_id and checkpoint_run and chosen_run != checkpoint_run:
        issues.append("explicit run_id differs from checkpoint run_id")
    if not _UUID4.fullmatch(chosen_run):
        issues.append("run_id is missing or is not a canonical UUIDv4")

    checkpoint_snapshot = str(snapshot.get("snapshot_digest") or "").strip().lower()
    chosen_snapshot = str(source_snapshot_digest or checkpoint_snapshot).strip().lower()
    if source_snapshot_digest and checkpoint_snapshot and chosen_snapshot != checkpoint_snapshot:
        issues.append("explicit source snapshot differs from checkpoint snapshot")
    if not _HEX64.fullmatch(chosen_snapshot):
        issues.append("source_snapshot_digest is missing or invalid")

    source_scope_digest = str(source_scope.get("digest") or "").strip().lower()
    if not _HEX64.fullmatch(source_scope_digest):
        issues.append("source_scope_digest is missing or invalid")

    chosen_ecosystem = _normalized_ecosystem(ecosystem or config.get("language"))
    chosen_mode = str(mode or config.get("mode") or "unknown").strip().lower()
    chosen_pipeline = str(config.get("pipeline") or "unknown").strip().lower()
    binding: dict[str, str] = {
        "run_id": chosen_run,
        "source_snapshot_digest": chosen_snapshot,
        "source_scope_digest": source_scope_digest,
        "ecosystem": chosen_ecosystem,
        "mode": chosen_mode,
        "pipeline": chosen_pipeline,
    }
    binding["binding_digest"] = _sha256_value(binding)
    return binding, issues


def _identifier_tokens(value: object) -> list[str]:
    text = str(value or "")
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", text)
    text = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", text)
    parts = [part.lower() for part in re.findall(r"[A-Za-z][A-Za-z0-9]*", text)]
    tokens = [_TOKEN_ALIASES.get(part, part) for part in parts]
    joined: list[str] = []
    for width in (2, 3):
        for index in range(0, max(0, len(tokens) - width + 1)):
            joined.append("".join(tokens[index : index + width]))
    return list(dict.fromkeys(tokens + joined))


def _identifier_tokens_exact(value: object) -> list[str]:
    """Preserve source spelling for identities that are case-sensitive.

    The normalized token projection remains useful for semantic discovery, but
    it is not safe evidence for binding an exact symbol/object relation.
    """

    return list(
        dict.fromkeys(re.findall(r"[A-Za-z][A-Za-z0-9]*", str(value or "")))
    )


def _safe_relative_candidate_source_path(value: object) -> str:
    path = _asset_repr.normalize_bound_path(value)
    if (
        not path
        or path.startswith("/")
        or _SAFE_PATH_DRIVE.match(path)
        or any(part == ".." for part in path.split("/"))
    ):
        return ""
    return path


def _ambiguous_wrapper_symbols(value: object) -> list[str]:
    """Return opaque leading-``w`` identifiers without granting a role.

    Symbol spelling cannot distinguish a wrapped-asset ticker from an ordinary
    word.  The caller may turn this into *classification debt* only after
    native-asset and token-operation facts co-occur in the same structural
    subject.  Exact wrapper authority must come from semantic vocabulary or a
    typed graph/recon feature relation.
    """

    owned_tokens = {
        token
        for vocabulary in _CONCEPT_TOKENS.values()
        for token in vocabulary
    } | set(_TOKEN_ALIASES) | set(_TOKEN_ALIASES.values())
    non_wrapper_words = {
        "wallet",
        "when",
        "where",
        "while",
        "with",
        "within",
        "without",
        "write",
    }
    raw_candidates: list[str] = []
    identifiers = re.findall(r"[A-Za-z][A-Za-z0-9_]*", str(value or ""))
    for identifier in identifiers:
        parts = [part for part in identifier.split("_") if part]
        for index, part in enumerate(parts):
            if part in {"w", "W"} and index + 1 < len(parts):
                stem = parts[index + 1]
                stem_n = _TOKEN_ALIASES.get(stem.casefold(), stem.casefold())
                if (
                    stem_n not in owned_tokens
                    or stem_n in _CONCEPT_TOKENS["value_asset"]
                ):
                    raw_candidates.append(part + stem)
                continue
            if re.fullmatch(r"[wW][A-Za-z0-9]{2,31}", part):
                raw_candidates.append(part)

        # Preserve a direct camel-case spelling before any tokenization.  This
        # is identity, not semantic comparison: wCoin and WCoin are distinct.
        if "_" not in identifier and re.fullmatch(
            r"[wW][A-Za-z0-9]{2,31}", identifier
        ):
            raw_candidates.append(identifier)
        if "_" not in identifier:
            camel_parts = re.findall(
                r"[A-Z]+(?=[A-Z][a-z]|[0-9]|$)|[A-Z]?[a-z]+|[0-9]+",
                identifier,
            )
            for index, part in enumerate(camel_parts):
                if part in {"w", "W"} and index + 1 < len(camel_parts):
                    raw_candidates.append(part + camel_parts[index + 1])
                elif re.fullmatch(r"[wW][A-Za-z0-9]{2,31}", part):
                    raw_candidates.append(part)

    out: list[str] = []
    for candidate in raw_candidates:
        normalized_for_filter = re.sub(
            r"[^a-z0-9]+", "", candidate.casefold()
        )
        if (
            normalized_for_filter in owned_tokens
            or normalized_for_filter in non_wrapper_words
            or len(normalized_for_filter) < 3
        ):
            continue
        exact = re.sub(r"[^A-Za-z0-9]+", "", candidate)
        if exact not in out:
            out.append(exact)
    return out


_WRAPPER_RELATION_KIND = "WRAPPED_ASSET_CLASSIFICATION"


def _wrapper_relation(
    *, subject_id: str, object_id: str, symbol: str
) -> dict[str, str]:
    subject_n = str(subject_id or "").strip()
    object_n = str(object_id or "").strip().replace("\\", "/")
    symbol_n = re.sub(r"[^A-Za-z0-9]+", "", str(symbol or ""))
    if not subject_n or not object_n or not re.fullmatch(
        r"[wW][A-Za-z0-9]{2,31}", symbol_n
    ):
        raise ValueError("wrapper relation requires subject, object, and normalized w-symbol")
    object_tokens = re.findall(r"[A-Za-z][A-Za-z0-9]*", object_n)
    if not object_tokens or object_tokens[-1] != symbol_n:
        raise ValueError("wrapper relation object does not bind its normalized symbol")
    identity = {
        "subject_id": subject_n,
        "kind": _WRAPPER_RELATION_KIND,
        "object_id": object_n,
        "symbol": symbol_n,
    }
    return {
        "relation_id": "SWR-" + _sha256_value(identity)[:24],
        "kind": _WRAPPER_RELATION_KIND,
        "object_id": object_n,
        "symbol": symbol_n,
    }


def _typed_wrapper_relation(
    raw: Mapping[str, Any],
    *,
    subject_id: str,
    label: str,
    issues: list[str],
    allow_relation: bool = True,
) -> dict[str, str] | None:
    """Validate relation metadata without treating legacy rows as authority.

    A subject-only ``wrapped_asset`` declaration may still contribute to the
    broad SO-005 question, but it cannot clear an object-specific SO-009 debt.
    Caller-supplied relation IDs are ignored and deterministically recomputed.
    """

    relation = raw.get("relation")
    if relation is None:
        return None
    if not allow_relation:
        issues.append(f"{label}: relation metadata requires recon schema v2")
        return None
    if not isinstance(relation, Mapping):
        issues.append(f"{label}: relation metadata is malformed")
        return None
    kind = str(relation.get("kind") or "").strip().upper()
    object_id = str(relation.get("object_id") or "").strip()
    symbol = str(relation.get("symbol") or "").strip()
    if kind != _WRAPPER_RELATION_KIND:
        issues.append(f"{label}: wrapper relation kind is invalid")
        return None
    try:
        return _wrapper_relation(
            subject_id=subject_id,
            object_id=object_id,
            symbol=symbol,
        )
    except ValueError as exc:
        issues.append(f"{label}: {exc}")
        return None


def _concept_evidence(value: object) -> list[tuple[str, str]]:
    tokens = _identifier_tokens(value)
    rows: list[tuple[str, str]] = []
    for concept, vocabulary in sorted(_CONCEPT_TOKENS.items()):
        for token in tokens:
            if token in vocabulary:
                rows.append((concept, token))
    return rows


def _source_row(
    *, path: Path, pointer: str, kind: str, binding_by_name: Mapping[str, Mapping[str, Any]]
) -> dict[str, str]:
    binding = binding_by_name[path.name]
    return {
        "artifact": path.name,
        "pointer": pointer,
        "source_kind": kind,
        "sha256": str(binding["sha256"]),
    }


def _add_fact(
    store: dict[str, dict[str, Any]],
    *,
    subject_id: str,
    concept: str,
    polarity: str,
    evidence_identity: str,
    fidelity: str,
    source: Mapping[str, str],
    relation: Mapping[str, str] | None = None,
    authority: Mapping[str, Any] | None = None,
) -> None:
    concept = str(concept or "").strip()
    polarity = str(polarity or "PRESENT").strip().upper()
    subject_id = str(subject_id or "").strip()
    evidence_identity = str(evidence_identity or "").strip()
    if concept not in set(_CONCEPT_TOKENS) | {"call_edge"}:
        raise ValueError(f"unsupported feature concept: {concept or '<empty>'}")
    if polarity not in {"PRESENT", "ABSENT"}:
        raise ValueError(f"unsupported feature polarity: {polarity or '<empty>'}")
    if not subject_id or not evidence_identity:
        raise ValueError("feature fact requires subject_id and evidence_identity")
    identity = {
        "subject_id": subject_id,
        "concept": concept,
        "polarity": polarity,
        "evidence_identity": evidence_identity,
    }
    relation_normalized: dict[str, str] | None = None
    if relation is not None:
        relation_normalized = {
            "relation_id": str(relation.get("relation_id") or "").strip(),
            "kind": str(relation.get("kind") or "").strip(),
            "object_id": str(relation.get("object_id") or "").strip(),
            "symbol": str(relation.get("symbol") or "").strip(),
        }
        if (
            not relation_normalized["relation_id"]
            or not relation_normalized["kind"]
            or not relation_normalized["object_id"]
            or not relation_normalized["symbol"]
        ):
            raise ValueError("feature relation metadata is incomplete")
        identity["relation_id"] = relation_normalized["relation_id"]
    fact_id = "SFF-" + _sha256_value(identity)[:24]
    row = store.get(fact_id)
    source_normalized = dict(sorted((str(k), str(v)) for k, v in source.items()))
    authority_normalized = {
        "provenance": str(
            (authority or {}).get("provenance") or _asset_repr.MODEL_PROPOSAL
        ).strip().upper(),
        "provider": str((authority or {}).get("provider") or "unknown")
        .strip()
        .casefold(),
        "capability": str(
            (authority or {}).get("capability") or _asset_repr.IDENTIFIER_ONLY
        ).strip(),
        "terminal_application_authority": bool(
            (authority or {}).get("terminal_application_authority") is True
        ),
    }
    if row is None:
        row = {
            "fact_id": fact_id,
            **identity,
            "relation": relation_normalized,
            "fidelities": [],
            "sources": [],
            "authority_provenance": [],
            "provider_capabilities": [],
            "terminal_application_authority": False,
        }
        store[fact_id] = row
    if fidelity not in row["fidelities"]:
        row["fidelities"].append(fidelity)
        row["fidelities"].sort()
    if source_normalized not in row["sources"]:
        row["sources"].append(source_normalized)
        row["sources"].sort(key=_canonical_json)
    provenance = authority_normalized["provenance"]
    if provenance not in row["authority_provenance"]:
        row["authority_provenance"].append(provenance)
        row["authority_provenance"].sort()
    provider_capability = {
        "provider": authority_normalized["provider"],
        "capability": authority_normalized["capability"],
        "terminal_application_authority": authority_normalized[
            "terminal_application_authority"
        ],
    }
    if provider_capability not in row["provider_capabilities"]:
        row["provider_capabilities"].append(provider_capability)
        row["provider_capabilities"].sort(key=_canonical_json)
    # Authority is monotonic only across independently retained evidence.  A
    # weak duplicate cannot erase a valid exact attestation, and a weak row
    # alone can never upgrade itself.
    row["terminal_application_authority"] = bool(
        row["terminal_application_authority"]
        or authority_normalized["terminal_application_authority"]
    )


def _graph_ref_subjects(
    descriptor: object,
    qualified_aliases: Mapping[str, str],
    bare_aliases: Mapping[str, Sequence[Mapping[str, str]]],
) -> list[str]:
    raw = str(descriptor or "").strip()
    name = raw.split("(", 1)[0].strip()
    if name in qualified_aliases:
        return [qualified_aliases[name]]

    # A provider may vary case when it has only one possible referent.  When
    # case-distinct source identities coexist, enumerate them as ambiguous;
    # never let a folded dict silently choose one sibling.
    qualified_folded = sorted(
        {
            subject
            for alias, subject in qualified_aliases.items()
            if alias.casefold() == name.casefold()
        }
    )
    if qualified_folded:
        return qualified_folded

    bare = re.split(r"::|\.", name)[-1]
    candidates = list(bare_aliases.get(bare, ()))
    if not candidates:
        candidates = [
            row
            for alias, rows in bare_aliases.items()
            if alias.casefold() == bare.casefold()
            for row in rows
        ]
    if candidates:
        locus_match = _SOURCE_LOCUS_RE.search(raw)
        if locus_match:
            locus = _normalized_locus(locus_match)
            exact = sorted(
                {
                    str(row.get("subject_id") or "")
                    for row in candidates
                    if str(row.get("locus") or "") == locus
                }
            )
            if exact:
                return exact
        return sorted(
            {
                str(row.get("subject_id") or "")
                for row in candidates
                if str(row.get("subject_id") or "")
            }
        )
    compact = re.sub(r"[^A-Za-z0-9_:.-]+", "_", name).strip("_")
    return ["fnref:" + (compact or _sha256_value(raw)[:16].lower())]


def _extract_graph_facts(
    root: Path,
    store: dict[str, dict[str, Any]],
    bindings: list[dict[str, Any]],
    issues: list[str],
    wrapper_candidates: list[dict[str, Any]],
    substrate_metadata: dict[str, Any] | None = None,
) -> bool:
    path = root / _GRAPH_FILE
    if not path.is_file():
        return False
    binding = _binding(path, "typed_graph")
    bindings.append(binding)
    binding_by_name = {path.name: binding}
    try:
        graph = _load_json(path)
    except Exception as exc:
        issues.append(f"mechanical graph parse failed: {type(exc).__name__}")
        return False
    if not isinstance(graph, Mapping):
        issues.append("mechanical graph root is not an object")
        return False
    functions = graph.get("functions")
    var_refs = graph.get("var_refs")
    if not isinstance(functions, Mapping) or not isinstance(var_refs, Mapping):
        issues.append("mechanical graph lacks typed functions/var_refs maps")
        return False

    qualified_aliases: dict[str, str] = {}
    bare_aliases: dict[str, list[dict[str, str]]] = {}
    for function_identity, raw in sorted(functions.items(), key=lambda item: str(item[0])):
        info = raw if isinstance(raw, Mapping) else {}
        bare = str(info.get("bare") or re.split(r"::|\.", str(function_identity))[-1])
        subject = f"fn:{function_identity}"
        qualified_aliases[str(function_identity)] = subject
        loc_match = _SOURCE_LOCUS_RE.search(str(info.get("loc") or ""))
        bare_aliases.setdefault(bare, []).append(
            {
                "subject_id": subject,
                "locus": _normalized_locus(loc_match) if loc_match else "",
            }
        )

    for function_identity, raw in sorted(functions.items(), key=lambda item: str(item[0])):
        info = raw if isinstance(raw, Mapping) else {}
        bare = str(info.get("bare") or re.split(r"::|\.", str(function_identity))[-1])
        subject = f"fn:{function_identity}"
        for concept, token in _concept_evidence(f"{function_identity} {bare}"):
            _add_fact(
                store,
                subject_id=subject,
                concept=concept,
                polarity="PRESENT",
                evidence_identity=f"graph:function-token:{token}",
                fidelity="GRAPH_SYMBOL_IDENTITY",
                source=_source_row(
                    path=path,
                    pointer=f"functions.{function_identity}",
                    kind="TYPED_GRAPH_FACT",
                    binding_by_name=binding_by_name,
                ),
            )
        callees = info.get("callees") if isinstance(info.get("callees"), list) else []
        function_source = _source_row(
            path=path,
            pointer=f"functions.{function_identity}",
            kind="TYPED_GRAPH_FACT",
            binding_by_name=binding_by_name,
        )
        for symbol in _ambiguous_wrapper_symbols(f"{function_identity} {bare}"):
            wrapper_candidates.append(
                {
                    "subject_id": subject,
                    "object_id": (
                        f"graph:function:{str(function_identity)}"
                        f"#identifier:{symbol}"
                    ),
                    "symbol": symbol,
                    "fidelity": "GRAPH_SYMBOL_CLASSIFICATION_DEBT",
                    "source": function_source,
                }
            )
        for index, callee in enumerate(callees):
            callee_text = str(callee or "").strip()
            if not callee_text:
                continue
            pointer = f"functions.{function_identity}.callees[{index}]"
            source = _source_row(
                path=path,
                pointer=pointer,
                kind="TYPED_GRAPH_FACT",
                binding_by_name=binding_by_name,
            )
            for symbol in _ambiguous_wrapper_symbols(callee_text):
                wrapper_candidates.append(
                    {
                        "subject_id": subject,
                        "object_id": (
                            "graph:callee:"
                            + _sha256_value(callee_text)[:24].lower()
                            + f"#identifier:{symbol}"
                        ),
                        "symbol": symbol,
                        "fidelity": "GRAPH_RELATION_CLASSIFICATION_DEBT",
                        "source": source,
                    }
                )
            _add_fact(
                store,
                subject_id=subject,
                concept="call_edge",
                polarity="PRESENT",
                evidence_identity=f"graph:call-edge:{callee_text.casefold()}",
                fidelity="GRAPH_RELATION",
                source=source,
            )
            for concept, token in _concept_evidence(callee_text):
                _add_fact(
                    store,
                    subject_id=subject,
                    concept=concept,
                    polarity="PRESENT",
                    evidence_identity=f"graph:callee-token:{token}:{callee_text.casefold()}",
                    fidelity="GRAPH_RELATION_TARGET",
                    source=source,
                )

    for symbol_identity, raw in sorted(var_refs.items(), key=lambda item: str(item[0])):
        info = raw if isinstance(raw, Mapping) else {}
        bare = str(info.get("bare") or re.split(r"::|\.", str(symbol_identity))[-1])
        refs = info.get("refs") if isinstance(info.get("refs"), list) else []
        for index, descriptor in enumerate(refs):
            source = _source_row(
                path=path,
                pointer=f"var_refs.{symbol_identity}.refs[{index}]",
                kind="TYPED_GRAPH_FACT",
                binding_by_name=binding_by_name,
            )
            subjects = _graph_ref_subjects(
                descriptor, qualified_aliases, bare_aliases
            )
            if len(subjects) > 1:
                issues.append(
                    "mechanical graph var_ref has ambiguous function binding: "
                    + str(descriptor or "")
                )
            for subject in subjects:
                for symbol in _ambiguous_wrapper_symbols(f"{symbol_identity} {bare}"):
                    wrapper_candidates.append(
                        {
                            "subject_id": subject,
                            "object_id": f"graph:var:{str(symbol_identity)}",
                            "symbol": symbol,
                            "fidelity": "GRAPH_STATE_CLASSIFICATION_DEBT",
                            "source": source,
                        }
                    )
                for concept, token in _concept_evidence(f"{symbol_identity} {bare}"):
                    _add_fact(
                        store,
                        subject_id=subject,
                        concept=concept,
                        polarity="PRESENT",
                        evidence_identity=f"graph:state-token:{symbol_identity}:{token}",
                        fidelity="GRAPH_STATE_REFERENCE",
                        source=source,
                    )

    # Name/reference evidence is useful for recall, but it is deliberately a
    # proposal-only boundary enumerator.  It adds one exact subject candidate
    # per seam and never claims that a representation relation is classified.
    boundary_foundation = _asset_repr.enumerate_asset_representation_candidates(
        graph
    )
    issues.extend(str(issue) for issue in boundary_foundation.get("issues", []))
    for candidate in boundary_foundation.get("candidates", []):
        if not isinstance(candidate, Mapping):
            continue
        candidate_id = str(candidate.get("candidate_id") or "").strip()
        subject_id = str(candidate.get("subject_id") or "").strip()
        occurrence_id = str(candidate.get("occurrence_id") or "").strip()
        if not candidate_id or not subject_id or not occurrence_id:
            issues.append("asset representation candidate is malformed")
            continue
        candidate_source_path = _safe_relative_candidate_source_path(
            candidate.get("source_path")
        )
        candidate_path_repair_id = ""
        if not candidate_source_path:
            # The exact graph pointer remains a safe, bound source for
            # additive work.  An untrusted filesystem spelling is never
            # promoted into candidate authority or used to discard the seam.
            stable_candidate_identity = {
                "subject_id": subject_id,
                "occurrence_id": occurrence_id,
                "native_evidence": sorted(
                    str(value)
                    for value in candidate.get("native_evidence") or []
                ),
                "representation_evidence": sorted(
                    str(value)
                    for value in candidate.get("representation_evidence") or []
                ),
                "provider": str(candidate.get("provider") or "unknown"),
                "source_binding": "UNSAFE_PATH_EXCLUDED",
            }
            candidate_id = (
                "ARB-" + _sha256_value(stable_candidate_identity)[:24]
            )
            candidate_path_repair_id = (
                "ARR-"
                + _sha256_value(
                    {
                        "repair_kind": "UNSAFE_CANDIDATE_SOURCE_PATH",
                        "subject_id": subject_id,
                        "occurrence_id": occurrence_id,
                    }
                )[:24]
            )
        candidate_source = _source_row(
            path=path,
            pointer="functions." + occurrence_id.removeprefix("function:"),
            kind="MECHANICAL_CANDIDATE",
            binding_by_name=binding_by_name,
        )
        _add_fact(
            store,
            subject_id=subject_id,
            concept="asset_representation_boundary",
            polarity="PRESENT",
            evidence_identity="asset-representation-candidate:" + candidate_id,
            fidelity="MECHANICAL_PROPOSAL_ONLY",
            source=candidate_source,
            relation={
                "relation_id": candidate_id,
                "kind": "ASSET_REPRESENTATION_BOUNDARY",
                "object_id": occurrence_id,
                "symbol": "native-tokenized-boundary",
            },
            authority={
                "provenance": _asset_repr.MODEL_PROPOSAL,
                "provider": str(candidate.get("provider") or "unknown"),
                "capability": str(
                    candidate.get("provider_capability")
                    or _asset_repr.IDENTIFIER_ONLY
                ),
                "terminal_application_authority": False,
            },
        )
        if candidate_path_repair_id:
            _add_fact(
                store,
                subject_id=subject_id,
                concept="asset_representation_edge_repair",
                polarity="PRESENT",
                evidence_identity=(
                    "asset-representation-candidate-path-repair:"
                    + candidate_path_repair_id
                ),
                fidelity="LOCALIZED_CANDIDATE_SOURCE_PATH_REPAIR",
                source={
                    **candidate_source,
                    "source_kind": "MECHANICAL_CANDIDATE_REPAIR",
                },
                relation={
                    "relation_id": candidate_path_repair_id,
                    "kind": "ASSET_REPRESENTATION_CANDIDATE_SOURCE_PATH_REPAIR",
                    "object_id": occurrence_id,
                    "symbol": occurrence_id,
                },
                authority={
                    "provenance": _asset_repr.MODEL_PROPOSAL,
                    "provider": str(candidate.get("provider") or "unknown"),
                    "capability": _asset_repr.UNAVAILABLE,
                    "terminal_application_authority": False,
                },
            )

    semantic_foundation = _asset_repr.extract_semantic_edge_foundation(graph)
    semantic_edge_registry = {
        str(row.get("edge_id") or ""): row
        for row in semantic_foundation.get("semantic_edges", [])
        if isinstance(row, Mapping) and str(row.get("edge_id") or "")
    }
    for repair in semantic_foundation.get("repair_obligations", []):
        if not isinstance(repair, Mapping):
            continue
        repair_id = str(repair.get("repair_id") or "").strip()
        object_id = str(repair.get("object_id") or "").strip()
        pointer = str(repair.get("pointer") or "semantic_edges[unknown]")
        if not repair_id or not object_id:
            continue
        _add_fact(
            store,
            subject_id=str(repair.get("subject_id") or f"graph:{graph.get('source') or 'unknown'}"),
            concept="asset_representation_edge_repair",
            polarity="PRESENT",
            evidence_identity="asset-representation-repair:" + repair_id,
            fidelity="LOCALIZED_TYPED_EDGE_REPAIR",
            source=_source_row(
                path=path,
                pointer=pointer,
                kind="TYPED_GRAPH_REPAIR_DEBT",
                binding_by_name=binding_by_name,
            ),
            relation={
                "relation_id": repair_id,
                "kind": "ASSET_REPRESENTATION_EDGE_REPAIR",
                "object_id": object_id,
                "symbol": str(repair.get("occurrence_id") or pointer),
            },
            authority={
                "provenance": _asset_repr.MODEL_PROPOSAL,
                "provider": str(graph.get("source") or "unknown"),
                "capability": _asset_repr.UNAVAILABLE,
                "terminal_application_authority": False,
            },
        )
    if substrate_metadata is not None:
        substrate_metadata["asset_representation_foundation"] = {
            "schema_version": str(semantic_foundation.get("schema_version") or ""),
            "migration_state": str(
                semantic_foundation.get("migration_state") or "DEBT"
            ),
            "provider_capability": semantic_foundation.get(
                "provider_capability", {}
            ),
            "semantic_edge_count": len(
                semantic_foundation.get("semantic_edges", [])
            ),
            "repair_obligation_count": len(
                semantic_foundation.get("repair_obligations", [])
            ),
            "provider_authority_state": str(
                semantic_foundation.get("provider_authority_state") or ""
            ),
            "provider_capability_matrix_version": str(
                semantic_foundation.get("provider_capability_matrix_version")
                or ""
            ),
            "provider_capability_matrix_sha256": str(
                semantic_foundation.get("provider_capability_matrix_sha256")
                or ""
            ),
            "candidate_count": int(
                boundary_foundation.get("candidate_count") or 0
            ),
            "issues": list(semantic_foundation.get("issues", [])),
        }
        substrate_metadata["_semantic_edge_registry"] = semantic_edge_registry

    explicit = graph.get("feature_facts")
    if explicit is not None:
        if not isinstance(explicit, list):
            issues.append("mechanical graph feature_facts is not a list")
        else:
            for index, raw in enumerate(explicit):
                if not isinstance(raw, Mapping):
                    issues.append(f"mechanical graph feature_facts[{index}] is malformed")
                    continue
                try:
                    subject_id = str(raw.get("subject_id") or "")
                    feature_authority, authority_issues = (
                        _asset_repr.resolve_feature_authority(
                            raw,
                            origin="GRAPH",
                            schema_version=str(graph.get("schema_version") or ""),
                            run_binding={},
                            graph_provider=str(graph.get("source") or ""),
                            semantic_edges=semantic_edge_registry,
                        )
                    )
                    issues.extend(
                        f"mechanical graph feature_facts[{index}]: {issue}"
                        for issue in authority_issues
                    )
                    relation = (
                        _typed_wrapper_relation(
                            raw,
                            subject_id=subject_id,
                            label=f"mechanical graph feature_facts[{index}]",
                            issues=issues,
                        )
                        if str(raw.get("concept") or "") == "wrapped_asset"
                        else None
                    )
                    _add_fact(
                        store,
                        subject_id=subject_id,
                        concept=str(raw.get("concept") or ""),
                        polarity=str(raw.get("polarity") or "PRESENT"),
                        evidence_identity=str(raw.get("evidence_identity") or raw.get("fact_id") or ""),
                        fidelity="GRAPH_EXPLICIT_FEATURE",
                        source=_source_row(
                            path=path,
                            pointer=f"feature_facts[{index}]",
                            kind="TYPED_GRAPH_FACT",
                            binding_by_name=binding_by_name,
                        ),
                        relation=relation,
                        authority=feature_authority,
                    )
                except ValueError as exc:
                    issues.append(f"mechanical graph feature_facts[{index}]: {exc}")

    return True


def _extract_recon_facts(
    root: Path,
    store: dict[str, dict[str, Any]],
    bindings: list[dict[str, Any]],
    issues: list[str],
    run_binding: Mapping[str, str],
    semantic_edges: Mapping[str, Mapping[str, Any]] | None = None,
    provenance_summary: dict[str, Any] | None = None,
) -> bool:
    path = root / RECON_FEATURE_FILE
    if not path.is_file():
        return False
    binding = _binding(path, "typed_recon_features")
    bindings.append(binding)
    binding_by_name = {path.name: binding}
    operator_attestations, attestation_issues = (
        _asset_repr.load_operator_attestation_registry(
            root, run_binding=run_binding
        )
    )
    if provenance_summary is not None:
        provenance_summary["attestation_registry_issues"] = sorted(
            set(str(issue) for issue in attestation_issues)
        )
    attestation_path = root / _asset_repr.OPERATOR_ATTESTATION_FILE
    if attestation_path.is_file():
        attestation_binding = _binding(
            attestation_path, "operator_asset_representation_attestation"
        )
        bindings.append(attestation_binding)
    try:
        payload = _load_json(path)
    except Exception as exc:
        issues.append(f"recon feature facts parse failed: {type(exc).__name__}")
        return False
    if not isinstance(payload, Mapping) or payload.get("schema_version") not in {
        RECON_FEATURE_SCHEMA_V3,
        RECON_FEATURE_SCHEMA,
        LEGACY_RECON_FEATURE_SCHEMA,
    }:
        issues.append("recon feature facts schema mismatch")
        return False
    recon_schema = str(payload.get("schema_version") or "")
    valid = True
    for field in ("run_id", "source_snapshot_digest", "ecosystem"):
        expected = str(run_binding.get(field) or "").casefold()
        actual = str(payload.get(field) or "").casefold()
        if actual != expected:
            issues.append(f"recon feature facts {field} mismatch")
            valid = False
    raw_facts = payload.get("facts")
    if not isinstance(raw_facts, list):
        issues.append("recon feature facts facts is not a list")
        return False
    if not valid:
        return False
    for index, raw in enumerate(raw_facts):
        if not isinstance(raw, Mapping):
            issues.append(f"recon feature facts row {index} is malformed")
            continue
        try:
            subject_id = str(raw.get("subject_id") or "")
            feature_authority, authority_issues = (
                _asset_repr.resolve_feature_authority(
                    raw,
                    origin="RECON",
                    schema_version=recon_schema,
                    run_binding=run_binding,
                    operator_attestations=operator_attestations,
                    semantic_edges=semantic_edges,
                )
            )
            if provenance_summary is not None:
                state = str(feature_authority.get("authority_state") or "")
                if state == "LEGACY_MODEL_PROPOSAL":
                    provenance_summary["legacy_model_proposal_count"] += 1
                elif state.startswith("RESERVED_OPERATOR_"):
                    provenance_summary["reserved_operator_count"] += 1
                elif state.startswith("RESERVED_PROVIDER_"):
                    provenance_summary["reserved_provider_count"] += 1
                elif state.startswith("INVALID_"):
                    provenance_summary["invalid_claim_count"] += 1
                else:
                    provenance_summary["model_proposal_count"] += 1
                if authority_issues:
                    provenance_summary["localized_notes"].extend(
                        f"facts[{index}]:{issue}" for issue in authority_issues
                    )
            relation = (
                _typed_wrapper_relation(
                    raw,
                    subject_id=subject_id,
                    label=f"recon feature facts row {index}",
                    issues=issues,
                    allow_relation=recon_schema
                    in {RECON_FEATURE_SCHEMA, RECON_FEATURE_SCHEMA_V3},
                )
                if str(raw.get("concept") or "") == "wrapped_asset"
                else None
            )
            _add_fact(
                store,
                subject_id=subject_id,
                concept=str(raw.get("concept") or ""),
                polarity=str(raw.get("polarity") or "PRESENT"),
                evidence_identity=str(raw.get("evidence_identity") or raw.get("fact_id") or ""),
                fidelity="TYPED_RECON_DECLARATION",
                source=_source_row(
                    path=path,
                    pointer=f"facts[{index}]",
                    kind="TYPED_RECON_FACT",
                    binding_by_name=binding_by_name,
                ),
                relation=relation,
                authority=feature_authority,
            )
        except ValueError as exc:
            issues.append(f"recon feature facts row {index}: {exc}")
    return True


def _normalized_locus(match: re.Match[str]) -> str:
    path = match.group("path").replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    path = "/".join(part for part in path.split("/") if part != ".")
    return f"{path}:L{int(match.group('line'))}"


def _extract_fallback_facts(
    root: Path,
    store: dict[str, dict[str, Any]],
    bindings: list[dict[str, Any]],
    wrapper_candidates: list[dict[str, Any]],
) -> int:
    emitted_before = len(store)
    binding_by_name: dict[str, dict[str, Any]] = {}
    for name in _FALLBACK_ARTIFACTS:
        path = root / name
        if not path.is_file():
            continue
        binding = _binding(path, "structured_markdown_fallback")
        bindings.append(binding)
        binding_by_name[name] = binding
        text = path.read_text(encoding="utf-8", errors="replace")
        for line_no, line in enumerate(text.splitlines(), start=1):
            loci = list(_SOURCE_LOCUS_RE.finditer(line))
            if not loci:
                continue
            concepts = _concept_evidence(line)
            if len({concept for concept, _ in concepts}) < 2:
                continue
            ambiguous_symbols = _ambiguous_wrapper_symbols(line)
            for locus_match in loci:
                locus = _normalized_locus(locus_match)
                subject = f"locus:{locus}"
                for concept, token in concepts:
                    _add_fact(
                        store,
                        subject_id=subject,
                        concept=concept,
                        polarity="PRESENT",
                        evidence_identity=f"fallback:{locus}:{token}",
                        fidelity="SOURCE_LOCUS_STRUCTURED_FALLBACK",
                        source=_source_row(
                            path=path,
                            pointer=f"line:{line_no}:{locus}",
                            kind="STRUCTURED_FALLBACK_FACT",
                            binding_by_name=binding_by_name,
                        ),
                    )
                for symbol in ambiguous_symbols:
                    wrapper_candidates.append(
                        {
                            "subject_id": subject,
                            "object_id": f"fallback:{locus}#identifier:{symbol}",
                            "symbol": symbol,
                            "fidelity": "SOURCE_LOCUS_CLASSIFICATION_DEBT",
                            "source": _source_row(
                            path=path,
                            pointer=f"line:{line_no}:{locus}",
                            kind="STRUCTURED_FALLBACK_FACT",
                            binding_by_name=binding_by_name,
                        ),
                        }
                    )
    return len(store) - emitted_before


def _reconcile_wrapper_candidates(
    store: dict[str, dict[str, Any]],
    candidates: Sequence[Mapping[str, Any]],
) -> None:
    """Emit unresolved wrapper-role debt after all typed sources are merged.

    Suppression is exact on a deterministic subject/object relation.  A legacy
    subject-only wrapped fact never clears an object relation, and a conflicted
    relation remains queueable.
    """

    concepts_by_subject: dict[str, set[str]] = {}
    wrapper_polarities: dict[str, set[str]] = {}
    for row in store.values():
        subject = str(row.get("subject_id") or "")
        polarity = str(row.get("polarity") or "")
        concept = str(row.get("concept") or "")
        if polarity == "PRESENT":
            concepts_by_subject.setdefault(subject, set()).add(concept)
        if concept != "wrapped_asset":
            continue
        # PRESENT is only classification authority when its exact provenance
        # and provider capability survived validation.  Model proposals and
        # legacy recon declarations remain useful context but cannot suppress
        # independently enumerated application work.
        if row.get("terminal_application_authority") is not True:
            continue
        relation = row.get("relation")
        if not isinstance(relation, Mapping):
            continue
        relation_id = str(relation.get("relation_id") or "")
        if relation_id:
            wrapper_polarities.setdefault(relation_id, set()).add(polarity)

    for raw in sorted(
        candidates,
        key=lambda row: (
            str(row.get("subject_id") or ""),
            str(row.get("object_id") or ""),
            _canonical_json(row.get("source") or {}),
        ),
    ):
        subject = str(raw.get("subject_id") or "").strip()
        concepts = concepts_by_subject.get(subject, set())
        if not {"native_asset", "token_operation"} <= concepts:
            continue
        try:
            relation = _wrapper_relation(
                subject_id=subject,
                object_id=str(raw.get("object_id") or ""),
                symbol=str(raw.get("symbol") or ""),
            )
        except ValueError:
            # Candidates are constructed internally; malformed rows are simply
            # ineligible rather than converted into misleading authority.
            continue
        if wrapper_polarities.get(relation["relation_id"]) == {"PRESENT"}:
            continue
        _add_fact(
            store,
            subject_id=subject,
            concept="wrapped_asset_ambiguous",
            polarity="PRESENT",
            evidence_identity="wrapper-candidate:" + relation["relation_id"],
            fidelity=str(raw.get("fidelity") or "WRAPPER_CLASSIFICATION_DEBT"),
            source=(
                raw.get("source")
                if isinstance(raw.get("source"), Mapping)
                else {}
            ),
            relation=relation,
        )


def _conflicts(facts: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str], dict[str, list[str]]] = {}
    for row in facts:
        relation = row.get("relation")
        relation_id = (
            str(relation.get("relation_id") or "")
            if isinstance(relation, Mapping)
            else ""
        )
        key = (str(row["subject_id"]), str(row["concept"]), relation_id)
        grouped.setdefault(key, {"PRESENT": [], "ABSENT": []})[
            str(row["polarity"])
        ].append(str(row["fact_id"]))
    out: list[dict[str, Any]] = []
    for (subject, concept, relation_id), polarities in sorted(grouped.items()):
        if polarities["PRESENT"] and polarities["ABSENT"]:
            identity = {
                "subject_id": subject,
                "concept": concept,
                "relation_id": relation_id,
                "present_fact_ids": sorted(polarities["PRESENT"]),
                "absent_fact_ids": sorted(polarities["ABSENT"]),
            }
            out.append({"conflict_id": "SFC-" + _sha256_value(identity)[:24], **identity})
    return out


def _match_groups(
    concept_facts: Mapping[str, Sequence[Mapping[str, Any]]],
    groups: Sequence[Sequence[str]],
) -> list[Mapping[str, Any]] | None:
    choices: list[list[Mapping[str, Any]]] = []
    for group in groups:
        rows = [
            row
            for concept in group
            for row in concept_facts.get(concept, ())
            if row.get("polarity") == "PRESENT"
        ]
        rows.sort(key=lambda row: str(row["fact_id"]))
        if not rows:
            return None
        choices.append(rows)

    def select(index: int, used: set[str], picked: list[Mapping[str, Any]]) -> list[Mapping[str, Any]] | None:
        if index == len(choices):
            return list(picked)
        for row in choices[index]:
            evidence = str(row["evidence_identity"])
            if evidence in used:
                continue
            found = select(index + 1, used | {evidence}, picked + [row])
            if found is not None:
                return found
        return None

    return select(0, set(), [])


def _trigger_source(rows: Sequence[Mapping[str, Any]]) -> str:
    kinds = {
        str(source.get("source_kind") or "")
        for row in rows
        for source in row.get("sources", [])
        if isinstance(source, Mapping)
    }
    graph_kinds = {
        "TYPED_GRAPH_FACT",
        "MECHANICAL_CANDIDATE",
        "MECHANICAL_CANDIDATE_REPAIR",
        "TYPED_GRAPH_REPAIR_DEBT",
    }
    has_graph = bool(kinds & graph_kinds)
    if has_graph and "TYPED_RECON_FACT" in kinds:
        return "MIXED_TYPED_FACTS"
    if has_graph:
        return "TYPED_GRAPH_FACTS"
    if "TYPED_RECON_FACT" in kinds:
        return "TYPED_RECON_FACTS"
    return "STRUCTURED_FALLBACK"


def _derive_obligations(
    facts: Sequence[Mapping[str, Any]],
    conflicts: Sequence[Mapping[str, Any]],
    run_binding: Mapping[str, str],
) -> list[dict[str, Any]]:
    by_subject: dict[str, dict[str, list[Mapping[str, Any]]]] = {}
    for row in facts:
        by_subject.setdefault(str(row["subject_id"]), {}).setdefault(
            str(row["concept"]), []
        ).append(row)
    conflict_by_key = {
        (
            str(row["subject_id"]),
            str(row["concept"]),
            str(row.get("relation_id") or ""),
        ): str(row["conflict_id"])
        for row in conflicts
    }
    conflict_by_relation: dict[tuple[str, str], set[str]] = {}
    for row in conflicts:
        relation_id = str(row.get("relation_id") or "")
        if relation_id:
            conflict_by_relation.setdefault(
                (str(row["subject_id"]), relation_id), set()
            ).add(str(row["conflict_id"]))
    obligations: list[dict[str, Any]] = []
    for rule in _RULES:
        aliases: list[dict[str, Any]] = []
        selected_rows: dict[str, Mapping[str, Any]] = {}
        conflict_ids: set[str] = set()
        for subject, concept_facts in sorted(by_subject.items()):
            if rule.get("alias_partition") == "fact":
                concept = str(rule["groups"][0][0])
                matches = [
                    [row]
                    for row in sorted(
                        concept_facts.get(concept, ()),
                        key=lambda item: str(item["fact_id"]),
                    )
                    if row.get("polarity") == "PRESENT"
                ]
            else:
                matched = _match_groups(concept_facts, rule["groups"])
                matches = [] if matched is None else [matched]
            for selected in matches:
                fact_ids = sorted(str(row["fact_id"]) for row in selected)
                relation = selected[0].get("relation")
                relation_fields = (
                    {
                        "relation_id": str(relation.get("relation_id") or ""),
                        "object_id": str(relation.get("object_id") or ""),
                        "symbol": str(relation.get("symbol") or ""),
                    }
                    if isinstance(relation, Mapping)
                    else {}
                )
                alias_identity = {
                    "rule_id": rule["rule_id"],
                    "subject_id": subject,
                    "fact_ids": fact_ids,
                    **relation_fields,
                }
                aliases.append(
                    {
                        "alias_id": "SOT-" + _sha256_value(alias_identity)[:24],
                        "subject_id": subject,
                        "fact_ids": fact_ids,
                        "trigger_source": _trigger_source(selected),
                        **relation_fields,
                    }
                )
                relation_id_for_alias = str(relation_fields.get("relation_id") or "")
                if relation_id_for_alias:
                    conflict_ids.update(
                        conflict_by_relation.get(
                            (subject, relation_id_for_alias), set()
                        )
                    )
                for row in selected:
                    selected_rows[str(row["fact_id"])] = row
                    row_relation = row.get("relation")
                    relation_id = (
                        str(row_relation.get("relation_id") or "")
                        if isinstance(row_relation, Mapping)
                        else ""
                    )
                    conflict_id = conflict_by_key.get(
                        (subject, str(row["concept"]), relation_id)
                    )
                    if conflict_id:
                        conflict_ids.add(conflict_id)
        if not aliases:
            continue
        aliases.sort(
            key=lambda row: (
                str(row.get("object_id") or ""),
                str(row["alias_id"]),
            )
        )
        all_rows = [selected_rows[key] for key in sorted(selected_rows)]
        sources = {str(row["trigger_source"]) for row in aliases}
        if "TYPED_GRAPH_FACTS" in sources:
            source = "TYPED_GRAPH_FACTS"
        elif "TYPED_RECON_FACTS" in sources or "MIXED_TYPED_FACTS" in sources:
            source = "TYPED_RECON_FACTS"
        else:
            source = "STRUCTURED_FALLBACK"
        identity = {
            "rule_id": rule["rule_id"],
            "rule_version": rule["rule_version"],
            "source_snapshot_digest": run_binding["source_snapshot_digest"],
        }
        obligations.append(
            {
                "obligation_id": "SOBL-" + _sha256_value(identity)[:24],
                "display_id": rule["display_id"],
                "rule_id": rule["rule_id"],
                "rule_version": rule["rule_version"],
                "class": rule["class"],
                "question": rule["question"],
                "trigger_source": source,
                "fact_ids": sorted(selected_rows),
                "target_ids": sorted(
                    {
                        str(alias.get("relation_id") or alias["subject_id"])
                        for alias in aliases
                    }
                ),
                "trigger_aliases": aliases,
                "conflict_ids": sorted(conflict_ids),
                "state": "CONFLICTED_REVIEW" if conflict_ids else "UNACCOUNTED",
                "receipts": [],
            }
        )
    return obligations


def _coverage_debt(run_binding: Mapping[str, str], reason: str) -> dict[str, Any]:
    identity = {
        "rule_id": "security.feature_fact_coverage.v1",
        "source_snapshot_digest": run_binding.get("source_snapshot_digest", ""),
    }
    return {
        "obligation_id": "SOBL-" + _sha256_value(identity)[:24],
        "display_id": "SO-000",
        "rule_id": "security.feature_fact_coverage.v1",
        "rule_version": "1.0.0",
        "class": "feature_fact_coverage_debt",
        "question": FEATURE_FACT_COVERAGE_QUESTION,
        "trigger_source": "FEATURE_FACT_SUBSTRATE_UNAVAILABLE",
        "fact_ids": [],
        "target_ids": [],
        "trigger_aliases": [],
        "conflict_ids": [],
        "state": "DEGRADED_REVIEW",
        "receipts": [],
        "coverage_reason": reason,
    }


def _universe_digest(obligations: Sequence[Mapping[str, Any]]) -> str:
    universe = [
        {
            "obligation_id": row["obligation_id"],
            "display_id": row["display_id"],
            "rule_id": row["rule_id"],
            "rule_version": row["rule_version"],
            "fact_ids": row.get("fact_ids", []),
            "target_ids": row.get("target_ids", []),
            "trigger_aliases": row.get("trigger_aliases", []),
        }
        for row in obligations
    ]
    return _sha256_value(universe)


def _valid_legacy_receipt(status: str, key: str, target: str) -> bool:
    if not key.strip() or not target.strip() or target.strip().casefold() in {"n/a", "none", "unknown"}:
        return False
    if status == "R":
        return bool(re.search(r"\b[A-Za-z][A-Za-z0-9_]*-\d+\b", target))
    if status == "C":
        return bool(re.fullmatch(r"[A-Za-z][A-Za-z0-9_.:-]*(?:\s+[A-Za-z][A-Za-z0-9_.:-]*)*", target))
    return len(target.strip()) >= 3


def _markdown_fence_transition(
    line: str, active: tuple[str, int] | None
) -> tuple[tuple[str, int] | None, bool]:
    """Track CommonMark-style backtick/tilde fences with <=3-space indent."""

    indent = len(line) - len(line.lstrip(" "))
    if indent > 3:
        return active, False
    stripped = line[indent:].rstrip("\r\n")
    if active is not None:
        marker, minimum = active
        run = len(stripped) - len(stripped.lstrip(marker))
        if run >= minimum and not stripped[run:].strip():
            return None, True
        return active, False
    if not stripped or stripped[0] not in {"`", "~"}:
        return None, False
    marker = stripped[0]
    run = len(stripped) - len(stripped.lstrip(marker))
    if run < 3:
        return None, False
    return (marker, run), True


def _finding_sections(
    text: str,
    *,
    issues: list[str] | None = None,
    source_label: str = "",
) -> dict[str, str]:
    """Return non-overlapping finding sections using Markdown heading scope."""

    collected: dict[str, list[str]] = {}
    active_id = ""
    active_level = 0
    active_lines: list[str] = []
    fence: tuple[str, int] | None = None

    def close_active() -> None:
        nonlocal active_id, active_level, active_lines
        if active_id:
            collected.setdefault(active_id, []).append("".join(active_lines))
        active_id = ""
        active_level = 0
        active_lines = []

    for line in (text or "").splitlines(keepends=True):
        was_fenced = fence is not None
        next_fence, fence_line = _markdown_fence_transition(line, fence)
        heading = None
        if not was_fenced and not fence_line:
            heading = _MARKDOWN_HEADING_RE.fullmatch(line.rstrip("\r\n"))

        if active_id and heading is not None:
            level = len(heading.group("hashes"))
            if level <= active_level:
                close_active()

        if not active_id and heading is not None:
            title_match = _FINDING_HEADING_TITLE_RE.fullmatch(
                heading.group("title").strip()
            )
            level = len(heading.group("hashes"))
            if title_match and 2 <= level <= 4:
                active_id = title_match.group("id").strip().casefold()
                active_level = level

        if active_id:
            active_lines.append(line)
        fence = next_fence
    close_active()

    sections: dict[str, str] = {}
    for finding_id, rows in collected.items():
        if len(rows) == 1:
            sections[finding_id] = rows[0]
            continue
        if issues is not None:
            issues.append(
                "duplicate finding referent invalidated locally: "
                f"{source_label or '<depth-output>'}:{finding_id}"
            )
    return sections


def _alias_evidence_binding(alias: Mapping[str, Any]) -> dict[str, str]:
    """Canonical exact identity a finding must carry for one current alias."""

    return {
        "schema_version": EVIDENCE_BINDING_SCHEMA,
        "alias_id": str(alias.get("alias_id") or ""),
        "subject_id": str(alias.get("subject_id") or ""),
        "relation_id": str(alias.get("relation_id") or ""),
        "object_id": str(alias.get("object_id") or ""),
        "symbol": str(alias.get("symbol") or ""),
    }


def _closed_alias_evidence_binding(
    raw: Mapping[str, Any],
) -> dict[str, str] | None:
    if set(raw) != _EVIDENCE_BINDING_KEYS:
        return None
    if any(type(raw[key]) is not str for key in _EVIDENCE_BINDING_KEYS):
        return None
    row = {key: str(raw[key]) for key in _EVIDENCE_BINDING_KEYS}
    if (
        row["schema_version"] != EVIDENCE_BINDING_SCHEMA
        or not re.fullmatch(r"SOT-[0-9A-F]{24}", row["alias_id"])
        or not row["subject_id"]
    ):
        return None
    return _alias_evidence_binding(row)


def _finding_alias_evidence_bindings(
    section: str,
    *,
    issues: list[str],
    source_label: str,
) -> list[dict[str, str]]:
    """Extract full-line structured bindings from one bound finding section.

    Natural-language tokens are intentionally not a fallback.  A malformed,
    partial, or conflicting marker stays nonterminal and leaves its alias
    queueable for repair.
    """

    rows: list[dict[str, str]] = []

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in pairs:
            if key in out:
                raise ValueError(f"duplicate JSON key: {key}")
            out[key] = value
        return out

    fence: tuple[str, int] | None = None
    for line_no, line in enumerate((section or "").splitlines(), start=1):
        was_fenced = fence is not None
        next_fence, fence_line = _markdown_fence_transition(line, fence)
        if "PLAMEN_SECURITY_OBLIGATION_EVIDENCE" not in line:
            fence = next_fence
            continue
        if was_fenced or fence_line:
            issues.append(
                "fenced structured obligation evidence ignored: "
                f"{source_label}:{line_no}"
            )
            fence = next_fence
            continue
        match = _EVIDENCE_BINDING_RE.fullmatch(line)
        if not match:
            issues.append(
                "malformed structured obligation evidence ignored: "
                f"{source_label}:{line_no}"
            )
            fence = next_fence
            continue
        try:
            raw = json.loads(
                match.group("payload"), object_pairs_hook=unique_object
            )
        except (TypeError, ValueError):
            issues.append(
                "malformed structured obligation evidence JSON ignored: "
                f"{source_label}:{line_no}"
            )
            fence = next_fence
            continue
        if not isinstance(raw, Mapping):
            issues.append(
                "structured obligation evidence is not an object: "
                f"{source_label}:{line_no}"
            )
            fence = next_fence
            continue
        row = _closed_alias_evidence_binding(raw)
        if row is None:
            issues.append(
                "structured obligation evidence schema or identity is invalid: "
                f"{source_label}:{line_no}"
            )
            fence = next_fence
            continue
        rows.append(row)
        fence = next_fence
    rows.sort(key=_canonical_json)
    return rows


def _reported_receipt_matches_alias(
    receipt: Mapping[str, Any], alias: Mapping[str, Any]
) -> bool:
    """Require structural finding evidence before a producer R can cover an alias.

    This predicate is used for every relation-scoped obligation.  It is
    deliberately conservative: failure keeps repair work alive and never
    drops a finding.
    """

    expected = _alias_evidence_binding(alias)
    rows = [
        closed
        for row in receipt.get("referent_alias_bindings") or []
        if isinstance(row, Mapping)
        for closed in [_closed_alias_evidence_binding(row)]
        if closed is not None and closed["alias_id"] == expected["alias_id"]
    ]
    if not rows:
        return False
    # An exact row may be repeated idempotently.  Any conflicting assertion
    # for the same alias makes the finding section ambiguous and non-binding.
    return all(row == expected for row in rows)


def _manifest_digest(manifest: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        manifest,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _input_set_digest(records: Mapping[str, Any]) -> str:
    semantic = [
        {
            "identity": identity,
            "input_class": row.get("input_class", ""),
            "status": row.get("status", ""),
            "size": row.get("size", 0),
            "sha256": row.get("sha256", ""),
            "producer_work_unit_key": row.get("producer_work_unit_key", ""),
            "producer_contract_digest": row.get("producer_contract_digest", ""),
        }
        for identity, raw in sorted(records.items())
        for row in [raw if isinstance(raw, Mapping) else {}]
    ]
    return hashlib.sha256(
        json.dumps(
            semantic, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()


def _manifest_output(
    manifest: Mapping[str, Any], identity: str
) -> Mapping[str, Any] | None:
    outputs = manifest.get("outputs")
    if not isinstance(outputs, list):
        return None
    return next(
        (
            row
            for row in outputs
            if isinstance(row, Mapping) and row.get("identity") == identity
        ),
        None,
    )


def _validate_pre_sidecar_consumption(
    ledger: Mapping[str, Any],
    owner_unit: Mapping[str, Any],
    *,
    run_id: str,
) -> str:
    inputs = owner_unit.get("input_bindings")
    if not isinstance(inputs, Mapping):
        return "owner work unit has no prelaunch input bindings"
    owner_manifest = owner_unit.get("contract_manifest")
    if not isinstance(owner_manifest, Mapping):
        return "owner work unit has no exact contract manifest"
    immutable = owner_manifest.get("immutable_inputs")
    bounded = owner_manifest.get("bounded_lookup_inputs")
    if not isinstance(immutable, list) or not isinstance(bounded, list):
        return "owner work unit input denominator is malformed"
    if set(inputs) != set(immutable) | set(bounded):
        return "owner work unit input denominator mismatch"
    if owner_unit.get("input_set_digest") != _input_set_digest(inputs):
        return "owner work unit input receipt digest mismatch"
    if owner_unit.get("semantic_status") != "ACTIVE" or any(
        not isinstance(row, Mapping) or row.get("status") != "ACTIVE"
        for row in inputs.values()
    ):
        return "owner work unit has unresolved prelaunch input debt"
    work_units = ledger.get("work_units")
    if not isinstance(work_units, Mapping):
        return "artifact ledger has no work_units map"
    global_bindings = ledger.get("artifact_bindings")
    if not isinstance(global_bindings, Mapping):
        return "artifact ledger has no global artifact bindings map"
    producer_keys: set[str] = set()
    for name in (FEATURE_FACT_FILE, AUTHORITY_FILE, PROJECTION_FILE):
        identity = f"scratchpad:{name}"
        binding = inputs.get(identity)
        if not isinstance(binding, Mapping):
            return f"owner work unit did not bind PRE sidecar {identity}"
        if binding.get("status") != "ACTIVE":
            return f"owner work unit PRE sidecar is not ACTIVE: {identity}"
        digest = str(binding.get("sha256") or "").lower()
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            return f"owner work unit PRE sidecar hash is invalid: {identity}"
        producer_key = str(binding.get("producer_work_unit_key") or "")
        parts = producer_key.split("/")
        if (
            len(parts) != 6
            or parts[4] != "depth"
            or parts[5] != "security_obligations.pre_depth"
        ):
            return f"owner work unit PRE sidecar producer is invalid: {identity}"
        producer_keys.add(producer_key)
        producer = work_units.get(producer_key)
        if not isinstance(producer, Mapping):
            return f"PRE sidecar producer work unit missing: {identity}"
        if str(producer.get("run_id") or "").casefold() != run_id.casefold():
            return f"PRE sidecar producer run_id mismatch: {identity}"
        producer_manifest = producer.get("contract_manifest")
        if not isinstance(producer_manifest, Mapping):
            return f"PRE sidecar producer manifest missing: {identity}"
        producer_digest = str(producer.get("contract_digest") or "")
        producer_launch_digest = str(producer.get("launch_digest") or "")
        if (
            producer_manifest.get("key") != producer_key
            or _manifest_digest(producer_manifest) != producer_digest
            or str(binding.get("producer_contract_digest") or "")
            != producer_digest
            or producer_manifest.get("model_invoked") is not False
            or producer.get("semantic_status") != "ACTIVE"
            or not _HEX64.fullmatch(producer_launch_digest)
        ):
            return f"PRE sidecar producer authority mismatch: {identity}"
        output_spec = _manifest_output(producer_manifest, identity)
        if not isinstance(output_spec, Mapping) or output_spec.get("writer") != "DRIVER":
            return f"PRE sidecar producer output contract mismatch: {identity}"
        artifacts = producer.get("artifacts")
        produced = artifacts.get(identity) if isinstance(artifacts, Mapping) else None
        global_record = global_bindings.get(identity)
        if (
            not isinstance(produced, Mapping)
            or produced.get("owner_key") != producer_key
            or str(produced.get("run_id") or "").casefold() != run_id.casefold()
            or str(produced.get("contract_digest") or "") != producer_digest
            or str(produced.get("launch_digest") or "") != producer_launch_digest
            or produced.get("writer") != "DRIVER"
            or produced.get("status") != "ACTIVE"
            or str(produced.get("sha256") or "").lower() != digest
        ):
            return f"PRE sidecar producer output binding mismatch: {identity}"
        output_contract_fields = (
            "identity",
            "owner_key",
            "artifact_class",
            "writer",
            "write_mode",
            "schema_version",
            "minimum_gate",
            "consumers",
            "condition_id",
        )
        if any(
            produced.get(field) != output_spec.get(field)
            for field in output_contract_fields
        ):
            return f"PRE sidecar producer output/spec mismatch: {identity}"
        global_snapshots: list[dict[str, Any]] = []
        if isinstance(global_record, Mapping):
            global_snapshots.append(
                {key: value for key, value in global_record.items() if key != "history"}
            )
            history = global_record.get("history")
            if isinstance(history, list):
                global_snapshots.extend(
                    dict(row) for row in history if isinstance(row, Mapping)
                )
        if dict(produced) not in global_snapshots:
            return f"PRE sidecar global output binding mismatch: {identity}"
    if len(producer_keys) != 1:
        return "owner work unit consumed PRE sidecars from mixed producers"
    return ""


def _bound_depth_output(
    root: Path,
    *,
    output_name: str,
    output_sha256: str,
    run_binding: Mapping[str, str],
) -> tuple[dict[str, Any] | None, str]:
    """Return a stable selected-ledger binding for one current output.

    The artifact ledger is mutable as later units finish, so binding its whole
    file would stale P1-C whenever unrelated work is appended.  Instead the
    authority binds the exact selected artifact record.  That record contains
    the worker output identity, current run ID, writer, state, and output hash.
    """
    path = root / _ARTIFACT_LEDGER_FILE
    if not path.is_file():
        return None, "artifact ledger missing"
    try:
        payload = _load_json(path)
    except Exception as exc:
        return None, f"artifact ledger parse failed: {type(exc).__name__}"
    if not isinstance(payload, Mapping):
        return None, "artifact ledger root is not an object"
    bindings = payload.get("artifact_bindings")
    work_units = payload.get("work_units")
    if not isinstance(bindings, Mapping):
        return None, "artifact ledger has no artifact_bindings map"
    if not isinstance(work_units, Mapping):
        return None, "artifact ledger has no work_units map"
    identity = f"scratchpad:{output_name}"
    record = bindings.get(identity)
    if not isinstance(record, Mapping):
        return None, f"artifact ledger has no current binding for {identity}"
    selected = {
        "identity": str(record.get("identity") or identity),
        "run_id": str(record.get("run_id") or ""),
        "writer": str(record.get("writer") or ""),
        "status": str(record.get("status") or ""),
        "sha256": str(record.get("sha256") or "").lower(),
        "owner_key": str(record.get("owner_key") or ""),
        "contract_digest": str(record.get("contract_digest") or ""),
        "launch_digest": str(record.get("launch_digest") or ""),
    }
    if selected["identity"] != identity:
        return None, f"artifact ledger identity mismatch for {identity}"
    if selected["run_id"].casefold() != str(run_binding.get("run_id") or "").casefold():
        return None, f"artifact ledger run_id mismatch for {identity}"
    if selected["writer"].upper() != "MODEL":
        return None, f"artifact ledger writer mismatch for {identity}"
    if selected["status"].upper() != "ACTIVE":
        return None, f"artifact ledger status is not ACTIVE for {identity}"
    if selected["sha256"] != output_sha256.lower():
        return None, f"artifact ledger sha256 mismatch for {identity}"
    owner_key = selected["owner_key"]
    owner = work_units.get(owner_key)
    if not owner_key or not isinstance(owner, Mapping):
        return None, f"artifact ledger owner work unit missing for {identity}"
    parts = owner_key.split("/")
    if len(parts) != 6 or parts[4] != "depth" or not parts[5].startswith("worker."):
        return None, f"artifact ledger owner work unit is not a depth worker for {identity}"
    if str(owner.get("run_id") or "").casefold() != str(
        run_binding.get("run_id") or ""
    ).casefold():
        return None, f"artifact ledger owner work unit run_id mismatch for {identity}"
    manifest = owner.get("contract_manifest")
    owner_contract_digest = str(owner.get("contract_digest") or "")
    owner_launch_digest = str(owner.get("launch_digest") or "")
    if (
        not isinstance(manifest, Mapping)
        or manifest.get("key") != owner_key
        or manifest.get("model_invoked") is not True
        or _manifest_digest(manifest) != owner_contract_digest
        or selected["contract_digest"] != owner_contract_digest
        or selected["launch_digest"] != owner_launch_digest
    ):
        return None, f"artifact ledger owner work unit contract mismatch for {identity}"
    output_spec = _manifest_output(manifest, identity)
    if not isinstance(output_spec, Mapping) or output_spec.get("writer") != "MODEL":
        return None, f"artifact ledger owner output contract mismatch for {identity}"
    artifacts = owner.get("artifacts")
    output_record = artifacts.get(identity) if isinstance(artifacts, Mapping) else None
    if (
        not isinstance(output_record, Mapping)
        or output_record.get("owner_key") != owner_key
        or str(output_record.get("run_id") or "").casefold()
        != str(run_binding.get("run_id") or "").casefold()
        or output_record.get("writer") != "MODEL"
        or output_record.get("status") != "ACTIVE"
        or str(output_record.get("sha256") or "").lower()
        != output_sha256.lower()
        or str(output_record.get("contract_digest") or "")
        != owner_contract_digest
        or str(output_record.get("launch_digest") or "")
        != owner_launch_digest
    ):
        return None, f"artifact ledger exact owner output binding mismatch for {identity}"
    pre_issue = _validate_pre_sidecar_consumption(
        payload,
        owner,
        run_id=str(run_binding.get("run_id") or ""),
    )
    if pre_issue:
        return None, f"{identity}: {pre_issue}"
    encoded = _canonical_json(selected).encode("utf-8")
    return {
        "artifact": f"{_ARTIFACT_LEDGER_FILE}#{identity}",
        "role": "depth_output_run_binding",
        "sha256": _sha256_bytes(encoded),
        "byte_count": len(encoded),
    }, ""


def _depth_receipts(
    root: Path,
    bindings: list[dict[str, Any]],
    issues: list[str],
    run_binding: Mapping[str, str],
) -> list[dict[str, Any]]:
    contract_path = root / _DEPTH_CONTRACT_FILE
    if not contract_path.is_file():
        return []
    contract_binding = _binding(contract_path, "depth_receipt_denominator")
    bindings.append(contract_binding)
    try:
        contract = _load_json(contract_path)
    except Exception as exc:
        issues.append(f"depth worker contract parse failed: {type(exc).__name__}")
        return []
    if not isinstance(contract, Mapping) or str(contract.get("phase") or "").lower() != "depth":
        issues.append("depth worker contract is malformed or has wrong phase")
        return []
    outputs = _depth_contract_output_names(contract, issues)
    receipts: dict[str, dict[str, Any]] = {}
    for name in outputs:
        path = root / name
        if not path.is_file():
            continue
        binding = _binding(path, "depth_obligation_receipts")
        bindings.append(binding)
        ledger_binding, ledger_issue = _bound_depth_output(
            root,
            output_name=name,
            output_sha256=str(binding["sha256"]),
            run_binding=run_binding,
        )
        if ledger_binding is None:
            issues.append(f"unbound depth receipt artifact ignored: {name}: {ledger_issue}")
            continue
        bindings.append(ledger_binding)
        text = path.read_text(encoding="utf-8", errors="replace")
        if not _COMPLETE_MARKER_RE.search(text) or not _PHASE_MARKER_RE.search(text):
            issues.append(f"depth receipt artifact is not current-complete: {name}")
            continue
        finding_sections = _finding_sections(
            text, issues=issues, source_label=name
        )
        bound_finding_ids = set(finding_sections)
        for line_no, line in enumerate(text.splitlines(), start=1):
            match = _RECEIPT_RE.fullmatch(line)
            if not match:
                continue
            status = match.group("status").upper()
            key = match.group("key").strip()
            target = match.group("target").strip()
            if not _valid_legacy_receipt(status, key, target):
                issues.append(f"malformed obligation receipt ignored: {name}:{line_no}")
                continue
            terminal_authority = False
            finding_id = ""
            referent_identifiers: list[str] = []
            referent_identifiers_exact: list[str] = []
            referent_normalized = ""
            referent_alias_bindings: list[dict[str, str]] = []
            if status == "R":
                referent_match = re.search(
                    r"\b[A-Za-z][A-Za-z0-9_]*-\d+\b", target
                )
                referent = (
                    referent_match.group(0).strip().casefold()
                    if referent_match
                    else ""
                )
                if not referent or referent not in bound_finding_ids:
                    issues.append(
                        "reported obligation receipt finding referent is not bound "
                        f"in its current worker output: {name}:{line_no}"
                    )
                    continue
                referent_section = "\n".join(
                    line
                    for line in finding_sections[referent].splitlines()
                    if _RECEIPT_RE.fullmatch(line) is None
                )
                referent_identifiers = _identifier_tokens(referent_section)
                referent_identifiers_exact = _identifier_tokens_exact(
                    referent_section
                )
                referent_normalized = re.sub(
                    r"[^a-z0-9]+", "", referent_section.casefold()
                )[:16000]
                referent_alias_bindings = _finding_alias_evidence_bindings(
                    referent_section,
                    issues=issues,
                    source_label=f"{name}:{finding_id or referent.upper()}",
                )
                finding_id = referent.upper()
            else:
                issues.append(
                    "producer-authored obligation disposition retained for "
                    f"independent review: {name}:{line_no}: STATUS:{status}"
                )
            identity = {
                "display_id": match.group("display").upper(),
                "covered_alias_ids": (
                    [match.group("alias").upper()]
                    if match.group("alias")
                    else []
                ),
                "status": status,
                "key": key,
                "target": target,
                "source_artifact": name,
                "source_sha256": binding["sha256"],
                "source_line": line_no,
                "referent_identifiers": referent_identifiers,
                "referent_identifiers_exact": referent_identifiers_exact,
                "referent_normalized": referent_normalized,
                "referent_alias_bindings": referent_alias_bindings,
                "finding_id": finding_id,
                "pending_independent_verification": False,
                "terminal_authority": terminal_authority,
            }
            receipt_id = "SOR-" + _sha256_value(identity)[:24]
            receipts[receipt_id] = {"receipt_id": receipt_id, **identity, "receipt_kind": "BOUND_DEPTH_MARKDOWN"}
    return [receipts[key] for key in sorted(receipts)]


def _typed_application_receipts(
    root: Path,
    bindings: list[dict[str, Any]],
    issues: list[str],
    *,
    run_binding: Mapping[str, str],
    universe_digest: str,
) -> list[dict[str, Any]]:
    path = root / APPLICATION_RECEIPT_FILE
    if not path.is_file():
        return []
    binding = _binding(path, "typed_obligation_application_receipts")
    bindings.append(binding)
    try:
        payload = _load_json(path)
    except Exception as exc:
        issues.append(f"typed application receipt parse failed: {type(exc).__name__}")
        return []
    if not isinstance(payload, Mapping) or payload.get("schema_version") != APPLICATION_RECEIPT_SCHEMA:
        issues.append("typed application receipt schema mismatch")
        return []
    expected = {
        "run_id": run_binding["run_id"],
        "source_snapshot_digest": run_binding["source_snapshot_digest"],
        "authority_universe_digest": universe_digest,
    }
    for field, value in expected.items():
        if str(payload.get(field) or "").casefold() != str(value).casefold():
            issues.append(f"typed application receipt {field} mismatch")
            return []
    raw_receipts = payload.get("receipts")
    if not isinstance(raw_receipts, list):
        issues.append("typed application receipts is not a list")
        return []
    receipts: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(raw_receipts):
        if not isinstance(raw, Mapping):
            issues.append(f"typed application receipt row {index} malformed")
            continue
        display = str(raw.get("display_id") or "").upper()
        obligation_id = str(raw.get("obligation_id") or "")
        disposition = str(raw.get("disposition") or "").upper()
        reason = str(raw.get("reason") or "").strip()
        if disposition not in {"REPORTED", "DISMISSED_EVIDENCE", "CARRIED"} or not reason:
            issues.append(f"typed application receipt row {index} has invalid disposition/reason")
            continue
        evidence_bindings: list[dict[str, str]] = []
        covered_alias_ids = sorted(
            {
                str(value)
                for value in raw.get("covered_alias_ids") or []
                if isinstance(value, str) and value.startswith("SOT-")
            }
        )
        evidence_ok = disposition == "CARRIED"
        for evidence in raw.get("evidence_bindings") or []:
            if not isinstance(evidence, Mapping):
                continue
            name = _dynamic_input_name(evidence.get("artifact"))
            claimed = str(evidence.get("sha256") or "").upper()
            if not name or not _HEX64.fullmatch(claimed):
                continue
            evidence_path = root / name
            if not evidence_path.is_file() or _sha256_bytes(evidence_path.read_bytes()) != claimed:
                continue
            evidence_bindings.append({"artifact": name, "sha256": claimed})
            evidence_ok = True
        if not evidence_ok:
            issues.append(f"typed application receipt row {index} lacks current evidence")
            continue
        identity = {
            "display_id": display,
            "obligation_id": obligation_id,
            "disposition": disposition,
            "reason": reason,
            "covered_alias_ids": covered_alias_ids,
            "evidence_bindings": sorted(evidence_bindings, key=_canonical_json),
            "source_artifact": path.name,
            "source_sha256": binding["sha256"],
            # This scratchpad JSON currently has no independently owned DRIVER
            # or discriminator PhaseIO producer.  Hashes of arbitrary current
            # files prove freshness only; they cannot grant terminal authority.
            "terminal_authority": False,
        }
        issues.append(
            "unowned typed application receipt retained for independent review: "
            f"row {index} {disposition}"
        )
        receipt_id = "SOR-" + _sha256_value(identity)[:24]
        receipts[receipt_id] = {"receipt_id": receipt_id, **identity, "receipt_kind": "TYPED_APPLICATION"}
    return [receipts[key] for key in sorted(receipts)]


def _apply_receipts(
    obligations: list[dict[str, Any]], receipts: Sequence[Mapping[str, Any]], issues: list[str]
) -> None:
    by_display = {str(row["display_id"]): row for row in obligations}
    by_id = {str(row["obligation_id"]): row for row in obligations}
    for receipt in receipts:
        row = by_id.get(str(receipt.get("obligation_id") or "")) or by_display.get(
            str(receipt.get("display_id") or "").upper()
        )
        if row is None:
            issues.append(
                "obligation receipt references unknown current obligation: "
                f"{receipt.get('display_id') or receipt.get('obligation_id')}"
            )
            continue
        current_aliases = {
            str(alias.get("alias_id") or "")
            for alias in row.get("trigger_aliases") or []
            if isinstance(alias, Mapping)
        }
        claimed_aliases = {
            str(alias)
            for alias in receipt.get("covered_alias_ids", [])
            if str(alias)
        }
        unknown_aliases = sorted(claimed_aliases - current_aliases)
        if unknown_aliases:
            issues.append(
                "obligation receipt references unknown current alias: "
                + ",".join(unknown_aliases)
            )
        row["receipts"].append(dict(receipt))
    for row in obligations:
        row["receipts"].sort(key=lambda value: str(value["receipt_id"]))
        if not row["receipts"] or row["display_id"] == "SO-000":
            continue
        # A receipt cannot resolve contradictory applicability facts.  That is
        # an application-substrate conflict, not a finding disposition.
        if row.get("conflict_ids"):
            row["state"] = "CONFLICTED_REVIEW"
            continue
        required_alias_rows = {
            str(alias.get("alias_id") or ""): alias
            for alias in row.get("trigger_aliases") or []
            if isinstance(alias, Mapping) and str(alias.get("alias_id") or "")
        }
        if required_alias_rows:
            for receipt in row["receipts"]:
                if (
                    receipt.get("receipt_kind") != "BOUND_DEPTH_MARKDOWN"
                    or receipt.get("status") != "R"
                ):
                    continue
                # A depth producer can propose a report route, but it cannot
                # independently certify either application or validity.  The
                # exact alias/finding binding below authorizes only a pending
                # verification route and never terminal ACCOUNTED state.
                receipt["terminal_authority"] = False
                receipt["pending_independent_verification"] = False
                explicitly_claimed = {
                    str(alias_id)
                    for alias_id in receipt.get("covered_alias_ids") or []
                    if str(alias_id)
                }
                claimed = explicitly_claimed & set(required_alias_rows)
                if not explicitly_claimed and len(required_alias_rows) == 1:
                    claimed = {next(iter(required_alias_rows))}
                    receipt["covered_alias_ids"] = sorted(claimed)
                if len(claimed) != 1:
                    issues.append(
                        f"{row['display_id']} reported receipt lacks one exact current alias"
                    )
                    continue
                alias_id = next(iter(claimed))
                if not _reported_receipt_matches_alias(
                    receipt, required_alias_rows[alias_id]
                ):
                    issues.append(
                        f"{row['display_id']} reported finding lacks structural evidence for alias {alias_id}"
                    )
                    continue
                receipt["pending_independent_verification"] = True
        else:
            # Retain compatibility for a rule-owned obligation without a
            # structural alias denominator.  Its bound reported finding is
            # still only a proposal for independent verification.
            for receipt in row["receipts"]:
                if (
                    receipt.get("receipt_kind") == "BOUND_DEPTH_MARKDOWN"
                    and receipt.get("status") == "R"
                ):
                    receipt["terminal_authority"] = False
                    receipt["pending_independent_verification"] = True
        terminal_receipts = [
            receipt
            for receipt in row["receipts"]
            if receipt.get("terminal_authority") is True
        ]
        if not terminal_receipts:
            pending_receipts = [
                receipt
                for receipt in row["receipts"]
                if receipt.get("pending_independent_verification") is True
            ]
            if not pending_receipts:
                # Producer-authored dismissal/carry prose and unmatched
                # reports prove only that the methodology question was
                # touched. They remain repair work.
                continue
            required_aliases = set(required_alias_rows)
            covered_aliases = {
                str(alias)
                for receipt in pending_receipts
                for alias in receipt.get("covered_alias_ids", [])
            }
            if not required_aliases or required_aliases <= covered_aliases:
                row["state"] = "PENDING_INDEPENDENT_VERIFICATION"
            else:
                row["state"] = "PARTIAL_PENDING_INDEPENDENT_VERIFICATION"
                issues.append(
                    f"{row['display_id']} reported receipt does not cover every structural target alias"
                )
            continue
        required_aliases = set(required_alias_rows)
        if len(required_aliases) <= 1:
            row["state"] = "ACCOUNTED"
            continue
        covered_aliases = {
            str(alias)
            for receipt in terminal_receipts
            for alias in receipt.get("covered_alias_ids", [])
        }
        if required_aliases and required_aliases <= covered_aliases:
            row["state"] = "ACCOUNTED"
        else:
            row["state"] = "PARTIAL_RECEIPT_REVIEW"
            issues.append(
                f"{row['display_id']} receipt does not cover every structural target alias"
            )


def _payload_digest(payload: Mapping[str, Any]) -> str:
    return _sha256_value({key: value for key, value in payload.items() if key != "authority_digest"})


def _finalize_payload(payload: dict[str, Any]) -> dict[str, Any]:
    payload["authority_digest"] = _payload_digest(payload)
    return payload


def derive_security_obligation_authority(
    scratchpad: Path,
    *,
    mode: str = "",
    ecosystem: str = "",
    run_id: str = "",
    source_snapshot_digest: str = "",
    stage: str = POST_DEPTH_STAGE,
) -> tuple[dict[str, Any], dict[str, Any], str]:
    root = Path(scratchpad)
    stage_n = _normalized_stage(stage)
    run_binding, issues = _load_run_binding(
        root,
        run_id=run_id,
        source_snapshot_digest=source_snapshot_digest,
        ecosystem=ecosystem,
        mode=mode,
    )
    facts_by_id: dict[str, dict[str, Any]] = {}
    bindings: list[dict[str, Any]] = []
    wrapper_candidates: list[dict[str, Any]] = []
    substrate_metadata: dict[str, Any] = {}
    recon_provenance_summary: dict[str, Any] = {
        "legacy_model_proposal_count": 0,
        "model_proposal_count": 0,
        "reserved_operator_count": 0,
        "reserved_provider_count": 0,
        "invalid_claim_count": 0,
        "attestation_registry_issues": [],
        "localized_notes": [],
    }
    graph_healthy = _extract_graph_facts(
        root,
        facts_by_id,
        bindings,
        issues,
        wrapper_candidates,
        substrate_metadata,
    )
    semantic_edge_registry = substrate_metadata.pop("_semantic_edge_registry", {})
    recon_healthy = _extract_recon_facts(
        root,
        facts_by_id,
        bindings,
        issues,
        run_binding,
        semantic_edge_registry,
        recon_provenance_summary,
    )
    fallback_new_count = _extract_fallback_facts(
        root, facts_by_id, bindings, wrapper_candidates
    )
    fallback_ids_before_wrapper_reconcile = set(facts_by_id)
    _reconcile_wrapper_candidates(facts_by_id, wrapper_candidates)
    fallback_new_count += sum(
        1
        for fact_id, row in facts_by_id.items()
        if fact_id not in fallback_ids_before_wrapper_reconcile
        and any(
            isinstance(source, Mapping)
            and source.get("source_kind") == "STRUCTURED_FALLBACK_FACT"
            for source in row.get("sources", [])
        )
    )
    facts = [facts_by_id[key] for key in sorted(facts_by_id)]
    conflicts = _conflicts(facts)
    bindings.sort(key=lambda row: (str(row["artifact"]), str(row["role"])))
    feature_payload = _finalize_payload(
        {
            "schema_version": FEATURE_FACT_SCHEMA,
            "rule_catalog_version": RULE_CATALOG_VERSION,
            "rule_catalog_sha256": _RULE_CATALOG_DIGEST,
            "stage": stage_n,
            "run_binding": run_binding,
            "input_bindings": bindings,
            "graph_substrate_healthy": graph_healthy,
            "typed_recon_substrate_healthy": recon_healthy,
            "recon_provenance_summary": recon_provenance_summary,
            **substrate_metadata,
            "fallback_fact_count": fallback_new_count,
            "fact_count": len(facts),
            "conflict_count": len(conflicts),
            "facts": facts,
            "conflicts": conflicts,
            "issues": sorted(set(issues)),
        }
    )

    obligations = _derive_obligations(facts, conflicts, run_binding)
    substrate_unavailable = not graph_healthy and not recon_healthy
    if substrate_unavailable:
        obligations.insert(
            0,
            _coverage_debt(
                run_binding,
                "FEATURE_FACT_SUBSTRATE_UNAVAILABLE"
                if fallback_new_count == 0
                else "TYPED_SUBSTRATE_UNAVAILABLE_FALLBACK_ACTIVE",
            ),
        )
    universe_digest = _universe_digest(obligations)
    receipt_bindings: list[dict[str, Any]] = []
    receipts: list[dict[str, Any]] = []
    if stage_n == POST_DEPTH_STAGE:
        receipts.extend(
            _depth_receipts(root, receipt_bindings, issues, run_binding)
        )
        receipts.extend(
            _typed_application_receipts(
                root,
                receipt_bindings,
                issues,
                run_binding=run_binding,
                universe_digest=universe_digest,
            )
        )
    _apply_receipts(obligations, receipts, issues)
    all_bindings = bindings + receipt_bindings
    all_bindings.sort(key=lambda row: (str(row["artifact"]), str(row["role"])))
    degraded = bool(issues) or substrate_unavailable or any(
        row["trigger_source"] == "STRUCTURED_FALLBACK" for row in obligations
    )
    authority = _finalize_payload(
        {
            "schema_version": OBLIGATION_SCHEMA,
            "rule_catalog_version": RULE_CATALOG_VERSION,
            "rule_catalog_sha256": _RULE_CATALOG_DIGEST,
            "stage": stage_n,
            "run_binding": run_binding,
            "ecosystem": run_binding["ecosystem"],
            "mode": run_binding["mode"],
            "status": "DEGRADED_HUMAN_REVIEW" if degraded else "COMPLETE",
            "feature_fact_authority_digest": feature_payload["authority_digest"],
            "input_bindings": all_bindings,
            "authority_universe_digest": universe_digest,
            "obligation_count": len(obligations),
            "queueable_count": sum(
                row["state"]
                not in {"ACCOUNTED", "PENDING_INDEPENDENT_VERIFICATION"}
                for row in obligations
            ),
            "obligations": obligations,
            "issues": sorted(set(issues)),
        }
    )
    return feature_payload, authority, render_security_obligations(authority)


def _escape_cell(value: object) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip().replace("|", "/")


def render_security_obligations(authority: Mapping[str, Any]) -> str:
    run_binding = authority.get("run_binding") if isinstance(authority.get("run_binding"), Mapping) else {}
    lines = [
        "# Security Obligations",
        "",
        "Driver-derived analysis obligations. Typed JSON is authoritative; this "
        "Markdown is an exact projection and is not parsed for methodology decisions.",
        "",
        f"**Status**: {_escape_cell(authority.get('status'))}",
        f"**Stage**: {_escape_cell(authority.get('stage'))}",
        f"**Mode**: {_escape_cell(authority.get('mode'))}",
        f"**Ecosystem**: {_escape_cell(authority.get('ecosystem'))}",
        f"**Run binding**: `{_escape_cell(run_binding.get('binding_digest'))}`",
        f"**Authority digest**: `{_escape_cell(authority.get('authority_digest'))}`",
        f"**Count**: {int(authority.get('obligation_count') or 0)}",
        f"**Queueable**: {int(authority.get('queueable_count') or 0)}",
        "",
        "| Obligation ID | Canonical ID | Class | State | Audit Question | Trigger Source | Targets | Fact / Alias IDs |",
        "|---|---|---|---|---|---|---|---|",
    ]
    obligations = authority.get("obligations") if isinstance(authority.get("obligations"), list) else []
    if obligations:
        for row in obligations:
            if not isinstance(row, Mapping):
                continue
            identities = list(row.get("fact_ids") or []) + [
                str(alias.get("alias_id"))
                for alias in row.get("trigger_aliases") or []
                if isinstance(alias, Mapping)
            ]
            lines.append(
                "| {display} | `{canonical}` | {klass} | {state} | {question} | "
                "{source} | {targets} | {identities} |".format(
                    display=_escape_cell(row.get("display_id")),
                    canonical=_escape_cell(row.get("obligation_id")),
                    klass=_escape_cell(row.get("class")),
                    state=_escape_cell(row.get("state")),
                    question=_escape_cell(row.get("question")),
                    source=_escape_cell(row.get("trigger_source")),
                    targets=_escape_cell(", ".join(row.get("target_ids") or []) or "n/a"),
                    identities=_escape_cell(", ".join(identities) or "n/a"),
                )
            )
    else:
        lines.append("| n/a | n/a | none | COMPLETE_ZERO | No structured feature obligations triggered. | n/a | n/a | n/a |")
    alias_rows = [
        (row, alias)
        for row in obligations
        if isinstance(row, Mapping)
        for alias in row.get("trigger_aliases") or []
        if isinstance(alias, Mapping)
    ]
    if alias_rows:
        lines.extend(
            [
                "",
                "## Exact Trigger Aliases",
                "",
                "Each row is independently enumerable application work. Use the "
                "exact alias ID in a receipt; do not treat one row as coverage of "
                "another.",
                "",
                "| Obligation | Alias ID | Subject | Relation | Symbol | Object / Structural Target | Trigger Source |",
                "|---|---|---|---|---|---|---|",
            ]
        )
        for row, alias in alias_rows:
            lines.append(
                "| {display} | `{alias_id}` | `{subject}` | `{relation}` | "
                "`{symbol}` | `{object_id}` | {source} |".format(
                    display=_escape_cell(row.get("display_id")),
                    alias_id=_escape_cell(alias.get("alias_id")),
                    subject=_escape_cell(alias.get("subject_id")),
                    relation=_escape_cell(alias.get("relation_id") or "n/a"),
                    symbol=_escape_cell(alias.get("symbol") or "n/a"),
                    object_id=_escape_cell(
                        alias.get("object_id") or alias.get("subject_id") or "n/a"
                    ),
                    source=_escape_cell(alias.get("trigger_source")),
                )
            )
        lines.extend(
            [
                "",
                "### Exact finding evidence bindings",
                "",
                "Copy the complete marker for each reported alias into the "
                "referenced finding section. Alias IDs and prose tokens alone "
                "do not bind application evidence.",
                "",
            ]
        )
        for row, alias in alias_rows:
            marker = (
                "<!-- PLAMEN_SECURITY_OBLIGATION_EVIDENCE: "
                + _canonical_json(_alias_evidence_binding(alias))
                + " -->"
            )
            lines.append(
                f"- {_escape_cell(row.get('display_id'))} "
                f"`{_escape_cell(alias.get('alias_id'))}`: `{marker}`"
            )
    issues = authority.get("issues") if isinstance(authority.get("issues"), list) else []
    if issues:
        lines.extend(["", "## Coverage / authority debt", ""])
        lines.extend(f"- {_escape_cell(issue)}" for issue in issues)
    lines.extend(
        [
            "",
            "## Receipt Contract",
            "",
            "A current depth worker may emit:",
            "",
            "`[OBLIG:security_obligations.md:<SO-ID>] ALIAS:<SOT-ID> STATUS:R|D|C KEY:<summary> -> <finding_id|reason|phase>`",
            "",
            "Emit one line per exact alias when an obligation has more than one "
            "alias. The `ALIAS:` field may be omitted only for a single-alias "
            "obligation.",
            "",
            "The referenced finding section must also contain the ready-to-copy "
            "`PLAMEN_SECURITY_OBLIGATION_EVIDENCE` marker from the exact alias "
            "row above. The marker binds the alias, relation, subject, object, "
            "and symbol with original casing. Normalized prose or token overlap "
            "never substitutes for this structured binding.",
            "",
            "Only receipts from the current bound depth worker contract are reconciled. "
            "An exact structurally matched `STATUS:R` receipt becomes pending "
            "independent verification; it never becomes `ACCOUNTED` from depth "
            "output alone. Dismissal, carry, unmatched, malformed, or stale "
            "receipts remain repair work.",
        ]
    )
    return "\n".join(lines) + "\n"


def _atomic_write(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


def write_security_obligation_authority(
    scratchpad: Path,
    *,
    mode: str = "",
    ecosystem: str = "",
    run_id: str = "",
    source_snapshot_digest: str = "",
    stage: str = POST_DEPTH_STAGE,
) -> dict[str, Any]:
    root = Path(scratchpad)
    root.mkdir(parents=True, exist_ok=True)
    features, authority, projection = derive_security_obligation_authority(
        root,
        mode=mode,
        ecosystem=ecosystem,
        run_id=run_id,
        source_snapshot_digest=source_snapshot_digest,
        stage=stage,
    )
    _atomic_write(
        root / FEATURE_FACT_FILE,
        (json.dumps(features, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8"),
    )
    _atomic_write(
        root / AUTHORITY_FILE,
        (json.dumps(authority, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8"),
    )
    _atomic_write(root / PROJECTION_FILE, projection.encode("utf-8"))
    return authority


def _reader_debt(reason: str) -> list[dict[str, str]]:
    canonical = "SOBL-" + _sha256_value(
        {"rule_id": "security.feature_fact_authority_debt.v1", "reason": reason}
    )[:24]
    return [
        {
            "id": "SO-000",
            "class": "feature_fact_authority_debt",
            "question": FEATURE_FACT_COVERAGE_QUESTION,
            "signals": reason,
            "canonical_id": canonical,
            "state": "DEGRADED_REVIEW",
        }
    ]


def _read_current_security_obligation_authority(
    scratchpad: Path,
    *,
    stage: str = POST_DEPTH_STAGE,
) -> tuple[Mapping[str, Any] | None, str]:
    path = Path(scratchpad) / AUTHORITY_FILE
    if not path.is_file():
        return None, "FEATURE_FACT_AUTHORITY_MISSING"
    try:
        payload = _load_json(path)
    except Exception:
        return None, "FEATURE_FACT_AUTHORITY_MALFORMED"
    if (
        not isinstance(payload, Mapping)
        or payload.get("schema_version") != OBLIGATION_SCHEMA
        or payload.get("authority_digest") != _payload_digest(payload)
        or not isinstance(payload.get("obligations"), list)
    ):
        return None, "FEATURE_FACT_AUTHORITY_INVALID"
    try:
        expected_features, expected_authority, _ = (
            derive_security_obligation_authority(
                Path(scratchpad), stage=_normalized_stage(stage)
            )
        )
        actual_features = _load_json(Path(scratchpad) / FEATURE_FACT_FILE)
    except Exception:
        return None, "FEATURE_FACT_AUTHORITY_STALE"
    if actual_features != expected_features or payload != expected_authority:
        return None, "FEATURE_FACT_AUTHORITY_STALE"
    return payload, ""


def read_repairable_security_obligations(
    scratchpad: Path,
    *,
    stage: str = POST_DEPTH_STAGE,
) -> list[dict[str, str]]:
    """Return only aliases that still need producer-side repair/application.

    Exact structurally bound reported aliases are excluded because they have
    advanced to independent verification.  Dismissed, carried, unmatched,
    conflicting, malformed, and stale work remains fail-visible here.
    """

    payload, debt = _read_current_security_obligation_authority(
        Path(scratchpad), stage=stage
    )
    if payload is None:
        return _reader_debt(debt)
    rows: list[dict[str, str]] = []
    for raw in payload["obligations"]:
        if not isinstance(raw, Mapping) or raw.get("state") in {
            "ACCOUNTED",
            "PENDING_INDEPENDENT_VERIFICATION",
        }:
            continue
        fact_ids = ",".join(str(value) for value in raw.get("fact_ids") or [])
        aliases = [
            alias
            for alias in raw.get("trigger_aliases") or []
            if isinstance(alias, Mapping)
        ]
        covered = {
            str(alias_id)
            for receipt in raw.get("receipts") or []
            if isinstance(receipt, Mapping)
            and (
                receipt.get("pending_independent_verification") is True
                or receipt.get("terminal_authority") is True
            )
            for alias_id in receipt.get("covered_alias_ids") or []
        }
        unresolved_aliases = [
            alias
            for alias in aliases
            if str(alias.get("alias_id") or "") not in covered
        ]
        if not unresolved_aliases:
            unresolved_aliases = [None]
        for alias in unresolved_aliases:
            alias_id = (
                str(alias.get("alias_id") or "")
                if isinstance(alias, Mapping)
                else ""
            )
            relation_id = (
                str(alias.get("relation_id") or "")
                if isinstance(alias, Mapping)
                else ""
            )
            object_id = (
                str(alias.get("object_id") or alias.get("subject_id") or "")
                if isinstance(alias, Mapping)
                else ""
            )
            symbol = (
                str(alias.get("symbol") or "")
                if isinstance(alias, Mapping)
                else ""
            )
            signal_parts = [
                str(raw.get("trigger_source") or ""),
                fact_ids,
                relation_id,
                object_id,
                symbol,
            ]
            queue_row = {
                "id": str(raw.get("display_id") or "SO-000"),
                "class": str(raw.get("class") or "feature_fact_authority_debt"),
                "question": str(raw.get("question") or FEATURE_FACT_COVERAGE_QUESTION),
                "signals": ":".join(part for part in signal_parts if part),
                "canonical_id": str(raw.get("obligation_id") or ""),
                "state": str(raw.get("state") or "DEGRADED_REVIEW"),
            }
            # Preserve the stable non-alias debt-row contract. Exact relation
            # fields are present only for an actual structural alias.
            if isinstance(alias, Mapping):
                queue_row.update(
                    {
                        "alias_id": alias_id,
                        "relation_id": relation_id,
                        "object_id": object_id,
                        "symbol": symbol,
                    }
                )
            rows.append(queue_row)
    return rows


def read_queueable_security_obligations(
    scratchpad: Path,
    *,
    stage: str = POST_DEPTH_STAGE,
) -> list[dict[str, str]]:
    """Compatibility name for the attention/repair queue reader.

    Before depth reports became explicitly non-terminal, a valid report
    removed its exact alias from this queue.  Delegating to the repair reader
    preserves that behavior and, critically, preserves the historical SO-000
    debt-row shape for missing, malformed, invalid, or stale authority.
    """

    return read_repairable_security_obligations(scratchpad, stage=stage)


def _pending_reader_debt(scratchpad: Path, reason: str) -> list[dict[str, str]]:
    canonical = "SOBL-" + _sha256_value(
        {"rule_id": "security.feature_fact_authority_debt.v1", "reason": reason}
    )[:24]
    path = Path(scratchpad) / AUTHORITY_FILE
    source_sha256 = (
        _sha256_bytes(path.read_bytes()).lower() if path.is_file() else ""
    )
    binding = {
        "obligation_id": canonical,
        "display_id": "SO-000",
        "alias_id": "",
        "relation_id": "",
        "object_id": "",
        "symbol": "",
        "finding_id": "",
        "receipt_id": "",
        "question": f"{FEATURE_FACT_COVERAGE_QUESTION} [{reason}]",
        "source_artifact": AUTHORITY_FILE,
        "source_artifact_sha256": source_sha256,
    }
    return [
        {
            **binding,
            "alias_binding_sha256": hashlib.sha256(
                _canonical_json(
                    {**binding, "authority_debt": reason}
                ).encode("utf-8")
            ).hexdigest(),
        }
    ]


def read_pending_security_obligation_verification(
    scratchpad: Path,
    *,
    stage: str = POST_DEPTH_STAGE,
) -> list[dict[str, str]]:
    """Return exact depth-reported aliases awaiting an independent verifier.

    This reader never interprets producer prose as a terminal disposition. It
    revalidates the current authority, binds every row to its exact receipt and
    alias, and emits a fail-visible SO-000 row when that authority is not
    current.  Consumers must not treat an SO-000 row as finding evidence.
    """

    root = Path(scratchpad)
    payload, debt = _read_current_security_obligation_authority(root, stage=stage)
    if payload is None:
        return _pending_reader_debt(root, debt)
    source_sha256 = _sha256_bytes((root / AUTHORITY_FILE).read_bytes()).lower()
    rows: list[dict[str, str]] = []
    for raw in payload["obligations"]:
        if not isinstance(raw, Mapping) or raw.get("conflict_ids"):
            continue
        aliases = {
            str(alias.get("alias_id") or ""): alias
            for alias in raw.get("trigger_aliases") or []
            if isinstance(alias, Mapping) and str(alias.get("alias_id") or "")
        }
        for receipt in raw.get("receipts") or []:
            if (
                not isinstance(receipt, Mapping)
                or receipt.get("pending_independent_verification") is not True
                or receipt.get("terminal_authority") is not False
            ):
                continue
            claimed = [
                str(value)
                for value in receipt.get("covered_alias_ids") or []
                if str(value)
            ]
            if aliases and len(claimed) != 1:
                continue
            alias_id = claimed[0] if claimed else ""
            alias = aliases.get(alias_id, {})
            if aliases and not alias:
                continue
            binding = {
                "obligation_id": str(raw.get("obligation_id") or ""),
                "display_id": str(raw.get("display_id") or "SO-000"),
                "alias_id": alias_id,
                "relation_id": str(alias.get("relation_id") or ""),
                "object_id": str(
                    alias.get("object_id") or alias.get("subject_id") or ""
                ),
                "symbol": str(alias.get("symbol") or ""),
                "finding_id": str(receipt.get("finding_id") or ""),
                "receipt_id": str(receipt.get("receipt_id") or ""),
                "question": str(
                    raw.get("question") or FEATURE_FACT_COVERAGE_QUESTION
                ),
                "source_artifact": AUTHORITY_FILE,
                "source_artifact_sha256": source_sha256,
            }
            rows.append(
                {
                    **binding,
                    # Match the mandatory-reverification adapter's lowercase
                    # digest while retaining the authority's UTF-8 canonical
                    # JSON bytes (including non-ASCII source identities).
                    "alias_binding_sha256": hashlib.sha256(
                        _canonical_json(binding).encode("utf-8")
                    ).hexdigest(),
                }
            )
    rows.sort(
        key=lambda row: (
            row["display_id"],
            row["alias_id"],
            row["finding_id"],
            row["receipt_id"],
        )
    )
    return rows


def validate_security_obligation_authority(
    scratchpad: Path,
    *,
    mode: str = "",
    ecosystem: str = "",
    run_id: str = "",
    source_snapshot_digest: str = "",
    stage: str = POST_DEPTH_STAGE,
) -> list[str]:
    root = Path(scratchpad)
    issues: list[str] = []
    try:
        expected_features, expected_authority, expected_projection = (
            derive_security_obligation_authority(
                root,
                mode=mode,
                ecosystem=ecosystem,
                run_id=run_id,
                source_snapshot_digest=source_snapshot_digest,
                stage=stage,
            )
        )
    except Exception as exc:
        return [f"security obligation authority re-derivation failed: {type(exc).__name__}"]
    for name, expected in (
        (FEATURE_FACT_FILE, expected_features),
        (AUTHORITY_FILE, expected_authority),
    ):
        path = root / name
        try:
            actual = _load_json(path)
        except Exception as exc:
            issues.append(f"{name} missing or malformed: {type(exc).__name__}")
            continue
        if actual != expected:
            issues.append(f"{name} authority differs from current inputs")
    projection_path = root / PROJECTION_FILE
    try:
        actual_projection = projection_path.read_text(encoding="utf-8", errors="strict")
    except Exception as exc:
        issues.append(f"{PROJECTION_FILE} missing or malformed: {type(exc).__name__}")
    else:
        if actual_projection != expected_projection:
            issues.append(f"{PROJECTION_FILE} projection differs from typed authority")
    return issues


__all__ = [
    "APPLICATION_RECEIPT_FILE",
    "APPLICATION_RECEIPT_SCHEMA",
    "AUTHORITY_FILE",
    "FEATURE_FACT_COVERAGE_QUESTION",
    "FEATURE_FACT_FILE",
    "FEATURE_FACT_SCHEMA",
    "LEGACY_RECON_FEATURE_SCHEMA",
    "OBLIGATION_SCHEMA",
    "POST_DEPTH_STAGE",
    "PRE_DEPTH_STAGE",
    "PROJECTION_FILE",
    "RECON_FEATURE_FILE",
    "RECON_FEATURE_SCHEMA",
    "RECON_FEATURE_SCHEMA_V3",
    "RULE_CATALOG_VERSION",
    "derive_security_obligation_authority",
    "read_pending_security_obligation_verification",
    "read_queueable_security_obligations",
    "read_repairable_security_obligations",
    "security_obligation_input_artifacts",
    "render_security_obligations",
    "validate_security_obligation_authority",
    "write_security_obligation_authority",
]
