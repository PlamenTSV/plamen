"""Authenticated resolver for the immutable pre-verification projection.

Post-cutover consumers must not rediscover their inventory denominator from
mutable root Markdown.  This module resolves the two stable successor
projections through their PhaseIO owner, the singular content-addressed
generation, and the exact frozen inventory/records/receipt producer.

It deliberately does not interpret findings or dispositions.  Consumers get
authenticated bytes and paths; domain-specific validators retain authority
over their own semantics.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from collections import Counter
from typing import Any, Mapping, Sequence

from artifact_ledger import (
    active_committed_work_unit_authority_issues,
    ArtifactLedgerError,
    read_artifact_ledger,
    semantic_import_authority_from_snapshot,
    semantic_input_producer_authority_issues,
)
from bounded_artifact_io import read_bounded_regular_bytes
from phase_io_contracts import LaunchSpec, resolve_phase_io_contract
from preverify_inventory_successor import (
    DELIVERY_RECEIPT_NAME,
    FINAL_RECEIPT_NAME,
    GENERATION_DIRECTORY,
    PreverifyInventorySuccessorError,
    validate_preverify_successor_payloads,
    validate_successor_generation_payload,
)


MAX_BYTES = 64 * 1024 * 1024
_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_FROZEN_ROOT = re.compile(
    r"^_preverify_frozen/generation_([0-9a-f]{64})$",
    re.ASCII,
)
_FROZEN_REQUIRED_LEAVES = (
    "findings_inventory.md",
    "finding_records.json",
    "receipt.json",
)
_FROZEN_OPTIONAL_LEAF = "inventory_evidence_validation.md"
_FINDING_HEADING = re.compile(
    r"(?im)^#{2,4}\s+Finding\s+\[([A-Za-z0-9_.-]+)\]\s*:"
)
_FROZEN_RECEIPT_FIELDS = frozenset({
    "schema_version",
    "pipeline",
    "mode",
    "ecosystem",
    "backend",
    "phase_name",
    "run_id",
    "inventory_source",
    "evidence_source",
    "inventory",
    "records",
    "evidence",
    "evidence_status",
    "evidence_reason_code",
    "evidence_semantic_use",
    "source_authorities",
    "source_preimage_bindings",
    "chain_candidate_delta",
    "candidate_delivery_fixed_point",
    "derivation_algorithm",
    "derivation_conformance_sha256",
    "generation_digest",
    "logical_to_physical",
    "advisory_evidence_path",
    "required_paths",
    "debt",
    "proof_authority",
    "receipt_digest",
})
_SOURCE_AUTHORITY_FIELDS = frozenset({
    "schema_version",
    "authority_kind",
    "identity",
    "run_id",
    "source_sha256",
    "source_size",
    "producer_work_unit_key",
    "producer_contract_digest",
    "mutation_event_ids",
    "mutation_authority_digests",
})
_CANONICAL_RESERVED_IDENTITIES = frozenset({
    "scratchpad:findings_inventory.md",
    "scratchpad:finding_records.json",
})


class PreverifyProjectionAuthorityError(ValueError):
    """The current frozen projection cannot be authenticated."""


def successor_projection_present(scratchpad: Path) -> bool:
    """Return whether either stable successor artifact is present."""

    root = Path(scratchpad)
    return (
        (root / FINAL_RECEIPT_NAME).exists()
        or (root / DELIVERY_RECEIPT_NAME).exists()
    )


def _read(root: Path, relative: str, *, label: str) -> bytes:
    try:
        return read_bounded_regular_bytes(
            root.joinpath(*PurePosixPath(relative).parts),
            MAX_BYTES,
        )
    except (OSError, ValueError) as exc:
        raise PreverifyProjectionAuthorityError(
            f"{label} is unavailable: {relative}"
        ) from exc


def _relative(value: object, *, label: str) -> str:
    text = str(value or "")
    path = PurePosixPath(text)
    if (
        not text
        or "\\" in text
        or path.is_absolute()
        or text != path.as_posix()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise PreverifyProjectionAuthorityError(
            f"{label} is not a canonical relative POSIX path"
        )
    return text


def _json(raw: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PreverifyProjectionAuthorityError(
            f"{label} is not strict JSON"
        ) from exc
    if not isinstance(value, dict):
        raise PreverifyProjectionAuthorityError(f"{label} is not an object")
    return value


def _strict_object(
    pairs: list[tuple[str, Any]],
    *,
    label: str,
) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise PreverifyProjectionAuthorityError(
                f"{label} contains duplicate JSON key {key!r}"
            )
        value[key] = item
    return value


def _strict_json(raw: bytes, *, label: str) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=lambda pairs: _strict_object(
                pairs,
                label=label,
            ),
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"invalid JSON constant {value}")
            ),
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        if isinstance(exc, PreverifyProjectionAuthorityError):
            raise
        raise PreverifyProjectionAuthorityError(
            f"{label} is not strict finite JSON"
        ) from exc
    if not isinstance(value, dict):
        raise PreverifyProjectionAuthorityError(
            f"{label} is not an object"
        )
    return value


def _replay_chain_candidate_delta(
    *,
    payload: Mapping[str, Any],
    chain_delta: Mapping[str, Any],
    candidate_raw: bytes,
    receipt_raw: bytes,
    source_preimages: Mapping[str, bytes],
    source_authorities: Mapping[str, Any],
    ledger: Mapping[str, Any],
    run_id: str,
) -> dict[str, Any]:
    """Rederive the v2 delta from its immutable source bundle."""

    try:
        from chain_candidate_inventory_union import (
            DELTA_DERIVATION_ALGORITHM,
            DELTA_DERIVATION_CONFORMANCE_SHA256,
            DELTA_RECEIPT_SCHEMA,
            DELTA_ROOT,
            DELTA_SCHEMA,
            DELTA_SOURCE_PREIMAGE_LEAVES,
            derive_preverify_chain_candidate_payload,
            validate_preverify_chain_candidate_derivation_conformance,
        )
        from preverify_chain_pair_projection import (
            PAIR_DERIVATION_ALGORITHM,
            PAIR_DERIVATION_CONFORMANCE_SHA256,
            RECEIPT_SCHEMA as PAIR_RECEIPT_SCHEMA,
            derive_preverify_chain_pair_relation,
            validate_preverify_chain_pair_derivation_conformance,
        )
    except ImportError as exc:
        raise PreverifyProjectionAuthorityError(
            "chain candidate delta replay implementation is unavailable"
        ) from exc
    candidate = _strict_json(
        candidate_raw,
        label="chain candidate delta payload",
    )
    receipt = _strict_json(
        receipt_raw,
        label="chain candidate delta receipt",
    )
    unsigned_candidate = {
        key: value
        for key, value in candidate.items()
        if key != "candidate_digest"
    }
    unsigned_receipt = {
        key: value
        for key, value in receipt.items()
        if key != "receipt_digest"
    }
    candidate_path = _relative(
        chain_delta.get("candidate_path"),
        label="chain candidate delta path",
    )
    receipt_path = _relative(
        chain_delta.get("receipt_path"),
        label="chain candidate receipt path",
    )
    generation = str(chain_delta.get("generation_digest") or "")
    dimensions = {
        key: payload.get(key)
        for key in (
            "pipeline",
            "mode",
            "ecosystem",
            "backend",
            "phase_name",
            "run_id",
        )
    }
    candidates = candidate.get("candidates")
    candidate_ids = candidate.get("candidate_ids")
    preimage_bindings = receipt.get("source_preimage_bindings")
    required_roles = {
        "hypotheses",
        "finding_mapping",
        "pair_receipt",
        "enabler_results",
    }
    allowed_roles = {*required_roles, "auto_map_receipt"}
    if (
        not isinstance(preimage_bindings, Mapping)
        or not required_roles.issubset(set(preimage_bindings))
        or not set(preimage_bindings).issubset(allowed_roles)
    ):
        raise PreverifyProjectionAuthorityError(
            "chain candidate delta source-preimage denominator differs"
        )
    role_to_frozen = {
        "hypotheses": "chain_candidate_source_hypotheses",
        "finding_mapping": (
            "chain_candidate_source_finding_mapping"
        ),
        "pair_receipt": "chain_candidate_source_pair_receipt",
        "enabler_results": (
            "chain_candidate_source_enabler_results"
        ),
        "auto_map_receipt": (
            "chain_candidate_source_auto_map_receipt"
        ),
    }
    delta_source_bytes: dict[str, bytes] = {}
    input_identities: dict[str, str] = {}
    expected_delta_source_paths: set[str] = set()
    for role in sorted(preimage_bindings):
        row = preimage_bindings.get(role)
        frozen_role = role_to_frozen[role]
        raw = source_preimages.get(frozen_role)
        if (
            not isinstance(row, Mapping)
            or set(row) != {
                "leaf",
                "input_identity",
                "sha256",
                "size",
            }
            or row.get("leaf")
            != DELTA_SOURCE_PREIMAGE_LEAVES[role]
            or not isinstance(raw, bytes)
            or isinstance(row.get("size"), bool)
            or row.get("sha256")
            != hashlib.sha256(raw).hexdigest()
            or row.get("size") != len(raw)
        ):
            raise PreverifyProjectionAuthorityError(
                "chain candidate delta immutable source preimage differs"
            )
        input_identity = str(row.get("input_identity") or "")
        if not input_identity.startswith("scratchpad:"):
            raise PreverifyProjectionAuthorityError(
                "chain candidate delta input identity is invalid"
            )
        _relative(
            input_identity.removeprefix("scratchpad:"),
            label=f"chain candidate {role} input identity",
        )
        input_identities[role] = input_identity
        delta_source_bytes[role] = raw
        expected_delta_source_paths.add(
            f"{DELTA_ROOT}/generation_{generation}/_sources/"
            f"{DELTA_SOURCE_PREIMAGE_LEAVES[role]}"
        )
    expected_required_paths = sorted({
        candidate_path,
        receipt_path,
        *expected_delta_source_paths,
    })
    if (
        candidate.get("schema_version") != DELTA_SCHEMA
        or candidate.get("candidate_digest")
        != _canonical_payload_digest(unsigned_candidate)
        or receipt.get("schema_version") != DELTA_RECEIPT_SCHEMA
        or receipt.get("receipt_digest")
        != _canonical_payload_digest(unsigned_receipt)
        or _HEX64.fullmatch(generation) is None
        or receipt.get("generation_digest") != generation
        or receipt.get("candidate_digest")
        != candidate.get("candidate_digest")
        or receipt.get("candidate_path") != candidate_path
        or receipt.get("required_paths")
        != expected_required_paths
        or receipt.get("derivation_algorithm")
        != DELTA_DERIVATION_ALGORITHM
        or receipt.get("derivation_conformance_sha256")
        != DELTA_DERIVATION_CONFORMANCE_SHA256
        or candidate.get("derivation_algorithm")
        != DELTA_DERIVATION_ALGORITHM
        or candidate.get("derivation_conformance_sha256")
        != DELTA_DERIVATION_CONFORMANCE_SHA256
        or any(
            candidate.get(key) != value
            or receipt.get(key) != value
            for key, value in dimensions.items()
        )
        or candidate.get("base_inventory_mutated") is not False
        or receipt.get("base_inventory_mutated") is not False
        or candidate.get("candidate_disposition")
        != "VERIFY_INDEPENDENTLY"
        or receipt.get("candidate_disposition")
        != "VERIFY_INDEPENDENTLY"
        or candidate.get("proof_authority") != "NONE"
        or receipt.get("proof_authority") != "NONE"
        or not isinstance(candidates, list)
        or not isinstance(candidate_ids, list)
        or any(not isinstance(row, Mapping) for row in candidates)
        or any(
            not isinstance(identity, str) or not identity
            for identity in candidate_ids
        )
        or len(candidate_ids) != len(set(candidate_ids))
        or candidate_ids
        != [
            str(row.get("candidate_identity") or "")
            for row in candidates
        ]
        or candidate.get("candidate_count") != len(candidates)
        or receipt.get("candidate_ids") != candidate_ids
        or receipt.get("debt") != candidate.get("debt")
        or chain_delta.get("candidate_digest")
        != candidate.get("candidate_digest")
        or chain_delta.get("candidate_ids") != candidate_ids
        or chain_delta.get("debt") != candidate.get("debt")
        or any(
            row.get("required_disposition") != "VERIFY_INDEPENDENTLY"
            or row.get("relation_kind") != "ENABLER_CONSTITUENT"
            or row.get("proof_authority") != "NONE"
            or not str(row.get("inventory_block") or "").strip()
            for row in candidates
        )
    ):
        raise PreverifyProjectionAuthorityError(
            "chain candidate delta source bytes do not replay their exact "
            "versioned derivation envelope"
        )
    try:
        validate_preverify_chain_candidate_derivation_conformance()
        validate_preverify_chain_pair_derivation_conformance()
    except (TypeError, ValueError) as exc:
        raise PreverifyProjectionAuthorityError(
            f"chain candidate derivation conformance failed: {exc}"
        ) from exc
    generation_core = {
        "schema_version": DELTA_RECEIPT_SCHEMA,
        **dimensions,
        "candidate_digest": candidate.get("candidate_digest"),
        "candidate_ids": candidate_ids,
        "source_bindings": candidate.get("source_bindings"),
        "source_authorities": candidate.get("source_authorities"),
        "model_lineage": candidate.get("model_lineage"),
        "source_preimage_bindings": preimage_bindings,
        "derivation_algorithm": DELTA_DERIVATION_ALGORITHM,
        "derivation_conformance_sha256": (
            DELTA_DERIVATION_CONFORMANCE_SHA256
        ),
    }
    if _canonical_payload_digest(generation_core) != generation:
        raise PreverifyProjectionAuthorityError(
            "chain candidate delta generation does not replay"
        )
    try:
        pair_receipt = _strict_json(
            delta_source_bytes["pair_receipt"],
            label="chain candidate pair receipt preimage",
        )
    except PreverifyProjectionAuthorityError:
        raise
    expected_pair_relation = derive_preverify_chain_pair_relation(
        delta_source_bytes["hypotheses"],
        delta_source_bytes["finding_mapping"],
    )
    if (
        pair_receipt.get("schema_version") != PAIR_RECEIPT_SCHEMA
        or pair_receipt.get("derivation_algorithm")
        != PAIR_DERIVATION_ALGORITHM
        or pair_receipt.get("derivation_conformance_sha256")
        != PAIR_DERIVATION_CONFORMANCE_SHA256
        or pair_receipt.get("relation_validation")
        != expected_pair_relation
        or pair_receipt.get("sources")
        != {
            "hypotheses.md": {
                "sha256": hashlib.sha256(
                    delta_source_bytes["hypotheses"]
                ).hexdigest(),
                "size": len(delta_source_bytes["hypotheses"]),
            },
            "finding_mapping.md": {
                "sha256": hashlib.sha256(
                    delta_source_bytes["finding_mapping"]
                ).hexdigest(),
                "size": len(
                    delta_source_bytes["finding_mapping"]
                ),
            },
        }
    ):
        raise PreverifyProjectionAuthorityError(
            "chain candidate pair receipt is not the source derivation"
        )
    candidate_authorities = candidate.get("source_authorities")
    model_lineage = candidate.get("model_lineage")
    if (
        not isinstance(candidate_authorities, Mapping)
        or not isinstance(model_lineage, Mapping)
    ):
        raise PreverifyProjectionAuthorityError(
            "chain candidate semantic authority envelope is malformed"
        )
    expected_candidate, expected_debt = (
        derive_preverify_chain_candidate_payload(
            dimensions=dimensions,
            pair_sources={
                "hypotheses.md": delta_source_bytes["hypotheses"],
                "finding_mapping.md": (
                    delta_source_bytes["finding_mapping"]
                ),
            },
            enabler_raw=delta_source_bytes["enabler_results"],
            source_authorities=candidate_authorities,
            lineage=model_lineage,
        )
    )
    if (
        candidate != expected_candidate
        or candidate.get("debt") != expected_debt
    ):
        raise PreverifyProjectionAuthorityError(
            "chain candidate payload is not the exact immutable source "
            "rederivation"
        )
    delta_output_row = source_authorities.get(
        "chain_candidate_delta"
    )
    delta_work_unit_key = str(
        delta_output_row.get("producer_work_unit_key") or ""
    ) if isinstance(delta_output_row, Mapping) else ""
    commit_issues = active_committed_work_unit_authority_issues(
        ledger,
        work_unit_key=delta_work_unit_key,
        run_id=run_id,
        expected_artifact_identities=tuple(
            "scratchpad:" + relative
            for relative in expected_required_paths
        ),
    )
    unit = (
        ledger.get("work_units", {}).get(delta_work_unit_key)
        if isinstance(ledger.get("work_units"), Mapping)
        else None
    )
    input_bindings = (
        unit.get("input_bindings")
        if isinstance(unit, Mapping)
        else None
    )
    if (
        commit_issues
        or not isinstance(input_bindings, Mapping)
        or set(input_bindings) != set(input_identities.values())
    ):
        raise PreverifyProjectionAuthorityError(
            "chain candidate provider commit/input denominator differs: "
            + "; ".join(commit_issues)
        )
    for role, identity in input_identities.items():
        binding = input_bindings.get(identity)
        if (
            not isinstance(binding, Mapping)
            or binding.get("sha256")
            != preimage_bindings[role].get("sha256")
            or binding.get("size")
            != preimage_bindings[role].get("size")
        ):
            raise PreverifyProjectionAuthorityError(
                "chain candidate source copy differs from its armed input"
            )
    return candidate


def _canonical_payload_digest(value: Mapping[str, Any]) -> str:
    try:
        raw = (
            json.dumps(
                value,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise PreverifyProjectionAuthorityError(
            "frozen projection receipt is not canonical JSON data"
        ) from exc
    return hashlib.sha256(raw).hexdigest()


def _binding_matches(
    binding: Mapping[str, Any],
    raw: bytes,
    *,
    label: str,
) -> None:
    if (
        binding.get("status") != "ACTIVE"
        or binding.get("sha256") != hashlib.sha256(raw).hexdigest()
        or binding.get("size") != len(raw)
    ):
        raise PreverifyProjectionAuthorityError(
            f"{label} differs from its ACTIVE PhaseIO binding"
        )


def _work_unit_parts(
    work_unit_key: str,
) -> tuple[str, str, str, str, str, str]:
    parts = tuple(str(work_unit_key or "").split("/"))
    if len(parts) != 6 or any(not part for part in parts):
        raise PreverifyProjectionAuthorityError(
            "preverify work-unit identity is malformed"
        )
    return parts  # type: ignore[return-value]


def _resolver_input_path(identity: str) -> str:
    value = str(identity or "")
    if value.startswith("scratchpad:"):
        return value.removeprefix("scratchpad:")
    if value.startswith("project:"):
        return "project::" + value.removeprefix("project:")
    raise PreverifyProjectionAuthorityError(
        f"{value}: preverify contract input root is unsupported"
    )


def _expected_driver_launch(contract: Any) -> LaunchSpec:
    return LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="driver",
        timeout_s=120,
        exec_mode="python",
        tool_policy=("filesystem",),
    )


def _require_exact_registered_contract(
    *,
    unit: Mapping[str, Any],
    expected_contract: Any,
    expected_launch: LaunchSpec,
    label: str,
) -> None:
    if (
        unit.get("contract_manifest") != expected_contract.to_dict()
        or unit.get("contract_digest") != expected_contract.digest
        or unit.get("launch_digest") != expected_launch.digest
        or unit.get("model_invoked") is not expected_contract.model_invoked
    ):
        raise PreverifyProjectionAuthorityError(
            f"{label} differs from its exact registered PhaseIO contract"
        )


def _input_binding_set_digest(
    bindings: Mapping[str, Any],
) -> str:
    semantic = [
        {
            "identity": identity,
            "input_class": row.get("input_class", ""),
            "status": row.get("status", ""),
            "size": row.get("size", 0),
            "sha256": row.get("sha256", ""),
            "producer_work_unit_key": row.get(
                "producer_work_unit_key",
                "",
            ),
            "producer_contract_digest": row.get(
                "producer_contract_digest",
                "",
            ),
        }
        for identity, row in sorted(bindings.items())
        if isinstance(row, Mapping)
    ]
    return hashlib.sha256(
        json.dumps(
            semantic,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _validate_routing_projection_capability(
    *,
    ledger: Mapping[str, Any],
    routing_key: str,
    run_id: str,
    stable_rows: Mapping[str, Mapping[str, Any]],
) -> None:
    """Require an exact current arm/commit before runtime projection use."""

    unit = (
        ledger.get("work_units", {}).get(routing_key)
        if isinstance(ledger.get("work_units"), Mapping)
        else None
    )
    if not isinstance(unit, Mapping):
        raise PreverifyProjectionAuthorityError(
            "current routing consumer capability is absent"
        )
    parts = _work_unit_parts(routing_key)
    manifest = unit.get("contract_manifest")
    inputs = unit.get("input_bindings")
    outputs = (
        manifest.get("outputs")
        if isinstance(manifest, Mapping)
        else None
    )
    immutable = (
        manifest.get("immutable_inputs")
        if isinstance(manifest, Mapping)
        else None
    )
    bounded = (
        manifest.get("bounded_lookup_inputs")
        if isinstance(manifest, Mapping)
        else None
    )
    if (
        parts[4] not in {"verify_queue", "sc_verify_queue"}
        or parts[5] != "routing"
        or unit.get("run_id") != run_id
        or not isinstance(manifest, Mapping)
        or manifest.get("key") != routing_key
        or not isinstance(inputs, Mapping)
        or not isinstance(outputs, list)
        or not isinstance(immutable, list)
        or not isinstance(bounded, list)
        or set(inputs)
        != set(str(value) for value in (*immutable, *bounded))
        or unit.get("input_set_digest")
        != _input_binding_set_digest(inputs)
    ):
        raise PreverifyProjectionAuthorityError(
            "current routing consumer capability is malformed or non-current"
        )
    output_paths = tuple(
        str(row.get("identity") or "").removeprefix("scratchpad:")
        for row in outputs
        if isinstance(row, Mapping)
    )
    if (
        len(output_paths) != len(outputs)
        or any(not path for path in output_paths)
    ):
        raise PreverifyProjectionAuthorityError(
            "current routing consumer capability output denominator is "
            "malformed"
        )
    try:
        contract = resolve_phase_io_contract(
            pipeline=parts[0],
            mode=parts[1],
            ecosystem=parts[2],
            backend=parts[3],
            phase=parts[4],
            work_unit_id=parts[5],
            exact_inputs=tuple(
                sorted(_resolver_input_path(identity) for identity in inputs)
            ),
            exact_outputs=tuple(sorted(output_paths)),
        )
    except (TypeError, ValueError) as exc:
        raise PreverifyProjectionAuthorityError(
            "current routing consumer capability contract cannot be "
            "reconstructed"
        ) from exc
    _require_exact_registered_contract(
        unit=unit,
        expected_contract=contract,
        expected_launch=LaunchSpec(
            work_unit_key=contract.key,
            pipeline=contract.pipeline,
            mode=contract.mode,
            ecosystem=contract.ecosystem,
            backend=contract.backend,
            model="driver",
            timeout_s=120,
            exec_mode="python",
        ),
        label="current routing consumer capability",
    )
    for identity, stable in stable_rows.items():
        binding = inputs.get(identity)
        if (
            not isinstance(binding, Mapping)
            or binding.get("status") != "ACTIVE"
            or binding.get("sha256") != stable.get("sha256")
            or binding.get("size") != stable.get("size")
            or binding.get("producer_work_unit_key")
            != stable.get("owner_key")
            or binding.get("producer_contract_digest")
            != stable.get("contract_digest")
        ):
            raise PreverifyProjectionAuthorityError(
                "current routing capability does not bind the exact stable "
                "preverify successor"
            )
    state = (
        unit.get("execution_state"),
        unit.get("semantic_status"),
    )
    if state == ("INPUTS_BOUND_PREEXECUTION", "INPUTS_BOUND"):
        if unit.get("artifacts") not in ({}, None) or unit.get(
            "commit_authority"
        ) is not None:
            raise PreverifyProjectionAuthorityError(
                "armed routing consumer capability carries premature output "
                "authority"
            )
        return
    if state == ("OUTPUT_COMMITTED", "ACTIVE"):
        issues = active_committed_work_unit_authority_issues(
            ledger,
            work_unit_key=routing_key,
            run_id=run_id,
            expected_artifact_identities=tuple(
                row["identity"]
                for row in outputs
                if isinstance(row, Mapping)
            ),
        )
        if not issues:
            return
        raise PreverifyProjectionAuthorityError(
            "committed routing consumer capability is invalid: "
            + "; ".join(issues)
        )
    raise PreverifyProjectionAuthorityError(
        "current routing consumer capability is neither exactly armed nor "
        "committed"
    )


def resolve_exact_frozen_capture_authority(
    *,
    input_bindings: Mapping[str, Any],
    ledger: Mapping[str, Any],
    run_id: str,
    identities: Sequence[str] | None = None,
    inventory_source: str = "",
    records_source: str = "",
    evidence_source: str = "",
) -> dict[str, Any]:
    """Authenticate one physical frozen projection and its exact producer.

    This is the shared structural predicate for the capture-time driver gate
    and the post-commit projection resolver.  It intentionally operates on
    the complete denominator as a sequence, never a basename-keyed mapping:
    duplicate or mixed generations therefore cannot disappear by overwrite.
    """

    run = str(run_id or "").strip()
    if not run:
        raise PreverifyProjectionAuthorityError(
            "preverify frozen capture run_id is absent"
        )
    selected_identities = tuple(
        str(value)
        for value in (
            identities if identities is not None else input_bindings
        )
    )
    if any(
        identity in _CANONICAL_RESERVED_IDENTITIES
        for identity in selected_identities
    ):
        raise PreverifyProjectionAuthorityError(
            "canonical logical inventory/records cannot accompany or "
            "substitute for the physical frozen projection"
        )
    work_units = ledger.get("work_units")
    artifact_bindings = ledger.get("artifact_bindings")
    if not isinstance(work_units, Mapping) or not isinstance(
        artifact_bindings, Mapping
    ):
        raise PreverifyProjectionAuthorityError(
            "preverify frozen producer ledger is malformed"
        )

    rows: list[tuple[str, str, str, Mapping[str, Any]]] = []
    for identity in selected_identities:
        if not identity.startswith("scratchpad:"):
            continue
        relative = identity.removeprefix("scratchpad:")
        path = PurePosixPath(relative)
        if (
            len(path.parts) == 3
            and _FROZEN_ROOT.fullmatch(path.parent.as_posix())
            and path.name in _FROZEN_REQUIRED_LEAVES
        ):
            binding = input_bindings.get(identity)
            if not isinstance(binding, Mapping):
                raise PreverifyProjectionAuthorityError(
                    f"{identity}: frozen capture input binding is absent"
                )
            rows.append((path.name, relative, identity, binding))

    expected_counts = Counter({
        "findings_inventory.md": 1,
        "finding_records.json": 1,
        "receipt.json": 1,
    })
    if len(rows) != 3 or Counter(row[0] for row in rows) != expected_counts:
        raise PreverifyProjectionAuthorityError(
            "preverify frozen capture requires exactly one inventory, "
            "records, and receipt triple"
        )
    parents = {
        PurePosixPath(relative).parent.as_posix()
        for _leaf, relative, _identity, _binding in rows
    }
    producers = {
        (
            str(binding.get("producer_work_unit_key") or ""),
            str(binding.get("producer_contract_digest") or ""),
        )
        for _leaf, _relative, _identity, binding in rows
    }
    if (
        len(parents) != 1
        or len(producers) != 1
        or not all(next(iter(producers)))
    ):
        raise PreverifyProjectionAuthorityError(
            "frozen inventory, records, and receipt are not co-rooted under "
            "one committed producer"
        )
    frozen_root = next(iter(parents))
    match = _FROZEN_ROOT.fullmatch(frozen_root)
    assert match is not None
    frozen_generation = match.group(1)
    producer_key, producer_contract_digest = next(iter(producers))
    expected_paths = {
        leaf: f"{frozen_root}/{leaf}"
        for leaf in _FROZEN_REQUIRED_LEAVES
    }
    row_by_leaf = {
        leaf: {
            "relative": relative,
            "identity": identity,
            "binding": binding,
        }
        for leaf, relative, identity, binding in rows
    }
    if any(
        row_by_leaf[leaf]["relative"] != expected_paths[leaf]
        for leaf in _FROZEN_REQUIRED_LEAVES
    ):
        raise PreverifyProjectionAuthorityError(
            "frozen capture members do not resolve to the exact common root"
        )

    if inventory_source and inventory_source != expected_paths[
        "findings_inventory.md"
    ]:
        raise PreverifyProjectionAuthorityError(
            "successor inventory source is not the authenticated frozen root"
        )
    if records_source and records_source != expected_paths[
        "finding_records.json"
    ]:
        raise PreverifyProjectionAuthorityError(
            "successor records source is not the authenticated frozen root"
        )
    expected_evidence = f"{frozen_root}/{_FROZEN_OPTIONAL_LEAF}"
    if evidence_source and evidence_source != expected_evidence:
        raise PreverifyProjectionAuthorityError(
            "successor evidence source is not the authenticated frozen root"
        )

    producer_unit = work_units.get(producer_key)
    producer_artifacts = (
        producer_unit.get("artifacts")
        if isinstance(producer_unit, Mapping)
        else None
    )
    manifest = (
        producer_unit.get("contract_manifest")
        if isinstance(producer_unit, Mapping)
        else None
    )
    manifest_outputs = (
        manifest.get("outputs")
        if isinstance(manifest, Mapping)
        else None
    )
    manifest_identity_rows = [
        str(row.get("identity") or "")
        for row in manifest_outputs or ()
        if isinstance(row, Mapping)
    ]
    manifest_identities = set(manifest_identity_rows)
    required_output_identities = {
        "scratchpad:" + relative
        for relative in expected_paths.values()
    }
    source_preimage_prefix = (
        "scratchpad:" + frozen_root + "/_sources/"
    )
    try:
        from preverify_frozen_projection import (
            FROZEN_SOURCE_PREIMAGE_LEAVES,
        )
    except ImportError as exc:
        raise PreverifyProjectionAuthorityError(
            "frozen projection source-preimage contract is unavailable"
        ) from exc
    source_preimage_leaves = set(
        FROZEN_SOURCE_PREIMAGE_LEAVES.values()
    )
    source_preimage_identities = {
        str(identity)
        for identity in (
            producer_artifacts if isinstance(producer_artifacts, Mapping)
            else ()
        )
        if (
            str(identity).startswith(source_preimage_prefix)
            and str(identity).removeprefix(source_preimage_prefix)
            in source_preimage_leaves
        )
    }
    allowed_output_identities = {
        *required_output_identities,
        "scratchpad:" + expected_evidence,
        *source_preimage_identities,
    }
    producer_parts = _work_unit_parts(producer_key)
    expected_phase = (
        "sc_verify_queue"
        if producer_parts[0] == "sc"
        else "verify_queue"
        if producer_parts[0] == "l1"
        else ""
    )
    if (
        not expected_phase
        or producer_parts[3] not in {"claude", "codex"}
        or producer_parts[4] != expected_phase
        or producer_parts[5]
        != f"preverify_frozen_projection.{frozen_generation}"
        or not isinstance(producer_unit, Mapping)
        or producer_unit.get("run_id") != run
        or producer_unit.get("execution_state") != "OUTPUT_COMMITTED"
        or producer_unit.get("semantic_status") != "ACTIVE"
        or producer_unit.get("contract_digest") != producer_contract_digest
        or not isinstance(producer_artifacts, Mapping)
        or set(producer_artifacts) != allowed_output_identities
        or (
            source_preimage_prefix
            + str(FROZEN_SOURCE_PREIMAGE_LEAVES["inventory"])
            not in source_preimage_identities
        )
        or not isinstance(manifest, Mapping)
        or manifest.get("key") != producer_key
        or manifest_identities != allowed_output_identities
        or len(manifest_identity_rows) != len(allowed_output_identities)
    ):
        raise PreverifyProjectionAuthorityError(
            "frozen projection producer is not the exact current-run "
            "content-addressed provider commit"
        )
    provider_input_bindings = producer_unit.get("input_bindings")
    if not isinstance(provider_input_bindings, Mapping):
        raise PreverifyProjectionAuthorityError(
            "frozen projection producer has no exact input denominator"
        )
    try:
        from preverify_frozen_projection import (
            reconstruct_preverify_frozen_contract_and_launch,
        )

        expected_contract, expected_launch = (
            reconstruct_preverify_frozen_contract_and_launch(
                generation_digest=frozen_generation,
                exact_input_identities=tuple(provider_input_bindings),
                output_paths=tuple(
                    identity.removeprefix("scratchpad:")
                    for identity in sorted(allowed_output_identities)
                ),
                pipeline=producer_parts[0],
                mode=producer_parts[1],
                ecosystem=producer_parts[2],
                backend=producer_parts[3],
                phase_name=producer_parts[4],
                run_id=run,
            )
        )
    except (ImportError, TypeError, ValueError) as exc:
        raise PreverifyProjectionAuthorityError(
            "frozen projection provider contract cannot be reconstructed"
        ) from exc
    _require_exact_registered_contract(
        unit=producer_unit,
        expected_contract=expected_contract,
        expected_launch=expected_launch,
        label="frozen projection producer",
    )
    committed_issues = active_committed_work_unit_authority_issues(
        ledger,
        work_unit_key=producer_key,
        run_id=run,
        expected_artifact_identities=tuple(
            sorted(allowed_output_identities)
        ),
    )
    if committed_issues:
        raise PreverifyProjectionAuthorityError(
            "frozen projection producer active commit is invalid: "
            + "; ".join(committed_issues)
        )
    if not required_output_identities <= set(producer_artifacts):
        raise PreverifyProjectionAuthorityError(
            "frozen projection producer output denominator is incomplete"
        )
    producer_issues: list[str] = []
    for leaf in _FROZEN_REQUIRED_LEAVES:
        row = row_by_leaf[leaf]
        producer_issues.extend(
            semantic_input_producer_authority_issues(
                ledger,
                row["binding"],
                run_id=run,
            )
        )
    for identity, binding in sorted(provider_input_bindings.items()):
        if identity == "scratchpad:_semantic_mutations.json":
            continue
        if not isinstance(binding, Mapping):
            producer_issues.append(
                f"{identity}: frozen provider input binding is malformed"
            )
            continue
        producer_issues.extend(
            semantic_input_producer_authority_issues(
                ledger,
                binding,
                run_id=run,
            )
        )
    exact_fields = (
        "identity",
        "owner_key",
        "writer",
        "run_id",
        "contract_digest",
        "launch_digest",
        "sha256",
        "size",
        "status",
    )
    for identity in sorted(allowed_output_identities):
        artifact = producer_artifacts.get(identity)
        binding = artifact_bindings.get(identity)
        if (
            not isinstance(artifact, Mapping)
            or not isinstance(binding, Mapping)
            or artifact.get("status") != "ACTIVE"
            or binding.get("status") != "ACTIVE"
            or artifact.get("owner_key") != producer_key
            or binding.get("owner_key") != producer_key
            or artifact.get("run_id") != run
            or binding.get("run_id") != run
            or artifact.get("contract_digest")
            != producer_contract_digest
            or binding.get("contract_digest")
            != producer_contract_digest
            or artifact.get("launch_digest")
            != producer_unit.get("launch_digest")
            or binding.get("launch_digest")
            != producer_unit.get("launch_digest")
            or artifact.get("writer") != "DRIVER"
            or binding.get("writer") != "DRIVER"
            or any(
                artifact.get(field) != binding.get(field)
                for field in exact_fields
            )
        ):
            producer_issues.append(
                f"{identity}: frozen producer artifact/global binding tuple "
                "is not exact and ACTIVE"
            )
    if producer_issues:
        raise PreverifyProjectionAuthorityError(
            "frozen projection producer authority is invalid: "
            + "; ".join(dict.fromkeys(producer_issues))
        )

    return {
        "frozen_root": frozen_root,
        "frozen_generation": frozen_generation,
        "producer_key": producer_key,
        "producer_contract_digest": producer_contract_digest,
        "inventory_path": expected_paths["findings_inventory.md"],
        "records_path": expected_paths["finding_records.json"],
        "receipt_path": expected_paths["receipt.json"],
        "evidence_path": expected_evidence,
        "provider_input_bindings": dict(provider_input_bindings),
        "rows": row_by_leaf,
        "source_preimage_rows": {
            identity.removeprefix(source_preimage_prefix): {
                "path": identity.removeprefix("scratchpad:"),
                "identity": identity,
                "binding": dict(producer_artifacts[identity]),
            }
            for identity in sorted(source_preimage_identities)
        },
    }


def validate_frozen_projection_receipt(
    payload: Mapping[str, Any],
    *,
    authority: Mapping[str, Any],
    run_id: str,
    evidence_source: str,
    inventory_raw: bytes,
    records_raw: bytes,
    advisory_evidence_raw: bytes,
    scratchpad: Path | None = None,
    project_root: Path | None = None,
) -> None:
    if set(payload) != _FROZEN_RECEIPT_FIELDS:
        missing = sorted(_FROZEN_RECEIPT_FIELDS - set(payload))
        unexpected = sorted(set(payload) - _FROZEN_RECEIPT_FIELDS)
        raise PreverifyProjectionAuthorityError(
            "frozen projection receipt field denominator differs; "
            f"missing={missing!r}; unexpected={unexpected!r}"
        )
    try:
        from preverify_frozen_projection import (
            DERIVATION_ALGORITHM,
            DERIVATION_CONFORMANCE_SHA256,
            derive_preverify_advisory_evidence_debt,
            derive_preverify_finding_records_bytes,
            derive_preverify_inventory_union,
            FROZEN_SOURCE_PREIMAGE_LEAVES,
            RECEIPT_SCHEMA,
            validate_preverify_derivation_conformance,
        )

        validate_preverify_derivation_conformance()
        expected_records_raw = derive_preverify_finding_records_bytes(
            inventory_raw
        )
    except (ImportError, OSError, TypeError, ValueError) as exc:
        raise PreverifyProjectionAuthorityError(
            "frozen projection deterministic provider cannot be replayed"
        ) from exc
    if records_raw != expected_records_raw:
        raise PreverifyProjectionAuthorityError(
            "frozen finding records are not the deterministic inventory "
            "derivation"
        )

    unsigned = {
        key: value for key, value in payload.items()
        if key != "receipt_digest"
    }
    logical = payload.get("logical_to_physical")
    required_paths = payload.get("required_paths")
    expected_logical = {
        "findings_inventory.md": authority["inventory_path"],
        "finding_records.json": authority["records_path"],
        **(
            {"inventory_evidence_validation.md": authority["evidence_path"]}
            if evidence_source
            else {}
        ),
    }
    expected_required = sorted({
        *expected_logical.values(),
        str(authority["receipt_path"]),
    })
    generation_core = {
        key: value
        for key, value in payload.items()
        if key
        not in {
            "generation_digest",
            "logical_to_physical",
            "advisory_evidence_path",
            "required_paths",
            "debt",
            "proof_authority",
            "receipt_digest",
        }
    }
    generation_core["schema_version"] = (
        "plamen.preverify_frozen_projection.v1"
    )
    producer_parts = str(authority["producer_key"]).split("/")
    expected_dimensions = (
        {
            "pipeline": producer_parts[0],
            "mode": producer_parts[1],
            "ecosystem": producer_parts[2],
            "backend": producer_parts[3],
            "phase_name": producer_parts[4],
        }
        if len(producer_parts) == 6
        else {}
    )
    expected_inventory_binding = {
        "sha256": hashlib.sha256(inventory_raw).hexdigest(),
        "size": len(inventory_raw),
    }
    expected_records_binding = {
        "sha256": hashlib.sha256(records_raw).hexdigest(),
        "size": len(records_raw),
    }
    expected_evidence_binding = {
        "sha256": hashlib.sha256(advisory_evidence_raw).hexdigest(),
        "size": len(advisory_evidence_raw),
    }
    if (
        payload.get("schema_version") != RECEIPT_SCHEMA
        or payload.get("derivation_algorithm") != DERIVATION_ALGORITHM
        or payload.get("derivation_conformance_sha256")
        != DERIVATION_CONFORMANCE_SHA256
    ):
        raise PreverifyProjectionAuthorityError(
            "frozen projection derivation algorithm or conformance authority "
            "is unsupported"
        )
    if (
        payload.get("run_id") != run_id
        or payload.get("generation_digest")
        != authority["frozen_generation"]
        or payload.get("generation_digest")
        != _canonical_payload_digest(generation_core)
        or payload.get("receipt_digest")
        != _canonical_payload_digest(unsigned)
        or any(
            payload.get(key) != value
            for key, value in expected_dimensions.items()
        )
        or payload.get("inventory") != expected_inventory_binding
        or payload.get("records") != expected_records_binding
        or payload.get("evidence") != expected_evidence_binding
        or logical != expected_logical
        or required_paths != expected_required
        or payload.get("advisory_evidence_path")
        != authority["evidence_path"]
        or payload.get("proof_authority") != "NONE"
    ):
        raise PreverifyProjectionAuthorityError(
            "frozen projection receipt does not bind the exact physical "
            "inventory/records/receipt authority"
        )

    evidence_semantic_use = payload.get("evidence_semantic_use")
    evidence_status = payload.get("evidence_status")
    evidence_reason = payload.get("evidence_reason_code")
    evidence_policy = {
        (
            True,
            "AUTHORIZED_ADVISORY",
            "",
        ): None,
        (
            False,
            "ABSENT_REPAIR_DEBT",
            "EVIDENCE_PROJECTION_ABSENT",
        ): "ABSENT",
        (
            False,
            "PRESENT_UNAUTHORIZED_REPAIR_DEBT",
            "EVIDENCE_PROJECTION_UNAUTHORIZED",
        ): "PRESENT_UNAUTHORIZED",
    }
    policy_key = (
        evidence_semantic_use,
        evidence_status,
        evidence_reason,
    )
    if policy_key not in evidence_policy:
        raise PreverifyProjectionAuthorityError(
            "frozen projection evidence policy state is invalid"
        )
    if bool(evidence_source) is not (evidence_semantic_use is True):
        raise PreverifyProjectionAuthorityError(
            "frozen successor evidence routing differs from receipt policy"
        )
    repair_status = evidence_policy[policy_key]
    if repair_status is not None:
        expected_advisory = derive_preverify_advisory_evidence_debt(
            status=repair_status,
            reason_code=str(evidence_reason),
        )
        if advisory_evidence_raw != expected_advisory:
            raise PreverifyProjectionAuthorityError(
                "frozen advisory evidence repair bytes are not canonical"
            )

    inventory_source = _relative(
        payload.get("inventory_source"),
        label="frozen inventory authority source",
    )
    evidence_input_source = _relative(
        payload.get("evidence_source"),
        label="frozen evidence authority source",
    )
    chain_delta = payload.get("chain_candidate_delta")
    if chain_delta is not None and not isinstance(chain_delta, Mapping):
        raise PreverifyProjectionAuthorityError(
            "frozen chain candidate delta authority is malformed"
        )
    expected_roles: dict[str, str] = {
        "inventory": "scratchpad:" + inventory_source,
    }
    if evidence_semantic_use is True:
        expected_roles["evidence"] = (
            "scratchpad:" + evidence_input_source
        )
    if isinstance(chain_delta, Mapping):
        if set(chain_delta) != {
            "generation_digest",
            "candidate_digest",
            "candidate_ids",
            "candidate_path",
            "receipt_path",
            "debt",
        }:
            raise PreverifyProjectionAuthorityError(
                "frozen chain candidate delta field denominator differs"
            )
        candidate_path = _relative(
            chain_delta.get("candidate_path"),
            label="chain candidate source",
        )
        delta_receipt_path = _relative(
            chain_delta.get("receipt_path"),
            label="chain candidate receipt source",
        )
        expected_roles.update({
            "chain_candidate_delta": "scratchpad:" + candidate_path,
            "chain_candidate_delta_receipt": (
                "scratchpad:" + delta_receipt_path
            ),
        })

    source_authorities = payload.get("source_authorities")
    if isinstance(chain_delta, Mapping):
        try:
            from chain_candidate_inventory_union import (
                DELTA_ROOT,
                DELTA_SOURCE_PREIMAGE_LEAVES,
            )
        except ImportError as exc:
            raise PreverifyProjectionAuthorityError(
                "chain candidate source-preimage contract is unavailable"
            ) from exc
        delta_generation = str(
            chain_delta.get("generation_digest") or ""
        )
        if _HEX64.fullmatch(delta_generation) is None:
            raise PreverifyProjectionAuthorityError(
                "chain candidate source-preimage generation is invalid"
            )
        frozen_to_delta_roles = {
            "chain_candidate_source_hypotheses": "hypotheses",
            "chain_candidate_source_finding_mapping": (
                "finding_mapping"
            ),
            "chain_candidate_source_pair_receipt": "pair_receipt",
            "chain_candidate_source_enabler_results": "enabler_results",
        }
        if (
            isinstance(source_authorities, Mapping)
            and "chain_candidate_source_auto_map_receipt"
            in source_authorities
        ):
            frozen_to_delta_roles[
                "chain_candidate_source_auto_map_receipt"
            ] = "auto_map_receipt"
        for frozen_role, delta_role in frozen_to_delta_roles.items():
            expected_roles[frozen_role] = (
                "scratchpad:"
                f"{DELTA_ROOT}/generation_{delta_generation}/_sources/"
                f"{DELTA_SOURCE_PREIMAGE_LEAVES[delta_role]}"
            )
    provider_inputs = authority.get("provider_input_bindings")
    if (
        not isinstance(source_authorities, Mapping)
        or set(source_authorities) != set(expected_roles)
        or not isinstance(provider_inputs, Mapping)
    ):
        raise PreverifyProjectionAuthorityError(
            "frozen receipt source-authority denominator differs"
        )
    if scratchpad is None or project_root is None:
        raise PreverifyProjectionAuthorityError(
            "frozen source replay requires the exact scratchpad and project "
            "authority roots"
        )
    source_root = Path(scratchpad)
    try:
        source_ledger = read_artifact_ledger(source_root)
    except (ArtifactLedgerError, OSError, TypeError, ValueError) as exc:
        raise PreverifyProjectionAuthorityError(
            "frozen source replay artifact ledger is unavailable"
        ) from exc
    semantic_control_required = any(
        isinstance(row, Mapping)
        and row.get("authority_kind")
        == "CONTIGUOUS_SEMANTIC_MUTATION_CHAIN"
        for row in source_authorities.values()
    )
    expected_preimage_roles = {
        *expected_roles,
        *(
            {"semantic_mutations"}
            if semantic_control_required
            else set()
        ),
    }
    expected_preimage_leaves = FROZEN_SOURCE_PREIMAGE_LEAVES
    preimage_bindings = payload.get("source_preimage_bindings")
    preimage_rows = authority.get("source_preimage_rows")
    frozen_root = _relative(
        authority.get("frozen_root"),
        label="frozen source-preimage root",
    )
    if (
        not isinstance(preimage_bindings, Mapping)
        or set(preimage_bindings) != expected_preimage_roles
        or not isinstance(preimage_rows, Mapping)
        or set(preimage_rows)
        != {
            expected_preimage_leaves[role]
            for role in expected_preimage_roles
        }
    ):
        raise PreverifyProjectionAuthorityError(
            "frozen source-preimage denominator differs"
        )
    replayed_source_bytes: dict[str, bytes] = {}
    for role in sorted(expected_preimage_roles):
        preimage = preimage_bindings.get(role)
        expected_leaf = expected_preimage_leaves[role]
        authority_row = preimage_rows.get(expected_leaf)
        if (
            not isinstance(preimage, Mapping)
            or set(preimage) != {"leaf", "sha256", "size"}
            or preimage.get("leaf") != expected_leaf
            or _HEX64.fullmatch(str(preimage.get("sha256") or ""))
            is None
            or not isinstance(preimage.get("size"), int)
            or isinstance(preimage.get("size"), bool)
            or int(preimage.get("size") or 0) < 0
            or not isinstance(authority_row, Mapping)
        ):
            raise PreverifyProjectionAuthorityError(
                f"frozen {role} source-preimage binding is malformed"
            )
        relative = f"{frozen_root}/_sources/{expected_leaf}"
        raw = _read(
            source_root,
            relative,
            label=f"frozen {role} source preimage",
        )
        artifact_binding = authority_row.get("binding")
        if (
            authority_row.get("path") != relative
            or authority_row.get("identity")
            != "scratchpad:" + relative
            or not isinstance(artifact_binding, Mapping)
            or artifact_binding.get("status") != "ACTIVE"
            or artifact_binding.get("sha256")
            != preimage.get("sha256")
            or artifact_binding.get("size") != preimage.get("size")
            or hashlib.sha256(raw).hexdigest()
            != preimage.get("sha256")
            or len(raw) != preimage.get("size")
        ):
            raise PreverifyProjectionAuthorityError(
                f"frozen {role} source preimage differs from its exact "
                "committed provider output"
            )
        replayed_source_bytes[role] = raw
    mutation_payload = (
        _strict_json(
            replayed_source_bytes["semantic_mutations"],
            label="frozen semantic mutation snapshot",
        )
        if semantic_control_required
        else None
    )
    for role, expected_identity in sorted(expected_roles.items()):
        row = source_authorities.get(role)
        binding = provider_inputs.get(expected_identity)
        if (
            not isinstance(row, Mapping)
            or set(row) != _SOURCE_AUTHORITY_FIELDS
            or not isinstance(binding, Mapping)
        ):
            raise PreverifyProjectionAuthorityError(
                f"frozen {role} source authority is incomplete"
            )
        kind = row.get("authority_kind")
        mutation_events = row.get("mutation_event_ids")
        mutation_digests = row.get("mutation_authority_digests")
        if (
            row.get("schema_version")
            != "plamen.semantic_import_authority.v1"
            or kind not in {
                "EXACT_PHASE_IO_PRODUCER",
                "CONTIGUOUS_SEMANTIC_MUTATION_CHAIN",
            }
            or row.get("identity") != expected_identity
            or row.get("run_id") != run_id
            or not isinstance(mutation_events, list)
            or not isinstance(mutation_digests, list)
            or any(not isinstance(value, str) or not value for value in mutation_events)
            or any(_HEX64.fullmatch(str(value)) is None for value in mutation_digests)
            or len(mutation_events) != len(set(mutation_events))
            or len(mutation_digests) != len(set(mutation_digests))
            or binding.get("identity") != expected_identity
            or binding.get("status") != "ACTIVE"
            or binding.get("sha256") != row.get("source_sha256")
            or binding.get("size") != row.get("source_size")
            or binding.get("producer_work_unit_key")
            != row.get("producer_work_unit_key")
            or binding.get("producer_contract_digest")
            != row.get("producer_contract_digest")
        ):
            raise PreverifyProjectionAuthorityError(
                f"frozen {role} source authority does not reconcile to "
                "its exact provider input"
            )
        try:
            replayed_authority = (
                semantic_import_authority_from_snapshot(
                    source_ledger,
                    mutation_payload,
                    expected_identity,
                    binding,
                    run_id=run_id,
                )
            )
        except (ArtifactLedgerError, TypeError, ValueError) as exc:
            raise PreverifyProjectionAuthorityError(
                f"frozen {role} semantic source/ledger authority cannot be "
                "replayed"
            ) from exc
        source_raw = replayed_source_bytes[role]
        if (
            dict(row) != replayed_authority
            or row.get("source_sha256")
            != hashlib.sha256(source_raw).hexdigest()
            or row.get("source_size") != len(source_raw)
        ):
            raise PreverifyProjectionAuthorityError(
                f"frozen {role} semantic source authority differs from the "
                "exact immutable ledger replay"
            )
        if kind == "EXACT_PHASE_IO_PRODUCER":
            if mutation_events or mutation_digests:
                raise PreverifyProjectionAuthorityError(
                    f"frozen {role} exact producer carries mutation claims"
                )
        elif (
            not mutation_events
            or len(mutation_events) != len(mutation_digests)
        ):
            raise PreverifyProjectionAuthorityError(
                f"frozen {role} semantic mutation chain is incomplete"
            )
    expected_provider_inputs = {
        *expected_roles.values(),
        *(
            {"scratchpad:_semantic_mutations.json"}
            if semantic_control_required
            else set()
        ),
    }
    if set(provider_inputs) != expected_provider_inputs:
        raise PreverifyProjectionAuthorityError(
            "frozen provider inputs differ from receipt source authorities"
        )
    if semantic_control_required:
        control_binding = provider_inputs.get(
            "scratchpad:_semantic_mutations.json"
        )
        control_raw = replayed_source_bytes["semantic_mutations"]
        if (
            not isinstance(control_binding, Mapping)
            or control_binding.get("status") != "ACTIVE"
            or control_binding.get("sha256")
            != hashlib.sha256(control_raw).hexdigest()
            or control_binding.get("size") != len(control_raw)
        ):
            raise PreverifyProjectionAuthorityError(
                "frozen semantic mutation control preimage differs from the "
                "provider input binding"
            )
    if evidence_semantic_use is True:
        evidence_authority = source_authorities["evidence"]
        if (
            evidence_authority.get("source_sha256")
            != expected_evidence_binding["sha256"]
            or evidence_authority.get("source_size")
            != expected_evidence_binding["size"]
            or replayed_source_bytes.get("evidence")
            != advisory_evidence_raw
        ):
            raise PreverifyProjectionAuthorityError(
                "frozen evidence output differs from its source authority"
            )

    base_inventory_raw = replayed_source_bytes["inventory"]
    replayed_delta_payload: dict[str, Any] | None = None
    if isinstance(chain_delta, Mapping):
        replayed_delta_payload = _replay_chain_candidate_delta(
            payload=payload,
            chain_delta=chain_delta,
            candidate_raw=replayed_source_bytes[
                "chain_candidate_delta"
            ],
            receipt_raw=replayed_source_bytes[
                "chain_candidate_delta_receipt"
            ],
            source_preimages=replayed_source_bytes,
            source_authorities=source_authorities,
            ledger=source_ledger,
            run_id=run_id,
        )
    try:
        (
            expected_inventory_raw,
            replayed_fixed_point,
            replayed_collision_debt,
        ) = derive_preverify_inventory_union(
            base_inventory_raw,
            replayed_delta_payload,
        )
    except (TypeError, ValueError) as exc:
        raise PreverifyProjectionAuthorityError(
            "frozen inventory base-plus-delta derivation cannot be replayed"
        ) from exc
    if inventory_raw != expected_inventory_raw:
        raise PreverifyProjectionAuthorityError(
            "frozen inventory bytes are not the exact authenticated "
            "base-plus-delta source replay"
        )

    try:
        inventory_text = inventory_raw.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise PreverifyProjectionAuthorityError(
            "frozen inventory is not strict UTF-8"
        ) from exc
    actual_frozen_ids = sorted(
        match.group(1).upper()
        for match in _FINDING_HEADING.finditer(inventory_text)
    )
    fixed_point = payload.get("candidate_delivery_fixed_point")
    if not isinstance(fixed_point, Mapping):
        raise PreverifyProjectionAuthorityError(
            "frozen candidate delivery fixed point is malformed"
        )
    if dict(fixed_point) != replayed_fixed_point:
        raise PreverifyProjectionAuthorityError(
            "frozen candidate delivery fixed point differs from exact source "
            "replay"
        )
    expected_fixed_fields = {
        "base_ids",
        "delta_ids",
        "frozen_ids",
        "base_union_delta_equals_frozen",
        "candidate_records_removed",
        *(
            {"identity_collision_ids"}
            if isinstance(chain_delta, Mapping)
            else set()
        ),
    }
    base_ids = fixed_point.get("base_ids")
    delta_ids = fixed_point.get("delta_ids")
    frozen_ids = fixed_point.get("frozen_ids")
    if (
        set(fixed_point) != expected_fixed_fields
        or not isinstance(base_ids, list)
        or not isinstance(delta_ids, list)
        or not isinstance(frozen_ids, list)
        or any(not isinstance(value, str) or not value for value in base_ids + delta_ids + frozen_ids)
        or base_ids != sorted(set(base_ids))
        or frozen_ids != sorted(set(frozen_ids))
        or fixed_point.get("base_union_delta_equals_frozen") is not True
        or fixed_point.get("candidate_records_removed") != 0
        or frozen_ids != actual_frozen_ids
        or sorted(set(base_ids) | set(delta_ids)) != frozen_ids
    ):
        raise PreverifyProjectionAuthorityError(
            "frozen candidate delivery fixed point does not replay"
        )
    if chain_delta is None:
        if delta_ids or base_ids != frozen_ids:
            raise PreverifyProjectionAuthorityError(
                "frozen no-delta fixed point is not exact"
            )
        delta_debt: list[Any] = []
        collision_debt: list[Any] = []
    else:
        candidate_ids = chain_delta.get("candidate_ids")
        delta_debt_value = chain_delta.get("debt")
        collision_ids = fixed_point.get("identity_collision_ids")
        if (
            not isinstance(candidate_ids, list)
            or any(not isinstance(value, str) or not value for value in candidate_ids)
            or delta_ids
            != [str(value).upper() for value in candidate_ids]
            or len(delta_ids) != len(set(delta_ids))
            or not isinstance(delta_debt_value, list)
            or not isinstance(collision_ids, list)
            or collision_ids != sorted(set(collision_ids))
            or not set(collision_ids) <= (set(base_ids) & set(delta_ids))
            or _HEX64.fullmatch(
                str(chain_delta.get("generation_digest") or "")
            )
            is None
            or _HEX64.fullmatch(
                str(chain_delta.get("candidate_digest") or "")
            )
            is None
        ):
            raise PreverifyProjectionAuthorityError(
                "frozen chain candidate fixed point is inconsistent"
            )
        delta_debt = list(delta_debt_value)
        debt_rows = payload.get("debt")
        if not isinstance(debt_rows, list):
            raise PreverifyProjectionAuthorityError(
                "frozen projection debt denominator is malformed"
            )
        evidence_debt_count = 0 if evidence_semantic_use is True else 1
        collision_debt = debt_rows[
            evidence_debt_count + len(delta_debt):
        ]
        if collision_debt != replayed_collision_debt:
            raise PreverifyProjectionAuthorityError(
                "frozen chain collision debt differs from exact source replay"
            )
        expected_collision_order = [
            identity
            for identity in delta_ids
            if identity in set(collision_ids)
        ]
        if (
            len(collision_debt) != len(expected_collision_order)
            or any(
                not isinstance(row, Mapping)
                or set(row) != {
                    "reason_code",
                    "candidate_identity",
                    "base_block_sha256",
                    "delta_block_sha256",
                    "candidate",
                    "candidate_disposition",
                    "proof_authority",
                }
                or row.get("reason_code")
                != "CHAIN_CANDIDATE_IDENTITY_COLLISION"
                or row.get("candidate_identity")
                != expected_collision_order[index]
                or _HEX64.fullmatch(
                    str(row.get("base_block_sha256") or "")
                )
                is None
                or _HEX64.fullmatch(
                    str(row.get("delta_block_sha256") or "")
                )
                is None
                or not isinstance(row.get("candidate"), Mapping)
                or row.get("candidate_disposition")
                != "VISIBLE_HUMAN_REVIEW_DEBT"
                or row.get("proof_authority") != "NONE"
                for index, row in enumerate(collision_debt)
            )
        ):
            raise PreverifyProjectionAuthorityError(
                "frozen chain collision debt is not exact"
            )

    evidence_debt = (
        []
        if evidence_semantic_use is True
        else [{
            "artifact": evidence_input_source,
            "reason_code": evidence_reason,
            "authority": "ADVISORY_REPAIR_ONLY",
            "candidate_disposition": "PRESERVE_ALL_FOR_VERIFICATION",
        }]
    )
    expected_debt = [*evidence_debt, *delta_debt, *collision_debt]
    if payload.get("debt") != expected_debt:
        raise PreverifyProjectionAuthorityError(
            "frozen projection repair-debt denominator differs"
        )


def _resolve_current_preverify_projection(
    scratchpad: Path,
    *,
    expected_run_id: str = "",
    expected_consumer_work_unit_key: str = "",
    require_frozen: bool = True,
    allow_unbound_introspection: bool = False,
) -> dict[str, Any]:
    """Resolve one current successor generation to authenticated source bytes.

    The caller must check :func:`successor_projection_present` when legacy
    no-successor behavior is allowed.  Once either stable successor exists,
    this resolver never falls back to canonical root files.
    """

    root = Path(scratchpad)
    runtime_bound = bool(expected_run_id or expected_consumer_work_unit_key)
    if not runtime_bound and not allow_unbound_introspection:
        raise PreverifyProjectionAuthorityError(
            "runtime projection authority requires exact run and consumer "
            "scope binding; use explicit offline introspection otherwise"
        )
    if runtime_bound and not (
        expected_run_id and expected_consumer_work_unit_key
    ):
        raise PreverifyProjectionAuthorityError(
            "runtime projection authority is partially specified"
        )
    if not successor_projection_present(root):
        raise PreverifyProjectionAuthorityError(
            "preverify successor projection is absent"
        )
    final_relative = FINAL_RECEIPT_NAME
    delivery_relative = DELIVERY_RECEIPT_NAME
    final_raw = _read(root, final_relative, label="final successor")
    delivery_raw = _read(
        root, delivery_relative, label="delivery successor"
    )
    final_payload = _json(final_raw, label="final successor")
    delivery_payload = _json(delivery_raw, label="delivery successor")
    run_id = str(final_payload.get("run_id") or "")
    if runtime_bound and run_id != expected_run_id:
        raise PreverifyProjectionAuthorityError(
            "preverify successor run differs from current runtime"
        )
    try:
        validate_preverify_successor_payloads(
            root,
            final_payload=final_payload,
            delivery_payload=delivery_payload,
            run_id=run_id,
            validate_current_sources=False,
        )
    except PreverifyInventorySuccessorError as exc:
        raise PreverifyProjectionAuthorityError(
            f"stable successor payload is invalid: {exc}"
        ) from exc

    try:
        ledger = read_artifact_ledger(root)
    except (ArtifactLedgerError, OSError, TypeError, ValueError) as exc:
        raise PreverifyProjectionAuthorityError(
            "preverify successor artifact ledger is unavailable"
        ) from exc
    artifact_bindings = ledger.get("artifact_bindings")
    work_units = ledger.get("work_units")
    if not isinstance(artifact_bindings, Mapping) or not isinstance(
        work_units, Mapping
    ):
        raise PreverifyProjectionAuthorityError(
            "preverify successor artifact ledger is malformed"
        )
    stable_identities = (
        f"scratchpad:{final_relative}",
        f"scratchpad:{delivery_relative}",
    )
    stable_rows = [
        artifact_bindings.get(identity) for identity in stable_identities
    ]
    if any(not isinstance(row, Mapping) for row in stable_rows):
        raise PreverifyProjectionAuthorityError(
            "preverify stable successor has no complete PhaseIO binding"
        )
    for identity, row, raw in zip(
        stable_identities,
        stable_rows,
        (final_raw, delivery_raw),
    ):
        assert isinstance(row, Mapping)
        _binding_matches(row, raw, label=identity)
    owner_keys = {
        str(row.get("owner_key") or "")
        for row in stable_rows
        if isinstance(row, Mapping)
    }
    if len(owner_keys) != 1:
        raise PreverifyProjectionAuthorityError(
            "preverify stable successors do not share one owner"
        )
    owner_key = next(iter(owner_keys))
    owner_unit = work_units.get(owner_key)
    owner_parts = _work_unit_parts(owner_key)
    owner_expected_phase = (
        "sc_verify_queue"
        if owner_parts[0] == "sc"
        else "verify_queue"
        if owner_parts[0] == "l1"
        else ""
    )
    if (
        not owner_expected_phase
        or owner_parts[3] not in {"claude", "codex"}
        or owner_parts[4] != owner_expected_phase
        or owner_parts[5] != "preverify_successors"
        or not isinstance(owner_unit, Mapping)
        or owner_unit.get("run_id") != run_id
        or owner_unit.get("execution_state") != "OUTPUT_COMMITTED"
        or owner_unit.get("semantic_status") != "ACTIVE"
        or set(owner_unit.get("artifacts") or {}) != set(stable_identities)
    ):
        raise PreverifyProjectionAuthorityError(
            "preverify stable successor owner is not a committed PhaseIO unit"
        )
    stable_commit_issues = active_committed_work_unit_authority_issues(
        ledger,
        work_unit_key=owner_key,
        run_id=run_id,
        expected_artifact_identities=stable_identities,
    )
    if stable_commit_issues:
        raise PreverifyProjectionAuthorityError(
            "preverify stable successor active commit is invalid: "
            + "; ".join(stable_commit_issues)
        )
    for identity, row in zip(stable_identities, stable_rows):
        assert isinstance(row, Mapping)
        if (
            owner_unit["artifacts"][identity].get("sha256")
            != row.get("sha256")
        ):
            raise PreverifyProjectionAuthorityError(
                "preverify successor unit and artifact binding disagree"
            )

    expected_owner = ""
    expected_capture_prefix = ""
    expected_routing_consumer = ""
    expected_successor_consumer = ""
    if runtime_bound:
        parts = expected_consumer_work_unit_key.split("/")
        if len(parts) != 6 or parts[-1] != "routing":
            raise PreverifyProjectionAuthorityError(
                "current queue consumer work-unit identity is malformed"
            )
        expected_owner = "/".join((*parts[:-1], "preverify_successors"))
        expected_capture_prefix = "/".join(
            (*parts[:-1], "preverify_capture.")
        )
        expected_routing_consumer = "/".join(parts[-2:])
        expected_successor_consumer = (
            f"{parts[-2]}/preverify_successors"
        )
        manifest = owner_unit.get("contract_manifest")
        outputs = (
            manifest.get("outputs")
            if isinstance(manifest, Mapping)
            else None
        )
        output_rows = {
            str(row.get("identity") or ""): row
            for row in outputs or ()
            if isinstance(row, Mapping)
        }
        if (
            owner_key != expected_owner
            or not isinstance(manifest, Mapping)
            or manifest.get("key") != expected_owner
            or set(output_rows) != set(stable_identities)
            or any(
                row.get("owner_key") != expected_owner
                or expected_routing_consumer
                not in set(row.get("consumers") or ())
                for row in output_rows.values()
            )
        ):
            raise PreverifyProjectionAuthorityError(
                "preverify successor owner does not authorize the current "
                "typed queue consumer"
            )
        _validate_routing_projection_capability(
            ledger=ledger,
            routing_key=expected_consumer_work_unit_key,
            run_id=run_id,
            stable_rows={
                identity: row
                for identity, row in zip(
                    stable_identities,
                    stable_rows,
                )
                if isinstance(row, Mapping)
            },
        )

    generation_inputs = owner_unit.get("input_bindings")
    if not isinstance(generation_inputs, Mapping) or len(
        generation_inputs
    ) != 1:
        raise PreverifyProjectionAuthorityError(
            "preverify successor generation denominator is not singular"
        )
    generation_identity, generation_binding = next(
        iter(generation_inputs.items())
    )
    generation_prefix = (
        f"scratchpad:{GENERATION_DIRECTORY}/generation_"
    )
    if (
        not str(generation_identity).startswith(generation_prefix)
        or not str(generation_identity).endswith(".json")
        or not isinstance(generation_binding, Mapping)
    ):
        raise PreverifyProjectionAuthorityError(
            "preverify successor generation input is malformed"
        )
    generation_relative = str(generation_identity).removeprefix(
        "scratchpad:"
    )
    try:
        expected_owner_contract = resolve_phase_io_contract(
            pipeline=owner_parts[0],
            mode=owner_parts[1],
            ecosystem=owner_parts[2],
            backend=owner_parts[3],
            phase=owner_parts[4],
            work_unit_id=owner_parts[5],
            exact_inputs=(generation_relative,),
            exact_outputs=(final_relative, delivery_relative),
        )
    except (TypeError, ValueError) as exc:
        raise PreverifyProjectionAuthorityError(
            "preverify successor contract cannot be reconstructed"
        ) from exc
    _require_exact_registered_contract(
        unit=owner_unit,
        expected_contract=expected_owner_contract,
        expected_launch=_expected_driver_launch(expected_owner_contract),
        label="preverify successor owner",
    )
    generation_raw = _read(
        root, generation_relative, label="successor generation"
    )
    _binding_matches(
        generation_binding,
        generation_raw,
        label=str(generation_identity),
    )
    generation_producer_issues = semantic_input_producer_authority_issues(
        ledger,
        generation_binding,
        run_id=run_id,
    )
    if generation_producer_issues:
        raise PreverifyProjectionAuthorityError(
            "preverify successor generation producer is invalid: "
            + "; ".join(generation_producer_issues)
        )
    generation_payload = _json(
        generation_raw, label="successor generation"
    )
    try:
        validate_successor_generation_payload(
            root,
            payload=generation_payload,
            artifact_name=generation_relative,
            # The generation is an immutable historical capture.  Runtime
            # source replay below uses its committed source preimages and
            # semantic mutation snapshot; rebuilding from mutable roots would
            # make acknowledgement-only control changes stale valid history.
            validate_current_sources=False,
        )
    except PreverifyInventorySuccessorError as exc:
        raise PreverifyProjectionAuthorityError(
            f"preverify successor generation is invalid: {exc}"
        ) from exc
    if (
        generation_payload.get("final_payload") != final_payload
        or generation_payload.get("delivery_payload") != delivery_payload
    ):
        raise PreverifyProjectionAuthorityError(
            "stable successor projections differ from their generation"
        )

    capture_plan = generation_payload.get("capture_plan")
    source_projection = (
        capture_plan.get("source_projection")
        if isinstance(capture_plan, Mapping)
        else None
    )
    if require_frozen and not isinstance(source_projection, Mapping):
        raise PreverifyProjectionAuthorityError(
            "preverify successor lacks an explicit frozen source projection"
        )
    if isinstance(source_projection, Mapping):
        inventory_source = _relative(
            source_projection.get("inventory"),
            label="inventory source projection",
        )
        records_source = _relative(
            source_projection.get("records"),
            label="records source projection",
        )
        evidence_value = str(source_projection.get("evidence") or "")
        evidence_source = (
            _relative(
                evidence_value,
                label="evidence source projection",
            )
            if evidence_value
            else ""
        )
    else:
        inventory_source = "findings_inventory.md"
        records_source = "finding_records.json"
        evidence_source = ""

    capture_owner = str(
        generation_binding.get("producer_work_unit_key")
        or generation_binding.get("owner_key")
        or ""
    )
    capture_unit = work_units.get(capture_owner)
    if (
        "/preverify_capture." not in capture_owner
        or not isinstance(capture_unit, Mapping)
        or capture_unit.get("run_id") != run_id
        or capture_unit.get("execution_state") != "OUTPUT_COMMITTED"
        or capture_unit.get("semantic_status") != "ACTIVE"
        or set(capture_unit.get("artifacts") or {})
        != {generation_identity}
    ):
        raise PreverifyProjectionAuthorityError(
            "successor capture generation is not a committed PhaseIO unit"
        )
    generation_digest = str(
        generation_payload.get("generation_digest") or ""
    )
    if _HEX64.fullmatch(generation_digest) is None or not capture_owner.endswith(
        f"/preverify_capture.{generation_digest}"
    ):
        raise PreverifyProjectionAuthorityError(
            "successor capture owner does not match generation content address"
        )
    capture_parts = _work_unit_parts(capture_owner)
    if (
        capture_parts[:5] != owner_parts[:5]
        or capture_parts[5] != f"preverify_capture.{generation_digest}"
    ):
        raise PreverifyProjectionAuthorityError(
            "successor capture belongs to a different typed queue authority"
        )
    if runtime_bound:
        manifest = capture_unit.get("contract_manifest")
        outputs = (
            manifest.get("outputs")
            if isinstance(manifest, Mapping)
            else None
        )
        rows = [
            row for row in outputs or () if isinstance(row, Mapping)
        ]
        if (
            not capture_owner.startswith(expected_capture_prefix)
            or not isinstance(manifest, Mapping)
            or manifest.get("key") != capture_owner
            or len(rows) != 1
            or rows[0].get("identity") != generation_identity
            or rows[0].get("owner_key") != capture_owner
            or expected_successor_consumer
            not in set(rows[0].get("consumers") or ())
        ):
            raise PreverifyProjectionAuthorityError(
                "successor capture does not authorize the current runtime"
            )

    capture_inputs = capture_unit.get("input_bindings")
    if not isinstance(capture_inputs, Mapping):
        raise PreverifyProjectionAuthorityError(
            "successor capture has no exact input bindings"
        )
    try:
        expected_capture_contract = resolve_phase_io_contract(
            pipeline=capture_parts[0],
            mode=capture_parts[1],
            ecosystem=capture_parts[2],
            backend=capture_parts[3],
            phase=capture_parts[4],
            work_unit_id=capture_parts[5],
            exact_inputs=tuple(
                sorted(
                    _resolver_input_path(identity)
                    for identity in capture_inputs
                )
            ),
            exact_outputs=(generation_relative,),
        )
    except (TypeError, ValueError) as exc:
        raise PreverifyProjectionAuthorityError(
            "preverify capture contract cannot be reconstructed"
        ) from exc
    _require_exact_registered_contract(
        unit=capture_unit,
        expected_contract=expected_capture_contract,
        expected_launch=_expected_driver_launch(expected_capture_contract),
        label="preverify capture",
    )
    capture_commit_issues = active_committed_work_unit_authority_issues(
        ledger,
        work_unit_key=capture_owner,
        run_id=run_id,
        expected_artifact_identities=(str(generation_identity),),
    )
    if capture_commit_issues:
        raise PreverifyProjectionAuthorityError(
            "preverify capture active commit is invalid: "
            + "; ".join(capture_commit_issues)
        )
    capture_source_issues: list[str] = []
    for identity, binding in sorted(capture_inputs.items()):
        if identity == "scratchpad:_semantic_mutations.json":
            continue
        if not isinstance(binding, Mapping):
            capture_source_issues.append(
                f"{identity}: preverify capture binding is malformed"
            )
            continue
        capture_source_issues.extend(
            semantic_input_producer_authority_issues(
                ledger,
                binding,
                run_id=run_id,
            )
        )
    if capture_source_issues:
        raise PreverifyProjectionAuthorityError(
            "preverify capture input producer authority is invalid: "
            + "; ".join(dict.fromkeys(capture_source_issues))
        )
    frozen_authority = resolve_exact_frozen_capture_authority(
        input_bindings=capture_inputs,
        ledger=ledger,
        run_id=run_id,
        inventory_source=inventory_source,
        records_source=records_source,
        evidence_source=evidence_source,
    )
    if runtime_bound:
        expected_frozen_owner = (
            expected_capture_prefix.rsplit("preverify_capture.", 1)[0]
            + "preverify_frozen_projection."
            + str(frozen_authority["frozen_generation"])
        )
        if frozen_authority["producer_key"] != expected_frozen_owner:
            raise PreverifyProjectionAuthorityError(
                "frozen projection producer does not belong to the current "
                "typed queue phase"
            )

    inventory_raw = _read(
        root, inventory_source, label="frozen inventory"
    )
    records_raw = _read(root, records_source, label="frozen records")
    evidence_raw = (
        _read(root, evidence_source, label="frozen evidence")
        if evidence_source
        else b""
    )
    advisory_evidence_raw = (
        evidence_raw
        if evidence_source
        else _read(
            root,
            str(frozen_authority["evidence_path"]),
            label="frozen advisory evidence",
        )
    )
    receipt_source = str(frozen_authority["receipt_path"])
    receipt_raw = _read(
        root, receipt_source, label="frozen projection receipt"
    )
    projected = {
        "findings_inventory.md": (inventory_source, inventory_raw),
        "finding_records.json": (records_source, records_raw),
    }
    if evidence_source:
        projected["inventory_evidence_validation.md"] = (
            evidence_source,
            evidence_raw,
        )
    for logical, (relative, raw) in projected.items():
        identity = "scratchpad:" + relative
        binding = capture_inputs.get(identity)
        if not isinstance(binding, Mapping):
            raise PreverifyProjectionAuthorityError(
                f"{logical} is absent from the successor capture denominator"
            )
        _binding_matches(binding, raw, label=identity)
    receipt_identity = "scratchpad:" + receipt_source
    receipt_binding = capture_inputs.get(receipt_identity)
    if not isinstance(receipt_binding, Mapping):
        raise PreverifyProjectionAuthorityError(
            "frozen projection receipt is absent from the capture denominator"
        )
    _binding_matches(
        receipt_binding,
        receipt_raw,
        label=receipt_identity,
    )
    validate_frozen_projection_receipt(
        _json(receipt_raw, label="frozen projection receipt"),
        authority=frozen_authority,
        run_id=run_id,
        evidence_source=evidence_source,
        inventory_raw=inventory_raw,
        records_raw=records_raw,
        advisory_evidence_raw=advisory_evidence_raw,
        scratchpad=root,
        project_root=root.parent,
    )

    try:
        inventory_text = inventory_raw.decode("utf-8", errors="strict")
        records_payload = json.loads(
            records_raw.decode("utf-8", errors="strict")
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PreverifyProjectionAuthorityError(
            "frozen inventory or records projection is malformed"
        ) from exc
    if not isinstance(records_payload, dict):
        raise PreverifyProjectionAuthorityError(
            "frozen records projection is not an object"
        )
    return {
        "state": "AUTHENTICATED_FROZEN",
        "run_id": run_id,
        "owner_key": owner_key,
        "capture_owner_key": capture_owner,
        "generation_artifact": generation_relative,
        "generation_digest": generation_digest,
        "frozen_generation_digest": frozen_authority[
            "frozen_generation"
        ],
        "inventory_source_artifact": inventory_source,
        "records_source_artifact": records_source,
        "evidence_source_artifact": evidence_source,
        "frozen_receipt_artifact": receipt_source,
        "inventory_raw": inventory_raw,
        "inventory_text": inventory_text,
        "records_raw": records_raw,
        "records_payload": records_payload,
        "evidence_raw": evidence_raw,
        "final_payload": final_payload,
        "delivery_payload": delivery_payload,
        "generation_payload": generation_payload,
        "authority_scope": (
            "RUNTIME_BOUND"
            if runtime_bound
            else "OFFLINE_INTROSPECTION_ONLY"
        ),
        "runtime_authority": runtime_bound,
    }


def resolve_current_preverify_projection(
    scratchpad: Path,
    *,
    expected_run_id: str = "",
    expected_consumer_work_unit_key: str = "",
    require_frozen: bool = True,
) -> dict[str, Any]:
    """Resolve runtime authority bound to one exact run/queue consumer."""

    return _resolve_current_preverify_projection(
        scratchpad,
        expected_run_id=expected_run_id,
        expected_consumer_work_unit_key=expected_consumer_work_unit_key,
        require_frozen=require_frozen,
        allow_unbound_introspection=False,
    )


def resolve_active_preverify_projection(
    scratchpad: Path,
    *,
    require_frozen: bool = True,
) -> dict[str, Any]:
    """Resolve the singular current armed/committed routing capability.

    Downstream helpers that do not own the audit configuration must not guess
    a run ID, reuse an offline inspection result, or impersonate a routing
    consumer by string.  This adapter derives the exact routing key from the
    committed successor owner, then the main resolver proves that the
    corresponding current-run routing work unit is exactly armed or committed.
    """

    root = Path(scratchpad)
    if not successor_projection_present(root):
        raise PreverifyProjectionAuthorityError(
            "preverify successor projection is absent"
        )
    final_payload = _json(
        _read(root, FINAL_RECEIPT_NAME, label="final successor"),
        label="final successor",
    )
    run_id = str(final_payload.get("run_id") or "")
    try:
        ledger = read_artifact_ledger(root)
    except (ArtifactLedgerError, OSError, TypeError, ValueError) as exc:
        raise PreverifyProjectionAuthorityError(
            "active preverify routing capability ledger is unavailable"
        ) from exc
    stable = ledger.get("artifact_bindings", {}).get(
        "scratchpad:" + FINAL_RECEIPT_NAME
    )
    owner = (
        str(stable.get("owner_key") or "")
        if isinstance(stable, Mapping)
        else ""
    )
    parts = owner.split("/")
    if (
        len(parts) != 6
        or parts[-1] != "preverify_successors"
        or not run_id
    ):
        raise PreverifyProjectionAuthorityError(
            "active preverify routing capability owner/run is malformed"
        )
    routing_key = "/".join((*parts[:-1], "routing"))
    return resolve_current_preverify_projection(
        root,
        expected_run_id=run_id,
        expected_consumer_work_unit_key=routing_key,
        require_frozen=require_frozen,
    )


def inspect_current_preverify_projection(
    scratchpad: Path,
    *,
    require_frozen: bool = True,
) -> dict[str, Any]:
    """Inspect a projection without granting it runtime proof authority."""

    return _resolve_current_preverify_projection(
        scratchpad,
        require_frozen=require_frozen,
        allow_unbound_introspection=True,
    )


__all__ = [
    "inspect_current_preverify_projection",
    "PreverifyProjectionAuthorityError",
    "resolve_active_preverify_projection",
    "resolve_current_preverify_projection",
    "resolve_exact_frozen_capture_authority",
    "successor_projection_present",
    "validate_frozen_projection_receipt",
]
