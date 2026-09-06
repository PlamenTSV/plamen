"""Typed phase I/O substrate for the staged P0-AE migration.

This module is deliberately independent of the driver and validators.  It
models exact semantic artifact identities and resolved work units; callers may
adapt the legacy ``Phase``/manifest structures into these records without
creating another implicit filename authority here.

The first resolver table covers only the live-reproduced P0-AE boundaries.
Unknown phases require explicit exact outputs and therefore cannot silently
fall back to a glob.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import PurePosixPath
import re
import threading
from typing import Any, Iterable, Mapping
import unicodedata
import weakref


ARTIFACT_CLASSES = frozenset({
    "REQUIRED",
    "OPTIONAL",
    "CONDITIONAL",
    "DRIVER_GENERATED",
})
WRITERS = frozenset({"MODEL", "DRIVER"})
WRITE_MODES = frozenset({"CREATE", "REPLACE", "APPEND", "MERGE"})
CONDITIONAL_STATES = frozenset({
    "NOT_TRIGGERED",
    "TRIGGERED_EMPTY",
    "PRODUCED",
    "FAILED",
})
ROOTS = frozenset({"scratchpad", "project"})
LAUNCH_PROFILES = frozenset({"DRIVER_PYTHON_NO_TOOLS"})

_COMPONENT_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]*$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_FORBIDDEN_PATH_CHARS = frozenset('*?[\\<>:"|]')
_WIN_RESERVED_DEVICE_STEMS = frozenset({
    "con",
    "prn",
    "aux",
    "nul",
    "clock$",
    "conin$",
    "conout$",
    *(f"com{ordinal}" for ordinal in range(1, 10)),
    *(f"lpt{ordinal}" for ordinal in range(1, 10)),
    "com¹",
    "com²",
    "com³",
    "lpt¹",
    "lpt²",
    "lpt³",
})
_PROGRAM_FACTS_LAUNCH_TIMEOUT_S = 30

_OBJECT_AUTHORITY_LOCK = threading.RLock()
_OBJECT_AUTHORITIES: dict[
    int, tuple[weakref.ReferenceType[object], str, str]
] = {}


def _stable_digest(payload: object) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _object_authority_digest(kind: str, payload: object) -> str:
    return _stable_digest({
        "authority_kind": kind,
        "payload": payload,
    })


def _issue_object_authority(
    value: object,
    *,
    kind: str,
    payload: object,
) -> None:
    """Seal one exact typed authority outside its mutable object slots."""

    key = id(value)

    def _cleanup(reference: weakref.ReferenceType[object]) -> None:
        with _OBJECT_AUTHORITY_LOCK:
            current = _OBJECT_AUTHORITIES.get(key)
            if current is not None and current[0] is reference:
                _OBJECT_AUTHORITIES.pop(key, None)

    reference = weakref.ref(value, _cleanup)
    digest = _object_authority_digest(kind, payload)
    with _OBJECT_AUTHORITY_LOCK:
        _OBJECT_AUTHORITIES[key] = (reference, kind, digest)


def _require_object_authority(
    value: object,
    *,
    exact_type: type[object],
    kind: str,
    payload: object,
) -> None:
    if type(value) is not exact_type:
        raise ValueError(
            f"{kind} authority requires the exact {exact_type.__name__} type"
        )
    with _OBJECT_AUTHORITY_LOCK:
        authority = _OBJECT_AUTHORITIES.get(id(value))
    if (
        authority is None
        or authority[0]() is not value
        or authority[1] != kind
        or authority[2] != _object_authority_digest(kind, payload)
    ):
        raise ValueError(
            f"{kind} authority seal is absent or the object was mutated"
        )


def _canonical_component(value: str, field_name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    normalized = value.strip().lower()
    if not _COMPONENT_RE.fullmatch(normalized):
        raise ValueError(
            f"{field_name} must match {_COMPONENT_RE.pattern}: {value!r}"
        )
    return normalized


def _canonical_relative_path(path: str) -> str:
    if not isinstance(path, str) or not path:
        raise ValueError("artifact path must be a non-empty string")
    if path != path.strip():
        raise ValueError("artifact path cannot contain leading/trailing whitespace")
    if any(char in path for char in _FORBIDDEN_PATH_CHARS):
        raise ValueError(f"artifact path is not cross-platform exact: {path!r}")
    if re.match(r"^[A-Za-z]:", path) or path.startswith("/"):
        raise ValueError(f"artifact path must be relative: {path!r}")
    candidate = PurePosixPath(path)
    # Classify traversal before Windows-equivalence checks.  ``..`` also
    # consists entirely of trailing dots, but traversal is the primary
    # contract violation and callers rely on that stable fail-closed reason.
    if (
        candidate.is_absolute()
        or any(part in {"", ".", ".."} for part in candidate.parts)
    ):
        raise ValueError(f"artifact path must be normalized and traversal-free: {path!r}")
    if any(part.rstrip(" .") != part for part in candidate.parts):
        raise ValueError(
            "artifact path contains a Windows-equivalent trailing dot/space "
            f"alias: {path!r}"
        )
    if any(
        part.split(".", 1)[0].rstrip(" ").casefold()
        in _WIN_RESERVED_DEVICE_STEMS
        for part in candidate.parts
    ):
        raise ValueError(
            "artifact path contains a Windows reserved device component: "
            f"{path!r}"
        )
    normalized = candidate.as_posix()
    if normalized != path or "//" in path:
        raise ValueError(f"artifact path must already be canonical POSIX: {path!r}")
    return normalized


def canonical_artifact_identity(root: str, path: str) -> str:
    normalized_root = str(root or "").strip().lower()
    if normalized_root not in ROOTS:
        raise ValueError(f"artifact root must be one of {sorted(ROOTS)}")
    return f"{normalized_root}:{_canonical_relative_path(path)}"


def _validate_artifact_identity(identity: str) -> str:
    if not isinstance(identity, str) or ":" not in identity:
        raise ValueError(f"invalid artifact identity: {identity!r}")
    root, path = identity.split(":", 1)
    canonical = canonical_artifact_identity(root, path)
    if canonical != identity:
        raise ValueError(f"artifact identity is not canonical: {identity!r}")
    return canonical


def canonical_work_unit_key(
    pipeline: str,
    mode: str,
    ecosystem: str,
    backend: str,
    phase: str,
    work_unit_id: str,
) -> str:
    components = (
        _canonical_component(pipeline, "pipeline"),
        _canonical_component(mode, "mode"),
        _canonical_component(ecosystem, "ecosystem"),
        _canonical_component(backend, "backend"),
        _canonical_component(phase, "phase"),
        _canonical_component(work_unit_id, "work_unit_id"),
    )
    return "/".join(components)


_REGISTERED_PROJECTION_HANDOFFS = frozenset({
    (
        "report_floor/assurance_projection",
        "report_floor/disposition_authority",
        "project:AUDIT_REPORT.md",
    ),
    (
        "report_floor/disposition_authority",
        "report_floor/assurance_projection",
        "project:AUDIT_REPORT.md",
    ),
    (
        "inventory/canonical_aggregate",
        "inventory/additive_reemit",
        "scratchpad:findings_inventory.md",
    ),
    (
        "inventory/canonical_aggregate",
        "inventory/additive_reemit",
        "scratchpad:finding_records.json",
    ),
    (
        "inventory/id_ledger_merge",
        "inventory/additive_reemit",
        "scratchpad:_id_ledger.json",
    ),
    (
        "invariants/worker.semantic_invariants",
        "invariants/semantic_invariants.fallback",
        "scratchpad:semantic_invariants.md",
    ),
    *(
        (
            predecessor,
            "semantic_dedup/prequeue_apply",
            f"scratchpad:{artifact}",
        )
        for predecessor in (
            "inventory/canonical_aggregate",
            "inventory/additive_reemit",
            "enumgap_delivery/inventory_append",
            "axis_disposition/promotion",
            "semantic_dedup/prequeue_apply",
        )
        for artifact in (
            "findings_inventory.md",
            *(
                ("finding_records.json",)
                if predecessor
                in {
                    "inventory/canonical_aggregate",
                    "inventory/additive_reemit",
                    "semantic_dedup/prequeue_apply",
                }
                else ()
            ),
        )
    ),
    *(
        (
            predecessor,
            "axis_disposition/promotion",
            "scratchpad:findings_inventory.md",
        )
        for predecessor in (
            "inventory/canonical_aggregate",
            "inventory/additive_reemit",
            "enumgap_delivery/inventory_append",
            "axis_disposition/promotion",
        )
    ),
    *(
        (
            f"exploration_clear/{predecessor}",
            "exploration_clear/repair_reconcile",
            f"scratchpad:{artifact}",
        )
        for predecessor in ("initial_compile.repair",)
        for artifact in (
            "exploration_clear_receipt.json",
            "exploration_clear_obligations.json",
        )
    ),
    (
        "invariants/semantic_invariants.post",
        "depth/semantic_invariants.independent_application",
        "scratchpad:semantic_invariant_application_receipt.json",
    ),
    (
        "invariants/semantic_invariants.post",
        "depth/semantic_invariants.independent_application",
        "scratchpad:semantic_invariant_coverage_gaps.md",
    ),
    (
        "depth/security_obligations.pre_depth",
        "depth/security_obligations.post_depth",
        "scratchpad:security_feature_facts.json",
    ),
    (
        "depth/security_obligations.pre_depth",
        "depth/security_obligations.post_depth",
        "scratchpad:security_obligation_authority.json",
    ),
    (
        "depth/security_obligations.pre_depth",
        "depth/security_obligations.post_depth",
        "scratchpad:security_obligations.md",
    ),
    (
        "report_index/model",
        "report_index/mechanical",
        "scratchpad:report_index.md",
    ),
    (
        "report_index/model",
        "report_index/mechanical",
        "scratchpad:report_coverage.md",
    ),
    (
        "report_index/model",
        "report_index/summary_parity",
        "scratchpad:report_index.md",
    ),
    (
        "report_index/model",
        "report_index/summary_parity",
        "scratchpad:report_coverage.md",
    ),
    (
        "report_index/model",
        "report_index/summary_parity",
        "scratchpad:report_records.json",
    ),
    (
        "report_index/model",
        "report_index/model",
        "scratchpad:report_index.md",
    ),
    (
        "report_index/model",
        "report_index/model",
        "scratchpad:report_coverage.md",
    ),
    (
        "report_index/model",
        "report_index/model",
        "scratchpad:report_records.json",
    ),
    (
        "report_index/summary_parity",
        "report_index/model",
        "scratchpad:report_index.md",
    ),
    (
        "report_index/summary_parity",
        "report_index/model",
        "scratchpad:report_coverage.md",
    ),
    (
        "report_index/summary_parity",
        "report_index/model",
        "scratchpad:report_records.json",
    ),
    *(
        (
            predecessor,
            "report_index/canonicalize",
            f"scratchpad:{artifact}",
        )
        for predecessor in (
            "report_index/model",
            "report_index/mechanical",
            "report_index/summary_parity",
        )
        for artifact in (
            "report_index.md",
            "report_coverage.md",
            "report_records.json",
        )
    ),
    *(
        (
            "report_index/canonicalize",
            "report_index/canonicalize",
            f"scratchpad:{artifact}",
        )
        for artifact in (
            "report_index.md",
            "report_coverage.md",
            "report_records.json",
            "report_index_status_projection.json",
            "_severity_override_ledger.json",
            "severity_overrides.md",
            "report_dropout_retention.json",
            "report_semantic_report_dropouts.md",
            "report_index_canonicalization_journal.json",
        )
    ),
    *(
        (
            "report_index/canonicalize",
            "report_index/model",
            f"scratchpad:{artifact}",
        )
        for artifact in (
            "report_index.md",
            "report_coverage.md",
            "report_records.json",
        )
    ),
    (
        "startup/trust_evidence_initial",
        "severity_adjudication_shadow/trust_evidence_reconcile",
        "scratchpad:trust_evidence_authority.json",
    ),
    (
        "startup/trust_evidence_initial",
        "severity_adjudication_shadow/trust_evidence_reconcile",
        "scratchpad:trust_evidence_provider_receipt.json",
    ),
    (
        "report_assemble/assembly",
        "report_floor/assurance_projection",
        "project:AUDIT_REPORT.md",
    ),
    (
        "report_assemble/source_capture",
        "report_assemble/tier_capture",
        "scratchpad:report_assembly_source_capture.json",
    ),
    (
        "report_assemble/source_capture",
        "report_assemble/appendix_projection",
        "scratchpad:report_assembly_source_capture.json",
    ),
    (
        "report_assemble/source_capture",
        "report_assemble/final_capture",
        "scratchpad:report_assembly_source_capture.json",
    ),
    (
        "report_assemble/final_capture",
        "report_assemble/assembly",
        "scratchpad:report_assembly_final_capture.json",
    ),
    (
        "report_floor/assurance_projection",
        "report_assemble/assembly",
        "project:AUDIT_REPORT.md",
    ),
    (
        "chain/scaffold",
        "chain/state_resolution_enabler_prefill",
        "scratchpad:enabler_results.md",
    ),
    (
        "chain/scaffold",
        "chain/model",
        "scratchpad:hypotheses.md",
    ),
    (
        "chain/scaffold",
        "chain/model",
        "scratchpad:finding_mapping.md",
    ),
    (
        "chain/state_resolution_enabler_prefill",
        "chain/model",
        "scratchpad:enabler_results.md",
    ),
    (
        "semantic_dedup/noop_proposal",
        "semantic_dedup/model",
        "scratchpad:dedup_decisions.md",
    ),
    (
        "semantic_dedup/model",
        "semantic_dedup/noop_proposal",
        "scratchpad:dedup_decisions.md",
    ),
    (
        "instantiate/model",
        "instantiate/model",
        "scratchpad:spawn_manifest_proposal.md",
    ),
    *(
        (
            "recon/prepass_fixture_prerequisite",
            "recon/canonical_merge",
            f"scratchpad:{artifact}",
        )
        for artifact in (
            "contract_inventory.md",
            "function_list.md",
            "state_variables.md",
        )
    ),
    *(
        (
            "recon/prepass",
            "recon/canonical_merge",
            f"scratchpad:{artifact}",
        )
        for artifact in (
            # SC prepass -> canonical merge projections.
            "contract_inventory.md",
            "state_variables.md",
            "function_list.md",
            "build_status.md",
            "design_context.md",
            "attack_surface.md",
            "detected_patterns.md",
            "setter_list.md",
            "emit_list.md",
            "template_recommendations.md",
            "recon_summary.md",
            # L1-only prepass -> canonical merge projections.
            "subsystem_map.md",
            "trust_boundaries.md",
            "threat_model.md",
        )
    ),
    (
        "recon/prepass",
        "recon/dependency_reconcile",
        "scratchpad:external_dependency_research.md",
    ),
    (
        "recon/dependency_reconcile.source_capture",
        "recon/dependency_reconcile.source_capture.active_research",
        "scratchpad:dependency_reconcile_preexecution_authority.json",
    ),
    *(
        (
            "recon/dependency_reconcile",
            "recon/dependency_reconcile.active_research",
            f"scratchpad:{artifact}",
        )
        for artifact in (
            "external_dependency_research.md",
            "report_semantic_dependency_research.md",
        )
    ),
    *(
        (
            "instantiate/manifest_reconcile",
            "instantiate/manifest_reconcile",
            f"scratchpad:{artifact}",
        )
        for artifact in (
            "spawn_manifest.md",
            "instantiate_manifest_reconcile_receipt.json",
        )
    ),
})


def registered_projection_handoff(
    predecessor_key: str,
    successor_key: str,
    identity: str,
) -> bool:
    """Return true only for an exact resolver-declared projection lineage."""

    predecessor = _validate_work_unit_key(predecessor_key)
    successor = _validate_work_unit_key(successor_key)
    artifact = _validate_artifact_identity(identity)
    prior_parts = predecessor.split("/")
    next_parts = successor.split("/")
    predecessor_relative = "/".join(prior_parts[4:])
    successor_relative = "/".join(next_parts[4:])
    prepass_attempt_re = re.compile(r"recon/prepass\.attempt-(\d{4})")
    predecessor_attempt = prepass_attempt_re.fullmatch(
        predecessor_relative
    )
    successor_attempt = prepass_attempt_re.fullmatch(successor_relative)
    if successor_attempt is not None:
        successor_ordinal = int(successor_attempt.group(1))
        predecessor_ordinal = (
            int(predecessor_attempt.group(1))
            if predecessor_attempt is not None
            else (1 if predecessor_relative == "recon/prepass" else 0)
        )
        try:
            successor_contract = resolve_phase_io_contract(
                pipeline=next_parts[0],
                mode=next_parts[1],
                ecosystem=next_parts[2],
                backend=next_parts[3],
                phase="recon",
                work_unit_id=next_parts[-1],
            )
        except (TypeError, ValueError):
            return False
        if (
            prior_parts[:4] == next_parts[:4]
            and successor_ordinal >= 2
            and predecessor_ordinal == successor_ordinal - 1
            and artifact in {
                output.identity for output in successor_contract.outputs
            }
        ):
            return True
    if (
        predecessor_attempt is not None
        and int(predecessor_attempt.group(1)) >= 2
    ):
        # A committed prepass retry is the same narrowly registered semantic
        # producer for the two existing downstream handoffs.  Normalizing only
        # the predecessor role preserves every backend/dimension check below.
        predecessor_relative = "recon/prepass"
    if (
        predecessor_relative == "recon/prepass_fixture_prerequisite"
        and successor_relative == "recon/canonical_merge"
        and artifact
        in {
            "scratchpad:contract_inventory.md",
            "scratchpad:function_list.md",
            "scratchpad:state_variables.md",
        }
    ):
        # The deterministic prepass producer is deliberately backend-neutral:
        # its fixture/runtime authority is registered once, while the canonical
        # merge consumer is resolved for the selected pipeline/mode/backend.
        # Keep this exception bounded to its exact three canonical projections.
        return True
    if (
        prior_parts[:3] == next_parts[:3]
        and prior_parts[3] in {"claude", "codex"}
        and next_parts[3] == "backend-neutral"
        and predecessor_relative == "recon/prepass"
        and successor_relative == "recon/dependency_reconcile"
        and artifact == "scratchpad:external_dependency_research.md"
    ):
        # The provider-selected deterministic prepass owns the initial
        # dependency-research placeholder, while dependency reconciliation is
        # deliberately provider-neutral.  This is one exact DRIVER->DRIVER
        # projection; rejecting it solely because component four changes from
        # the selected provider to backend-neutral makes every real audit fail
        # even though same-backend fixtures pass.
        return True
    if prior_parts[:4] != next_parts[:4]:
        return False
    inventory_retry_pattern = re.compile(
        r"inventory_chunk_([abc])/model\.attempt(\d{4})"
    )
    prior_inventory_attempt = inventory_retry_pattern.fullmatch(
        predecessor_relative
    )
    next_inventory_attempt = inventory_retry_pattern.fullmatch(
        successor_relative
    )
    if prior_inventory_attempt and next_inventory_attempt:
        # Inventory shard retries are immutable MODEL generations.  A rejected
        # generation is physically quarantined before the next one is armed,
        # but its typed artifact binding deliberately remains as provenance.
        # Register only the exact same-shard N -> N+1 output transition; without
        # this narrow lineage the general owner-conflict guard mistakes the
        # retry for an unrelated producer and quarantines a valid CAS commit.
        if (
            prior_inventory_attempt.group(1)
            == next_inventory_attempt.group(1)
            and int(next_inventory_attempt.group(2))
            == int(prior_inventory_attempt.group(2)) + 1
        ):
            shard = next_inventory_attempt.group(1)
            return artifact == (
                f"scratchpad:findings_inventory_chunk_{shard}.md"
            )
        return False
    # MODEL retries retain immutable attempt work-unit identities.  The
    # deterministic Summary successor is registered against the semantic model
    # role, not against one hard-coded attempt ordinal.
    for role in ("model", "summary_parity", "canonicalize"):
        retry_pattern = rf"report_index/{role}\.attempt-\d{{4}}"
        if re.fullmatch(retry_pattern, predecessor_relative):
            predecessor_relative = f"report_index/{role}"
        successor_relative = "/".join(next_parts[4:])
        if re.fullmatch(retry_pattern, successor_relative):
            next_parts[-1] = role
            successor_relative = f"report_index/{role}"
    # Instantiate retries are explicit semantic replacements of the preceding
    # attempt's proposal/canonical generation, never anonymous overwrites.
    # Normalize only these two exact work-unit roles; all other phase attempts
    # retain the default owner-conflict fail-closed behavior.
    for role in ("model", "manifest_reconcile"):
        retry_pattern = rf"instantiate/{role}\.attempt-\d{{4}}"
        if re.fullmatch(retry_pattern, predecessor_relative):
            predecessor_relative = f"instantiate/{role}"
        if re.fullmatch(retry_pattern, successor_relative):
            successor_relative = f"instantiate/{role}"
    if (
        predecessor_relative == "chain/model"
        and re.fullmatch(
            r"chain/final_pair_auto_map_apply\.[0-9a-f]{64}",
            successor_relative,
        )
        and artifact in {
            "scratchpad:hypotheses.md",
            "scratchpad:finding_mapping.md",
            "scratchpad:enabler_results.md",
        }
    ):
        return True
    if (
        re.fullmatch(
            r"semantic_identity/projection\.[a-z0-9_.-]+",
            predecessor_relative,
        )
        and re.fullmatch(
            r"semantic_identity/projection\.[a-z0-9_.-]+",
            successor_relative,
        )
        and artifact in {
            "scratchpad:_canonical_finding_ids.json",
            "scratchpad:_unmapped_id_tokens.json",
        }
    ):
        # Canonical identity is a deterministic projection refreshed at
        # several finding-producing boundaries.  The changing work-unit
        # suffix records which source phase froze the current denominator;
        # it must form an explicit DRIVER->DRIVER lineage instead of looking
        # like an anonymous REPLACE of the preceding projection.
        return True
    if (
        predecessor_relative == "report_body/evidence_pre"
        and successor_relative == "report_body/evidence_repair.apply"
        and (
            artifact
            in {
                "scratchpad:report_evidence_records.json",
                "scratchpad:report_evidence_repair_request.json",
                "scratchpad:report_evidence_projection.md",
            }
            or re.fullmatch(
                r"scratchpad:report_evidence_manifests/"
                r"report_[a-z_]+\.json",
                artifact,
            )
        )
    ):
        # The bounded semantic repair is an exact DRIVER successor of the
        # baseline typed evidence bundle. Its response may add missing report
        # fields, but it cannot replace or detach the candidate denominator.
        return True
    next_rearm = re.fullmatch(
        r"chain_iter2/tail_rearm_control\.p(\d{4})\.s(\d{4})",
        successor_relative,
    )
    prior_reconcile = re.fullmatch(
        r"chain_iter2/tail_reconcile\.p(\d{4})\.s(\d{4})",
        predecessor_relative,
    )
    next_reconcile = re.fullmatch(
        r"chain_iter2/tail_reconcile\.p(\d{4})\.s(\d{4})",
        successor_relative,
    )
    prior_snapshot = re.fullmatch(
        r"chain_iter2/tail_snapshot\.p(\d{4})\.s(\d{4})",
        predecessor_relative,
    )
    next_snapshot = re.fullmatch(
        r"chain_iter2/tail_snapshot\.p(\d{4})\.s(\d{4})",
        successor_relative,
    )
    prior_merge = re.fullmatch(
        r"chain_iter2/driver_merge\.p(\d{4})\.s(\d{4})",
        predecessor_relative,
    )
    next_merge = re.fullmatch(
        r"chain_iter2/driver_merge\.p(\d{4})\.s(\d{4})",
        successor_relative,
    )
    if (
        artifact == "scratchpad:chain_tail_terminal_snapshot.json"
        and prior_snapshot
        and next_snapshot
    ):
        return (
            int(prior_snapshot.group(1)),
            int(prior_snapshot.group(2)),
        ) < (
            int(next_snapshot.group(1)),
            int(next_snapshot.group(2)),
        )
    if (
        artifact == "scratchpad:chain_tail_terminal_snapshot.json"
        and prior_snapshot
        and next_reconcile
    ):
        return (
            prior_snapshot.group(1),
            prior_snapshot.group(2),
        ) == (
            next_reconcile.group(1),
            next_reconcile.group(2),
        )
    if (
        artifact == "scratchpad:chain_iteration2.md"
        and prior_reconcile
        and next_merge
    ):
        return (
            prior_reconcile.group(1),
            prior_reconcile.group(2),
        ) == (
            next_merge.group(1),
            next_merge.group(2),
        )
    if (
        artifact
        in {
            "scratchpad:chain_hypotheses.md",
            "scratchpad:composition_coverage.md",
        }
        and predecessor_relative == "chain_agent2/model"
        and next_merge
    ):
        # The first merge may legitimately occur after one or more terminal
        # rearms. This registry establishes only typed lineage; runtime binds
        # current exact G and proves both siblings share this MODEL owner.
        return True
    if (
        artifact
        in {
            "scratchpad:chain_hypotheses.md",
            "scratchpad:composition_coverage.md",
        }
        and prior_merge
        and next_merge
    ):
        return (
            int(prior_merge.group(1)),
            int(prior_merge.group(2)),
        ) < (
            int(next_merge.group(1)),
            int(next_merge.group(2)),
        )
    chain_final_root_identities = {
        f"scratchpad:{path}"
        for path in _CHAIN_TAIL_FINAL_ROOT_OUTPUTS
    }
    initial_chain_tail_root_identities = {
        "scratchpad:chain_tail_disposition_ledger.json",
        "scratchpad:chain_tail_coverage_receipt.json",
        "scratchpad:chain_composition_verification_candidates.json",
        "scratchpad:chain_composition_coverage_gaps.md",
    }
    if (
        artifact in initial_chain_tail_root_identities
        and predecessor_relative == "chain/state_resolution"
        and next_reconcile
    ):
        return int(next_reconcile.group(1)) == 0
    if (
        artifact in chain_final_root_identities
        and prior_reconcile
        and next_rearm
    ):
        # A rearm consumes the frozen root publication to derive one exact
        # control-only successor.  This registered consumer handoff does not
        # transfer root ownership: the successor output intersection remains
        # the five mutable control siblings.
        return bool(
            int(next_rearm.group(1)) == int(prior_reconcile.group(1)) + 1
            and next_rearm.group(2) == prior_reconcile.group(2)
        )
    if (
        artifact in chain_final_root_identities
        and prior_reconcile
        and next_reconcile
    ):
        return (
            int(prior_reconcile.group(1)),
            int(prior_reconcile.group(2)),
        ) < (
            int(next_reconcile.group(1)),
            int(next_reconcile.group(2)),
        )
    chain_control_identities = {
        f"scratchpad:{path}"
        for path in _CHAIN_TAIL_MUTABLE_CONTROL_OUTPUTS
    }
    if artifact in chain_control_identities:
        next_budget_stop = re.fullmatch(
            r"chain_iter2/tail_budget_stop\.p(\d{4})\.s(\d{4})",
            successor_relative,
        )
        prior_rearm = re.fullmatch(
            r"chain_iter2/tail_rearm_control\.p(\d{4})\.s(\d{4})",
            predecessor_relative,
        )
        if next_reconcile:
            next_pass = int(next_reconcile.group(1))
            next_shards = int(next_reconcile.group(2))
            if predecessor_relative in {
                "chain/tail_control_init",
                "chain_iter2/tail_primary_control",
            }:
                return next_pass == 0 and next_shards == 0
            prior_terminal_for_reconcile = re.fullmatch(
                r"chain_iter2/tail_shard_"
                r"(?:disposition|failure)_control\.(\d{4})",
                predecessor_relative,
            )
            if prior_terminal_for_reconcile:
                return next_shards == (
                    int(prior_terminal_for_reconcile.group(1)) + 1
                )
            prior_budget_stop = re.fullmatch(
                r"chain_iter2/tail_budget_stop\.p(\d{4})\.s(\d{4})",
                predecessor_relative,
            )
            if prior_budget_stop:
                return (
                    prior_budget_stop.group(1) == next_reconcile.group(1)
                    and prior_budget_stop.group(2) == next_reconcile.group(2)
                )
        if prior_reconcile and next_rearm:
            return bool(
                int(next_rearm.group(1))
                == int(prior_reconcile.group(1)) + 1
                and next_rearm.group(2) == prior_reconcile.group(2)
            )
        if prior_rearm:
            next_prepare_after_rearm = re.fullmatch(
                r"chain_iter2/tail_shard_prepare_control\.(\d{4})",
                successor_relative,
            )
            return bool(
                next_prepare_after_rearm
                and int(next_prepare_after_rearm.group(1))
                == int(prior_rearm.group(2))
            )
        if predecessor_relative == "chain/tail_control_init":
            return bool(
                successor_relative == "chain_iter2/tail_primary_control"
                or successor_relative
                == "chain_iter2/tail_shard_prepare_control.0000"
            )
        if predecessor_relative == "chain_iter2/tail_primary_control":
            return bool(
                successor_relative
                == "chain_iter2/tail_shard_prepare_control.0000"
                or (
                    next_budget_stop
                    and next_budget_stop.group(1) == "0000"
                    and next_budget_stop.group(2) == "0000"
                )
            )
        prior_prepare = re.fullmatch(
            r"chain_iter2/tail_shard_prepare_control\.(\d{4})",
            predecessor_relative,
        )
        next_terminal = re.fullmatch(
            r"chain_iter2/tail_shard_(?:disposition|failure)_control\.(\d{4})",
            successor_relative,
        )
        if prior_prepare and next_terminal:
            return prior_prepare.group(1) == next_terminal.group(1)
        prior_terminal = re.fullmatch(
            r"chain_iter2/tail_shard_(?:disposition|failure)_control\.(\d{4})",
            predecessor_relative,
        )
        next_prepare = re.fullmatch(
            r"chain_iter2/tail_shard_prepare_control\.(\d{4})",
            successor_relative,
        )
        if prior_terminal and next_prepare:
            return int(next_prepare.group(1)) == int(prior_terminal.group(1)) + 1
        if prior_terminal and next_budget_stop:
            return int(next_budget_stop.group(2)) == (
                int(prior_terminal.group(1)) + 1
            )
    if (
        predecessor_relative == "chain/tail_control_init"
        and successor_relative
        == "chain_iter2/tail_shard_prepare_artifacts.0000"
        and artifact == "scratchpad:_chain_tail_shards/shard_0000.input.md"
    ):
        return True
    return (
        predecessor_relative,
        successor_relative,
        artifact,
    ) in _REGISTERED_PROJECTION_HANDOFFS


def _validate_work_unit_key(key: str) -> str:
    if not isinstance(key, str):
        raise ValueError("work-unit key must be a string")
    parts = key.split("/")
    if len(parts) != 6:
        raise ValueError(f"work-unit key must have six components: {key!r}")
    canonical = canonical_work_unit_key(*parts)
    if canonical != key:
        raise ValueError(f"work-unit key is not canonical: {key!r}")
    return canonical


def _normalized_strings(values: Iterable[str], field_name: str) -> tuple[str, ...]:
    result: set[str] = set()
    for value in values:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field_name} must contain non-empty strings")
        result.add(value.strip())
    return tuple(sorted(result))


@dataclass(frozen=True)
class ArtifactSpec:
    """One exact output in a resolved work-unit contract."""

    root: str
    path: str
    owner_key: str
    artifact_class: str
    writer: str
    write_mode: str
    schema_version: str = "unstructured.v1"
    minimum_gate: str = "PRESENCE"
    consumers: tuple[str, ...] = ()
    condition_id: str = ""
    external_preimage_validator: str = ""

    def __post_init__(self) -> None:
        root = str(self.root or "").strip().lower()
        if root not in ROOTS:
            raise ValueError(f"root must be one of {sorted(ROOTS)}")
        path = _canonical_relative_path(self.path)
        owner = _validate_work_unit_key(self.owner_key)
        artifact_class = str(self.artifact_class or "").strip().upper()
        writer = str(self.writer or "").strip().upper()
        write_mode = str(self.write_mode or "").strip().upper()
        if artifact_class not in ARTIFACT_CLASSES:
            raise ValueError(
                f"artifact_class must be one of {sorted(ARTIFACT_CLASSES)}"
            )
        if writer not in WRITERS:
            raise ValueError(f"writer must be one of {sorted(WRITERS)}")
        if write_mode not in WRITE_MODES:
            raise ValueError(
                f"write_mode must be one of {sorted(WRITE_MODES)}"
            )
        if write_mode == "MERGE" and writer != "DRIVER":
            raise ValueError("MERGE outputs must be driver-owned")
        external_validator = str(
            self.external_preimage_validator or ""
        ).strip()
        if external_validator and (
            writer != "DRIVER" or write_mode != "MERGE"
        ):
            raise ValueError(
                "external_preimage_validator is valid only for DRIVER/MERGE"
            )
        if artifact_class == "DRIVER_GENERATED" and writer != "DRIVER":
            raise ValueError("DRIVER_GENERATED outputs must use writer=DRIVER")
        condition_id = str(self.condition_id or "").strip()
        if artifact_class == "CONDITIONAL" and not condition_id:
            raise ValueError("CONDITIONAL outputs require condition_id")
        if artifact_class != "CONDITIONAL" and condition_id:
            raise ValueError("condition_id is valid only for CONDITIONAL outputs")
        if not isinstance(self.schema_version, str) or not self.schema_version.strip():
            raise ValueError("schema_version must be a non-empty string")
        if not isinstance(self.minimum_gate, str) or not self.minimum_gate.strip():
            raise ValueError("minimum_gate must be a non-empty string")
        object.__setattr__(self, "root", root)
        object.__setattr__(self, "path", path)
        object.__setattr__(self, "owner_key", owner)
        object.__setattr__(self, "artifact_class", artifact_class)
        object.__setattr__(self, "writer", writer)
        object.__setattr__(self, "write_mode", write_mode)
        object.__setattr__(self, "schema_version", self.schema_version.strip())
        object.__setattr__(self, "minimum_gate", self.minimum_gate.strip())
        object.__setattr__(
            self, "consumers", _normalized_strings(self.consumers, "consumers")
        )
        object.__setattr__(self, "condition_id", condition_id)
        object.__setattr__(
            self, "external_preimage_validator", external_validator
        )

    @property
    def identity(self) -> str:
        return canonical_artifact_identity(self.root, self.path)

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "identity": self.identity,
            "owner_key": self.owner_key,
            "artifact_class": self.artifact_class,
            "writer": self.writer,
            "write_mode": self.write_mode,
            "schema_version": self.schema_version,
            "minimum_gate": self.minimum_gate,
            "consumers": list(self.consumers),
            "condition_id": self.condition_id,
        }
        if self.external_preimage_validator:
            payload["external_preimage_validator"] = (
                self.external_preimage_validator
            )
        return payload


@dataclass(frozen=True)
class WriteObservation:
    root: str
    path: str
    existed_before: bool
    exists_after: bool
    prefix_preserved: bool | None = None

    def __post_init__(self) -> None:
        identity = canonical_artifact_identity(self.root, self.path)
        root, path = identity.split(":", 1)
        if not isinstance(self.existed_before, bool) or not isinstance(
            self.exists_after, bool
        ):
            raise ValueError("write observation existence flags must be booleans")
        if self.prefix_preserved not in {True, False, None}:
            raise ValueError("prefix_preserved must be true, false, or null")
        object.__setattr__(self, "root", root)
        object.__setattr__(self, "path", path)

    @property
    def identity(self) -> str:
        return canonical_artifact_identity(self.root, self.path)

    @classmethod
    def created(cls, root: str, path: str) -> "WriteObservation":
        return cls(root, path, False, True)

    @classmethod
    def changed(
        cls, root: str, path: str, *, prefix_preserved: bool | None = None
    ) -> "WriteObservation":
        return cls(root, path, True, True, prefix_preserved)

    @classmethod
    def deleted(cls, root: str, path: str) -> "WriteObservation":
        return cls(root, path, True, False)


@dataclass(frozen=True)
class ContractViolation:
    code: str
    identity: str
    detail: str


@dataclass(frozen=True)
class ContainmentResult:
    allowed: tuple[str, ...]
    violations: tuple[ContractViolation, ...]

    @property
    def ok(self) -> bool:
        return not self.violations


@dataclass(frozen=True)
class InputAuthorityRequirement:
    """Closed provenance requirement for one exact semantic input.

    ``allow_raw`` is an explicit import boundary, not the absence of policy.
    Producer-backed inputs can additionally pin one predecessor key and
    contract while requiring the ledger's exact current-run contract/launch
    tuple.  An empty expected producer key intentionally means that the
    concrete producer is dynamic, but it must still be a committed producer
    with the required writer.
    """

    identity: str
    allow_raw: bool = False
    expected_producer_work_unit_key: str = ""
    expected_writer: str = ""
    require_same_run: bool = True
    expected_contract_digest: str = ""
    expected_launch_digest: str = ""
    require_exact_contract: bool = True
    require_exact_launch: bool = True

    def __post_init__(self) -> None:
        identity = _validate_artifact_identity(self.identity)
        if not isinstance(self.allow_raw, bool):
            raise ValueError("allow_raw must be boolean")
        producer = str(self.expected_producer_work_unit_key or "").strip()
        if producer:
            producer = _validate_work_unit_key(producer)
        writer = str(self.expected_writer or "").strip().upper()
        if writer and writer not in WRITERS:
            raise ValueError(
                f"expected_writer must be one of {sorted(WRITERS)}"
            )
        if not isinstance(self.require_same_run, bool):
            raise ValueError("require_same_run must be boolean")
        contract_digest = str(
            self.expected_contract_digest or ""
        ).strip().lower()
        if contract_digest and not _SHA256_RE.fullmatch(contract_digest):
            raise ValueError(
                "expected_contract_digest must be lowercase SHA-256"
            )
        launch_digest = str(
            self.expected_launch_digest or ""
        ).strip().lower()
        if launch_digest and not _SHA256_RE.fullmatch(launch_digest):
            raise ValueError(
                "expected_launch_digest must be lowercase SHA-256"
            )
        if not isinstance(self.require_exact_contract, bool):
            raise ValueError("require_exact_contract must be boolean")
        if not isinstance(self.require_exact_launch, bool):
            raise ValueError("require_exact_launch must be boolean")
        if self.allow_raw and any(
            (
                producer,
                writer,
                contract_digest,
                launch_digest,
            )
        ):
            raise ValueError(
                "an explicit raw input boundary cannot also prescribe a "
                "producer"
            )
        if not self.allow_raw and not (producer or writer):
            raise ValueError(
                "producer-backed input authority requires an expected "
                "producer or writer"
            )
        object.__setattr__(self, "identity", identity)
        object.__setattr__(
            self, "expected_producer_work_unit_key", producer
        )
        object.__setattr__(self, "expected_writer", writer)
        object.__setattr__(
            self, "expected_contract_digest", contract_digest
        )
        object.__setattr__(
            self, "expected_launch_digest", launch_digest
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "identity": self.identity,
            "allow_raw": self.allow_raw,
            "expected_producer_work_unit_key": (
                self.expected_producer_work_unit_key
            ),
            "expected_writer": self.expected_writer,
            "require_same_run": self.require_same_run,
            "expected_contract_digest": self.expected_contract_digest,
            "expected_launch_digest": self.expected_launch_digest,
            "require_exact_contract": self.require_exact_contract,
            "require_exact_launch": self.require_exact_launch,
        }


@dataclass(frozen=True)
class PhaseIOContract:
    """Resolved, exact I/O contract for one producer or driver work unit."""

    pipeline: str
    mode: str
    ecosystem: str
    backend: str
    phase: str
    work_unit_id: str
    outputs: tuple[ArtifactSpec, ...]
    immutable_inputs: tuple[str, ...] = ()
    bounded_lookup_inputs: tuple[str, ...] = ()
    model_invoked: bool = True
    input_authority_requirements: tuple[
        InputAuthorityRequirement, ...
    ] = ()
    launch_profile: str = ""
    required_commit_actor: str = ""
    contract_version: str = "plamen.phase_io.v1"

    def __post_init__(self) -> None:
        pipeline = _canonical_component(self.pipeline, "pipeline")
        mode = _canonical_component(self.mode, "mode")
        ecosystem = _canonical_component(self.ecosystem, "ecosystem")
        backend = _canonical_component(self.backend, "backend")
        phase = _canonical_component(self.phase, "phase")
        work_unit = _canonical_component(self.work_unit_id, "work_unit_id")
        key = canonical_work_unit_key(
            pipeline, mode, ecosystem, backend, phase, work_unit
        )
        outputs = tuple(self.outputs)
        if not all(isinstance(item, ArtifactSpec) for item in outputs):
            raise ValueError("outputs must contain ArtifactSpec records")
        identities = [item.identity for item in outputs]
        if len(identities) != len(set(identities)):
            raise ValueError("contract contains duplicate output identities")
        if any(item.owner_key != key for item in outputs):
            raise ValueError("every output owner_key must equal the contract key")
        immutable = tuple(sorted({
            _validate_artifact_identity(item) for item in self.immutable_inputs
        }))
        bounded = tuple(sorted({
            _validate_artifact_identity(item) for item in self.bounded_lookup_inputs
        }))
        overlap = set(identities) & (set(immutable) | set(bounded))
        if overlap:
            raise ValueError(
                "outputs cannot also be semantic inputs without an explicit "
                "read-modify-write transaction: " + ", ".join(sorted(overlap))
            )
        if not isinstance(self.model_invoked, bool):
            raise ValueError("model_invoked must be boolean")
        requirements = tuple(self.input_authority_requirements)
        if not all(
            isinstance(item, InputAuthorityRequirement)
            for item in requirements
        ):
            raise ValueError(
                "input_authority_requirements must contain "
                "InputAuthorityRequirement records"
            )
        requirement_identities = [
            item.identity for item in requirements
        ]
        if len(requirement_identities) != len(
            set(requirement_identities)
        ):
            raise ValueError(
                "input authority requirement denominator contains duplicates"
            )
        semantic_inputs = set(immutable) | set(bounded)
        if requirements and set(requirement_identities) != semantic_inputs:
            raise ValueError(
                "input authority requirements must exactly cover the "
                "semantic input denominator"
            )
        alias_denominator = [
            *semantic_inputs,
            *(item.identity for item in outputs),
        ]
        for identity in alias_denominator:
            if unicodedata.normalize("NFC", identity) != identity:
                raise ValueError(
                    f"artifact identity must be NFC canonical: {identity!r}"
                )
        folded = [
            unicodedata.normalize("NFC", identity).casefold()
            for identity in alias_denominator
        ]
        if len(folded) != len(set(folded)):
            raise ValueError(
                "contract contains a casefold artifact identity alias"
            )
        launch_profile = str(self.launch_profile or "").strip().upper()
        if launch_profile and launch_profile not in LAUNCH_PROFILES:
            raise ValueError(
                f"launch_profile must be one of {sorted(LAUNCH_PROFILES)}"
            )
        if launch_profile and self.model_invoked:
            raise ValueError(
                "a model-invoked contract cannot use a model-free "
                "launch profile"
            )
        required_actor = str(
            self.required_commit_actor or ""
        ).strip().upper()
        if required_actor and required_actor not in WRITERS:
            raise ValueError(
                f"required_commit_actor must be one of {sorted(WRITERS)}"
            )
        if required_actor and required_actor not in {
            output.writer for output in outputs
        }:
            raise ValueError(
                "required_commit_actor does not own a contract output"
            )
        if not isinstance(self.contract_version, str) or not self.contract_version.strip():
            raise ValueError("contract_version must be non-empty")
        object.__setattr__(self, "pipeline", pipeline)
        object.__setattr__(self, "mode", mode)
        object.__setattr__(self, "ecosystem", ecosystem)
        object.__setattr__(self, "backend", backend)
        object.__setattr__(self, "phase", phase)
        object.__setattr__(self, "work_unit_id", work_unit)
        object.__setattr__(self, "outputs", outputs)
        object.__setattr__(self, "immutable_inputs", immutable)
        object.__setattr__(self, "bounded_lookup_inputs", bounded)
        object.__setattr__(
            self,
            "input_authority_requirements",
            tuple(sorted(requirements, key=lambda item: item.identity)),
        )
        object.__setattr__(self, "launch_profile", launch_profile)
        object.__setattr__(
            self, "required_commit_actor", required_actor
        )
        object.__setattr__(self, "contract_version", self.contract_version.strip())
        if type(self) is PhaseIOContract:
            _issue_object_authority(
                self,
                kind="phase_io_contract",
                payload=PhaseIOContract.to_dict(self),
            )

    @property
    def key(self) -> str:
        return canonical_work_unit_key(
            self.pipeline,
            self.mode,
            self.ecosystem,
            self.backend,
            self.phase,
            self.work_unit_id,
        )

    @property
    def digest(self) -> str:
        return _stable_digest(self.to_dict())

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "contract_version": self.contract_version,
            "key": self.key,
            "model_invoked": self.model_invoked,
            "outputs": [
                ArtifactSpec.to_dict(item) for item in sorted(
                    self.outputs, key=lambda output: output.identity
                )
            ],
            "immutable_inputs": list(self.immutable_inputs),
            "bounded_lookup_inputs": list(self.bounded_lookup_inputs),
        }
        if self.input_authority_requirements:
            payload["input_authority_requirements"] = [
                InputAuthorityRequirement.to_dict(item)
                for item in self.input_authority_requirements
            ]
        if self.launch_profile:
            payload["launch_profile"] = self.launch_profile
        if self.required_commit_actor:
            payload["required_commit_actor"] = self.required_commit_actor
        return payload

    def input_authority(
        self, identity: str,
    ) -> InputAuthorityRequirement:
        canonical = _validate_artifact_identity(identity)
        for requirement in self.input_authority_requirements:
            if requirement.identity == canonical:
                return requirement
        raise KeyError(canonical)

    def output(self, identity: str) -> ArtifactSpec:
        canonical = _validate_artifact_identity(identity)
        for artifact in self.outputs:
            if artifact.identity == canonical:
                return artifact
        raise KeyError(canonical)

    def validate_writes(
        self,
        observations: Iterable[WriteObservation],
        *,
        actor: str,
    ) -> ContainmentResult:
        """Classify an exact observed write set against this contract.

        Unlike future-pattern containment, every semantic write must be an
        exact output of the current work unit.  Operational driver logs and
        prompt snapshots belong to a separate supervisor contract and should
        not be mixed into the model observation set.
        """
        normalized_actor = str(actor or "").strip().upper()
        if normalized_actor not in WRITERS:
            raise ValueError(f"actor must be one of {sorted(WRITERS)}")
        output_map = {item.identity: item for item in self.outputs}
        immutable = set(self.immutable_inputs)
        allowed: set[str] = set()
        violations: list[ContractViolation] = []
        seen: set[str] = set()
        for observation in observations:
            if not isinstance(observation, WriteObservation):
                raise ValueError("observations must contain WriteObservation records")
            identity = observation.identity
            if identity in seen:
                violations.append(ContractViolation(
                    "DUPLICATE_OBSERVATION", identity,
                    "identity appeared more than once in the observed write set",
                ))
                continue
            seen.add(identity)
            if identity in immutable:
                violations.append(ContractViolation(
                    "IMMUTABLE_INPUT_WRITE", identity,
                    "work unit modified an immutable input",
                ))
                continue
            artifact = output_map.get(identity)
            if artifact is None:
                violations.append(ContractViolation(
                    "UNKNOWN_WRITE", identity,
                    "identity is absent from the exact current work-unit outputs",
                ))
                continue
            mode_violations: list[ContractViolation] = []
            if artifact.writer != normalized_actor:
                mode_violations.append(ContractViolation(
                    "WRITER_MISMATCH", identity,
                    f"contract writer is {artifact.writer}, observed actor is {normalized_actor}",
                ))
            if not observation.exists_after:
                mode_violations.append(ContractViolation(
                    "OUTPUT_DELETED", identity,
                    "contract outputs may not be deleted by their producer",
                ))
            elif artifact.write_mode == "CREATE" and observation.existed_before:
                mode_violations.append(ContractViolation(
                    "CREATE_OVER_EXISTING", identity,
                    "CREATE requires the artifact to be absent before the work unit",
                ))
            elif artifact.write_mode == "APPEND":
                if not observation.existed_before:
                    mode_violations.append(ContractViolation(
                        "APPEND_WITHOUT_BASE", identity,
                        "APPEND requires a pre-existing artifact",
                    ))
                elif observation.prefix_preserved is not True:
                    mode_violations.append(ContractViolation(
                        "APPEND_PREFIX_UNPROVEN", identity,
                        "APPEND requires byte-prefix preservation evidence",
                    ))
            if mode_violations:
                violations.extend(mode_violations)
            else:
                allowed.add(identity)
        return ContainmentResult(
            allowed=tuple(sorted(allowed)),
            violations=tuple(violations),
        )


@dataclass(frozen=True)
class LaunchSpec:
    work_unit_key: str
    pipeline: str
    mode: str
    ecosystem: str
    backend: str
    model: str
    timeout_s: int
    exec_mode: str
    tool_policy: tuple[str, ...] = ()
    launch_version: str = "plamen.launch.v1"

    def __post_init__(self) -> None:
        key = _validate_work_unit_key(self.work_unit_key)
        pipeline = _canonical_component(self.pipeline, "pipeline")
        mode = _canonical_component(self.mode, "mode")
        ecosystem = _canonical_component(self.ecosystem, "ecosystem")
        backend = _canonical_component(self.backend, "backend")
        key_parts = key.split("/")
        if key_parts[:4] != [pipeline, mode, ecosystem, backend]:
            raise ValueError("launch dimensions disagree with work_unit_key")
        if not isinstance(self.model, str) or not self.model.strip():
            raise ValueError("model must be non-empty")
        if not isinstance(self.timeout_s, int) or isinstance(self.timeout_s, bool) or self.timeout_s <= 0:
            raise ValueError("timeout_s must be a positive integer")
        exec_mode = _canonical_component(self.exec_mode, "exec_mode")
        if not isinstance(self.launch_version, str) or not self.launch_version.strip():
            raise ValueError("launch_version must be non-empty")
        object.__setattr__(self, "work_unit_key", key)
        object.__setattr__(self, "pipeline", pipeline)
        object.__setattr__(self, "mode", mode)
        object.__setattr__(self, "ecosystem", ecosystem)
        object.__setattr__(self, "backend", backend)
        object.__setattr__(self, "model", self.model.strip())
        object.__setattr__(self, "exec_mode", exec_mode)
        object.__setattr__(
            self, "tool_policy", _normalized_strings(self.tool_policy, "tool_policy")
        )
        object.__setattr__(self, "launch_version", self.launch_version.strip())
        if type(self) is LaunchSpec:
            _issue_object_authority(
                self,
                kind="launch_spec",
                payload=LaunchSpec.to_dict(self),
            )

    @property
    def digest(self) -> str:
        return _stable_digest(self.to_dict())

    def to_dict(self) -> dict[str, object]:
        return {
            "launch_version": self.launch_version,
            "work_unit_key": self.work_unit_key,
            "pipeline": self.pipeline,
            "mode": self.mode,
            "ecosystem": self.ecosystem,
            "backend": self.backend,
            "model": self.model,
            "timeout_s": self.timeout_s,
            "exec_mode": self.exec_mode,
            "tool_policy": list(self.tool_policy),
        }


def _phase_io_contract_manifest(
    contract: PhaseIOContract,
) -> dict[str, object]:
    if type(contract) is not PhaseIOContract:
        raise ValueError(
            "PhaseIO contract authority requires the exact "
            "PhaseIOContract type"
        )
    if any(type(output) is not ArtifactSpec for output in contract.outputs):
        raise ValueError(
            "PhaseIO contract authority requires exact ArtifactSpec outputs"
        )
    if any(
        type(requirement) is not InputAuthorityRequirement
        for requirement in contract.input_authority_requirements
    ):
        raise ValueError(
            "PhaseIO contract authority requires exact "
            "InputAuthorityRequirement records"
        )
    return PhaseIOContract.to_dict(contract)


def _launch_spec_manifest(launch: LaunchSpec) -> dict[str, object]:
    if type(launch) is not LaunchSpec:
        raise ValueError(
            "launch authority requires the exact LaunchSpec type"
        )
    return LaunchSpec.to_dict(launch)


def _is_program_facts_contract(contract: PhaseIOContract) -> bool:
    return (
        contract.phase == "recon"
        and contract.work_unit_id
        in {
            "program_facts_checkpoint_capture",
            "program_facts_methodology_capture",
            "program_facts_bake",
        }
    )


def _program_facts_registered_launch(
    contract: PhaseIOContract,
) -> LaunchSpec:
    return LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="driver",
        timeout_s=_PROGRAM_FACTS_LAUNCH_TIMEOUT_S,
        exec_mode="python",
        tool_policy=(),
    )


def replay_phase_io_contract_authority(
    contract: PhaseIOContract,
) -> PhaseIOContract:
    """Return a fresh, sealed replay instead of trusting caller methods."""

    manifest = _phase_io_contract_manifest(contract)
    _require_object_authority(
        contract,
        exact_type=PhaseIOContract,
        kind="phase_io_contract",
        payload=manifest,
    )
    outputs = tuple(
        ArtifactSpec(
            root=output.root,
            path=output.path,
            owner_key=output.owner_key,
            artifact_class=output.artifact_class,
            writer=output.writer,
            write_mode=output.write_mode,
            schema_version=output.schema_version,
            minimum_gate=output.minimum_gate,
            consumers=tuple(output.consumers),
            condition_id=output.condition_id,
            external_preimage_validator=(
                output.external_preimage_validator
            ),
        )
        for output in contract.outputs
    )
    requirements = tuple(
        InputAuthorityRequirement(
            identity=requirement.identity,
            allow_raw=requirement.allow_raw,
            expected_producer_work_unit_key=(
                requirement.expected_producer_work_unit_key
            ),
            expected_writer=requirement.expected_writer,
            require_same_run=requirement.require_same_run,
            expected_contract_digest=(
                requirement.expected_contract_digest
            ),
            expected_launch_digest=requirement.expected_launch_digest,
            require_exact_contract=requirement.require_exact_contract,
            require_exact_launch=requirement.require_exact_launch,
        )
        for requirement in contract.input_authority_requirements
    )
    replayed = PhaseIOContract(
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        phase=contract.phase,
        work_unit_id=contract.work_unit_id,
        outputs=outputs,
        immutable_inputs=tuple(contract.immutable_inputs),
        bounded_lookup_inputs=tuple(contract.bounded_lookup_inputs),
        model_invoked=contract.model_invoked,
        input_authority_requirements=requirements,
        launch_profile=contract.launch_profile,
        required_commit_actor=contract.required_commit_actor,
        contract_version=contract.contract_version,
    )
    if _phase_io_contract_manifest(replayed) != manifest:
        raise ValueError("PhaseIO contract authority replay changed")
    if not _is_program_facts_contract(replayed):
        return replayed

    def _scratchpad_paths(
        identities: tuple[str, ...],
        label: str,
    ) -> tuple[str, ...]:
        paths: list[str] = []
        for identity in identities:
            root, path = identity.split(":", 1)
            if root != "scratchpad":
                raise ValueError(
                    f"registered Program Facts {label} must use scratchpad"
                )
            paths.append(path)
        return tuple(paths)

    expected = resolve_phase_io_contract(
        pipeline=replayed.pipeline,
        mode=replayed.mode,
        ecosystem=replayed.ecosystem,
        backend=replayed.backend,
        phase=replayed.phase,
        work_unit_id=replayed.work_unit_id,
        exact_inputs=_scratchpad_paths(
            replayed.immutable_inputs, "inputs"
        ),
        exact_outputs=tuple(output.path for output in replayed.outputs),
        exact_writer="DRIVER",
    )
    if _phase_io_contract_manifest(expected) != manifest:
        raise ValueError(
            "Program Facts contract differs from the registered canonical "
            "manifest"
        )
    return expected


def replay_launch_spec_authority(
    launch: LaunchSpec,
    *,
    contract: PhaseIOContract,
) -> LaunchSpec:
    """Replay one exact launch and close registered model-free dimensions."""

    manifest = _launch_spec_manifest(launch)
    _require_object_authority(
        launch,
        exact_type=LaunchSpec,
        kind="launch_spec",
        payload=manifest,
    )
    replayed = LaunchSpec(
        work_unit_key=launch.work_unit_key,
        pipeline=launch.pipeline,
        mode=launch.mode,
        ecosystem=launch.ecosystem,
        backend=launch.backend,
        model=launch.model,
        timeout_s=launch.timeout_s,
        exec_mode=launch.exec_mode,
        tool_policy=tuple(launch.tool_policy),
        launch_version=launch.launch_version,
    )
    if _launch_spec_manifest(replayed) != manifest:
        raise ValueError("launch authority replay changed")
    if replayed.work_unit_key != contract.key:
        raise ValueError("launch and contract work-unit keys differ")
    if _is_program_facts_contract(contract):
        expected = _program_facts_registered_launch(contract)
        if _launch_spec_manifest(expected) != manifest:
            raise ValueError(
                "closed model-free launch profile differs from the exact "
                "registered launch manifest"
            )
        return expected
    return replayed


def replay_phase_io_authority_pair(
    contract: PhaseIOContract,
    launch: LaunchSpec,
) -> tuple[PhaseIOContract, LaunchSpec]:
    replayed_contract = replay_phase_io_contract_authority(contract)
    replayed_launch = replay_launch_spec_authority(
        launch,
        contract=replayed_contract,
    )
    return replayed_contract, replayed_launch


@dataclass(frozen=True)
class ConditionalOutputReceipt:
    work_unit_key: str
    contract_digest: str
    artifact_identity: str
    condition_id: str
    state: str
    expected_denominator: int
    produced_identities: tuple[str, ...] = ()
    failure_ids: tuple[str, ...] = ()
    receipt_version: str = "plamen.conditional_output.v1"

    def __post_init__(self) -> None:
        key = _validate_work_unit_key(self.work_unit_key)
        digest = str(self.contract_digest or "").strip().lower()
        if not _SHA256_RE.fullmatch(digest):
            raise ValueError("contract_digest must be lowercase SHA-256")
        identity = _validate_artifact_identity(self.artifact_identity)
        condition = str(self.condition_id or "").strip()
        if not condition:
            raise ValueError("condition_id must be non-empty")
        state = str(self.state or "").strip().upper()
        if state not in CONDITIONAL_STATES:
            raise ValueError(
                f"state must be one of {sorted(CONDITIONAL_STATES)}"
            )
        if (
            not isinstance(self.expected_denominator, int)
            or isinstance(self.expected_denominator, bool)
            or self.expected_denominator < 0
        ):
            raise ValueError("expected_denominator must be a non-negative integer")
        produced = _normalized_strings(
            self.produced_identities, "produced_identities"
        )
        failures = _normalized_strings(self.failure_ids, "failure_ids")
        if state in {"NOT_TRIGGERED", "TRIGGERED_EMPTY"} and (produced or failures):
            raise ValueError(f"{state} cannot carry produced identities or failures")
        if state == "NOT_TRIGGERED" and self.expected_denominator != 0:
            raise ValueError("NOT_TRIGGERED requires expected_denominator=0")
        if state == "PRODUCED":
            if not produced or failures:
                raise ValueError("PRODUCED requires identities and no failure IDs")
            if self.expected_denominator < len(produced):
                raise ValueError("produced identities exceed expected denominator")
        if state == "FAILED" and not failures:
            raise ValueError("FAILED requires at least one failure ID")
        if state != "FAILED" and failures:
            raise ValueError("failure IDs are valid only for FAILED receipts")
        object.__setattr__(self, "work_unit_key", key)
        object.__setattr__(self, "contract_digest", digest)
        object.__setattr__(self, "artifact_identity", identity)
        object.__setattr__(self, "condition_id", condition)
        object.__setattr__(self, "state", state)
        object.__setattr__(self, "produced_identities", produced)
        object.__setattr__(self, "failure_ids", failures)

    @property
    def digest(self) -> str:
        return _stable_digest(self.to_dict())

    def to_dict(self) -> dict[str, object]:
        return {
            "receipt_version": self.receipt_version,
            "work_unit_key": self.work_unit_key,
            "contract_digest": self.contract_digest,
            "artifact_identity": self.artifact_identity,
            "condition_id": self.condition_id,
            "state": self.state,
            "expected_denominator": self.expected_denominator,
            "produced_identities": list(self.produced_identities),
            "failure_ids": list(self.failure_ids),
        }

    def validate_against(self, contract: PhaseIOContract) -> None:
        if not isinstance(contract, PhaseIOContract):
            raise ValueError("conditional receipt requires a PhaseIOContract")
        if self.work_unit_key != contract.key:
            raise ValueError("conditional receipt work-unit key mismatch")
        if self.contract_digest != contract.digest:
            raise ValueError("conditional receipt contract digest mismatch")
        try:
            artifact = contract.output(self.artifact_identity)
        except KeyError as exc:
            raise ValueError(
                "conditional receipt artifact is absent from the contract"
            ) from exc
        if artifact.artifact_class != "CONDITIONAL":
            raise ValueError("conditional receipt artifact is not CONDITIONAL")
        if artifact.condition_id != self.condition_id:
            raise ValueError("conditional receipt condition_id mismatch")


@dataclass(frozen=True)
class DriverMergeEvent:
    """Digest-bound evidence for a recall-monotonic driver-owned merge."""

    work_unit_key: str
    contract_digest: str
    artifact_identity: str
    before_sha256: str
    after_sha256: str
    source_identities: tuple[str, ...]
    identities_before: tuple[str, ...]
    identities_after: tuple[str, ...]
    event_version: str = "plamen.driver_merge.v1"

    def __post_init__(self) -> None:
        key = _validate_work_unit_key(self.work_unit_key)
        contract_digest = str(self.contract_digest or "").strip().lower()
        before = str(self.before_sha256 or "").strip().lower()
        after = str(self.after_sha256 or "").strip().lower()
        for value, name in (
            (contract_digest, "contract_digest"),
            (before, "before_sha256"),
            (after, "after_sha256"),
        ):
            if not _SHA256_RE.fullmatch(value):
                raise ValueError(f"{name} must be lowercase SHA-256")
        artifact = _validate_artifact_identity(self.artifact_identity)
        sources = tuple(sorted({
            _validate_artifact_identity(item) for item in self.source_identities
        }))
        if not sources:
            raise ValueError("driver merge requires at least one source identity")
        identities_before = _normalized_strings(
            self.identities_before, "identities_before"
        )
        identities_after = _normalized_strings(
            self.identities_after, "identities_after"
        )
        removed = set(identities_before) - set(identities_after)
        if removed:
            raise ValueError(
                "driver merge is not recall-monotonic; removed identities: "
                + ", ".join(sorted(removed))
            )
        if not isinstance(self.event_version, str) or not self.event_version.strip():
            raise ValueError("event_version must be non-empty")
        object.__setattr__(self, "work_unit_key", key)
        object.__setattr__(self, "contract_digest", contract_digest)
        object.__setattr__(self, "artifact_identity", artifact)
        object.__setattr__(self, "before_sha256", before)
        object.__setattr__(self, "after_sha256", after)
        object.__setattr__(self, "source_identities", sources)
        object.__setattr__(self, "identities_before", identities_before)
        object.__setattr__(self, "identities_after", identities_after)
        object.__setattr__(self, "event_version", self.event_version.strip())

    @property
    def added_identities(self) -> tuple[str, ...]:
        return tuple(sorted(set(self.identities_after) - set(self.identities_before)))

    @property
    def removed_identities(self) -> tuple[str, ...]:
        return tuple(sorted(set(self.identities_before) - set(self.identities_after)))

    @property
    def digest(self) -> str:
        return _stable_digest(self.to_dict())

    def to_dict(self) -> dict[str, object]:
        return {
            "event_version": self.event_version,
            "work_unit_key": self.work_unit_key,
            "contract_digest": self.contract_digest,
            "artifact_identity": self.artifact_identity,
            "before_sha256": self.before_sha256,
            "after_sha256": self.after_sha256,
            "source_identities": list(self.source_identities),
            "identities_before": list(self.identities_before),
            "identities_after": list(self.identities_after),
        }

    def validate_against(self, contract: PhaseIOContract) -> None:
        if not isinstance(contract, PhaseIOContract):
            raise ValueError("driver merge event requires a PhaseIOContract")
        if self.work_unit_key != contract.key:
            raise ValueError("driver merge event work-unit key mismatch")
        if self.contract_digest != contract.digest:
            raise ValueError("driver merge event contract digest mismatch")
        try:
            artifact = contract.output(self.artifact_identity)
        except KeyError as exc:
            raise ValueError(
                "driver merge target is absent from the contract"
            ) from exc
        if artifact.writer != "DRIVER" or artifact.write_mode != "MERGE":
            raise ValueError("driver merge target must be DRIVER/MERGE")
        allowed_sources = set(contract.immutable_inputs) | set(
            contract.bounded_lookup_inputs
        )
        missing_sources = set(self.source_identities) - allowed_sources
        if missing_sources:
            raise ValueError(
                "driver merge sources are absent from contract inputs: "
                + ", ".join(sorted(missing_sources))
            )


@dataclass(frozen=True)
class DriverOutputTransition:
    """Exact byte transition for one driver-owned contract output."""

    work_unit_key: str
    contract_digest: str
    ordinal: int
    artifact_identity: str
    before_status: str
    before_sha256: str
    before_size: int
    after_sha256: str
    after_size: int
    merge_event: DriverMergeEvent | None = None
    transition_version: str = "plamen.driver_output_transition.v1"

    def __post_init__(self) -> None:
        key = _validate_work_unit_key(self.work_unit_key)
        contract_digest = str(self.contract_digest or "").strip().lower()
        if not _SHA256_RE.fullmatch(contract_digest):
            raise ValueError("contract_digest must be lowercase SHA-256")
        if (
            not isinstance(self.ordinal, int)
            or isinstance(self.ordinal, bool)
            or self.ordinal < 1
        ):
            raise ValueError("ordinal must be a positive integer")
        artifact_identity = _validate_artifact_identity(
            self.artifact_identity
        )
        if not isinstance(self.before_status, str):
            raise ValueError("before_status must be ACTIVE or MISSING")
        before_status = self.before_status.strip()
        if before_status not in {"ACTIVE", "MISSING"}:
            raise ValueError("before_status must be ACTIVE or MISSING")
        before_sha256 = str(self.before_sha256 or "").strip().lower()
        if (
            not isinstance(self.before_size, int)
            or isinstance(self.before_size, bool)
            or self.before_size < 0
        ):
            raise ValueError("before_size must be a non-negative integer")
        if before_status == "MISSING":
            if before_sha256 or self.before_size != 0:
                raise ValueError(
                    "MISSING requires an empty before_sha256 and "
                    "before_size=0"
                )
        elif not _SHA256_RE.fullmatch(before_sha256):
            raise ValueError(
                "ACTIVE before_sha256 must be lowercase SHA-256"
            )
        after_sha256 = str(self.after_sha256 or "").strip().lower()
        if not _SHA256_RE.fullmatch(after_sha256):
            raise ValueError("after_sha256 must be lowercase SHA-256")
        if (
            not isinstance(self.after_size, int)
            or isinstance(self.after_size, bool)
            or self.after_size < 0
        ):
            raise ValueError("after_size must be a non-negative integer")
        if self.transition_version != "plamen.driver_output_transition.v1":
            raise ValueError(
                "transition_version must be "
                "plamen.driver_output_transition.v1"
            )

        merge_event: DriverMergeEvent | None = None
        if self.merge_event is not None:
            if type(self.merge_event) is not DriverMergeEvent:
                raise ValueError(
                    "merge_event must be the exact DriverMergeEvent type"
                )
            source = self.merge_event
            if source.event_version != "plamen.driver_merge.v1":
                raise ValueError(
                    "merge_event must use plamen.driver_merge.v1"
                )
            merge_event = DriverMergeEvent(
                work_unit_key=source.work_unit_key,
                contract_digest=source.contract_digest,
                artifact_identity=source.artifact_identity,
                before_sha256=source.before_sha256,
                after_sha256=source.after_sha256,
                source_identities=tuple(source.source_identities),
                identities_before=tuple(source.identities_before),
                identities_after=tuple(source.identities_after),
                event_version=source.event_version,
            )
            if merge_event.to_dict() != DriverMergeEvent.to_dict(source):
                raise ValueError("merge_event canonical replay changed")

        object.__setattr__(self, "work_unit_key", key)
        object.__setattr__(self, "contract_digest", contract_digest)
        object.__setattr__(self, "artifact_identity", artifact_identity)
        object.__setattr__(self, "before_status", before_status)
        object.__setattr__(self, "before_sha256", before_sha256)
        object.__setattr__(self, "after_sha256", after_sha256)
        object.__setattr__(self, "merge_event", merge_event)
        _issue_object_authority(
            self,
            kind="driver_output_transition",
            payload=DriverOutputTransition.to_dict(self),
        )

    @property
    def digest(self) -> str:
        return _stable_digest(self.to_dict())

    def to_dict(self) -> dict[str, object]:
        return {
            "transition_version": self.transition_version,
            "work_unit_key": self.work_unit_key,
            "contract_digest": self.contract_digest,
            "ordinal": self.ordinal,
            "artifact_identity": self.artifact_identity,
            "before_status": self.before_status,
            "before_sha256": self.before_sha256,
            "before_size": self.before_size,
            "after_sha256": self.after_sha256,
            "after_size": self.after_size,
            "merge_event": (
                None
                if self.merge_event is None
                else DriverMergeEvent.to_dict(self.merge_event)
            ),
        }

    def validate_against(self, contract: PhaseIOContract) -> None:
        replayed_contract = replay_phase_io_contract_authority(contract)
        if self.work_unit_key != replayed_contract.key:
            raise ValueError("driver transition work-unit key mismatch")
        if self.contract_digest != replayed_contract.digest:
            raise ValueError("driver transition contract digest mismatch")
        try:
            artifact = replayed_contract.output(self.artifact_identity)
        except KeyError as exc:
            raise ValueError(
                "driver transition artifact is absent from the contract"
            ) from exc
        if artifact.writer != "DRIVER":
            raise ValueError(
                "driver transition requires a DRIVER-owned output"
            )
        if self.merge_event is None:
            return
        if artifact.write_mode != "MERGE":
            raise ValueError(
                "merge_event is valid only for a DRIVER/MERGE output"
            )
        self.merge_event.validate_against(replayed_contract)
        if self.merge_event.artifact_identity != self.artifact_identity:
            raise ValueError("merge_event artifact identity mismatch")
        if self.merge_event.before_sha256 != self.before_sha256:
            raise ValueError("merge_event before_sha256 mismatch")
        if self.merge_event.after_sha256 != self.after_sha256:
            raise ValueError("merge_event after_sha256 mismatch")


def replay_driver_output_transition_authority(
    transition: DriverOutputTransition,
    *,
    contract: PhaseIOContract,
) -> DriverOutputTransition:
    """Return a fresh transition after checking its external object seal."""

    if type(transition) is not DriverOutputTransition:
        raise ValueError(
            "driver output transition authority requires the exact "
            "DriverOutputTransition type"
        )
    payload = DriverOutputTransition.to_dict(transition)
    _require_object_authority(
        transition,
        exact_type=DriverOutputTransition,
        kind="driver_output_transition",
        payload=payload,
    )
    replayed = DriverOutputTransition(
        work_unit_key=transition.work_unit_key,
        contract_digest=transition.contract_digest,
        ordinal=transition.ordinal,
        artifact_identity=transition.artifact_identity,
        before_status=transition.before_status,
        before_sha256=transition.before_sha256,
        before_size=transition.before_size,
        after_sha256=transition.after_sha256,
        after_size=transition.after_size,
        merge_event=transition.merge_event,
        transition_version=transition.transition_version,
    )
    if replayed.to_dict() != payload:
        raise ValueError("driver output transition authority replay changed")
    replayed.validate_against(contract)
    return replayed


@dataclass(frozen=True)
class DriverSuccessorPlan:
    """Sealed, ordered denominator for a driver-owned output transaction."""

    run_id: str
    work_unit_key: str
    contract_digest: str
    launch_digest: str
    output_prestate_digest: str
    transitions: tuple[DriverOutputTransition, ...]
    plan_version: str = "plamen.driver_successor_plan.v1"

    def __post_init__(self) -> None:
        if (
            not isinstance(self.run_id, str)
            or not self.run_id
            or self.run_id != self.run_id.strip()
        ):
            raise ValueError("run_id must be a canonical non-empty string")
        key = _validate_work_unit_key(self.work_unit_key)
        digests: dict[str, str] = {}
        for field_name in (
            "contract_digest",
            "launch_digest",
            "output_prestate_digest",
        ):
            raw = getattr(self, field_name)
            value = str(raw or "").strip().lower()
            if not _SHA256_RE.fullmatch(value):
                raise ValueError(
                    f"{field_name} must be lowercase SHA-256"
                )
            digests[field_name] = value
        if self.plan_version != "plamen.driver_successor_plan.v1":
            raise ValueError(
                "plan_version must be plamen.driver_successor_plan.v1"
            )
        if not isinstance(self.transitions, tuple) or not self.transitions:
            raise ValueError(
                "transitions must be a non-empty exact tuple"
            )

        transitions: list[DriverOutputTransition] = []
        for transition in self.transitions:
            if type(transition) is not DriverOutputTransition:
                raise ValueError(
                    "transitions must contain exact "
                    "DriverOutputTransition values"
                )
            payload = DriverOutputTransition.to_dict(transition)
            _require_object_authority(
                transition,
                exact_type=DriverOutputTransition,
                kind="driver_output_transition",
                payload=payload,
            )
            copied = DriverOutputTransition(
                work_unit_key=transition.work_unit_key,
                contract_digest=transition.contract_digest,
                ordinal=transition.ordinal,
                artifact_identity=transition.artifact_identity,
                before_status=transition.before_status,
                before_sha256=transition.before_sha256,
                before_size=transition.before_size,
                after_sha256=transition.after_sha256,
                after_size=transition.after_size,
                merge_event=transition.merge_event,
                transition_version=transition.transition_version,
            )
            if copied.to_dict() != payload:
                raise ValueError(
                    "driver transition canonical replay changed"
                )
            if copied.work_unit_key != key:
                raise ValueError(
                    "transition work-unit key differs from plan"
                )
            if copied.contract_digest != digests["contract_digest"]:
                raise ValueError(
                    "transition contract digest differs from plan"
                )
            transitions.append(copied)

        identities = tuple(
            item.artifact_identity for item in transitions
        )
        if len(set(identities)) != len(identities):
            raise ValueError(
                "driver successor plan contains a duplicate output identity"
            )
        ordinals = tuple(item.ordinal for item in transitions)
        expected_ordinals = tuple(range(1, len(transitions) + 1))
        if ordinals != expected_ordinals:
            raise ValueError(
                "transition ordinals must be contiguous and ordered from 1"
            )

        object.__setattr__(self, "work_unit_key", key)
        object.__setattr__(
            self, "contract_digest", digests["contract_digest"]
        )
        object.__setattr__(self, "launch_digest", digests["launch_digest"])
        object.__setattr__(
            self,
            "output_prestate_digest",
            digests["output_prestate_digest"],
        )
        object.__setattr__(self, "transitions", tuple(transitions))
        _issue_object_authority(
            self,
            kind="driver_successor_plan",
            payload=DriverSuccessorPlan.to_dict(self),
        )

    @property
    def output_order(self) -> tuple[str, ...]:
        return tuple(
            transition.artifact_identity
            for transition in self.transitions
        )

    @property
    def expected_output_records(self) -> dict[str, dict[str, object]]:
        return {
            transition.artifact_identity: {
                "sha256": transition.after_sha256,
                "size": transition.after_size,
            }
            for transition in self.transitions
        }

    @property
    def digest(self) -> str:
        return _stable_digest(self.to_dict())

    def to_dict(self) -> dict[str, object]:
        return {
            "plan_version": self.plan_version,
            "run_id": self.run_id,
            "work_unit_key": self.work_unit_key,
            "contract_digest": self.contract_digest,
            "launch_digest": self.launch_digest,
            "output_prestate_digest": self.output_prestate_digest,
            "output_order": list(self.output_order),
            "expected_output_records": self.expected_output_records,
            "transitions": [
                DriverOutputTransition.to_dict(transition)
                for transition in self.transitions
            ],
        }

    def validate_against(
        self,
        contract: PhaseIOContract,
        launch: LaunchSpec,
    ) -> None:
        replayed_contract, replayed_launch = (
            replay_phase_io_authority_pair(contract, launch)
        )
        if self.work_unit_key != replayed_contract.key:
            raise ValueError("successor plan work-unit key mismatch")
        if self.contract_digest != replayed_contract.digest:
            raise ValueError("successor plan contract digest mismatch")
        if self.launch_digest != replayed_launch.digest:
            raise ValueError("successor plan launch digest mismatch")
        if replayed_contract.model_invoked:
            raise ValueError(
                "driver successor plan cannot authorize a model work unit"
            )
        if any(
            artifact.writer != "DRIVER"
            for artifact in replayed_contract.outputs
        ):
            raise ValueError(
                "driver successor plan requires every output to be DRIVER"
            )

        denominator = tuple(
            artifact.identity for artifact in replayed_contract.outputs
        )
        if (
            len(self.output_order) != len(denominator)
            or set(self.output_order) != set(denominator)
        ):
            raise ValueError(
                "driver successor plan output denominator differs "
                "from the contract"
            )
        if set(self.expected_output_records) != set(denominator):
            raise ValueError(
                "expected output records differ from the contract denominator"
            )
        for transition in self.transitions:
            replay_driver_output_transition_authority(
                transition,
                contract=replayed_contract,
            )


def replay_driver_successor_plan_authority(
    plan: DriverSuccessorPlan,
    *,
    contract: PhaseIOContract,
    launch: LaunchSpec,
) -> DriverSuccessorPlan:
    """Return a fresh successor plan after exact sealed replay."""

    if type(plan) is not DriverSuccessorPlan:
        raise ValueError(
            "driver successor plan authority requires the exact "
            "DriverSuccessorPlan type"
        )
    payload = DriverSuccessorPlan.to_dict(plan)
    _require_object_authority(
        plan,
        exact_type=DriverSuccessorPlan,
        kind="driver_successor_plan",
        payload=payload,
    )
    transitions = tuple(
        replay_driver_output_transition_authority(
            transition,
            contract=contract,
        )
        for transition in plan.transitions
    )
    replayed = DriverSuccessorPlan(
        run_id=plan.run_id,
        work_unit_key=plan.work_unit_key,
        contract_digest=plan.contract_digest,
        launch_digest=plan.launch_digest,
        output_prestate_digest=plan.output_prestate_digest,
        transitions=transitions,
        plan_version=plan.plan_version,
    )
    if replayed.to_dict() != payload:
        raise ValueError("driver successor plan authority replay changed")
    replayed.validate_against(contract, launch)
    return replayed


def _exact_mapping(
    value: object,
    *,
    expected_fields: frozenset[str],
    label: str,
) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be a mapping")
    result = dict(value)
    if set(result) != expected_fields:
        raise ValueError(
            f"{label} fields differ from the exact schema"
        )
    if any(not isinstance(key, str) for key in result):
        raise ValueError(f"{label} fields must be strings")
    return result


def _driver_merge_event_from_dict(payload: object) -> DriverMergeEvent:
    raw = _exact_mapping(
        payload,
        expected_fields=frozenset({
            "event_version",
            "work_unit_key",
            "contract_digest",
            "artifact_identity",
            "before_sha256",
            "after_sha256",
            "source_identities",
            "identities_before",
            "identities_after",
        }),
        label="driver merge event",
    )
    for field_name in (
        "source_identities",
        "identities_before",
        "identities_after",
    ):
        if not isinstance(raw[field_name], list):
            raise ValueError(
                f"driver merge event {field_name} must be a canonical list"
            )
    decoded = DriverMergeEvent(
        work_unit_key=raw["work_unit_key"],
        contract_digest=raw["contract_digest"],
        artifact_identity=raw["artifact_identity"],
        before_sha256=raw["before_sha256"],
        after_sha256=raw["after_sha256"],
        source_identities=tuple(raw["source_identities"]),
        identities_before=tuple(raw["identities_before"]),
        identities_after=tuple(raw["identities_after"]),
        event_version=raw["event_version"],
    )
    if _stable_digest(decoded.to_dict()) != _stable_digest(raw):
        raise ValueError(
            "driver merge event payload is not canonical"
        )
    return decoded


def _driver_output_transition_from_dict(
    payload: object,
) -> DriverOutputTransition:
    raw = _exact_mapping(
        payload,
        expected_fields=frozenset({
            "transition_version",
            "work_unit_key",
            "contract_digest",
            "ordinal",
            "artifact_identity",
            "before_status",
            "before_sha256",
            "before_size",
            "after_sha256",
            "after_size",
            "merge_event",
        }),
        label="driver output transition",
    )
    merge_event = (
        None
        if raw["merge_event"] is None
        else _driver_merge_event_from_dict(raw["merge_event"])
    )
    decoded = DriverOutputTransition(
        work_unit_key=raw["work_unit_key"],
        contract_digest=raw["contract_digest"],
        ordinal=raw["ordinal"],
        artifact_identity=raw["artifact_identity"],
        before_status=raw["before_status"],
        before_sha256=raw["before_sha256"],
        before_size=raw["before_size"],
        after_sha256=raw["after_sha256"],
        after_size=raw["after_size"],
        merge_event=merge_event,
        transition_version=raw["transition_version"],
    )
    if _stable_digest(decoded.to_dict()) != _stable_digest(raw):
        raise ValueError(
            "driver output transition payload is not canonical"
        )
    return decoded


def driver_successor_plan_from_dict(
    payload: Mapping[str, object],
    *,
    contract: PhaseIOContract,
    launch: LaunchSpec,
) -> DriverSuccessorPlan:
    """Decode persisted JSON without delegating authority to its methods."""

    raw = _exact_mapping(
        payload,
        expected_fields=frozenset({
            "plan_version",
            "run_id",
            "work_unit_key",
            "contract_digest",
            "launch_digest",
            "output_prestate_digest",
            "output_order",
            "expected_output_records",
            "transitions",
        }),
        label="driver successor plan",
    )
    if not isinstance(raw["output_order"], list):
        raise ValueError("output_order must be a canonical list")
    expected_records = raw["expected_output_records"]
    if not isinstance(expected_records, Mapping):
        raise ValueError("expected_output_records must be a mapping")
    normalized_records: dict[str, object] = {}
    for identity, record in expected_records.items():
        canonical_identity = _validate_artifact_identity(identity)
        normalized_records[canonical_identity] = _exact_mapping(
            record,
            expected_fields=frozenset({"sha256", "size"}),
            label=f"expected_output_records[{identity}]",
        )
    transitions_raw = raw["transitions"]
    if not isinstance(transitions_raw, list):
        raise ValueError("transitions must be a canonical list")
    transitions = tuple(
        _driver_output_transition_from_dict(item)
        for item in transitions_raw
    )
    decoded = DriverSuccessorPlan(
        run_id=raw["run_id"],
        work_unit_key=raw["work_unit_key"],
        contract_digest=raw["contract_digest"],
        launch_digest=raw["launch_digest"],
        output_prestate_digest=raw["output_prestate_digest"],
        transitions=transitions,
        plan_version=raw["plan_version"],
    )
    canonical_raw = {
        **raw,
        "expected_output_records": normalized_records,
    }
    if _stable_digest(decoded.to_dict()) != _stable_digest(canonical_raw):
        raise ValueError(
            "driver successor plan payload is not canonical"
        )
    return replay_driver_successor_plan_authority(
        decoded,
        contract=contract,
        launch=launch,
    )


_RECON_CANONICAL_OUTPUTS = (
    "recon_summary.md",
    "design_context.md",
    "attack_surface.md",
    "state_variables.md",
    "function_list.md",
    "contract_inventory.md",
    "template_recommendations.md",
    "detected_patterns.md",
    "setter_list.md",
    "emit_list.md",
    "build_status.md",
)

_RECON_LIGHT_SHARDS = (
    "recon_build_static.md",
    "recon_inventory_surface.md",
)

_RECON_SHARDS = (
    "recon_build_static.md",
    "recon_design_context.md",
    "recon_inventory_surface.md",
    "recon_templates_patterns.md",
)

_RECON_DEPENDENCY_RESEARCH_OUTPUT = (
    "recon_external_dependency_research.md",
)

_RECON_DEPENDENCY_RESEARCH_INPUT = (
    "external_dependency_obligations.json",
)

_RECON_DEPENDENCY_RESEARCH_RETRY_RE = re.compile(
    r"dependency_research(?:\.attempt-(\d{4}))?",
    re.ASCII,
)

_RECON_TRANSFORM_RECEIPT = "recon_signal_transform_receipt.json"

_RECON_DIRECT_RETRY_RE = re.compile(
    r"direct_retry\.attempt-(000[23])",
    re.ASCII,
)

_RECON_DIRECT_RETRY_INPUTS = (
    "recon_retry_plan.json",
)

_L1_RECON_CANONICAL_OUTPUTS = (
    "recon_summary.md",
    "threat_model.md",
    "subsystem_map.md",
    "attack_surface.md",
    "trust_boundaries.md",
    "template_recommendations.md",
    "scope_leftover.md",
)

_L1_RECON_SHARDS = (
    "recon_l1_threat_fork.md",
    "recon_l1_subsystem_scope.md",
    "recon_l1_attack_trust.md",
    "recon_l1_build_static.md",
    "recon_l1_templates_patterns.md",
)

_L1_RECON_LIGHT_SHARDS = (
    "recon_l1_threat_fork.md",
    "recon_l1_subsystem_attack_trust.md",
    "recon_l1_build_templates.md",
)


def recon_direct_retry_output_paths(
    pipeline: str,
    attempt: int,
) -> tuple[str, ...]:
    """Return the private MODEL denominator for one direct recon attempt.

    These identities intentionally never overlap the root-level canonical
    recon artifacts.  The driver may copy their authenticated bytes to the
    root only as candidates for the existing ``recon/canonical_merge`` owner.
    """

    pipeline_n = _canonical_component(pipeline, "pipeline")
    if pipeline_n == "l1":
        canonical = _L1_RECON_CANONICAL_OUTPUTS
    elif pipeline_n == "sc":
        canonical = _RECON_CANONICAL_OUTPUTS
    else:
        raise ValueError("recon direct retry is registered only for SC and L1")
    if type(attempt) is not int or attempt not in {2, 3}:
        raise ValueError("recon direct retry attempt must be 2 or 3")
    # Keep these flat.  They are also projected beneath the transaction's
    # attempt directory, and another nested attempt prefix crosses legacy
    # Windows MAX_PATH on real contest worktrees.
    return tuple(f"_rr{attempt}_{name}" for name in canonical)

_RECON_RETRY_GENERATION_ROOT = "_canonical_retry_generation/recon"


def _canonical_retry_generation_inputs(
    provided: tuple[str, ...],
    canonical_inputs: tuple[str, ...],
    canonical_outputs: tuple[str, ...],
) -> tuple[str, ...] | None:
    """Validate one sealed semantic-retry projection denominator.

    The work-unit identity deliberately remains ``recon/canonical_merge`` so
    every existing canonical consumer sees the newly committed generation.
    Only its immutable input denominator grows: exact model candidate bytes,
    the exact prior committed generation, and the DRIVER-authored retry plan
    and bundle manifest. Arbitrary extras therefore cannot acquire a canonical
    publication capability.
    """

    if not provided:
        return None
    normalized = tuple(_canonical_relative_path(path) for path in provided)
    if len(normalized) != len(set(normalized)):
        return None
    extras = set(normalized) - set(canonical_inputs)
    if not extras:
        return None
    attempts = {
        match.group(1)
        for path in extras
        if (
            match := re.fullmatch(
                rf"{re.escape(_RECON_RETRY_GENERATION_ROOT)}/"
                r"attempt-([2-9][0-9]*)/(?:candidate|predecessor)/.+",
                path,
            )
        )
    }
    if len(attempts) != 1:
        return None
    attempt = next(iter(attempts))
    root = f"{_RECON_RETRY_GENERATION_ROOT}/attempt-{attempt}"
    expected_extras = {
        f"{root}/candidate/{name}" for name in canonical_outputs[:-1]
    } | {
        f"{root}/predecessor/{name}" for name in canonical_outputs
    } | {
        f"{root}/retry_plan.json",
        f"{root}/prompt.md",
        f"{root}/transcript.log",
        f"{root}/manifest.json",
    }
    if extras != expected_extras:
        return None
    return normalized


_SECURITY_OBLIGATION_SIDECARS = (
    "security_feature_facts.json",
    "security_obligation_authority.json",
    "security_obligations.md",
)
_IMPACT_MAP_EVIDENCE_FILE = "impact_map_evidence.md"

# Closed evidence denominators for driver-scheduled analysis leaves.  These
# names are deliberately data-only: methodology files are separately
# content-bound by the dispatch receipt and project source is separately bound
# by the audit snapshot.  A leaf may therefore never turn prose such as "use
# artifacts in the scratchpad as needed" into directory-enumeration authority.
_SC_RECON_EVIDENCE_INPUTS = (
    "recon_summary.md",
    "design_context.md",
    "attack_surface.md",
    "state_variables.md",
    "function_list.md",
    "contract_inventory.md",
    "template_recommendations.md",
    "detected_patterns.md",
    "setter_list.md",
    "emit_list.md",
    "build_status.md",
    "meta_buffer.md",
    "external_dependency_research.md",
)
_L1_RECON_EVIDENCE_INPUTS = (
    "recon_summary.md",
    "threat_model.md",
    "subsystem_map.md",
    "attack_surface.md",
    "trust_boundaries.md",
    "template_recommendations.md",
    "scope_leftover.md",
    "meta_buffer.md",
    "external_dependency_research.md",
    "primitive_status.md",
)
_SC_BREADTH_REQUIRED_INPUTS = (
    "recon_summary.md",
    "attack_surface.md",
    "contract_inventory.md",
    "function_list.md",
    "state_variables.md",
    "template_recommendations.md",
)
_L1_BREADTH_REQUIRED_INPUTS = (
    "recon_summary.md",
    "attack_surface.md",
    "subsystem_map.md",
    "trust_boundaries.md",
    "template_recommendations.md",
    "primitive_status.md",
)
_COMMON_DEPTH_REGISTERED_FIXED_INPUTS = frozenset({
    "findings_inventory.md",
    "depth_candidates.md",
    "semantic_invariants.md",
    "semantic_invariant_coverage_gaps.md",
    "constraint_variables.md",
    "modifiers.md",
    "blind_spot_a_findings.md",
    "blind_spot_b_findings.md",
    "blind_spot_c_findings.md",
    "validation_sweep_findings.md",
    "spawn_manifest.md",
    "skill_selection_catalog.json",
    "skill_consumer_coverage.json",
    "fuzz_workspace_index.json",
    "semantic_invariant_final_byte_authority.json",
    _IMPACT_MAP_EVIDENCE_FILE,
})
_SC_DEPTH_REGISTERED_FIXED_INPUTS = frozenset({
    *_COMMON_DEPTH_REGISTERED_FIXED_INPUTS,
    "opengrep_findings.md",
    "_mechanical_graph.json",
    "call_graph.md",
    "caller_map.md",
    "callee_map.md",
    "state_read_map.md",
    "state_write_map.md",
    "function_summary.md",
    "external_interfaces.md",
    "static_analysis.md",
    "scip/repo_map.md",
    "scip/repo_map_full.md",
    "scip/xref_map.md",
    "scip/type_hierarchy.md",
    "scip/call_graph.md",
    *_SECURITY_OBLIGATION_SIDECARS,
})
_L1_DEPTH_REGISTERED_FIXED_INPUTS = frozenset({
    *_COMMON_DEPTH_REGISTERED_FIXED_INPUTS,
    "instantiation.json",
    "opengrep_hits_ranked.md",
    "confidence_scores.md",
    "violations.md",
    "scip/repo_map.md",
    "scip/repo_map_full.md",
    "scip/xref_map.md",
    "scip/type_hierarchy.md",
    "scip/concurrency_inventory.md",
    "scip/panic_sites.md",
    "scip/all_symbols.txt",
    "scip/call_graph_consensus.md",
    "scip/call_graph_p2p.md",
    "scip/call_graph_execution.md",
})


def _legacy_worker_fallback_inputs(
    phase: str,
    pipeline: str,
    *,
    exact_outputs: tuple[str, ...],
    mode: str,
) -> tuple[str, ...]:
    """Return the closed, pipeline-specific denominator for legacy callers.

    Current transactional leaves always provide ``exact_inputs``.  A small
    number of read-only/compatibility callers still resolve worker contracts
    without that job-aware roster, so their fallback must remain usable while
    never importing evidence names from the other pipeline.
    """

    if phase == "breadth":
        return (
            _SC_BREADTH_REQUIRED_INPUTS
            if pipeline == "sc" else _L1_BREADTH_REQUIRED_INPUTS
        )

    recon = (
        _SC_RECON_EVIDENCE_INPUTS
        if pipeline == "sc" else _L1_RECON_EVIDENCE_INPUTS
    )
    opengrep = (
        "opengrep_findings.md"
        if pipeline == "sc" else "opengrep_hits_ranked.md"
    )
    if phase == "rescan":
        return tuple(dict.fromkeys((
            *recon,
            "rescan_manifest.md",
            opengrep,
        )))

    if phase == "depth":
        output_names = " ".join(exact_outputs).lower()
        fuzz_inputs = (
            ("fuzz_workspace_index.json",)
            if any(
                marker in output_names
                for marker in ("invariant_fuzz", "medusa_fuzz")
            )
            else ()
        )
        graph_inputs = (
            (
                "_mechanical_graph.json",
                "depth_candidates.md",
                "caller_map.md",
                "callee_map.md",
                "state_write_map.md",
                "function_summary.md",
            )
            if pipeline == "sc"
            else (
                "scip/repo_map.md", "scip/repo_map_full.md",
                "scip/xref_map.md", "scip/type_hierarchy.md",
                "scip/concurrency_inventory.md", "scip/panic_sites.md",
                "scip/all_symbols.txt",
            )
        )
        pipeline_inputs = (
            _SECURITY_OBLIGATION_SIDECARS
            if pipeline == "sc"
            else (
                "instantiation.json", "confidence_scores.md", "violations.md",
            )
        )
        l1_role_graph: tuple[str, ...] = ()
        if pipeline == "l1":
            output_name = " ".join(exact_outputs).lower()
            selected = next((
                graph for marker, graph in (
                    ("consensus_invariant", "scip/call_graph_consensus.md"),
                    ("network_surface", "scip/call_graph_p2p.md"),
                    ("state_trace", "scip/call_graph_execution.md"),
                )
                if marker in output_name
            ), None)
            if selected:
                l1_role_graph = (selected,)
        return tuple(dict.fromkeys((
            *recon,
            "findings_inventory.md",
            opengrep,
            *graph_inputs,
            *pipeline_inputs,
            *fuzz_inputs,
            *(
                ("semantic_invariants.md", "semantic_invariant_coverage_gaps.md")
                if str(mode).lower() in {"core", "thorough"} else ()
            ),
            *(
                ("semantic_invariant_final_byte_authority.json",)
                if pipeline == "sc" and str(mode).lower() == "thorough" else ()
            ),
            *l1_role_graph,
        )))

    raise ValueError(f"no legacy worker fallback shape for {phase}")


def _registered_worker_inputs(
    phase: str,
    pipeline: str,
    exact_inputs: tuple[str, ...],
    *,
    exact_outputs: tuple[str, ...],
    mode: str = "core",
) -> tuple[str, ...]:
    """Validate a finite worker evidence denominator without disk discovery."""

    normalized = tuple(_canonical_relative_path(path) for path in exact_inputs)
    if len(normalized) != len(set(normalized)):
        raise ValueError(f"{phase} worker exact inputs contain duplicates")
    if set(normalized) & set(exact_outputs):
        raise ValueError(f"{phase} worker input/output denominator overlaps")

    if phase == "breadth":
        required = set(
            _SC_BREADTH_REQUIRED_INPUTS
            if pipeline == "sc" else _L1_BREADTH_REQUIRED_INPUTS
        )
        optional = {_IMPACT_MAP_EVIDENCE_FILE}
        extras = set(normalized) - required - optional
        if not required.issubset(normalized) or any(
            re.fullmatch(r"opengrep_obligations_[A-Za-z0-9_.-]+\.md", path)
            is None
            for path in extras
        ):
            raise ValueError(
                "breadth worker inputs must be the registered recon evidence "
                "plus only its exact opengrep obligation shard"
            )
        if len(extras) != 1:
            raise ValueError("breadth worker requires exactly one opengrep shard")
        return normalized

    if phase == "rescan":
        recon = (
            _SC_RECON_EVIDENCE_INPUTS
            if pipeline == "sc" else _L1_RECON_EVIDENCE_INPUTS
        )
        opengrep = (
            "opengrep_findings.md"
            if pipeline == "sc" else "opengrep_hits_ranked.md"
        )
        required = {
            *recon, "rescan_manifest.md", opengrep,
        }
        fixed = set(required)
        invalid = sorted(
            path for path in normalized
            if path not in fixed
            and re.fullmatch(r"analysis_(?!rescan_|percontract_)[A-Za-z0-9_.-]+\.md", path)
            is None
        )
        if not required.issubset(normalized) or invalid:
            raise ValueError(
                "rescan worker inputs omit the pipeline base denominator or "
                "contain unregistered prior artifacts: " + ", ".join(invalid)
            )
        return normalized

    if phase == "depth":
        recon = (
            _SC_RECON_EVIDENCE_INPUTS
            if pipeline == "sc" else _L1_RECON_EVIDENCE_INPUTS
        )
        opengrep = (
            "opengrep_findings.md"
            if pipeline == "sc" else "opengrep_hits_ranked.md"
        )
        graph_required = ({
            "_mechanical_graph.json",
            "depth_candidates.md",
            "caller_map.md",
            "callee_map.md",
            "state_write_map.md",
            "function_summary.md",
        } if pipeline == "sc" else {
            "scip/repo_map.md", "scip/repo_map_full.md", "scip/xref_map.md",
            "scip/type_hierarchy.md", "scip/concurrency_inventory.md",
            "scip/panic_sites.md", "scip/all_symbols.txt",
        })
        if pipeline == "l1":
            output_name = " ".join(exact_outputs).lower()
            l1_call_graph = next((
                graph for marker, graph in (
                    ("consensus_invariant", "scip/call_graph_consensus.md"),
                    ("network_surface", "scip/call_graph_p2p.md"),
                    ("state_trace", "scip/call_graph_execution.md"),
                )
                if marker in output_name
            ), None)
            if l1_call_graph:
                graph_required.add(l1_call_graph)
        required = {
            *recon, "findings_inventory.md", opengrep,
            *graph_required,
        }
        if pipeline == "sc":
            required.update(_SECURITY_OBLIGATION_SIDECARS)
        else:
            required.update({
                "instantiation.json", "confidence_scores.md", "violations.md",
            })
        if str(mode).lower() in {"core", "thorough"}:
            required.update({
                "semantic_invariants.md", "semantic_invariant_coverage_gaps.md",
            })
        if str(mode).lower() == "thorough" and pipeline == "sc":
            required.add("semantic_invariant_final_byte_authority.json")
        registered_fixed = (
            _SC_DEPTH_REGISTERED_FIXED_INPUTS
            if pipeline == "sc" else _L1_DEPTH_REGISTERED_FIXED_INPUTS
        )
        opposing_fixed = (
            _L1_DEPTH_REGISTERED_FIXED_INPUTS
            if pipeline == "sc" else _SC_DEPTH_REGISTERED_FIXED_INPUTS
        ) - registered_fixed
        invalid = sorted(
            path for path in normalized
            if (
                path in opposing_fixed
                or (
                    path not in registered_fixed
                    and path not in recon
                    and re.fullmatch(r"scip/[A-Za-z0-9_.-]+\.md", path) is None
                    and re.fullmatch(r"(?:analysis|depth)_[A-Za-z0-9_.-]+\.md", path) is None
                    # Niche rows are generated from the authenticated niche
                    # job registry with this exact namespaced output shape.
                    # Keep the four fixed scanner rows above explicit; never
                    # admit a generic ``*_findings.md`` fallback here.
                    and re.fullmatch(r"niche_[A-Za-z0-9_.-]+_findings\.md", path) is None
                    and re.fullmatch(r"opengrep_obligations_[A-Za-z0-9_.-]+\.md", path)
                    is None
                    and re.fullmatch(r"(?:call|inheritance|state|dependency)_graph[A-Za-z0-9_.-]*\.md", path)
                    is None
                )
            )
        )
        if not required.issubset(normalized) or invalid:
            raise ValueError(
                "depth worker inputs omit the pipeline base denominator or "
                "contain unregistered evidence: " + ", ".join(invalid)
            )
        return normalized

    raise ValueError(f"no registered finite worker input shape for {phase}")

_CHAIN_TAIL_CONTROL_MANIFEST = (
    "_chain_tail_control/chain_candidate_pairs_iter2.json"
)
_CHAIN_TAIL_MUTABLE_CONTROL_OUTPUTS = (
    "_chain_tail_control/chain_tail_disposition_ledger.json",
    "_chain_tail_control/chain_tail_coverage_receipt.json",
    "_chain_tail_control/chain_composition_verification_candidates.json",
    "_chain_tail_control/chain_composition_coverage_gaps.md",
    "_chain_tail_control/scheduler_journal.json",
)
_CHAIN_TAIL_FINAL_ROOT_OUTPUTS = (
    "chain_tail_disposition_ledger.json",
    "chain_tail_coverage_receipt.json",
    "chain_composition_verification_candidates.json",
    "chain_composition_coverage_gaps.md",
    "chain_iteration2.md",
)
_CHAIN_TAIL_FINAL_PUBLICATION_OUTPUTS = (
    *_CHAIN_TAIL_FINAL_ROOT_OUTPUTS,
    *_CHAIN_TAIL_MUTABLE_CONTROL_OUTPUTS,
)
_SECURITY_OBLIGATION_LIFECYCLE_SIDECARS = (
    "security_obligation_lifecycle.json",
    "security_obligation_lifecycle.md",
    "security_obligation_report_retention.md",
)
_REPORT_INDEX_LEGACY_DENOMINATOR = (
    "verification_queue.md",
    "finding_mapping.md",
    "dedup_decisions.md",
)
_REPORT_CANDIDATE_TYPED_BASE = "verification_queue.work_items.json"
_REPORT_CANDIDATE_DELTA = "post_verify_candidate_delta.json"
_REPORT_CANDIDATE_LATE_DELIVERY = "post_verify_late_delivery.json"
_REPORT_CANDIDATE_LATE_AUTHORITY = (
    "post_verify_late_verification_authority.json"
)
_REPORT_CANDIDATE_LEGACY_SOURCE = "post_verify_extract.md"
_REPORT_INDEX_CANONICAL_OUTPUTS = (
    "report_index.md",
    "report_coverage.md",
    "report_index_status_projection.json",
    "_severity_override_ledger.json",
    "severity_overrides.md",
    "report_dropout_retention.json",
    "report_semantic_report_dropouts.md",
    "report_index_canonicalization_journal.json",
)
_REPORT_INDEX_CANONICAL_RECEIPT = (
    "report_index_canonicalization_receipt.json"
)
_REPORT_ASSEMBLY_SOURCE_CAPTURE = "report_assembly_source_capture.json"
_REPORT_ASSEMBLY_FINAL_CAPTURE = "report_assembly_final_capture.json"
_REPORT_SOURCE_PATH_AUTHORITY = "report_source_path_authority.json"
_REPORT_HUMAN_REVIEW_AUTHORITY_OUTPUTS = (
    "report_human_review_authority.json",
    "report_semantic_retention_risks.md",
    "report_semantic_severity_repairs.md",
)
_REPORT_ASSEMBLY_TIER_CAPTURE_OUTPUTS = (
    "report_assembly_tier_capture.json",
    "report_assembly_staged_index.md",
    "report_assembly_staged_critical_high.md",
    "report_assembly_staged_medium.md",
    "report_assembly_staged_low_info.md",
)
_REPORT_ASSEMBLY_APPENDIX_OUTPUTS = (
    "report_human_review_appendix.json",
    "report_human_review_appendix.md",
)
_REPORT_ASSEMBLY_PUBLISH_OUTPUTS = (
    "AUDIT_REPORT.md",
    "report_quality.md",
    "report_traceability_internal.md",
    "report_consolidation_internal.md",
    "report_evidence_quality_receipt.json",
    "report_assemble_retry_hint.md",
    "report_quality_debt.json",
)


_SEMANTIC_INVARIANT_SOURCE_INPUTS = (
    "_v2_checkpoint.json",
    "_mechanical_graph.json",
    "state_write_map.md",
    "state_variables.md",
)
_SEMANTIC_INVARIANT_PRE_SIDECARS = (
    "semantic_invariant_authority.json",
    "semantic_invariant_worklist.json",
    "semantic_invariant_worklist.md",
)
_PROGRAM_FACTS_BAKE_OUTPUTS = (
    "mechanical_program_facts.v1.json",
    "mechanical_program_facts_receipt.v1.json",
    "mechanical_program_facts_debt.v1.json",
)
_PROGRAM_FACTS_CHECKPOINT_CAPTURE = (
    "_program_facts_inputs/checkpoint_capture.v1.json"
)
_PROGRAM_FACTS_BAKE_CORE_INPUTS = (
    _PROGRAM_FACTS_CHECKPOINT_CAPTURE,
    "_program_facts_methodology/program-facts-methodology-package.v1.json",
    "_program_facts_methodology/program-facts-provider-registry.v1.json",
    "_program_facts_methodology/schemas/mechanical_program_facts.v1.schema.json",
    "_program_facts_methodology/schemas/mechanical_program_facts_receipt.v1.schema.json",
    "_program_facts_methodology/schemas/mechanical_program_facts_debt.v1.schema.json",
    "_program_facts_methodology/schemas/program_facts_provider_registry.v1.schema.json",
    "_program_facts_methodology/schemas/program_facts_disagreement.v1.schema.json",
    "_program_facts_methodology/schemas/program_facts_slice.v1.schema.json",
)
_PROGRAM_FACTS_METHODOLOGY_OUTPUTS = _PROGRAM_FACTS_BAKE_CORE_INPUTS[1:]
_PROGRAM_FACTS_ECOSYSTEMS_BY_PIPELINE = {
    "sc": frozenset({"evm", "solana", "soroban", "aptos", "sui"}),
    "l1": frozenset({"go", "rust", "daml"}),
}
_PROGRAM_FACTS_MODES = frozenset({"light", "core", "thorough"})
_PROGRAM_FACTS_BACKENDS = frozenset({"claude", "codex", "native"})
_SEMANTIC_INVARIANT_RESULT_SIDECARS = (
    "semantic_invariant_application_receipt.json",
    "semantic_invariant_coverage_gaps.md",
)
_SEMANTIC_INVARIANT_PASS2_PRE_FILE = (
    "semantic_invariant_pass2_append_authority.json"
)
_SEMANTIC_INVARIANT_FINAL_BYTE_FILE = (
    "semantic_invariant_final_byte_authority.json"
)
_AUTHENTICATION_ROLE_RESULT_SIDECARS = (
    "authentication_role_authority.json",
    "arm_before_trust_composition_obligations.json",
    "authentication_external_research_obligations.json",
    "authentication_role_obligations.md",
)
_P0AF_V2_QUEUE_INPUTS = (
    "arm_before_trust_compound_candidates.json",
    "arm_before_trust_compound_work_plan.json",
    "arm_before_trust_p0af_route_debt.json",
    "p0af_v2_queue_input.work_items.json",
)
_P0AF_V2_QUEUE_OUTPUTS = (
    "p0af_v2_queue_delivery_receipt.json",
    "p0af_v2_queue_delivery_debt.json",
    "p0af_v2_queue_delivery_status.json",
    "p0af_v2_queue_delivery_transaction.json",
)
_L1_COMPOSITION_SOURCE_RE = re.compile(
    r"^(?:findings_inventory|depth_[A-Za-z0-9_]{1,160}_findings|depth_findings|"
    r"blind_spot_[A-Za-z0-9_]{1,160}_findings|niche_[A-Za-z0-9_]{1,160}_findings|"
    r"scanner_[A-Za-z0-9_]{1,160}_findings|validation_sweep_findings|"
    r"design_stress_findings|perturbation_findings)\.md$",
    re.ASCII,
)


def _l1_composition_sources(values: tuple[str, ...]) -> tuple[str, ...]:
    normalized = tuple(_canonical_relative_path(path) for path in values)
    if (
        len(normalized) != len(set(normalized))
        or any(not _L1_COMPOSITION_SOURCE_RE.fullmatch(path) for path in normalized)
    ):
        raise ValueError("L1 composition source denominator is invalid")
    return normalized


def _security_obligation_sidecar_identities() -> tuple[str, ...]:
    return _identities(_SECURITY_OBLIGATION_SIDECARS)


def _fixed_path_set(
    provided: tuple[str, ...],
    expected: tuple[str, ...],
    *,
    label: str,
) -> tuple[str, ...]:
    """Return one registered path set or reject denominator drift.

    An omitted caller value selects the registered denominator.  Supplying a
    value is allowed for explicit call-site documentation, but it must be the
    same duplicate-free set.  This prevents a future runtime integration from
    silently dropping an authority input or smuggling a mutable lookup into a
    deterministic unit.
    """
    if not provided:
        return expected
    normalized = tuple(_canonical_relative_path(path) for path in provided)
    if len(normalized) != len(set(normalized)) or set(normalized) != set(expected):
        raise ValueError(
            f"{label} must use the registered exact input denominator: "
            + ", ".join(expected)
        )
    return expected


def _fixed_output_set(
    provided: tuple[str, ...],
    expected: tuple[str, ...],
    *,
    label: str,
) -> tuple[str, ...]:
    if not provided:
        return expected
    normalized = tuple(_canonical_relative_path(path) for path in provided)
    if len(normalized) != len(set(normalized)) or set(normalized) != set(expected):
        raise ValueError(
            f"{label} must use the registered exact output denominator: "
            + ", ".join(expected)
        )
    return expected


def _program_facts_alias_free_paths(
    values: tuple[str, ...],
    *,
    label: str,
) -> None:
    normalized: list[str] = []
    for raw in values:
        path = _canonical_relative_path(raw)
        if unicodedata.normalize("NFC", path) != path:
            raise ValueError(f"{label} contains a non-NFC path: {path!r}")
        normalized.append(path)
    if len(normalized) != len(set(normalized)):
        raise ValueError(f"{label} contains a duplicate path")
    folded = [path.casefold() for path in normalized]
    if len(folded) != len(set(folded)):
        raise ValueError(f"{label} contains a casefold path alias")


def _report_candidate_semantic_inputs(
    provided: tuple[str, ...],
    legacy_default: tuple[str, ...],
    *,
    label: str,
) -> tuple[str, ...]:
    """Validate one caller-enumerated report candidate-universe denominator.

    The resolver intentionally does not inspect disk.  The live candidate
    authority loader is therefore responsible for replay-validating the delta
    and enumerating every transitive source authority; this function makes
    that enumeration an exact PhaseIO denominator instead of silently
    replacing it with the legacy Markdown defaults.

    An omitted value retains the registered legacy contract.  Once any typed
    or post-verification signal is supplied, however, the typed base is
    mandatory and post-verification evidence cannot be represented without
    the additive delta.  A delta with no source authority remains a valid
    structural denominator because the independently replayed delta may carry
    explicit missing-source debt.  When a clean-marker source exists, that
    source must be included and is bound here like every other input.
    """

    if not provided:
        return legacy_default
    normalized = tuple(_canonical_relative_path(path) for path in provided)
    if len(normalized) != len(set(normalized)):
        raise ValueError(f"{label} contains duplicate semantic inputs")
    paths = set(normalized)
    operator_evidence = any(
        re.fullmatch(
            r"verification_operator_consumer_authority[^/]*\.json",
            path,
        )
        for path in paths
    )
    postverify_evidence = bool(
        {
            _REPORT_CANDIDATE_LEGACY_SOURCE,
            _REPORT_CANDIDATE_LATE_DELIVERY,
            _REPORT_CANDIDATE_LATE_AUTHORITY,
        }
        & paths
    ) or operator_evidence
    typed_selected = bool(
        {
            _REPORT_CANDIDATE_TYPED_BASE,
            _REPORT_CANDIDATE_DELTA,
        }
        & paths
    ) or postverify_evidence
    if typed_selected and _REPORT_CANDIDATE_TYPED_BASE not in paths:
        raise ValueError(
            f"{label}: typed report candidate universe requires "
            f"{_REPORT_CANDIDATE_TYPED_BASE}"
        )
    if postverify_evidence and _REPORT_CANDIDATE_DELTA not in paths:
        raise ValueError(
            f"{label}: post-verification evidence requires "
            f"{_REPORT_CANDIDATE_DELTA}"
        )
    return normalized


def _identities(paths: Iterable[str]) -> tuple[str, ...]:
    return tuple(canonical_artifact_identity("scratchpad", path) for path in paths)


def _strict_dynamic_input_authorities(
    paths: tuple[str, ...],
    exact_input_authorities: Mapping[
        str, InputAuthorityRequirement
    ] | None,
    *,
    label: str,
) -> tuple[InputAuthorityRequirement, ...]:
    """Close a dynamic DRIVER denominator over exact non-RAW producers."""

    authority_by_path: dict[str, InputAuthorityRequirement] = {}
    if exact_input_authorities is not None:
        if not isinstance(exact_input_authorities, Mapping):
            raise ValueError(f"{label} exact producer authority must be a mapping")
        for raw_path, requirement in exact_input_authorities.items():
            path = _canonical_relative_path(raw_path)
            if path in authority_by_path:
                raise ValueError(
                    f"{label} exact producer authority contains a duplicate path"
                )
            if type(requirement) is not InputAuthorityRequirement:
                raise ValueError(
                    f"{label} exact producer authority values are malformed"
                )
            try:
                canonical_requirement = InputAuthorityRequirement(
                    **InputAuthorityRequirement.to_dict(requirement)
                )
            except (AttributeError, TypeError, ValueError) as exc:
                raise ValueError(
                    f"{label} producer authority failed canonical replay for "
                    f"{path}: {exc}"
                ) from exc
            authority_by_path[path] = canonical_requirement
    if set(authority_by_path) != set(paths):
        raise ValueError(
            f"{label} requires exact producer authority for every present input"
        )
    for path in paths:
        requirement = authority_by_path[path]
        if (
            requirement.identity
            != canonical_artifact_identity("scratchpad", path)
            or requirement.allow_raw
            or not requirement.expected_producer_work_unit_key
            or requirement.expected_writer not in {"MODEL", "DRIVER"}
            or not requirement.expected_contract_digest
            or not requirement.expected_launch_digest
            or not requirement.require_same_run
            or not requirement.require_exact_contract
            or not requirement.require_exact_launch
        ):
            raise ValueError(
                f"{label} raw or incomplete producer authority is forbidden "
                f"for {path}"
            )
    return tuple(authority_by_path[path] for path in paths)


def _mixed_identities(paths: Iterable[str]) -> tuple[str, ...]:
    """Resolve the narrow dynamic-input notation used by cross-root gates."""

    identities: list[str] = []
    for raw in paths:
        value = str(raw)
        if value.startswith("project::"):
            identities.append(
                canonical_artifact_identity("project", value[len("project::"):])
            )
        else:
            identities.append(canonical_artifact_identity("scratchpad", value))
    return tuple(identities)


def _axis_input_identities(
    provided: tuple[str, ...],
    *,
    required: tuple[str, ...],
    label: str,
    paired: tuple[tuple[str, str], ...] = (),
) -> tuple[str, ...]:
    """Bind a caller-enumerated axis denominator without inspecting disk.

    Axis planning and reconciliation consume project sources plus a changing
    set of graph/provider sidecars.  The caller must therefore enumerate the
    whole immutable denominator.  This helper rejects omissions in the fixed
    semantic core and partial optional pairs (notably repair Markdown+JSON)
    while retaining ecosystem- and backend-neutral path handling.
    """

    if not provided:
        raise ValueError(f"{label} requires an exact input denominator")
    identities = _mixed_identities(provided)
    if len(identities) != len(set(identities)):
        raise ValueError(f"{label} exact input denominator contains duplicates")
    scratchpad_paths = {
        identity.split(":", 1)[1]
        for identity in identities
        if identity.startswith("scratchpad:")
    }
    missing = set(required) - scratchpad_paths
    if missing:
        raise ValueError(
            f"{label} exact input denominator is missing: "
            + ", ".join(sorted(missing))
        )
    for left, right in paired:
        present = {left, right} & scratchpad_paths
        if present and present != {left, right}:
            raise ValueError(
                f"{label} requires paired repair outputs: {left}, {right}"
            )
    return identities


def _artifact(
    owner: str,
    path: str,
    *,
    root: str = "scratchpad",
    artifact_class: str,
    writer: str,
    write_mode: str = "REPLACE",
    condition_id: str = "",
    schema_version: str = "unstructured.v1",
    minimum_gate: str = "PRESENCE",
    consumers: tuple[str, ...] = (),
    external_preimage_validator: str = "",
) -> ArtifactSpec:
    return ArtifactSpec(
        root=root,
        path=path,
        owner_key=owner,
        artifact_class=artifact_class,
        writer=writer,
        write_mode=write_mode,
        condition_id=condition_id,
        schema_version=schema_version,
        minimum_gate=minimum_gate,
        consumers=consumers,
        external_preimage_validator=external_preimage_validator,
    )


def _dynamic_specs(
    owner: str,
    exact_outputs: tuple[str, ...],
    *,
    writer: str,
    conditional_output_ids: tuple[str, ...],
    condition_id: str,
) -> tuple[ArtifactSpec, ...]:
    if not exact_outputs:
        raise ValueError("this work unit requires explicit exact_outputs")
    conditional = set(conditional_output_ids)
    unknown_conditional = conditional - set(exact_outputs)
    if unknown_conditional:
        raise ValueError(
            "conditional outputs are absent from exact_outputs: "
            + ", ".join(sorted(unknown_conditional))
        )
    if conditional and not condition_id:
        raise ValueError("conditional dynamic outputs require condition_id")
    return tuple(
        _artifact(
            owner,
            path,
            artifact_class=(
                "CONDITIONAL"
                if path in conditional
                else ("DRIVER_GENERATED" if writer == "DRIVER" else "REQUIRED")
            ),
            writer=writer,
            condition_id=(condition_id if path in conditional else ""),
            minimum_gate="STRUCTURAL",
        )
        for path in exact_outputs
    )


def resolve_phase_io_contract(
    *,
    pipeline: str,
    mode: str,
    ecosystem: str,
    backend: str,
    phase: str,
    work_unit_id: str,
    exact_outputs: tuple[str, ...] = (),
    exact_inputs: tuple[str, ...] = (),
    conditional_output_ids: tuple[str, ...] = (),
    condition_id: str = "",
    source_phase: str = "",
    exact_writer: str | None = None,
    exact_input_authorities: Mapping[
        str, InputAuthorityRequirement
    ] | None = None,
) -> PhaseIOContract:
    """Resolve one of the reproduced P0-AE work-unit shapes.

    Dynamic planners must pass concrete filenames through ``exact_outputs``.
    Globs are rejected by ``ArtifactSpec``; the resolver never enumerates disk
    state and therefore stays deterministic and testable.
    """
    raw_dimensions = {
        "pipeline": pipeline,
        "mode": mode,
        "ecosystem": ecosystem,
        "backend": backend,
        "phase": phase,
        "work_unit_id": work_unit_id,
    }
    pipeline_n = _canonical_component(pipeline, "pipeline")
    mode_n = _canonical_component(mode, "mode")
    ecosystem_n = _canonical_component(ecosystem, "ecosystem")
    backend_n = _canonical_component(backend, "backend")
    phase_n = _canonical_component(phase, "phase")
    work_n = _canonical_component(work_unit_id, "work_unit_id")
    program_facts_unit = (
        phase_n == "recon"
        and work_n in {
            "program_facts_checkpoint_capture",
            "program_facts_methodology_capture",
            "program_facts_bake",
        }
    )
    if program_facts_unit:
        canonical_dimensions = {
            "pipeline": pipeline_n,
            "mode": mode_n,
            "ecosystem": ecosystem_n,
            "backend": backend_n,
            "phase": phase_n,
            "work_unit_id": work_n,
        }
        for field, raw in raw_dimensions.items():
            if raw != canonical_dimensions[field]:
                raise ValueError(
                    f"program-facts {field} uses a non-canonical alias"
                )
        if (
            pipeline_n not in _PROGRAM_FACTS_ECOSYSTEMS_BY_PIPELINE
            or ecosystem_n
            not in _PROGRAM_FACTS_ECOSYSTEMS_BY_PIPELINE[pipeline_n]
            or mode_n not in _PROGRAM_FACTS_MODES
            or backend_n not in _PROGRAM_FACTS_BACKENDS
        ):
            raise ValueError(
                "program-facts work unit has no registered dimension pairing"
            )
        _program_facts_alias_free_paths(
            exact_inputs,
            label=f"{phase_n}/{work_n} exact inputs",
        )
        _program_facts_alias_free_paths(
            exact_outputs,
            label=f"{phase_n}/{work_n} exact outputs",
        )
    writer_n = (
        str(exact_writer).strip().upper()
        if exact_writer is not None
        else None
    )
    if writer_n is not None and writer_n not in {"MODEL", "DRIVER"}:
        raise ValueError("exact_writer must be MODEL or DRIVER")
    if (
        phase_n in {"axis_disposition", "axis_coverage"}
        and (pipeline_n != "sc" or mode_n != "thorough")
    ):
        raise ValueError(
            "axis-disposition PhaseIO is scheduled only for SC Thorough"
        )
    owner = canonical_work_unit_key(
        pipeline_n, mode_n, ecosystem_n, backend_n, phase_n, work_n
    )
    outputs: tuple[ArtifactSpec, ...]
    immutable: tuple[str, ...] = ()
    bounded: tuple[str, ...] = ()
    model_invoked = True
    input_authority_requirements: tuple[
        InputAuthorityRequirement, ...
    ] = ()
    launch_profile = ""
    required_commit_actor = ""

    if exact_input_authorities and (
        (phase_n, work_n)
        not in {
            ("report_assemble", "source_capture"),
            ("report_index", "human_review_authority"),
            ("report_index", "chain_deferred_authority"),
        }
    ):
        raise ValueError(
            "exact_input_authorities is registered only for "
            "closed report authority work units"
        )

    if (
        phase_n == "recon"
        and work_n == "program_facts_checkpoint_capture"
    ):
        canonical_outputs = _fixed_output_set(
            exact_outputs,
            (_PROGRAM_FACTS_CHECKPOINT_CAPTURE,),
            label=f"{phase_n}/{work_n}",
        )
        if exact_inputs:
            raise ValueError(
                "recon/program_facts_checkpoint_capture has the registered "
                "zero-input denominator"
            )
        if conditional_output_ids or condition_id:
            raise ValueError(
                "recon/program_facts_checkpoint_capture has no conditional "
                "outputs"
            )
        outputs = (
            _artifact(
                owner,
                canonical_outputs[0],
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="CREATE",
                schema_version=(
                    "plamen.program_facts_checkpoint_capture.v1"
                ),
                minimum_gate=(
                    "EXACT_CANONICAL_AUDIT_SNAPSHOT_AND_RUN_ID_CAPTURE"
                ),
                consumers=(
                    "recon/program_facts_methodology_capture",
                    "recon/program_facts_bake",
                ),
            ),
        )
        immutable = ()
        model_invoked = False
        launch_profile = "DRIVER_PYTHON_NO_TOOLS"
        required_commit_actor = "DRIVER"

    elif (
        phase_n == "recon"
        and work_n == "program_facts_methodology_capture"
    ):
        canonical_outputs = _fixed_output_set(
            exact_outputs,
            _PROGRAM_FACTS_METHODOLOGY_OUTPUTS,
            label=f"{phase_n}/{work_n}",
        )
        if exact_inputs != (_PROGRAM_FACTS_CHECKPOINT_CAPTURE,):
            raise ValueError(
                "recon/program_facts_methodology_capture must use the "
                "registered immutable checkpoint-capture input denominator"
            )
        if conditional_output_ids or condition_id:
            raise ValueError(
                "recon/program_facts_methodology_capture has no conditional "
                "outputs"
            )
        outputs = tuple(
            _artifact(
                owner,
                path,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="CREATE",
                schema_version=(
                    "plamen.program_facts_methodology_package.v1"
                    if path.endswith(
                        "program-facts-methodology-package.v1.json"
                    )
                    else "plamen.program_facts_provider_registry.v1"
                    if path.endswith(
                        "program-facts-provider-registry.v1.json"
                    )
                    else "json-schema.draft-2020-12"
                ),
                minimum_gate=(
                    "EXACT_INSTALLED_METHODOLOGY_PACKAGE_AND_SNAPSHOT_PARITY"
                ),
                consumers=("recon/program_facts_bake",),
            )
            for path in canonical_outputs
        )
        immutable = _identities(exact_inputs)
        model_invoked = False
        checkpoint_contract = resolve_phase_io_contract(
            pipeline=pipeline_n,
            mode=mode_n,
            ecosystem=ecosystem_n,
            backend=backend_n,
            phase="recon",
            work_unit_id="program_facts_checkpoint_capture",
            exact_inputs=(),
            exact_outputs=(_PROGRAM_FACTS_CHECKPOINT_CAPTURE,),
            exact_writer="DRIVER",
        )
        checkpoint_launch = _program_facts_registered_launch(
            checkpoint_contract
        )
        input_authority_requirements = (
            InputAuthorityRequirement(
                identity=canonical_artifact_identity(
                    "scratchpad", _PROGRAM_FACTS_CHECKPOINT_CAPTURE
                ),
                allow_raw=False,
                expected_producer_work_unit_key=checkpoint_contract.key,
                expected_writer="DRIVER",
                require_same_run=True,
                expected_contract_digest=checkpoint_contract.digest,
                expected_launch_digest=checkpoint_launch.digest,
                require_exact_contract=True,
                require_exact_launch=True,
            ),
        )
        launch_profile = "DRIVER_PYTHON_NO_TOOLS"
        required_commit_actor = "DRIVER"

    elif phase_n == "recon" and work_n == "codex_dependency_fetch":
        if pipeline_n != "sc" or backend_n != "codex":
            raise ValueError(
                "recon/codex_dependency_fetch is SC Codex-only"
            )
        _fixed_path_set(
            exact_inputs,
            ("recon_external_dependency_research.md",),
            label=f"{phase_n}/{work_n}",
        )
        _fixed_output_set(
            exact_outputs,
            ("codex_dependency_fetch_receipt.json",),
            label=f"{phase_n}/{work_n}",
        )
        outputs = (
            _artifact(
                owner,
                "codex_dependency_fetch_receipt.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.codex_dependency_fetch_receipt.v1",
                minimum_gate=(
                    "SSRF_SAFE_BOUNDED_HTTPS_FETCH_AND_EXACT_REPORT_CLAIM_PARITY"
                ),
                consumers=("recon/dependency_reconcile",),
            ),
        )
        immutable = _identities(exact_inputs)
        model_invoked = False
        launch_profile = "DRIVER_PYTHON_NO_TOOLS"
        required_commit_actor = "DRIVER"

    elif phase_n == "recon" and work_n == "program_facts_bake":
        canonical_outputs = _fixed_output_set(
            exact_outputs,
            _PROGRAM_FACTS_BAKE_OUTPUTS,
            label=f"{phase_n}/{work_n}",
        )
        if conditional_output_ids or condition_id:
            raise ValueError(
                "recon/program_facts_bake has no conditional outputs"
            )
        if not exact_inputs:
            raise ValueError(
                "recon/program_facts_bake requires its exact immutable input "
                "denominator"
            )
        canonical_inputs = tuple(
            _canonical_relative_path(path) for path in exact_inputs
        )
        if len(canonical_inputs) != len(set(canonical_inputs)):
            raise ValueError(
                "recon/program_facts_bake exact inputs contain a duplicate"
            )
        missing_inputs = set(_PROGRAM_FACTS_BAKE_CORE_INPUTS) - set(
            canonical_inputs
        )
        if missing_inputs:
            raise ValueError(
                "recon/program_facts_bake exact inputs are missing: "
                + ", ".join(sorted(missing_inputs))
            )
        additional_inputs = (
            set(canonical_inputs) - set(_PROGRAM_FACTS_BAKE_CORE_INPUTS)
        )
        invalid_additional = sorted(
            path
            for path in additional_inputs
            if (
                not path.startswith("_program_facts_inputs/")
                or not path.endswith(".json")
            )
        )
        if invalid_additional:
            raise ValueError(
                "recon/program_facts_bake additional inputs must be "
                "driver-produced JSON under _program_facts_inputs/: "
                + ", ".join(invalid_additional)
            )
        schema_by_path = {
            "mechanical_program_facts.v1.json": (
                "plamen.mechanical_program_facts.v1"
            ),
            "mechanical_program_facts_receipt.v1.json": (
                "plamen.mechanical_program_facts_receipt.v1"
            ),
            "mechanical_program_facts_debt.v1.json": (
                "plamen.mechanical_program_facts_debt.v1"
            ),
        }
        gate_by_path = {
            "mechanical_program_facts.v1.json": (
                "SIGNED_CLOSED_SCHEMA_CROSS_REFERENCE_AND_SOURCE_BINDING_VALID"
            ),
            "mechanical_program_facts_receipt.v1.json": (
                "SNAPSHOT_BUILD_TOOL_EXECUTION_AND_OUTPUT_PARITY"
            ),
            "mechanical_program_facts_debt.v1.json": (
                "TOTAL_UNSUPPORTED_PARTIAL_AND_DISAGREEMENT_ACCOUNTING"
            ),
        }
        consumers_by_path = {
            "mechanical_program_facts.v1.json": (
                "program_facts/loader",
                "program_facts/slicing",
            ),
            "mechanical_program_facts_receipt.v1.json": (
                "program_facts/loader",
            ),
            "mechanical_program_facts_debt.v1.json": (
                "program_facts/loader",
                "program_facts/obligations",
            ),
        }
        outputs = tuple(
            _artifact(
                owner,
                path,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="CREATE",
                schema_version=schema_by_path[path],
                minimum_gate=gate_by_path[path],
                consumers=consumers_by_path[path],
            )
            for path in canonical_outputs
        )
        immutable = _identities(canonical_inputs)
        model_invoked = False
        capture_contract = resolve_phase_io_contract(
            pipeline=pipeline_n,
            mode=mode_n,
            ecosystem=ecosystem_n,
            backend=backend_n,
            phase="recon",
            work_unit_id="program_facts_methodology_capture",
            exact_inputs=(_PROGRAM_FACTS_CHECKPOINT_CAPTURE,),
            exact_outputs=_PROGRAM_FACTS_METHODOLOGY_OUTPUTS,
            exact_writer="DRIVER",
        )
        capture_launch = _program_facts_registered_launch(
            capture_contract
        )
        checkpoint_contract = resolve_phase_io_contract(
            pipeline=pipeline_n,
            mode=mode_n,
            ecosystem=ecosystem_n,
            backend=backend_n,
            phase="recon",
            work_unit_id="program_facts_checkpoint_capture",
            exact_inputs=(),
            exact_outputs=(_PROGRAM_FACTS_CHECKPOINT_CAPTURE,),
            exact_writer="DRIVER",
        )
        checkpoint_launch = _program_facts_registered_launch(
            checkpoint_contract
        )
        methodology_paths = set(_PROGRAM_FACTS_METHODOLOGY_OUTPUTS)
        requirements: list[InputAuthorityRequirement] = []
        for path in canonical_inputs:
            predecessor: PhaseIOContract | None = None
            predecessor_launch: LaunchSpec | None = None
            if path in methodology_paths:
                predecessor = capture_contract
                predecessor_launch = capture_launch
            elif path == _PROGRAM_FACTS_CHECKPOINT_CAPTURE:
                predecessor = checkpoint_contract
                predecessor_launch = checkpoint_launch
            requirements.append(
                InputAuthorityRequirement(
                    identity=canonical_artifact_identity(
                        "scratchpad", path
                    ),
                    allow_raw=False,
                    expected_producer_work_unit_key=(
                        predecessor.key
                        if predecessor is not None
                        else ""
                    ),
                    expected_writer="DRIVER",
                    require_same_run=True,
                    expected_contract_digest=(
                        predecessor.digest
                        if predecessor is not None
                        else ""
                    ),
                    expected_launch_digest=(
                        predecessor_launch.digest
                        if predecessor_launch is not None
                        else ""
                    ),
                    require_exact_contract=True,
                    require_exact_launch=True,
                )
            )
        input_authority_requirements = tuple(requirements)
        launch_profile = "DRIVER_PYTHON_NO_TOOLS"
        required_commit_actor = "DRIVER"

    elif phase_n == "bake" and work_n == "capability_status":
        if pipeline_n != "l1":
            raise ValueError("bake/capability_status is L1-only")
        if exact_inputs or exact_outputs:
            raise ValueError(
                "bake/capability_status has a fixed empty input denominator "
                "and one fixed status output"
            )
        outputs = (
            _artifact(
                owner,
                "primitive_status.md",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.l1_bake_capability_status.v1",
                minimum_gate="HONEST_AVAILABILITY_PROBE_NO_EXECUTION_CLAIM",
            ),
        )
        model_invoked = False

    elif phase_n == "invariants" and work_n == "semantic_invariants.pre":
        _fixed_output_set(
            exact_outputs,
            _SEMANTIC_INVARIANT_PRE_SIDECARS,
            label=f"{phase_n}/{work_n}",
        )
        semantic_inputs = _fixed_path_set(
            exact_inputs,
            _SEMANTIC_INVARIANT_SOURCE_INPUTS,
            label=f"{phase_n}/{work_n}",
        )
        schema_by_path = {
            "semantic_invariant_authority.json": (
                "plamen.semantic_invariant_state_authority.v1"
            ),
            "semantic_invariant_worklist.json": (
                "plamen.semantic_invariant_worklist.v1"
            ),
            "semantic_invariant_worklist.md": (
                "plamen.semantic_invariant_worklist_projection.v1"
            ),
        }
        gate_by_path = {
            "semantic_invariant_authority.json": (
                "EXACT_STATE_DENOMINATOR_AND_SOURCE_CONFLICT_PARITY"
            ),
            "semantic_invariant_worklist.json": (
                "EXACT_AUTHORITY_TO_WORKLIST_PARITY"
            ),
            "semantic_invariant_worklist.md": "EXACT_WORKLIST_PROJECTION",
        }
        outputs = tuple(
            _artifact(
                owner,
                path,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version=schema_by_path[path],
                minimum_gate=gate_by_path[path],
                consumers=(
                    "invariants/worker.semantic_invariants",
                    "depth/worker.semantic_invariant_independent",
                ),
            )
            for path in _SEMANTIC_INVARIANT_PRE_SIDECARS
        )
        immutable = _identities(semantic_inputs)
        model_invoked = False

    elif phase_n == "invariants" and work_n == "worker.semantic_invariants":
        _fixed_output_set(
            exact_outputs,
            ("semantic_invariants.md",),
            label=f"{phase_n}/{work_n}",
        )
        semantic_inputs = _fixed_path_set(
            exact_inputs,
            (
                *_SEMANTIC_INVARIANT_SOURCE_INPUTS,
                *_SEMANTIC_INVARIANT_PRE_SIDECARS,
            ),
            label=f"{phase_n}/{work_n}",
        )
        outputs = (
            _artifact(
                owner,
                "semantic_invariants.md",
                artifact_class="REQUIRED",
                writer="MODEL",
                schema_version=(
                    "plamen.semantic_invariants_markdown_with_typed_trace.v1"
                ),
                minimum_gate="EXACT_STATE_DENOMINATOR_TYPED_TRACE",
            ),
        )
        immutable = _identities(semantic_inputs)

    elif (
        phase_n == "invariants"
        and work_n == "semantic_invariants.fallback"
    ):
        _fixed_output_set(
            exact_outputs,
            ("semantic_invariants.md",),
            label=f"{phase_n}/{work_n}",
        )
        semantic_inputs = _fixed_path_set(
            exact_inputs,
            (
                *_SEMANTIC_INVARIANT_SOURCE_INPUTS,
                *_SEMANTIC_INVARIANT_PRE_SIDECARS,
            ),
            label=f"{phase_n}/{work_n}",
        )
        outputs = (
            _artifact(
                owner,
                "semantic_invariants.md",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="REPLACE",
                schema_version=(
                    "plamen.semantic_invariants_deferred_fallback.v1"
                ),
                minimum_gate="EXACT_STATE_DENOMINATOR_DEFERRED_TRACE",
                consumers=(
                    "invariants/semantic_invariants.post",
                    "invariants_p2/semantic_invariants.pass2_pre",
                    "depth/worker.semantic_invariant_independent",
                ),
            ),
        )
        immutable = _identities(semantic_inputs)
        model_invoked = False
        launch_profile = "DRIVER_PYTHON_NO_TOOLS"
        required_commit_actor = "DRIVER"

    elif phase_n == "inventory" and work_n == "depth_handoff":
        canonical_outputs = _fixed_output_set(
            exact_outputs,
            (
                "depth_candidates.md",
                "file_coverage.md",
                "state_dependency_map.md",
                "phase4_gates.md",
                "caller_map.md",
                "callee_map.md",
                "state_write_map.md",
                "function_summary.md",
                "depth_handoff_receipt.json",
            ),
            label=f"{phase_n}/{work_n}",
        )
        canonical_inputs = tuple(
            _canonical_relative_path(path) for path in exact_inputs
        )
        if len(canonical_inputs) != len(set(canonical_inputs)):
            raise ValueError("inventory/depth_handoff inputs contain duplicates")
        required_inputs = {
            "_mechanical_graph.json",
            "findings_inventory.md",
            "contract_inventory.md",
            "attack_surface.md",
            "spawn_manifest.md",
        }
        invalid_inputs = sorted(
            path for path in canonical_inputs
            if path not in required_inputs
            and re.fullmatch(r"analysis_[A-Za-z0-9_.-]+\.md", path) is None
        )
        breadth_inputs = tuple(
            path for path in canonical_inputs if path.startswith("analysis_")
        )
        if (
            not required_inputs.issubset(canonical_inputs)
            or not breadth_inputs
            or invalid_inputs
        ):
            raise ValueError(
                "inventory/depth_handoff requires its graph, canonical "
                "inventory, recon surface, spawn manifest, and manifest-exact "
                "breadth outputs; invalid: " + ", ".join(invalid_inputs)
            )
        schema_by_path = {
            "depth_candidates.md": "plamen.depth_candidates_projection.v1",
            "file_coverage.md": "plamen.file_coverage_projection.v1",
            "state_dependency_map.md": "plamen.state_dependency_projection.v1",
            "phase4_gates.md": "plamen.phase4_gate_projection.v1",
            "caller_map.md": "plamen.mechanical_caller_projection.v1",
            "callee_map.md": "plamen.mechanical_callee_projection.v1",
            "state_write_map.md": "plamen.mechanical_state_write_projection.v1",
            "function_summary.md": "plamen.mechanical_function_summary_projection.v1",
            "depth_handoff_receipt.json": "plamen.depth_handoff_receipt.v1",
        }
        outputs = tuple(
            _artifact(
                owner,
                path,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version=schema_by_path[path],
                minimum_gate=(
                    "EXACT_RECALL_PRESERVING_INVENTORY_AND_GRAPH_PROJECTION"
                ),
                consumers=("depth/worker.*",),
            )
            for path in canonical_outputs
        )
        immutable = _identities(canonical_inputs)
        model_invoked = False
        launch_profile = "DRIVER_PYTHON_NO_TOOLS"
        required_commit_actor = "DRIVER"

    elif phase_n == "inventory" and work_n == "additive_reemit":
        outputs = (
            _artifact(
                owner,
                "inventory_reemit_intent.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.inventory_reemit_intent.v2",
                minimum_gate="ARMED_RECALL_MONOTONIC_ADDITIVE_REEMIT",
            ),
            _artifact(
                owner,
                "findings_inventory.md",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="MERGE",
                minimum_gate="ADDITIVE_IDENTITY_SUPERSET",
            ),
            _artifact(
                owner,
                "inventory_reemit_receipt.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.inventory_reemit_receipt.v1",
                minimum_gate="EXACT_SOURCE_TO_INDEPENDENT_DELIVERY_PARITY",
            ),
            _artifact(
                owner,
                "finding_records.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="MERGE",
                schema_version="plamen.finding_records.v2",
                minimum_gate="ADDITIVE_IDENTITY_SUPERSET_EXACT_PROJECTION",
            ),
            _artifact(
                owner,
                "_id_ledger.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="MERGE",
                schema_version="plamen.id_ledger.v1",
                minimum_gate="ADDITIVE_ID_ALLOCATION_SUPERSET",
            ),
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif (
        phase_n == "inventory"
        and work_n in {
            "aggregate_plan.multi_shard",
            "aggregate_plan.single_shard",
            "aggregate_plan.typed_empty",
            "aggregate_plan.floor_reconstruction",
        }
    ):
        _fixed_output_set(
            exact_outputs,
            ("inventory_aggregate_derivation.json",),
            label=f"{phase_n}/{work_n}",
        )
        if not exact_inputs:
            raise ValueError(
                f"{phase_n}/{work_n} requires an exact source denominator"
            )
        outputs = (
            _artifact(
                owner,
                "inventory_aggregate_derivation.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.inventory_aggregate_derivation.v1",
                minimum_gate=(
                    "EXACT_TERMINAL_CHUNK_ROSTER_AND_OUTPUT_DIGEST_PLAN"
                ),
                consumers=(
                    "inventory/canonical_aggregate",
                    "inventory/id_ledger_merge",
                ),
            ),
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif phase_n == "inventory" and work_n == "canonical_aggregate":
        _fixed_output_set(
            exact_outputs,
            (
                "findings_inventory.md",
                "finding_records.json",
                "inventory_merge_receipt.md",
                "inventory_id_allocation_delta.json",
            ),
            label=f"{phase_n}/{work_n}",
        )
        if "inventory_aggregate_derivation.json" not in exact_inputs:
            raise ValueError(
                "inventory/canonical_aggregate requires its exact derivation plan"
            )
        outputs = tuple(
            _artifact(
                owner,
                path,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version={
                    "findings_inventory.md": (
                        "plamen.canonical_finding_inventory.v1"
                    ),
                    "finding_records.json": "plamen.finding_records.v2",
                    "inventory_merge_receipt.md": (
                        "plamen.inventory_merge_receipt.v1"
                    ),
                    "inventory_id_allocation_delta.json": (
                        "plamen.inventory_id_allocation_delta.v1"
                    ),
                }[path],
                minimum_gate={
                    "findings_inventory.md": (
                        "LOSSLESS_SOURCE_ID_SUPERSET_AND_DEFAULTED_EVIDENCE"
                    ),
                    "finding_records.json": (
                        "EXACT_INVENTORY_IDENTITY_PROJECTION"
                    ),
                    "inventory_merge_receipt.md": (
                        "EXACT_DERIVATION_KIND_AND_SOURCE_DENOMINATOR"
                    ),
                    "inventory_id_allocation_delta.json": (
                        "EXACT_IMMUTABLE_INVENTORY_ID_ALLOCATION_PROJECTION"
                    ),
                }[path],
                consumers=(
                    (
                        "inventory/id_ledger_merge",
                        "inventory/additive_reemit",
                        "inventory/exact_reconciliation",
                    )
                    if path == "findings_inventory.md"
                    else (
                        "inventory/id_ledger_merge",
                        "inventory/additive_reemit",
                    )
                    if path == "finding_records.json"
                    else (
                        "inventory/id_ledger_merge",
                        "inventory/additive_reemit",
                    )
                    if path == "inventory_id_allocation_delta.json"
                    else ()
                ),
            )
            for path in (
                "findings_inventory.md",
                "finding_records.json",
                "inventory_merge_receipt.md",
                "inventory_id_allocation_delta.json",
            )
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif phase_n == "inventory" and work_n == "id_ledger_merge":
        _fixed_output_set(
            exact_outputs,
            (
                "_id_ledger.json",
                "inventory_id_ledger_merge_receipt.json",
            ),
            label=f"{phase_n}/{work_n}",
        )
        required = {
            "inventory_aggregate_derivation.json",
            "inventory_id_allocation_delta.json",
            "findings_inventory.md",
            "finding_records.json",
        }
        if set(exact_inputs) != required:
            raise ValueError(
                "inventory/id_ledger_merge requires the exact canonical "
                "allocation and producer anchors"
            )
        outputs = (
            _artifact(
                owner,
                "_id_ledger.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="MERGE",
                schema_version="plamen.id_ledger.v1",
                minimum_gate=(
                    "VALIDATED_EXTERNAL_PREIMAGE_ADDITIVE_IDENTITY_SUPERSET"
                ),
                consumers=("inventory/additive_reemit",),
                external_preimage_validator="plamen.strict_id_ledger.v1",
            ),
            _artifact(
                owner,
                "inventory_id_ledger_merge_receipt.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version=(
                    "plamen.inventory_id_ledger_merge_receipt.v1"
                ),
                minimum_gate=(
                    "EXACT_PREIMAGE_CAS_COLLISION_CHECKED_UNION"
                ),
                consumers=("inventory/additive_reemit",),
            ),
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif phase_n == "semantic_dedup" and work_n == "prequeue_apply":
        decision_inputs = tuple(exact_inputs)
        if decision_inputs not in {
            ("dedup_decisions.md",),
            (
                "dedup_decisions.md",
                "semantic_dedup_supplemental_proposals.json",
            ),
        }:
            raise ValueError(
                "semantic_dedup/prequeue_apply exact inputs must be the "
                "primary proposal, optionally followed by its typed "
                "supplemental proposal"
            )
        _fixed_output_set(
            exact_outputs,
            (
                "findings_inventory.md",
                "finding_records.json",
                "findings_inventory_deduped.md",
                "semantic_dedup_applied_receipt.json",
                "dedup_absorbed_map.md",
            ),
            label=f"{phase_n}/{work_n}",
        )
        outputs = (
            _artifact(
                owner,
                "findings_inventory.md",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="REPLACE",
                schema_version="plamen.canonical_finding_inventory.v1",
                minimum_gate=(
                    "EXACT_RECEIPT_AUTHORIZED_CANDIDATE_PARTITION"
                ),
                consumers=(
                    "rag_sweep/precedent_facts",
                    "verify_queue/preverify_capture",
                ),
            ),
            _artifact(
                owner,
                "finding_records.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="REPLACE",
                schema_version="plamen.finding_records.v2",
                minimum_gate=(
                    "EXACT_POST_INVENTORY_RECORD_PROJECTION"
                ),
                consumers=(
                    "rag_sweep/precedent_facts",
                    "verify_queue/preverify_capture",
                ),
            ),
            _artifact(
                owner,
                "findings_inventory_deduped.md",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="REPLACE",
                schema_version="plamen.canonical_finding_inventory.v1",
                minimum_gate=(
                    "BYTE_EXACT_POST_INVENTORY_PROJECTION"
                ),
                consumers=(
                    "rag_sweep/precedent_facts",
                    "verify_queue/preverify_capture",
                ),
            ),
            _artifact(
                owner,
                "semantic_dedup_applied_receipt.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="REPLACE",
                schema_version="plamen.semantic_dedup_applied.v1",
                minimum_gate=(
                    "FIELD_COMPLETE_APPLIED_RECEIPT_AND_IDENTITY_PARTITION"
                ),
                consumers=(
                    "semantic_dedup/absorbed_projection",
                    "verify_queue/preverify_capture",
                ),
            ),
            _artifact(
                owner,
                "dedup_absorbed_map.md",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="REPLACE",
                schema_version=(
                    "plamen.semantic_dedup_absorbed_projection.v1"
                ),
                minimum_gate=(
                    "EXACT_APPLIED_RECEIPT_AUTHORIZED_ALIAS_PROJECTION"
                ),
                consumers=(
                    "chain/chain_agent1",
                    "verify_queue/preverify_capture",
                ),
            ),
        )
        # The canonical inventory/record pair are output prestates, not
        # immutable inputs. Their exact current-run producer or contiguous
        # semantic-mutation lineage is bound by the artifact ledger.
        immutable = _identities(decision_inputs)
        model_invoked = False

    elif (
        phase_n == "invariants_p2"
        and work_n == "semantic_invariants.pass2_pre"
    ):
        _fixed_output_set(
            exact_outputs,
            (_SEMANTIC_INVARIANT_PASS2_PRE_FILE,),
            label=f"{phase_n}/{work_n}",
        )
        # The deterministic output is the content-addressed seal over the
        # live Pass-1 receipt and semantic bytes.  Those live identities are
        # intentionally not ledger inputs: Pass 2 must mutate the semantic
        # artifact and depth later advances the receipt, so recording either
        # as an immutable input would create guaranteed false P0-Z drift on
        # every exact resume.  All later units bind this immutable seal.
        semantic_inputs = _fixed_path_set(
            exact_inputs,
            (),
            label=f"{phase_n}/{work_n}",
        )
        outputs = (
            _artifact(
                owner,
                _SEMANTIC_INVARIANT_PASS2_PRE_FILE,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version=(
                    "plamen.semantic_invariant_pass2_append_authority.v1"
                ),
                minimum_gate=(
                    "EXACT_PRIOR_RECEIPT_AND_PRE_APPEND_BYTE_BINDING"
                ),
                consumers=(
                    "invariants_p2/worker.semantic_invariants_pass2",
                    "invariants_p2/semantic_invariants.pass2_reconcile",
                ),
            ),
        )
        immutable = _identities(semantic_inputs)
        model_invoked = False

    elif (
        phase_n == "invariants_p2"
        and work_n == "worker.semantic_invariants_pass2"
    ):
        _fixed_output_set(
            exact_outputs,
            ("semantic_invariants.md",),
            label=f"{phase_n}/{work_n}",
        )
        semantic_inputs = _fixed_path_set(
            exact_inputs,
            (_SEMANTIC_INVARIANT_PASS2_PRE_FILE,),
            label=f"{phase_n}/{work_n}",
        )
        outputs = (
            _artifact(
                owner,
                "semantic_invariants.md",
                artifact_class="REQUIRED",
                writer="MODEL",
                write_mode="APPEND",
                schema_version=(
                    "plamen.semantic_invariants_markdown_pass2_append.v1"
                ),
                minimum_gate="EXACT_PREFIX_PRESERVING_CONTENT_BEARING_APPEND",
                consumers=(
                    "invariants_p2/semantic_invariants.pass2_reconcile",
                ),
            ),
        )
        immutable = _identities(semantic_inputs)

    elif (
        phase_n == "invariants_p2"
        and work_n == "semantic_invariants.pass2_reconcile"
    ):
        _fixed_output_set(
            exact_outputs,
            (_SEMANTIC_INVARIANT_FINAL_BYTE_FILE,),
            label=f"{phase_n}/{work_n}",
        )
        semantic_inputs = _fixed_path_set(
            exact_inputs,
            (
                _SEMANTIC_INVARIANT_PASS2_PRE_FILE,
                "semantic_invariants.md",
            ),
            label=f"{phase_n}/{work_n}",
        )
        outputs = (
            _artifact(
                owner,
                _SEMANTIC_INVARIANT_FINAL_BYTE_FILE,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version=(
                    "plamen.semantic_invariant_final_byte_authority.v1"
                ),
                minimum_gate=(
                    "EXACT_PRE_POST_PREFIX_AND_PRIOR_RECEIPT_SUCCESSOR_BINDING"
                ),
                consumers=(
                    "depth/worker.semantic_invariant_independent",
                    "depth/semantic_invariants.independent_application",
                    "depth/model",
                ),
            ),
        )
        immutable = _identities(semantic_inputs)
        model_invoked = False

    elif (
        (phase_n == "invariants" and work_n == "semantic_invariants.post")
        or (
            phase_n == "depth"
            and work_n == "semantic_invariants.independent_application"
        )
    ):
        _fixed_output_set(
            exact_outputs,
            _SEMANTIC_INVARIANT_RESULT_SIDECARS,
            label=f"{phase_n}/{work_n}",
        )
        independent = work_n.endswith("independent_application")
        expected_inputs = (
            *_SEMANTIC_INVARIANT_SOURCE_INPUTS,
            *_SEMANTIC_INVARIANT_PRE_SIDECARS,
            "semantic_invariants.md",
            *(
                ("semantic_invariant_independent_application.input.json",)
                if work_n.endswith("independent_application")
                else ()
            ),
        )
        semantic_inputs = _fixed_path_set(
            exact_inputs,
            expected_inputs,
            label=f"{phase_n}/{work_n}",
        )
        outputs = (
            _artifact(
                owner,
                "semantic_invariant_application_receipt.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version=(
                    "plamen.semantic_invariant_application_receipt.v3"
                ),
                minimum_gate=(
                    "DISTINCT_OPERATOR_EXACT_ROW_BINDING_RECONCILIATION"
                    if independent
                    else "EXACT_PRODUCER_DELIVERY_ENUMERATE_DIFF_RECONCILIATION"
                ),
                consumers=(
                    "depth/worker.semantic_invariant_independent",
                    "depth/model",
                    "application_skeptic/model",
                ),
            ),
            _artifact(
                owner,
                "semantic_invariant_coverage_gaps.md",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version=(
                    "plamen.semantic_invariant_coverage_gaps_projection.v1"
                ),
                minimum_gate="EXACT_NON_APPLIED_STATE_PROJECTION",
                consumers=(
                    "depth/worker.semantic_invariant_independent",
                    "depth/model",
                    "application_skeptic/model",
                ),
            ),
        )
        immutable = _identities(semantic_inputs)
        if independent and mode_n == "thorough":
            # The legacy receipt filename is advanced in-place by this
            # deterministic reconciliation. Bind the immutable Pass-2 byte
            # successor as a separate exact lookup so that ownership transfer
            # is explicit without making the prior receipt its own input.
            bounded = _identities((_SEMANTIC_INVARIANT_FINAL_BYTE_FILE,))
        model_invoked = False

    elif (
        phase_n == "depth"
        and work_n == "worker.semantic_invariant_independent"
    ):
        _fixed_output_set(
            exact_outputs,
            ("semantic_invariant_independent_application.input.json",),
            label=f"{phase_n}/{work_n}",
        )
        independent_inputs = _fixed_path_set(
            exact_inputs,
            (
                *_SEMANTIC_INVARIANT_SOURCE_INPUTS,
                *_SEMANTIC_INVARIANT_PRE_SIDECARS,
                "semantic_invariants.md",
                *_SEMANTIC_INVARIANT_RESULT_SIDECARS,
                *(
                    (_SEMANTIC_INVARIANT_FINAL_BYTE_FILE,)
                    if mode_n == "thorough"
                    else ()
                ),
            ),
            label=f"{phase_n}/{work_n}",
        )
        outputs = (
            _artifact(
                owner,
                "semantic_invariant_independent_application.input.json",
                artifact_class="REQUIRED",
                writer="MODEL",
                schema_version=(
                    "plamen.semantic_invariant_independent_application_trace.v1"
                ),
                minimum_gate="DISTINCT_OPERATOR_EXACT_PRODUCER_ROW_BINDING",
            ),
        )
        immutable = _identities(independent_inputs)

    elif phase_n == "depth" and work_n == "worker.authentication_role_facts":
        _fixed_output_set(
            exact_outputs,
            ("authentication_role_facts.input.json",),
            label=f"{phase_n}/{work_n}",
        )
        authentication_inputs = _fixed_path_set(
            exact_inputs,
            ("_v2_checkpoint.json", "_mechanical_graph.json"),
            label=f"{phase_n}/{work_n}",
        )
        outputs = (
            _artifact(
                owner,
                "authentication_role_facts.input.json",
                artifact_class="REQUIRED",
                writer="MODEL",
                schema_version="plamen.authentication_role_fact_trace.v1",
                minimum_gate="EXACT_TYPED_FACT_TRACE_AND_OPERATOR_BINDING",
            ),
        )
        immutable = _identities(authentication_inputs)

    elif phase_n == "depth" and work_n == "authentication_roles.fact_authority":
        _fixed_output_set(
            exact_outputs,
            ("authentication_role_authority.json",),
            label=f"{phase_n}/{work_n}",
        )
        # Cross-ecosystem activation is deliberately held.  A non-EVM run has
        # no model fact trace by design, so binding that absent MODEL output as
        # a DRIVER input would manufacture permanent INPUT_DEBT for a clean,
        # deterministic NOT_TRIGGERED decision.  EVM remains trace-bound.
        expected_auth_inputs = (
            ("_v2_checkpoint.json", "authentication_role_facts.input.json")
            if ecosystem_n == "evm"
            else ("_v2_checkpoint.json",)
        )
        auth_inputs = _fixed_path_set(
            exact_inputs,
            expected_auth_inputs,
            label=f"{phase_n}/{work_n}",
        )
        outputs = (
            _artifact(
                owner,
                "authentication_role_authority.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.authentication_role_fact_authority.v1",
                minimum_gate=(
                    "EXACT_TYPED_FACT_TRACE_AND_RUN_BINDING"
                    if ecosystem_n == "evm"
                    else "EXPLICIT_NON_EVM_ACTIVATION_GATE"
                ),
                consumers=(
                    "depth/authentication_roles.composition",
                    "chain/worker.arm_before_trust",
                ),
            ),
        )
        immutable = _identities(auth_inputs)
        model_invoked = False

    elif phase_n == "depth" and work_n == "authentication_roles.composition":
        _fixed_output_set(
            exact_outputs,
            _AUTHENTICATION_ROLE_RESULT_SIDECARS[1:],
            label=f"{phase_n}/{work_n}",
        )
        auth_inputs = _fixed_path_set(
            exact_inputs,
            ("authentication_role_authority.json",),
            label=f"{phase_n}/{work_n}",
        )
        outputs = (
            _artifact(
                owner,
                "arm_before_trust_composition_obligations.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version=(
                    "plamen.arm_before_trust_composition_obligations.v1"
                ),
                minimum_gate="EXACT_TYPED_FACT_PAIRING_AND_DEBT_PARITY",
                consumers=("chain/worker.arm_before_trust",),
            ),
            _artifact(
                owner,
                "authentication_external_research_obligations.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version=(
                    "plamen.authentication_external_research_obligations.v1"
                ),
                minimum_gate="EXTERNAL_UNKNOWN_CANDIDATE_SCOPED_PARITY",
                consumers=("chain/worker.arm_before_trust",),
            ),
            _artifact(
                owner,
                "authentication_role_obligations.md",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version=(
                    "plamen.authentication_role_obligations_projection.v1"
                ),
                minimum_gate=(
                    "EXACT_AUTHORITY_COMPOSITION_RESEARCH_PROJECTION"
                ),
                consumers=("chain/worker.arm_before_trust",),
            ),
        )
        immutable = _identities(auth_inputs)
        model_invoked = False

    elif phase_n == "chain" and work_n == "summary_compaction":
        _fixed_output_set(
            exact_outputs,
            ("chain_summaries_compact.md",),
            label=f"{phase_n}/{work_n}",
        )
        if "_v2_checkpoint.json" not in exact_inputs:
            raise ValueError(
                "chain/summary_compaction requires the run checkpoint "
                "plus its exact discovered source roster"
            )
        outputs = (
            _artifact(
                owner,
                "chain_summaries_compact.md",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="unstructured.v1",
                minimum_gate="EXACT_CHAIN_SUMMARY_SOURCE_DENOMINATOR",
                consumers=("chain/model",),
            ),
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif phase_n == "chain" and work_n == "scaffold":
        _fixed_output_set(
            exact_outputs,
            ("hypotheses.md", "finding_mapping.md", "enabler_results.md"),
            label=f"{phase_n}/{work_n}",
        )
        scaffold_inputs = _fixed_path_set(
            exact_inputs,
            ("findings_inventory.md",),
            label=f"{phase_n}/{work_n}",
        )
        outputs = tuple(
            _artifact(
                owner,
                path,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="unstructured.v1",
                minimum_gate="RECALL_SAFE_ONE_TO_ONE_CHAIN_SCAFFOLD",
                consumers=(
                    ("chain/state_resolution", "chain/model")
                    if path == "enabler_results.md"
                    else ("chain/model",)
                ),
            )
            for path in (
                "hypotheses.md",
                "finding_mapping.md",
                "enabler_results.md",
            )
        )
        immutable = _identities(scaffold_inputs)
        model_invoked = False

    elif phase_n == "chain" and work_n == "model":
        _fixed_output_set(
            exact_outputs,
            ("hypotheses.md", "finding_mapping.md", "enabler_results.md"),
            label=f"{phase_n}/{work_n}",
        )
        if not exact_inputs:
            raise ValueError(
                "chain/model requires its exact final discovery denominator"
            )
        required_chain_inputs = {
            "_v2_checkpoint.json",
            "findings_inventory.md",
            "chain_summaries_compact.md",
            "attack_surface.md",
        }
        if not required_chain_inputs <= set(exact_inputs):
            raise ValueError(
                "chain/model exact input denominator is incomplete: "
                + ", ".join(sorted(required_chain_inputs - set(exact_inputs)))
            )
        outputs = tuple(
            _artifact(
                owner,
                path,
                artifact_class="REQUIRED",
                writer="MODEL",
                schema_version="unstructured.v1",
                minimum_gate="CHAIN_GROUPING_AND_ENABLER_STRUCTURAL_GATE",
                consumers=(
                    "chain/final_pair_auto_map_stage",
                    "chain_agent2/model",
                    "sc_verify_queue/preverify_chain_pair",
                ),
            )
            for path in (
                "hypotheses.md",
                "finding_mapping.md",
                "enabler_results.md",
            )
        )
        immutable = _mixed_identities(exact_inputs)

    elif phase_n == "chain" and work_n == "worker.arm_before_trust":
        if not exact_outputs:
            raise ValueError(
                "chain/worker.arm_before_trust requires exact model outputs"
            )
        authentication_inputs = _fixed_path_set(
            exact_inputs,
            _AUTHENTICATION_ROLE_RESULT_SIDECARS,
            label=f"{phase_n}/{work_n}",
        )
        outputs = _dynamic_specs(
            owner,
            exact_outputs,
            writer="MODEL",
            conditional_output_ids=(),
            condition_id="",
        )
        immutable = _identities(authentication_inputs)

    elif (
        phase_n == "chain"
        and work_n == "authentication_roles.compound_work"
    ):
        _fixed_output_set(
            exact_outputs,
            (
                "arm_before_trust_compound_candidates.json",
                "arm_before_trust_compound_work_plan.json",
                "arm_before_trust_p0af_route_debt.json",
            ),
            label=f"{phase_n}/{work_n}",
        )
        authentication_inputs = _fixed_path_set(
            exact_inputs,
            (
                "arm_before_trust_chain_analysis.input.json",
                "arm_before_trust_composition_obligations.json",
                "authentication_role_authority.json",
                "_canonical_finding_ids.json",
            ),
            label=f"{phase_n}/{work_n}",
        )
        outputs = (
            _artifact(
                owner,
                "arm_before_trust_compound_candidates.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version=(
                    "plamen.arm_before_trust_compound_candidates.v1"
                ),
                minimum_gate="EXACT_EVIDENCE_FACT_AUTHORITY_BINDINGS",
                consumers=("p0af_v2_queue_adapter",),
            ),
            _artifact(
                owner,
                "arm_before_trust_compound_work_plan.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version=(
                    "plamen.arm_before_trust_compound_work_authority.v1"
                ),
                minimum_gate="P0_AF_V2_READY_TYPED_WORK",
                consumers=("p0af_v2_queue_adapter",),
            ),
            _artifact(
                owner,
                "arm_before_trust_p0af_route_debt.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version=(
                    "plamen.arm_before_trust_p0af_route_debt.v1"
                ),
                minimum_gate="EXPLICIT_PENDING_QUEUE_DELIVERY_DEBT",
                consumers=("p0af_v2_queue_adapter",),
            ),
        )
        immutable = _identities(authentication_inputs)
        model_invoked = False

    elif phase_n == "sc_verify_queue" and work_n == "p0af_v2_queue_adapter":
        queue_inputs = _fixed_path_set(
            exact_inputs,
            _P0AF_V2_QUEUE_INPUTS,
            label=f"{phase_n}/{work_n}",
        )
        queue_outputs = _fixed_output_set(
            exact_outputs,
            _P0AF_V2_QUEUE_OUTPUTS,
            label=f"{phase_n}/{work_n}",
        )
        schemas = {
            "p0af_v2_queue_delivery_receipt.json": (
                "plamen.p0af_v2_queue_delivery.v1"
            ),
            "p0af_v2_queue_delivery_debt.json": (
                "plamen.p0af_v2_queue_delivery_debt.v1"
            ),
            "p0af_v2_queue_delivery_status.json": (
                "plamen.p0af_v2_queue_runtime_status.v1"
            ),
            "p0af_v2_queue_delivery_transaction.json": (
                "plamen.p0af_v2_queue_transaction.v1"
            ),
        }
        outputs = tuple(
            _artifact(
                owner,
                path,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version=schemas[path],
                minimum_gate=(
                    "PREPARE_PUBLISH_COMMIT_AND_EXACT_QUEUE_PARITY"
                ),
                consumers=(
                    "sc_verify_queue/routing",
                    "sc_verify_critical_high/planning",
                ),
            )
            for path in queue_outputs
        )
        immutable = _identities(queue_inputs)
        model_invoked = False

    elif (
        phase_n == "candidate_negative_authority"
        and work_n.startswith("harvest.")
    ):
        if len(exact_outputs) != 1 or not exact_outputs[0].startswith(
            "candidate_negative_proposals_"
        ) or not exact_outputs[0].endswith(".json"):
            raise ValueError(
                "candidate-negative harvest requires one exact phase ledger output"
            )
        outputs = (
            _artifact(
                owner,
                exact_outputs[0],
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.candidate_negative_proposal_ledger.v1",
                minimum_gate="APPEND_ONLY_STRUCTURED_NEGATIVE_ENUMERATION",
                consumers=("application_skeptic/negative.planning",),
            ),
        )
        immutable = _mixed_identities(exact_inputs)
        model_invoked = False

    elif phase_n == "application_skeptic" and work_n == "planning":
        outputs = (
            _artifact(
                owner, "application_skeptic_work_plan.json",
                artifact_class="DRIVER_GENERATED", writer="DRIVER",
                schema_version="plamen.application_skeptic_work_plan.v1",
                minimum_gate="EXACT_INPUT_UNION",
            ),
        )
        immutable = _identities(tuple(
            f"methodology_skeptic_queue_{source}.json"
            for source in (
                "breadth", "breadth_repair", "rescan", "rescan_repair",
                "depth", "depth_repair",
            )
        ))
        model_invoked = False

    elif phase_n == "application_skeptic" and work_n == "negative.planning":
        outputs = (
            _artifact(
                owner,
                "candidate_negative_skeptic_work_plan.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.application_skeptic_work_plan.v1",
                minimum_gate="EXACT_CANDIDATE_NEGATIVE_LEDGER_UNION",
                consumers=("application_skeptic/negative.worker",),
            ),
        )
        planning_inputs = exact_inputs or tuple(
            f"candidate_negative_proposals_{source}.json"
            for source in (
                "breadth",
                "rescan",
                "depth",
                "attention_repair",
            )
        )
        if any(
            not str(path).startswith("candidate_negative_proposals_")
            or not str(path).endswith(".json")
            for path in planning_inputs
        ):
            raise ValueError(
                "candidate-negative planning inputs are not phase ledgers"
            )
        immutable = _identities(planning_inputs)
        model_invoked = False

    elif phase_n == "severity_adjudication_shadow" and work_n == "planning":
        outputs = _dynamic_specs(
            owner,
            exact_outputs,
            writer="DRIVER",
            conditional_output_ids=(),
            condition_id="",
        )
        immutable = _identities((
            "severity_decision_ledger.shadow.json",
            *exact_inputs,
        ))
        model_invoked = False

    elif phase_n == "startup" and work_n == "trust_evidence_initial":
        outputs = tuple(
            _artifact(
                owner,
                path,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version=(
                    "plamen.trust_evidence_authority.v1"
                    if path == "trust_evidence_authority.json"
                    else "plamen.trust_evidence_provider_receipt.v1"
                ),
                minimum_gate="FAIL_CLOSED_PRECONSUMER_ZERO_AUTHORITY",
            )
            for path in (
                "trust_evidence_authority.json",
                "trust_evidence_provider_receipt.json",
            )
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif (
        phase_n == "severity_adjudication_shadow"
        and work_n == "trust_evidence_reconcile"
    ):
        outputs = tuple(
            _artifact(
                owner,
                path,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version=(
                    "plamen.trust_evidence_authority.v1"
                    if path == "trust_evidence_authority.json"
                    else "plamen.trust_evidence_provider_receipt.v1"
                ),
                minimum_gate="ZERO_NEGATIVE_AUTHORITY_EXACT_RECONCILIATION",
            )
            for path in (
                "trust_evidence_authority.json",
                "trust_evidence_provider_receipt.json",
            )
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif phase_n == "skeptic" and work_n == "challenge_reconcile":
        outputs = (
            _artifact(
                owner,
                "judge_decisions.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.judge_decisions.v1",
                minimum_gate="PRESENTATION_PROJECTION_ONLY",
            ),
            _artifact(
                owner,
                "skeptic_challenges.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.skeptic_challenges.v1",
                minimum_gate="EXACT_TRIGGER_DENOMINATOR_AND_SOURCE_HASHES",
            ),
        )
        immutable = _identities((
            "skeptic_manifest.json",
            "skeptic_findings.md",
            "skeptic_judge_decisions.md",
        ))
        model_invoked = False

    elif phase_n == "chain" and work_n == "grouping_relation_repair":
        outputs = (
            _artifact(
                owner,
                "chain_grouping_relations.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.chain_grouping_relations.v2",
                minimum_gate="EXACT_INDEPENDENT_MEMBER_MAPPING_PROPOSAL_ONLY",
            ),
            _artifact(
                owner,
                "chain_anti_absorption_applied_receipt.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.chain_anti_absorption_applied_receipt.v2",
                minimum_gate="LOSSLESS_FIELD_DIFF_AND_SOURCE_HASH_PARITY",
            ),
            _artifact(
                owner,
                "chain_grouping_debt.md",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                minimum_gate="INDEPENDENT_MEMBER_RETENTION_PROJECTION",
            ),
            _artifact(
                owner,
                "anti_absorption_repair.md",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                minimum_gate="OBSERVABILITY_ONLY_PROJECTION",
            ),
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif (
        phase_n in {"verify_aggregate", "sc_verify_aggregate"}
        and work_n == "independent_severity_reconcile"
    ):
        outputs = (
            _artifact(
                owner,
                "independent_severity_challenges.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.independent_severity_challenges.v1",
                minimum_gate="EXACT_QUEUE_AND_SOURCE_HASH_BINDING",
            ),
            _artifact(
                owner,
                "independent_severity_challenges.md",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                minimum_gate="CHALLENGE_ONLY_PROJECTION",
            ),
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif (
        phase_n in {"verify_aggregate", "sc_verify_aggregate"}
        and work_n == "empty_aggregate_projection"
    ):
        _fixed_output_set(
            exact_outputs,
            ("verify_core.md",),
            label=f"{phase_n}/{work_n}",
        )
        required_empty_inputs = {
            "verification_queue.md",
            "verification_queue.work_items.json",
            "verification_queue.work_plan.json",
        }
        if not required_empty_inputs.issubset(set(exact_inputs)):
            raise ValueError(
                f"{phase_n}/{work_n} requires the exact empty typed queue "
                "Markdown, work-item, and work-plan denominator"
            )
        outputs = (
            _artifact(
                owner,
                "verify_core.md",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                minimum_gate="EXACT_TYPED_ZERO_QUEUE_AGGREGATE_PROJECTION",
                consumers=(
                    "report_index/model",
                    "report_index/canonicalize",
                    "skeptic/model",
                    "crossbatch/model",
                ),
            ),
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif (
        phase_n in {"verify_aggregate", "sc_verify_aggregate"}
        and work_n == "external_assumption_undemotion_reconcile"
    ):
        outputs = (
            _artifact(
                owner,
                "external_assumption_undemotion_compute.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version=(
                    "plamen.external_assumption_undemotion_compute.v1"
                ),
                minimum_gate=(
                    "FULL_CANDIDATE_DENOMINATOR_AND_CURRENT_PRODUCER_REPLAY"
                ),
                consumers=("report_index/canonicalize",),
            ),
            _artifact(
                owner,
                "external_assumption_undemotions.json",
                artifact_class="CONDITIONAL",
                writer="DRIVER",
                condition_id="r10_fired",
                schema_version="plamen.external_assumption_undemotions.v1",
                minimum_gate="FIRED_RESULT_EXACT_REDERIVATION",
                consumers=("report_index/canonicalize",),
            ),
            _artifact(
                owner,
                "external_assumption_undemotions.md",
                artifact_class="CONDITIONAL",
                writer="DRIVER",
                condition_id="r10_fired",
                minimum_gate="COMPATIBILITY_PROJECTION_ONLY",
            ),
            _artifact(
                owner,
                "external_assumption_undemotion_debt.json",
                artifact_class="CONDITIONAL",
                writer="DRIVER",
                condition_id="r10_authority_debt",
                schema_version=(
                    "plamen.external_assumption_undemotion_debt.v1"
                ),
                minimum_gate="ZERO_AUTHORITY_REVERIFICATION_DEBT",
                consumers=("report_index/canonicalize", "skeptic/model"),
            ),
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif (
        phase_n == "severity_adjudication_shadow"
        and work_n.startswith("worker.")
    ):
        outputs = _dynamic_specs(
            owner,
            exact_outputs,
            writer="MODEL",
            conditional_output_ids=(),
            condition_id="",
        )
        immutable = _identities((
            "severity_adjudication_work_manifest.json",
            "severity_adjudication_work_plan.json",
            *exact_inputs,
        ))

    elif phase_n == "severity_adjudication_shadow" and work_n == "bind":
        outputs = _dynamic_specs(
            owner,
            exact_outputs,
            writer="DRIVER",
            conditional_output_ids=(),
            condition_id="",
        )
        immutable = _identities((
            "severity_adjudication_work_manifest.json",
            "severity_adjudication_work_plan.json",
            *exact_inputs,
        ))
        model_invoked = False

    elif (
        phase_n == "severity_adjudication_shadow"
        and work_n == "report_projection"
    ):
        outputs = (
            _artifact(
                owner,
                "severity_report_shadow_receipt.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.severity_report_shadow_receipt.v1",
                minimum_gate="CANDIDATE_TO_REPORT_PARITY",
            ),
        )
        immutable = _identities((
            "severity_decision_ledger.shadow.json",
            "report_index.md",
            "report_critical_high.md",
            "report_medium.md",
            "report_low_info.md",
        ))
        model_invoked = False

    elif (
        phase_n == "severity_adjudication_shadow"
        and work_n == "final_report_projection"
    ):
        outputs = (
            _artifact(
                owner,
                "severity_final_report_shadow_receipt.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.severity_report_shadow_receipt.v1",
                minimum_gate="FINAL_CANDIDATE_TO_REPORT_PARITY",
            ),
        )
        immutable = (
            *_identities((
                "severity_decision_ledger.shadow.json",
                "severity_report_shadow_receipt.json",
            )),
            canonical_artifact_identity("project", "AUDIT_REPORT.md"),
        )
        model_invoked = False

    elif phase_n == "exploration_clear" and work_n == "alias_authority":
        outputs = (
            _artifact(
                owner,
                "exploration_clear_prior_aliases.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.exploration_clear_prior_aliases.v1",
                minimum_gate="EXACT_CANONICAL_IDENTITY_PROJECTION",
            ),
        )
        immutable = _mixed_identities(exact_inputs)
        model_invoked = False

    elif (
        phase_n == "exploration_clear"
        and work_n in {"initial_compile.clean", "initial_compile.repair"}
    ):
        outputs = _dynamic_specs(
            owner, exact_outputs, writer="DRIVER",
            conditional_output_ids=(), condition_id="",
        )
        immutable = _mixed_identities(exact_inputs)
        model_invoked = False

    elif phase_n == "exploration_clear" and work_n == "repair_plan":
        if exact_outputs != ("exploration_clear_repair_plan.json",):
            raise ValueError(
                "exploration-clear repair plan requires its exact single output"
            )
        stable_prefix = (
            "exploration_skeptic_findings.md",
            "exploration_clear_prior_aliases.json",
        )
        project_loci = exact_inputs[len(stable_prefix):]
        if (
            exact_inputs[:len(stable_prefix)] != stable_prefix
            or len(exact_inputs) != len(set(exact_inputs))
            or any(
                not str(path).startswith("project::")
                for path in project_loci
            )
            or tuple(sorted(project_loci)) != project_loci
        ):
            raise ValueError(
                "exploration-clear repair plan requires the exact stable "
                "source, alias, and ordered project-locus denominator"
            )
        outputs = (
            _artifact(
                owner,
                "exploration_clear_repair_plan.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.exploration_clear_repair_plan.v1",
                minimum_gate="STABLE_SOURCE_ALIAS_LOCUS_REDERIVATION",
            ),
        )
        immutable = _mixed_identities(exact_inputs)
        model_invoked = False

    elif phase_n == "exploration_clear" and work_n == "repair_arm":
        outputs = (
            _artifact(
                owner,
                "exploration_clear_repair_attempt.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.exploration_clear_repair_attempt.v1",
                minimum_gate="AT_MOST_ONCE_ATTEMPT_BINDING",
            ),
        )
        immutable = _identities(("exploration_clear_repair_plan.json",))
        model_invoked = False

    elif phase_n == "exploration_clear" and work_n == "worker.0001":
        outputs = (
            _artifact(
                owner,
                "exploration_clear_repair_response.md",
                artifact_class="REQUIRED",
                writer="MODEL",
                minimum_gate="EXACT_REPAIR_PLAN_DISPOSITION_PARITY",
            ),
        )
        immutable = _identities((
            "exploration_clear_repair_plan.json",
            "exploration_clear_repair_attempt.json",
        ))

    elif phase_n == "exploration_clear" and work_n == "repair_terminal":
        outputs = (
            _artifact(
                owner,
                "exploration_clear_repair_failure.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.exploration_clear_repair_failure.v1",
                minimum_gate="EXACT_ABANDONED_MODEL_BINDING",
            ),
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif phase_n == "exploration_clear" and work_n == "repair_reconcile":
        outputs = (
            _artifact(
                owner,
                "exploration_clear_receipt.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.exploration_clear_receipt.v1",
                minimum_gate="EXACT_REPAIR_REDERIVATION",
            ),
            _artifact(
                owner,
                "exploration_clear_obligations.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.exploration_clear_obligation_queue.v1",
                minimum_gate="EXACT_RESIDUAL_TAIL",
            ),
        )
        immutable = _mixed_identities(exact_inputs)
        model_invoked = False

    elif phase_n == "exploration_skeptic" and work_n == "model":
        outputs = (
            _artifact(
                owner,
                "exploration_skeptic_findings.md",
                artifact_class="REQUIRED",
                writer="MODEL",
                minimum_gate="CONTENT_BEARING_EXPLORATION_COVERAGE",
            ),
        )
        immutable = _identities(exact_inputs)

    elif phase_n == "enumgap_exploration" and work_n == "model":
        outputs = (
            _artifact(
                owner,
                "enumgap_exploration_findings.md",
                artifact_class="REQUIRED",
                writer="MODEL",
                minimum_gate="EXACT_ENUMGAP_WORKLIST_DISPOSITION_PARITY",
            ),
        )
        immutable = _identities(exact_inputs)

    elif phase_n == "enumgap_exploration" and work_n == "empty_stub":
        outputs = (
            _artifact(
                owner,
                "enumgap_exploration_findings.md",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                minimum_gate="EXPLICIT_EMPTY_ENUMGAP_DENOMINATOR",
            ),
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif phase_n == "enumgap_disposition" and work_n == "planning":
        outputs = (
            _artifact(
                owner,
                "enumgap_worklist.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.enumgap_worklist.v1",
                minimum_gate="EXACT_INPUT_UNION",
            ),
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif phase_n == "enumgap_disposition" and work_n == "reconcile":
        outputs = (
            _artifact(
                owner,
                "enumgap_disposition_receipt.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.enumgap_disposition_receipt.v1",
                minimum_gate="INPUT_TO_DISPOSITION_PARITY",
            ),
            _artifact(
                owner,
                "enumgap_residual_obligations.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.enumgap_residual_obligations.v1",
                minimum_gate="EXACT_RESIDUAL_TAIL",
            ),
        )
        immutable = _mixed_identities(
            exact_inputs or (
                "enumgap_worklist.json",
                "enumgap_exploration_findings.md",
            )
        )
        model_invoked = False

    elif phase_n == "enumgap_delivery" and work_n == "inventory_append":
        outputs = (
            _artifact(
                owner,
                "findings_inventory.md",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="MERGE",
                minimum_gate="LOCKED_APPEND_PREFIX_AND_EXACT_DELIVERY",
            ),
            _artifact(
                owner,
                "enumgap_inventory_append_plan.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.enumgap_inventory_append_plan.v1",
                minimum_gate="EXACT_PREIMAGE_POSTIMAGE_PLAN",
            ),
            _artifact(
                owner,
                "enumgap_inventory_append_commit.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.enumgap_inventory_append_commit.v1",
                minimum_gate="EXACT_APPEND_COMMIT",
            ),
            _artifact(
                owner,
                "enumgap_exploration_promotion_receipt.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.enumgap_exploration_promotion_receipt.v1",
                minimum_gate="EXACT_ACTION_TO_INVENTORY_DELIVERY",
            ),
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif phase_n == "axis_disposition" and work_n == "planning":
        _fixed_output_set(
            exact_outputs,
            (
                "axis_disposition_worklist.json",
                "axis_execution_evidence_authority.json",
            ),
            label=f"{phase_n}/{work_n}",
        )
        immutable = _axis_input_identities(
            exact_inputs,
            required=(
                "_hot_function_axes.json",
                "_hot_function_cap_receipt.json",
            ),
            label=f"{phase_n}/{work_n}",
        )
        outputs = (
            _artifact(
                owner,
                "axis_disposition_worklist.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.axis_disposition_worklist.v2",
                minimum_gate=(
                    "EXACT_POPULATION_SOURCE_LOCUS_AND_ACTION_DENOMINATOR"
                ),
                consumers=(
                    "axis_coverage/model",
                    "axis_disposition/reconcile.initial",
                    "axis_disposition/reconcile.final",
                ),
            ),
            _artifact(
                owner,
                "axis_execution_evidence_authority.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.axis_execution_evidence_authority.v1",
                minimum_gate=(
                    "CURRENT_RUN_REGISTERED_PRE_AXIS_EVIDENCE_DENOMINATOR"
                ),
                consumers=(
                    "axis_coverage/model",
                    "axis_disposition/reconcile.initial",
                    "axis_disposition/reconcile.final",
                ),
            ),
        )
        model_invoked = False

    elif (
        phase_n == "axis_disposition"
        and work_n == "prior.snapshot"
    ):
        _fixed_output_set(
            exact_outputs,
            (
                "axis_canonical_prior_snapshot.json",
                "axis_canonical_prior_authority.json",
            ),
            label=f"{phase_n}/{work_n}",
        )
        immutable = _axis_input_identities(
            exact_inputs,
            required=("axis_disposition_worklist.json",),
            label=f"{phase_n}/{work_n}",
        )
        outputs = (
            _artifact(
                owner,
                "axis_canonical_prior_snapshot.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.axis_canonical_prior_snapshot.v1",
                minimum_gate=(
                    "EXACT_PRE_AXIS_IDENTITY_CAPTURE_OR_EXPLICIT_DEGRADED_AUTHORITY"
                ),
                consumers=(
                    "axis_coverage/model",
                    "axis_disposition/reconcile.initial",
                    "axis_coverage/repair.worker.0001",
                    "axis_disposition/reconcile.final",
                    "application_skeptic/negative.planning",
                    "assurance_limitations/compile",
                ),
            ),
            _artifact(
                owner,
                "axis_canonical_prior_authority.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.axis_canonical_prior_authority.v1",
                minimum_gate=(
                    "FROZEN_SNAPSHOT_ALIAS_REPLAY_AND_RUN_WORKLIST_BINDING"
                ),
                consumers=(
                    "axis_coverage/model",
                    "axis_disposition/reconcile.initial",
                    "axis_coverage/repair.worker.0001",
                    "axis_disposition/reconcile.final",
                    "application_skeptic/negative.planning",
                    "assurance_limitations/compile",
                ),
            ),
        )
        model_invoked = False

    elif phase_n == "axis_coverage" and work_n == "model":
        _fixed_output_set(
            exact_outputs,
            (
                "axis_coverage_findings.md",
                "axis_coverage_dispositions.json",
            ),
            label=f"{phase_n}/{work_n}",
        )
        immutable = _axis_input_identities(
            exact_inputs,
            required=(
                "axis_disposition_worklist.json",
                "axis_execution_evidence_authority.json",
                "findings_inventory.md",
                "axis_canonical_prior_snapshot.json",
                "axis_canonical_prior_authority.json",
            ),
            label=f"{phase_n}/{work_n}",
        )
        outputs = (
            _artifact(
                owner,
                "axis_coverage_findings.md",
                artifact_class="REQUIRED",
                writer="MODEL",
                minimum_gate="CONTENT_BEARING_ACTION_SUPPORT_PROJECTION",
                consumers=(
                    "axis_disposition/reconcile.initial",
                    "axis_disposition/reconcile.final",
                    "axis_disposition/promotion",
                ),
            ),
            _artifact(
                owner,
                "axis_coverage_dispositions.json",
                artifact_class="REQUIRED",
                writer="MODEL",
                schema_version="plamen.axis_model_dispositions.v1",
                minimum_gate="EXACT_AXW_CARDINALITY_AND_WORKLIST_HASH",
                consumers=(
                    "axis_disposition/reconcile.initial",
                    "axis_disposition/reconcile.final",
                    "axis_disposition/promotion",
                ),
            ),
        )

    elif (
        phase_n == "axis_disposition"
        and work_n == "reconcile.initial"
    ):
        _fixed_output_set(
            exact_outputs,
            (
                "axis_disposition_initial_receipt.json",
                "axis_repair_plan.json",
            ),
            label=f"{phase_n}/{work_n}",
        )
        immutable = _axis_input_identities(
            exact_inputs,
            required=(
                "axis_disposition_worklist.json",
                "axis_execution_evidence_authority.json",
                "axis_coverage_findings.md",
                "axis_coverage_dispositions.json",
                "axis_canonical_prior_snapshot.json",
                "axis_canonical_prior_authority.json",
            ),
            label=f"{phase_n}/{work_n}",
        )
        outputs = (
            _artifact(
                owner,
                "axis_disposition_initial_receipt.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.axis_disposition_initial_receipt.v1",
                minimum_gate="EXACT_BASE_DISPOSITION_RECONCILIATION",
                consumers=("axis_disposition/reconcile.final",),
            ),
            _artifact(
                owner,
                "axis_repair_plan.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.axis_repair_plan.v1",
                minimum_gate="EXACT_MISSING_OR_INVALID_AXW_SUBSET",
                consumers=(
                    "axis_coverage/repair.worker.0001",
                    "axis_disposition/repair.execution",
                    "axis_disposition/reconcile.final",
                ),
            ),
        )
        model_invoked = False

    elif (
        phase_n == "axis_coverage"
        and work_n == "repair.worker.0001"
    ):
        _fixed_output_set(
            exact_outputs,
            (
                "axis_coverage_repair_findings.md",
                "axis_coverage_repair_dispositions.json",
            ),
            label=f"{phase_n}/{work_n}",
        )
        immutable = _axis_input_identities(
            exact_inputs,
            required=(
                "axis_repair_plan.json",
                "axis_disposition_worklist.json",
                "axis_execution_evidence_authority.json",
                "axis_coverage_findings.md",
                "axis_coverage_dispositions.json",
                "axis_canonical_prior_snapshot.json",
                "axis_canonical_prior_authority.json",
            ),
            label=f"{phase_n}/{work_n}",
        )
        outputs = (
            _artifact(
                owner,
                "axis_coverage_repair_findings.md",
                artifact_class="REQUIRED",
                writer="MODEL",
                minimum_gate="EXACT_REPAIR_PLAN_ACTION_SUPPORT",
                consumers=(
                    "axis_disposition/repair.execution",
                    "axis_disposition/reconcile.final",
                    "axis_disposition/promotion",
                ),
            ),
            _artifact(
                owner,
                "axis_coverage_repair_dispositions.json",
                artifact_class="REQUIRED",
                writer="MODEL",
                schema_version="plamen.axis_repair_model_dispositions.v1",
                minimum_gate="EXACT_REPAIR_PLAN_SUBSET_AND_NO_BASE_OVERRIDE",
                consumers=(
                    "axis_disposition/repair.execution",
                    "axis_disposition/reconcile.final",
                    "axis_disposition/promotion",
                ),
            ),
        )

    elif (
        phase_n == "axis_disposition"
        and work_n == "repair.execution"
    ):
        _fixed_output_set(
            exact_outputs,
            ("axis_repair_execution_receipt.json",),
            label=f"{phase_n}/{work_n}",
        )
        immutable = _axis_input_identities(
            exact_inputs,
            required=("axis_repair_plan.json",),
            label=f"{phase_n}/{work_n}",
            paired=((
                "axis_coverage_repair_findings.md",
                "axis_coverage_repair_dispositions.json",
            ),),
        )
        outputs = (
            _artifact(
                owner,
                "axis_repair_execution_receipt.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.axis_repair_execution_receipt.v1",
                minimum_gate="BOUNDED_REPAIR_EXECUTION_STATE",
                consumers=("axis_disposition/reconcile.final",),
            ),
        )
        model_invoked = False

    elif (
        phase_n == "axis_disposition"
        and work_n == "reconcile.final"
    ):
        _fixed_output_set(
            exact_outputs,
            (
                "axis_disposition_receipt.json",
                "axis_repair_work.json",
                "axis_assurance_debt.json",
                "axis_assurance_limitations.md",
            ),
            label=f"{phase_n}/{work_n}",
        )
        immutable = _axis_input_identities(
            exact_inputs,
            required=(
                "axis_disposition_worklist.json",
                "axis_execution_evidence_authority.json",
                "axis_coverage_findings.md",
                "axis_coverage_dispositions.json",
                "axis_disposition_initial_receipt.json",
                "axis_repair_plan.json",
                "axis_repair_execution_receipt.json",
                "axis_canonical_prior_snapshot.json",
                "axis_canonical_prior_authority.json",
            ),
            label=f"{phase_n}/{work_n}",
            paired=((
                "axis_coverage_repair_findings.md",
                "axis_coverage_repair_dispositions.json",
            ),),
        )
        outputs = (
            _artifact(
                owner,
                "axis_disposition_receipt.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version=(
                    "plamen.axis_disposition_application_receipt.v2"
                ),
                minimum_gate="EXACT_BASE_REPAIR_AND_EXECUTION_RECONCILIATION",
                consumers=(
                    "axis_disposition/promotion",
                    "application_skeptic/negative.planning",
                ),
            ),
            _artifact(
                owner,
                "axis_repair_work.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.axis_repair_work.v2",
                minimum_gate="EXACT_FINAL_RESIDUAL_WORK",
                consumers=("assurance_limitations/compile",),
            ),
            _artifact(
                owner,
                "axis_assurance_debt.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.axis_assurance_debt.v2",
                minimum_gate="EXACT_UNRESOLVED_AND_DEGRADED_TAIL",
                consumers=("assurance_limitations/compile",),
            ),
            _artifact(
                owner,
                "axis_assurance_limitations.md",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.axis_assurance_limitations_projection.v1",
                minimum_gate="EXACT_AXIS_ASSURANCE_DEBT_PROJECTION",
                consumers=("assurance_limitations/compile",),
            ),
        )
        model_invoked = False

    elif (
        phase_n == "axis_disposition"
        and work_n == "promotion.plan"
    ):
        _fixed_output_set(
            exact_outputs,
            ("axis_coverage_promotion_plan.json",),
            label=f"{phase_n}/{work_n}",
        )
        immutable = _axis_input_identities(
            exact_inputs,
            required=(
                "axis_disposition_receipt.json",
                "findings_inventory.md",
            ),
            label=f"{phase_n}/{work_n}",
            paired=(
                (
                    "axis_coverage_findings.md",
                    "axis_coverage_dispositions.json",
                ),
                (
                    "axis_coverage_repair_findings.md",
                    "axis_coverage_repair_dispositions.json",
                ),
            ),
        )
        outputs = (
            _artifact(
                owner,
                "axis_coverage_promotion_plan.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.axis_coverage_promotion_plan.v1",
                minimum_gate=(
                    "EXACT_PREMUTATION_INVENTORY_PREDECESSOR_SUCCESSOR_CAS"
                ),
                consumers=("axis_disposition/promotion",),
            ),
        )
        model_invoked = False

    elif phase_n == "axis_disposition" and work_n == "promotion":
        _fixed_output_set(
            exact_outputs,
            (
                "findings_inventory.md",
                "axis_coverage_promotion_receipt.json",
            ),
            label=f"{phase_n}/{work_n}",
        )
        immutable = _axis_input_identities(
            exact_inputs,
            required=(
                "axis_coverage_promotion_plan.json",
            ),
            label=f"{phase_n}/{work_n}",
        )
        outputs = (
            _artifact(
                owner,
                "findings_inventory.md",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="MERGE",
                schema_version="plamen.canonical_finding_inventory.v1",
                minimum_gate=(
                    "LOCKED_EXPECTED_PRESTATE_REFERENCED_ACTION_DELIVERY"
                ),
                consumers=("semantic_dedup/prequeue_apply",),
                external_preimage_validator="plamen.axis_inventory_prestate.v1",
            ),
            _artifact(
                owner,
                "axis_coverage_promotion_receipt.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.axis_coverage_promotion_receipt.v2",
                minimum_gate="EXACT_ACTION_TO_INVENTORY_DELIVERY",
                consumers=(
                    "application_skeptic/negative.planning",
                    "assurance_limitations/compile",
                    "semantic_dedup/prequeue_apply",
                ),
            ),
        )
        model_invoked = False

    elif phase_n == "application_skeptic" and work_n.startswith("worker."):
        ordinal = work_n.rsplit(".", 1)[-1]
        authority_output = (
            f"application_skeptic_provider_authority_{ordinal}.json"
        )
        if exact_inputs:
            raise ValueError(
                "application skeptic worker inputs are fixed by its work plan"
            )
        if set(exact_outputs) != {
            f"application_skeptic_assessments_{ordinal}.json",
            authority_output,
        } or len(exact_outputs) != 2:
            raise ValueError(
                "application skeptic worker must publish its exact assessment "
                "and provider authority"
            )
        outputs = _dynamic_specs(
            owner, exact_outputs, writer="DRIVER",
            conditional_output_ids=(), condition_id="",
        )
        immutable = _identities((
            "application_skeptic_work_plan.json",
        ))

    elif (
        phase_n == "application_skeptic"
        and work_n.startswith("negative.worker.")
    ):
        ordinal = work_n.rsplit(".", 1)[-1]
        authority_output = (
            f"candidate_negative_skeptic_provider_authority_{ordinal}.json"
        )
        if exact_inputs:
            raise ValueError(
                "candidate-negative skeptic worker inputs are fixed by its work plan"
            )
        if set(exact_outputs) != {
            f"candidate_negative_skeptic_assessments_{ordinal}.json",
            authority_output,
        } or len(exact_outputs) != 2:
            raise ValueError(
                "candidate-negative skeptic worker must publish its exact "
                "assessment and provider authority"
            )
        outputs = _dynamic_specs(
            owner, exact_outputs, writer="DRIVER",
            conditional_output_ids=(), condition_id="",
        )
        immutable = _identities((
            "candidate_negative_skeptic_work_plan.json",
        ))

    elif phase_n == "application_skeptic" and work_n == "reconcile":
        outputs = (
            _artifact(
                owner, "application_skeptic_receipt.json",
                artifact_class="DRIVER_GENERATED", writer="DRIVER",
                schema_version="plamen.application_skeptic_receipt.v1",
                minimum_gate="INPUT_TO_DISPOSITION_PARITY",
            ),
            _artifact(
                owner, "application_skeptic_proposals.md",
                artifact_class="DRIVER_GENERATED", writer="DRIVER",
                minimum_gate="REGISTERED_CANDIDATE_DELIVERY",
            ),
            _artifact(
                owner,
                "application_skeptic_delivery_binding.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.application_skeptic_delivery_binding.v1",
                minimum_gate="EXACT_LAST_GOOD_DELIVERY_BINDING",
            ),
        )
        immutable = _identities(
            ("application_skeptic_work_plan.json", *exact_inputs)
        )
        model_invoked = False

    elif phase_n == "application_skeptic" and work_n == "negative.reconcile":
        outputs = (
            _artifact(
                owner,
                "candidate_negative_skeptic_receipt.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.application_skeptic_receipt.v1",
                minimum_gate="CANDIDATE_NEGATIVE_INPUT_TO_DISPOSITION_PARITY",
            ),
            _artifact(
                owner,
                "candidate_negative_skeptic_proposals.md",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                minimum_gate="REGISTERED_REOPENED_CANDIDATE_DELIVERY",
            ),
            _artifact(
                owner,
                "candidate_negative_denominator.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.candidate_negative_denominator.v1",
                minimum_gate="EXACT_CANDIDATE_NEGATIVE_DENOMINATOR",
            ),
        )
        immutable = _identities(
            ("candidate_negative_skeptic_work_plan.json", *exact_inputs)
        )
        model_invoked = False

    elif work_n == "methodology_repair.model":
        source = _canonical_component(source_phase or phase_n, "source_phase")
        repair_output = {
            "breadth": "analysis_methodology_repair_breadth.md",
            "rescan": "analysis_methodology_repair_rescan.md",
            "depth": "depth_methodology_repair_findings.md",
        }.get(source)
        if repair_output is None:
            raise ValueError(
                f"unsupported methodology repair source phase: {source}"
            )
        if tuple(exact_outputs) != (repair_output,):
            raise ValueError(
                "methodology repair model output denominator must be exact"
            )
        outputs = (
            _artifact(
                owner,
                repair_output,
                artifact_class="CONDITIONAL",
                writer="MODEL",
                condition_id="methodology_application_gap_present",
                minimum_gate="METHODOLOGY_APPLICATION_TRACE",
            ),
        )
        immutable = _identities(
            (
                f"methodology_repair_queue_{source}.json",
                f"skill_application_receipt_{source}.json",
            )
        )

    elif work_n == "methodology_repair":
        source = _canonical_component(source_phase or phase_n, "source_phase")
        repair_output = {
            "breadth": "analysis_methodology_repair_breadth.md",
            "rescan": "analysis_methodology_repair_rescan.md",
            "depth": "depth_methodology_repair_findings.md",
        }.get(source)
        if repair_output is None:
            raise ValueError(f"unsupported methodology repair source phase: {source}")
        outputs = (
            _artifact(
                owner, repair_output,
                artifact_class="CONDITIONAL", writer="MODEL",
                condition_id="methodology_application_gap_present",
                minimum_gate="METHODOLOGY_APPLICATION_TRACE",
            ),
            _artifact(
                owner, "skill_dispatch.json",
                artifact_class="DRIVER_GENERATED", writer="DRIVER",
                write_mode="MERGE", schema_version="plamen.skill_dispatch.v1",
            ),
            _artifact(
                owner, f"methodology_repair_attempt_{source}.json",
                artifact_class="DRIVER_GENERATED", writer="DRIVER",
                schema_version="plamen.methodology_repair_attempt.v1",
            ),
            _artifact(
                owner, f"skill_application_receipt_{source}_repair.json",
                artifact_class="DRIVER_GENERATED", writer="DRIVER",
                schema_version="plamen.skill_application_receipt.v2",
            ),
            _artifact(
                owner, f"skill_execution_gaps_{source}_repair.md",
                artifact_class="DRIVER_GENERATED", writer="DRIVER",
            ),
            _artifact(
                owner, f"methodology_repair_queue_{source}_repair.json",
                artifact_class="DRIVER_GENERATED", writer="DRIVER",
                schema_version="plamen.methodology_repair_queue.v2",
            ),
            _artifact(
                owner, f"methodology_skeptic_queue_{source}_repair.json",
                artifact_class="DRIVER_GENERATED", writer="DRIVER",
                schema_version="plamen.methodology_skeptic_queue.v2",
            ),
            _artifact(
                owner, f"report_semantic_methodology_application_{source}.md",
                artifact_class="CONDITIONAL", writer="DRIVER",
                condition_id="methodology_application_debt_present",
            ),
        )
        # The shared dispatch is a driver-owned MERGE target. Its post-merge
        # bytes are an exact output, but it is not also declared as an input:
        # a single receipt cannot bind both preimage and postimage without a
        # separate typed read-modify-write/CAS transaction.
        immutable = _identities((
            f"methodology_repair_queue_{source}.json",
            f"skill_application_receipt_{source}.json",
        ))

    elif phase_n == "recon" and work_n == "skill_selection_authority":
        outputs = (
            _artifact(
                owner,
                "skill_selection_catalog.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.skill_selection_catalog.v1",
                minimum_gate="EXACT_POLARITY_AND_METHODOLOGY_HASH_BINDING",
            ),
        )
        # The driver passes the exact active producer set.  Thorough/Core use
        # the isolated recon selection shard; legacy/direct paths may bind the
        # canonical template handoff instead.  No glob or disk enumeration is
        # hidden inside the contract resolver.
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif (
        phase_n == "instantiate"
        and (
            work_n == "model"
            or work_n.startswith("model.attempt-")
        )
    ):
        outputs = _dynamic_specs(
            owner,
            exact_outputs or ("spawn_manifest_proposal.md",),
            writer="MODEL",
            conditional_output_ids=(),
            condition_id="",
        )
        immutable = _identities(exact_inputs)

    elif (
        phase_n == "instantiate"
        and (
            work_n == "manifest_reconcile"
            or work_n.startswith("manifest_reconcile.attempt-")
        )
    ):
        outputs = (
            _artifact(
                owner,
                "spawn_manifest.md",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                minimum_gate="SPAWN_SCHEMA_AND_RECALL_SAFE_NICHE_UNION",
            ),
            _artifact(
                owner,
                "instantiate_manifest_reconcile_receipt.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.instantiate_manifest_reconcile.v1",
            ),
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif phase_n == "instantiate" and work_n == "skill_consumer_authority":
        outputs = (
            _artifact(
                owner,
                "skill_consumer_coverage.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.skill_consumer_coverage.v1",
                minimum_gate="ALL_DECLARED_CONSUMER_DISPOSITION_PARITY",
            ),
        )
        immutable = _identities((
            "skill_selection_catalog.json",
            "spawn_manifest.md",
        ))
        model_invoked = False

    elif phase_n == "recon" and (
        work_n == "prepass"
        or re.fullmatch(r"prepass\.attempt-\d{4}", work_n) is not None
    ):
        prepass_attempt = re.fullmatch(
            r"prepass\.attempt-(\d{4})", work_n
        )
        if prepass_attempt is not None and int(prepass_attempt.group(1)) < 2:
            raise ValueError(
                "recon prepass successor ordinal must be at least 0002"
            )
        registered = (
            (
                "subsystem_map.md",
                "trust_boundaries.md",
                "attack_surface.md",
                "threat_model.md",
                "template_recommendations.md",
                "recon_summary.md",
                "meta_buffer.md",
                "external_dependency_research.md",
            )
            if pipeline_n == "l1"
            else (
                "contract_inventory.md",
                "state_variables.md",
                "function_list.md",
                "build_status.md",
                "design_context.md",
                "attack_surface.md",
                "detected_patterns.md",
                "setter_list.md",
                "emit_list.md",
                "template_recommendations.md",
                "recon_summary.md",
                "meta_buffer.md",
                "external_dependency_research.md",
            )
        )
        registered = (*registered, "recon_prepass_publication_receipt.json")
        if exact_outputs and tuple(exact_outputs) != registered:
            raise ValueError(
                "recon/prepass output denominator is fixed by pipeline authority"
            )
        if exact_inputs:
            raise ValueError(
                "recon/prepass source/config authority is receipt-bound and "
                "cannot be caller-narrowed"
            )
        outputs = tuple(
            _artifact(
                owner,
                path,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode=(
                    "REPLACE" if prepass_attempt is not None else "CREATE"
                ),
                schema_version=(
                    "plamen.recon_prepass_publication.v2"
                    if path == "recon_prepass_publication_receipt.json"
                    else "unstructured.v1"
                ),
                minimum_gate="COMPLETE_SELECTED_PREPASS_PUBLICATION",
            )
            for path in registered
        )
        model_invoked = False

    elif (
        phase_n == "recon"
        and _RECON_DIRECT_RETRY_RE.fullmatch(work_n) is not None
    ):
        match = _RECON_DIRECT_RETRY_RE.fullmatch(work_n)
        assert match is not None
        registered_private_outputs = recon_direct_retry_output_paths(
            pipeline_n, int(match.group(1))
        )
        if not exact_inputs:
            raise ValueError(
                f"{phase_n}/{work_n} requires caller-supplied exact inputs"
            )
        if not exact_outputs:
            raise ValueError(
                f"{phase_n}/{work_n} requires caller-supplied exact outputs"
            )
        registered_inputs = _fixed_path_set(
            exact_inputs,
            _RECON_DIRECT_RETRY_INPUTS,
            label=f"{phase_n}/{work_n} inputs",
        )
        registered_outputs = _fixed_output_set(
            exact_outputs,
            registered_private_outputs,
            label=f"{phase_n}/{work_n} outputs",
        )
        outputs = tuple(
            _artifact(
                owner,
                path,
                artifact_class="REQUIRED",
                writer="MODEL",
                write_mode="REPLACE",
                schema_version="plamen.recon_direct_retry_markdown.v1",
                minimum_gate="RECON_CANONICAL_STRUCTURE",
            )
            for path in registered_outputs
        )
        immutable = _identities(registered_inputs)

    elif phase_n == "recon" and work_n.startswith("worker."):
        outputs = _dynamic_specs(
            owner, exact_outputs, writer="MODEL",
            conditional_output_ids=conditional_output_ids,
            condition_id=condition_id,
        )
        default_inputs = (
            ("primitive_status.md",)
            if pipeline_n == "l1"
            else (
                "contract_inventory.md", "function_list.md",
                "state_variables.md", "meta_buffer.md",
            )
        )
        if exact_inputs:
            normalized_inputs = tuple(
                _canonical_relative_path(path) for path in exact_inputs
            )
            allowed_inputs = {
                *default_inputs,
                "recon_retry_plan.json",
                _IMPACT_MAP_EVIDENCE_FILE,
            }
            if (
                not set(default_inputs).issubset(normalized_inputs)
                or set(normalized_inputs) - allowed_inputs
            ):
                raise ValueError(
                    "recon worker inputs must be its exact registered prepass "
                    "evidence plus only recon_retry_plan.json on retry"
                )
        else:
            normalized_inputs = default_inputs
        if pipeline_n == "l1":
            immutable = _identities(normalized_inputs)
        else:
            bounded = _identities(normalized_inputs)

    elif phase_n == "recon" and work_n == "dependency_obligations.source_capture":
        _fixed_path_set(exact_inputs, (), label=f"{phase_n}/{work_n}")
        _fixed_output_set(
            exact_outputs,
            ("dependency_obligations_preexecution_authority.json",),
            label=f"{phase_n}/{work_n}",
        )
        outputs = (
            _artifact(
                owner,
                "dependency_obligations_preexecution_authority.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="REPLACE",
                schema_version="plamen.dependency-obligations-preexecution-authority.v1",
                minimum_gate="DEPENDENCY_PREEXECUTION_AUTHORITY",
            ),
        )
        model_invoked = False

    elif phase_n == "recon" and work_n == "dependency_obligations":
        _fixed_path_set(
            exact_inputs,
            ("dependency_obligations_preexecution_authority.json",),
            label=f"{phase_n}/{work_n}",
        )
        _fixed_output_set(
            exact_outputs,
            ("external_dependency_obligations.json",),
            label=f"{phase_n}/{work_n}",
        )
        outputs = (
            _artifact(
                owner,
                "external_dependency_obligations.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="REPLACE",
                schema_version="plamen.external_dependency_obligations.v1",
                minimum_gate="DEPENDENCY_OBLIGATION_AUTHORITY",
            ),
        )
        immutable = _identities((
            "dependency_obligations_preexecution_authority.json",
        ))
        model_invoked = False

    elif (
        phase_n == "recon"
        and (
            dependency_research_match := (
                _RECON_DEPENDENCY_RESEARCH_RETRY_RE.fullmatch(work_n)
            )
        )
        is not None
    ):
        retry_ordinal = dependency_research_match.group(1)
        if retry_ordinal is not None and int(retry_ordinal) < 2:
            raise ValueError(
                "recon dependency-research retry ordinal must be at least 0002"
            )
        if pipeline_n != "sc" or mode_n not in {
            "light", "core", "thorough",
        }:
            raise ValueError(
                "recon dependency research is registered only for SC "
                "Light/Core/Thorough"
            )
        base_shards = (
            _RECON_LIGHT_SHARDS if mode_n == "light" else _RECON_SHARDS
        )
        registered_inputs = (
            *_RECON_DEPENDENCY_RESEARCH_INPUT,
            *base_shards,
        )
        _fixed_path_set(
            exact_inputs,
            registered_inputs,
            label=f"{phase_n}/{work_n}",
        )
        _fixed_output_set(
            exact_outputs,
            _RECON_DEPENDENCY_RESEARCH_OUTPUT,
            label=f"{phase_n}/{work_n}",
        )
        if conditional_output_ids:
            _fixed_path_set(
                conditional_output_ids,
                _RECON_DEPENDENCY_RESEARCH_OUTPUT,
                label="recon dependency research conditional outputs",
            )
        if condition_id and condition_id != (
            "external_dependency_obligations_present"
        ):
            raise ValueError(
                "recon dependency research condition_id differs from the "
                "registered obligation predicate"
            )
        outputs = (
            _artifact(
                owner, "recon_external_dependency_research.md",
                artifact_class="CONDITIONAL", writer="MODEL",
                condition_id="external_dependency_obligations_present",
                minimum_gate="DEPENDENCY_ROW_PARITY",
            ),
        )
        immutable = _identities(_RECON_DEPENDENCY_RESEARCH_INPUT)
        bounded = _identities(base_shards)

    elif phase_n == "recon" and work_n == "dependency_reconcile.source_capture":
        _fixed_path_set(
            exact_inputs,
            ("external_dependency_obligations.json",),
            label=f"{phase_n}/{work_n}",
        )
        _fixed_output_set(
            exact_outputs,
            ("dependency_reconcile_preexecution_authority.json",),
            label=f"{phase_n}/{work_n}",
        )
        immutable = _identities(("external_dependency_obligations.json",))
        outputs = (
            _artifact(
                owner,
                "dependency_reconcile_preexecution_authority.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="REPLACE",
                schema_version="plamen.dependency-reconcile-preexecution-authority.v1",
                minimum_gate="DEPENDENCY_PREEXECUTION_AUTHORITY",
            ),
        )
        model_invoked = False

    elif (
        phase_n == "recon"
        and work_n == "dependency_reconcile.source_capture.active_research"
    ):
        _fixed_path_set(
            exact_inputs,
            (
                "external_dependency_obligations.json",
                "recon_external_dependency_research.md",
            ),
            label=f"{phase_n}/{work_n}",
        )
        _fixed_output_set(
            exact_outputs,
            ("dependency_reconcile_preexecution_authority.json",),
            label=f"{phase_n}/{work_n}",
        )
        immutable = _identities((
            "external_dependency_obligations.json",
            "recon_external_dependency_research.md",
        ))
        outputs = (
            _artifact(
                owner,
                "dependency_reconcile_preexecution_authority.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="REPLACE",
                schema_version=(
                    "plamen.dependency-reconcile-preexecution-authority.v1"
                ),
                minimum_gate="DEPENDENCY_PREEXECUTION_AUTHORITY",
            ),
        )
        model_invoked = False

    elif phase_n == "recon" and work_n in {
        "dependency_reconcile",
        "dependency_reconcile.active_research",
    }:
        outputs = (
            _artifact(
                owner, "external_dependency_research.md",
                artifact_class="DRIVER_GENERATED", writer="DRIVER",
                write_mode="REPLACE", minimum_gate="DEPENDENCY_ROW_PARITY",
            ),
            _artifact(
                owner, "report_semantic_dependency_research.md",
                artifact_class="CONDITIONAL", writer="DRIVER",
                condition_id="dependency_research_debt_present",
            ),
        )
        immutable = _identities((
            "dependency_reconcile_preexecution_authority.json",
            "external_dependency_obligations.json",
        ))
        model_invoked = False

    elif phase_n == "recon" and work_n == "dependency_research_debt":
        _fixed_path_set(
            exact_inputs,
            (),
            label=f"{phase_n}/{work_n}",
        )
        _fixed_output_set(
            exact_outputs,
            ("report_semantic_dependency_research.md",),
            label=f"{phase_n}/{work_n}",
        )
        outputs = (
            _artifact(
                owner,
                "report_semantic_dependency_research.md",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="REPLACE",
                schema_version="plamen.report_dependency_research_debt.v1",
                minimum_gate="HALTLESS_DEPENDENCY_RESEARCH_UNKNOWN",
                consumers=("report_assemble/source_capture",),
            ),
        )
        model_invoked = False

    elif phase_n == "recon" and work_n == "supplementary_disposition.source_capture":
        _fixed_path_set(
            exact_inputs,
            ("recon_summary.md",),
            label=f"{phase_n}/{work_n}",
        )
        _fixed_output_set(
            exact_outputs,
            ("recon_supplementary_disposition_input_authority.json",),
            label=f"{phase_n}/{work_n}",
        )
        immutable = _identities(("recon_summary.md",))
        outputs = (
            _artifact(
                owner,
                "recon_supplementary_disposition_input_authority.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="REPLACE",
                schema_version="plamen.recon-supplementary-input-authority.v1",
                minimum_gate="COMPLETE_SUPPLEMENTARY_INPUT_AUTHORITY",
            ),
        )
        model_invoked = False

    elif phase_n == "recon" and work_n == "supplementary_disposition":
        _fixed_path_set(
            exact_inputs,
            (
                "recon_summary.md",
                "recon_supplementary_disposition_input_authority.json",
            ),
            label=f"{phase_n}/{work_n}",
        )
        _fixed_output_set(
            exact_outputs,
            (
                "recon_supplementary_disposition.json",
                "recon_supplementary_disposition_receipt.json",
            ),
            label=f"{phase_n}/{work_n}",
        )
        immutable = _identities((
            "recon_summary.md",
            "recon_supplementary_disposition_input_authority.json",
        ))
        outputs = (
            _artifact(
                owner,
                "recon_supplementary_disposition.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="REPLACE",
                schema_version="plamen.recon_supplementary_disposition.v1",
                minimum_gate="COMPLETE_SUPPLEMENTARY_DISPOSITION",
            ),
            _artifact(
                owner,
                "recon_supplementary_disposition_receipt.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="REPLACE",
                schema_version="plamen.recon_supplementary_disposition_receipt.v1",
                minimum_gate="COMPLETE_SUPPLEMENTARY_DISPOSITION",
            ),
        )
        model_invoked = False

    elif phase_n == "recon" and work_n == "audit_input_limitations":
        _fixed_path_set(
            exact_inputs,
            (),
            label=f"{phase_n}/{work_n}",
        )
        _fixed_output_set(
            exact_outputs,
            ("report_semantic_audit_input_limitations.md",),
            label=f"{phase_n}/{work_n}",
        )
        outputs = (
            _artifact(
                owner,
                "report_semantic_audit_input_limitations.md",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="CREATE",
                schema_version="plamen.report_audit_input_limitations.v1",
                minimum_gate="SNAPSHOT_BOUND_COVERAGE_LIMITATIONS",
                consumers=("report_assemble/source_capture",),
            ),
        )
        model_invoked = False

    elif phase_n == "recon" and work_n == "canonical_merge":
        if pipeline_n == "l1":
            canonical_outputs = _L1_RECON_CANONICAL_OUTPUTS
            canonical_inputs = (
                _L1_RECON_LIGHT_SHARDS
                if mode_n == "light"
                else _L1_RECON_SHARDS
            )
        else:
            canonical_outputs = _RECON_CANONICAL_OUTPUTS
            canonical_inputs = (
                _RECON_LIGHT_SHARDS
                if mode_n == "light"
                else _RECON_SHARDS
            )
        canonical_outputs = (*canonical_outputs, _RECON_TRANSFORM_RECEIPT)
        retry_inputs = _canonical_retry_generation_inputs(
            exact_inputs, canonical_inputs, canonical_outputs
        )
        canonical_inputs = (
            retry_inputs
            if retry_inputs is not None
            else _fixed_path_set(
                exact_inputs,
                canonical_inputs,
                label=f"{phase_n}/{work_n} inputs",
            )
        )
        _fixed_output_set(
            exact_outputs,
            canonical_outputs,
            label=f"{phase_n}/{work_n} outputs",
        )
        outputs = tuple(
            _artifact(
                owner, path,
                artifact_class="DRIVER_GENERATED", writer="DRIVER",
                minimum_gate=(
                    "RECON_SIGNAL_TRANSFORM_RECEIPT"
                    if path == _RECON_TRANSFORM_RECEIPT
                    else "RECON_CANONICAL_STRUCTURE"
                ),
            )
            for path in canonical_outputs
        )
        immutable = _identities(canonical_inputs)
        model_invoked = False

    elif phase_n == "graph_sweeps" and work_n.startswith("worker."):
        if pipeline_n != "l1" or mode_n != "thorough":
            raise ValueError(
                "graph-sweep workers are scheduled only for L1 Thorough"
            )
        if len(exact_outputs) != 1:
            raise ValueError(
                "graph-sweep worker requires exactly one output"
            )
        output_name = _canonical_relative_path(exact_outputs[0])
        if (
            re.fullmatch(r"coverage_fill_[1-9][0-9]*\.md", output_name)
            is None
            and re.fullmatch(r"panic_audit_[1-9][0-9]*\.md", output_name)
            is None
            and output_name
            not in {
                "symmetric_pair_findings.md",
                "field_validation_matrix.md",
                "primitive_correctness_findings.md",
                "network_amplification_findings.md",
                "lifecycle_replay_findings.md",
            }
        ):
            raise ValueError(
                f"unregistered graph-sweep worker output: {output_name}"
            )
        queue_name = (
            "_graph_sweep_queue_"
            + PurePosixPath(output_name).stem
            + ".json"
        )
        outputs = (
            _artifact(
                owner,
                output_name,
                artifact_class="REQUIRED",
                writer="MODEL",
                schema_version="plamen.l1_graph_sweep_markdown.v1",
                minimum_gate="EXACT_QUEUE_ROW_DISPOSITION_AND_EVIDENCE",
            ),
        )
        immutable = _identities((
            "_graph_sweep_plan.json",
            queue_name,
        ))
        bounded = _identities((
            "subsystem_coverage_gap.md",
            "scip/panic_sites.md",
            "scip/repo_map.md",
            "scip/xref_map.md",
            "scip/call_graph_p2p.md",
            "scip/call_graph_consensus.md",
            "scip/call_graph_execution.md",
            "scip/type_hierarchy.md",
            "scip/concurrency_inventory.md",
            "recon_summary.md",
            "threat_model.md",
            "subsystem_map.md",
            "attack_surface.md",
            "trust_boundaries.md",
        ))

    elif phase_n == "location_recovery" and work_n == "worklist":
        if pipeline_n != "l1" or mode_n != "thorough":
            raise ValueError(
                "location-recovery worklist is L1 Thorough-only"
            )
        _fixed_output_set(
            exact_outputs,
            (
                "_location_recovery_worklist.json",
                "_location_recovery_inventory_preimage.md",
            ),
            label=f"{phase_n}/{work_n}",
        )
        outputs = (
            _artifact(
                owner,
                "_location_recovery_worklist.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.l1_location_recovery_worklist.v1",
                minimum_gate="EXACT_UNRESOLVED_FINDING_DENOMINATOR",
                consumers=("location_recovery/worker.location_recovery",),
            ),
            _artifact(
                owner,
                "_location_recovery_inventory_preimage.md",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.canonical_finding_inventory.v1",
                minimum_gate="BYTE_EXACT_INVENTORY_PREIMAGE",
                consumers=("location_recovery/worker.location_recovery",),
            ),
        )
        immutable = _identities(("findings_inventory.md",))
        bounded = _identities(("inventory_evidence_validation.md",))
        model_invoked = False

    elif (
        phase_n == "location_recovery"
        and work_n.startswith("worker.")
    ):
        if pipeline_n != "l1" or mode_n != "thorough":
            raise ValueError(
                "location-recovery model is L1 Thorough-only"
            )
        _fixed_output_set(
            exact_outputs,
            ("location_recovery_proposals.md",),
            label=f"{phase_n}/{work_n}",
        )
        outputs = (
            _artifact(
                owner,
                "location_recovery_proposals.md",
                artifact_class="REQUIRED",
                writer="MODEL",
                schema_version="plamen.l1_location_recovery_proposals.v1",
                minimum_gate="ONE_PROPOSAL_PER_UNRESOLVED_FINDING",
                consumers=("location_recovery/reconcile",),
            ),
        )
        immutable = _identities((
            "_location_recovery_worklist.json",
            "_location_recovery_inventory_preimage.md",
        ))
        bounded = _identities(("scip/repo_map.md",))

    elif phase_n == "location_recovery" and work_n == "reconcile":
        if pipeline_n != "l1" or mode_n != "thorough":
            raise ValueError(
                "location-recovery reconciliation is L1 Thorough-only"
            )
        _fixed_output_set(
            exact_outputs,
            ("location_recovery.md",),
            label=f"{phase_n}/{work_n}",
        )
        outputs = (
            _artifact(
                owner,
                "location_recovery.md",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.l1_location_recovery_projection.v1",
                minimum_gate=(
                    "EXACT_WORKLIST_PARITY_AND_MECHANICAL_LOCATION_VALIDATION"
                ),
            ),
        )
        immutable = _identities((
            "_location_recovery_worklist.json",
            "location_recovery_proposals.md",
        ))
        model_invoked = False

    elif phase_n == "rescan_prepare" and work_n == "python":
        outputs = (
            _artifact(
                owner, "rescan_manifest.md",
                artifact_class="DRIVER_GENERATED", writer="DRIVER",
                schema_version="plamen.rescan_manifest.v1",
                minimum_gate="MANIFEST_EXACT_OUTPUTS",
            ),
        )
        immutable = _identities(("contract_inventory.md",))
        model_invoked = False

    elif phase_n == "inventory" and work_n == "model":
        outputs = (
            _artifact(
                owner,
                "findings_inventory.md",
                artifact_class="REQUIRED",
                writer="MODEL",
                minimum_gate="CONTENT_BEARING_INVENTORY",
            ),
        )
        immutable = _identities(exact_inputs)

    elif phase_n == "post_verify_extract" and work_n == "model":
        _fixed_output_set(
            exact_outputs,
            ("post_verify_extract.md",),
            label=f"{phase_n}/{work_n}",
        )
        if not exact_inputs:
            raise ValueError(
                "post_verify_extract/model requires its exact verifier "
                "and candidate denominator"
            )
        outputs = (
            _artifact(
                owner,
                "post_verify_extract.md",
                artifact_class="REQUIRED",
                writer="MODEL",
                write_mode="REPLACE",
                schema_version="plamen.post_verify_extract_proposals.v1",
                minimum_gate="EXACT_VERIFY_FILE_SWEEP_AND_CANDIDATE_PARITY",
            ),
        )
        immutable = _mixed_identities(exact_inputs)

    elif phase_n == "skeptic" and work_n == "model":
        _fixed_output_set(
            exact_outputs,
            ("skeptic_findings.md", "skeptic_judge_decisions.md"),
            label=f"{phase_n}/{work_n}",
        )
        if "skeptic_manifest.json" not in exact_inputs:
            raise ValueError(
                "skeptic/model requires its exact challenge manifest"
            )
        outputs = tuple(
            _artifact(
                owner,
                path,
                artifact_class="REQUIRED",
                writer="MODEL",
                write_mode="REPLACE",
                schema_version=(
                    "plamen.skeptic_challenge_proposals.v1"
                    if path == "skeptic_findings.md"
                    else "plamen.skeptic_proposal_projection.v1"
                ),
                minimum_gate="EXACT_MANIFEST_IDENTITY_AND_TRIGGER_PARITY",
            )
            for path in exact_outputs
        )
        immutable = _mixed_identities(exact_inputs)

    elif phase_n == "crossbatch" and work_n == "model":
        _fixed_output_set(
            exact_outputs,
            ("cross_batch_consistency.md",),
            label=f"{phase_n}/{work_n}",
        )
        if "crossbatch_manifest.json" not in exact_inputs:
            raise ValueError(
                "crossbatch/model requires its exact verifier manifest"
            )
        outputs = (
            _artifact(
                owner,
                "cross_batch_consistency.md",
                artifact_class="REQUIRED",
                writer="MODEL",
                write_mode="REPLACE",
                schema_version="plamen.crossbatch_consistency.v1",
                minimum_gate="EXACT_VERIFY_COVERAGE_AND_CONTRADICTION_PARITY",
            ),
        )
        immutable = _mixed_identities(exact_inputs)

    elif phase_n == "report_dedup_agent" and work_n == "model":
        _fixed_output_set(
            exact_outputs,
            ("report_dedup_agent_decisions.md",),
            label=f"{phase_n}/{work_n}",
        )
        required = {
            "project::AUDIT_REPORT.md",
            "report_index.md",
            "finding_mapping.md",
            "report_dedup_candidate_pairs.json",
        }
        missing = required - set(exact_inputs)
        if missing:
            raise ValueError(
                "report_dedup_agent/model exact denominator is missing: "
                + ", ".join(sorted(missing))
            )
        outputs = (
            _artifact(
                owner,
                "report_dedup_agent_decisions.md",
                artifact_class="REQUIRED",
                writer="MODEL",
                write_mode="REPLACE",
                schema_version="plamen.report_dedup_proposals.v1",
                minimum_gate="EXACT_UNORDERED_PAIR_DISPOSITION_PARITY",
            ),
        )
        immutable = _mixed_identities(exact_inputs)

    elif phase_n == "report_disposition" and work_n == "model":
        _fixed_output_set(
            exact_outputs,
            ("disposition.md",),
            label=f"{phase_n}/{work_n}",
        )
        if exact_inputs != ("project::AUDIT_REPORT.md",):
            raise ValueError(
                "report_disposition/model requires exactly "
                "project::AUDIT_REPORT.md"
            )
        outputs = (
            _artifact(
                owner,
                "disposition.md",
                artifact_class="REQUIRED",
                writer="MODEL",
                write_mode="REPLACE",
                schema_version="plamen.report_disposition_proposals.v1",
                minimum_gate="EVERY_REPORT_FINDING_EXACT_DISPOSITION_PARITY",
            ),
        )
        immutable = _mixed_identities(exact_inputs)

    elif (
        phase_n == "semantic_dedup"
        and work_n == "dedup_pair_candidates"
    ):
        _fixed_path_set(
            exact_inputs,
            ("findings_inventory.md",),
            label=f"{phase_n}/{work_n}",
        )
        _fixed_output_set(
            exact_outputs,
            (
                "dedup_blocks.md",
                "dedup_candidate_pairs.md",
                "dedup_candidate_pairs_full.md",
                "dedup_focus_inventory.md",
            ),
            label=f"{phase_n}/{work_n}",
        )
        outputs = (
            _artifact(
                owner,
                "dedup_blocks.md",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="REPLACE",
                schema_version="plamen.dedup_candidate_blocks.v1",
                minimum_gate="EXACT_INVENTORY_BOUND_SIGNAL_ENUMERATION",
                consumers=(
                    "semantic_dedup/noop_proposal",
                    "semantic_dedup/model",
                ),
            ),
            _artifact(
                owner,
                "dedup_candidate_pairs.md",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="REPLACE",
                schema_version="plamen.dedup_candidate_pairs.v1",
                minimum_gate="EXACT_INVENTORY_BOUND_SIGNAL_ENUMERATION",
                consumers=(
                    "semantic_dedup/noop_proposal",
                    "semantic_dedup/model",
                    "semantic_dedup/supplemental_proposals",
                ),
            ),
            _artifact(
                owner,
                "dedup_candidate_pairs_full.md",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="REPLACE",
                schema_version="plamen.dedup_candidate_pairs.v1",
                minimum_gate="FULL_SIGNAL_DENOMINATOR_PRESERVED",
                consumers=(
                    "semantic_dedup/noop_proposal",
                    "semantic_dedup/supplemental_proposals",
                ),
            ),
            _artifact(
                owner,
                "dedup_focus_inventory.md",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="REPLACE",
                schema_version="plamen.dedup_focus_inventory.v1",
                minimum_gate="EXACT_PACKET_MEMBER_BODY_PROJECTION",
                consumers=("semantic_dedup/model",),
            ),
        )
        immutable = _identities(("findings_inventory.md",))
        model_invoked = False

    elif (
        phase_n in {"semantic_dedup", "sc_semantic_dedup"}
        and work_n == "model"
    ):
        _fixed_output_set(
            exact_outputs,
            ("dedup_decisions.md",),
            label=f"{phase_n}/{work_n}",
        )
        if not exact_inputs:
            raise ValueError(
                f"{phase_n}/{work_n} requires its exact bounded candidate "
                "packet denominator"
            )
        outputs = (
            _artifact(
                owner,
                "dedup_decisions.md",
                artifact_class="REQUIRED",
                writer="MODEL",
                write_mode="REPLACE",
                schema_version="plamen.semantic_dedup_proposals.v1",
                minimum_gate=(
                    "EXACT_BOUNDED_PAIR_DISPOSITION_PARITY"
                ),
                consumers=(
                    "semantic_dedup/prequeue_apply"
                    if phase_n == "semantic_dedup"
                    else "sc_semantic_dedup/canonical_apply",
                ),
            ),
        )
        immutable = _identities(exact_inputs)

    elif phase_n == "semantic_dedup" and work_n == "noop_proposal":
        _fixed_output_set(
            exact_outputs,
            ("dedup_decisions.md",),
            label=f"{phase_n}/{work_n}",
        )
        if not exact_inputs:
            raise ValueError(
                "semantic_dedup/noop_proposal requires its exact bounded "
                "signal denominator"
            )
        outputs = (
            _artifact(
                owner,
                "dedup_decisions.md",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="REPLACE",
                schema_version="plamen.semantic_dedup_proposals.v1",
                minimum_gate=(
                    "DRIVER_PASSTHROUGH_BOUND_TO_EXACT_SIGNAL_DENOMINATOR"
                ),
                consumers=("semantic_dedup/prequeue_apply",),
            ),
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif (
        phase_n == "semantic_dedup"
        and work_n == "supplemental_proposals"
    ):
        _fixed_path_set(
            exact_inputs,
            (
                "findings_inventory.md",
                "dedup_decisions.md",
                "dedup_candidate_pairs.md",
                "dedup_candidate_pairs_full.md",
            ),
            label=f"{phase_n}/{work_n}",
        )
        _fixed_output_set(
            exact_outputs,
            ("semantic_dedup_supplemental_proposals.json",),
            label=f"{phase_n}/{work_n}",
        )
        outputs = (
            _artifact(
                owner,
                "semantic_dedup_supplemental_proposals.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                # The proposal is a pure projection of four immutable inputs.
                # An authorized replacement of the primary decision must
                # therefore refresh this exact same work unit before apply.
                write_mode="REPLACE",
                schema_version=(
                    "plamen.semantic_dedup_supplemental_proposals.v1"
                ),
                minimum_gate=(
                    "CONSERVATIVE_EXACT_LOCATION_SAME_SEVERITY_PROPOSALS"
                ),
                consumers=("semantic_dedup/prequeue_apply",),
            ),
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif (
        phase_n in {
            "inventory_chunk_a",
            "inventory_chunk_b",
            "inventory_chunk_c",
        }
        and re.fullmatch(r"model\.attempt[0-9]{4}", work_n)
    ):
        expected_output = f"findings_{phase_n}.md"
        _fixed_output_set(
            exact_outputs,
            (expected_output,),
            label=f"{phase_n}/{work_n}",
        )
        manifest = f"{phase_n}.manifest.md"
        if manifest not in exact_inputs:
            raise ValueError(
                f"{phase_n}/{work_n} requires its exact shard manifest"
            )
        outputs = (
            _artifact(
                owner,
                expected_output,
                artifact_class="REQUIRED",
                writer="MODEL",
                schema_version="plamen.inventory_chunk_markdown.v1",
                minimum_gate=(
                    "EXACT_MANIFEST_DENOMINATOR_AND_CONTENT_BEARING_CHUNK"
                ),
                consumers=(f"{phase_n}/exact_reconciliation",),
            ),
        )
        immutable = _identities(exact_inputs)
        model_invoked = True

    elif (
        phase_n in {
            "inventory_chunk_a",
            "inventory_chunk_b",
            "inventory_chunk_c",
            "inventory",
        }
        and work_n == "exact_reconciliation"
    ):
        if phase_n.startswith("inventory_chunk_"):
            receipt_name = f"{phase_n}.reconciliation.json"
            human_name = f"{phase_n}.human_review.md"
        else:
            receipt_name = "inventory_reconciliation.json"
            human_name = "inventory_reconciliation_human_review.md"
        outputs = (
            _artifact(
                owner,
                receipt_name,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.inventory_reconciliation.v1",
                minimum_gate="EXACT_RAW_TO_INVENTORY_DISPOSITION_PARITY",
            ),
            _artifact(
                owner,
                human_name,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                minimum_gate="CONTENT_BEARING_UNRESOLVED_CANDIDATE_PROJECTION",
            ),
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif phase_n == "depth" and work_n == "confidence_consensus":
        outputs = (
            _artifact(
                owner,
                "confidence_consensus_authority.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.confidence_consensus_authority.v1",
                minimum_gate="EXACT_INDEPENDENT_CORROBORATION_REDERIVATION",
            ),
            _artifact(
                owner,
                "consensus_map.md",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                minimum_gate="EXACT_AUTHORITY_PROJECTION",
            ),
            _artifact(
                owner,
                "confidence_scores.md",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                minimum_gate="MODE_AWARE_TYPED_CONSENSUS_APPLICATION",
            ),
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif (
        phase_n == "depth"
        and work_n in {
            "security_obligations.pre_depth",
            "security_obligations.post_depth",
        }
    ):
        if "_artifact_state.json" in exact_inputs:
            raise ValueError(
                "security-obligation PhaseIO binds selected artifact-state rows "
                "through their exact depth-output identities; the whole mutable "
                "_artifact_state.json ledger cannot be an immutable input"
            )
        schema_by_path = {
            "security_feature_facts.json": (
                "plamen.security_feature_fact_authority.v2"
            ),
            "security_obligation_authority.json": (
                "plamen.security_obligation_authority.v2"
            ),
            "security_obligations.md": (
                "plamen.security_obligation_projection.v1"
            ),
        }
        gate_by_path = {
            "security_feature_facts.json": "EXACT_TYPED_FACT_REDERIVATION",
            "security_obligation_authority.json": (
                "EXACT_OBLIGATION_RECEIPT_RECONCILIATION"
            ),
            "security_obligations.md": "EXACT_AUTHORITY_PROJECTION",
        }
        outputs = tuple(
            _artifact(
                owner,
                path,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version=schema_by_path[path],
                minimum_gate=gate_by_path[path],
                consumers=(
                    "depth/model",
                    "attention_repair/model",
                    "report_index/model",
                ),
            )
            for path in _SECURITY_OBLIGATION_SIDECARS
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif phase_n == "rag_sweep" and work_n == "precedent_facts":
        _fixed_output_set(
            exact_outputs,
            ("precedent_finding_facts.json",),
            label=f"{phase_n}/{work_n}",
        )
        fact_inputs = _fixed_path_set(
            exact_inputs,
            ("finding_records.json", "findings_inventory.md"),
            label=f"{phase_n}/{work_n}",
        )
        outputs = (
            _artifact(
                owner,
                "precedent_finding_facts.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.precedent_finding_facts.v1",
                minimum_gate="EXACT_FINDING_DENOMINATOR_AND_SOURCE_BINDING",
                consumers=(
                    "rag_sweep/precedent_research",
                    "rag_sweep/precedent_normalize",
                    "rag_sweep/precedent_reconcile",
                ),
            ),
        )
        immutable = _identities(fact_inputs)
        model_invoked = False

    elif phase_n == "rag_sweep" and work_n == "precedent_research":
        _fixed_output_set(
            exact_outputs,
            ("rag_validation.md",),
            label=f"{phase_n}/{work_n}",
        )
        research_inputs = _fixed_path_set(
            exact_inputs,
            (
                "build_status.md",
                "findings_inventory.md",
                "precedent_finding_facts.json",
            ),
            label=f"{phase_n}/{work_n}",
        )
        outputs = (
            _artifact(
                owner,
                "rag_validation.md",
                artifact_class="REQUIRED",
                writer="MODEL",
                schema_version="plamen.precedent_proposal_markdown.v1",
                minimum_gate="BOUNDED_TYPED_PROPOSAL_TRANSPORT",
                consumers=("rag_sweep/precedent_normalize",),
            ),
        )
        immutable = _identities(research_inputs)

    elif phase_n == "rag_sweep" and work_n == "precedent_normalize":
        _fixed_output_set(
            exact_outputs,
            ("precedent_evidence_proposals.json",),
            label=f"{phase_n}/{work_n}",
        )
        normalize_inputs = _fixed_path_set(
            exact_inputs,
            ("precedent_finding_facts.json", "rag_validation.md"),
            label=f"{phase_n}/{work_n}",
        )
        outputs = (
            _artifact(
                owner,
                "precedent_evidence_proposals.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.precedent_evidence_proposals.v1",
                minimum_gate="COMPLETE_FINDING_DENOMINATOR_AND_TRANSPORT_DEBT",
                consumers=("rag_sweep/precedent_reconcile",),
            ),
        )
        immutable = _identities(normalize_inputs)
        model_invoked = False

    elif phase_n == "rag_sweep" and work_n == "precedent_reconcile":
        _fixed_output_set(
            exact_outputs,
            (
                "precedent_context.md",
                "precedent_evidence_authority.json",
                "precedent_report_context.md",
            ),
            label=f"{phase_n}/{work_n}",
        )
        reconcile_inputs = _fixed_path_set(
            exact_inputs,
            (
                "precedent_evidence_proposals.json",
                "precedent_finding_facts.json",
            ),
            label=f"{phase_n}/{work_n}",
        )
        outputs = tuple(
            _artifact(
                owner,
                path,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version=(
                    "plamen.precedent_evidence_authority.v1"
                    if path.endswith(".json")
                    else "plamen.precedent_report_context_projection.v1"
                    if path == "precedent_report_context.md"
                    else "plamen.precedent_context_projection.v1"
                ),
                minimum_gate=(
                    "EXACT_FACT_PROPOSAL_RECONCILIATION"
                    if path.endswith(".json")
                    else "EXACT_AUTHORITY_PROJECTION"
                ),
                consumers=(
                    ("report_index/model",)
                    if path == "precedent_report_context.md"
                    else ("chain_agent2/model", "chain_iter2/model")
                    if path == "precedent_context.md"
                    else ()
                ),
            )
            for path in (
                "precedent_context.md",
                "precedent_evidence_authority.json",
                "precedent_report_context.md",
            )
        )
        immutable = _identities(reconcile_inputs)
        model_invoked = False

    elif phase_n == "depth" and work_n == "fuzz_workspace.prepare":
        _fixed_output_set(
            exact_outputs,
            ("fuzz_workspace_index.json",),
            label=f"{phase_n}/{work_n}",
        )
        outputs = (
            _artifact(
                owner,
                "fuzz_workspace_index.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.fuzz-workspace-index.v1",
                minimum_gate="EXACT_AUTHORITY_DENOMINATOR_AND_ROW_PARITY",
                consumers=("depth/fuzz-model", "depth/fuzz-finalizer"),
            ),
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif phase_n == "depth" and work_n == "fuzz_workspace.finalize.all":
        _fixed_output_set(
            exact_outputs,
            ("fuzz_workspace_result_index.json",),
            label=f"{phase_n}/{work_n}",
        )
        normalized_inputs = tuple(
            _canonical_relative_path(path) for path in exact_inputs
        )
        if "fuzz_workspace_index.json" not in normalized_inputs:
            raise ValueError(
                "depth/fuzz_workspace.finalize.all requires "
                "fuzz_workspace_index.json"
            )
        if not any(path.endswith(".md") for path in normalized_inputs):
            raise ValueError(
                "depth/fuzz_workspace.finalize.all requires at least one "
                "fuzz worker artifact"
            )
        outputs = (
            _artifact(
                owner,
                "fuzz_workspace_result_index.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.fuzz-workspace-result-index.v1",
                minimum_gate="EXACT_RESULT_OUTPUT_AND_AUTHORITY_RECONCILIATION",
                consumers=("depth/validator", "report-index/model"),
            ),
        )
        immutable = _identities(normalized_inputs)
        model_invoked = False

    elif phase_n in {"breadth", "rescan", "depth"} and work_n.startswith("worker."):
        outputs = _dynamic_specs(
            owner, exact_outputs, writer="MODEL",
            conditional_output_ids=conditional_output_ids,
            condition_id=condition_id,
        )
        if phase_n == "breadth":
            if exact_inputs:
                immutable = _identities(_registered_worker_inputs(
                    phase_n,
                    pipeline_n,
                    exact_inputs,
                    exact_outputs=exact_outputs,
                    mode=mode_n,
                ))
            else:
                immutable = _identities(_legacy_worker_fallback_inputs(
                    phase_n,
                    pipeline_n,
                    exact_outputs=exact_outputs,
                    mode=mode_n,
                ))
        elif phase_n == "rescan":
            if exact_inputs:
                immutable = _identities(_registered_worker_inputs(
                    phase_n,
                    pipeline_n,
                    exact_inputs,
                    exact_outputs=exact_outputs,
                    mode=mode_n,
                ))
            else:
                immutable = _identities(_legacy_worker_fallback_inputs(
                    phase_n,
                    pipeline_n,
                    exact_outputs=exact_outputs,
                    mode=mode_n,
                ))
        else:
            if exact_inputs:
                immutable = _identities(_registered_worker_inputs(
                    phase_n,
                    pipeline_n,
                    exact_inputs,
                    exact_outputs=exact_outputs,
                    mode=mode_n,
                ))
            else:
                immutable = _identities(_legacy_worker_fallback_inputs(
                    phase_n,
                    pipeline_n,
                    exact_outputs=exact_outputs,
                    mode=mode_n,
                ))

    elif phase_n == "chain" and work_n == "state_resolution":
        state_resolution_only = ("chain_state_resolution.json",)
        state_resolution_with_tail_static_initialization = (
            "chain_state_resolution.json",
            "chain_candidate_pairs.md",
            "chain_candidate_pairs_full.md",
            "variable_finding_map.md",
            "chain_enabler_baseline.md",
            "chain_candidate_pairs_iter2.json",
            "chain_tail_disposition_ledger.json",
            "chain_tail_coverage_receipt.json",
            "chain_composition_verification_candidates.json",
            "chain_composition_coverage_gaps.md",
            "chain_candidate_pairs_iter2.md",
        )
        state_resolution_with_legacy_enabler_initialization = (
            *state_resolution_with_tail_static_initialization[:4],
            "enabler_results.md",
            *state_resolution_with_tail_static_initialization[4:],
        )
        # Accepted only for resume/backward compatibility. New runs split the
        # mutable control generation from immutable/root presentation so later
        # cursor movement cannot stale the manifest's aggregate producer.
        state_resolution_with_legacy_tail_initialization = (
            *state_resolution_with_legacy_enabler_initialization,
            "_chain_tail_control/chain_tail_disposition_ledger.json",
            "_chain_tail_control/chain_tail_coverage_receipt.json",
            "_chain_tail_control/"
            "chain_composition_verification_candidates.json",
            "_chain_tail_control/chain_composition_coverage_gaps.md",
            "_chain_tail_shards/shard_0000.input.md",
        )
        if exact_outputs not in (
            state_resolution_only,
            state_resolution_with_tail_static_initialization,
            state_resolution_with_legacy_enabler_initialization,
            state_resolution_with_legacy_tail_initialization,
        ):
            raise ValueError(
                "chain/state_resolution requires either the exact state-resolution "
                "output or the exact state-resolution + chain-tail initialization "
                "output denominator"
            )
        outputs = tuple(
            _artifact(
                owner,
                path,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version=(
                    "plamen.chain_state_resolution.v1"
                    if path == "chain_state_resolution.json"
                    else "plamen.chain_tail_manifest.v2"
                    if path == "chain_candidate_pairs_iter2.json"
                    else "plamen.chain_tail_disposition_ledger.v2"
                    if path.endswith("chain_tail_disposition_ledger.json")
                    else "plamen.chain_tail_coverage_receipt.v2"
                    if path.endswith("chain_tail_coverage_receipt.json")
                    else "plamen.chain_composition_candidates.v1"
                    if path.endswith(
                        "chain_composition_verification_candidates.json"
                    )
                    else "unstructured.v1"
                ),
                minimum_gate=(
                    "STATE_SYMBOL_EDGE_AND_PAIR_PARITY"
                    if path == "chain_state_resolution.json"
                    else "EXACT_CHAIN_TAIL_INITIAL_DENOMINATOR"
                ),
            )
            for path in exact_outputs
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif (
        phase_n == "chain"
        and work_n == "state_resolution_enabler_prefill"
    ):
        if exact_outputs != ("enabler_results.md",):
            raise ValueError(
                "chain/state_resolution_enabler_prefill requires exactly "
                "enabler_results.md"
            )
        if (
            "findings_inventory.md" not in exact_inputs
            or len(exact_inputs) != len(set(exact_inputs))
        ):
            raise ValueError(
                "chain/state_resolution_enabler_prefill requires the exact "
                "state-source denominator"
            )
        outputs = (
            _artifact(
                owner,
                "enabler_results.md",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="unstructured.v1",
                minimum_gate="EXACT_CHAIN_ENABLER_PREFILL_DENOMINATOR",
                consumers=("chain/model",),
            ),
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif phase_n == "chain" and work_n == "tail_manifest":
        if exact_outputs != (_CHAIN_TAIL_CONTROL_MANIFEST,):
            raise ValueError(
                "chain/tail_manifest requires one immutable control manifest"
            )
        outputs = (
            _artifact(
                owner,
                _CHAIN_TAIL_CONTROL_MANIFEST,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.chain_tail_manifest.v2",
                minimum_gate="EXACT_CHAIN_TAIL_INITIAL_DENOMINATOR",
            ),
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif phase_n == "chain" and work_n == "tail_control_init":
        expected = (
            *_CHAIN_TAIL_MUTABLE_CONTROL_OUTPUTS[:-1],
            "_chain_tail_shards/shard_0000.input.md",
        )
        if exact_outputs != expected:
            raise ValueError(
                "chain/tail_control_init output denominator mismatch"
            )
        outputs = _dynamic_specs(
            owner,
            exact_outputs,
            writer="DRIVER",
            conditional_output_ids=(),
            condition_id="",
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif phase_n == "chain_agent2" and work_n == "model":
        outputs = tuple(
            _artifact(
                owner, path,
                artifact_class="REQUIRED", writer="MODEL",
                minimum_gate="CHAIN_STRUCTURE",
            )
            for path in (
                "chain_hypotheses.md",
                "composition_coverage.md",
                "synthesis_full.md",
            )
        )
        chain_inputs = (
            "hypotheses.md", "finding_mapping.md", "enabler_results.md",
            "variable_finding_map.md", "chain_candidate_pairs.md",
            "findings_inventory.md",
            *(("precedent_context.md",) if mode_n != "light" else ()),
        )
        if exact_inputs:
            without_precedent = tuple(
                path for path in chain_inputs if path != "precedent_context.md"
            )
            allowed = {frozenset(chain_inputs), frozenset(without_precedent)}
            if frozenset(exact_inputs) not in allowed or len(exact_inputs) != len(
                set(exact_inputs)
            ):
                raise ValueError(
                    "chain_agent2/model received an unregistered semantic input"
                )
            chain_inputs = tuple(exact_inputs)
        immutable = _identities(chain_inputs)

    elif phase_n == "chain_iter2" and work_n == "tail_primary_control":
        if exact_outputs != _CHAIN_TAIL_MUTABLE_CONTROL_OUTPUTS:
            raise ValueError(
                "chain-tail primary control generation denominator mismatch"
            )
        required = {
            _CHAIN_TAIL_CONTROL_MANIFEST,
            "composition_coverage.md",
            "chain_hypotheses.md",
        }
        if set(exact_inputs) != required:
            raise ValueError(
                "chain-tail primary control input denominator mismatch"
            )
        outputs = _dynamic_specs(
            owner,
            exact_outputs,
            writer="DRIVER",
            conditional_output_ids=(),
            condition_id="",
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif (
        phase_n == "chain_iter2"
        and work_n.startswith("tail_shard_prepare_control.")
    ):
        if exact_outputs != _CHAIN_TAIL_MUTABLE_CONTROL_OUTPUTS:
            raise ValueError(
                "isolated chain-tail prepare control denominator mismatch"
            )
        if _CHAIN_TAIL_CONTROL_MANIFEST not in exact_inputs:
            raise ValueError(
                "isolated chain-tail prepare requires immutable manifest authority"
            )
        outputs = _dynamic_specs(
            owner,
            exact_outputs,
            writer="DRIVER",
            conditional_output_ids=(),
            condition_id="",
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif (
        phase_n == "chain_iter2"
        and work_n.startswith("tail_shard_prepare_artifacts.")
    ):
        suffix = work_n.rsplit(".", 1)[-1]
        if not re.fullmatch(r"\d{4}", suffix):
            raise ValueError(
                "isolated chain-tail prepare artifact generation is malformed"
            )
        shard_root = f"_chain_tail_shards/shard_{suffix}"
        archive = f"_chain_tail_shards/shard_{suffix}.input.md"
        required_outputs = {
            archive,
            f"{shard_root}/work_unit.json",
            f"{shard_root}/chain_candidate_pairs_iter2.md",
        }
        if (
            not required_outputs.issubset(set(exact_outputs))
            or len(exact_outputs) != len(set(exact_outputs))
            or any(
                path != archive and not path.startswith(f"{shard_root}/")
                for path in exact_outputs
            )
            or any(
                path.endswith(
                    (
                        "/chain_iteration2.md",
                        "/terminal_plan.json",
                        "/disposition_receipt.json",
                    )
                )
                for path in exact_outputs
            )
        ):
            raise ValueError(
                "isolated chain-tail prepare artifact denominator mismatch"
            )
        if _CHAIN_TAIL_CONTROL_MANIFEST not in exact_inputs:
            raise ValueError(
                "isolated chain-tail prepare artifacts require manifest authority"
            )
        outputs = _dynamic_specs(
            owner,
            exact_outputs,
            writer="DRIVER",
            conditional_output_ids=(),
            condition_id="",
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif (
        phase_n == "chain_iter2"
        and work_n.startswith("tail_shard_model.")
    ):
        if (
            len(exact_outputs) != 1
            or not re.fullmatch(
                r"_chain_tail_shards/shard_\d{4}/chain_iteration2\.md",
                exact_outputs[0],
            )
        ):
            raise ValueError(
                "isolated chain-tail model requires one shard-local transcript"
            )
        if not exact_inputs or not any(
            path.endswith("/work_unit.json") for path in exact_inputs
        ):
            raise ValueError(
                "isolated chain-tail model requires its immutable work unit"
            )
        if _CHAIN_TAIL_CONTROL_MANIFEST not in exact_inputs:
            raise ValueError(
                "isolated chain-tail model requires the authoritative manifest"
            )
        outputs = _dynamic_specs(
            owner,
            exact_outputs,
            writer="MODEL",
            conditional_output_ids=(),
            condition_id="",
        )
        immutable = _identities(exact_inputs)

    elif (
        phase_n == "chain_iter2"
        and work_n.startswith("tail_shard_disposition.")
    ):
        if (
            len(exact_outputs) != 2
            or len({
                re.sub(
                    r"/(?:disposition_receipt|terminal_plan)\.json$",
                    "",
                    value,
                )
                for value in exact_outputs
            }) != 1
            or not any(value.endswith("/disposition_receipt.json") for value in exact_outputs)
            or not any(value.endswith("/terminal_plan.json") for value in exact_outputs)
            or any(
                not re.fullmatch(
                    r"_chain_tail_shards/shard_\d{4}/"
                    r"(?:disposition_receipt|terminal_plan)\.json",
                    value,
                )
                for value in exact_outputs
            )
        ):
            raise ValueError(
                "isolated chain-tail disposition requires one shard-local plan "
                "and receipt"
            )
        if not exact_inputs or not any(
            path.endswith("/chain_iteration2.md") for path in exact_inputs
        ):
            raise ValueError(
                "chain-tail disposition requires the committed shard transcript"
            )
        if not any(path.endswith("/work_unit.json") for path in exact_inputs):
            raise ValueError(
                "chain-tail disposition requires its immutable work unit"
            )
        outputs = _dynamic_specs(
            owner,
            exact_outputs,
            writer="DRIVER",
            conditional_output_ids=(),
            condition_id="",
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif (
        phase_n == "chain_iter2"
        and (
            work_n.startswith("tail_shard_disposition_control.")
            or work_n.startswith("tail_shard_failure_control.")
        )
    ):
        if exact_outputs != _CHAIN_TAIL_MUTABLE_CONTROL_OUTPUTS:
            raise ValueError(
                "isolated chain-tail terminal control denominator mismatch"
            )
        if (
            _CHAIN_TAIL_CONTROL_MANIFEST not in exact_inputs
            or not any(path.endswith("/work_unit.json") for path in exact_inputs)
        ):
            raise ValueError(
                "isolated chain-tail terminal control inputs are incomplete"
            )
        outputs = _dynamic_specs(
            owner,
            exact_outputs,
            writer="DRIVER",
            conditional_output_ids=(),
            condition_id="",
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif (
        phase_n == "chain_iter2"
        and re.fullmatch(r"tail_budget_stop\.p\d{4}\.s\d{4}", work_n)
    ):
        if exact_outputs != _CHAIN_TAIL_MUTABLE_CONTROL_OUTPUTS:
            raise ValueError(
                "chain-tail budget-stop control denominator mismatch"
            )
        if exact_inputs != (_CHAIN_TAIL_CONTROL_MANIFEST,):
            raise ValueError(
                "chain-tail budget-stop requires only immutable manifest "
                "authority"
            )
        outputs = _dynamic_specs(
            owner,
            exact_outputs,
            writer="DRIVER",
            conditional_output_ids=(),
            condition_id="",
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif (
        phase_n == "chain_iter2"
        and work_n.startswith("tail_shard_failure.")
    ):
        if (
            len(exact_outputs) != 2
            or len({
                re.sub(
                    r"/(?:disposition_receipt|terminal_plan)\.json$",
                    "",
                    value,
                )
                for value in exact_outputs
            }) != 1
            or not any(value.endswith("/disposition_receipt.json") for value in exact_outputs)
            or not any(value.endswith("/terminal_plan.json") for value in exact_outputs)
            or any(
                not re.fullmatch(
                    r"_chain_tail_shards/shard_\d{4}/"
                    r"(?:disposition_receipt|terminal_plan)\.json",
                    value,
                )
                for value in exact_outputs
            )
        ):
            raise ValueError(
                "failed chain-tail shard requires one terminal debt plan and receipt"
            )
        shard_root = re.sub(
            r"/(?:disposition_receipt|terminal_plan)\.json$",
            "",
            exact_outputs[0],
        )
        failure_base_inputs = {
            _CHAIN_TAIL_CONTROL_MANIFEST,
            f"{shard_root}/work_unit.json",
        }
        failure_model_inputs = {
            *failure_base_inputs,
            f"{shard_root}/chain_iteration2.md",
        }
        if (
            set(exact_inputs) not in (
                failure_base_inputs,
                failure_model_inputs,
            )
            or len(exact_inputs) != len(set(exact_inputs))
        ):
            raise ValueError(
                "failed chain-tail shard requires the exact manifest/work-unit "
                "inputs and may add only its committed MODEL transcript"
            )
        outputs = _dynamic_specs(
            owner,
            exact_outputs,
            writer="DRIVER",
            conditional_output_ids=(),
            condition_id="",
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif phase_n == "chain_iter2" and work_n == "model":
        outputs = (
            _artifact(
                owner, "chain_iteration2.md",
                artifact_class="REQUIRED", writer="MODEL",
                minimum_gate="TAIL_PAIR_DISPOSITION_PARITY",
            ),
        )
        chain_inputs = (
            "chain_candidate_pairs_iter2.md", "composition_coverage.md",
            "chain_hypotheses.md", "findings_inventory.md",
            *(("precedent_context.md",) if mode_n != "light" else ()),
        )
        if exact_inputs:
            without_precedent = tuple(
                path for path in chain_inputs if path != "precedent_context.md"
            )
            allowed = {frozenset(chain_inputs), frozenset(without_precedent)}
            if frozenset(exact_inputs) not in allowed or len(exact_inputs) != len(
                set(exact_inputs)
            ):
                raise ValueError(
                    "chain_iter2/model received an unregistered semantic input"
                )
            chain_inputs = tuple(exact_inputs)
        immutable = _identities(chain_inputs)

    elif phase_n == "chain_iter2" and work_n == "tail_primary":
        if exact_outputs != ("chain_tail_primary_receipt.json",):
            raise ValueError(
                "chain-tail primary reconciliation requires its typed receipt"
            )
        required = {
            _CHAIN_TAIL_CONTROL_MANIFEST,
            "composition_coverage.md",
            "chain_hypotheses.md",
        }
        if set(exact_inputs) != required:
            raise ValueError(
                "chain-tail primary reconciliation input denominator mismatch"
            )
        outputs = _dynamic_specs(
            owner,
            exact_outputs,
            writer="DRIVER",
            conditional_output_ids=(),
            condition_id="",
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif (
        phase_n == "chain_iter2"
        and work_n in {"driver_merge", "tail_snapshot", "tail_reconcile"}
    ):
        raise ValueError(
            "CHAIN_TAIL_LEGACY_FIXED_GENERATION: fixed-key chain-tail "
            "terminal work units are legacy debt; "
            "a pPPPP.sSSSS generation is required"
        )

    elif (
        phase_n == "chain_iter2"
        and any(
            work_n.startswith(f"{role}.")
            for role in ("driver_merge", "tail_snapshot", "tail_reconcile")
        )
        and not re.fullmatch(
            r"(?:driver_merge|tail_snapshot|tail_reconcile)"
            r"\.p\d{4}\.s\d{4}",
            work_n,
        )
    ):
        raise ValueError(
            "CHAIN_TAIL_TERMINAL_GENERATION_MALFORMED: terminal work-unit "
            "generation must be exact pPPPP.sSSSS"
        )

    elif (
        phase_n == "chain_iter2"
        and re.fullmatch(
            r"driver_merge\.p\d{4}\.s\d{4}",
            work_n,
        )
    ):
        outputs = tuple(
            _artifact(
                owner, path,
                artifact_class="DRIVER_GENERATED", writer="DRIVER",
                write_mode="MERGE", minimum_gate="IDENTITY_PARITY",
            )
            for path in ("chain_hypotheses.md", "composition_coverage.md")
        )
        immutable = _identities(("chain_iteration2.md",))
        model_invoked = False

    elif (
        phase_n == "chain_iter2"
        and re.fullmatch(
            r"tail_snapshot\.p\d{4}\.s\d{4}",
            work_n,
        )
    ):
        if exact_outputs != ("chain_tail_terminal_snapshot.json",):
            raise ValueError(
                "chain-tail terminal snapshot requires one typed output"
            )
        generation_match = re.fullmatch(
            r"tail_snapshot\.(p\d{4}\.s(\d{4}))",
            work_n,
        )
        if generation_match is None:
            raise ValueError(
                "chain-tail terminal snapshot generation is malformed"
            )
        shard_count = int(generation_match.group(2))
        required_inputs = {
            _CHAIN_TAIL_CONTROL_MANIFEST,
            *_CHAIN_TAIL_MUTABLE_CONTROL_OUTPUTS,
        }
        optional_transcripts: set[str] = set()
        for shard_index in range(shard_count):
            shard_root = (
                f"_chain_tail_shards/shard_{shard_index:04d}"
            )
            required_inputs.update({
                f"{shard_root}/work_unit.json",
                f"{shard_root}/terminal_plan.json",
                f"{shard_root}/disposition_receipt.json",
            })
            optional_transcripts.add(
                f"{shard_root}/chain_iteration2.md"
            )
        primary_inputs = {
            "chain_tail_primary_receipt.json",
            "composition_coverage.md",
            "chain_hypotheses.md",
        }
        observed_inputs = set(exact_inputs)
        primary_present = observed_inputs & primary_inputs
        if (
            len(exact_inputs) != len(observed_inputs)
            or not required_inputs <= observed_inputs
            or (
                primary_present
                and primary_present != primary_inputs
            )
            or not observed_inputs
            <= (
                required_inputs
                | optional_transcripts
                | (primary_inputs if primary_present else set())
            )
        ):
            raise ValueError(
                "chain-tail terminal snapshot input denominator is invalid"
            )
        outputs = (
            _artifact(
                owner,
                "chain_tail_terminal_snapshot.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.chain_tail.terminal_snapshot.v2",
                minimum_gate="EXACT_TERMINAL_GENERATION",
                consumers=(
                    "chain_iter2/tail_reconcile."
                    f"{generation_match.group(1)}",
                ),
            ),
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif (
        phase_n == "chain_iter2"
        and re.fullmatch(
            r"tail_rearm_control\.p\d{4}\.s\d{4}",
            work_n,
        )
    ):
        required_inputs = {
            _CHAIN_TAIL_CONTROL_MANIFEST,
            *_CHAIN_TAIL_FINAL_ROOT_OUTPUTS,
        }
        if (
            set(exact_outputs)
            != set(_CHAIN_TAIL_MUTABLE_CONTROL_OUTPUTS)
            or len(exact_outputs)
            != len(_CHAIN_TAIL_MUTABLE_CONTROL_OUTPUTS)
            or set(exact_inputs) != required_inputs
            or len(exact_inputs) != len(required_inputs)
        ):
            raise ValueError(
                "chain-tail rearm control generation denominator mismatch"
            )
        outputs = _dynamic_specs(
            owner,
            exact_outputs,
            writer="DRIVER",
            conditional_output_ids=(),
            condition_id="",
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif (
        phase_n == "chain_iter2"
        and re.fullmatch(
            r"tail_reconcile\.p\d{4}\.s\d{4}",
            work_n,
        )
    ):
        if (
            set(exact_outputs)
            != set(_CHAIN_TAIL_FINAL_PUBLICATION_OUTPUTS)
            or len(exact_outputs)
            != len(_CHAIN_TAIL_FINAL_PUBLICATION_OUTPUTS)
        ):
            raise ValueError(
                "chain-tail final publication output denominator mismatch"
            )
        required_inputs = {
            _CHAIN_TAIL_CONTROL_MANIFEST,
            "chain_tail_terminal_snapshot.json",
        }
        observed_inputs = set(exact_inputs)
        allowed_inputs = {
            *required_inputs,
            "chain_hypotheses.md",
        }
        if (
            len(exact_inputs) != len(observed_inputs)
            or not required_inputs <= observed_inputs
            or not observed_inputs <= allowed_inputs
        ):
            raise ValueError(
                "chain-tail final publication input denominator mismatch"
            )
        outputs = tuple(
            _artifact(
                owner,
                path,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version=(
                    "plamen.chain_tail_disposition_ledger.v2"
                    if path.endswith("chain_tail_disposition_ledger.json")
                    else "plamen.chain_tail_coverage_receipt.v2"
                    if path.endswith("chain_tail_coverage_receipt.json")
                    else "plamen.chain_composition_candidates.v1"
                    if path.endswith(
                        "chain_composition_verification_candidates.json"
                    )
                    else "unstructured.v1"
                ),
                minimum_gate=(
                    "EXACT_PAIR_DENOMINATOR_AND_DISPOSITION_PARITY"
                    if path.endswith(".json")
                    else "BOUNDED_RENDERER_PARITY"
                    if path.endswith("chain_composition_coverage_gaps.md")
                    else "LOSSLESS_SHARD_AGGREGATE"
                ),
            )
            for path in _CHAIN_TAIL_FINAL_PUBLICATION_OUTPUTS
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif (
        phase_n == "attention_repair"
        and (
            work_n == "shard_plan"
            or work_n.startswith("shard_aggregate.")
        )
    ):
        outputs = _dynamic_specs(
            owner,
            exact_outputs,
            writer="DRIVER",
            conditional_output_ids=(),
            condition_id="",
        )
        immutable = _mixed_identities(exact_inputs)
        model_invoked = False

    elif (
        phase_n == "attention_repair"
        and re.fullmatch(r"worker\.attn-\d{4}(?:\.r\d{4})?", work_n)
    ):
        outputs = _dynamic_specs(
            owner,
            exact_outputs,
            writer="MODEL",
            conditional_output_ids=(),
            condition_id="",
        )
        immutable = _mixed_identities(exact_inputs)

    elif phase_n == "attention_repair" and work_n == "model":
        outputs = _dynamic_specs(
            owner,
            exact_outputs,
            writer="MODEL",
            conditional_output_ids=conditional_output_ids,
            condition_id=condition_id,
        )
        immutable = _security_obligation_sidecar_identities()

    elif phase_n == "report_body" and work_n.startswith("model.report_"):
        shard = work_n[len("model.") :]
        expected_body_manifest = f"body_manifests/{shard}.json"
        expected_typed_manifest = f"report_evidence_manifests/{shard}.json"
        if expected_body_manifest not in exact_inputs or expected_typed_manifest not in exact_inputs:
            raise ValueError(
                "report body model requires its exact legacy and typed manifests"
            )
        if len(exact_outputs) != 1 or exact_outputs[0] != f"{shard}.md":
            raise ValueError(
                "report body model requires its exact shard Markdown output"
            )
        invalid_inputs = [
            path
            for path in exact_inputs
            if path not in {expected_body_manifest, expected_typed_manifest}
            and not re.fullmatch(r"verify_[A-Za-z0-9_.-]+\.md", path)
        ]
        if invalid_inputs:
            raise ValueError(
                "report body model received an unregistered input: "
                + ", ".join(sorted(invalid_inputs))
            )
        outputs = (
            _artifact(
                owner,
                exact_outputs[0],
                artifact_class="REQUIRED",
                writer="MODEL",
                schema_version="plamen.report_finding_bodies.v1",
                minimum_gate=(
                    "EXACT_TYPED_MANIFEST_DENOMINATOR_AND_SEMANTIC_PARITY"
                ),
                consumers=("report_assemble/model", "report_floor/evidence_quality"),
            ),
        )
        immutable = _identities(exact_inputs)
        model_invoked = True

    elif (
        phase_n == "report_body"
        and work_n.startswith("report_")
        and work_n.endswith(".runtime_debt_fallback")
    ):
        shard = work_n[: -len(".runtime_debt_fallback")]
        expected_typed_manifest = f"report_evidence_manifests/{shard}.json"
        if not {
            "report_evidence_records.json",
            expected_typed_manifest,
        }.issubset(set(exact_inputs)):
            raise ValueError(
                "runtime-debt report fallback requires its exact typed bundle and shard manifest"
            )
        if len(exact_outputs) != 1 or exact_outputs[0] != f"{shard}.md":
            raise ValueError(
                "runtime-debt report fallback requires its exact shard Markdown output"
            )
        invalid_inputs = [
            path
            for path in exact_inputs
            if path not in {
                "report_evidence_records.json",
                expected_typed_manifest,
            }
        ]
        if invalid_inputs:
            raise ValueError(
                "runtime-debt report fallback received an unregistered input: "
                + ", ".join(sorted(invalid_inputs))
            )
        outputs = (
            _artifact(
                owner,
                exact_outputs[0],
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.report_finding_bodies.v1",
                minimum_gate=(
                    "EXACT_RUNTIME_DEBT_RETENTION_AND_REPORT_BLOCKED_PARITY"
                ),
                consumers=("report_assemble/model", "report_floor/evidence_quality"),
            ),
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif phase_n == "report_body" and work_n == "evidence_pre":
        if not exact_outputs:
            raise ValueError(
                "report_body/evidence_pre requires its exact typed sidecar set"
            )
        required_outputs = {
            "report_evidence_records.json",
            "report_evidence_repair_request.json",
            "report_evidence_projection.md",
        }
        if not required_outputs.issubset(set(exact_outputs)):
            raise ValueError(
                "report_body/evidence_pre is missing a required typed sidecar"
            )
        invalid = [
            path
            for path in exact_outputs
            if path not in required_outputs
            and not re.fullmatch(
                r"report_evidence_manifests/report_[a-z_]+\.json", path
            )
        ]
        if invalid:
            raise ValueError(
                "report_body/evidence_pre received an unregistered output: "
                + ", ".join(sorted(invalid))
            )
        schema_by_path = {
            "report_evidence_records.json": "plamen.report_evidence_bundle.v1",
            "report_evidence_repair_request.json": (
                "plamen.report_evidence_repair_request.v1"
            ),
            "report_evidence_projection.md": (
                "plamen.report_evidence_projection.v1"
            ),
        }
        gate_by_path = {
            "report_evidence_records.json": (
                "EXACT_REPORT_ID_EVIDENCE_SCOPE_AND_SOURCE_DIGEST_PARITY"
            ),
            "report_evidence_repair_request.json": (
                "ONE_BOUNDED_EXACT_MISSING_FIELD_DELTA"
            ),
            "report_evidence_projection.md": "EXACT_TYPED_AUTHORITY_PROJECTION",
        }
        outputs = tuple(
            _artifact(
                owner,
                path,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version=schema_by_path.get(
                    path, "plamen.report_evidence_manifest.v1"
                ),
                minimum_gate=gate_by_path.get(
                    path, "EXACT_SOURCE_MANIFEST_AND_RECORD_DIGEST_PARITY"
                ),
                consumers=(
                    "report_body/evidence_repair.apply",
                    "report_body/model",
                    "report_floor/evidence_quality",
                ),
            )
            for path in exact_outputs
        )
        if "report_records.json" not in exact_inputs or not any(
            path.startswith("body_manifests/") for path in exact_inputs
        ):
            raise ValueError(
                "report_body/evidence_pre requires report records and exact body manifests"
            )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif phase_n == "report_body" and work_n == "evidence_repair.arm":
        _fixed_output_set(
            exact_outputs,
            (
                "report_evidence_repair_attempt.json",
                "_prompt_report_evidence_repair.md",
            ),
            label=f"{phase_n}/{work_n}",
        )
        if not {
            "report_evidence_records.json",
            "report_evidence_repair_request.json",
        }.issubset(set(exact_inputs)):
            raise ValueError(
                "report evidence repair arm requires the exact bundle and request"
            )
        outputs = (
            _artifact(
                owner,
                "report_evidence_repair_attempt.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.report_evidence_repair_attempt.v1",
                minimum_gate="IMMUTABLE_ONE_SHOT_INPUT_MANIFEST",
                consumers=("report_body/evidence_repair.model",),
            ),
            _artifact(
                owner,
                "_prompt_report_evidence_repair.md",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="unstructured.v1",
                minimum_gate="EXACT_RENDERED_PROMPT_DIGEST",
                consumers=("report_body/evidence_repair.model",),
            ),
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif phase_n == "report_body" and work_n == "evidence_repair.model":
        _fixed_output_set(
            exact_outputs,
            ("report_evidence_repair_response.json",),
            label=f"{phase_n}/{work_n}",
        )
        if not {
            "report_evidence_records.json",
            "report_evidence_repair_request.json",
            "report_evidence_repair_attempt.json",
            "_prompt_report_evidence_repair.md",
        }.issubset(set(exact_inputs)):
            raise ValueError(
                "report evidence repair model requires its immutable armed input manifest"
            )
        outputs = (
            _artifact(
                owner,
                "report_evidence_repair_response.json",
                artifact_class="REQUIRED",
                writer="MODEL",
                schema_version="plamen.report_evidence_repair_response.v1",
                minimum_gate="ONE_EXACT_REQUEST_BOUND_SEMANTIC_DELTA",
                consumers=("report_body/evidence_repair.apply",),
            ),
        )
        immutable = _identities(exact_inputs)
        model_invoked = True

    elif phase_n == "report_body" and work_n == "evidence_repair.prepare":
        _fixed_output_set(
            exact_outputs,
            ("report_evidence_repair_apply_plan.json",),
            label=f"{phase_n}/{work_n}",
        )
        required_inputs = {
            "report_evidence_records.json",
            "report_evidence_repair_request.json",
            "report_evidence_repair_response.json",
        }
        if not required_inputs.issubset(set(exact_inputs)):
            raise ValueError(
                "report evidence repair prepare requires bundle, request, and response"
            )
        outputs = (
            _artifact(
                owner,
                "report_evidence_repair_apply_plan.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.report_evidence_repair_apply_plan.v1",
                minimum_gate="EXACT_BEFORE_RESPONSE_TRANSACTION_BINDING",
                consumers=("report_body/evidence_repair.apply",),
            ),
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif phase_n == "report_body" and work_n == "evidence_repair.apply":
        required_outputs = {
            "report_evidence_records.json",
            "report_evidence_repair_request.json",
            "report_evidence_projection.md",
            "report_evidence_repair_receipt.json",
        }
        invalid = [
            path
            for path in exact_outputs
            if path not in required_outputs
            and not re.fullmatch(
                r"report_evidence_manifests/report_[a-z_]+\.json", path
            )
        ]
        if (
            not required_outputs.issubset(set(exact_outputs))
            or not any(
                path.startswith("report_evidence_manifests/")
                for path in exact_outputs
            )
            or invalid
        ):
            raise ValueError(
                "report evidence repair apply requires its exact canonical output set"
            )
        required_inputs = {
            "report_evidence_repair_apply_plan.json",
            "report_evidence_repair_response.json",
        }
        if (
            not required_inputs.issubset(set(exact_inputs))
            or not any(path.startswith("body_manifests/") for path in exact_inputs)
        ):
            raise ValueError(
                "report evidence repair apply requires its immutable plan, response, and source manifests"
            )
        schema_by_path = {
            "report_evidence_records.json": "plamen.report_evidence_bundle.v1",
            "report_evidence_repair_request.json": (
                "plamen.report_evidence_repair_request.v1"
            ),
            "report_evidence_projection.md": (
                "plamen.report_evidence_projection.v1"
            ),
            "report_evidence_repair_receipt.json": (
                "plamen.report_evidence_repair_receipt.v1"
            ),
        }
        outputs = tuple(
            _artifact(
                owner,
                path,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version=schema_by_path.get(
                    path, "plamen.report_evidence_manifest.v1"
                ),
                minimum_gate=(
                    "EXACT_REQUEST_RESPONSE_DELTA_AND_DIGEST_PARITY"
                    if path == "report_evidence_repair_receipt.json"
                    else "REPAIRED_BUNDLE_MANIFEST_PROJECTION_PARITY"
                ),
                consumers=("report_body/model", "report_floor/evidence_quality"),
            )
            for path in exact_outputs
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif (
        phase_n == "report_index"
        and work_n == "security_obligation_lifecycle.final"
    ):
        lifecycle_outputs = _fixed_output_set(
            exact_outputs,
            (
                "security_obligation_lifecycle.json",
                "security_obligation_lifecycle.md",
                "security_obligation_report_retention.md",
            ),
            label=f"{phase_n}/{work_n}",
        )
        schema_by_path = {
            "security_obligation_lifecycle.json": (
                "plamen.security_obligation_lifecycle.v1"
            ),
            "security_obligation_lifecycle.md": (
                "plamen.security_obligation_lifecycle_projection.v1"
            ),
            "security_obligation_report_retention.md": (
                "plamen.security_obligation_report_retention.v1"
            ),
        }
        gate_by_path = {
            "security_obligation_lifecycle.json": (
                "EXACT_ALIAS_LIFECYCLE_RECONCILIATION"
            ),
            "security_obligation_lifecycle.md": "EXACT_AUTHORITY_PROJECTION",
            "security_obligation_report_retention.md": (
                "NONAUTHORIZED_NEGATIVE_ALIAS_RETENTION_PARITY"
            ),
        }
        outputs = tuple(
            _artifact(
                owner,
                path,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version=schema_by_path[path],
                minimum_gate=gate_by_path[path],
                consumers=(
                    "report_index/model",
                    "report_index/mechanical",
                    "report_assemble/model",
                ),
            )
            for path in lifecycle_outputs
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif phase_n == "report_index" and work_n == "prework":
        semantic_inputs = _report_candidate_semantic_inputs(
            exact_inputs,
            _REPORT_INDEX_LEGACY_DENOMINATOR,
            label=f"{phase_n}/{work_n}",
        )
        if exact_inputs and not set(
            _REPORT_INDEX_LEGACY_DENOMINATOR
        ).issubset(set(semantic_inputs)):
            raise ValueError(
                "report_index/prework requires the legacy mapping inputs "
                "alongside the typed candidate universe"
            )
        outputs = (
            _artifact(
                owner, "severity_binding.md",
                artifact_class="CONDITIONAL", writer="DRIVER",
                condition_id="severity_rows_present",
            ),
            _artifact(
                owner, "status_binding.md",
                artifact_class="CONDITIONAL", writer="DRIVER",
                condition_id="status_rows_present",
            ),
            _artifact(
                owner, "report_index_coverage_seed.md",
                artifact_class="DRIVER_GENERATED", writer="DRIVER",
                minimum_gate="CANDIDATE_ID_SUPERSET",
            ),
            _artifact(
                owner, "candidate_semantic_facets.md",
                artifact_class="DRIVER_GENERATED", writer="DRIVER",
            ),
            _artifact(
                owner, "candidate_semantic_facets.json",
                artifact_class="DRIVER_GENERATED", writer="DRIVER",
                schema_version="plamen.candidate_semantic_facets.v1",
            ),
            *tuple(
                _artifact(
                    owner, path,
                    artifact_class="DRIVER_GENERATED", writer="DRIVER",
                    minimum_gate="TIER_PARTITION_PARITY",
                )
                for path in (
                    "report_index_seed_critical_high.md",
                    "report_index_seed_medium.md",
                    "report_index_seed_low_info.md",
                )
            ),
            _artifact(
                owner, "external_research_gaps.md",
                artifact_class="CONDITIONAL", writer="DRIVER",
                condition_id="external_research_gaps_present",
            ),
        )
        immutable = _identities(semantic_inputs)
        model_invoked = False

    elif (
        phase_n == "report_index"
        and (
            work_n == "model"
            or re.fullmatch(r"model\.attempt-\d{4}", work_n)
        )
    ):
        outputs = tuple(
            _artifact(
                owner, path,
                artifact_class="REQUIRED", writer="MODEL",
                minimum_gate="REPORT_INDEX_COMPLETENESS",
            )
            for path in (
                "report_index.md",
                "report_coverage.md",
                *(("report_records.json",) if pipeline_n == "l1" else ()),
            )
        )
        semantic_inputs = _report_candidate_semantic_inputs(
            exact_inputs,
            (
                "severity_binding.md", "status_binding.md",
                "report_index_coverage_seed.md",
                "candidate_semantic_facets.md",
                "candidate_semantic_facets.json",
                "external_research_gaps.md",
                "precedent_report_context.md",
                "verification_queue.md",
                *_SECURITY_OBLIGATION_SIDECARS,
                *_SECURITY_OBLIGATION_LIFECYCLE_SIDECARS,
            ),
            label=f"{phase_n}/{work_n}",
        )
        immutable = _identities(semantic_inputs)

    elif phase_n == "report_index" and (
        work_n == "canonicalize"
        or re.fullmatch(r"canonicalize\.attempt-\d{4}", work_n)
    ):
        if work_n == "canonicalize":
            canonical_receipt = _REPORT_INDEX_CANONICAL_RECEIPT
        else:
            canonical_ordinal = int(work_n.rsplit(".attempt-", 1)[1])
            if canonical_ordinal < 2:
                raise ValueError(
                    "report-index canonicalization retry ordinal must be >= 2"
                )
            canonical_receipt = (
                "report_index_canonicalization_receipt."
                f"attempt-{canonical_ordinal:04d}.json"
            )
        canonical_outputs = (
            *_REPORT_INDEX_CANONICAL_OUTPUTS,
            *(("report_records.json",) if pipeline_n == "l1" else ()),
            canonical_receipt,
        )
        _fixed_output_set(
            exact_outputs,
            canonical_outputs,
            label=f"{phase_n}/{work_n}",
        )
        canonical_inputs = tuple(
            _canonical_relative_path(path) for path in exact_inputs
        )
        if len(canonical_inputs) != len(set(canonical_inputs)):
            raise ValueError(
                f"{phase_n}/{work_n} contains duplicate semantic inputs"
            )
        overlap = set(canonical_inputs) & set(canonical_outputs)
        if overlap:
            raise ValueError(
                f"{phase_n}/{work_n} predecessor outputs are bound as "
                "registered output prestates, not immutable semantic inputs: "
                + ", ".join(sorted(overlap))
            )
        schema_by_path = {
            "report_index.md": "plamen.report_index_projection.v1",
            "report_coverage.md": "plamen.report_coverage_projection.v1",
            "report_records.json": "plamen.report_records.v1",
            "report_index_status_projection.json": (
                "plamen.report_index_status_projection.v1"
            ),
            "_severity_override_ledger.json": (
                "plamen.severity_overrides.v1"
            ),
            "severity_overrides.md": (
                "plamen.severity_overrides_projection.v1"
            ),
            "report_dropout_retention.json": (
                "plamen.report_dropout_retention.v1"
            ),
            "report_semantic_report_dropouts.md": (
                "plamen.report_dropout_retention_projection.v1"
            ),
            "report_index_canonicalization_journal.json": (
                "plamen.report_index_canonicalization_journal.v1"
            ),
            canonical_receipt: "plamen.report_index_canonicalization.v1",
        }
        gate_by_path = {
            "report_index.md": (
                "EXACT_PREDECESSOR_TO_CANONICAL_REPORT_DERIVATION"
            ),
            "report_coverage.md": (
                "EXACT_CANDIDATE_DENOMINATOR_AND_DROPOUT_RETENTION_PARITY"
            ),
            "report_records.json": (
                "EXACT_L1_REPORT_RECORD_DENOMINATOR_PARITY"
            ),
            "report_index_status_projection.json": (
                "EXACT_STATUS_AUTHORITY_PROJECTION"
            ),
            "_severity_override_ledger.json": (
                "EXACT_SEVERITY_OVERRIDE_AUTHORITY"
            ),
            "severity_overrides.md": (
                "EXACT_SEVERITY_OVERRIDE_AUTHORITY_PROJECTION"
            ),
            "report_dropout_retention.json": (
                "EXACT_DROPOUT_RETENTION_SOURCE_BINDING"
            ),
            "report_semantic_report_dropouts.md": (
                "EXACT_DROPOUT_RETENTION_CONTENT_PROJECTION"
            ),
            "report_index_canonicalization_journal.json": (
                "STAGED_DERIVATION_TELEMETRY_ONLY"
            ),
            canonical_receipt: (
                "INDEPENDENT_STAGED_TARGET_AND_OLD_OR_TARGET_PUBLICATION_PARITY"
            ),
        }
        outputs = tuple(
            _artifact(
                owner,
                path,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="REPLACE",
                schema_version=schema_by_path[path],
                minimum_gate=gate_by_path[path],
                consumers=(
                    ("report_index/routing", "report_body/model")
                    if path
                    in {"report_index.md", "report_coverage.md", "report_records.json"}
                    else ("report_index/routing",)
                ),
            )
            for path in canonical_outputs
        )
        # The live caller enumerates the complete typed candidate/evidence
        # authority denominator.  Rewritten predecessor outputs are deliberately
        # absent here: the artifact ledger binds those exact bytes as registered
        # output prestates for this read-modify-write successor.
        immutable = _identities(canonical_inputs)
        model_invoked = False

    elif phase_n == "report_index" and (
        work_n == "summary_parity"
        or re.fullmatch(r"summary_parity\.attempt-\d{4}", work_n)
    ):
        if work_n == "summary_parity":
            parity_receipt = "report_index_summary_parity_receipt.json"
        else:
            parity_ordinal = int(work_n.rsplit(".attempt-", 1)[1])
            if parity_ordinal < 2:
                raise ValueError(
                    "report-index Summary parity retry ordinal must be >= 2"
                )
            parity_receipt = (
                "report_index_summary_parity_receipt."
                f"attempt-{parity_ordinal:04d}.json"
            )
        passthrough_outputs = (
            "report_coverage.md",
            *(("report_records.json",) if pipeline_n == "l1" else ()),
        )
        outputs = (
            _artifact(
                owner,
                "report_index.md",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="REPLACE",
                schema_version="unstructured.v1",
                minimum_gate=(
                    "EXACT_MODEL_PREIMAGE_AND_SUMMARY_MASTER_PARITY"
                ),
                consumers=("report_index/routing", "report_body/model"),
            ),
            *(
                _artifact(
                    owner,
                    path,
                    artifact_class="DRIVER_GENERATED",
                    writer="DRIVER",
                    write_mode="REPLACE",
                    schema_version=(
                        "plamen.report_coverage_projection.v1"
                        if path == "report_coverage.md"
                        else "plamen.report_records.v1"
                    ),
                    minimum_gate=(
                        "EXACT_REGISTERED_MODEL_PREDECESSOR_BYTE_PASSTHROUGH"
                    ),
                    consumers=("report_index/routing", "report_body/model"),
                )
                for path in passthrough_outputs
            ),
            _artifact(
                owner,
                parity_receipt,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="REPLACE",
                schema_version="plamen.report_index_summary_parity.v1",
                minimum_gate=(
                    "EXACT_SUMMARY_ONLY_SUCCESSOR_DERIVATION_RECEIPT"
                ),
                consumers=("report_index/routing",),
            ),
        )
        immutable = ()
        model_invoked = False

    elif phase_n == "report_index" and work_n == "mechanical":
        outputs = tuple(
            _artifact(
                owner, path,
                artifact_class="DRIVER_GENERATED", writer="DRIVER",
                minimum_gate="REPORT_INDEX_COMPLETENESS",
            )
            for path in (
                "report_index.md",
                "report_coverage.md",
                *(("report_records.json",) if pipeline_n == "l1" else ()),
            )
        )
        semantic_inputs = _report_candidate_semantic_inputs(
            exact_inputs,
            _REPORT_INDEX_LEGACY_DENOMINATOR,
            label=f"{phase_n}/{work_n}",
        )
        immutable = _identities(semantic_inputs)
        model_invoked = False

    elif phase_n == "report_index" and work_n == "routing":
        outputs = _dynamic_specs(
            owner, exact_outputs, writer="DRIVER",
            conditional_output_ids=conditional_output_ids,
            condition_id=condition_id,
        )
        routing_base = (
            "report_index.md",
            "report_coverage.md",
            *(("report_records.json",) if pipeline_n == "l1" else ()),
        )
        semantic_inputs = _report_candidate_semantic_inputs(
            exact_inputs,
            routing_base,
            label=f"{phase_n}/{work_n}",
        )
        if exact_inputs and not set(routing_base).issubset(
            set(semantic_inputs)
        ):
            raise ValueError(
                "report_index/routing requires the report-index outputs "
                "alongside the typed candidate universe"
            )
        immutable = _identities(semantic_inputs)
        model_invoked = False

    elif phase_n == "depth" and work_n == "finalization_report_authority":
        _fixed_path_set(
            exact_inputs,
            (),
            label=f"{phase_n}/{work_n}",
        )
        _fixed_output_set(
            exact_outputs,
            ("depth_finalization_report_authority.json",),
            label=f"{phase_n}/{work_n}",
        )
        outputs = (
            _artifact(
                owner,
                "depth_finalization_report_authority.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="CREATE",
                schema_version="plamen.depth_finalization_report_authority.v1",
                minimum_gate="FINALIZER_RECEIPT_AND_REVIEW_PROJECTION",
                consumers=("report_assemble/source_capture",),
            ),
        )
        model_invoked = False

    elif phase_n == "report_index" and work_n == "chain_deferred_authority":
        normalized_inputs = tuple(
            sorted(_canonical_relative_path(path) for path in exact_inputs)
        )
        if "chain_hypotheses.md" not in normalized_inputs:
            raise ValueError(
                "report_index/chain_deferred_authority requires chain_hypotheses.md"
            )
        _fixed_output_set(
            exact_outputs,
            ("report_semantic_chain_deferred.md",),
            label=f"{phase_n}/{work_n}",
        )
        input_authority_requirements = _strict_dynamic_input_authorities(
            normalized_inputs,
            exact_input_authorities,
            label="report_index/chain_deferred_authority",
        )
        outputs = (
            _artifact(
                owner,
                "report_semantic_chain_deferred.md",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="CREATE",
                schema_version="plamen.report_semantic_chain_deferred.v1",
                minimum_gate="JUSTIFIED_CHAIN_AND_QUEUE_DENOMINATOR",
                consumers=("report_assemble/source_capture",),
            ),
        )
        immutable = _identities(normalized_inputs)
        model_invoked = False

    elif phase_n == "report_index" and work_n == "human_review_authority":
        normalized_inputs = tuple(
            sorted(_canonical_relative_path(path) for path in exact_inputs)
        )
        if not {"report_index.md", "report_coverage.md"}.issubset(
            normalized_inputs
        ):
            raise ValueError(
                "report_index/human_review_authority requires canonical index "
                "and coverage inputs"
            )
        normalized_outputs = tuple(
            sorted(_canonical_relative_path(path) for path in exact_outputs)
        )
        allowed_outputs = set(_REPORT_HUMAN_REVIEW_AUTHORITY_OUTPUTS)
        if (
            "report_human_review_authority.json" not in normalized_outputs
            or not set(normalized_outputs).issubset(allowed_outputs)
            or len(normalized_outputs) != len(set(normalized_outputs))
        ):
            raise ValueError(
                "report_index/human_review_authority requires its authority "
                "JSON and only the exact materialized review-section subset"
            )
        input_authority_requirements = _strict_dynamic_input_authorities(
            normalized_inputs,
            exact_input_authorities,
            label="report_index/human_review_authority",
        )
        outputs = tuple(
            _artifact(
                owner,
                path,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="CREATE",
                condition_id="",
                schema_version=(
                    "plamen.report_human_review_authority.v1"
                    if path.endswith(".json")
                    else "plamen.report_human_review_markdown.v1"
                ),
                minimum_gate=(
                    "VALIDATOR_BYTES_AND_EXACT_CURRENT_INPUT_AUTHORITY"
                ),
                consumers=("report_assemble/source_capture",),
            )
            for path in normalized_outputs
        )
        immutable = _identities(normalized_inputs)
        model_invoked = False

    elif phase_n == "report_assemble" and work_n == "source_path_authority":
        _fixed_path_set(
            exact_inputs,
            (),
            label=f"{phase_n}/{work_n}",
        )
        _fixed_output_set(
            exact_outputs,
            (_REPORT_SOURCE_PATH_AUTHORITY,),
            label=f"{phase_n}/{work_n}",
        )
        outputs = (
            _artifact(
                owner,
                _REPORT_SOURCE_PATH_AUTHORITY,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="CREATE",
                schema_version="plamen.report_source_path_authority.v1",
                minimum_gate=(
                    "BOUND_AUDIT_SNAPSHOT_AND_EXACT_PRODUCTION_PATH_ROSTER"
                ),
                consumers=("report_assemble/source_capture",),
            ),
        )
        immutable = ()
        model_invoked = False

    elif phase_n == "report_assemble" and work_n == "source_capture":
        _fixed_output_set(
            exact_outputs,
            (_REPORT_ASSEMBLY_SOURCE_CAPTURE,),
            label=f"{phase_n}/{work_n}",
        )
        _program_facts_alias_free_paths(
            exact_inputs,
            label=f"{phase_n}/{work_n} exact inputs",
        )
        normalized_inputs = tuple(
            sorted(_canonical_relative_path(path) for path in exact_inputs)
        )
        if _REPORT_ASSEMBLY_SOURCE_CAPTURE in normalized_inputs:
            raise ValueError(
                "report_assemble/source_capture cannot consume its own output"
            )
        input_authority_requirements = _strict_dynamic_input_authorities(
            normalized_inputs,
            exact_input_authorities,
            label="source_capture",
        )
        outputs = (
            _artifact(
                owner,
                _REPORT_ASSEMBLY_SOURCE_CAPTURE,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="CREATE",
                schema_version="plamen.report_assembly_source_capture.v3",
                minimum_gate=(
                    "EXACT_BYTES_EXPLICIT_ABSENCE_AND_NAMESPACE_ROSTER_REPLAY"
                ),
                consumers=(
                    "report_assemble/tier_capture",
                    "report_assemble/appendix_projection",
                    "report_assemble/final_capture",
                ),
            ),
        )
        immutable = _identities(normalized_inputs)
        model_invoked = False

    elif phase_n == "report_assemble" and work_n == "final_capture":
        canonical_inputs = _fixed_path_set(
            exact_inputs,
            (_REPORT_ASSEMBLY_SOURCE_CAPTURE,),
            label=f"{phase_n}/{work_n}",
        )
        _fixed_output_set(
            exact_outputs,
            (_REPORT_ASSEMBLY_FINAL_CAPTURE,),
            label=f"{phase_n}/{work_n}",
        )
        outputs = (
            _artifact(
                owner,
                _REPORT_ASSEMBLY_FINAL_CAPTURE,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="CREATE",
                schema_version="plamen.report_assembly_final_capture.v1",
                minimum_gate=(
                    "EXACT_SOURCE_PREDECESSOR_BINDING_AND_SEVEN_OUTPUT_ROSTER"
                ),
                consumers=("report_assemble/assembly",),
            ),
        )
        immutable = _identities(canonical_inputs)
        input_authority_requirements = (
            InputAuthorityRequirement(
                identity=canonical_artifact_identity(
                    "scratchpad", _REPORT_ASSEMBLY_SOURCE_CAPTURE
                ),
                expected_producer_work_unit_key=canonical_work_unit_key(
                    pipeline_n,
                    mode_n,
                    ecosystem_n,
                    backend_n,
                    "report_assemble",
                    "source_capture",
                ),
                expected_writer="DRIVER",
            ),
        )
        model_invoked = False

    elif phase_n == "report_assemble" and work_n == "tier_capture":
        canonical_inputs = _fixed_path_set(
            exact_inputs,
            (_REPORT_ASSEMBLY_SOURCE_CAPTURE,),
            label=f"{phase_n}/{work_n}",
        )
        canonical_outputs = _fixed_output_set(
            exact_outputs,
            _REPORT_ASSEMBLY_TIER_CAPTURE_OUTPUTS,
            label=f"{phase_n}/{work_n}",
        )
        outputs = tuple(
            _artifact(
                owner,
                path,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="CREATE",
                schema_version=(
                    "plamen.report_assembly_tier_capture.v1"
                    if path.endswith(".json")
                    else "plamen.report_assembly_staged_markdown.v1"
                ),
                minimum_gate=(
                    "NON_AUTHORITATIVE_TIER_PROJECTION_OVER_FROZEN_CAPTURE"
                ),
                consumers=(),
            )
            for path in canonical_outputs
        )
        immutable = _identities(canonical_inputs)
        input_authority_requirements = (
            InputAuthorityRequirement(
                identity=canonical_artifact_identity(
                    "scratchpad", _REPORT_ASSEMBLY_SOURCE_CAPTURE
                ),
                expected_producer_work_unit_key=canonical_work_unit_key(
                    pipeline_n,
                    mode_n,
                    ecosystem_n,
                    backend_n,
                    "report_assemble",
                    "source_capture",
                ),
                expected_writer="DRIVER",
            ),
        )
        model_invoked = False

    elif phase_n == "report_assemble" and work_n == "appendix_projection":
        canonical_inputs = _fixed_path_set(
            exact_inputs,
            (_REPORT_ASSEMBLY_SOURCE_CAPTURE,),
            label=f"{phase_n}/{work_n}",
        )
        canonical_outputs = _fixed_output_set(
            exact_outputs,
            _REPORT_ASSEMBLY_APPENDIX_OUTPUTS,
            label=f"{phase_n}/{work_n}",
        )
        outputs = tuple(
            _artifact(
                owner,
                path,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="CREATE",
                schema_version=(
                    "plamen.report_human_review_appendix.v1"
                    if path.endswith(".json")
                    else "plamen.report_human_review_appendix_markdown.v1"
                ),
                minimum_gate=(
                    "NON_AUTHORITATIVE_APPENDIX_PROJECTION_OVER_FROZEN_CAPTURE"
                ),
                consumers=(),
            )
            for path in canonical_outputs
        )
        immutable = _identities(canonical_inputs)
        input_authority_requirements = (
            InputAuthorityRequirement(
                identity=canonical_artifact_identity(
                    "scratchpad", _REPORT_ASSEMBLY_SOURCE_CAPTURE
                ),
                expected_producer_work_unit_key=canonical_work_unit_key(
                    pipeline_n,
                    mode_n,
                    ecosystem_n,
                    backend_n,
                    "report_assemble",
                    "source_capture",
                ),
                expected_writer="DRIVER",
            ),
        )
        model_invoked = False

    elif phase_n == "report_assemble" and work_n == "assembly":
        normalized_inputs = tuple(
            _canonical_relative_path(path) for path in exact_inputs
        )
        if _REPORT_ASSEMBLY_SOURCE_CAPTURE in normalized_inputs:
            raise ValueError(
                "report_assemble/final_capture is the sole production "
                "assembly predecessor; a source capture carries no output "
                "authority"
            )
        captured_assembly = (
            _REPORT_ASSEMBLY_FINAL_CAPTURE in normalized_inputs
        )
        if captured_assembly:
            if normalized_inputs != (_REPORT_ASSEMBLY_FINAL_CAPTURE,):
                raise ValueError(
                    "report_assemble/final_capture is the sole production "
                    "assembly predecessor; decomposed tier/appendix projections "
                    "are non-authoritative"
                )
            input_authority_requirements = tuple(
                InputAuthorityRequirement(
                    identity=canonical_artifact_identity(
                        "scratchpad", path
                    ),
                    expected_producer_work_unit_key=canonical_work_unit_key(
                        pipeline_n,
                        mode_n,
                        ecosystem_n,
                        backend_n,
                        "report_assemble",
                        "final_capture",
                    ),
                    expected_writer="DRIVER",
                )
                for path in normalized_inputs
            )
        # Until the driver/mechanical integration slice lands, legacy raw
        # denominators remain resolvable.  The captured path above is closed;
        # the focused integration RED proves the runtime still selects legacy.
        if captured_assembly:
            if conditional_output_ids or condition_id:
                raise ValueError(
                    "report_assemble/assembly output conditions are derived "
                    "only from the committed final capture"
                )
            requested_outputs = tuple(
                _canonical_relative_path(path) for path in exact_outputs
            )
            if (
                len(requested_outputs) != len(set(requested_outputs))
                or set(requested_outputs)
                != set(_REPORT_ASSEMBLY_PUBLISH_OUTPUTS)
                or len(requested_outputs)
                != len(_REPORT_ASSEMBLY_PUBLISH_OUTPUTS)
            ):
                raise ValueError(
                    "report_assemble/assembly requires the exact seven-output "
                    "denominator carried by the final capture"
                )
            canonical_outputs = _REPORT_ASSEMBLY_PUBLISH_OUTPUTS
            outputs = tuple(
                _artifact(
                    owner,
                    path,
                    root=("project" if path == "AUDIT_REPORT.md" else "scratchpad"),
                    artifact_class=(
                        "DRIVER_GENERATED"
                        if path in {"AUDIT_REPORT.md", "report_quality.md"}
                        else "CONDITIONAL"
                    ),
                    writer="DRIVER",
                    write_mode="REPLACE",
                    condition_id=(
                        "report_assembly_final_capture_output_presence"
                        if path not in {"AUDIT_REPORT.md", "report_quality.md"}
                        else ""
                    ),
                    schema_version=(
                        "plamen.report_assembly_final_published_json.v1"
                        if path.endswith(".json")
                        else "plamen.report_assembly_final_published_markdown.v1"
                    ),
                    minimum_gate=(
                        "EXACT_CAPTURED_OUTPUT_BYTES_AND_HASH_PUBLICATION"
                    ),
                )
                for path in canonical_outputs
            )
        else:
            outputs = (
                _artifact(
                    owner,
                    "AUDIT_REPORT.md",
                    root="project",
                    artifact_class="DRIVER_GENERATED",
                    writer="DRIVER",
                    write_mode="REPLACE",
                    minimum_gate="DETERMINISTIC_TIER_ASSEMBLY_AND_QUALITY",
                ),
            )
        immutable = _identities(normalized_inputs)
        model_invoked = False

    elif phase_n == "report_floor" and work_n == "disposition_authority":
        outputs = (
            _artifact(
                owner,
                "report_disposition_authority.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.report_disposition_authority.v1",
                minimum_gate="INDEPENDENT_DECISION_AND_SOURCE_HASH_BINDING",
            ),
            _artifact(
                owner,
                "report_appendix_full_content.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.report_appendix_full_content.v1",
                minimum_gate="LOSSLESS_RELOCATION_AND_CLIENT_FIELD_DIFF",
            ),
            _artifact(
                owner,
                "material_harm_floor.md",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                minimum_gate="VISIBLE_DISPOSITION_DEBT",
            ),
            _artifact(
                owner,
                "report_disposition_merge_intent.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.report_disposition_merge_intent.v1",
                minimum_gate="PREWRITE_REPORT_IDENTITY_DENOMINATOR",
            ),
            _artifact(
                owner,
                "AUDIT_REPORT.md",
                root="project",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="MERGE",
                minimum_gate="AUTHORIZED_APPENDIX_RELOCATION_ONLY",
            ),
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif phase_n == "report_floor" and work_n == "assurance_projection":
        outputs = (
            _artifact(
                owner,
                "assurance_limitations.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.assurance_limitations.v1",
                minimum_gate="AUTHORITATIVE_CHECKPOINT_PARITY",
            ),
            _artifact(
                owner,
                "assurance_limitations.md",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                minimum_gate="EXACT_RENDER_PARITY",
            ),
            _artifact(
                owner,
                "assurance_limitations_projection.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.assurance_limitations_projection.v1",
                minimum_gate="BOUNDED_PROJECTION_PARITY",
            ),
            _artifact(
                owner,
                "assurance_projection_merge_intent.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.assurance_projection_merge_intent.v1",
                minimum_gate="PREWRITE_REPORT_IDENTITY_DENOMINATOR",
            ),
            _artifact(
                owner,
                "AUDIT_REPORT.md",
                root="project",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="MERGE",
                minimum_gate="ASSURANCE_PROJECTION_PARITY",
            ),
        )
        immutable = _identities(("_v2_checkpoint.json", *exact_inputs))
        model_invoked = False

    elif phase_n == "report_floor" and work_n == "chain_grouping_assurance":
        outputs = (
            _artifact(
                owner,
                "chain_grouping_assurance_reconciliation.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.chain_grouping_assurance_reconciliation.v1",
                minimum_gate="INDEPENDENT_MEMBER_DELIVERY_REPLAY",
            ),
            _artifact(
                owner,
                "chain_grouping_assurance_limitations.md",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                minimum_gate="EXACT_ASSURANCE_DEBT_PROJECTION",
            ),
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif phase_n == "report_floor" and work_n == "evidence_quality":
        _fixed_output_set(
            exact_outputs,
            ("report_evidence_quality_receipt.json",),
            label=f"{phase_n}/{work_n}",
        )
        if (
            "report_evidence_records.json" not in exact_inputs
            or "report_evidence_projection.md" not in exact_inputs
            or not any(
                path.startswith("report_evidence_manifests/")
                for path in exact_inputs
            )
        ):
            raise ValueError(
                "report_floor/evidence_quality requires the exact typed report evidence set"
            )
        outputs = (
            _artifact(
                owner,
                "report_evidence_quality_receipt.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.report_quality_receipt.v1",
                minimum_gate="TYPED_MANIFEST_MARKDOWN_DELIVERY_PARITY",
            ),
        )
        immutable = _identities(exact_inputs)
        bounded = (canonical_artifact_identity("project", "AUDIT_REPORT.md"),)
        model_invoked = False

    elif phase_n == "verify_recovery" and work_n == "compatibility_projection":
        _fixed_output_set(
            exact_outputs,
            (
                "verification_queue_recovery.md",
                "_prompt_verify_recovery.attempt1.md",
            ),
            label=f"{phase_n}/{work_n}",
        )
        recovery_manifests = tuple(
            path
            for path in exact_inputs
            if path.startswith("_verification_recovery/VREC-")
            and path.endswith("/manifest.md")
        )
        recovery_prompts = tuple(
            path
            for path in exact_inputs
            if path.startswith("_verification_recovery/VREC-")
            and PurePosixPath(path).name
            in {"prompt.md", "prompt_with_bb_policy.md"}
        )
        if (
            len(exact_inputs) != 2
            or len(recovery_manifests) != 1
            or len(recovery_prompts) != 1
            or PurePosixPath(recovery_manifests[0]).parent
            != PurePosixPath(recovery_prompts[0]).parent
        ):
            raise ValueError(
                "verify_recovery/compatibility_projection requires one "
                "co-rooted compiler-bound manifest and prompt"
            )
        outputs = tuple(
            _artifact(
                owner,
                path,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                minimum_gate="EXACT_COMPILER_BOUND_RECOVERY_PROJECTION",
            )
            for path in exact_outputs
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif phase_n == "verify_recovery" and work_n.startswith("model."):
        outputs = _dynamic_specs(
            owner,
            exact_outputs,
            writer="MODEL",
            conditional_output_ids=(),
            condition_id="",
        )
        immutable = _identities(exact_inputs)
        model_invoked = True

    elif phase_n == "verify_recovery" and work_n.startswith("control."):
        outputs = _dynamic_specs(
            owner,
            exact_outputs,
            writer="DRIVER",
            conditional_output_ids=conditional_output_ids,
            condition_id=condition_id,
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif phase_n == "verify" and work_n == "runtime_debt":
        _fixed_output_set(
            exact_outputs,
            (
                "verification_runtime_debt.json",
                "verification_runtime_debt.md",
            ),
            label=f"{phase_n}/{work_n}",
        )
        if "verification_queue.md" not in exact_inputs:
            raise ValueError(
                "verify/runtime_debt requires the exact verification queue"
            )
        invalid_inputs = [
            path
            for path in exact_inputs
            if path not in {
                "verification_queue.md",
                "verification_queue.work_plan.json",
            }
        ]
        if invalid_inputs:
            raise ValueError(
                "verify/runtime_debt received an unregistered input: "
                + ", ".join(sorted(invalid_inputs))
            )
        outputs = (
            _artifact(
                owner,
                "verification_runtime_debt.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.verification_runtime_debt.v2",
                minimum_gate=(
                    "EXACT_QUEUE_DENOMINATOR_AND_PROOF_FREE_RETENTION"
                ),
                consumers=("report_index/model", "report_body/evidence_pre"),
            ),
            _artifact(
                owner,
                "verification_runtime_debt.md",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.verification_runtime_debt_projection.v1",
                minimum_gate="EXACT_VISIBLE_UNRESOLVED_PROJECTION",
                consumers=("report_index/model",),
            ),
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif (
        (phase_n.startswith("verify_") or phase_n.startswith("sc_verify_"))
        and work_n.startswith("method_model.")
    ):
        outputs = _dynamic_specs(
            owner,
            exact_outputs,
            writer="MODEL",
            conditional_output_ids=(),
            condition_id="",
        )
        immutable = _identities(exact_inputs)
        model_invoked = True

    elif (
        (phase_n.startswith("verify_") or phase_n.startswith("sc_verify_"))
        and (
            work_n.startswith("method_context.")
            or work_n.startswith("method_dispatch.")
            or work_n.startswith("method_receipt.")
        )
    ):
        outputs = _dynamic_specs(
            owner,
            exact_outputs,
            writer="DRIVER",
            conditional_output_ids=conditional_output_ids,
            condition_id=condition_id,
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif phase_n == "verify_queue" and work_n == "l1_composition.fact_worklist":
        _fixed_output_set(
            exact_outputs,
            ("l1_composition_fact_worklist.json",),
            label=f"{phase_n}/{work_n}",
        )
        sources = _l1_composition_sources(exact_inputs)
        outputs = (
            _artifact(
                owner,
                "l1_composition_fact_worklist.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.l1_composition_fact_worklist.v1",
                minimum_gate="EXACT_SOURCE_OCCURRENCE_DENOMINATOR",
                consumers=("verify_queue/worker.l1_composition_facts",),
            ),
        )
        immutable = _identities(sources)
        model_invoked = False

    elif phase_n == "verify_queue" and work_n == "worker.l1_composition_facts":
        _fixed_output_set(
            exact_outputs,
            ("l1_composition_fact_records.json",),
            label=f"{phase_n}/{work_n}",
        )
        if not exact_inputs or exact_inputs[0] != "l1_composition_fact_worklist.json":
            raise ValueError("L1 composition fact worker requires its exact worklist")
        _l1_composition_sources(tuple(exact_inputs[1:]))
        outputs = (
            _artifact(
                owner,
                "l1_composition_fact_records.json",
                artifact_class="REQUIRED",
                writer="MODEL",
                schema_version="plamen.l1_composition_typed_records.v1",
                minimum_gate="ONE_TYPED_FACT_PER_BOUND_SOURCE_OCCURRENCE",
                consumers=("verify_queue/l1_composition.runtime",),
            ),
        )
        immutable = _identities(exact_inputs)

    elif phase_n == "verify_queue" and work_n == "l1_composition.runtime":
        _fixed_output_set(
            exact_outputs,
            ("l1_composition_runtime.json",),
            label=f"{phase_n}/{work_n}",
        )
        if not exact_inputs or exact_inputs[-1] != "l1_composition_fact_records.json":
            raise ValueError("L1 composition runtime requires typed fact records")
        _l1_composition_sources(tuple(exact_inputs[:-1]))
        outputs = (
            _artifact(
                owner,
                "l1_composition_runtime.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.l1_composition_runtime.v1",
                minimum_gate="EXACT_TYPED_GRAPH_AND_OBLIGATION_ENUMERATION",
                consumers=("verify_queue/worker.l1_composition_dispositions",),
            ),
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif phase_n == "verify_queue" and work_n == "worker.l1_composition_dispositions":
        _fixed_output_set(
            exact_outputs,
            ("l1_composition_model_dispositions.json",),
            label=f"{phase_n}/{work_n}",
        )
        if not exact_inputs or exact_inputs[0] != "l1_composition_runtime.json":
            raise ValueError("L1 disposition worker requires the exact runtime")
        _l1_composition_sources(tuple(exact_inputs[1:]))
        outputs = (
            _artifact(
                owner,
                "l1_composition_model_dispositions.json",
                artifact_class="REQUIRED",
                writer="MODEL",
                schema_version="plamen.l1_composition_model_dispositions.v1",
                minimum_gate="EXACT_INDEPENDENT_OBLIGATION_DISPOSITION_COVERAGE",
                consumers=("verify_queue/l1_composition.reconcile",),
            ),
        )
        immutable = _identities(exact_inputs)

    elif phase_n == "verify_queue" and work_n == "l1_composition.reconcile":
        _fixed_output_set(
            exact_outputs,
            ("l1_composition_receipt.json",),
            label=f"{phase_n}/{work_n}",
        )
        if set(exact_inputs) != {
            "l1_composition_runtime.json",
            "l1_composition_model_dispositions.json",
        } or len(exact_inputs) != 2:
            raise ValueError("L1 reconciliation requires runtime plus dispositions")
        outputs = (
            _artifact(
                owner,
                "l1_composition_receipt.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.l1_composition_runtime_receipt.v1",
                minimum_gate="INDEPENDENT_RECONCILIATION_PROPOSAL_ONLY",
                consumers=("verify_queue/l1_composition.queue_delivery",),
            ),
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif (
        phase_n in {"verify_queue", "sc_verify_queue"}
        and work_n.startswith("preverify_capture.")
    ):
        capture_rows: list[tuple[str, str]] = []
        for raw_value in exact_inputs:
            raw = str(raw_value)
            root_name = "project" if raw.startswith("project::") else "scratchpad"
            relative = raw[len("project::"):] if root_name == "project" else raw
            capture_rows.append(
                (root_name, _canonical_relative_path(relative))
            )
        reserved_leaves = {
            "findings_inventory.md",
            "finding_records.json",
        }
        reserved_rows = tuple(
            (root_name, relative)
            for root_name, relative in capture_rows
            if PurePosixPath(relative).name in reserved_leaves
        )
        pair_kind = ""
        frozen_generation_root = ""
        if len(reserved_rows) == 2 and all(
            root_name == "scratchpad"
            for root_name, _relative in reserved_rows
        ):
            pair_paths = tuple(
                PurePosixPath(relative)
                for _root_name, relative in reserved_rows
            )
            parents = {path.parent.as_posix() for path in pair_paths}
            leaves = {path.name for path in pair_paths}
            if len(parents) == 1 and leaves == reserved_leaves:
                candidate_root = next(iter(parents))
                root_parts = PurePosixPath(candidate_root).parts
                if (
                    len(root_parts) == 2
                    and root_parts[0] == "_preverify_frozen"
                    and re.fullmatch(
                        r"generation_[0-9a-f]{64}",
                        root_parts[1],
                    )
                    is not None
                ):
                    pair_kind = "FROZEN"
                    frozen_generation_root = candidate_root
        if pair_kind == "FROZEN":
            frozen_receipt = (
                frozen_generation_root + "/receipt.json"
            )
            if ("scratchpad", frozen_receipt) not in capture_rows:
                pair_kind = ""
        work_digest_match = re.fullmatch(
            r"preverify_capture\.([0-9a-f]{64})",
            work_n,
        )
        output_digest_match = (
            re.fullmatch(
                r"_preverify_successors/generation_([0-9a-f]{64})\.json",
                exact_outputs[0],
            )
            if len(exact_outputs) == 1
            else None
        )
        if (
            len(exact_outputs) != 1
            or not exact_inputs
            or not pair_kind
            or work_digest_match is None
            or output_digest_match is None
            or work_digest_match.group(1) != output_digest_match.group(1)
        ):
            raise ValueError(
                f"{phase_n}/{work_n} requires one content-addressed "
                "generation output and an exact non-empty capture denominator "
                "including the paired findings_inventory.md and "
                "finding_records.json projections"
            )
        outputs = (
            _artifact(
                owner,
                exact_outputs[0],
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.preverify_successor_generation.v2",
                minimum_gate=(
                    "CONTENT_ADDRESSED_CURRENT_INVENTORY_AND_DELIVERY_CAPTURE"
                ),
                consumers=(f"{phase_n}/preverify_successors",),
            ),
        )
        immutable = _mixed_identities(exact_inputs)
        model_invoked = False

    elif (
        phase_n in {"verify_queue", "sc_verify_queue"}
        and work_n == "preverify_successors"
    ):
        _fixed_output_set(
            exact_outputs,
            (
                "preverify_inventory_successor.json",
                "finding_delivery_successor.json",
            ),
            label=f"{phase_n}/{work_n}",
        )
        normalized_inputs = tuple(
            _canonical_relative_path(path) for path in exact_inputs
        )
        if (
            len(normalized_inputs) != 1
            or re.fullmatch(
                r"_preverify_successors/generation_[0-9a-f]{64}\.json",
                normalized_inputs[0],
            )
            is None
        ):
            raise ValueError(
                f"{phase_n}/{work_n} requires one content-addressed "
                "preverify generation"
            )
        outputs = (
            _artifact(
                owner,
                "preverify_inventory_successor.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.preverify_inventory_successor.v1",
                minimum_gate=(
                    "EXACT_FINAL_INVENTORY_AND_IMMUTABLE_PRODUCER_DENOMINATOR"
                ),
                consumers=(f"{phase_n}/routing",),
            ),
            _artifact(
                owner,
                "finding_delivery_successor.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                schema_version="plamen.finding_delivery_successor.v1",
                minimum_gate=(
                    "EXACT_FINAL_INVENTORY_TO_REGISTERED_ACTION_DISPOSITION"
                ),
                consumers=(f"{phase_n}/routing",),
            ),
        )
        immutable = _identities(normalized_inputs)
        model_invoked = False

    elif phase_n in {"verify_queue", "sc_verify_queue"} and work_n == "routing":
        required_routing_inputs = {
            "findings_inventory.md",
            "preverify_inventory_successor.json",
            "finding_delivery_successor.json",
        }
        normalized_routing_inputs = {
            _canonical_relative_path(path) for path in exact_inputs
        }
        if not required_routing_inputs.issubset(
            normalized_routing_inputs
        ):
            raise ValueError(
                f"{phase_n}/{work_n} requires the mandatory final inventory "
                "and both preverify successor inputs"
            )
        outputs = _dynamic_specs(
            owner, exact_outputs, writer="DRIVER",
            conditional_output_ids=conditional_output_ids,
            condition_id=condition_id,
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif (
        phase_n == "semantic_identity"
        and work_n.startswith("projection.")
    ):
        required = {
            "_canonical_finding_ids.json",
            "_unmapped_id_tokens.json",
        }
        if set(exact_outputs) != required or len(exact_outputs) != 2:
            raise ValueError(
                "semantic_identity projection requires its exact canonical "
                "map and unmapped-token sidecars"
            )
        outputs = tuple(
            _artifact(
                owner,
                path,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="REPLACE",
                schema_version=(
                    "plamen.canonical_finding_ids.v1"
                    if path == "_canonical_finding_ids.json"
                    else "plamen.unmapped_id_tokens.v1"
                ),
                minimum_gate=(
                    "EXACT_REGISTERED_PRODUCER_IDENTITY_PROJECTION"
                ),
                consumers=(
                    "verify_queue/preverify_capture",
                    "sc_verify_queue/preverify_capture",
                ),
            )
            for path in exact_outputs
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif phase_n == "bb_policy" and work_n == "ingress":
        _fixed_output_set(
            exact_outputs,
            (".bb/verification_operator_policy.json",),
            label=f"{phase_n}/{work_n}",
        )
        if exact_inputs:
            raise ValueError(
                "bb_policy/ingress binds its external preimage through the "
                "validated payload and audit snapshot, not an artifact glob"
            )
        outputs = (
            _artifact(
                owner,
                ".bb/verification_operator_policy.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="CREATE",
                schema_version=(
                    "plamen.bb.verification-policy-ingress.v1"
                ),
                minimum_gate=(
                    "EXACT_EXTERNAL_DIGEST_SANITIZED_VERIFICATION_ONLY"
                ),
                consumers=(
                    "bb_policy/projection",
                    "verify_queue/worker",
                    "sc_verify_queue/worker",
                    "verify_recovery/worker",
                ),
            ),
        )
        model_invoked = False

    elif (
        phase_n == "bb_policy"
        and work_n.startswith("projection.")
    ):
        normalized_inputs = tuple(
            _canonical_relative_path(path) for path in exact_inputs
        )
        if normalized_inputs != (
            ".bb/verification_operator_policy.json",
        ):
            raise ValueError(
                "bb_policy projection requires the exact sanitized ingress"
            )
        if len(exact_outputs) != 1:
            raise ValueError(
                "bb_policy projection requires one exact local work packet"
            )
        outputs = _dynamic_specs(
            owner,
            exact_outputs,
            writer="DRIVER",
            conditional_output_ids=(),
            condition_id="",
        )
        immutable = _identities(normalized_inputs)
        model_invoked = False

    elif (
        phase_n == "bb_policy"
        and work_n.startswith("consumption.")
    ):
        if not exact_inputs:
            raise ValueError(
                "bb_policy consumption requires its exact work, proposal, "
                "dispatch, launch, and verifier-output denominator"
            )
        if len(exact_outputs) != 1:
            raise ValueError(
                "bb_policy consumption requires one exact driver receipt"
            )
        outputs = _dynamic_specs(
            owner,
            exact_outputs,
            writer="DRIVER",
            conditional_output_ids=(),
            condition_id="",
        )
        immutable = _identities(exact_inputs)
        model_invoked = False

    elif (
        phase_n == "bb_policy"
        and work_n == "terminal_reconciliation"
    ):
        _fixed_output_set(
            exact_outputs,
            (".bb/verification_policy_reconciliation.json",),
            label=f"{phase_n}/{work_n}",
        )
        normalized_inputs = tuple(
            _canonical_relative_path(path) for path in exact_inputs
        )
        work_parents = {
            PurePosixPath(path).parent
            for path in normalized_inputs
            if PurePosixPath(path).name == "bb_policy_work.json"
        }
        application_parents = {
            PurePosixPath(path).parent
            for path in normalized_inputs
            if PurePosixPath(path).name == "bb_policy_application.json"
        }
        receipt_parents = {
            PurePosixPath(path).parent
            for path in normalized_inputs
            if PurePosixPath(path).name
            == "bb_policy_consumption_receipt.json"
        }
        if (
            ".bb/verification_operator_policy.json"
            not in normalized_inputs
            or not application_parents.issubset(work_parents)
            or not receipt_parents.issubset(application_parents)
        ):
            raise ValueError(
                "bb_policy terminal reconciliation requires the sanitized "
                "ingress plus an exact prefix-closed roster of local "
                "work/application/receipt artifacts"
            )
        outputs = (
            _artifact(
                owner,
                ".bb/verification_policy_reconciliation.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="CREATE",
                schema_version=(
                    "plamen.bb.verification-policy-reconciliation.v1"
                ),
                minimum_gate=(
                    "EXACT_RUN_LEVEL_POLICY_CONSUMPTION_RECONCILIATION"
                ),
                consumers=(
                    "bb_policy/severity_reverification",
                    "bb_policy/downstream.skeptic",
                    "bb_policy/downstream.report",
                ),
            ),
        )
        immutable = _identities(normalized_inputs)
        model_invoked = False

    elif (
        phase_n == "bb_policy"
        and work_n == "severity_reverification"
    ):
        _fixed_output_set(
            exact_outputs,
            (
                ".bb/verification_policy_severity_reverification.json",
            ),
            label=f"{phase_n}/{work_n}",
        )
        normalized_inputs = tuple(
            _canonical_relative_path(path) for path in exact_inputs
        )
        if set(normalized_inputs) != {
            ".bb/verification_operator_policy.json",
            ".bb/verification_policy_reconciliation.json",
        }:
            raise ValueError(
                "bb_policy severity re-verification requires the exact "
                "ingress and terminal reconciliation"
            )
        outputs = (
            _artifact(
                owner,
                ".bb/verification_policy_severity_reverification.json",
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="CREATE",
                schema_version=(
                    "plamen.bb.verification-policy-severity-reverification.v1"
                ),
                minimum_gate=(
                    "ADDITIVE_POLICY_REVERIFICATION_NO_QUEUE_MUTATION"
                ),
                consumers=("verify_recovery/bb_policy_severity_change",),
            ),
        )
        immutable = _identities(normalized_inputs)
        model_invoked = False

    elif (
        phase_n == "bb_policy"
        and work_n in {"downstream.skeptic", "downstream.report"}
    ):
        expected_output = (
            ".bb/verification_policy_skeptic_projection.json"
            if work_n.endswith(".skeptic")
            else ".bb/verification_policy_report_projection.json"
        )
        _fixed_output_set(
            exact_outputs,
            (expected_output,),
            label=f"{phase_n}/{work_n}",
        )
        normalized_inputs = tuple(
            _canonical_relative_path(path) for path in exact_inputs
        )
        if normalized_inputs != (
            ".bb/verification_policy_reconciliation.json",
        ):
            raise ValueError(
                "bb_policy downstream projection requires only the exact "
                "terminal reconciliation"
            )
        outputs = (
            _artifact(
                owner,
                expected_output,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="CREATE",
                schema_version=(
                    "plamen.bb.verification-policy-downstream.v1"
                ),
                minimum_gate=(
                    "BOUNDED_NON_NORMATIVE_RECONCILIATION_REFERENCES"
                ),
                consumers=(
                    ()
                    if work_n.endswith(".skeptic")
                    else ("report_index/model",)
                ),
            ),
        )
        immutable = _identities(normalized_inputs)
        model_invoked = False

    else:
        raise ValueError(
            f"no P0-AE resolver shape for {phase_n}/{work_n}; "
            "register the work unit and its writer authority explicitly"
        )

    if writer_n is not None:
        actual_writers = {output.writer for output in outputs}
        if actual_writers != {writer_n}:
            raise ValueError(
                f"registered writer authority for {phase_n}/{work_n} is "
                f"{', '.join(sorted(actual_writers))}; caller requested {writer_n}"
            )

    return PhaseIOContract(
        pipeline=pipeline_n,
        mode=mode_n,
        ecosystem=ecosystem_n,
        backend=backend_n,
        phase=phase_n,
        work_unit_id=work_n,
        outputs=outputs,
        immutable_inputs=immutable,
        bounded_lookup_inputs=bounded,
        model_invoked=model_invoked,
        input_authority_requirements=input_authority_requirements,
        launch_profile=launch_profile,
        required_commit_actor=required_commit_actor,
    )


def validate_program_facts_v2_private_commit_candidate(
    candidate: object,
    *,
    sealed_composition_inputs: Mapping[str, Any],
    activation_permit_document: Mapping[str, Any],
    provider_environment: Mapping[str, Any],
    expected_run_id: str,
    expected_run_generation: int,
    expected_execution_authority_digest: str,
    expected_composition_authority_digest: str,
    expected_methodology_package_digest: str,
    expected_provider_environment_digest: str,
    expected_provider_package_digest: str,
    expected_native_host_receipt_digest: str,
    expected_independent_review_receipts: Mapping[str, str],
    expected_issuer_policy_digest: str,
    expected_issuer_id: str,
    expected_release_id: str,
    expected_activation_decision_digest: str,
) -> dict[str, Any]:
    """Replay one untrusted Program Facts private-commit candidate."""

    from program_facts_positive_composer import (
        snapshot_sealed_composition_inputs_v1,
        validate_production_composition_candidate,
    )

    sealed_inputs_snapshot = snapshot_sealed_composition_inputs_v1(
        sealed_composition_inputs
    )
    return validate_production_composition_candidate(
        candidate,
        sealed_composition_inputs=sealed_inputs_snapshot,
        activation_permit_document=activation_permit_document,
        provider_environment=provider_environment,
        expected_run_id=expected_run_id,
        expected_run_generation=expected_run_generation,
        expected_execution_authority_digest=(
            expected_execution_authority_digest
        ),
        expected_composition_authority_digest=(
            expected_composition_authority_digest
        ),
        expected_methodology_package_digest=(
            expected_methodology_package_digest
        ),
        expected_provider_environment_digest=(
            expected_provider_environment_digest
        ),
        expected_provider_package_digest=expected_provider_package_digest,
        expected_native_host_receipt_digest=(
            expected_native_host_receipt_digest
        ),
        expected_independent_review_receipts=(
            expected_independent_review_receipts
        ),
        expected_issuer_policy_digest=expected_issuer_policy_digest,
        expected_issuer_id=expected_issuer_id,
        expected_release_id=expected_release_id,
        expected_activation_decision_digest=(
            expected_activation_decision_digest
        ),
    )


__all__ = [
    "ARTIFACT_CLASSES",
    "WRITERS",
    "WRITE_MODES",
    "CONDITIONAL_STATES",
    "LAUNCH_PROFILES",
    "ArtifactSpec",
    "InputAuthorityRequirement",
    "PhaseIOContract",
    "LaunchSpec",
    "ConditionalOutputReceipt",
    "DriverMergeEvent",
    "DriverOutputTransition",
    "DriverSuccessorPlan",
    "WriteObservation",
    "ContractViolation",
    "ContainmentResult",
    "canonical_artifact_identity",
    "canonical_work_unit_key",
    "driver_successor_plan_from_dict",
    "replay_driver_output_transition_authority",
    "replay_driver_successor_plan_authority",
    "replay_launch_spec_authority",
    "replay_phase_io_authority_pair",
    "replay_phase_io_contract_authority",
    "registered_projection_handoff",
    "recon_direct_retry_output_paths",
    "resolve_phase_io_contract",
    "validate_program_facts_v2_private_commit_candidate",
]
