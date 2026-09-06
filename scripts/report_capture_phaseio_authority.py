"""Ledger-resolved production boundary for report source/final captures.

Caller-owned mappings are never provenance.  Every public operation resolves
the current, committed PhaseIO producer from the active ArtifactLedger, replays
its registered contract and launch, validates its live output, and binds the
exact stable bytes to the commit receipt before delegating to the private pure
capture codec.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from audit_snapshot import (
    SnapshotInputError,
    build_production_source_path_authority,
    canonical_production_source_path_authority_bytes,
    validate_production_source_path_authority,
)
from artifact_ledger import (
    ArtifactLedgerError,
    active_committed_work_unit_authority_issues,
    read_artifact_ledger,
    validate_work_unit_artifacts,
)
from bounded_artifact_io import read_bounded_regular_bytes
from phase_io_contracts import (
    InputAuthorityRequirement,
    LaunchSpec,
    PhaseIOContract,
    replay_phase_io_authority_pair,
    resolve_phase_io_contract,
)
import report_assembly_capture as _capture
import rooted_path_io as _rooted


_MAX_CAPTURE_BYTES = 192 * 1024 * 1024
_SOURCE_NAME = "report_assembly_source_capture.json"
_FINAL_NAME = "report_assembly_final_capture.json"


@dataclass(frozen=True)
class _ReservedReportSourceAuthority:
    role: str
    phase: str
    work_unit_id: str
    schema_version: str


_RESERVED_REPORT_SOURCE_AUTHORITIES = {
    "report_source_path_authority.json": _ReservedReportSourceAuthority(
        role="PRODUCTION_SOURCE_PATH_AUTHORITY",
        phase="report_assemble",
        work_unit_id="source_path_authority",
        schema_version="plamen.report_source_path_authority.v1",
    ),
    "depth_finalization_report_authority.json": _ReservedReportSourceAuthority(
        role="DEPTH_FINALIZATION_REPORT_AUTHORITY",
        phase="depth",
        work_unit_id="finalization_report_authority",
        schema_version="plamen.depth_finalization_report_authority.v1",
    ),
    "report_human_review_authority.json": _ReservedReportSourceAuthority(
        role="REPORT_HUMAN_REVIEW_AUTHORITY",
        phase="report_index",
        work_unit_id="human_review_authority",
        schema_version="plamen.report_human_review_authority.v1",
    ),
}
_RESERVED_REPORT_SOURCE_ROLES = {
    spec.role: path
    for path, spec in _RESERVED_REPORT_SOURCE_AUTHORITIES.items()
}


@dataclass(frozen=True)
class _ReportSourceProducerPolicy:
    role: str
    owner_suffix_patterns: tuple[str, ...]
    writers: tuple[str, ...]
    schema_patterns: tuple[str, ...]
    content_contract: str
    blocker: str = ""


def _policy(
    role: str,
    owners: tuple[str, ...],
    writers: tuple[str, ...],
    schemas: tuple[str, ...],
    content: str,
    blocker: str = "",
) -> _ReportSourceProducerPolicy:
    return _ReportSourceProducerPolicy(
        role=role,
        owner_suffix_patterns=owners,
        writers=writers,
        schema_patterns=schemas,
        content_contract=content,
        blocker=blocker,
    )


_DRIVER = ("DRIVER",)
_MODEL = ("MODEL",)
_DRIVER_OR_MODEL = ("DRIVER", "MODEL")
_UNSTRUCTURED = (r"unstructured\.v1",)
_REPORT_BODY_OWNERS = (
    r"/report_body/model\.report_[a-z_]+",
    r"/report_body/report_[a-z_]+\.runtime_debt_fallback",
)


# This is deliberately a path denominator, not a prose allow-list.  A default
# source that lacks a registered PhaseIO producer is an explicit P3 blocker;
# it is never silently widened to "any committed DRIVER/MODEL".
_FIXED_REPORT_SOURCE_POLICIES: dict[str, _ReportSourceProducerPolicy] = {
    "_coverage_shortfalls.json": _policy(
        "COVERAGE_SHORTFALL_AUTHORITY", (), (), (), "JSON_SCHEMA",
        "legacy coverage-shortfall writer has no registered report producer",
    ),
    "chain_composition_coverage_gaps.md": _policy(
        "CHAIN_COVERAGE_DEBT",
        (r"/chain_iter2/tail_reconcile\.p\d{4}\.s\d{4}",),
        _DRIVER, _UNSTRUCTURED, "MARKDOWN_CONTRACT",
    ),
    "contract_inventory.md": _policy(
        "COMPONENT_FALLBACK_CONTRACTS", (r"/recon/canonical_merge",),
        _DRIVER, _UNSTRUCTURED, "MARKDOWN_CONTRACT",
    ),
    "depth_finalization_report_authority.json": _policy(
        "DEPTH_FINALIZATION_REPORT_AUTHORITY",
        (r"/depth/finalization_report_authority",), _DRIVER,
        (r"plamen\.depth_finalization_report_authority\.v1",),
        "EXACT_DEPTH_AUTHORITY_JSON",
    ),
    "disposition.md": _policy(
        "REPORT_DISPOSITION", (r"/report_disposition/model",), _MODEL,
        (r"plamen\.report_disposition_proposals\.v1",),
        "MARKDOWN_CONTRACT",
    ),
    "exact_scope_coverage_authority.json": _policy(
        "EXACT_SCOPE_COVERAGE_AUTHORITY", (), (), (), "JSON_SCHEMA",
        "exact-scope authority has no registered report producer",
    ),
    "file_coverage_ledger.md": _policy(
        "COMPONENT_FILE_COVERAGE", (), (), (), "MARKDOWN_CONTRACT",
        "legacy file-coverage ledger has no registered report producer",
    ),
    "finding_delivery_receipt.json": _policy(
        "FINDING_DELIVERY_LEGACY_RECEIPT", (), (), (), "JSON_SCHEMA",
        "legacy delivery receipt is superseded and has no report producer",
    ),
    "finding_delivery_successor.json": _policy(
        "FINDING_DELIVERY_SUCCESSOR",
        (r"/(?:verify_queue|sc_verify_queue)/preverify_successors",),
        _DRIVER, (r"plamen\.finding_delivery_successor\.v1",),
        "JSON_SCHEMA",
    ),
    "findings_inventory.md": _policy(
        "COMPONENT_FINDING_CONTEXT",
        (
            r"/inventory/model",
            r"/inventory/canonical_aggregate",
            r"/inventory/additive_reemit",
            r"/enumgap_delivery/inventory_append",
            r"/axis_disposition/promotion",
            r"/semantic_dedup/prequeue_apply",
            r"/exploration_clear/repair_reconcile",
        ),
        _DRIVER_OR_MODEL,
        (r"unstructured\.v1", r"plamen\.canonical_finding_inventory\.v1"),
        "MARKDOWN_CONTRACT",
    ),
    "mandatory_reverification_assignment.json": _policy(
        "MANDATORY_ASSIGNMENT", (), (), (), "JSON_SCHEMA",
        "mandatory assignment is not yet a registered report-source product",
    ),
    "mandatory_reverification_completion.json": _policy(
        "MANDATORY_COMPLETION", (), (), (), "JSON_SCHEMA",
        "mandatory completion is not yet a registered report-source product",
    ),
    "mandatory_reverification_denominator.json": _policy(
        "MANDATORY_DENOMINATOR",
        (r"/(?:verify_queue|sc_verify_queue)/routing",), _DRIVER,
        _UNSTRUCTURED, "JSON_SCHEMA",
    ),
    "mandatory_reverification_routing.json": _policy(
        "MANDATORY_ROUTING",
        (r"/(?:verify_queue|sc_verify_queue)/routing",), _DRIVER,
        _UNSTRUCTURED, "JSON_SCHEMA",
    ),
    "negative_closure_broker_authority.json": _policy(
        "NEGATIVE_CLOSURE_AUTHORITY", (), (), (), "JSON_SCHEMA",
        "negative-closure broker authority lacks a registered report producer",
    ),
    "preverify_inventory_successor.json": _policy(
        "PREVERIFY_INVENTORY_SUCCESSOR",
        (r"/(?:verify_queue|sc_verify_queue)/preverify_successors",),
        _DRIVER, (r"plamen\.preverify_inventory_successor\.v1",),
        "JSON_SCHEMA",
    ),
    "judge_decisions.json": _policy(
        "JUDGE_TYPED_DECISIONS", (r"/skeptic/challenge_reconcile",),
        _DRIVER, (r"plamen\.judge_decisions\.v1",), "JSON_SCHEMA",
    ),
    "report_critical_high.md": _policy(
        "TIER_CRITICAL_HIGH", _REPORT_BODY_OWNERS, _DRIVER_OR_MODEL,
        (r"plamen\.report_finding_bodies\.v1",), "MARKDOWN_CONTRACT",
    ),
    "report_evidence_projection.md": _policy(
        "REPORT_EVIDENCE_PROJECTION",
        (r"/report_body/evidence_pre", r"/report_body/evidence_repair\.apply"),
        _DRIVER, (r"plamen\.report_evidence_projection\.v1",),
        "MARKDOWN_CONTRACT",
    ),
    "report_evidence_records.json": _policy(
        "REPORT_EVIDENCE_AUTHORITY",
        (r"/report_body/evidence_pre", r"/report_body/evidence_repair\.apply"),
        _DRIVER, (r"plamen\.report_evidence_bundle\.v1",), "JSON_SCHEMA",
    ),
    "report_human_review_authority.json": _policy(
        "REPORT_HUMAN_REVIEW_AUTHORITY",
        (r"/report_index/human_review_authority",), _DRIVER,
        (r"plamen\.report_human_review_authority\.v1",),
        "EXACT_HUMAN_REVIEW_AUTHORITY_JSON",
    ),
    "report_index.md": _policy(
        "REPORT_INDEX",
        (
            r"/report_index/canonicalize(?:\.attempt-\d{4})?",
            r"/report_index/summary_parity(?:\.attempt-\d{4})?",
            r"/report_index/mechanical",
        ),
        _DRIVER,
        (r"unstructured\.v1", r"plamen\.report_index_projection\.v1"),
        "MARKDOWN_CONTRACT",
    ),
    "report_index_status_projection.json": _policy(
        "REPORT_INDEX_STATUS",
        (r"/report_index/canonicalize(?:\.attempt-\d{4})?",), _DRIVER,
        (r"plamen\.report_index_status_projection\.v1",), "JSON_SCHEMA",
    ),
    "report_low_info.md": _policy(
        "TIER_LOW_INFO", _REPORT_BODY_OWNERS, _DRIVER_OR_MODEL,
        (r"plamen\.report_finding_bodies\.v1",), "MARKDOWN_CONTRACT",
    ),
    "report_low_info_a.md": _policy(
        "TIER_LOW_INFO_SHARD", _REPORT_BODY_OWNERS, _DRIVER_OR_MODEL,
        (r"plamen\.report_finding_bodies\.v1",), "MARKDOWN_CONTRACT",
    ),
    "report_low_info_b.md": _policy(
        "TIER_LOW_INFO_SHARD", _REPORT_BODY_OWNERS, _DRIVER_OR_MODEL,
        (r"plamen\.report_finding_bodies\.v1",), "MARKDOWN_CONTRACT",
    ),
    "report_medium.md": _policy(
        "TIER_MEDIUM", _REPORT_BODY_OWNERS, _DRIVER_OR_MODEL,
        (r"plamen\.report_finding_bodies\.v1",), "MARKDOWN_CONTRACT",
    ),
    "report_medium_a.md": _policy(
        "TIER_MEDIUM_SHARD", _REPORT_BODY_OWNERS, _DRIVER_OR_MODEL,
        (r"plamen\.report_finding_bodies\.v1",), "MARKDOWN_CONTRACT",
    ),
    "report_medium_b.md": _policy(
        "TIER_MEDIUM_SHARD", _REPORT_BODY_OWNERS, _DRIVER_OR_MODEL,
        (r"plamen\.report_finding_bodies\.v1",), "MARKDOWN_CONTRACT",
    ),
    "report_records.json": _policy(
        "REPORT_RECORDS",
        (
            r"/report_index/canonicalize(?:\.attempt-\d{4})?",
            r"/report_index/mechanical",
        ),
        _DRIVER, (r"plamen\.report_records\.v1",), "JSON_SCHEMA",
    ),
    "report_source_path_authority.json": _policy(
        "PRODUCTION_SOURCE_PATH_AUTHORITY",
        (r"/report_assemble/source_path_authority",), _DRIVER,
        (r"plamen\.report_source_path_authority\.v1",),
        "EXACT_SOURCE_PATH_AUTHORITY_JSON",
    ),
    "report_semantic_retention_risks.md": _policy(
        "RETENTION_REVIEW_DEBT",
        (r"/report_index/human_review_authority",), _DRIVER,
        (r"plamen\.report_human_review_markdown\.v1",),
        "MARKDOWN_CONTRACT",
    ),
    "report_semantic_severity_repairs.md": _policy(
        "SEVERITY_REVIEW_DEBT",
        (r"/report_index/human_review_authority",), _DRIVER,
        (r"plamen\.report_human_review_markdown\.v1",),
        "MARKDOWN_CONTRACT",
    ),
    "security_obligation_authority.json": _policy(
        "SECURITY_OBLIGATION_AUTHORITY",
        (r"/depth/security_obligations\.(?:pre_depth|post_depth)",), _DRIVER,
        (r"plamen\.security_obligation_authority\.v2",), "JSON_SCHEMA",
    ),
    "security_obligation_lifecycle.json": _policy(
        "SECURITY_OBLIGATION_LIFECYCLE",
        (r"/report_index/security_obligation_lifecycle\.final",), _DRIVER,
        (r"plamen\.security_obligation_lifecycle\.v1",), "JSON_SCHEMA",
    ),
    "security_obligation_report_retention.md": _policy(
        "LIFECYCLE_RETENTION_CACHE",
        (r"/report_index/security_obligation_lifecycle\.final",), _DRIVER,
        (r"plamen\.security_obligation_report_retention\.v1",),
        "MARKDOWN_CONTRACT",
    ),
    "severity_binding.md": _policy(
        "SEVERITY_BINDING", (r"/report_index/prework",), _DRIVER,
        _UNSTRUCTURED, "MARKDOWN_CONTRACT",
    ),
    "skeptic_judge_decisions.md": _policy(
        "JUDGE_PRIMARY", (r"/skeptic/model",), _MODEL,
        (r"plamen\.skeptic_proposal_projection\.v1",), "MARKDOWN_CONTRACT",
    ),
    "status_binding.md": _policy(
        "STATUS_BINDING", (r"/report_index/prework",), _DRIVER,
        _UNSTRUCTURED, "MARKDOWN_CONTRACT",
    ),
    "subsystem_map.md": _policy(
        "COMPONENT_SUBSYSTEM_MAP", (r"/recon/canonical_merge",), _DRIVER,
        _UNSTRUCTURED, "MARKDOWN_CONTRACT",
    ),
    "verification_queue.work_items.json": _policy(
        "VERIFICATION_QUEUE_ITEMS",
        (r"/(?:verify_queue|sc_verify_queue)/routing",), _DRIVER,
        _UNSTRUCTURED, "JSON_SCHEMA",
    ),
    "verification_queue.work_plan.json": _policy(
        "VERIFICATION_QUEUE_PLAN",
        (r"/(?:verify_queue|sc_verify_queue)/routing",), _DRIVER,
        _UNSTRUCTURED, "JSON_SCHEMA",
    ),
    "verification_runtime_roster.json": _policy(
        "VERIFIER_RUNTIME_ROSTER", (), (), (), "JSON_SCHEMA",
        "verifier runtime roster lacks a registered report producer",
    ),
}


_NAMESPACE_REPORT_SOURCE_POLICIES: dict[str, _ReportSourceProducerPolicy] = {
    "body_manifests/report_*.json": _policy(
        "BODY_MANIFEST_NAMESPACE", (r"/report_index/routing",), _DRIVER,
        _UNSTRUCTURED, "JSON_SCHEMA",
    ),
    "judge_*.md": _policy(
        "JUDGE_FALLBACK_NAMESPACE", (), (), (), "MARKDOWN_CONTRACT",
        "legacy judge shard namespace has no registered report producer",
    ),
    "negative_closure_provider_bundles/**/*": _policy(
        "NEGATIVE_CLOSURE_BUNDLE_NAMESPACE", (), (), (), "TYPED_BUNDLE",
        "negative-closure provider bundles lack registered report producers",
    ),
    "report_evidence_manifests/*.json": _policy(
        "REPORT_EVIDENCE_MANIFEST_NAMESPACE",
        (r"/report_body/evidence_pre", r"/report_body/evidence_repair\.apply"),
        _DRIVER, (r"plamen\.report_evidence_manifest\.v1",), "JSON_SCHEMA",
    ),
    "report_semantic_*.md": _policy(
        "REPORT_SEMANTIC_NAMESPACE",
        (
            r"/recon/(?:dependency_reconcile|dependency_research_debt|audit_input_limitations)",
            r"/(?:breadth|rescan|depth)/methodology_repair",
            r"/report_index/canonicalize(?:\.attempt-\d{4})?",
            r"/report_index/human_review_authority",
            r"/report_index/chain_deferred_authority",
        ),
        _DRIVER, (r"unstructured\.v1", r"plamen\..+"),
        "MARKDOWN_CONTRACT",
    ),
}


class ReportCaptureAuthorityError(ValueError):
    """A committed report-capture authority could not be reproduced."""


@dataclass(frozen=True)
class CommittedReportPublication:
    final_capture_bytes: bytes
    output_bytes: dict[str, bytes]
    absent_output_identities: tuple[str, ...]
    source_commit_receipt_digest: str
    final_commit_receipt_digest: str


@dataclass(frozen=True)
class CapturedReportSourceInput:
    path: str
    roles: tuple[str, ...]
    content: bytes
    sha256: str
    size: int


@dataclass(frozen=True)
class CapturedReportSourceNamespace:
    pattern: str
    role: str
    members: tuple[str, ...]
    membership_digest: str


@dataclass(frozen=True)
class CommittedReportSourceInputs:
    capture_bytes: bytes
    inputs: tuple[CapturedReportSourceInput, ...]
    explicit_absences: tuple[str, ...]
    namespace_rosters: tuple[CapturedReportSourceNamespace, ...]
    metadata: tuple[tuple[str, str], ...]
    source_set_digest: str
    commit_receipt_digest: str


@dataclass(frozen=True)
class PreparedReportSourceCapture:
    capture_bytes: bytes
    contract: PhaseIOContract
    launch: LaunchSpec
    exact_input_paths: tuple[str, ...]
    explicit_absences: tuple[str, ...]


@dataclass(frozen=True)
class _ResolvedCapture:
    payload: dict[str, Any]
    raw: bytes
    binding: dict[str, str]
    contract: PhaseIOContract
    launch: LaunchSpec
    authority_fingerprint: str


@dataclass(frozen=True)
class _ExpectedSourceRosterBinding:
    """One public-call epoch of driver-supplied audit configuration authority.

    The production driver is responsible for supplying its snapshot-bound run
    config.  This seal prevents capture bytes from substituting a different
    self-consistent source roster.  It is not a capability boundary against an
    arbitrary same-process caller that is itself allowed to invent config;
    such a caller remains outside the artifact-authority trust boundary.
    """

    config: Mapping[str, Any]
    snapshot: Mapping[str, Any]
    authority: dict[str, Any]


def _fail(detail: str) -> None:
    raise ReportCaptureAuthorityError(detail)


def _expected_source_roster_binding(
    *,
    scratch: Path,
    project: Path,
    run: str,
    expected_config: Mapping[str, Any],
) -> _ExpectedSourceRosterBinding:
    if not isinstance(expected_config, Mapping):
        raise TypeError("expected_config must be a snapshot-bound mapping")
    snapshot = expected_config.get("_audit_snapshot")
    if not isinstance(snapshot, Mapping):
        _fail("expected_config has no bound audit snapshot")
    if str(expected_config.get("_run_id") or "").strip() != run:
        _fail("expected_config run_id differs from report capture run")
    try:
        configured_project = Path(
            str(expected_config.get("project_root") or "")
        ).expanduser().resolve()
        configured_scratch_raw = str(
            expected_config.get("scratchpad") or ""
        ).strip()
        configured_scratch = (
            Path(configured_scratch_raw).expanduser().resolve()
            if configured_scratch_raw
            else (configured_project / ".scratchpad").resolve()
        )
    except (OSError, RuntimeError, ValueError) as exc:
        _fail(f"expected_config roots are invalid: {exc}")
    if configured_project != project or configured_scratch != scratch:
        _fail("expected_config roots differ from report capture roots")
    try:
        authority = build_production_source_path_authority(
            expected_config, snapshot
        )
    except (SnapshotInputError, TypeError, ValueError) as exc:
        _fail(f"expected_config source-roster binding is invalid: {exc}")
    return _ExpectedSourceRosterBinding(
        config=expected_config,
        snapshot=snapshot,
        authority=authority,
    )


def _metadata_bound_to_expected_roster(
    metadata: Mapping[str, str],
    expected: _ExpectedSourceRosterBinding,
) -> dict[str, str]:
    if not isinstance(metadata, Mapping):
        raise TypeError("metadata must be a mapping")
    if "source_roster_authority_sha256" in metadata:
        _fail(
            "source roster metadata is adapter-owned and cannot be caller supplied"
        )
    result = dict(metadata)
    result["source_roster_authority_sha256"] = expected.authority[
        "authority_digest"
    ]
    return result


def _exact_bytes(value: object, *, label: str) -> bytes:
    if type(value) is not bytes:
        raise TypeError(f"{label} must be exact bytes")
    if len(value) > _MAX_CAPTURE_BYTES:
        _fail(f"{label} exceeds the bounded capture limit")
    return value


def _json_exact_dict(raw: bytes, *, label: str) -> dict[str, Any]:
    def pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in rows:
            if key in result:
                _fail(f"{label} contains duplicate JSON key {key!r}")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ReportCaptureAuthorityError(
                    f"{label} contains non-finite JSON value {token}"
                )
            ),
        )
    except ReportCaptureAuthorityError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _fail(f"{label} is not exact UTF-8 JSON: {type(exc).__name__}")
    if type(value) is not dict:
        _fail(f"{label} root must be an exact object")
    return value


def _canonical_json_line(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        + "\n"
    ).encode("utf-8")


def _digest_without(value: Mapping[str, Any], field: str) -> str:
    unsigned = dict(value)
    unsigned.pop(field, None)
    return hashlib.sha256(
        json.dumps(
            unsigned,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def _validate_depth_report_authority_bytes(
    raw: bytes,
    *,
    expected_run_id: str,
) -> dict[str, Any]:
    value = _json_exact_dict(raw, label="depth finalization report authority")
    required = {
        "schema",
        "authority_class",
        "permitted_use",
        "publication_eligible",
        "run_id",
        "phase",
        "status",
        "source_digest",
        "processors",
        "review",
        "authority_digest",
    }
    if set(value) != required:
        _fail("depth finalization report authority content schema differs")
    if (
        value.get("schema")
        != "plamen.depth_finalization_report_authority.v1"
        or value.get("authority_class") != "NON_EVIDENCE_REPORT_DEBT"
        or value.get("permitted_use") != "INTERNAL_REPORT_REVIEW_ONLY"
        or value.get("publication_eligible") is not False
        or value.get("run_id") != expected_run_id
        or not isinstance(value.get("phase"), str)
        or not value["phase"]
        or not isinstance(value.get("status"), str)
        or not value["status"]
        or not isinstance(value.get("source_digest"), str)
        or len(value["source_digest"]) != 64
        or any(char not in "0123456789abcdef" for char in value["source_digest"])
    ):
        _fail("depth finalization report authority content differs")
    processors = value.get("processors")
    if not isinstance(processors, list) or not processors:
        _fail("depth finalization report authority processor schema differs")
    normalized_processors: list[dict[str, str]] = []
    for row in processors:
        if not isinstance(row, dict) or set(row) != {"name", "status", "error"}:
            _fail("depth finalization report authority processor row differs")
        if (
            not isinstance(row.get("name"), str)
            or not row["name"]
            or not isinstance(row.get("status"), str)
            or not row["status"]
            or not isinstance(row.get("error"), str)
        ):
            _fail("depth finalization report authority processor content differs")
        normalized_processors.append(dict(row))
    if normalized_processors != sorted(
        normalized_processors, key=lambda row: row["name"]
    ) or len({row["name"] for row in normalized_processors}) != len(
        normalized_processors
    ):
        _fail("depth finalization report authority processor roster differs")
    review = value.get("review")
    if not isinstance(review, dict) or set(review) != {
        "presence",
        "sha256",
        "size",
        "content",
    }:
        _fail("depth finalization report authority review schema differs")
    presence = review.get("presence")
    content = review.get("content")
    size = review.get("size")
    digest = review.get("sha256")
    if (
        presence not in {"PRESENT", "ABSENT"}
        or not isinstance(content, str)
        or type(size) is not int
        or size < 0
        or not isinstance(digest, str)
    ):
        _fail("depth finalization report authority review content differs")
    content_raw = content.encode("utf-8")
    if presence == "ABSENT":
        if content or size or digest:
            _fail("depth finalization report authority absent review differs")
    elif (
        size != len(content_raw)
        or digest != hashlib.sha256(content_raw).hexdigest()
    ):
        _fail("depth finalization report authority present review differs")
    failed = any(row["status"] == "FAILED" for row in normalized_processors)
    if failed != (presence == "PRESENT"):
        _fail("depth finalization report authority failure review differs")
    authority_digest = value.get("authority_digest")
    if (
        not isinstance(authority_digest, str)
        or authority_digest != _digest_without(value, "authority_digest")
        or raw != _canonical_json_line(value)
    ):
        _fail("depth finalization report authority digest/canonical bytes differ")
    return value


def _validate_human_review_authority_bytes(
    raw: bytes,
    *,
    expected_run_id: str,
    expected_contract_digest: str | None = None,
    expected_launch_digest: str | None = None,
) -> dict[str, Any]:
    value = _json_exact_dict(raw, label="report human-review authority")
    required = {
        "schema",
        "run_id",
        "contract_digest",
        "launch_digest",
        "inputs",
        "sections",
        "authority_digest",
    }
    if set(value) != required:
        _fail("report human-review authority content schema differs")
    if (
        value.get("schema") != "plamen.report_human_review_authority.v1"
        or value.get("run_id") != expected_run_id
        or not isinstance(value.get("contract_digest"), str)
        or len(value["contract_digest"]) != 64
        or any(
            char not in "0123456789abcdef"
            for char in value["contract_digest"]
        )
        or not isinstance(value.get("launch_digest"), str)
        or len(value["launch_digest"]) != 64
        or any(
            char not in "0123456789abcdef"
            for char in value["launch_digest"]
        )
        or (
            expected_contract_digest is not None
            and value["contract_digest"] != expected_contract_digest
        )
        or (
            expected_launch_digest is not None
            and value["launch_digest"] != expected_launch_digest
        )
    ):
        _fail("report human-review authority binding differs")
    inputs = value.get("inputs")
    if not isinstance(inputs, list) or len(inputs) != 2:
        _fail("report human-review authority input denominator differs")
    expected_input_ids = (
        "scratchpad:report_coverage.md",
        "scratchpad:report_index.md",
    )
    if tuple(row.get("identity") for row in inputs if isinstance(row, dict)) != (
        expected_input_ids
    ):
        _fail("report human-review authority input roster differs")
    for row in inputs:
        if (
            not isinstance(row, dict)
            or set(row) != {"identity", "sha256", "size"}
            or not isinstance(row.get("sha256"), str)
            or len(row["sha256"]) != 64
            or type(row.get("size")) is not int
            or row["size"] < 0
        ):
            _fail("report human-review authority input row differs")
    sections = value.get("sections")
    expected_sections = (
        "scratchpad:report_semantic_retention_risks.md",
        "scratchpad:report_semantic_severity_repairs.md",
    )
    if (
        not isinstance(sections, list)
        or len(sections) != 2
        or tuple(
            row.get("identity") for row in sections if isinstance(row, dict)
        )
        != expected_sections
    ):
        _fail("report human-review authority section denominator differs")
    for row in sections:
        if (
            not isinstance(row, dict)
            or set(row) != {"identity", "presence", "sha256", "size"}
            or row.get("presence") not in {"PRESENT", "ABSENT"}
            or not isinstance(row.get("sha256"), str)
            or type(row.get("size")) is not int
            or row["size"] < 0
        ):
            _fail("report human-review authority section row differs")
        if row["presence"] == "ABSENT" and (row["sha256"] or row["size"]):
            _fail("report human-review authority absent section differs")
        if row["presence"] == "PRESENT" and len(row["sha256"]) != 64:
            _fail("report human-review authority present section differs")
    authority_digest = value.get("authority_digest")
    if (
        not isinstance(authority_digest, str)
        or authority_digest != _digest_without(value, "authority_digest")
        or raw != _canonical_json_line(value)
    ):
        _fail("report human-review authority digest/canonical bytes differ")
    return value


def _reserved_source_bytes(
    payload: Mapping[str, Any],
) -> dict[str, bytes]:
    try:
        captured = _capture._report_assembly_capture_source_bytes(payload)
    except _capture.ReportAssemblyCaptureError as exc:
        _fail(f"reserved report source extraction failed: {exc}")
    return {path: row[1] for path, row in captured.items()}


def report_source_policy_inventory() -> tuple[dict[str, Any], ...]:
    """Return the closed 43-fixed + 5-namespace producer policy roster."""

    _validate_report_source_policy_denominator()
    rows: list[dict[str, Any]] = []
    for path, policy in sorted(_FIXED_REPORT_SOURCE_POLICIES.items()):
        rows.append(
            {
                "kind": "FIXED",
                "selector": path,
                "role": policy.role,
                "owner_suffix_patterns": policy.owner_suffix_patterns,
                "writers": policy.writers,
                "schema_patterns": policy.schema_patterns,
                "content_contract": policy.content_contract,
                "blocker": policy.blocker,
            }
        )
    for pattern, policy in sorted(_NAMESPACE_REPORT_SOURCE_POLICIES.items()):
        rows.append(
            {
                "kind": "NAMESPACE",
                "selector": pattern,
                "role": policy.role,
                "owner_suffix_patterns": policy.owner_suffix_patterns,
                "writers": policy.writers,
                "schema_patterns": policy.schema_patterns,
                "content_contract": policy.content_contract,
                "blocker": policy.blocker,
            }
        )
    return tuple(rows)


def _validate_report_source_policy_denominator() -> None:
    """Keep producer policy in exact lockstep with the capture denominator."""

    fixed = {
        path: policy.role
        for path, policy in _FIXED_REPORT_SOURCE_POLICIES.items()
    }
    namespaces = {
        pattern: policy.role
        for pattern, policy in _NAMESPACE_REPORT_SOURCE_POLICIES.items()
    }
    if fixed != _capture.DEFAULT_FIXED_SOURCE_ROLES:
        missing = sorted(set(_capture.DEFAULT_FIXED_SOURCE_ROLES) - set(fixed))
        extra = sorted(set(fixed) - set(_capture.DEFAULT_FIXED_SOURCE_ROLES))
        wrong = sorted(
            path
            for path in set(fixed) & set(_capture.DEFAULT_FIXED_SOURCE_ROLES)
            if fixed[path] != _capture.DEFAULT_FIXED_SOURCE_ROLES[path]
        )
        _fail(
            "fixed report-source producer policy denominator differs: "
            f"missing={missing}; extra={extra}; role_mismatch={wrong}"
        )
    if namespaces != _capture.DEFAULT_NAMESPACE_ROLES:
        missing = sorted(set(_capture.DEFAULT_NAMESPACE_ROLES) - set(namespaces))
        extra = sorted(set(namespaces) - set(_capture.DEFAULT_NAMESPACE_ROLES))
        wrong = sorted(
            pattern
            for pattern in set(namespaces) & set(_capture.DEFAULT_NAMESPACE_ROLES)
            if namespaces[pattern] != _capture.DEFAULT_NAMESPACE_ROLES[pattern]
        )
        _fail(
            "namespace report-source producer policy denominator differs: "
            f"missing={missing}; extra={extra}; role_mismatch={wrong}"
        )


def _report_source_policies(
    path: str,
    roles: tuple[str, ...],
) -> tuple[_ReportSourceProducerPolicy, ...]:
    result: list[_ReportSourceProducerPolicy] = []
    fixed = _FIXED_REPORT_SOURCE_POLICIES.get(path)
    if fixed is not None and fixed.role in roles:
        result.append(fixed)
    namespace_by_role = {
        policy.role: policy
        for policy in _NAMESPACE_REPORT_SOURCE_POLICIES.values()
    }
    for role in roles:
        policy = namespace_by_role.get(role)
        if policy is not None and policy not in result:
            result.append(policy)
    return tuple(result)


def _policy_owner_allowed(
    policy: _ReportSourceProducerPolicy,
    *,
    owner_suffix: str,
    writer: str,
    schema_version: str,
) -> bool:
    return bool(
        not policy.blocker
        and writer in policy.writers
        and any(
            re.fullmatch(pattern, owner_suffix)
            for pattern in policy.owner_suffix_patterns
        )
        and any(
            re.fullmatch(pattern, schema_version)
            for pattern in policy.schema_patterns
        )
    )


def _validate_policy_launch(
    policy: _ReportSourceProducerPolicy,
    *,
    contract: PhaseIOContract,
    launch: LaunchSpec,
    writer: str,
) -> None:
    """Enforce the registered execution class for one privileged producer."""

    del policy  # The writer roster is policy-owned; launch shape is writer-owned.
    if writer == "DRIVER":
        if (
            contract.model_invoked
            or launch.model != "driver"
            or launch.exec_mode != "python"
            or launch.tool_policy not in {(), ("filesystem",)}
        ):
            _fail(
                f"{contract.key}: DRIVER report-source launch authority differs"
            )
        return
    if (
        writer != "MODEL"
        or not contract.model_invoked
        or launch.model == "driver"
        or launch.tool_policy != ("filesystem",)
    ):
        _fail(f"{contract.key}: MODEL report-source launch authority differs")
    expected_modes = {
        "claude": {"headless", "pty"},
        "codex": {"codex"},
    }.get(launch.backend, {"headless", "pty", "codex"})
    if launch.exec_mode not in expected_modes:
        _fail(f"{contract.key}: MODEL report-source execution mode differs")


def _validate_policy_source_content(
    policy: _ReportSourceProducerPolicy,
    *,
    path: str,
    raw: bytes,
) -> None:
    """Apply the declared structural content contract without semantic guessing."""

    contract = policy.content_contract
    if contract.startswith("EXACT_"):
        # The three privileged exact formats are checked by their dedicated
        # validators before producer resolution.  Never replace those checks
        # with a generic JSON parse here.
        if path not in _RESERVED_REPORT_SOURCE_AUTHORITIES:
            _fail(f"{path}: exact content contract has no registered validator")
        return
    if contract == "JSON_SCHEMA":
        if not path.endswith(".json"):
            _fail(f"{path}: JSON report-source content path differs")
        try:
            text = raw.decode("utf-8", errors="strict")
            if text.startswith("\ufeff"):
                raise ValueError("UTF-8 BOM is forbidden")

            def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
                result: dict[str, Any] = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError(f"duplicate JSON key: {key}")
                    result[key] = value
                return result

            value = json.loads(
                text,
                object_pairs_hook=_unique_pairs,
                parse_constant=lambda token: (_ for _ in ()).throw(
                    ValueError(f"non-finite JSON number: {token}")
                ),
            )
        except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
            _fail(f"{path}: JSON report-source content is invalid: {exc}")
        if type(value) not in {dict, list}:
            _fail(f"{path}: JSON report-source root must be object or array")
        return
    if contract == "MARKDOWN_CONTRACT":
        if not path.endswith(".md"):
            _fail(f"{path}: Markdown report-source content path differs")
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeError as exc:
            _fail(f"{path}: Markdown report-source encoding is invalid: {exc}")
        if (
            not text.strip()
            or "\x00" in text
            or any(
                ord(character) < 32 and character not in "\t\n\r"
                for character in text
            )
        ):
            _fail(f"{path}: Markdown report-source structure is invalid")
        return
    _fail(f"{path}: unsupported report-source content contract {contract!r}")


def _validate_reserved_source_declarations_and_content(
    payload: Mapping[str, Any],
    *,
    expected: _ExpectedSourceRosterBinding,
) -> dict[str, bytes]:
    _validate_report_source_policy_denominator()
    fixed = {
        row["path"]: row["role"] for row in payload.get("fixed_sources", [])
    }
    namespaces = payload.get("namespace_specs", [])
    for path, role in fixed.items():
        policy = _FIXED_REPORT_SOURCE_POLICIES.get(path)
        if policy is None:
            _fail(
                f"{path}: fixed report source path selector is absent from registry"
            )
        if role != policy.role:
            _fail(f"{path}: fixed report source role differs from registry")
    for row in namespaces:
        role = row.get("role")
        pattern = row.get("pattern")
        policy = _NAMESPACE_REPORT_SOURCE_POLICIES.get(pattern)
        if policy is None:
            _fail(
                f"{pattern}: report namespace role selector is absent from registry"
            )
        if role != policy.role:
            _fail(f"{pattern}: report namespace role differs from registry")

    source_bytes = _reserved_source_bytes(payload)
    metadata = payload["metadata"]
    if (
        metadata["source_roster_authority_sha256"]
        != expected.authority["authority_digest"]
        or metadata["source_snapshot_sha256"]
        != expected.authority["snapshot_digest"]
        or metadata["pipeline"] != expected.authority["pipeline"]
        or metadata["ecosystem"] != expected.authority["language"]
    ):
        _fail(
            "report source capture metadata differs from expected config/roster"
        )
    expected_dimensions = {
        "mode": str(expected.config.get("mode") or "").strip().lower(),
        "backend": str(
            expected.config.get("cli_backend") or ""
        ).strip().lower(),
    }
    if any(metadata[field] != value for field, value in expected_dimensions.items()):
        _fail("report source capture dimensions differ from expected config")
    path_raw = source_bytes.get("report_source_path_authority.json")
    if path_raw is not None:
        try:
            path_payload = _json_exact_dict(
                path_raw, label="production source-path authority"
            )
            normalized = validate_production_source_path_authority(
                path_payload,
                expected_snapshot=expected.snapshot,
                expected_config=expected.config,
            )
            canonical = canonical_production_source_path_authority_bytes(
                normalized,
                expected_snapshot=expected.snapshot,
                expected_config=expected.config,
            )
        except (SnapshotInputError, TypeError, ValueError) as exc:
            _fail(f"production source-path authority content is invalid: {exc}")
        if canonical != path_raw:
            _fail("production source-path authority bytes are not canonical")
        if (
            normalized != expected.authority
            or normalized["authority_digest"]
            != metadata["source_roster_authority_sha256"]
        ):
            _fail(
                "production source-path authority differs from expected config roster"
            )

    for row in payload.get("sources", []):
        roles = tuple(row.get("roles", ()))
        policies = _report_source_policies(str(row.get("path") or ""), roles)
        if not policies or {policy.role for policy in policies} != set(roles):
            _fail(
                f"{row.get('path')}: report source has no exact nonempty policy resolution"
            )

    depth_raw = source_bytes.get("depth_finalization_report_authority.json")
    if depth_raw is not None:
        _validate_depth_report_authority_bytes(
            depth_raw, expected_run_id=metadata["run_id"]
        )
    human_raw = source_bytes.get("report_human_review_authority.json")
    if human_raw is not None:
        _validate_human_review_authority_bytes(
            human_raw, expected_run_id=metadata["run_id"]
        )
    return source_bytes


def _roots(
    scratchpad: str | Path,
    project_root: str | Path,
) -> tuple[Path, Path]:
    try:
        scratch = _rooted.checked_directory(
            scratchpad, label="report capture scratchpad"
        )
        project = _rooted.checked_directory(
            project_root, label="report capture project root"
        )
        try:
            relative = scratch.relative_to(project)
        except ValueError:
            _fail("report capture scratchpad is outside project root")
        if not relative.parts:
            _fail("report capture scratchpad cannot equal project root")
    except _rooted.RootedPathIOError as exc:
        _fail(f"report capture root is unsafe: {exc}")
    return scratch, project


def _run_id(value: object) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        _fail("report capture run_id is absent or malformed")
    return value


def _contract_from_committed_manifest(
    unit: dict[str, Any],
    *,
    expected_work_unit: str,
    expected_output_name: str,
) -> PhaseIOContract:
    manifest = unit.get("contract_manifest")
    if type(manifest) is not dict:
        _fail(f"{expected_work_unit}: contract manifest is absent")
    parts = expected_work_unit.split("/")
    if len(parts) != 6:
        _fail("committed report work-unit key is malformed")
    identities = manifest.get("immutable_inputs")
    bounded = manifest.get("bounded_lookup_inputs")
    if type(identities) is not list or bounded != []:
        _fail(f"{expected_work_unit}: exact input denominator is malformed")
    exact_inputs: list[str] = []
    for identity in identities:
        if not isinstance(identity, str) or not identity.startswith("scratchpad:"):
            _fail(f"{expected_work_unit}: non-scratchpad input is forbidden")
        exact_inputs.append(identity.split(":", 1)[1])
    kwargs: dict[str, Any] = {}
    if parts[4:] == ["report_assemble", "source_capture"]:
        requirements = manifest.get("input_authority_requirements", [])
        if type(requirements) is not list:
            _fail("source capture input authority denominator is malformed")
        authority: dict[str, InputAuthorityRequirement] = {}
        for raw in requirements:
            if type(raw) is not dict:
                _fail("source capture input authority row is malformed")
            try:
                requirement = InputAuthorityRequirement(**raw)
            except (TypeError, ValueError) as exc:
                _fail(f"source capture input authority replay failed: {exc}")
            root, path = requirement.identity.split(":", 1)
            if root != "scratchpad" or path in authority:
                _fail("source capture input authority identity is malformed")
            authority[path] = requirement
        kwargs["exact_input_authorities"] = authority
    try:
        replayed = resolve_phase_io_contract(
            pipeline=parts[0],
            mode=parts[1],
            ecosystem=parts[2],
            backend=parts[3],
            phase=parts[4],
            work_unit_id=parts[5],
            exact_inputs=tuple(exact_inputs),
            exact_outputs=(expected_output_name,),
            **kwargs,
        )
    except (TypeError, ValueError) as exc:
        _fail(f"{expected_work_unit}: registered PhaseIO replay failed: {exc}")
    if replayed.key != expected_work_unit or replayed.to_dict() != manifest:
        _fail(f"{expected_work_unit}: committed contract is not registered exact")
    if replayed.digest != unit.get("contract_digest"):
        _fail(f"{expected_work_unit}: contract digest differs")
    return replayed


def _registered_producer_contract_from_committed_manifest(
    unit: dict[str, Any],
    *,
    expected_work_unit: str,
) -> PhaseIOContract:
    """Replay a reserved source producer over its complete dynamic manifest."""

    manifest = unit.get("contract_manifest")
    if type(manifest) is not dict:
        _fail(f"{expected_work_unit}: contract manifest is absent")
    parts = expected_work_unit.split("/")
    if len(parts) != 6:
        _fail("reserved report producer work-unit key is malformed")
    immutable = manifest.get("immutable_inputs")
    bounded = manifest.get("bounded_lookup_inputs")
    outputs = manifest.get("outputs")
    if (
        type(immutable) is not list
        or type(bounded) is not list
        or type(outputs) is not list
    ):
        _fail(f"{expected_work_unit}: producer denominator is malformed")
    exact_inputs: list[str] = []
    for identity in immutable:
        if not isinstance(identity, str) or ":" not in identity:
            _fail(f"{expected_work_unit}: producer input roster is malformed")
        root, relative = identity.split(":", 1)
        if root == "scratchpad":
            exact_inputs.append(relative)
        elif root == "project":
            exact_inputs.append(f"project::{relative}")
        else:
            _fail(f"{expected_work_unit}: producer input root is forbidden")
    exact_outputs: list[str] = []
    for row in outputs:
        identity = row.get("identity") if isinstance(row, dict) else None
        if not isinstance(identity, str) or not identity.startswith("scratchpad:"):
            _fail(f"{expected_work_unit}: producer output roster is malformed")
        exact_outputs.append(identity.split(":", 1)[1])
    requirements_raw = manifest.get("input_authority_requirements", [])
    if type(requirements_raw) is not list:
        _fail(f"{expected_work_unit}: input authority denominator is malformed")
    requirements: dict[str, InputAuthorityRequirement] = {}
    for row in requirements_raw:
        if type(row) is not dict:
            _fail(f"{expected_work_unit}: input authority row is malformed")
        try:
            requirement = InputAuthorityRequirement(**row)
        except (TypeError, ValueError) as exc:
            _fail(f"{expected_work_unit}: input authority replay failed: {exc}")
        root, path = requirement.identity.split(":", 1)
        if root != "scratchpad" or path in requirements:
            _fail(f"{expected_work_unit}: input authority identity is malformed")
        requirements[path] = requirement
    kwargs: dict[str, Any] = {}
    output_writers = {
        str(row.get("writer") or "").strip().upper()
        for row in outputs
        if isinstance(row, dict)
    }
    if len(output_writers) == 1 and "" not in output_writers:
        kwargs["exact_writer"] = next(iter(output_writers))
    if requirements and tuple(parts[4:]) in {
        ("report_assemble", "source_capture"),
        ("report_index", "human_review_authority"),
        ("report_index", "chain_deferred_authority"),
    }:
        kwargs["exact_input_authorities"] = requirements
    try:
        replayed = resolve_phase_io_contract(
            pipeline=parts[0],
            mode=parts[1],
            ecosystem=parts[2],
            backend=parts[3],
            phase=parts[4],
            work_unit_id=parts[5],
            exact_inputs=tuple(exact_inputs),
            exact_outputs=tuple(exact_outputs),
            **kwargs,
        )
    except (TypeError, ValueError) as exc:
        _fail(f"{expected_work_unit}: registered producer replay failed: {exc}")
    if replayed.key != expected_work_unit or replayed.to_dict() != manifest:
        _fail(f"{expected_work_unit}: producer contract is not registered exact")
    if replayed.digest != unit.get("contract_digest"):
        _fail(f"{expected_work_unit}: producer contract digest differs")
    return replayed


def _launch_from_committed_manifest(
    unit: dict[str, Any], contract: PhaseIOContract
) -> LaunchSpec:
    manifest = unit.get("launch_manifest")
    if type(manifest) is not dict:
        _fail(f"{contract.key}: launch manifest is absent")
    try:
        launch = LaunchSpec(
            work_unit_key=manifest["work_unit_key"],
            pipeline=manifest["pipeline"],
            mode=manifest["mode"],
            ecosystem=manifest["ecosystem"],
            backend=manifest["backend"],
            model=manifest["model"],
            timeout_s=manifest["timeout_s"],
            exec_mode=manifest["exec_mode"],
            tool_policy=tuple(manifest["tool_policy"]),
            launch_version=manifest["launch_version"],
        )
        replayed_contract, replayed_launch = replay_phase_io_authority_pair(
            contract, launch
        )
    except (KeyError, TypeError, ValueError) as exc:
        _fail(f"{contract.key}: PhaseIO launch replay failed: {exc}")
    if (
        replayed_contract.to_dict() != contract.to_dict()
        or replayed_launch.to_dict() != manifest
        or replayed_launch.digest != unit.get("launch_digest")
    ):
        _fail(f"{contract.key}: launch authority differs")
    return replayed_launch


def _authority_fingerprint(unit: dict[str, Any], identity: str) -> str:
    commit = unit.get("commit_authority")
    artifact = unit.get("artifacts", {}).get(identity)
    if type(commit) is not dict or type(artifact) is not dict:
        _fail("report capture commit/artifact authority is incomplete")
    value = {
        "work_unit_key": unit.get("work_unit_key"),
        "run_id": unit.get("run_id"),
        "contract_digest": unit.get("contract_digest"),
        "launch_digest": unit.get("launch_digest"),
        "receipt_digest": commit.get("receipt_digest"),
        "artifact": artifact,
    }
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    ).hexdigest()


def _resolve_committed_capture(
    scratch: Path,
    project: Path,
    run: str,
    *,
    identity: str,
    output_name: str,
    work_unit_suffix: str,
    schema_version: str,
) -> _ResolvedCapture:
    try:
        ledger = read_artifact_ledger(scratch)
    except ArtifactLedgerError as exc:
        _fail(f"report capture ArtifactLedger is invalid: {exc}")
    bindings = ledger.get("artifact_bindings")
    binding = bindings.get(identity) if type(bindings) is dict else None
    if type(binding) is not dict:
        _fail(f"{identity}: active ArtifactLedger binding is absent")
    owner = binding.get("owner_key")
    if (
        not isinstance(owner, str)
        or not owner.endswith(work_unit_suffix)
        or binding.get("writer") != "DRIVER"
        or binding.get("run_id") != run
        or binding.get("schema_version") != schema_version
        or binding.get("status") != "ACTIVE"
    ):
        _fail(f"{identity}: active producer identity/writer/run/schema differs")
    units = ledger.get("work_units")
    unit = units.get(owner) if type(units) is dict else None
    if type(unit) is not dict:
        _fail(f"{identity}: producer work-unit receipt is absent")
    issues = active_committed_work_unit_authority_issues(
        ledger,
        work_unit_key=owner,
        run_id=run,
        expected_artifact_identities=(identity,),
    )
    if issues:
        _fail(f"{identity}: active commit authority failed: {'; '.join(issues)}")
    contract = _contract_from_committed_manifest(
        unit,
        expected_work_unit=owner,
        expected_output_name=output_name,
    )
    launch = _launch_from_committed_manifest(unit, contract)
    live_issues = validate_work_unit_artifacts(
        scratch,
        project,
        contract,
        launch,
        run_id=run,
        actor="DRIVER",
        require_live_input_authority=True,
    )
    if live_issues:
        _fail(f"{identity}: live artifact authority failed: {'; '.join(live_issues)}")
    try:
        raw = read_bounded_regular_bytes(
            scratch / output_name,
            _MAX_CAPTURE_BYTES,
            require_single_link=True,
        )
    except (OSError, ValueError) as exc:
        _fail(f"{identity}: bounded single-link read failed: {exc}")
    artifact = unit["artifacts"].get(identity)
    if (
        type(artifact) is not dict
        or artifact.get("sha256") != hashlib.sha256(raw).hexdigest()
        or artifact.get("size") != len(raw)
        or binding.get("sha256") != artifact.get("sha256")
        or binding.get("size") != artifact.get("size")
    ):
        _fail(f"{identity}: live bytes differ from committed artifact hash")
    payload = _json_exact_dict(raw, label=identity)
    commit = unit.get("commit_authority")
    if type(commit) is not dict:
        _fail(f"{identity}: commit receipt is absent")
    authority = {
        "artifact_identity": identity,
        "content_sha256": hashlib.sha256(raw).hexdigest(),
        "run_id": run,
        "producer_work_unit_key": owner,
        "contract_digest": str(unit.get("contract_digest") or ""),
        "launch_digest": str(unit.get("launch_digest") or ""),
        "commit_receipt_digest": str(commit.get("receipt_digest") or ""),
    }
    return _ResolvedCapture(
        payload=payload,
        raw=raw,
        binding=authority,
        contract=contract,
        launch=launch,
        authority_fingerprint=_authority_fingerprint(unit, identity),
    )


def _source(
    scratch: Path,
    project: Path,
    run: str,
    expected: _ExpectedSourceRosterBinding,
) -> _ResolvedCapture:
    resolved = _resolve_committed_capture(
        scratch,
        project,
        run,
        identity=_capture.SOURCE_CAPTURE_IDENTITY,
        output_name=_SOURCE_NAME,
        work_unit_suffix="/report_assemble/source_capture",
        schema_version=_capture.SOURCE_SCHEMA_VERSION,
    )
    try:
        payload = _capture._validate_report_assembly_source_capture(
            resolved.payload
        )
        canonical = _capture._canonical_report_assembly_source_capture_bytes(
            payload
        )
        _validate_reserved_source_declarations_and_content(
            payload, expected=expected
        )
        payload_input_identities = tuple(
            sorted(f"scratchpad:{path}" for path in payload["input_paths"])
        )
        contract_input_identities = tuple(
            sorted(resolved.contract.immutable_inputs)
        )
        requirement_identities = tuple(
            sorted(
                requirement.identity
                for requirement in (
                    resolved.contract.input_authority_requirements
                )
            )
        )
        if (
            resolved.contract.bounded_lookup_inputs
            or payload_input_identities != contract_input_identities
            or contract_input_identities != requirement_identities
        ):
            _fail(
                "committed source capture input denominator differs from "
                "exact PhaseIO immutable-input/authority denominator"
            )
        live_requirements = _producer_requirements_for_source(
            scratch,
            run,
            payload,
            expected=expected,
        )
        live_requirement_rows = tuple(
            live_requirements[path].to_dict()
            for path in payload["input_paths"]
        )
        captured_requirement_rows = tuple(
            requirement.to_dict()
            for requirement in resolved.contract.input_authority_requirements
        )
        if live_requirement_rows != captured_requirement_rows:
            _fail(
                "committed source capture requirements differ from live "
                "producer policy authority"
            )
        replayed = _capture._replay_report_assembly_source_capture(
            scratch, payload
        )
        terminal_requirements = _producer_requirements_for_source(
            scratch,
            run,
            payload,
            expected=expected,
        )
        terminal_requirement_rows = tuple(
            terminal_requirements[path].to_dict()
            for path in payload["input_paths"]
        )
        if (
            terminal_requirement_rows != live_requirement_rows
            or terminal_requirement_rows != captured_requirement_rows
        ):
            _fail(
                "committed source producer authority drifted during terminal "
                "live replay"
            )
    except _capture.ReportAssemblyCaptureError as exc:
        _fail(f"committed source capture schema/replay is invalid: {exc}")
    if (
        replayed != payload
        or canonical != resolved.raw
        or payload["metadata"]["run_id"] != run
    ):
        _fail("committed source capture bytes/run are not canonical exact")
    parts = resolved.contract.key.split("/")
    for field, expected in zip(
        ("pipeline", "mode", "ecosystem", "backend"), parts[:4], strict=True
    ):
        if payload["metadata"][field] != expected:
            _fail("committed source capture metadata differs from producer key")
    return _ResolvedCapture(
        payload=payload,
        raw=resolved.raw,
        binding=resolved.binding,
        contract=resolved.contract,
        launch=resolved.launch,
        authority_fingerprint=resolved.authority_fingerprint,
    )


def _final(scratch: Path, project: Path, run: str) -> _ResolvedCapture:
    resolved = _resolve_committed_capture(
        scratch,
        project,
        run,
        identity=_capture.FINAL_CAPTURE_IDENTITY,
        output_name=_FINAL_NAME,
        work_unit_suffix="/report_assemble/final_capture",
        schema_version=_capture.FINAL_SCHEMA_VERSION,
    )
    return resolved


def _replay_final_against_source(
    scratch: Path,
    source: _ResolvedCapture,
    final: _ResolvedCapture,
    *,
    label: str,
) -> dict[str, Any]:
    """Semantically replay one resolved final against one resolved source."""

    try:
        payload = _capture._validate_report_assembly_final_capture(
            final.payload,
            expected_final_artifact_identity=_capture.FINAL_CAPTURE_IDENTITY,
            expected_predecessor_binding=source.binding,
        )
        canonical = _capture._canonical_report_assembly_final_capture_bytes(
            payload,
            expected_final_artifact_identity=_capture.FINAL_CAPTURE_IDENTITY,
            expected_predecessor_binding=source.binding,
        )
        replayed = _capture._replay_report_assembly_final_capture(
            scratch,
            payload,
            expected_final_artifact_identity=_capture.FINAL_CAPTURE_IDENTITY,
            expected_predecessor_binding=source.binding,
        )
    except _capture.ReportAssemblyCaptureError as exc:
        _fail(f"{label} final/source capture replay failed: {exc}")
    if replayed != payload or canonical != final.raw:
        _fail(f"{label} final capture bytes are not canonical exact")
    return payload


def _exact_outputs(value: object) -> dict[str, tuple[str, bytes]]:
    if type(value) is not dict:
        raise TypeError("derived_outputs must be an exact dict")
    result: dict[str, tuple[str, bytes]] = {}
    for key, row in value.items():
        if type(key) is not str or type(row) is not tuple or len(row) != 2:
            raise TypeError("derived_outputs rows must be exact string/tuple values")
        role, raw = row
        if type(role) is not str or type(raw) is not bytes:
            raise TypeError("derived_outputs rows must contain exact string/bytes")
        result[key] = (role, raw)
    return result


def _exact_locations(value: object) -> tuple[dict[str, Any], ...]:
    if type(value) is not tuple or any(type(row) is not dict for row in value):
        raise TypeError("location_decisions must be an exact tuple of dicts")
    return tuple(dict(row) for row in value)


def _source_still_exact(
    scratch: Path,
    project: Path,
    run: str,
    prior: _ResolvedCapture,
    expected: _ExpectedSourceRosterBinding,
) -> None:
    current = _source(scratch, project, run, expected)
    if (
        current.raw != prior.raw
        or current.binding != prior.binding
        or current.authority_fingerprint != prior.authority_fingerprint
    ):
        _fail("source capture authority drifted during final construction")


def _producer_requirements_for_source(
    scratch: Path,
    run: str,
    payload: Mapping[str, Any],
    *,
    expected: _ExpectedSourceRosterBinding,
) -> dict[str, InputAuthorityRequirement]:
    """Resolve every present source to one exact active committed producer."""

    source_bytes = (
        _validate_reserved_source_declarations_and_content(
            payload, expected=expected
        )
        if payload.get("schema_version") == _capture.SOURCE_SCHEMA_VERSION
        else {}
    )

    try:
        ledger = read_artifact_ledger(scratch)
    except ArtifactLedgerError as exc:
        _fail(f"source producer ArtifactLedger is invalid: {exc}")
    bindings = ledger.get("artifact_bindings")
    units = ledger.get("work_units")
    if type(bindings) is not dict or type(units) is not dict:
        _fail("source producer ArtifactLedger tables are absent")
    source_rows = {
        row["path"]: row
        for row in payload["sources"]
        if row["presence"] == _capture.PRESENT
    }
    expected_paths = tuple(payload["input_paths"])
    if set(source_rows) != set(expected_paths):
        _fail("source producer denominator differs from capture inputs")

    checked_owners: set[str] = set()
    result: dict[str, InputAuthorityRequirement] = {}
    for path in expected_paths:
        identity = f"scratchpad:{path}"
        row = source_rows[path]
        policies = _report_source_policies(
            path, tuple(row.get("roles", ()))
        )
        binding = bindings.get(identity)
        if type(binding) is not dict:
            _fail(f"{identity}: active committed producer binding is absent")
        owner = binding.get("owner_key")
        writer = str(binding.get("writer") or "").strip().upper()
        unit = units.get(owner) if isinstance(owner, str) else None
        if (
            not isinstance(owner, str)
            or not owner
            or owner.endswith("/report_assemble/source_capture")
            or writer not in {"MODEL", "DRIVER"}
            or binding.get("run_id") != run
            or binding.get("status") != "ACTIVE"
            or type(unit) is not dict
            or unit.get("run_id") != run
            or unit.get("work_unit_key") != owner
            or unit.get("contract_digest") != binding.get("contract_digest")
            or unit.get("launch_digest") != binding.get("launch_digest")
        ):
            _fail(f"{identity}: producer identity/writer/run authority differs")

        metadata = payload.get("metadata")
        if isinstance(metadata, Mapping):
            expected_prefix = "/".join(
                str(metadata[field])
                for field in ("pipeline", "mode", "ecosystem", "backend")
            )
            if not owner.startswith(expected_prefix + "/"):
                _fail(
                    f"{identity}: producer dimensions differ from capture metadata"
                )
            owner_suffix = owner[len(expected_prefix):]
        else:
            owner_parts = owner.split("/")
            if len(owner_parts) != 6:
                _fail(f"{identity}: producer work-unit key is malformed")
            owner_suffix = "/" + "/".join(owner_parts[4:])

        for policy in policies:
            if policy.blocker:
                _fail(
                    f"{identity}: report-source producer is blocked: "
                    f"{policy.blocker}"
                )
            schema_version = str(binding.get("schema_version") or "")
            if not _policy_owner_allowed(
                policy,
                owner_suffix=owner_suffix,
                writer=writer,
                schema_version=schema_version,
            ):
                _fail(
                    f"{identity}: producer owner/writer/schema is not permitted "
                    f"for role {policy.role}"
                )

        reserved = (
            _RESERVED_REPORT_SOURCE_AUTHORITIES.get(path)
            if source_bytes
            else None
        )
        if reserved is not None:
            metadata = payload["metadata"]
            expected_owner = "/".join(
                (
                    metadata["pipeline"],
                    metadata["mode"],
                    metadata["ecosystem"],
                    metadata["backend"],
                    reserved.phase,
                    reserved.work_unit_id,
                )
            )
            if (
                owner != expected_owner
                or writer != "DRIVER"
                or binding.get("schema_version") != reserved.schema_version
            ):
                _fail(
                    f"{identity}: reserved producer owner/writer/schema authority differs"
                )
            producer_contract = _registered_producer_contract_from_committed_manifest(
                unit,
                expected_work_unit=expected_owner,
            )
            producer_launch = _launch_from_committed_manifest(
                unit, producer_contract
            )
            try:
                output_spec = producer_contract.output(identity)
            except KeyError:
                _fail(f"{identity}: reserved producer output is absent")
            if (
                producer_contract.model_invoked
                or output_spec.writer != "DRIVER"
                or output_spec.schema_version != reserved.schema_version
                or producer_launch.model != "driver"
                or producer_launch.exec_mode != "python"
                or producer_launch.tool_policy != ("filesystem",)
            ):
                _fail(
                    f"{identity}: reserved producer contract/launch authority differs"
                )
            if path == "report_human_review_authority.json":
                human = _validate_human_review_authority_bytes(
                    source_bytes[path],
                    expected_run_id=run,
                    expected_contract_digest=producer_contract.digest,
                    expected_launch_digest=producer_launch.digest,
                )
                expected_inputs = tuple(
                    row["identity"] for row in human["inputs"]
                )
                expected_outputs = {
                    identity,
                    *(
                        row["identity"]
                        for row in human["sections"]
                        if row["presence"] == "PRESENT"
                    ),
                }
                if (
                    producer_contract.immutable_inputs != expected_inputs
                    or {row.identity for row in producer_contract.outputs}
                    != expected_outputs
                ):
                    _fail(
                        f"{identity}: human-review content denominator differs from producer contract"
                    )
            elif producer_contract.immutable_inputs or len(
                producer_contract.outputs
            ) != 1:
                _fail(
                    f"{identity}: reserved zero-input producer denominator differs"
                )

        producer_contract: PhaseIOContract | None = None
        producer_launch: LaunchSpec | None = None
        if policies and reserved is None:
            producer_contract = _registered_producer_contract_from_committed_manifest(
                unit,
                expected_work_unit=owner,
            )
            producer_launch = _launch_from_committed_manifest(
                unit, producer_contract
            )
            try:
                output_spec = producer_contract.output(identity)
            except KeyError:
                _fail(f"{identity}: registered producer output is absent")
            if (
                output_spec.owner_key != owner
                or output_spec.writer != writer
                or output_spec.schema_version != binding.get("schema_version")
            ):
                _fail(
                    f"{identity}: registered producer output authority differs"
                )
            for policy in policies:
                if not any(
                    re.fullmatch(pattern, output_spec.schema_version)
                    for pattern in policy.schema_patterns
                ):
                    _fail(
                        f"{identity}: registered producer output schema is not "
                        f"permitted for role {policy.role}"
                    )
                _validate_policy_launch(
                    policy,
                    contract=producer_contract,
                    launch=producer_launch,
                    writer=writer,
                )
        if owner not in checked_owners:
            artifacts = unit.get("artifacts")
            if type(artifacts) is not dict or not artifacts:
                _fail(f"{owner}: committed producer artifacts are absent")
            issues = active_committed_work_unit_authority_issues(
                ledger,
                work_unit_key=owner,
                run_id=run,
                expected_artifact_identities=tuple(sorted(artifacts)),
            )
            if issues:
                _fail(
                    f"{owner}: active producer authority failed: "
                    + "; ".join(issues)
                )
            checked_owners.add(owner)
        artifact = unit["artifacts"].get(identity)
        if (
            type(artifact) is not dict
            or artifact.get("sha256") != row["sha256"]
            or artifact.get("size") != row["size"]
            or binding.get("sha256") != row["sha256"]
            or binding.get("size") != row["size"]
        ):
            _fail(f"{identity}: captured bytes differ from producer authority")
        if policies:
            raw = source_bytes.get(path)
            if raw is None:
                try:
                    raw = read_bounded_regular_bytes(
                        scratch / path,
                        _MAX_CAPTURE_BYTES,
                        require_single_link=True,
                    )
                except (OSError, ValueError) as exc:
                    _fail(f"{identity}: policy content read failed: {exc}")
            if (
                hashlib.sha256(raw).hexdigest() != row["sha256"]
                or len(raw) != row["size"]
            ):
                _fail(f"{identity}: policy content differs from capture")
            for policy in policies:
                _validate_policy_source_content(
                    policy,
                    path=path,
                    raw=raw,
                )
        result[path] = InputAuthorityRequirement(
            identity=identity,
            allow_raw=False,
            expected_producer_work_unit_key=owner,
            expected_writer=writer,
            require_same_run=True,
            expected_contract_digest=str(unit.get("contract_digest") or ""),
            expected_launch_digest=str(unit.get("launch_digest") or ""),
            require_exact_contract=True,
            require_exact_launch=True,
        )
    return result


def resolve_exact_report_input_authorities(
    *,
    scratchpad: str | Path,
    project_root: str | Path,
    run_id: str,
    expected_config: Mapping[str, Any],
    input_paths: tuple[str, ...],
) -> tuple[InputAuthorityRequirement, ...]:
    """Resolve an exact present-file denominator without admitting RAW rows."""

    if type(input_paths) is not tuple or any(
        type(path) is not str for path in input_paths
    ):
        raise TypeError("input_paths must be an exact tuple of strings")
    if tuple(sorted(set(input_paths))) != input_paths:
        _fail("exact report input paths must be sorted and unique")
    scratch, project = _roots(scratchpad, project_root)
    run = _run_id(run_id)
    expected = _expected_source_roster_binding(
        scratch=scratch,
        project=project,
        run=run,
        expected_config=expected_config,
    )
    rows: list[dict[str, Any]] = []
    for relative in input_paths:
        candidate = Path(relative)
        if (
            not relative
            or candidate.is_absolute()
            or ".." in candidate.parts
            or candidate.as_posix() != relative
        ):
            _fail(f"exact report input path is unsafe: {relative!r}")
        try:
            raw = read_bounded_regular_bytes(
                scratch / candidate,
                _MAX_CAPTURE_BYTES,
                require_single_link=True,
            )
        except (OSError, ValueError) as exc:
            _fail(f"scratchpad:{relative}: exact input read failed: {exc}")
        rows.append(
            {
                "path": relative,
                "presence": _capture.PRESENT,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "size": len(raw),
            }
        )
    requirements = _producer_requirements_for_source(
        scratch,
        run,
        {"sources": rows, "input_paths": list(input_paths)},
        expected=expected,
    )
    return tuple(requirements[path] for path in input_paths)


def _source_contract_and_launch_for_candidate(
    *,
    scratch: Path,
    run: str,
    raw: bytes,
    timeout_s: int,
    expected: _ExpectedSourceRosterBinding,
) -> tuple[dict[str, Any], PhaseIOContract, LaunchSpec]:
    payload = _json_exact_dict(raw, label="source capture candidate")
    try:
        normalized = _capture._validate_report_assembly_source_capture(payload)
        canonical = _capture._canonical_report_assembly_source_capture_bytes(
            normalized
        )
        _capture._replay_report_assembly_source_capture(scratch, normalized)
    except _capture.ReportAssemblyCaptureError as exc:
        _fail(f"source capture candidate schema/replay failed: {exc}")
    if canonical != raw:
        _fail("source capture candidate bytes are not canonical exact")
    metadata = normalized["metadata"]
    if metadata["run_id"] != run:
        _fail("source capture candidate run_id differs")
    _validate_reserved_source_declarations_and_content(
        normalized, expected=expected
    )
    requirements = _producer_requirements_for_source(
        scratch, run, normalized, expected=expected
    )
    try:
        contract = resolve_phase_io_contract(
            pipeline=metadata["pipeline"],
            mode=metadata["mode"],
            ecosystem=metadata["ecosystem"],
            backend=metadata["backend"],
            phase="report_assemble",
            work_unit_id="source_capture",
            exact_inputs=tuple(normalized["input_paths"]),
            exact_outputs=(_SOURCE_NAME,),
            exact_input_authorities=requirements,
        )
        launch = LaunchSpec(
            work_unit_key=contract.key,
            pipeline=contract.pipeline,
            mode=contract.mode,
            ecosystem=contract.ecosystem,
            backend=contract.backend,
            model="driver",
            timeout_s=max(1, int(timeout_s)),
            exec_mode="python",
            tool_policy=("filesystem",),
        )
    except (TypeError, ValueError) as exc:
        _fail(f"source capture PhaseIO authority cannot resolve: {exc}")

    # Close both live source and producer-binding races after contract creation.
    try:
        replayed = _capture._replay_report_assembly_source_capture(
            scratch, normalized
        )
    except _capture.ReportAssemblyCaptureError as exc:
        _fail(f"source capture candidate terminal replay failed: {exc}")
    terminal_requirements = _producer_requirements_for_source(
        scratch, run, normalized, expected=expected
    )
    if (
        replayed != normalized
        or {
            path: requirement.to_dict()
            for path, requirement in terminal_requirements.items()
        }
        != {
            path: requirement.to_dict()
            for path, requirement in requirements.items()
        }
    ):
        _fail("source capture producer authority drifted during preparation")
    return normalized, contract, launch


def prepare_report_source_capture(
    *,
    scratchpad: str | Path,
    project_root: str | Path,
    run_id: str,
    expected_config: Mapping[str, Any],
    metadata: Mapping[str, str],
    fixed_source_roles: Mapping[str, str] | None = None,
    namespace_roles: Mapping[str, str] | None = None,
    timeout_s: int = 120,
) -> PreparedReportSourceCapture:
    """Build a candidate whose every present input has exact producer authority."""

    scratch, project = _roots(scratchpad, project_root)
    run = _run_id(run_id)
    expected = _expected_source_roster_binding(
        scratch=scratch,
        project=project,
        run=run,
        expected_config=expected_config,
    )
    bound_metadata = _metadata_bound_to_expected_roster(metadata, expected)
    try:
        payload = _capture._capture_report_assembly_source(
            scratch,
            metadata=bound_metadata,
            fixed_source_roles=fixed_source_roles,
            namespace_roles=namespace_roles,
        )
        raw = _capture._canonical_report_assembly_source_capture_bytes(payload)
    except _capture.ReportAssemblyCaptureError as exc:
        _fail(f"source capture construction failed: {exc}")
    normalized, contract, launch = _source_contract_and_launch_for_candidate(
        scratch=scratch,
        run=run,
        raw=raw,
        timeout_s=timeout_s,
        expected=expected,
    )
    return PreparedReportSourceCapture(
        capture_bytes=raw,
        contract=contract,
        launch=launch,
        exact_input_paths=tuple(normalized["input_paths"]),
        explicit_absences=tuple(normalized["explicit_absences"]),
    )


def validate_report_source_candidate_bytes(
    *,
    scratchpad: str | Path,
    project_root: str | Path,
    run_id: str,
    expected_config: Mapping[str, Any],
    source_capture_bytes: bytes,
    expected_contract: PhaseIOContract | None = None,
    expected_launch: LaunchSpec | None = None,
    timeout_s: int = 120,
) -> bytes:
    """Replay one armed candidate and its exact current producer denominator."""

    raw = _exact_bytes(source_capture_bytes, label="source_capture_bytes")
    scratch, project = _roots(scratchpad, project_root)
    run = _run_id(run_id)
    expected = _expected_source_roster_binding(
        scratch=scratch,
        project=project,
        run=run,
        expected_config=expected_config,
    )
    _, contract, launch = _source_contract_and_launch_for_candidate(
        scratch=scratch,
        run=run,
        raw=raw,
        timeout_s=timeout_s,
        expected=expected,
    )
    if expected_contract is not None and (
        type(expected_contract) is not PhaseIOContract
        or expected_contract.to_dict() != contract.to_dict()
    ):
        _fail("source capture candidate contract authority drifted")
    if expected_launch is not None and (
        type(expected_launch) is not LaunchSpec
        or expected_launch.to_dict() != launch.to_dict()
    ):
        _fail("source capture candidate launch authority drifted")
    return raw


def load_committed_report_source_capture_bytes(
    *,
    scratchpad: str | Path,
    project_root: str | Path,
    run_id: str,
    expected_config: Mapping[str, Any],
) -> bytes:
    """Load exact source bytes only through the active committed receipt."""

    scratch, project = _roots(scratchpad, project_root)
    run = _run_id(run_id)
    expected = _expected_source_roster_binding(
        scratch=scratch,
        project=project,
        run=run,
        expected_config=expected_config,
    )
    return _source(scratch, project, run, expected).raw


def extract_committed_report_source_inputs(
    *,
    scratchpad: str | Path,
    project_root: str | Path,
    run_id: str,
    expected_config: Mapping[str, Any],
) -> CommittedReportSourceInputs:
    """Expose frozen exact source inputs after committed authority replay."""

    scratch, project = _roots(scratchpad, project_root)
    run = _run_id(run_id)
    expected = _expected_source_roster_binding(
        scratch=scratch,
        project=project,
        run=run,
        expected_config=expected_config,
    )
    source = _source(scratch, project, run, expected)
    try:
        source_bytes = _capture._report_assembly_capture_source_bytes(
            source.payload
        )
        namespaces = _capture._report_assembly_capture_source_namespaces(
            source.payload
        )
    except _capture.ReportAssemblyCaptureError as exc:
        _fail(f"committed source extraction failed: {exc}")
    source_rows = {
        row["path"]: row for row in source.payload["sources"]
    }
    inputs = tuple(
        CapturedReportSourceInput(
            path=path,
            roles=roles,
            content=raw,
            sha256=source_rows[path]["sha256"],
            size=source_rows[path]["size"],
        )
        for path, (roles, raw) in sorted(source_bytes.items())
    )
    namespace_rosters = tuple(
        CapturedReportSourceNamespace(
            pattern=pattern,
            role=role,
            members=members,
            membership_digest=digest,
        )
        for pattern, role, members, digest in namespaces
    )
    return CommittedReportSourceInputs(
        capture_bytes=source.raw,
        inputs=inputs,
        explicit_absences=tuple(source.payload["explicit_absences"]),
        namespace_rosters=namespace_rosters,
        metadata=tuple(sorted(source.payload["metadata"].items())),
        source_set_digest=source.payload["source_set_digest"],
        commit_receipt_digest=source.binding["commit_receipt_digest"],
    )


def build_report_final_capture_bytes(
    *,
    scratchpad: str | Path,
    project_root: str | Path,
    run_id: str,
    expected_config: Mapping[str, Any],
    derived_outputs: dict[str, tuple[str, bytes]],
    location_decisions: tuple[dict[str, Any], ...] = (),
) -> bytes:
    """Construct final bytes from the exact active source-capture receipt."""

    scratch, project = _roots(scratchpad, project_root)
    run = _run_id(run_id)
    expected = _expected_source_roster_binding(
        scratch=scratch,
        project=project,
        run=run,
        expected_config=expected_config,
    )
    outputs = _exact_outputs(derived_outputs)
    locations = _exact_locations(location_decisions)
    source = _source(scratch, project, run, expected)
    try:
        payload = _capture._build_report_assembly_final_capture(
            scratch,
            source_capture=source.payload,
            expected_final_artifact_identity=_capture.FINAL_CAPTURE_IDENTITY,
            predecessor_binding=source.binding,
            derived_outputs=outputs,
            location_decisions=locations,
        )
        raw = _capture._canonical_report_assembly_final_capture_bytes(
            payload,
            expected_final_artifact_identity=_capture.FINAL_CAPTURE_IDENTITY,
            expected_predecessor_binding=source.binding,
        )
    except _capture.ReportAssemblyCaptureError as exc:
        _fail(f"final capture construction failed: {exc}")
    _source_still_exact(scratch, project, run, source, expected)
    return raw


def validate_report_final_candidate_bytes(
    *,
    scratchpad: str | Path,
    project_root: str | Path,
    run_id: str,
    expected_config: Mapping[str, Any],
    final_capture_bytes: bytes,
) -> bytes:
    """Validate proposed exact final bytes against current source authority."""

    raw = _exact_bytes(final_capture_bytes, label="final_capture_bytes")
    scratch, project = _roots(scratchpad, project_root)
    run = _run_id(run_id)
    expected = _expected_source_roster_binding(
        scratch=scratch,
        project=project,
        run=run,
        expected_config=expected_config,
    )
    source = _source(scratch, project, run, expected)
    payload = _json_exact_dict(raw, label="final capture candidate")
    try:
        normalized = _capture._validate_report_assembly_final_capture(
            payload,
            expected_final_artifact_identity=_capture.FINAL_CAPTURE_IDENTITY,
            expected_predecessor_binding=source.binding,
        )
        canonical = _capture._canonical_report_assembly_final_capture_bytes(
            normalized,
            expected_final_artifact_identity=_capture.FINAL_CAPTURE_IDENTITY,
            expected_predecessor_binding=source.binding,
        )
        _capture._replay_report_assembly_final_capture(
            scratch,
            normalized,
            expected_final_artifact_identity=_capture.FINAL_CAPTURE_IDENTITY,
            expected_predecessor_binding=source.binding,
        )
    except _capture.ReportAssemblyCaptureError as exc:
        _fail(f"final capture predecessor/authority validation failed: {exc}")
    if canonical != raw:
        _fail("final capture candidate bytes are not canonical exact")
    _source_still_exact(scratch, project, run, source, expected)
    return raw


def _committed_pair(
    scratchpad: str | Path,
    project_root: str | Path,
    run_id: str,
    expected_config: Mapping[str, Any],
) -> tuple[Path, Path, str, _ResolvedCapture, _ResolvedCapture]:
    scratch, project = _roots(scratchpad, project_root)
    run = _run_id(run_id)
    expected = _expected_source_roster_binding(
        scratch=scratch,
        project=project,
        run=run,
        expected_config=expected_config,
    )
    source = _source(scratch, project, run, expected)
    final = _final(scratch, project, run)
    _replay_final_against_source(
        scratch, source, final, label="committed initial"
    )
    _source_still_exact(scratch, project, run, source, expected)
    current_final = _final(scratch, project, run)
    if (
        current_final.raw != final.raw
        or current_final.binding != final.binding
        or current_final.authority_fingerprint != final.authority_fingerprint
    ):
        _fail("final capture authority drifted during committed replay")
    _replay_final_against_source(
        scratch, source, current_final, label="committed terminal"
    )
    terminal_source = _source(scratch, project, run, expected)
    if (
        terminal_source.raw != source.raw
        or terminal_source.binding != source.binding
        or terminal_source.authority_fingerprint != source.authority_fingerprint
    ):
        _fail("source capture authority drifted during terminal final replay")
    try:
        combined_source, combined_final = (
            _capture._replay_report_assembly_terminal_pair(
                scratch,
                source_capture=terminal_source.payload,
                source_capture_bytes=terminal_source.raw,
                final_capture=current_final.payload,
                final_capture_bytes=current_final.raw,
                expected_final_artifact_identity=(
                    _capture.FINAL_CAPTURE_IDENTITY
                ),
                expected_predecessor_binding=terminal_source.binding,
            )
        )
    except _capture.ReportAssemblyCaptureError as exc:
        _fail(f"committed terminal combined authority replay failed: {exc}")
    if (
        combined_source != terminal_source.payload
        or combined_final != current_final.payload
    ):
        _fail("committed terminal combined authority payload drifted")
    # No filesystem, callback, ledger, or mutable authority is consulted after
    # this combined epoch.  Downstream consumers use only this in-memory pair.
    return scratch, project, run, terminal_source, current_final


def load_committed_report_final_capture_bytes(
    *,
    scratchpad: str | Path,
    project_root: str | Path,
    run_id: str,
    expected_config: Mapping[str, Any],
) -> bytes:
    """Load only an exact live final capture with source+final receipts."""

    return _committed_pair(
        scratchpad, project_root, run_id, expected_config
    )[4].raw


def extract_committed_report_outputs(
    *,
    scratchpad: str | Path,
    project_root: str | Path,
    run_id: str,
    expected_config: Mapping[str, Any],
) -> tuple[dict[str, bytes], tuple[str, ...]]:
    """Extract output bytes/absences only after both committed receipts replay."""

    _, _, _, source, final = _committed_pair(
        scratchpad, project_root, run_id, expected_config
    )
    try:
        outputs = _capture._report_assembly_capture_output_bytes(
            final.payload,
            expected_final_artifact_identity=_capture.FINAL_CAPTURE_IDENTITY,
            expected_predecessor_binding=source.binding,
        )
        absences = _capture._report_assembly_capture_output_absences(
            final.payload,
            expected_final_artifact_identity=_capture.FINAL_CAPTURE_IDENTITY,
            expected_predecessor_binding=source.binding,
        )
    except _capture.ReportAssemblyCaptureError as exc:
        _fail(f"committed output extraction failed: {exc}")
    return outputs, absences


def prepare_committed_report_publication(
    *,
    scratchpad: str | Path,
    project_root: str | Path,
    run_id: str,
    expected_config: Mapping[str, Any],
) -> CommittedReportPublication:
    """Return the exact publication plan after a final full authority replay."""

    _, _, _, source, final = _committed_pair(
        scratchpad, project_root, run_id, expected_config
    )
    try:
        outputs = _capture._report_assembly_capture_output_bytes(
            final.payload,
            expected_final_artifact_identity=_capture.FINAL_CAPTURE_IDENTITY,
            expected_predecessor_binding=source.binding,
        )
        absences = _capture._report_assembly_capture_output_absences(
            final.payload,
            expected_final_artifact_identity=_capture.FINAL_CAPTURE_IDENTITY,
            expected_predecessor_binding=source.binding,
        )
    except _capture.ReportAssemblyCaptureError as exc:
        _fail(f"publication preparation failed: {exc}")
    return CommittedReportPublication(
        final_capture_bytes=final.raw,
        output_bytes=outputs,
        absent_output_identities=absences,
        source_commit_receipt_digest=source.binding["commit_receipt_digest"],
        final_commit_receipt_digest=final.binding["commit_receipt_digest"],
    )


__all__ = [
    "CapturedReportSourceInput",
    "CapturedReportSourceNamespace",
    "CommittedReportPublication",
    "CommittedReportSourceInputs",
    "PreparedReportSourceCapture",
    "ReportCaptureAuthorityError",
    "build_report_final_capture_bytes",
    "extract_committed_report_source_inputs",
    "extract_committed_report_outputs",
    "load_committed_report_source_capture_bytes",
    "load_committed_report_final_capture_bytes",
    "prepare_report_source_capture",
    "prepare_committed_report_publication",
    "report_source_policy_inventory",
    "resolve_exact_report_input_authorities",
    "validate_report_source_candidate_bytes",
    "validate_report_final_candidate_bytes",
]
