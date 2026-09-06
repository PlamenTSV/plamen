"""Loss-accounting harvest compiler for real-audit RunBundle v2.

The harvest draft is GT-blind and deliberately conservative:

* exact producer lineage may link occurrences;
* prose/title/location/native-ID similarity never creates an alias;
* report-only findings become candidates with explicit parse debt;
* every physical source record is partitioned into an occurrence,
  authenticated/nonfinding placeholder, or explicit debt.

The production materializer below emits USER_RUN/B0_LOCAL evidence with
``UNAUTHENTICATED_PARSE`` authority sentinels.  Those rows are useful for
diagnosis and private adjudication but can never satisfy a B1 publication gate.
"""
from __future__ import annotations

from dataclasses import dataclass
import base64
import copy
import hashlib
import re
from typing import Any, Iterable, Mapping

try:
    import runbundle_contracts as C
    import runbundle_phase_map as M
    import runbundle_privacy as P
    import runbundle_sources as S
except ImportError:  # pragma: no cover
    from . import runbundle_contracts as C
    from . import runbundle_phase_map as M
    from . import runbundle_privacy as P
    from . import runbundle_sources as S


HARVEST_DRAFT_RECEIPT_SCHEMA = "plamen.runbundle-harvest-draft-receipt.v1"
LOCAL_MATERIALIZATION_POLICY_SCHEMA = (
    "plamen.runbundle-local-materialization-policy.v1"
)
LOCAL_MATERIALIZATION_POLICY_VERSION = "2026.07.29"


class RunBundleHarvestError(ValueError):
    """Harvest evidence could not be conserved without fabrication."""


@dataclass(frozen=True, slots=True)
class HarvestDraft:
    run_id: str
    candidate_set: dict[str, Any]
    lineage: dict[str, Any]
    report_projection: dict[str, Any]
    raw_output_index: dict[str, Any]
    source_receipt: dict[str, Any]
    nonfinding_record_ids: tuple[str, ...]
    debt_record_ids: tuple[str, ...]
    record_debt_ids: dict[str, str]
    inventory: S.SourceInventory


_LABELED_FIELD_RE = re.compile(
    r"(?im)^\s*\*{0,2}(?P<label>mechanism|description|impact|preconditions?)"
    r"\*{0,2}\s*:\s*(?P<value>.+?)\s*$"
)
_LOCATION_RE = re.compile(
    r"`?(?P<path>[A-Za-z0-9_.@+\-/]+)"
    r"(?::(?P<start>\d+)(?:-(?P<end>\d+))?)?`?"
)


def _id(prefix: str, *parts: bytes, length: int = 28) -> str:
    digest = hashlib.sha256(
        b"plamen.runbundle.harvest-id.v1\0"
        + b"\0".join(parts)
    ).hexdigest()
    return f"{prefix}-{digest[:length]}"


def _candidate_id(
    run_id: str,
    artifact: S.SourceArtifact,
    record: S.SourceRecord,
) -> str:
    digest = hashlib.sha256(
        b"plamen.real-audit.candidate.v2\0"
        + C.canonical_json_bytes(
            {
                "run_id": run_id,
                "first_producer_artifact_id": artifact.artifact_id,
                "first_source_record_key_hash": record.record_sha256,
                "native_lineage_anchor": (
                    record.native_candidate_id or record.record_id
                ),
            }
        )
    ).digest()
    encoded = base64.b32encode(digest).decode("ascii").rstrip("=")
    return "C2-" + encoded[:26]


def _record_text(artifact: S.SourceArtifact, record: S.SourceRecord) -> str:
    return artifact.raw[record.byte_start : record.byte_end].decode(
        "utf-8", errors="replace"
    )


def _claim(
    artifact: S.SourceArtifact,
    record: S.SourceRecord,
) -> tuple[dict[str, Any], list[str]]:
    text = _record_text(artifact, record)
    fields: dict[str, list[str]] = {}
    for match in _LABELED_FIELD_RE.finditer(text):
        fields.setdefault(match.group("label").casefold(), []).append(
            match.group("value").strip()
        )
    title = record.title or record.native_candidate_id or "Unparsed audit claim"
    mechanism = (fields.get("mechanism") or [None])[0]
    description = (fields.get("description") or [None])[0]
    impact = (fields.get("impact") or [None])[0]
    preconditions = (
        fields.get("precondition")
        or fields.get("preconditions")
        or []
    )
    debts = list(record.debt_codes)
    if mechanism is None:
        debts.append("MISSING_MECHANISM")
    if impact is None:
        debts.append("MISSING_IMPACT")
    return (
        {
            "title": title,
            "mechanism": mechanism,
            "description": description or text.strip()[:100_000] or None,
            "impact": impact,
            "preconditions": preconditions,
        },
        sorted(set(debts)),
    )


def _locations(
    artifact: S.SourceArtifact,
    record: S.SourceRecord,
) -> tuple[list[dict[str, Any]], list[str]]:
    text = _record_text(artifact, record)
    candidate: re.Match[str] | None = None
    for match in _LOCATION_RE.finditer(text):
        path = match.group("path")
        if "/" not in path and "." not in path:
            continue
        try:
            P.assert_safe_relative_path(path, label="parsed candidate location")
        except P.RunBundlePrivacyError:
            continue
        candidate = match
        break
    if candidate is None:
        return [], ["UNRESOLVED_LOCATION"]
    path = candidate.group("path")
    start_text = candidate.group("start")
    end_text = candidate.group("end")
    if start_text is None:
        return (
            [
                {
                    "relative_path": path,
                    "function": None,
                    "line_start": None,
                    "line_end": None,
                    "location_state": "UNRESOLVED",
                    "source_record_id": record.record_id,
                }
            ],
            ["UNRESOLVED_LOCATION"],
        )
    start = int(start_text)
    end = int(end_text or start_text)
    return (
        [
            {
                "relative_path": path,
                "function": None,
                "line_start": start,
                "line_end": end,
                "location_state": "EXACT",
                "source_record_id": record.record_id,
            }
        ],
        [],
    )


def _record_partition(inventory: S.SourceInventory) -> dict[str, str]:
    partition: dict[str, str] = {}
    for artifact in inventory.artifacts:
        cursor = 0
        for record in artifact.records:
            if record.byte_start != cursor or record.byte_end <= record.byte_start:
                raise RunBundleHarvestError(
                    f"record partition gap/overlap in {artifact.relative_source_path}"
                )
            cursor = record.byte_end
            if record.record_id in partition:
                raise RunBundleHarvestError("record identity collision")
            partition[record.record_id] = artifact.artifact_id
        if cursor != artifact.byte_length:
            raise RunBundleHarvestError(
                f"record partition does not cover {artifact.relative_source_path}"
            )
    return partition


def _raw_output_index(
    run_id: str,
    inventory: S.SourceInventory,
    *,
    inline_limit: int,
) -> dict[str, Any]:
    artifacts: list[dict[str, Any]] = []
    for row in inventory.artifacts:
        base = {
            "artifact_id": row.artifact_id,
            "relative_source_path": row.relative_source_path,
            "native_phase": row.native_phase,
            "macro_phase": row.macro_phase,
            "work_unit_id": row.work_unit_id,
            "producer_kind": row.producer_kind,
            "media_type": row.media_type,
            "byte_length": row.byte_length,
            "sha256": row.sha256,
            "record_ids": sorted(
                (record.record_id for record in row.records),
                key=lambda item: item.encode("utf-8"),
            ),
            "source_contract_ref": row.source_contract_ref,
            "commit_state": row.commit_state,
            "redactions": [],
        }
        try:
            content = row.raw.decode("utf-8")
            P.validate_public_object_bytes(row.raw, media_type=row.media_type)
        except (UnicodeDecodeError, P.RunBundlePrivacyError):
            content = None
        if content is not None and row.byte_length <= inline_limit:
            artifacts.append(
                {
                    **base,
                    "storage": "INLINE_UTF8",
                    "content": content,
                }
            )
        else:
            artifacts.append(
                {
                    **base,
                    "storage": "OBJECT",
                    "object_path": f"objects/sha256/{row.sha256}",
                }
            )
    return {
        "schema_version": C.RAW_OUTPUT_INDEX_SCHEMA,
        "run_id": run_id,
        "authority_receipts": [],
        "artifacts": sorted(
            artifacts, key=lambda item: item["artifact_id"].encode("utf-8")
        ),
    }


def build_harvest_draft(
    *,
    run_id: str,
    adapter_id: str,
    inventory: S.SourceInventory,
    inline_limit: int = 1 << 20,
) -> HarvestDraft:
    if not isinstance(run_id, str) or not run_id or any(
        char.isspace() for char in run_id
    ):
        raise RunBundleHarvestError("run ID is invalid")
    if not isinstance(adapter_id, str) or not adapter_id:
        raise RunBundleHarvestError("adapter ID is invalid")
    if not isinstance(inventory, S.SourceInventory) or not inventory.stable:
        raise RunBundleHarvestError("harvest requires a stable source inventory")
    if not isinstance(inline_limit, int) or inline_limit < 0:
        raise RunBundleHarvestError("inline limit is invalid")
    _record_partition(inventory)

    candidates: list[dict[str, Any]] = []
    occurrences: list[dict[str, Any]] = []
    debts: list[dict[str, Any]] = []
    nonfinding: list[str] = []
    debt_records: list[str] = []
    record_debt_ids: dict[str, str] = {}
    report_unmapped: list[dict[str, Any]] = []
    report_artifact: S.SourceArtifact | None = None

    for artifact in inventory.artifacts:
        if artifact.producer_kind == "FINAL_REPORT":
            report_artifact = artifact
        for record in artifact.records:
            if record.record_kind == "NONFINDING":
                nonfinding.append(record.record_id)
                continue
            if record.record_kind == "DEBT":
                debt_id = _id(
                    "debt",
                    artifact.artifact_id.encode("ascii"),
                    record.record_id.encode("ascii"),
                )
                debt_records.append(record.record_id)
                record_debt_ids[record.record_id] = debt_id
                debts.append(
                    {
                        "debt_id": debt_id,
                        "debt_code": (
                            record.debt_codes[0]
                            if record.debt_codes
                            else "UNPARSED_RECORD"
                        ),
                        "candidate_ids": [],
                        "occurrence_ids": [],
                        "authority_refs": [C.UNAUTHENTICATED_AUTHORITY],
                        "detail": (
                            "The source record is preserved exactly but its "
                            "schema/parser contract was unavailable."
                        ),
                    }
                )
                continue

            candidate_id = _candidate_id(run_id, artifact, record)
            occurrence_id = _id(
                "occurrence",
                candidate_id.encode("ascii"),
                record.record_id.encode("ascii"),
            )
            claim, claim_debts = _claim(artifact, record)
            locations, location_debts = _locations(artifact, record)
            quality_debts = sorted(set(claim_debts + location_debts))
            report_only = artifact.producer_kind == "FINAL_REPORT"
            if report_only:
                quality_debts.append("UNMAPPED_REPORT_FINDING")
                quality_debts = sorted(set(quality_debts))
            candidate = {
                "candidate_id": candidate_id,
                "first_occurrence_id": occurrence_id,
                "native_candidate_ids": [
                    record.native_candidate_id or record.record_id
                ],
                "producer": {
                    "adapter_id": adapter_id,
                    "native_phase": artifact.native_phase,
                    "work_unit_id": artifact.work_unit_id,
                    "artifact_id": artifact.artifact_id,
                    "record_id": record.record_id,
                },
                "claim": claim,
                "locations": locations,
                "evidence_refs": [
                    f"{artifact.artifact_id}#{record.record_id}"
                ],
                "audit_severity": {
                    "label": "UNASSESSED",
                    "authority_receipt_id": None,
                },
                "quality": {
                    "parse_completeness": (
                        "PARTIAL" if quality_debts else "COMPLETE"
                    ),
                    "location_quality": (
                        "EXACT" if locations and not location_debts else "UNRESOLVED"
                    ),
                    "evidence_quality": "UNAUTHENTICATED",
                    "debts": quality_debts,
                },
                "audit_cluster_id": None,
            }
            occurrence = {
                "occurrence_id": occurrence_id,
                "candidate_id": candidate_id,
                "native_phase": artifact.native_phase,
                "macro_phase": artifact.macro_phase,
                "artifact_id": artifact.artifact_id,
                "record_id": record.record_id,
                "record_sha256": record.record_sha256,
                "byte_range": {
                    "start": record.byte_start,
                    "end": record.byte_end,
                },
                "role": "FINAL_REPORT" if report_only else "DISCOVERY",
                "state": "UNKNOWN" if report_only else "POSITIVE",
                "asserted_severity": "UNASSESSED",
                "location_snapshot": copy.deepcopy(locations),
                "evidence_refs": [
                    f"{artifact.artifact_id}#{record.record_id}"
                ],
                "authority_ref": C.UNAUTHENTICATED_AUTHORITY,
            }
            candidates.append(candidate)
            occurrences.append(occurrence)
            if report_only:
                debt_id = _id(
                    "debt",
                    candidate_id.encode("ascii"),
                    b"UNMAPPED_REPORT_FINDING",
                )
                debts.append(
                    {
                        "debt_id": debt_id,
                        "debt_code": "UNMAPPED_REPORT_FINDING",
                        "candidate_ids": [candidate_id],
                        "occurrence_ids": [occurrence_id],
                        "authority_refs": [C.UNAUTHENTICATED_AUTHORITY],
                        "detail": (
                            "A finding-like final-report section has no exact "
                            "authenticated candidate lineage."
                        ),
                    }
                )
                report_unmapped.append(
                    {
                        "entry_id": _id(
                            "report-unmapped",
                            candidate_id.encode("ascii"),
                            record.record_id.encode("ascii"),
                        ),
                        "section_locator": (
                            record.native_candidate_id or record.record_id
                        ),
                        "byte_range": {
                            "start": record.byte_start,
                            "end": record.byte_end,
                        },
                        "byte_range_sha256": record.record_sha256,
                        "promoted_candidate_id": candidate_id,
                        "debt_code": "UNMAPPED_REPORT_FINDING",
                    }
                )

    if report_artifact is None:
        raise RunBundleHarvestError("final AUDIT_REPORT.md was not inventoried")

    candidates.sort(key=lambda item: item["candidate_id"].encode("utf-8"))
    occurrences.sort(key=lambda item: item["occurrence_id"].encode("utf-8"))
    debts.sort(key=lambda item: item["debt_id"].encode("utf-8"))
    report_unmapped.sort(key=lambda item: item["entry_id"].encode("utf-8"))
    candidate_ids = [item["candidate_id"] for item in candidates]
    candidate_set = {
        "schema_version": C.CANDIDATE_SET_SCHEMA,
        "run_id": run_id,
        "candidates": candidates,
    }
    lineage = {
        "schema_version": C.CANDIDATE_LINEAGE_SCHEMA,
        "run_id": run_id,
        "occurrences": occurrences,
        "edges": [],
        "alias_classes": [],
        "negative_dispositions": [],
        "lineage_debts": debts,
    }
    report_projection = {
        "schema_version": C.REPORT_PROJECTION_SCHEMA,
        "run_id": run_id,
        "final_report_artifact_id": report_artifact.artifact_id,
        "final_report_sha256": report_artifact.sha256,
        "final_report_byte_length": report_artifact.byte_length,
        "delivery_state": "DELIVERED",
        "report_entries": [],
        "appendix_entries": [],
        "unmapped_finding_sections": report_unmapped,
        "candidate_report_dispositions": [
            {
                "candidate_id": candidate_id,
                "report_status": "DEBT",
                "authority_receipt_id": C.UNAUTHENTICATED_AUTHORITY,
                "debt_code": (
                    "UNMAPPED_REPORT_FINDING"
                    if candidate_id
                    in {
                        row["promoted_candidate_id"] for row in report_unmapped
                    }
                    else "UNAUTHENTICATED_REPORT_DISPOSITION"
                ),
            }
            for candidate_id in candidate_ids
        ],
        "report_evidence_quality_receipt_ref": C.UNAUTHENTICATED_AUTHORITY,
        "report_integrity_state": "DEGRADED",
    }
    raw_outputs = _raw_output_index(
        run_id, inventory, inline_limit=inline_limit
    )

    all_record_ids = {
        record.record_id
        for artifact in inventory.artifacts
        for record in artifact.records
    }
    occurrence_record_ids = {
        item["record_id"] for item in lineage["occurrences"]
    }
    partitions = (
        occurrence_record_ids,
        set(nonfinding),
        set(debt_records),
    )
    if (
        any(
            left & right
            for index, left in enumerate(partitions)
            for right in partitions[index + 1 :]
        )
        or set().union(*partitions) != all_record_ids
    ):
        raise RunBundleHarvestError("harvest record denominator is not conserved")
    source_receipt: dict[str, Any] = {
        "schema_version": HARVEST_DRAFT_RECEIPT_SCHEMA,
        "registry_sha256": inventory.registry_sha256,
        "input_snapshot_sha256": inventory.input_snapshot_sha256,
        "artifact_ids": sorted(
            (row.artifact_id for row in inventory.artifacts),
            key=lambda item: item.encode("utf-8"),
        ),
        "record_ids": sorted(all_record_ids, key=lambda item: item.encode("utf-8")),
        "candidate_ids": candidate_ids,
        "occurrence_ids": [
            item["occurrence_id"] for item in lineage["occurrences"]
        ],
        "nonfinding_record_ids": sorted(
            nonfinding, key=lambda item: item.encode("utf-8")
        ),
        "debt_record_ids": sorted(
            debt_records, key=lambda item: item.encode("utf-8")
        ),
        "parse_states": [
            {
                "artifact_id": row.artifact_id,
                "parser_id": row.parser_id,
                "parser_version": row.parser_version,
                "parse_state": row.outcome,
                "debt_codes": list(row.debt_codes),
            }
            for row in inventory.artifacts
        ],
    }
    source_receipt = C.bind_embedded_sha256(
        source_receipt, "receipt_sha256"
    )
    P.validate_public_payload(source_receipt)
    return HarvestDraft(
        run_id=run_id,
        candidate_set=candidate_set,
        lineage=lineage,
        report_projection=report_projection,
        raw_output_index=raw_outputs,
        source_receipt=source_receipt,
        nonfinding_record_ids=tuple(sorted(nonfinding)),
        debt_record_ids=tuple(sorted(debt_records)),
        record_debt_ids=record_debt_ids,
        inventory=inventory,
    )


def local_materialization_policy_preimage() -> dict[str, Any]:
    return {
        "schema_version": LOCAL_MATERIALIZATION_POLICY_SCHEMA,
        "version": LOCAL_MATERIALIZATION_POLICY_VERSION,
        "trust_profiles": ["B0_LOCAL", "USER_RUN"],
        "authority_sentinel": C.UNAUTHENTICATED_AUTHORITY,
        "publication_ceilings": {
            "B0_LOCAL": "B0_LOCAL",
            "USER_RUN": "USER_RUN",
        },
        "b1_eligible": False,
        "alias_policy": "EXACT_APPLIED_AUTHORITY_ONLY",
        "report_mapping_policy": "UNAUTHENTICATED_REPORT_SECTIONS_ARE_UNMAPPED",
    }


def local_materialization_policy_sha256() -> str:
    return C.document_sha256(local_materialization_policy_preimage())


__all__ = [
    "HARVEST_DRAFT_RECEIPT_SCHEMA",
    "HarvestDraft",
    "LOCAL_MATERIALIZATION_POLICY_SCHEMA",
    "LOCAL_MATERIALIZATION_POLICY_VERSION",
    "RunBundleHarvestError",
    "build_harvest_draft",
    "local_materialization_policy_preimage",
    "local_materialization_policy_sha256",
]
