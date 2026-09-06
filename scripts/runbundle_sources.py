"""GT-blind source registry and stable inventory for real-audit RunBundle v2.

This module inventories only the explicit scratchpad and final report selected
by the caller.  It never opens a ground-truth, prior-report, grader, corpus, or
private-lock path.  Matching is against a frozen exact/anchored registry; an
unknown file is preserved as opaque CONTROL evidence rather than guessed into
a favorable lifecycle phase.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
from typing import Any, Iterable

try:
    import runbundle_contracts as C
    import runbundle_phase_map as M
    import runbundle_privacy as P
except ImportError:  # pragma: no cover - package-style fallback
    from . import runbundle_contracts as C
    from . import runbundle_phase_map as M
    from . import runbundle_privacy as P


SOURCE_REGISTRY_SCHEMA = "plamen.runbundle-source-registry.v1"
SOURCE_INVENTORY_SCHEMA = "plamen.runbundle-source-inventory.v1"
SOURCE_REGISTRY_VERSION = "2026.07.29"
MAX_SOURCE_FILES = 100_000
MAX_SOURCE_BYTES = 8 << 30


class RunBundleSourceError(ValueError):
    """The explicit audit evidence inputs could not be inventoried safely."""


@dataclass(frozen=True, slots=True)
class SourceAdapter:
    adapter_id: str
    pattern: str
    pattern_kind: str
    parser_id: str
    parser_version: str
    source_contract_ref: str
    native_phase_sc: str
    native_phase_l1: str
    macro_phase_sc: str
    macro_phase_l1: str
    producer_kind: str
    expected_schema_versions: tuple[str, ...] = ()

    def phase(self, pipeline_kind: str) -> tuple[str, str]:
        if pipeline_kind == "SC":
            return self.native_phase_sc, self.macro_phase_sc
        if pipeline_kind == "L1":
            return self.native_phase_l1, self.macro_phase_l1
        raise RunBundleSourceError(f"unknown pipeline kind {pipeline_kind!r}")


@dataclass(frozen=True, slots=True)
class SourceRecord:
    record_id: str
    byte_start: int
    byte_end: int
    record_sha256: str
    record_kind: str
    native_candidate_id: str | None
    title: str | None
    debt_codes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SourceArtifact:
    artifact_id: str
    relative_source_path: str
    native_phase: str
    macro_phase: str
    work_unit_id: str
    producer_kind: str
    media_type: str
    byte_length: int
    sha256: str
    source_contract_ref: str
    commit_state: str
    parser_id: str
    parser_version: str
    outcome: str
    debt_codes: tuple[str, ...]
    records: tuple[SourceRecord, ...]
    raw: bytes


@dataclass(frozen=True, slots=True)
class SourceInventory:
    schema_version: str
    pipeline_kind: str
    registry_sha256: str
    artifacts: tuple[SourceArtifact, ...]
    before_sha256: str
    after_sha256: str
    stable: bool
    scratchpad_snapshot: P.StableRegularTreeSnapshot
    report_snapshot: P.StableRegularFileSnapshot

    @property
    def input_snapshot_sha256(self) -> str:
        return self.before_sha256

    @property
    def live_source_authority_sha256(self) -> str:
        """Bind content, exact roster, and physical identity without paths."""

        scratch_files = {
            relative: raw
            for relative, raw in self.scratchpad_snapshot.files
        }
        return C.document_sha256(
            {
                "schema_version": (
                    "plamen.runbundle-live-source-authority.v1"
                ),
                "pipeline_kind": self.pipeline_kind,
                "input_snapshot_sha256": self.input_snapshot_sha256,
                "scratchpad": {
                    "tree_sha256": self.scratchpad_snapshot.tree_sha256,
                    "directories": list(
                        self.scratchpad_snapshot.directories
                    ),
                    "files": [
                        {
                            "relative_path": relative,
                            "byte_length": len(scratch_files[relative]),
                            "sha256": C.sha256_bytes(
                                scratch_files[relative]
                            ),
                            "physical_state": list(state),
                        }
                        for relative, state in (
                            self.scratchpad_snapshot.file_states
                        )
                    ],
                    "directory_states": [
                        {
                            "relative_path": relative,
                            "physical_state": list(state),
                            "members": list(members),
                        }
                        for relative, state, members in (
                            self.scratchpad_snapshot.directory_states
                        )
                    ],
                },
                "report": {
                    "byte_length": len(self.report_snapshot.raw),
                    "sha256": self.report_snapshot.sha256,
                    "physical_state": list(self.report_snapshot.state),
                },
            }
        )


def _adapter(
    adapter_id: str,
    pattern: str,
    *,
    pattern_kind: str = "EXACT",
    parser_id: str,
    source_contract_ref: str,
    sc: tuple[str, str],
    l1: tuple[str, str],
    producer_kind: str = "PLAMEN_OUTPUT",
    expected: Iterable[str] = (),
) -> SourceAdapter:
    return SourceAdapter(
        adapter_id=adapter_id,
        pattern=pattern,
        pattern_kind=pattern_kind,
        parser_id=parser_id,
        parser_version="1",
        source_contract_ref=source_contract_ref,
        native_phase_sc=sc[0],
        native_phase_l1=l1[0],
        macro_phase_sc=sc[1],
        macro_phase_l1=l1[1],
        producer_kind=producer_kind,
        expected_schema_versions=tuple(expected),
    )


# Order is part of the protocol: exact bindings precede anchored pattern rows.
_REGISTRY: tuple[SourceAdapter, ...] = (
    _adapter(
        "final-report",
        "AUDIT_REPORT.md",
        parser_id="plamen-final-report",
        source_contract_ref=C.REPORT_PROJECTION_SCHEMA,
        sc=("report_assemble", "report"),
        l1=("report_assemble", "report"),
        producer_kind="FINAL_REPORT",
    ),
    _adapter(
        "inventory-reconciliation",
        ".scratchpad/inventory_reconciliation.json",
        parser_id="typed-json-authority",
        source_contract_ref="plamen.inventory-reconciliation",
        sc=("inventory", "inventory"),
        l1=("inventory", "inventory"),
        expected=(
            "plamen.inventory-reconciliation.v1",
            "plamen.inventory-reconciliation.v2",
        ),
    ),
    _adapter(
        "inventory-disposition",
        ".scratchpad/inventory_disposition_authority.json",
        parser_id="typed-json-authority",
        source_contract_ref="plamen.inventory-disposition-authority",
        sc=("inventory", "inventory"),
        l1=("inventory", "inventory"),
        expected=("plamen.inventory-disposition-authority.v1",),
    ),
    _adapter(
        "inventory-reemit",
        ".scratchpad/inventory_reemit_receipt.json",
        parser_id="typed-json-authority",
        source_contract_ref="plamen.inventory-reemit-receipt",
        sc=("inventory", "inventory"),
        l1=("inventory", "inventory"),
        expected=("plamen.inventory-reemit-receipt.v1",),
    ),
    _adapter(
        "semantic-alias",
        ".scratchpad/semantic_dedup_applied_receipt.json",
        parser_id="typed-json-authority",
        source_contract_ref="plamen.semantic-dedup-applied-receipt",
        sc=("sc_semantic_dedup", "inventory"),
        l1=("semantic_dedup", "inventory"),
        expected=("plamen.semantic-dedup-applied-receipt.v1",),
    ),
    _adapter(
        "semantic-alias-supplemental",
        ".scratchpad/semantic_dedup_supplemental_applied_receipt.json",
        parser_id="typed-json-authority",
        source_contract_ref="plamen.semantic-dedup-supplemental-applied-receipt",
        sc=("sc_semantic_dedup", "inventory"),
        l1=("semantic_dedup", "inventory"),
        expected=("plamen.semantic-dedup-supplemental-applied-receipt.v1",),
    ),
    _adapter(
        "report-alias",
        ".scratchpad/report_dedup_applied_alias_receipt.json",
        parser_id="typed-json-authority",
        source_contract_ref="plamen.report-dedup-applied-alias-receipt",
        sc=("report_dedup", "report"),
        l1=("report_dedup", "report"),
        expected=("plamen.report-dedup-applied-alias-receipt.v1",),
    ),
    _adapter(
        "report-disposition",
        ".scratchpad/report_disposition_authority.json",
        parser_id="typed-json-authority",
        source_contract_ref="plamen.report-disposition-authority",
        sc=("report_disposition", "report"),
        l1=("report_disposition", "report"),
        expected=("plamen.report-disposition-authority.v1",),
    ),
    _adapter(
        "security-obligations",
        ".scratchpad/security_obligation_lifecycle.json",
        parser_id="typed-json-authority",
        source_contract_ref="plamen.security-obligation-lifecycle",
        sc=("post_verify_extract", "verify"),
        l1=("post_verify_extract", "verify"),
        expected=("plamen.security-obligation-lifecycle.v1",),
    ),
    _adapter(
        "artifact-ledger",
        ".scratchpad/_artifact_state.json",
        parser_id="typed-json-control",
        source_contract_ref="plamen.artifact-state",
        sc=("instantiate", "CONTROL"),
        l1=("bake", "CONTROL"),
        producer_kind="PLAMEN_PLANNING_CONTROL",
    ),
    _adapter(
        "checkpoint",
        ".scratchpad/checkpoint.json",
        parser_id="typed-json-control",
        source_contract_ref="plamen.checkpoint",
        sc=("instantiate", "CONTROL"),
        l1=("bake", "CONTROL"),
        producer_kind="PLAMEN_PLANNING_CONTROL",
    ),
    _adapter(
        "breadth-markdown",
        r"^\.scratchpad/(?:breadth_findings|breadth_[a-z0-9_.-]+)\.md$",
        pattern_kind="REGEX",
        parser_id="plamen-markdown-findings",
        source_contract_ref="finding-output-format.v1",
        sc=("breadth", "breadth"),
        l1=("breadth", "breadth"),
    ),
    _adapter(
        "depth-markdown",
        r"^\.scratchpad/(?:depth_findings|depth_[a-z0-9_.-]+|"
        r"attention_repair_[a-z0-9_.-]+|enumgap_[a-z0-9_.-]+)\.md$",
        pattern_kind="REGEX",
        parser_id="plamen-markdown-findings",
        source_contract_ref="finding-output-format.v1",
        sc=("depth", "depth"),
        l1=("depth", "depth"),
    ),
    _adapter(
        "verify-markdown",
        r"^\.scratchpad/verify_[A-Za-z0-9_.-]+\.md$",
        pattern_kind="REGEX",
        parser_id="plamen-markdown-findings",
        source_contract_ref="verification-output.v1",
        sc=("sc_verify_aggregate", "verify"),
        l1=("verify_aggregate", "verify"),
    ),
    _adapter(
        "report-index-markdown",
        r"^\.scratchpad/(?:report_index|report_disposition|report_floor)\.md$",
        pattern_kind="REGEX",
        parser_id="plamen-markdown-findings",
        source_contract_ref="report-intermediate.v1",
        sc=("report_index", "report"),
        l1=("report_index", "report"),
    ),
)


_OPAQUE = _adapter(
    "opaque-preserve",
    "*",
    parser_id="opaque-preserve",
    source_contract_ref="opaque-unclassified.v1",
    sc=("instantiate", "CONTROL"),
    l1=("bake", "CONTROL"),
    producer_kind="PLAMEN_PLANNING_CONTROL",
)


def source_registry_preimage() -> dict[str, Any]:
    return {
        "schema_version": SOURCE_REGISTRY_SCHEMA,
        "version": SOURCE_REGISTRY_VERSION,
        "entries": [
            {
                "adapter_id": row.adapter_id,
                "pattern": row.pattern,
                "pattern_kind": row.pattern_kind,
                "parser_id": row.parser_id,
                "parser_version": row.parser_version,
                "source_contract_ref": row.source_contract_ref,
                "sc": {
                    "native_phase": row.native_phase_sc,
                    "macro_phase": row.macro_phase_sc,
                },
                "l1": {
                    "native_phase": row.native_phase_l1,
                    "macro_phase": row.macro_phase_l1,
                },
                "producer_kind": row.producer_kind,
                "expected_schema_versions": list(row.expected_schema_versions),
            }
            for row in _REGISTRY
        ],
        "fallback": {
            "adapter_id": _OPAQUE.adapter_id,
            "parser_id": _OPAQUE.parser_id,
            "phase": "CONTROL",
        },
    }


def source_registry_sha256() -> str:
    return C.sha256_bytes(C.canonical_json_bytes(source_registry_preimage()))


def resolve_source_adapter(
    relative_source_path: str,
    *,
    pipeline_kind: str,
) -> SourceAdapter:
    try:
        safe = P.assert_safe_relative_path(
            relative_source_path, label="source registry path"
        )
        M.pinned_phase_map(pipeline_kind)
    except (P.RunBundlePrivacyError, M.RunBundlePhaseMapError) as exc:
        raise RunBundleSourceError(str(exc)) from exc
    for row in _REGISTRY:
        if row.pattern_kind == "EXACT" and safe == row.pattern:
            return row
        if row.pattern_kind == "REGEX" and re.fullmatch(row.pattern, safe):
            return row
    return _OPAQUE


_ATX_HEADING_RE = re.compile(br"(?m)^(#{1,6})[ \t]+([^\r\n]+)(?:\r?\n|$)")
_FINDING_TITLE_RE = re.compile(
    r"^\s*(?:\[(?P<bracket>[A-Za-z]{1,12}-?\d+)\]|"
    r"(?P<plain>(?:C|H|M|L|I|INV|GRP|HC|HH|HM|HL)-\d+))"
    r"\s*(?:[-:]\s*)?(?P<title>.*)$",
    re.IGNORECASE,
)


def _record_id(artifact_id: str, start: int, end: int, raw: bytes) -> str:
    digest = hashlib.sha256(
        b"plamen.runbundle.record.v1\0"
        + artifact_id.encode("ascii")
        + start.to_bytes(8, "big")
        + end.to_bytes(8, "big")
        + raw[start:end]
    ).hexdigest()
    return f"record-{digest[:28]}"


def _partition_markdown(artifact_id: str, raw: bytes) -> tuple[SourceRecord, ...]:
    matches = list(_ATX_HEADING_RE.finditer(raw))
    boundaries = [0]
    boundaries.extend(match.start() for match in matches if match.start() != 0)
    boundaries.append(len(raw))
    boundaries = sorted(set(boundaries))
    records: list[SourceRecord] = []
    heading_at = {match.start(): match for match in matches}
    for start, end in zip(boundaries, boundaries[1:]):
        if end <= start:
            continue
        match = heading_at.get(start)
        native_id: str | None = None
        title: str | None = None
        kind = "NONFINDING"
        debts: tuple[str, ...] = ()
        if match is not None:
            heading = match.group(2).decode("utf-8", errors="replace")
            finding = _FINDING_TITLE_RE.fullmatch(heading)
            if finding is not None:
                native_id = (
                    finding.group("bracket") or finding.group("plain") or ""
                ).upper()
                title = (finding.group("title") or native_id).strip()
                kind = "CANDIDATE"
                if "\ufffd" in heading:
                    debts = ("INVALID_UTF8_REPLACED_IN_HEADING",)
        record_id = _record_id(artifact_id, start, end, raw)
        records.append(
            SourceRecord(
                record_id=record_id,
                byte_start=start,
                byte_end=end,
                record_sha256=C.sha256_bytes(raw[start:end]),
                record_kind=kind,
                native_candidate_id=native_id,
                title=title,
                debt_codes=debts,
            )
        )
    if not records and raw:
        records.append(
            SourceRecord(
                record_id=_record_id(artifact_id, 0, len(raw), raw),
                byte_start=0,
                byte_end=len(raw),
                record_sha256=C.sha256_bytes(raw),
                record_kind="NONFINDING",
                native_candidate_id=None,
                title=None,
                debt_codes=(),
            )
        )
    return tuple(records)


def _partition_json(
    adapter: SourceAdapter,
    artifact_id: str,
    raw: bytes,
) -> tuple[tuple[SourceRecord, ...], str, tuple[str, ...]]:
    debts: list[str] = []
    outcome = "EXACT"
    try:
        value = C.strict_json_loads(raw, require_canonical=False)
    except C.RunBundleContractError:
        value = None
        debts.append("INVALID_JSON_PRESERVED")
        outcome = "PARSED_WITH_DEBT"
    if isinstance(value, dict) and adapter.expected_schema_versions:
        schema = value.get("schema_version")
        if schema not in adapter.expected_schema_versions:
            debts.append("UNKNOWN_SCHEMA_VERSION")
            outcome = "PARSED_WITH_DEBT"
    record = SourceRecord(
        record_id=_record_id(artifact_id, 0, len(raw), raw),
        byte_start=0,
        byte_end=len(raw),
        record_sha256=C.sha256_bytes(raw),
        record_kind="DEBT" if debts else "NONFINDING",
        native_candidate_id=None,
        title=None,
        debt_codes=tuple(sorted(set(debts))),
    )
    return (record,), outcome, tuple(sorted(set(debts)))


def _media_type(path: str) -> str:
    suffix = PurePosixPath(path).suffix.casefold()
    return {
        ".json": "application/json",
        ".jsonl": "application/jsonl",
        ".md": "text/markdown",
        ".txt": "text/plain",
        ".log": "text/plain",
        ".out": "text/plain",
    }.get(suffix, "application/octet-stream")


def _artifact_from_bytes(
    relative_source_path: str,
    raw: bytes,
    *,
    pipeline_kind: str,
) -> SourceArtifact:
    adapter = resolve_source_adapter(
        relative_source_path, pipeline_kind=pipeline_kind
    )
    native_phase, macro_phase = adapter.phase(pipeline_kind)
    digest = C.sha256_bytes(raw)
    artifact_id = "artifact-" + hashlib.sha256(
        b"plamen.runbundle.artifact.v1\0"
        + relative_source_path.encode("utf-8")
        + bytes.fromhex(digest)
    ).hexdigest()[:28]
    work_unit_id = "work-export-" + hashlib.sha256(
        f"{native_phase}\0{relative_source_path}".encode("utf-8")
    ).hexdigest()[:20]
    media_type = _media_type(relative_source_path)
    outcome = "EXACT"
    debts: tuple[str, ...] = ()
    if adapter.parser_id in {"plamen-markdown-findings", "plamen-final-report"}:
        records = _partition_markdown(artifact_id, raw)
    elif adapter.parser_id.startswith("typed-json"):
        records, outcome, debts = _partition_json(adapter, artifact_id, raw)
    else:
        records = (
            SourceRecord(
                record_id=_record_id(artifact_id, 0, len(raw), raw),
                byte_start=0,
                byte_end=len(raw),
                record_sha256=C.sha256_bytes(raw),
                record_kind="NONFINDING",
                native_candidate_id=None,
                title=None,
                debt_codes=(),
            ),
        ) if raw else ()
        if adapter is _OPAQUE:
            debts = ("UNCLASSIFIED_SOURCE_ARTIFACT",)
            outcome = "PARSED_WITH_DEBT"
    return SourceArtifact(
        artifact_id=artifact_id,
        relative_source_path=relative_source_path,
        native_phase=native_phase,
        macro_phase=macro_phase,
        work_unit_id=work_unit_id,
        producer_kind=adapter.producer_kind,
        media_type=media_type,
        byte_length=len(raw),
        sha256=digest,
        source_contract_ref=adapter.source_contract_ref,
        commit_state="DEGRADED" if debts else "CLEAN",
        parser_id=adapter.parser_id,
        parser_version=adapter.parser_version,
        outcome=outcome,
        debt_codes=debts,
        records=records,
        raw=raw,
    )


def _snapshot_preimage(artifacts: Iterable[SourceArtifact]) -> dict[str, Any]:
    return {
        "schema_version": SOURCE_INVENTORY_SCHEMA,
        "registry_sha256": source_registry_sha256(),
        "artifacts": [
            {
                "relative_source_path": row.relative_source_path,
                "byte_length": row.byte_length,
                "sha256": row.sha256,
            }
            for row in sorted(
                artifacts, key=lambda item: item.relative_source_path.encode("utf-8")
            )
        ],
    }


def inventory_run_sources(
    *,
    project_root: Path,
    scratchpad: Path,
    report: Path,
    pipeline_kind: str,
) -> SourceInventory:
    """Capture one stable, explicit scratchpad+report evidence generation."""

    root = Path(project_root).resolve()
    scratch = Path(scratchpad).resolve()
    final_report = Path(report).resolve()
    if not root.is_dir() or scratch.parent != root or final_report.parent != root:
        raise RunBundleSourceError(
            "project, scratchpad, and report must use the exact project-root topology"
        )
    if scratch.name != ".scratchpad" or final_report.name != "AUDIT_REPORT.md":
        raise RunBundleSourceError(
            "real-audit export requires .scratchpad and AUDIT_REPORT.md"
        )
    try:
        M.pinned_phase_map(pipeline_kind)
    except M.RunBundlePhaseMapError as exc:
        raise RunBundleSourceError(str(exc)) from exc

    try:
        before_tree = P.read_stable_regular_tree_snapshot(
            scratch,
            maximum_files=MAX_SOURCE_FILES,
            maximum_total_bytes=MAX_SOURCE_BYTES,
        )
        before_report = P.read_stable_regular_file_snapshot(
            final_report,
            maximum_bytes=MAX_SOURCE_BYTES,
            label="audit export input AUDIT_REPORT.md",
        )
    except P.RunBundlePrivacyError as exc:
        raise RunBundleSourceError(str(exc)) from exc
    before_rows: list[SourceArtifact] = []
    for relative_in_scratch, raw in before_tree.files:
        relative = f".scratchpad/{relative_in_scratch}"
        before_rows.append(
            _artifact_from_bytes(relative, raw, pipeline_kind=pipeline_kind)
        )
    before_rows.append(
        _artifact_from_bytes(
            "AUDIT_REPORT.md",
            before_report.raw,
            pipeline_kind=pipeline_kind,
        )
    )
    before = C.document_sha256(_snapshot_preimage(before_rows))

    # A second complete enumeration detects membership, identity, or byte drift,
    # including mutations whose timestamps are restored.
    try:
        after_tree = P.read_stable_regular_tree_snapshot(
            scratch,
            maximum_files=MAX_SOURCE_FILES,
            maximum_total_bytes=MAX_SOURCE_BYTES,
        )
        after_report = P.read_stable_regular_file_snapshot(
            final_report,
            maximum_bytes=MAX_SOURCE_BYTES,
            label="audit export recheck AUDIT_REPORT.md",
        )
    except P.RunBundlePrivacyError as exc:
        raise RunBundleSourceError("MUTATED_DURING_EXPORT") from exc
    after_rows: list[SourceArtifact] = []
    for relative_in_scratch, raw in after_tree.files:
        relative = f".scratchpad/{relative_in_scratch}"
        after_rows.append(
            _artifact_from_bytes(relative, raw, pipeline_kind=pipeline_kind)
        )
    after_rows.append(
        _artifact_from_bytes(
            "AUDIT_REPORT.md",
            after_report.raw,
            pipeline_kind=pipeline_kind,
        )
    )
    after = C.document_sha256(_snapshot_preimage(after_rows))
    if (
        before != after
        or before_tree != after_tree
        or before_report != after_report
    ):
        raise RunBundleSourceError("MUTATED_DURING_EXPORT")

    ids = [row.artifact_id for row in before_rows]
    if len(ids) != len(set(ids)):
        raise RunBundleSourceError("source artifact identity collision")
    paths_posix = [row.relative_source_path for row in before_rows]
    try:
        P.assert_no_casefold_collisions(paths_posix)
    except P.RunBundlePrivacyError as exc:
        raise RunBundleSourceError(str(exc)) from exc
    return SourceInventory(
        schema_version=SOURCE_INVENTORY_SCHEMA,
        pipeline_kind=pipeline_kind,
        registry_sha256=source_registry_sha256(),
        artifacts=tuple(
            sorted(
                before_rows,
                key=lambda item: item.relative_source_path.encode("utf-8"),
            )
        ),
        before_sha256=before,
        after_sha256=after,
        stable=True,
        scratchpad_snapshot=before_tree,
        report_snapshot=before_report,
    )


def verify_live_source_closure(
    *,
    project_root: Path,
    scratchpad: Path,
    report: Path,
    inventory: SourceInventory,
) -> str:
    """Re-enumerate and rehash the exact live source generation before publish."""

    if not isinstance(inventory, SourceInventory) or not inventory.stable:
        raise RunBundleSourceError("source closure authority is invalid")
    root = Path(project_root).resolve()
    scratch = Path(scratchpad).resolve()
    final_report = Path(report).resolve()
    if (
        not root.is_dir()
        or scratch.parent != root
        or final_report.parent != root
        or scratch.name != ".scratchpad"
        or final_report.name != "AUDIT_REPORT.md"
    ):
        raise RunBundleSourceError("MUTATED_DURING_EXPORT")
    try:
        P.assert_stable_regular_tree_snapshot_unchanged(
            scratch,
            inventory.scratchpad_snapshot,
            maximum_files=MAX_SOURCE_FILES,
            maximum_total_bytes=MAX_SOURCE_BYTES,
        )
        P.assert_stable_regular_file_snapshot_unchanged(
            final_report,
            inventory.report_snapshot,
            maximum_bytes=MAX_SOURCE_BYTES,
            label="audit export final report",
        )
    except P.RunBundlePrivacyError as exc:
        raise RunBundleSourceError("MUTATED_DURING_EXPORT") from exc
    return inventory.live_source_authority_sha256


__all__ = [
    "MAX_SOURCE_BYTES",
    "MAX_SOURCE_FILES",
    "RunBundleSourceError",
    "SOURCE_INVENTORY_SCHEMA",
    "SOURCE_REGISTRY_SCHEMA",
    "SOURCE_REGISTRY_VERSION",
    "SourceAdapter",
    "SourceArtifact",
    "SourceInventory",
    "SourceRecord",
    "inventory_run_sources",
    "resolve_source_adapter",
    "source_registry_preimage",
    "source_registry_sha256",
    "verify_live_source_closure",
]
