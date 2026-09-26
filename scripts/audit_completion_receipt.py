"""Atomic driver-terminal receipt publication for strict SC Thorough acceptance.

This module has no orchestration side effects.  The driver calls
``publish_audit_completion_receipt`` only after its report/checkpoint gates and
immediately before returning the already-computed exit status.  Expected
identities must have been captured before the audit; terminal state may not
assert a new identity for itself.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping


LEGACY_DRIVER_TERMINAL_SCHEMA = "plamen.driver_terminal_receipt.v1"
DRIVER_TERMINAL_SCHEMA = "plamen.driver_terminal_receipt.v2"
TERMINAL_CLOSURE_SCHEMA = "plamen.terminal_semantic_closure.v1"
RECEIPT_NAME = "_driver_terminal_receipt.json"
SC_THOROUGH_PHASES = (
    "recon", "instantiate", "breadth", "rescan_prepare", "rescan",
    "inventory_prepare", "inventory_chunk_a", "inventory_chunk_b",
    "inventory_chunk_c", "inventory", "invariants", "invariants_p2",
    "depth", "attention_repair", "exploration_skeptic",
    "enumgap_exploration", "axis_coverage", "application_skeptic",
    "sc_semantic_dedup", "rag_sweep", "chain", "chain_agent2",
    "chain_iter2", "sc_verify_queue", "sc_verify_crithigh",
    "sc_verify_high_b", "sc_verify_high_c", "sc_verify_high_d",
    "sc_verify_high_e", "sc_verify_high_f", "sc_verify_high_g",
    "sc_verify_high_h", "sc_verify_high_i", "sc_verify_high_j",
    "sc_verify_medium_a", "sc_verify_medium_b", "sc_verify_medium_c",
    "sc_verify_medium_d", "sc_verify_medium_e", "sc_verify_medium_f",
    "sc_verify_medium_g", "sc_verify_medium_h", "sc_verify_medium_i",
    "sc_verify_medium_j", "sc_verify_low_a", "sc_verify_low_b",
    "sc_verify_low_c", "sc_verify_low_d", "sc_verify_low_e",
    "sc_verify_low_f", "sc_verify_low_g", "sc_verify_low_h",
    "sc_verify_low_i", "sc_verify_low_j", "sc_verify_aggregate",
    "sc_mechanical_verify", "post_verify_extract", "skeptic", "crossbatch",
    "severity_adjudication_shadow", "report_index",
    "report_body_writer_critical_high", "report_body_writer_medium",
    "report_body_writer_low_info", "report_critical_high",
    "report_critical_high_merge", "report_medium", "report_medium_merge",
    "report_low_info", "report_low_info_merge", "report_assemble",
    "report_dedup_agent", "report_dedup", "report_disposition",
    "report_floor",
)
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_UUID4 = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_MAX_JSON = 32 * 1024 * 1024
_CODEX_INSTALL_RECEIPT_NAME = ".plamen-codex-install.json"
_CODEX_INSTALL_ANCHOR_NAME = ".plamen-install.admission.lock"
_CODEX_INSTALL_ANCHOR_BYTES = {
    b"plamen-install-admission-v1\n",
    b"plamen-install-admission-v1\r\n",
}


class CompletionReceiptError(RuntimeError):
    """Terminal evidence is incomplete, drifted, or already published."""


@dataclass(frozen=True)
class ExpectedCompletionIdentity:
    run_id: str
    installed_package_root: Path
    installed_package_receipt: str
    installed_package_receipt_sha256: str
    installed_generation_receipt: str
    installed_generation_receipt_sha256: str
    installed_package_generation_sha256: str
    plamen_source_root: Path
    plamen_source_commit: str
    target_repository_root: Path
    target_commit: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ExpectedCompletionIdentity":
        exact = {
            "run_id", "installed_package_root", "installed_package_receipt",
            "installed_package_receipt_sha256", "installed_generation_receipt",
            "installed_generation_receipt_sha256", "installed_package_generation_sha256",
            "plamen_source_root", "plamen_source_commit", "target_repository_root",
            "target_commit",
        }
        if set(value) != exact:
            raise CompletionReceiptError("completion identity keys are not exact")
        identity = cls(
            run_id=str(value["run_id"]),
            installed_package_root=Path(str(value["installed_package_root"])),
            installed_package_receipt=str(value["installed_package_receipt"]),
            installed_package_receipt_sha256=str(value["installed_package_receipt_sha256"]),
            installed_generation_receipt=str(value["installed_generation_receipt"]),
            installed_generation_receipt_sha256=str(value["installed_generation_receipt_sha256"]),
            installed_package_generation_sha256=str(value["installed_package_generation_sha256"]),
            plamen_source_root=Path(str(value["plamen_source_root"])),
            plamen_source_commit=str(value["plamen_source_commit"]),
            target_repository_root=Path(str(value["target_repository_root"])),
            target_commit=str(value["target_commit"]),
        )
        identity.validate()
        return identity

    def validate(self) -> None:
        if not _UUID4.fullmatch(self.run_id):
            raise CompletionReceiptError("completion run_id is not canonical UUID4")
        if not _HEX64.fullmatch(self.installed_package_receipt_sha256):
            raise CompletionReceiptError("installed receipt digest is not canonical")
        if not _HEX64.fullmatch(self.installed_generation_receipt_sha256):
            raise CompletionReceiptError("installed generation receipt digest is not canonical")
        if not _HEX64.fullmatch(self.installed_package_generation_sha256):
            raise CompletionReceiptError("installed generation digest is not canonical")
        if not _COMMIT.fullmatch(self.plamen_source_commit):
            raise CompletionReceiptError("Plamen source commit is not canonical")
        if not _COMMIT.fullmatch(self.target_commit):
            raise CompletionReceiptError("target commit is not canonical")
        for label, raw in (
            ("installed receipt", self.installed_package_receipt),
            ("installed generation receipt", self.installed_generation_receipt),
        ):
            path = Path(raw)
            if not path.is_absolute() or ".." in path.parts:
                raise CompletionReceiptError(f"{label} path is not canonical absolute")


@dataclass(frozen=True)
class PublishedCompletionReceipt:
    path: Path
    receipt_sha256: str
    payload: Mapping[str, Any]


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def phase_names_sha256(phases: list[str] | tuple[str, ...] | None = None) -> str:
    """Digest an ordered realized plan (the unexpanded plan by default)."""

    selected = SC_THOROUGH_PHASES if phases is None else phases
    return _sha(_canonical(list(selected)))


def validate_realized_phase_plan(value: Any) -> tuple[str, ...]:
    """Validate one deterministic SC Thorough plan, including report shards.

    Report sharding replaces a tier's writer and confirmation sentinels with
    matching ``_a`` .. ``_z`` phase families.  Collapsing those families must
    reproduce the canonical base plan exactly; arbitrary phase insertion,
    deletion, reordering, sparse suffixes, or writer/confirmation drift is
    rejected.
    """

    if not isinstance(value, (list, tuple)) or not value:
        raise CompletionReceiptError("realized phase plan is absent")
    phases = tuple(value)
    if any(
        type(name) is not str
        or not name
        or not re.fullmatch(r"[a-z0-9_]+", name)
        for name in phases
    ):
        raise CompletionReceiptError("realized phase plan contains an invalid phase")
    if len(phases) != len(set(phases)):
        raise CompletionReceiptError("realized phase plan contains duplicate phases")

    collapsed: list[str] = []
    shards: dict[str, dict[str, list[str]]] = {
        tier: {"writer": [], "confirm": []}
        for tier in ("critical_high", "medium", "low_info")
    }
    for name in phases:
        matched = False
        for tier in shards:
            writer = re.fullmatch(
                rf"report_body_writer_{re.escape(tier)}_([a-z])", name
            )
            confirm = re.fullmatch(rf"report_{re.escape(tier)}_([a-z])", name)
            if writer:
                shards[tier]["writer"].append(writer.group(1))
                if not collapsed or collapsed[-1] != f"report_body_writer_{tier}":
                    collapsed.append(f"report_body_writer_{tier}")
                matched = True
                break
            if confirm:
                shards[tier]["confirm"].append(confirm.group(1))
                if not collapsed or collapsed[-1] != f"report_{tier}":
                    collapsed.append(f"report_{tier}")
                matched = True
                break
        if not matched:
            collapsed.append(name)

    if tuple(collapsed) != SC_THOROUGH_PHASES:
        raise CompletionReceiptError(
            "realized phase plan does not collapse to the SC Thorough base plan"
        )
    for tier, families in shards.items():
        writer = families["writer"]
        confirm = families["confirm"]
        if bool(writer) != bool(confirm):
            raise CompletionReceiptError(
                f"realized phase plan has partial report shard family: {tier}"
            )
        if writer:
            expected = [chr(ord("a") + index) for index in range(len(writer))]
            if writer != expected or confirm != expected:
                raise CompletionReceiptError(
                    f"realized phase plan has non-deterministic report shards: {tier}"
                )
            if (
                f"report_body_writer_{tier}" in phases
                or f"report_{tier}" in phases
            ):
                raise CompletionReceiptError(
                    f"realized phase plan mixes report sentinel and shards: {tier}"
                )
    return phases


def realized_phase_plan_from_checkpoint(
    checkpoint: Mapping[str, Any],
) -> tuple[str, ...]:
    config = checkpoint.get("config")
    active = config.get("_active_phase_names") if isinstance(config, Mapping) else None
    phases = validate_realized_phase_plan(active)
    if checkpoint.get("completed") != list(phases):
        raise CompletionReceiptError(
            "checkpoint has not completed the exact realized phase plan"
        )
    commits = checkpoint.get("phase_commits")
    if not isinstance(commits, Mapping) or set(commits) != set(phases):
        raise CompletionReceiptError("checkpoint phase commit keyset is incomplete")
    return phases


_TERMINAL_CLOSURE_FIELDS = frozenset({
    "schema_version", "run_id",
    "candidate_count", "candidate_ids_sha256", "candidate_universe_sha256",
    "candidate_record_set_digest", "candidate_authority_sha256",
    "candidate_source_count", "candidate_sources_sha256",
    "provenance_id_count", "provenance_ids_sha256", "candidate_provenance_sha256",
    "verifier_disposition_count", "verifier_disposition_ids_sha256",
    "verifier_dispositions_sha256",
    "report_evidence_bundle_sha256", "report_evidence_bundle_digest",
    "report_id_count", "report_ids_sha256", "reported_candidate_id_count",
    "reported_candidate_ids_sha256", "evidence_source_count",
    "evidence_sources_sha256", "report_quality_receipt_sha256",
    "report_quality_receipt_digest", "report_quality_state",
    "report_structurally_delivered", "report_semantically_complete",
    "report_disposition_authority_sha256", "report_disposition_receipt_sha256",
    "report_disposition_candidate_count", "report_disposition_candidate_ids_sha256",
    "artifact_ledger_sha256", "artifact_ledger_digest",
    "artifact_ledger_work_unit_count", "artifact_ledger_current_run_work_unit_count",
    "artifact_ledger_binding_count", "artifact_ledger_terminal_states_sha256",
    "closure_digest",
})


def build_terminal_closure_projection(
    *, run_id: str, candidate_rows: list[Mapping[str, Any]],
    candidate_authority: Mapping[str, Any],
    provenance_ids: list[str] | tuple[str, ...] | set[str],
    verifier_dispositions: list[Mapping[str, Any]],
    report_bundle: Mapping[str, Any], report_bundle_sha256: str,
    report_quality: Mapping[str, Any], report_quality_sha256: str,
    report_disposition: Mapping[str, Any], report_disposition_sha256: str,
    artifact_ledger_sha256: str, artifact_ledger_digest: str,
    artifact_ledger_work_units: Mapping[str, Mapping[str, Any]],
    artifact_ledger_binding_count: int,
) -> dict[str, Any]:
    """Pure, deterministic builder for the strict terminal closure record."""

    if not _UUID4.fullmatch(run_id):
        raise CompletionReceiptError("terminal closure run_id is not canonical UUID4")
    if not isinstance(candidate_authority, Mapping):
        raise CompletionReceiptError("terminal candidate authority is malformed")
    candidate_sources = candidate_authority.get("source_bindings")
    if (
        set(candidate_authority) != {
            "base_queue_binding", "delta_binding", "union_record_count",
            "union_record_set_digest", "source_bindings",
        }
        or type(candidate_authority.get("union_record_count")) is not int
        or candidate_authority["union_record_count"] < 0
        or not isinstance(candidate_authority.get("union_record_set_digest"), str)
        or not _HEX64.fullmatch(candidate_authority["union_record_set_digest"])
        or not isinstance(candidate_sources, list)
        or any(
            not isinstance(row, Mapping)
            or set(row) != {"artifact", "sha256"}
            or not isinstance(row.get("artifact"), str)
            or not row["artifact"]
            or not isinstance(row.get("sha256"), str)
            or not _HEX64.fullmatch(row["sha256"])
            for row in candidate_sources
        )
    ):
        raise CompletionReceiptError("terminal candidate authority is malformed")
    candidate_sources = sorted(
        (dict(row) for row in candidate_sources), key=lambda row: row["artifact"]
    )
    if len(candidate_sources) != len({row["artifact"] for row in candidate_sources}):
        raise CompletionReceiptError("terminal candidate source denominator is not unique")
    candidate_authority = dict(candidate_authority)
    candidate_authority["source_bindings"] = candidate_sources
    if any(not isinstance(row, Mapping) for row in candidate_rows):
        raise CompletionReceiptError("terminal candidate rows are malformed")
    if any(not isinstance(row, Mapping) for row in verifier_dispositions):
        raise CompletionReceiptError("terminal verifier disposition rows are malformed")
    candidate_rows = sorted(
        (dict(row) for row in candidate_rows),
        key=lambda row: str(row.get("candidate_id") or ""),
    )
    verifier_dispositions = sorted(
        (dict(row) for row in verifier_dispositions),
        key=lambda row: str(row.get("candidate_id") or ""),
    )
    candidate_ids = [str(row.get("candidate_id") or "") for row in candidate_rows]
    disposition_ids = [
        str(row.get("candidate_id") or "") for row in verifier_dispositions
    ]
    if (
        any(not value for value in candidate_ids)
        or len(candidate_ids) != len(set(candidate_ids))
        or candidate_authority["union_record_count"] != len(candidate_ids)
        or disposition_ids != candidate_ids
    ):
        raise CompletionReceiptError(
            "verifier dispositions do not exactly close the candidate denominator"
        )
    provenance = sorted(set(provenance_ids))
    if any(type(value) is not str or not value for value in provenance):
        raise CompletionReceiptError("terminal provenance identities are malformed")
    if not set(candidate_ids).issubset(set(provenance)):
        raise CompletionReceiptError(
            "terminal candidate identities are absent from provenance closure"
        )
    if (
        not isinstance(report_bundle, Mapping)
        or not isinstance(report_quality, Mapping)
        or not isinstance(report_disposition, Mapping)
    ):
        raise CompletionReceiptError("terminal report evidence authorities are malformed")
    if not all(
        _HEX64.fullmatch(value)
        for value in (
            report_bundle_sha256, report_quality_sha256,
            report_disposition_sha256,
            artifact_ledger_sha256, artifact_ledger_digest,
            str(report_bundle.get("bundle_digest") or ""),
            str(report_quality.get("receipt_digest") or ""),
            str(report_disposition.get("receipt_sha256") or ""),
        )
    ):
        raise CompletionReceiptError("terminal closure contains a malformed authority digest")
    if (
        report_quality.get("delivery_state") != "SEMANTICALLY_COMPLETE"
        or report_quality.get("structurally_delivered") is not True
        or report_quality.get("semantically_complete") is not True
        or report_quality.get("missing_semantic_fields") != {}
        or report_quality.get("evidence_limitations") != {}
        or report_quality.get("hidden_quality_debt_report_ids") != []
        or report_quality.get("unauthorized_proof_grade_report_ids") != []
    ):
        raise CompletionReceiptError(
            "terminal report evidence is not semantically complete"
        )
    report_ids = sorted(str(value) for value in report_bundle.get("expected_report_ids", []))
    records = report_bundle.get("records")
    if not isinstance(records, list):
        raise CompletionReceiptError("terminal report evidence records are malformed")
    reported_candidate_ids = sorted({
        str(candidate_id)
        for record in records if isinstance(record, Mapping)
        for candidate_id in (record.get("candidate_ids") or [])
    })
    actual_report_ids = sorted(
        str(record.get("report_id") or "")
        for record in records if isinstance(record, Mapping)
    )
    if (
        not isinstance(report_bundle.get("expected_report_ids"), list)
        or actual_report_ids != report_ids
        or len(report_ids) != len(set(report_ids))
        or sorted(report_quality.get("expected_report_ids") or []) != report_ids
        or sorted(report_quality.get("delivered_report_ids") or []) != report_ids
        or not set(reported_candidate_ids).issubset(set(provenance))
    ):
        raise CompletionReceiptError(
            "report evidence does not exactly match its IDs or candidate provenance"
        )
    evidence_sources = sorted(
        (
            str(record.get("report_id") or ""),
            str(source.get("artifact") or ""),
            str(source.get("sha256") or ""),
        )
        for record in records if isinstance(record, Mapping)
        for source in (record.get("evidence_sources") or [])
        if isinstance(source, Mapping)
    )
    if any(not all(row) or not _HEX64.fullmatch(row[2]) for row in evidence_sources):
        raise CompletionReceiptError("terminal report evidence source binding is malformed")
    disposition_rows = report_disposition.get("rows")
    if not isinstance(disposition_rows, list):
        raise CompletionReceiptError("terminal report disposition rows are malformed")
    report_disposition_ids = sorted(
        str(row.get("candidate_id") or "")
        for row in disposition_rows if isinstance(row, Mapping)
    )
    if (
        report_disposition_ids != candidate_ids
        or len(disposition_rows) != len(report_disposition_ids)
        or any(
            not isinstance(row, Mapping)
            or row.get("identity_accounted") is not True
            or row.get("visible_debt") is not False
            for row in disposition_rows
        )
    ):
        raise CompletionReceiptError(
            "report disposition authority does not exactly close all candidates"
        )

    terminal_states: list[dict[str, str]] = []
    current_run_count = 0
    for key, raw in sorted(artifact_ledger_work_units.items()):
        if not isinstance(raw, Mapping):
            raise CompletionReceiptError("artifact ledger work unit is malformed")
        row = {
            "work_unit_key": str(key),
            "run_id": str(raw.get("run_id") or ""),
            "semantic_status": str(raw.get("semantic_status") or ""),
            "execution_state": str(raw.get("execution_state") or ""),
            "contract_digest": str(raw.get("contract_digest") or ""),
            "launch_digest": str(raw.get("launch_digest") or ""),
        }
        terminal_states.append(row)
        if row["run_id"] == run_id:
            current_run_count += 1
            if (row["semantic_status"], row["execution_state"]) not in {
                ("ACTIVE", "OUTPUT_COMMITTED"),
                ("SUPERSEDED", "OUTPUT_SUPERSEDED"),
            }:
                raise CompletionReceiptError(
                    f"artifact ledger retains nonterminal work unit: {key}"
                )
    if current_run_count == 0:
        raise CompletionReceiptError("artifact ledger has no work units for the terminal run")
    if type(artifact_ledger_binding_count) is not int or artifact_ledger_binding_count < 0:
        raise CompletionReceiptError("artifact ledger binding count is malformed")

    unsigned = {
        "schema_version": TERMINAL_CLOSURE_SCHEMA,
        "run_id": run_id,
        "candidate_count": len(candidate_ids),
        "candidate_ids_sha256": _sha(_canonical(candidate_ids)),
        "candidate_universe_sha256": _sha(_canonical(candidate_rows)),
        "candidate_record_set_digest": str(
            candidate_authority["union_record_set_digest"]
        ),
        "candidate_authority_sha256": _sha(_canonical(candidate_authority)),
        "candidate_source_count": len(candidate_sources),
        "candidate_sources_sha256": _sha(_canonical(candidate_sources)),
        "provenance_id_count": len(provenance),
        "provenance_ids_sha256": _sha(_canonical(provenance)),
        "candidate_provenance_sha256": _sha(_canonical({
            "rows": candidate_rows, "provenance_ids": provenance,
        })),
        "verifier_disposition_count": len(verifier_dispositions),
        "verifier_disposition_ids_sha256": _sha(_canonical(disposition_ids)),
        "verifier_dispositions_sha256": _sha(_canonical(verifier_dispositions)),
        "report_evidence_bundle_sha256": report_bundle_sha256,
        "report_evidence_bundle_digest": str(report_bundle["bundle_digest"]),
        "report_id_count": len(report_ids),
        "report_ids_sha256": _sha(_canonical(report_ids)),
        "reported_candidate_id_count": len(reported_candidate_ids),
        "reported_candidate_ids_sha256": _sha(_canonical(reported_candidate_ids)),
        "evidence_source_count": len(evidence_sources),
        "evidence_sources_sha256": _sha(_canonical(evidence_sources)),
        "report_quality_receipt_sha256": report_quality_sha256,
        "report_quality_receipt_digest": str(report_quality["receipt_digest"]),
        "report_quality_state": str(report_quality["delivery_state"]),
        "report_structurally_delivered": True,
        "report_semantically_complete": True,
        "report_disposition_authority_sha256": report_disposition_sha256,
        "report_disposition_receipt_sha256": str(
            report_disposition["receipt_sha256"]
        ),
        "report_disposition_candidate_count": len(report_disposition_ids),
        "report_disposition_candidate_ids_sha256": _sha(
            _canonical(report_disposition_ids)
        ),
        "artifact_ledger_sha256": artifact_ledger_sha256,
        "artifact_ledger_digest": artifact_ledger_digest,
        "artifact_ledger_work_unit_count": len(artifact_ledger_work_units),
        "artifact_ledger_current_run_work_unit_count": current_run_count,
        "artifact_ledger_binding_count": artifact_ledger_binding_count,
        "artifact_ledger_terminal_states_sha256": _sha(_canonical(terminal_states)),
        "closure_digest": "",
    }
    unsigned["closure_digest"] = _sha(_canonical(unsigned))
    return unsigned


def validate_terminal_closure(value: Mapping[str, Any]) -> dict[str, Any]:
    """Pure strict-schema and self-digest validation for a closure record."""

    if not isinstance(value, Mapping) or set(value) != _TERMINAL_CLOSURE_FIELDS:
        raise CompletionReceiptError("terminal closure schema keys are not exact")
    if value.get("schema_version") != TERMINAL_CLOSURE_SCHEMA:
        raise CompletionReceiptError("terminal closure schema version is invalid")
    if not isinstance(value.get("run_id"), str) or not _UUID4.fullmatch(value["run_id"]):
        raise CompletionReceiptError("terminal closure run_id is invalid")
    for field in _TERMINAL_CLOSURE_FIELDS:
        if field.endswith("_sha256") or field.endswith("_digest"):
            if not isinstance(value.get(field), str) or not _HEX64.fullmatch(value[field]):
                raise CompletionReceiptError(f"terminal closure digest is malformed: {field}")
    for field in (
        "candidate_count", "provenance_id_count", "verifier_disposition_count",
        "candidate_source_count",
        "report_id_count", "reported_candidate_id_count", "evidence_source_count",
        "report_disposition_candidate_count",
        "artifact_ledger_work_unit_count",
        "artifact_ledger_current_run_work_unit_count", "artifact_ledger_binding_count",
    ):
        if type(value.get(field)) is not int or value[field] < 0:
            raise CompletionReceiptError(f"terminal closure count is malformed: {field}")
    if value["candidate_count"] != value["verifier_disposition_count"]:
        raise CompletionReceiptError("terminal candidate/verifier counts differ")
    if value["candidate_ids_sha256"] != value["verifier_disposition_ids_sha256"]:
        raise CompletionReceiptError("terminal candidate/verifier identity sets differ")
    if (
        value["candidate_count"] != value["report_disposition_candidate_count"]
        or value["candidate_ids_sha256"]
        != value["report_disposition_candidate_ids_sha256"]
    ):
        raise CompletionReceiptError("terminal report dispositions omit candidates")
    if (
        value.get("report_quality_state") != "SEMANTICALLY_COMPLETE"
        or value.get("report_structurally_delivered") is not True
        or value.get("report_semantically_complete") is not True
        or value["artifact_ledger_current_run_work_unit_count"] == 0
    ):
        raise CompletionReceiptError("terminal semantic closure is incomplete")
    unsigned = dict(value)
    claimed = unsigned["closure_digest"]
    unsigned["closure_digest"] = ""
    if _sha(_canonical(unsigned)) != claimed:
        raise CompletionReceiptError("terminal closure self-digest is invalid")
    return dict(value)


def recompute_terminal_closure(
    *, scratchpad: Path, project_root: Path, checkpoint: Mapping[str, Any],
) -> dict[str, Any]:
    """Independently replay canonical V3 terminal authorities without writes."""

    root = Path(scratchpad)
    run_id = str(checkpoint.get("run_id") or "")
    try:
        from artifact_ledger import (
            active_committed_work_unit_authority_issues,
            artifact_ledger_digest,
            read_artifact_ledger,
            stored_committed_work_unit_authority_issues,
        )
        from post_verify_candidate_delta import (
            load_current_report_candidate_universe_authority,
            load_post_verify_late_delivery_statuses,
        )
        from report_evidence_authority import (
            finalize_report_evidence_delivery,
            validate_report_evidence_runtime,
        )
        from report_disposition_authority import (
            AUTHORITY_NAME as REPORT_DISPOSITION_AUTHORITY_NAME,
            validate_report_disposition_authority,
        )
        from plamen_parsers import _verifier_status_from_text
        from plamen_validators import _verifier_completion_authority_issues

        universe = load_current_report_candidate_universe_authority(
            root, run_id=run_id, project_root=Path(project_root)
        )
        if universe.run_id and universe.run_id != run_id:
            raise CompletionReceiptError("candidate universe run identity differs")
        if universe.source_debts:
            raise CompletionReceiptError("candidate universe retains source debt")
        candidate_rows: list[dict[str, Any]] = []
        provenance_ids: set[str] = set()
        for bound in universe.candidates:
            item = bound.item
            lineage_ids = sorted(link.identity for link in item.lineage)
            provenance_ids.update(
                [item.work_item_id, item.candidate_identity, *item.aliases,
                 *item.constituents, *lineage_ids]
            )
            candidate_rows.append({
                "candidate_id": item.work_item_id,
                "candidate_identity": item.candidate_identity,
                "work_item_digest": item.digest,
                "aliases": list(item.aliases),
                "constituents": list(item.constituents),
                "lineage_ids": lineage_ids,
                "source_kind": bound.source_kind,
                "source_artifact": bound.source_artifact,
                "source_artifact_sha256": bound.source_artifact_sha256,
                "source_record_ordinal": bound.source_record_ordinal,
                "source_record_digest": bound.source_record_digest,
                "authority_artifact": bound.authority_artifact,
                "authority_artifact_sha256": bound.authority_artifact_sha256,
                "authority_record_digest": bound.authority_record_digest,
                "claim_digest": bound.claim_digest,
            })
        candidate_rows.sort(key=lambda row: row["candidate_id"])
        candidate_source_bindings = [
            {
                "artifact": relative,
                "sha256": _sha(_read_regular(root / relative, 64 * 1024 * 1024)),
            }
            for relative in universe.input_artifacts
        ]
        candidate_authority = {
            "base_queue_binding": dict(universe.base_queue_binding),
            "delta_binding": (
                dict(universe.delta_binding)
                if isinstance(universe.delta_binding, Mapping) else None
            ),
            "union_record_count": universe.union_record_count,
            "union_record_set_digest": universe.union_record_set_digest,
            "source_bindings": candidate_source_bindings,
        }

        late = load_post_verify_late_delivery_statuses(root, run_id=run_id) if any(
            row["source_kind"] != "BASE_VERIFICATION_QUEUE" for row in candidate_rows
        ) else {}
        dispositions: list[dict[str, Any]] = []
        for bound in sorted(universe.candidates, key=lambda row: row.item.work_item_id):
            fid = bound.item.work_item_id
            if bound.source_kind == "BASE_VERIFICATION_QUEUE":
                issues = _verifier_completion_authority_issues(root, fid)
                if issues:
                    raise CompletionReceiptError(
                        f"verifier completion authority is incomplete for {fid}: {issues[0]}"
                    )
                output = root / bound.item.expected_output_file
                output_raw = _read_regular(output, 64 * 1024 * 1024)
                status = _verifier_status_from_text(
                    output_raw.decode("utf-8", errors="replace")
                )
                if not status:
                    raise CompletionReceiptError(f"verifier disposition is absent for {fid}")
                authority_files = [
                    output,
                    root / f"verify_{fid}.identity.json",
                    root / f"verify_{fid}.receipt.json",
                    root / f"verify_{fid}.severity_proposal.json",
                ]
                successor = root / f"verify_{fid}.mechanical_successor.receipt.json"
                if successor.is_file():
                    authority_files.append(successor)
                authority_bindings = [
                    {"artifact": path.name, "sha256": _sha(_read_regular(path, 64 * 1024 * 1024))}
                    for path in authority_files
                ]
                row = {
                    "candidate_id": fid,
                    "source_kind": bound.source_kind,
                    "source_record_digest": bound.source_record_digest,
                    "disposition": status,
                    "verify_artifact": output.name,
                    "verify_sha256": _sha(output_raw),
                    "completion_authority_sha256": _sha(_canonical(authority_bindings)),
                }
            else:
                delivery = late.get(fid)
                if delivery is None or delivery.delivery_state != "INDEPENDENT_VERIFICATION_RECORDED":
                    raise CompletionReceiptError(
                        f"late verifier disposition is not independently complete: {fid}"
                    )
                if not delivery.verifier_status or not delivery.verify_artifact or not delivery.verify_sha256:
                    raise CompletionReceiptError(f"late verifier disposition is incomplete: {fid}")
                row = {
                    "candidate_id": fid,
                    "source_kind": bound.source_kind,
                    "source_record_digest": bound.source_record_digest,
                    "disposition": delivery.verifier_status,
                    "verify_artifact": delivery.verify_artifact,
                    "verify_sha256": delivery.verify_sha256,
                    "completion_authority_sha256": delivery.delivery_artifact_sha256,
                }
            dispositions.append(row)

        runtime = validate_report_evidence_runtime(root)
        bundle = runtime["bundle"]
        bundle_raw = _read_regular(root / "report_evidence_records.json")
        quality = finalize_report_evidence_delivery(
            root, report_path=Path(project_root) / "AUDIT_REPORT.md", compare_only=True,
            project_root=Path(project_root), run_id=run_id,
        )
        quality_raw = _read_regular(root / "report_evidence_quality_receipt.json")
        report_disposition = validate_report_disposition_authority(
            root, Path(project_root), run_id=run_id
        )
        report_disposition_raw = _read_regular(
            root / REPORT_DISPOSITION_AUTHORITY_NAME
        )
        ledger_raw = _read_regular(root / "_artifact_state.json", 256 * 1024 * 1024)
        ledger = read_artifact_ledger(root)
        for key, unit in sorted(ledger.get("work_units", {}).items()):
            if not isinstance(unit, Mapping) or unit.get("run_id") != run_id:
                continue
            if unit.get("semantic_status") == "ACTIVE":
                ledger_issues = active_committed_work_unit_authority_issues(
                    ledger, work_unit_key=key, run_id=run_id
                )
            elif unit.get("semantic_status") == "SUPERSEDED":
                ledger_issues = stored_committed_work_unit_authority_issues(
                    ledger, work_unit_key=key, run_id=run_id
                )
            else:
                ledger_issues = [f"{key}: nonterminal semantic status"]
            if ledger_issues:
                raise CompletionReceiptError(
                    "artifact ledger terminal authority is invalid: "
                    + ledger_issues[0]
                )
        closure = build_terminal_closure_projection(
            run_id=run_id,
            candidate_rows=candidate_rows,
            candidate_authority=candidate_authority,
            provenance_ids=provenance_ids,
            verifier_dispositions=dispositions,
            report_bundle=bundle,
            report_bundle_sha256=_sha(bundle_raw),
            report_quality=quality,
            report_quality_sha256=_sha(quality_raw),
            report_disposition=report_disposition,
            report_disposition_sha256=_sha(report_disposition_raw),
            artifact_ledger_sha256=_sha(ledger_raw),
            artifact_ledger_digest=artifact_ledger_digest(ledger),
            artifact_ledger_work_units=ledger.get("work_units", {}),
            artifact_ledger_binding_count=len(ledger.get("artifact_bindings", {})),
        )
        return validate_terminal_closure(closure)
    except CompletionReceiptError:
        raise
    except Exception as exc:
        raise CompletionReceiptError(
            f"terminal semantic closure replay failed: {type(exc).__name__}: {exc}"
        ) from exc


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CompletionReceiptError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_regular(path: Path, limit: int = _MAX_JSON) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise CompletionReceiptError(f"required file unavailable: {path.name}") from exc
    if path.is_symlink() or not stat.S_ISREG(before.st_mode) or before.st_size > limit:
        raise CompletionReceiptError(f"required file is not an admitted regular file: {path.name}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise CompletionReceiptError(f"required file cannot be opened: {path.name}") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise CompletionReceiptError(f"required file identity drifted: {path.name}")
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, limit + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > limit:
                raise CompletionReceiptError(f"required file exceeds limit: {path.name}")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        size != opened.st_size
        or (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    ):
        raise CompletionReceiptError(f"required file changed during read: {path.name}")
    return b"".join(chunks)


def _read_json(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = _read_regular(path)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CompletionReceiptError(f"malformed JSON: {path.name}") from exc
    if not isinstance(value, dict):
        raise CompletionReceiptError(f"JSON root is not an object: {path.name}")
    return value, raw


def _is_windows_host() -> bool:
    """Keep host dispatch explicit and independently replaceable in tests."""
    return os.name == "nt"


def _open_windows_admission_anchor(
    path: Path,
) -> tuple[bytes, tuple[int, int], Callable[[], None]]:
    """Retain the exact Windows install reader lease and return its identity.

    The committed installer records the Win32 volume serial number and file
    index, not Python's portable ``st_dev``/``st_ino`` projection.  Query the
    same handle identity here so completion cannot substitute a same-content
    lock file or race the package installer while its receipt is captured.
    """
    if not _is_windows_host():
        raise CompletionReceiptError("Windows admission authority used on another host")
    import ctypes
    from ctypes import wintypes

    class _FileInformation(ctypes.Structure):
        _fields_ = [
            ("attributes", wintypes.DWORD),
            ("created", wintypes.FILETIME),
            ("accessed", wintypes.FILETIME),
            ("written", wintypes.FILETIME),
            ("volume", wintypes.DWORD),
            ("size_high", wintypes.DWORD),
            ("size_low", wintypes.DWORD),
            ("links", wintypes.DWORD),
            ("index_high", wintypes.DWORD),
            ("index_low", wintypes.DWORD),
        ]

    class _AttributeTag(ctypes.Structure):
        _fields_ = [("attributes", wintypes.DWORD), ("tag", wintypes.DWORD)]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
        wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.GetFileInformationByHandle.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(_FileInformation),
    ]
    kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
    kernel32.GetFileInformationByHandleEx.argtypes = [
        wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD,
    ]
    kernel32.GetFileInformationByHandleEx.restype = wintypes.BOOL
    kernel32.GetFinalPathNameByHandleW.argtypes = [
        wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD,
    ]
    kernel32.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    kernel32.SetFilePointerEx.argtypes = [
        wintypes.HANDLE, ctypes.c_longlong,
        ctypes.POINTER(ctypes.c_longlong), wintypes.DWORD,
    ]
    kernel32.SetFilePointerEx.restype = wintypes.BOOL
    kernel32.ReadFile.argtypes = [
        wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID,
    ]
    kernel32.ReadFile.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    # GENERIC_READ; FILE_SHARE_READ only; OPEN_EXISTING; ordinary file plus
    # OPEN_REPARSE_POINT/OPEN_NO_RECALL.  Excluding write/delete sharing is the
    # same reader lease used by the installed front and driver admission.
    handle = kernel32.CreateFileW(
        str(path), 0x80000000, 0x00000001, None, 3,
        0x00000080 | 0x00200000 | 0x02000000, None,
    )
    invalid = ctypes.c_void_p(-1).value
    if handle == invalid:
        code = ctypes.get_last_error()
        raise CompletionReceiptError(
            f"Windows install admission anchor unavailable (error {code})"
        )
    handle = int(handle)
    closed = False

    def close() -> None:
        nonlocal closed
        if not closed:
            closed = True
            kernel32.CloseHandle(handle)

    try:
        information = _FileInformation()
        tag = _AttributeTag()
        if not kernel32.GetFileInformationByHandle(handle, ctypes.byref(information)):
            raise OSError(ctypes.get_last_error(), "anchor identity unavailable")
        if not kernel32.GetFileInformationByHandleEx(
            handle, 9, ctypes.byref(tag), ctypes.sizeof(tag)
        ):
            raise OSError(ctypes.get_last_error(), "anchor tag unavailable")
        size = (int(information.size_high) << 32) | int(information.size_low)
        file_id = (int(information.index_high) << 32) | int(information.index_low)
        if (
            int(information.attributes) != int(tag.attributes)
            or int(tag.tag) != 0
            or int(information.attributes) & (0x10 | 0x400)
            or int(information.links) != 1
            or int(information.volume) <= 0
            or file_id <= 0
            or size > 4096
        ):
            raise CompletionReceiptError(
                "Windows install admission anchor is not an ordinary single-link file"
            )
        needed = kernel32.GetFinalPathNameByHandleW(handle, None, 0, 0)
        if not needed:
            raise OSError(ctypes.get_last_error(), "anchor final path unavailable")
        buffer = ctypes.create_unicode_buffer(needed + 1)
        observed = kernel32.GetFinalPathNameByHandleW(handle, buffer, len(buffer), 0)
        final_name = buffer.value.rstrip("\\/").rsplit("\\", 1)[-1]
        if not observed or final_name.casefold() != _CODEX_INSTALL_ANCHOR_NAME.casefold():
            raise CompletionReceiptError("Windows install admission anchor name differs")
        position = ctypes.c_longlong()
        if not kernel32.SetFilePointerEx(handle, 0, ctypes.byref(position), 0):
            raise OSError(ctypes.get_last_error(), "anchor seek failed")
        raw_buffer = ctypes.create_string_buffer(size)
        read = wintypes.DWORD()
        if size and not kernel32.ReadFile(
            handle, raw_buffer, size, ctypes.byref(read), None
        ):
            raise OSError(ctypes.get_last_error(), "anchor read failed")
        raw = raw_buffer.raw[:read.value]
        if read.value != size or raw not in _CODEX_INSTALL_ANCHOR_BYTES:
            raise CompletionReceiptError("Windows install admission anchor bytes differ")
        return raw, (int(information.volume), file_id), close
    except CompletionReceiptError:
        close()
        raise
    except (OSError, RuntimeError) as exc:
        close()
        raise CompletionReceiptError(
            "Windows install admission anchor could not be authenticated"
        ) from exc


def _git_head(root: Path) -> str:
    proc = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--verify", "HEAD"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, timeout=10, check=False,
    )
    value = proc.stdout.strip().lower()
    if proc.returncode != 0 or not _COMMIT.fullmatch(value):
        raise CompletionReceiptError(f"Git identity unavailable: {root}")
    return value


def _git_tracked_clean(root: Path, scope: Path | None = None) -> bool:
    relative = "." if scope is None else scope.resolve().relative_to(root.resolve()).as_posix()
    for cached in (False, True):
        command = ["git", "-C", str(root), "diff", "--quiet"]
        if cached:
            command.append("--cached")
        command.extend(["HEAD", "--", relative])
        result = subprocess.run(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=10, check=False,
        )
        if result.returncode != 0:
            return False
    return True


def _installed_authority(
    *, installed_root: Path, package_receipt_path: Path,
    generation_receipt_path: Path,
) -> tuple[str, str, str]:
    if (
        not package_receipt_path.is_absolute()
        or not generation_receipt_path.is_absolute()
    ):
        raise CompletionReceiptError("installed authority paths are not absolute")
    windows_anchor = (
        _is_windows_host()
        and generation_receipt_path.name.casefold()
        == _CODEX_INSTALL_ANCHOR_NAME.casefold()
    )
    anchor_identity: tuple[int, int] | None = None
    close_anchor: Callable[[], None] | None = None
    if windows_anchor:
        generation_raw, anchor_identity, close_anchor = (
            _open_windows_admission_anchor(generation_receipt_path)
        )
    else:
        generation_raw = _read_regular(generation_receipt_path)
    try:
        package, package_raw = _read_json(package_receipt_path)
        schema = package.get("schema")
        package_digest = _sha(package_raw)
        generation_receipt_digest = _sha(generation_raw)
        result = _validate_installed_authority_payload(
            installed_root=installed_root,
            package_receipt_path=package_receipt_path,
            generation_receipt_path=generation_receipt_path,
            package=package,
            package_digest=package_digest,
            generation_raw=generation_raw,
            generation_receipt_digest=generation_receipt_digest,
            windows_anchor=windows_anchor,
            anchor_identity=anchor_identity,
        )
        if windows_anchor:
            # Keep the no-write/no-delete reader lease until the package bytes
            # have been replayed and then prove the named receipt stayed exact.
            _package_after, package_after_raw = _read_json(package_receipt_path)
            if package_after_raw != package_raw:
                raise CompletionReceiptError(
                    "Windows installed package receipt changed during admission"
                )
        return result
    finally:
        if close_anchor is not None:
            close_anchor()


def _validate_installed_authority_payload(
    *, installed_root: Path, package_receipt_path: Path,
    generation_receipt_path: Path, package: Mapping[str, Any],
    package_digest: str, generation_raw: bytes,
    generation_receipt_digest: str, windows_anchor: bool,
    anchor_identity: tuple[int, int] | None,
) -> tuple[str, str, str]:
    """Replay one already-read package under its platform authority."""
    schema = package.get("schema")
    if schema == "plamen.posix_compat_v2.install.v2":
        if windows_anchor:
            raise CompletionReceiptError("compat package cannot use Windows admission authority")
        if generation_receipt_path != package_receipt_path:
            raise CompletionReceiptError("compat generation authority must be its provenance receipt")
        generation = package.get("generation_sha256")
    elif schema == "plamen.codex_install.v2":
        rows = package.get("rows")
        source_count = package.get("source_count")
        manifest = package.get("source_manifest_sha256")
        if (
            package.get("state") != "COMMITTED"
            or not re.fullmatch(r"[0-9a-f]{32}", str(package.get("transaction_id") or ""))
            or type(source_count) is not int
            or source_count <= 0
            or not isinstance(rows, list)
            or source_count != len(rows)
            or not _HEX64.fullmatch(str(manifest or ""))
        ):
            raise CompletionReceiptError("native package receipt is not committed authority")
        manifest_rows: list[tuple[str, bytes]] = []
        seen_sources: set[str] = set()
        for row in rows:
            source_path = row.get("source_path") if isinstance(row, dict) else None
            size = row.get("size") if isinstance(row, dict) else None
            digest = row.get("sha256") if isinstance(row, dict) else None
            if (
                not isinstance(source_path, str) or not source_path
                or source_path in seen_sources
                or type(size) is not int or size < 0
                or not isinstance(digest, str) or not _HEX64.fullmatch(digest)
            ):
                raise CompletionReceiptError("native package receipt rows are malformed")
            seen_sources.add(source_path)
            manifest_rows.append((
                source_path, f"{source_path}|{size}|{digest}\n".encode()
            ))
        manifest_payload = b"".join(raw for _source, raw in sorted(manifest_rows))
        if _sha(manifest_payload) != manifest:
            raise CompletionReceiptError("native package source manifest does not replay")
        try:
            bound_root = Path(str(package.get("plamen_root"))).resolve(strict=True)
        except (OSError, ValueError) as exc:
            raise CompletionReceiptError("native package receipt root is invalid") from exc
        if bound_root != installed_root:
            raise CompletionReceiptError("native package receipt binds another installed root")
        if windows_anchor:
            try:
                codex_root = Path(str(package.get("codex_root"))).resolve(strict=True)
            except (OSError, ValueError) as exc:
                raise CompletionReceiptError("Windows package Codex root is invalid") from exc
            if (
                package_receipt_path.parent != codex_root
                or package_receipt_path.name.casefold()
                != _CODEX_INSTALL_RECEIPT_NAME.casefold()
                or generation_receipt_path.parent != codex_root
                or generation_receipt_path.name.casefold()
                != _CODEX_INSTALL_ANCHOR_NAME.casefold()
            ):
                raise CompletionReceiptError(
                    "Windows package receipt and admission anchor are not exact Codex authorities"
                )
            lock_identity = package.get("lock_identity")
            if (
                anchor_identity is None
                or not isinstance(lock_identity, list)
                or len(lock_identity) != 2
                or any(type(value) is not int or value <= 0 for value in lock_identity)
                or lock_identity != list(anchor_identity)
            ):
                raise CompletionReceiptError(
                    "Windows admission anchor identity differs from committed receipt"
                )
            if generation_raw not in _CODEX_INSTALL_ANCHOR_BYTES:
                raise CompletionReceiptError("Windows install admission anchor bytes differ")
            # Windows has no POSIX native-image receipt.  The committed source
            # manifest is its package generation identity; the separate anchor
            # digest/identity proves the receipt was replayed under the exact
            # retained install authority.
            generation = manifest
        else:
            if _is_windows_host():
                raise CompletionReceiptError(
                    "Windows native package requires its install admission anchor"
                )
            if len(generation_raw) != 16384 or generation_raw[:8] != b"PLMINS2\x00":
                raise CompletionReceiptError("native generation receipt framing is invalid")
            generation = generation_raw[16:48].hex()
    else:
        raise CompletionReceiptError("unsupported installed package receipt schema")
    if not isinstance(generation, str) or not _HEX64.fullmatch(generation):
        raise CompletionReceiptError("installed generation authority is invalid")
    return package_digest, generation_receipt_digest, generation


def validate_installed_authority(
    *, installed_root: Path, package_receipt_path: Path,
    generation_receipt_path: Path,
) -> tuple[str, str, str]:
    """Public shared verifier for the platform-specific install authority."""
    return _installed_authority(
        installed_root=installed_root,
        package_receipt_path=package_receipt_path,
        generation_receipt_path=generation_receipt_path,
    )


def capture_start_completion_identity(
    *, run_id: str, installed_package_root: Path,
    installed_package_receipt: Path, installed_generation_receipt: Path | None,
    plamen_source_root: Path, target_repository_root: Path, project_root: Path,
) -> dict[str, str]:
    """Capture exact immutable identities before any audit worker is launched."""
    if not isinstance(run_id, str) or not _UUID4.fullmatch(run_id):
        raise CompletionReceiptError("completion run_id is not canonical UUID4")
    installed_root = Path(installed_package_root).resolve(strict=True)
    package_path = Path(installed_package_receipt).resolve(strict=True)
    generation_path = (
        Path(installed_generation_receipt).resolve(strict=True)
        if installed_generation_receipt is not None else package_path
    )
    source_root = Path(plamen_source_root).resolve(strict=True)
    target_root = Path(target_repository_root).resolve(strict=True)
    project = Path(project_root).resolve(strict=True)
    project.relative_to(target_root)
    package_digest, generation_receipt_digest, generation = _installed_authority(
        installed_root=installed_root,
        package_receipt_path=package_path,
        generation_receipt_path=generation_path,
    )
    source_commit = _git_head(source_root)
    target_commit = _git_head(target_root)
    if not _git_tracked_clean(source_root):
        raise CompletionReceiptError("Plamen source is not frozen at capture")
    if not _git_tracked_clean(target_root, project):
        raise CompletionReceiptError("target source is not frozen at capture")
    mapping = {
        "run_id": run_id,
        "installed_package_root": str(installed_root),
        "installed_package_receipt": str(package_path),
        "installed_package_receipt_sha256": package_digest,
        "installed_generation_receipt": str(generation_path),
        "installed_generation_receipt_sha256": generation_receipt_digest,
        "installed_package_generation_sha256": generation,
        "plamen_source_root": str(source_root),
        "plamen_source_commit": source_commit,
        "target_repository_root": str(target_root),
        "target_commit": target_commit,
    }
    ExpectedCompletionIdentity.from_mapping(mapping)
    return mapping


def completion_identity_run_id(
    config: Mapping[str, Any], checkpoint_run_id: str | None,
) -> str | None:
    """Return the exact prebound terminal run or reject resume drift."""
    if config.get("pipeline") != "sc" or config.get("mode") != "thorough":
        return None
    raw = config.get("_audit_completion_identity")
    if not isinstance(raw, Mapping):
        raise CompletionReceiptError("start-bound _audit_completion_identity is absent")
    run_id = ExpectedCompletionIdentity.from_mapping(raw).run_id
    if checkpoint_run_id is not None and checkpoint_run_id != run_id:
        raise CompletionReceiptError("checkpoint run_id differs from start identity")
    return run_id


def _validate_final_checkpoint(
    checkpoint: Mapping[str, Any], identity: ExpectedCompletionIdentity,
) -> tuple[str, tuple[str, ...]]:
    if checkpoint.get("run_id") != identity.run_id:
        raise CompletionReceiptError("checkpoint run_id differs from start identity")
    config = checkpoint.get("config")
    if not isinstance(config, dict):
        raise CompletionReceiptError("checkpoint config is absent")
    phases = realized_phase_plan_from_checkpoint(checkpoint)
    if checkpoint.get("degraded") != [] or checkpoint.get("runtime_debts") != {}:
        raise CompletionReceiptError("checkpoint retains degradation or runtime debt")
    if checkpoint.get("rate_limited_at") is not None:
        raise CompletionReceiptError("checkpoint retains rate-limit state")
    commits = checkpoint.get("phase_commits")
    commit_keys = {
        "phase_name", "state", "run_id", "work_unit_id", "contract_digest",
        "launch_digest", "artifact_digest", "unresolved_failures",
        "clearance_events", "committed_at",
    }
    for phase in phases:
        row = commits.get(phase)
        if (
            not isinstance(row, dict)
            or set(row) != commit_keys
            or row.get("phase_name") != phase
            or row.get("run_id") != identity.run_id
            or row.get("work_unit_id") != "phase"
            or row.get("state") != "CLEAN"
            or row.get("unresolved_failures") != []
            or not isinstance(row.get("clearance_events"), list)
            or not isinstance(row.get("committed_at"), str)
            or not row.get("committed_at")
            or any(
                not isinstance(row.get(field), str)
                or not _HEX64.fullmatch(row[field])
                for field in ("contract_digest", "launch_digest", "artifact_digest")
            )
        ):
            raise CompletionReceiptError(f"phase commit is not clean: {phase}")
    for key in ("_active_model_attempts", "_phase_io_model_attempts"):
        attempts = config.get(key, {})
        if not isinstance(attempts, dict) or any(type(value) is not int or value != 1 for value in attempts.values()):
            raise CompletionReceiptError(f"checkpoint retains retry state: {key}")
    snapshot = checkpoint.get("audit_snapshot")
    if not isinstance(snapshot, dict) or snapshot.get("schema") != "plamen.audit-input-snapshot.v1":
        raise CompletionReceiptError("audit snapshot is absent")
    unsigned = dict(snapshot)
    digest = unsigned.pop("snapshot_digest", None)
    if not isinstance(digest, str) or not _HEX64.fullmatch(digest) or _sha(_canonical(unsigned)) != digest:
        raise CompletionReceiptError("audit snapshot self-digest is invalid")
    components = snapshot.get("components")
    source = components.get("source_scope") if isinstance(components, dict) else None
    if not isinstance(source, dict) or source.get("git_head") != identity.target_commit:
        raise CompletionReceiptError("audit snapshot does not bind target commit")
    return digest, phases


def _atomic_create(path: Path, payload: bytes) -> None:
    if path.exists() or path.is_symlink():
        raise CompletionReceiptError("terminal receipt already exists; replay is forbidden")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as exc:
            raise CompletionReceiptError("terminal receipt appeared during publication") from exc
        temporary.unlink()
        if os.name != "nt":
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def publish_audit_completion_receipt(
    *, scratchpad: Path, project_root: Path, terminal_exit_code: int,
    identity: ExpectedCompletionIdentity,
    completed_at: str | None = None,
) -> PublishedCompletionReceipt:
    """Validate final evidence and exclusively publish its terminal receipt.

    Minimal driver callsite contract::

        exit_code = _pipeline_terminal_exit_code(checkpoint)
        publish_from_driver_terminal_state(
            scratchpad=scratchpad,
            config=config,
            terminal_exit_code=exit_code,
        )
        sys.exit(exit_code)

    ``_audit_completion_identity`` must be captured before the audit starts.
    Do not derive its expected digests or commits from terminal artifacts.
    """
    if type(terminal_exit_code) is not int or terminal_exit_code != 0:
        raise CompletionReceiptError("terminal exit decision is not exact integer zero")
    identity.validate()
    scratchpad = Path(scratchpad).resolve(strict=True)
    project_root = Path(project_root).resolve(strict=True)
    if scratchpad != (project_root / ".scratchpad").resolve(strict=True):
        raise CompletionReceiptError("scratchpad is not project/.scratchpad")
    receipt_path = scratchpad / RECEIPT_NAME
    if receipt_path.exists() or receipt_path.is_symlink():
        raise CompletionReceiptError("terminal receipt already exists; replay is forbidden")

    checkpoint, checkpoint_raw = _read_json(scratchpad / "_v2_checkpoint.json")
    snapshot_digest, realized_phases = _validate_final_checkpoint(checkpoint, identity)
    report_raw = _read_regular(project_root / "AUDIT_REPORT.md", 64 * 1024 * 1024)
    if not report_raw.strip():
        raise CompletionReceiptError("terminal report is empty")

    installed_root = identity.installed_package_root.resolve(strict=True)
    source_root = identity.plamen_source_root.resolve(strict=True)
    target_root = identity.target_repository_root.resolve(strict=True)
    project_root.relative_to(target_root)
    package_digest, generation_receipt_digest, generation = _installed_authority(
        installed_root=installed_root,
        package_receipt_path=Path(identity.installed_package_receipt),
        generation_receipt_path=Path(identity.installed_generation_receipt),
    )
    if package_digest != identity.installed_package_receipt_sha256:
        raise CompletionReceiptError("installed package receipt digest drifted")
    if generation_receipt_digest != identity.installed_generation_receipt_sha256:
        raise CompletionReceiptError("installed generation receipt digest drifted")
    if generation != identity.installed_package_generation_sha256:
        raise CompletionReceiptError("installed package generation drifted")
    if _git_head(source_root) != identity.plamen_source_commit or not _git_tracked_clean(source_root):
        raise CompletionReceiptError("Plamen source is not frozen at expected commit")
    if _git_head(target_root) != identity.target_commit or not _git_tracked_clean(target_root, project_root):
        raise CompletionReceiptError("target source is not frozen at expected commit")

    terminal_closure = recompute_terminal_closure(
        scratchpad=scratchpad,
        project_root=project_root,
        checkpoint=checkpoint,
    )

    timestamp = completed_at or datetime.now(timezone.utc).isoformat()
    if not isinstance(timestamp, str) or not timestamp:
        raise CompletionReceiptError("completed_at is invalid")
    unsigned = {
        "schema_version": DRIVER_TERMINAL_SCHEMA,
        "run_id": identity.run_id,
        "pipeline": "sc",
        "mode": "thorough",
        "exit_code": 0,
        "phase_count": len(realized_phases),
        "realized_phase_plan_sha256": phase_names_sha256(realized_phases),
        "checkpoint_sha256": _sha(checkpoint_raw),
        "report_sha256": _sha(report_raw),
        "audit_snapshot_digest": snapshot_digest,
        "plamen_source_commit": identity.plamen_source_commit,
        "installed_package_receipt_sha256": identity.installed_package_receipt_sha256,
        "installed_generation_receipt_sha256": identity.installed_generation_receipt_sha256,
        "installed_package_generation_sha256": identity.installed_package_generation_sha256,
        "target_commit": identity.target_commit,
        "terminal_closure": terminal_closure,
        "completed_at": timestamp,
    }
    receipt_digest = _sha(_canonical(unsigned))
    payload = {**unsigned, "receipt_sha256": receipt_digest}
    _atomic_create(receipt_path, _canonical(payload) + b"\n")
    return PublishedCompletionReceipt(receipt_path, receipt_digest, payload)


def publish_from_driver_terminal_state(
    *, scratchpad: Path, config: Mapping[str, Any], terminal_exit_code: int,
) -> PublishedCompletionReceipt:
    """Thin driver adapter; expected identity must already be start-bound."""
    raw_identity = config.get("_audit_completion_identity")
    if not isinstance(raw_identity, Mapping):
        raise CompletionReceiptError("start-bound _audit_completion_identity is absent")
    project = config.get("project_root")
    if not isinstance(project, str) or not project:
        raise CompletionReceiptError("project_root is absent from driver config")
    return publish_audit_completion_receipt(
        scratchpad=scratchpad,
        project_root=Path(project),
        terminal_exit_code=terminal_exit_code,
        identity=ExpectedCompletionIdentity.from_mapping(raw_identity),
    )


__all__ = [
    "build_terminal_closure_projection", "CompletionReceiptError",
    "DRIVER_TERMINAL_SCHEMA", "LEGACY_DRIVER_TERMINAL_SCHEMA",
    "TERMINAL_CLOSURE_SCHEMA", "capture_start_completion_identity",
    "completion_identity_run_id", "ExpectedCompletionIdentity", "PublishedCompletionReceipt", "RECEIPT_NAME",
    "SC_THOROUGH_PHASES", "phase_names_sha256", "publish_audit_completion_receipt",
    "publish_from_driver_terminal_state", "realized_phase_plan_from_checkpoint",
    "recompute_terminal_closure", "validate_installed_authority",
    "validate_realized_phase_plan", "validate_terminal_closure",
]
