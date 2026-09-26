"""Driver integration for retained MODEL body -> evidence projection.

The driver supplies its normal phase-contract resolver and authenticated MODEL
commit boundary.  This module never invents a contract from a ledger row or
attributes a deterministic postimage to the MODEL that produced its preimage.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Mapping

import rooted_path_io as rooted
from artifact_ledger import ArtifactLedgerError, read_artifact_ledger
from phase_io_contracts import (
    parse_report_body_attempt_work_unit,
    report_body_attempt_work_unit_id,
)


def run_report_body_driver_bridge(
    phase: Any,
    scratchpad: Path,
    config: Mapping[str, Any],
    *,
    resolve_model: Callable[..., Any],
    record_model: Callable[..., Any],
    read_only: bool = False,
    fault_hook: Callable[[str], None] | None = None,
) -> list[str]:
    """Commit raw MODEL output once, then publish or validate its successor."""

    try:
        root = Path(scratchpad)
        project = Path(str(config["project_root"]))
        # A zero-tier phase has a distinct DRIVER producer and no MODEL
        # generation, and routing omits its per-tier manifest altogether.
        # Manifest presence only selects the validator; neither absence nor
        # an empty findings list establishes empty-tier authority by itself.
        prefix = "report_body_writer_"
        if not isinstance(phase.name, str) or not phase.name.startswith(prefix):
            raise ArtifactLedgerError("report-body phase name is unsupported")
        shard_name = "report_" + phase.name[len(prefix):]
        report_body_attempt_work_unit_id("model", shard_name, 1)
        manifest_path = root / "body_manifests" / f"{shard_name}.json"
        try:
            rooted.lstat(manifest_path)
        except FileNotFoundError:
            manifest_absent = True
            manifest = None
        else:
            manifest_absent = False
            manifest = json.loads(rooted.read_bytes(
                manifest_path,
                label="report body routing selector",
                require_single_link=True,
                max_bytes=32 * 1024 * 1024,
            ).decode("utf-8", errors="strict"))
        if manifest_absent or (
            isinstance(manifest, Mapping) and manifest.get("findings") == []
        ):
            from report_empty_tier import validate_committed_empty_report_tier
            if not validate_committed_empty_report_tier(
                scratchpad=root, project_root=project, config=config,
                phase_name=phase.name,
            ):
                raise ArtifactLedgerError("empty report body has no committed producer")
            return []
        contract, launch = resolve_model(phase, root, config)
        if contract is None or launch is None:
            raise ArtifactLedgerError("report-body MODEL contract is unavailable")
        parsed = parse_report_body_attempt_work_unit(contract.work_unit_id)
        if contract.phase != "report_body" or parsed is None or parsed[0] != "model":
            raise ArtifactLedgerError("report-body MODEL identity is unsupported")
        _role, shard, ordinal = parsed
        successor_key = contract.key.rsplit("/", 1)[0] + "/" + (
            report_body_attempt_work_unit_id("evidence_projection", shard, ordinal)
        )
        if read_only:
            from report_body_evidence_projection import (
                validate_committed_report_body_evidence_projection,
            )
            validate_committed_report_body_evidence_projection(
                scratchpad=root,
                project_root=project,
                config=config,
                phase_name=phase.name,
                model_contract=contract,
                model_launch=launch,
            )
            return []

        ledger = read_artifact_ledger(root)
        units = ledger.get("work_units")
        if not isinstance(units, Mapping):
            raise ArtifactLedgerError("report-body work-unit ledger is malformed")
        # A previously armed successor may already have replaced the live body.
        # Its transaction must replay retained MODEL bytes, never recapture the
        # current DRIVER body under the historical MODEL commit.
        if successor_key not in units:
            issues = record_model(
                phase,
                root,
                config,
                allow_report_body_preimage=True,
                _resolved_contract=contract,
                _resolved_launch=launch,
            )
            if issues:
                return ["report-body raw MODEL attribution: " + str(item) for item in issues]
        from report_body_evidence_projection import run_report_body_evidence_projection
        run_report_body_evidence_projection(
            scratchpad=root,
            project_root=project,
            config=config,
            phase_name=phase.name,
            model_contract=contract,
            model_launch=launch,
            fault_hook=fault_hook,
        )
        return []
    except (
        OSError, KeyError, TypeError, ValueError, ArtifactLedgerError,
        rooted.RootedPathIOError,
    ) as exc:
        return [
            "report-body evidence successor failed: "
            f"{type(exc).__name__}: {exc}"
        ]
