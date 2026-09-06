"""P1 fixtures for every deterministic report-source producer conversion."""
from __future__ import annotations

from pathlib import Path
import sys


SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(ROOT))

from artifact_ledger import (  # noqa: E402
    active_committed_work_unit_authority_issues,
    read_artifact_ledger,
)
from report_assembly_capture import DEFAULT_FIXED_SOURCE_ROLES  # noqa: E402
import report_capture_phaseio_authority as RCA  # noqa: E402
from test_report_source_capture_cutover_p2 import (  # noqa: E402
    RUN_ID,
    _commit_generic_sources,
    _config as _fixture_config,
    _metadata,
    _roots,
)
import plamen_driver as driver  # noqa: E402
import plamen_mechanical as mechanical  # noqa: E402


def _config(project: Path) -> dict[str, object]:
    return _fixture_config(project / ".scratchpad")


def _assert_active_single_output(
    scratch: Path,
    *,
    suffix: str,
    identity: str,
) -> None:
    ledger = read_artifact_ledger(scratch)
    keys = [key for key in ledger["work_units"] if key.endswith(suffix)]
    assert len(keys) == 1
    assert active_committed_work_unit_authority_issues(
        ledger,
        work_unit_key=keys[0],
        run_id=RUN_ID,
        expected_artifact_identities=(identity,),
    ) == []


def test_depth_legacy_caches_are_replaced_by_typed_report_authority(
    tmp_path: Path,
) -> None:
    project, scratch = _roots(tmp_path)
    config = _config(project)
    receipt = {
        "schema_version": 2,
        "phase": "depth",
        "source_digest": "d" * 64,
        "status": "FINALIZED",
        "processors": {
            name: {"status": "COMPLETE"}
            for name in (
                "blind_spot_recovery",
                "enumeration_gate",
                "niche_promotion",
                "variant_gate",
            )
        },
    }
    # Legacy resume caches may still exist, but they are no longer report inputs.
    (scratch / "depth_finalization_receipt.json").write_text("{}\n", encoding="utf-8")
    assert "depth_finalization_receipt.json" not in DEFAULT_FIXED_SOURCE_ROLES
    assert "depth_finalization_human_review.md" not in DEFAULT_FIXED_SOURCE_ROLES

    assert driver._run_depth_finalization_report_authority_transaction(
        scratch,
        config,
        receipt,
        phase_name="depth",
    ) == []
    _assert_active_single_output(
        scratch,
        suffix="/depth/finalization_report_authority",
        identity="scratchpad:depth_finalization_report_authority.json",
    )
    prepared = RCA.prepare_report_source_capture(
        scratchpad=scratch,
        project_root=project,
        run_id=RUN_ID,
        expected_config=config,
        metadata=_metadata(scratch),
        fixed_source_roles={
            "depth_finalization_report_authority.json": (
                "DEPTH_FINALIZATION_REPORT_AUTHORITY"
            )
        },
        namespace_roles={},
    )
    assert prepared.exact_input_paths == (
        "depth_finalization_report_authority.json",
    )


def test_deferred_chain_markdown_has_exact_chain_and_queue_producers(
    tmp_path: Path,
) -> None:
    project, scratch = _roots(tmp_path)
    _commit_generic_sources(
        project,
        scratch,
        {
            "chain_hypotheses.md": (
                "# Chain Hypotheses\n\n"
                "## Chain Hypothesis CH-1\n"
                "Chain Severity: High\n"
                "`Constituents: H-1,H-23 | Severity-Upgrade-Justified: YES | "
                "Combined-Impact: combined cross-user loss absent alone`\n"
            ).encode("utf-8"),
            "verification_queue.md": (
                "| Queue # | Finding ID | Severity | Title |\n"
                "|---|---|---|---|\n"
            ).encode("utf-8"),
        },
    )
    _ids, raw = mechanical._deferred_chain_notes_projection(scratch)
    assert raw is not None and _ids == {"CH-1"}
    assert not (scratch / "report_semantic_chain_deferred.md").exists()

    assert driver._run_chain_deferred_report_transaction(
        scratch, _config(project)
    ) == []
    assert (scratch / "report_semantic_chain_deferred.md").read_bytes() == raw
    _assert_active_single_output(
        scratch,
        suffix="/report_index/chain_deferred_authority",
        identity="scratchpad:report_semantic_chain_deferred.md",
    )
    prepared = RCA.prepare_report_source_capture(
        scratchpad=scratch,
        project_root=project,
        run_id=RUN_ID,
        expected_config=_config(project),
        metadata=_metadata(scratch),
        fixed_source_roles={},
        namespace_roles={
            "report_semantic_*.md": "REPORT_SEMANTIC_NAMESPACE"
        },
    )
    requirement = prepared.contract.input_authority_requirements[0]
    assert requirement.allow_raw is False
    assert requirement.expected_producer_work_unit_key.endswith(
        "/report_index/chain_deferred_authority"
    )


def test_dependency_unknown_fallback_is_a_typed_one_output_transaction(
    tmp_path: Path,
) -> None:
    project, scratch = _roots(tmp_path)
    raw = (
        "# External Dependency Research Coverage\n\n"
        "Status: UNKNOWN — deterministic parity failed.\n"
    ).encode("utf-8")
    assert driver._run_zero_input_driver_projection_transaction(
        scratchpad=scratch,
        config=_config(project),
        phase="recon",
        work_unit_id="dependency_research_debt",
        output_name="report_semantic_dependency_research.md",
        output_bytes=raw,
    ) == []
    _assert_active_single_output(
        scratch,
        suffix="/recon/dependency_research_debt",
        identity="scratchpad:report_semantic_dependency_research.md",
    )
    prepared = RCA.prepare_report_source_capture(
        scratchpad=scratch,
        project_root=project,
        run_id=RUN_ID,
        expected_config=_config(project),
        metadata=_metadata(scratch),
        fixed_source_roles={},
        namespace_roles={
            "report_semantic_*.md": "REPORT_SEMANTIC_NAMESPACE"
        },
    )
    assert prepared.exact_input_paths == (
        "report_semantic_dependency_research.md",
    )


def test_audit_input_limitations_are_snapshot_derived_and_typed(
    tmp_path: Path,
) -> None:
    project, scratch = _roots(tmp_path)
    snapshot = {
        "components": {
            "source_scope": {
                "coverage_limitations": [
                    "one generated dependency could not be materialized"
                ]
            }
        }
    }
    assert driver._run_audit_input_limitations_transaction(
        scratch,
        snapshot,
        _config(project),
    ) == []
    raw = scratch.joinpath(
        "report_semantic_audit_input_limitations.md"
    ).read_bytes()
    assert raw == driver._audit_input_limitations_bytes(snapshot)
    _assert_active_single_output(
        scratch,
        suffix="/recon/audit_input_limitations",
        identity="scratchpad:report_semantic_audit_input_limitations.md",
    )
    prepared = RCA.prepare_report_source_capture(
        scratchpad=scratch,
        project_root=project,
        run_id=RUN_ID,
        expected_config=_config(project),
        metadata=_metadata(scratch),
        fixed_source_roles={},
        namespace_roles={
            "report_semantic_*.md": "REPORT_SEMANTIC_NAMESPACE"
        },
    )
    assert prepared.exact_input_paths == (
        "report_semantic_audit_input_limitations.md",
    )
