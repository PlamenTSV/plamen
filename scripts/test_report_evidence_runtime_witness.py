from pathlib import Path
import json
import os
import pytest

from report_evidence_runtime_witness import (
    ReportEvidenceRuntimeWitnessError,
    capture_report_evidence_runtime_authority,
    validate_report_evidence_runtime_authority,
)
from report_evidence_authority import (
    ReportEvidenceError, materialize_report_evidence_runtime,
    validate_report_evidence_runtime,
)
from test_report_evidence_runtime_p1_k import _write_inputs


def test_bundle_runtime_authority_is_exact_and_replayable(tmp_path: Path):
    _write_inputs(tmp_path, impact="", recommendation="")
    materialize_report_evidence_runtime(tmp_path)
    authority = capture_report_evidence_runtime_authority(
        tmp_path, project_root=tmp_path,
    )
    assert authority["schema"] == "plamen.report-evidence-runtime-authority.v1"
    assert "scratchpad:report_records.json" in authority["read_set"]
    assert "scratchpad:report_evidence_records.json" in authority["read_set"]
    assert "scratchpad:report_evidence_projection.md" in authority["read_set"]
    assert validate_report_evidence_runtime_authority(
        tmp_path, project_root=tmp_path, expected=authority,
    ) == authority


def test_bundle_runtime_authority_rejects_source_drift(tmp_path: Path):
    _write_inputs(tmp_path, impact="", recommendation="")
    materialize_report_evidence_runtime(tmp_path)
    authority = capture_report_evidence_runtime_authority(
        tmp_path, project_root=tmp_path,
    )
    (tmp_path / "report_evidence_projection.md").write_text(
        "changed\n", encoding="utf-8"
    )
    # Semantic replay rejects this corruption before freshness comparison.
    with pytest.raises(ReportEvidenceError, match="projection parity failed"):
        validate_report_evidence_runtime_authority(
            tmp_path, project_root=tmp_path, expected=authority,
        )


def test_root_directory_publication_metadata_is_not_authority(tmp_path: Path):
    _write_inputs(tmp_path, impact="", recommendation="")
    materialize_report_evidence_runtime(tmp_path)
    authority = capture_report_evidence_runtime_authority(
        tmp_path, project_root=tmp_path,
    )
    # Model transaction arm/publication: mutate scratchpad directory metadata
    # without changing any captured file, absence, or namespace witness.
    (tmp_path / "_artifact_state.json").write_bytes(b"{}\n")
    (tmp_path / "report_evidence_projection_receipts").mkdir()
    assert validate_report_evidence_runtime_authority(
        tmp_path, project_root=tmp_path, expected=authority,
    ) == authority


def test_report_without_assessed_candidates_has_replayable_witness(tmp_path: Path):
    _write_inputs(tmp_path, impact="", recommendation="", include_assessment=False)
    materialize_report_evidence_runtime(tmp_path)
    authority = capture_report_evidence_runtime_authority(
        tmp_path, project_root=tmp_path,
    )
    assert authority["candidate_ids"] == []
    assert set(authority["implementation_identities"]) == {
        "report_evidence_authority"
    }
    assert validate_report_evidence_runtime_authority(
        tmp_path, project_root=tmp_path, expected=authority,
    ) == authority


def test_same_bytes_replaced_file_is_not_same_witness(tmp_path: Path):
    _write_inputs(tmp_path, impact="", recommendation="")
    materialize_report_evidence_runtime(tmp_path)
    authority = capture_report_evidence_runtime_authority(
        tmp_path, project_root=tmp_path,
    )
    target = tmp_path / "report_evidence_projection.md"
    replacement = tmp_path / ".replacement"
    replacement.write_bytes(target.read_bytes())
    os.replace(replacement, target)
    with pytest.raises(ReportEvidenceRuntimeWitnessError):
        validate_report_evidence_runtime_authority(
            tmp_path, project_root=tmp_path, expected=authority,
        )


def test_same_semantic_report_records_replacement_is_not_same_witness(
    tmp_path: Path,
):
    _write_inputs(tmp_path, impact="", recommendation="")
    materialize_report_evidence_runtime(tmp_path)
    authority = capture_report_evidence_runtime_authority(
        tmp_path, project_root=tmp_path,
    )
    semantic_runtime = validate_report_evidence_runtime(tmp_path)
    identity = "scratchpad:report_records.json"
    original = authority["read_set"][identity]
    target = tmp_path / "report_records.json"
    replacement = tmp_path / ".report-records-replacement"
    replacement.write_bytes(target.read_bytes())
    os.replace(replacement, target)
    # Runtime semantics and bytes remain identical, but retained physical
    # provenance changed.  The witness must detect that substitution.
    assert target.read_bytes() and target.stat().st_ino != original[
        "physical_identity"
    ][1]
    assert validate_report_evidence_runtime(tmp_path) == semantic_runtime
    with pytest.raises(ReportEvidenceRuntimeWitnessError):
        validate_report_evidence_runtime_authority(
            tmp_path, project_root=tmp_path, expected=authority,
        )


def test_empty_runtime_seals_report_records_physical_identity(
    tmp_path: Path,
):
    manifest_dir = tmp_path / "body_manifests"
    manifest_dir.mkdir()
    (tmp_path / "report_records.json").write_text(
        json.dumps(
            {
                "schema_version": "plamen.report_records.v1",
                "source": "report_index.md",
                "active": [],
                "excluded": [],
                "consolidation_map": [],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (manifest_dir / "report_empty.json").write_text(
        json.dumps(
            {
                "schema_version": "plamen.empty_report_denominator.v1",
                "denominator_state": "EMPTY",
                "findings": [],
                "shard": "report_empty",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    materialize_report_evidence_runtime(tmp_path)
    semantic_runtime = validate_report_evidence_runtime(tmp_path)
    authority = capture_report_evidence_runtime_authority(
        tmp_path, project_root=tmp_path,
    )
    identity = "scratchpad:report_records.json"
    target = tmp_path / "report_records.json"
    original_inode = target.stat().st_ino
    replacement = tmp_path / ".empty-report-records-replacement"
    replacement.write_bytes(target.read_bytes())
    os.replace(replacement, target)
    assert target.stat().st_ino != original_inode
    # The canonical empty denominator is semantically unchanged.  Physical
    # substitution must nevertheless invalidate its retained witness.
    assert validate_report_evidence_runtime(tmp_path) == semantic_runtime
    with pytest.raises(ReportEvidenceRuntimeWitnessError):
        validate_report_evidence_runtime_authority(
            tmp_path, project_root=tmp_path, expected=authority,
        )
    assert identity in authority["read_set"]
