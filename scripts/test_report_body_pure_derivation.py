"""Pure postimage derivation for typed report-body repair successors."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import plamen_mechanical as mechanical
from report_evidence_authority import (
    ReportEvidenceError,
    materialize_report_evidence_runtime,
)
from test_report_evidence_runtime_p1_k import _write_inputs


def _inputs(root: Path):
    _write_inputs(root, impact="A proven transition can misallocate value.")
    runtime = materialize_report_evidence_runtime(root)
    model_body = (
        "# Critical and High Findings\n\n"
        "### [REPORT-BLOCKED: insufficient evidence] [H-01] stale body\n\n"
        "Phase 5 verification did not produce evidence.\n"
    ).encode("utf-8")
    body_path = root / "report_critical_high.md"
    body_path.write_bytes(model_body)
    manifest_bytes = (
        root / "body_manifests" / "report_critical_high.json"
    ).read_bytes()
    typed_manifest = json.loads(
        (
            root
            / "report_evidence_manifests"
            / "report_critical_high.json"
        ).read_text(encoding="utf-8")
    )
    verifier = {
        "verify_INV-001.md": (root / "verify_INV-001.md").read_bytes()
    }
    return (
        body_path,
        model_body,
        manifest_bytes,
        typed_manifest,
        verifier,
        runtime["bundle"],
    )


def test_pure_report_body_derivation_matches_legacy_complete_read_set(
    tmp_path: Path, monkeypatch
):
    (
        body_path,
        model_body,
        manifest_bytes,
        typed_manifest,
        verifier,
        bundle,
    ) = _inputs(tmp_path)

    expected = mechanical.derive_report_body_evidence_projection(
        phase_name="report_body_writer_critical_high",
        model_body=model_body,
        body_manifest_bytes=manifest_bytes,
        typed_manifest=typed_manifest,
        verifier_artifacts=verifier,
        evidence_bundle=bundle,
    )
    assert expected.repair_count == 2
    assert expected.repaired_report_ids == ("H-01",)
    assert expected.consumed_verify_files == ("verify_INV-001.md",)
    assert expected.evidence_projection_applied is True
    assert b"[REPORT-BLOCKED" not in expected.output_bytes
    assert b"PLAMEN_REPORT_EVIDENCE rid=H-01" in expected.output_bytes
    assert b"A proven transition can misallocate value" in expected.output_bytes
    assert (
        b"Evidence assurance**: Confirmed mechanism; harm proof not established"
        in expected.output_bytes
    )
    assert b"Evidence and report limitation" in expected.output_bytes

    def ambient_read_forbidden(*_args, **_kwargs):
        pytest.fail("pure report-body derivation attempted filesystem I/O")

    with monkeypatch.context() as no_ambient:
        no_ambient.setattr(Path, "read_bytes", ambient_read_forbidden)
        no_ambient.setattr(Path, "read_text", ambient_read_forbidden)
        replay = mechanical.derive_report_body_evidence_projection(
            phase_name="report_body_writer_critical_high",
            model_body=model_body,
            body_manifest_bytes=manifest_bytes,
            typed_manifest=typed_manifest,
            verifier_artifacts=verifier,
            evidence_bundle=bundle,
        )
    assert replay == expected

    legacy_count = mechanical._repair_report_body_from_manifest(
        tmp_path, "report_body_writer_critical_high"
    )
    assert legacy_count == expected.repair_count
    assert body_path.read_bytes() == expected.output_bytes

    (tmp_path / "verify_INV-001.md").write_text(
        "untrusted ambient replacement\n", encoding="utf-8"
    )
    assert mechanical.derive_report_body_evidence_projection(
        phase_name="report_body_writer_critical_high",
        model_body=model_body,
        body_manifest_bytes=manifest_bytes,
        typed_manifest=typed_manifest,
        verifier_artifacts=verifier,
        evidence_bundle=bundle,
    ) == expected


def test_pure_report_body_derivation_requires_exact_explicit_evidence(
    tmp_path: Path,
):
    (
        _body_path,
        model_body,
        manifest_bytes,
        typed_manifest,
        verifier,
        bundle,
    ) = _inputs(tmp_path)
    with pytest.raises(
        ValueError, match="verifier artifact denominator differs"
    ):
        mechanical.derive_report_body_evidence_projection(
            phase_name="report_body_writer_critical_high",
            model_body=model_body,
            body_manifest_bytes=manifest_bytes,
            typed_manifest=typed_manifest,
            verifier_artifacts={},
            evidence_bundle=bundle,
        )
    with pytest.raises(
        ValueError, match="verifier artifact denominator differs"
    ):
        mechanical.derive_report_body_evidence_projection(
            phase_name="report_body_writer_critical_high",
            model_body=model_body,
            body_manifest_bytes=manifest_bytes,
            typed_manifest=typed_manifest,
            verifier_artifacts={**verifier, "verify_EXTRA.md": b"extra\n"},
            evidence_bundle=bundle,
        )
    with pytest.raises(ReportEvidenceError):
        mechanical.derive_report_body_evidence_projection(
            phase_name="report_body_writer_critical_high",
            model_body=model_body,
            body_manifest_bytes=manifest_bytes,
            typed_manifest=typed_manifest,
            verifier_artifacts=verifier,
            evidence_bundle={},
        )
    with pytest.raises(
        ReportEvidenceError, match="source manifest differs"
    ):
        mechanical.derive_report_body_evidence_projection(
            phase_name="report_body_writer_critical_high",
            model_body=model_body,
            body_manifest_bytes=manifest_bytes + b" ",
            typed_manifest=typed_manifest,
            verifier_artifacts=verifier,
            evidence_bundle=bundle,
        )
    with pytest.raises(ValueError, match="MODEL bytes are not UTF-8"):
        mechanical.derive_report_body_evidence_projection(
            phase_name="report_body_writer_critical_high",
            model_body=b"# Findings\n\xff\n",
            body_manifest_bytes=manifest_bytes,
            typed_manifest=typed_manifest,
            verifier_artifacts=verifier,
            evidence_bundle=bundle,
        )
    assert not (tmp_path / "report_evidence_runtime_debt.md").exists()


def test_pure_report_body_derivation_preserves_exact_crlf_noop_bytes(
    tmp_path: Path, monkeypatch
):
    (
        _body_path,
        model_body,
        manifest_bytes,
        typed_manifest,
        verifier,
        bundle,
    ) = _inputs(tmp_path)
    canonical = mechanical.derive_report_body_evidence_projection(
        phase_name="report_body_writer_critical_high",
        model_body=model_body,
        body_manifest_bytes=manifest_bytes,
        typed_manifest=typed_manifest,
        verifier_artifacts=verifier,
        evidence_bundle=bundle,
    )
    crlf = canonical.output_bytes.replace(b"\n", b"\r\n")
    assert b"\r\n" in crlf

    def ambient_read_forbidden(*_args, **_kwargs):
        pytest.fail("pure report-body no-op attempted filesystem I/O")

    with monkeypatch.context() as no_ambient:
        no_ambient.setattr(Path, "read_bytes", ambient_read_forbidden)
        no_ambient.setattr(Path, "read_text", ambient_read_forbidden)
        replay = mechanical.derive_report_body_evidence_projection(
            phase_name="report_body_writer_critical_high",
            model_body=crlf,
            body_manifest_bytes=manifest_bytes,
            typed_manifest=typed_manifest,
            verifier_artifacts=verifier,
            evidence_bundle=bundle,
        )
    assert replay.repair_count == 0
    assert replay.repaired_report_ids == ()
    assert replay.evidence_projection_applied is False
    assert replay.output_bytes == crlf
