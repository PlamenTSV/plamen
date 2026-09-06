"""Fixture-first REDs for the frozen full report-assembly PhaseIO cut.

The accepted denominator is deliberately wider than Appendix B.  Tier repair
and recovery happen before assembly arm, assembly consumes captured immutable
bytes only, and every quality/repair mutation is an explicit typed successor.
"""
from __future__ import annotations

import ast
import base64
import hashlib
import inspect
import json
import os
from pathlib import Path
import sys
import textwrap

import pytest


SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(ROOT))

from phase_io_contracts import (  # noqa: E402
    InputAuthorityRequirement,
    resolve_phase_io_contract,
)
from artifact_ledger import record_work_unit_inputs  # noqa: E402
import phase_io_contracts as PIO  # noqa: E402
import report_assembly_capture as RAC  # noqa: E402
import report_capture_phaseio_authority as RCA  # noqa: E402
from test_report_source_authority_r3_repair import (  # noqa: E402
    _fixture as _authority_fixture,
)
from report_assembly_capture import (  # noqa: E402
    ReportAssemblyCaptureError,
)

build_report_assembly_final_capture = RAC._build_report_assembly_final_capture
build_report_assembly_source_capture = RAC._capture_report_assembly_source
report_assembly_capture_exact_inputs = RAC._report_assembly_capture_exact_inputs
report_assembly_capture_explicit_absences = (
    RAC._report_assembly_capture_explicit_absences
)
report_assembly_capture_output_absences = (
    RAC._report_assembly_capture_output_absences
)
report_assembly_capture_output_bytes = RAC._report_assembly_capture_output_bytes
replay_report_assembly_final_capture = RAC._replay_report_assembly_final_capture
replay_report_assembly_source_capture = RAC._replay_report_assembly_source_capture
validate_report_assembly_final_capture = RAC._validate_report_assembly_final_capture
validate_report_assembly_source_capture = RAC._validate_report_assembly_source_capture


INTEGRATION_RED = pytest.mark.xfail(
    strict=True,
    reason=(
        "report driver/mechanical/quality integration is intentionally outside "
        "the capture-foundation ownership slice"
    ),
)

_CAPTURE_METADATA = {
    "backend": "claude",
    "ecosystem": "evm",
    "mode": "thorough",
    "pipeline": "sc",
    "project_name": "fixture-project",
    "report_date": "2026-08-04",
    "run_id": "123e4567-e89b-42d3-a456-426614174000",
    "scope": "contracts/",
    "source_roster_authority_sha256": "b" * 64,
    "source_snapshot_sha256": "a" * 64,
}


def _source_capture_predecessor(
    tmp_path: Path,
) -> tuple[dict[str, object], dict[str, str]]:
    source = build_report_assembly_source_capture(
        tmp_path,
        metadata=_CAPTURE_METADATA,
        fixed_source_roles={},
        namespace_roles={},
    )
    source_bytes = RAC._canonical_report_assembly_source_capture_bytes(source)
    predecessor = {
        "artifact_identity": (
            "scratchpad:report_assembly_source_capture.json"
        ),
        "content_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "run_id": _CAPTURE_METADATA["run_id"],
        "producer_work_unit_key": (
            "sc/thorough/evm/claude/report_assemble/source_capture"
        ),
        "contract_digest": "b" * 64,
        "launch_digest": "c" * 64,
        "commit_receipt_digest": "d" * 64,
    }
    return source, predecessor


def _build_final_capture(
    tmp_path: Path,
    *,
    derived_outputs: dict[str, tuple[str, bytes]] | None = None,
    location_decisions: tuple[dict[str, object], ...] = (),
    fixed_source_roles: dict[str, str] | None = None,
) -> tuple[dict[str, object], dict[str, str]]:
    source = build_report_assembly_source_capture(
        tmp_path,
        metadata=_CAPTURE_METADATA,
        fixed_source_roles=(
            {} if fixed_source_roles is None else fixed_source_roles
        ),
        namespace_roles={},
    )
    predecessor = {
        "artifact_identity": RAC.SOURCE_CAPTURE_IDENTITY,
        "content_sha256": hashlib.sha256(
            RAC._canonical_report_assembly_source_capture_bytes(source)
        ).hexdigest(),
        "run_id": _CAPTURE_METADATA["run_id"],
        "producer_work_unit_key": (
            "sc/thorough/evm/claude/report_assemble/source_capture"
        ),
        "contract_digest": "b" * 64,
        "launch_digest": "c" * 64,
        "commit_receipt_digest": "d" * 64,
    }
    final = build_report_assembly_final_capture(
        tmp_path,
        source_capture=source,
        expected_final_artifact_identity=RAC.FINAL_CAPTURE_IDENTITY,
        predecessor_binding=predecessor,
        derived_outputs=(
            _final_outputs()
            if derived_outputs is None
            else derived_outputs
        ),
        location_decisions=location_decisions,
    )
    return final, predecessor


def _validate_final(
    capture: object,
    predecessor: dict[str, str],
) -> dict[str, object]:
    return validate_report_assembly_final_capture(
        capture,
        expected_final_artifact_identity=RAC.FINAL_CAPTURE_IDENTITY,
        expected_predecessor_binding=predecessor,
    )


def _output_bytes(
    capture: object,
    predecessor: dict[str, str],
) -> dict[str, bytes]:
    return report_assembly_capture_output_bytes(
        capture,
        expected_final_artifact_identity=RAC.FINAL_CAPTURE_IDENTITY,
        expected_predecessor_binding=predecessor,
    )


def _output_absences(
    capture: object,
    predecessor: dict[str, str],
) -> tuple[str, ...]:
    return report_assembly_capture_output_absences(
        capture,
        expected_final_artifact_identity=RAC.FINAL_CAPTURE_IDENTITY,
        expected_predecessor_binding=predecessor,
    )


def _final_outputs(
    **overrides: tuple[str, bytes],
) -> dict[str, tuple[str, bytes]]:
    outputs = {
        "project:AUDIT_REPORT.md": ("CLIENT_REPORT", b"# Audit\n"),
        "scratchpad:report_quality.md": ("REPORT_QUALITY", b"# Quality\n"),
    }
    outputs.update(overrides)
    return outputs


def _resign_capture(payload: dict[str, object]) -> None:
    unsigned = dict(payload)
    unsigned["capture_digest"] = ""
    payload["capture_digest"] = hashlib.sha256(
        json.dumps(
            unsigned,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def _source_authority(path: str, ordinal: int) -> InputAuthorityRequirement:
    return InputAuthorityRequirement(
        identity=f"scratchpad:{path}",
        expected_producer_work_unit_key=(
            "sc/thorough/evm/claude/report_index/"
            f"capture_fixture_{ordinal}"
        ),
        expected_writer="MODEL" if ordinal % 2 else "DRIVER",
        expected_contract_digest=hashlib.sha256(
            f"contract:{path}".encode("utf-8")
        ).hexdigest(),
        expected_launch_digest=hashlib.sha256(
            f"launch:{path}".encode("utf-8")
        ).hexdigest(),
    )


def _called_names(callable_object: object) -> set[str]:
    tree = ast.parse(textwrap.dedent(inspect.getsource(callable_object)))
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name):
            names.add(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            names.add(node.func.attr)
    return names


def _driver():
    import plamen_driver

    return plamen_driver


def _mechanical():
    import plamen_mechanical

    return plamen_mechanical


def _main_calls() -> list[tuple[int, str]]:
    tree = ast.parse(textwrap.dedent(inspect.getsource(_driver().main)))
    calls: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name):
            calls.append((node.lineno, node.func.id))
        elif isinstance(node.func, ast.Attribute):
            calls.append((node.lineno, node.func.attr))
    return sorted(calls)


def test_r2_source_and_final_are_distinct_external_kinds(tmp_path: Path) -> None:
    source, predecessor = _source_capture_predecessor(tmp_path)
    final = RAC._build_report_assembly_final_capture(
        tmp_path,
        source_capture=source,
        expected_final_artifact_identity=(
            "scratchpad:report_assembly_final_capture.json"
        ),
        predecessor_binding=predecessor,
        derived_outputs=_final_outputs(),
    )

    assert source["schema_version"] == RAC.SOURCE_SCHEMA_VERSION
    assert final["schema_version"] == RAC.FINAL_SCHEMA_VERSION
    assert "capture_kind" not in source
    assert "capture_kind" not in final
    with pytest.raises(ReportAssemblyCaptureError, match="CAPTURE_SCHEMA"):
        validate_report_assembly_source_capture(final)
    with pytest.raises(ReportAssemblyCaptureError, match="CAPTURE_SCHEMA"):
        RAC._validate_report_assembly_final_capture(
            source,
            expected_final_artifact_identity=(
                "scratchpad:report_assembly_final_capture.json"
            ),
            expected_predecessor_binding=predecessor,
        )


@pytest.mark.parametrize(
    "field,replacement",
    (
        ("artifact_identity", "scratchpad:other.json"),
        ("content_sha256", "e" * 64),
        ("run_id", "123e4567-e89b-42d3-a456-426614174001"),
        (
            "producer_work_unit_key",
            "sc/thorough/evm/claude/report_assemble/other",
        ),
        ("contract_digest", "e" * 64),
        ("launch_digest", "e" * 64),
        ("commit_receipt_digest", "e" * 64),
    ),
)
def test_r2_final_rejects_resigned_predecessor_rebinding(
    tmp_path: Path,
    field: str,
    replacement: str,
) -> None:
    source, predecessor = _source_capture_predecessor(tmp_path)
    final = RAC._build_report_assembly_final_capture(
        tmp_path,
        source_capture=source,
        expected_final_artifact_identity=(
            "scratchpad:report_assembly_final_capture.json"
        ),
        predecessor_binding=predecessor,
        derived_outputs=_final_outputs(),
    )
    final["predecessor_binding"][field] = replacement
    _resign_capture(final)
    with pytest.raises(
        ReportAssemblyCaptureError,
        match="PREDECESSOR_BINDING",
    ):
        RAC._validate_report_assembly_final_capture(
            final,
            expected_final_artifact_identity=(
                "scratchpad:report_assembly_final_capture.json"
            ),
            expected_predecessor_binding=predecessor,
        )


def test_r2_final_build_requires_exact_committed_source_content(
    tmp_path: Path,
) -> None:
    source, predecessor = _source_capture_predecessor(tmp_path)
    wrong = dict(predecessor)
    wrong["content_sha256"] = "e" * 64
    with pytest.raises(
        ReportAssemblyCaptureError,
        match="PREDECESSOR_CONTENT",
    ):
        RAC._build_report_assembly_final_capture(
            tmp_path,
            source_capture=source,
            expected_final_artifact_identity=(
                "scratchpad:report_assembly_final_capture.json"
            ),
            predecessor_binding=wrong,
            derived_outputs=_final_outputs(),
        )


@pytest.mark.parametrize(
    "mutation,match",
    (
        ({"run_id": "123e4567-e89b-42d3-a456-426614174001"}, "RUN"),
        (
            {
                "producer_work_unit_key": (
                    "sc/thorough/evm/claude/report_assemble/other"
                )
            },
            "PRODUCER",
        ),
    ),
)
def test_r2_final_builder_rejects_wrong_source_authority(
    tmp_path: Path,
    mutation: dict[str, str],
    match: str,
) -> None:
    source, predecessor = _source_capture_predecessor(tmp_path)
    predecessor.update(mutation)
    with pytest.raises(ReportAssemblyCaptureError, match=match):
        build_report_assembly_final_capture(
            tmp_path,
            source_capture=source,
            expected_final_artifact_identity=RAC.FINAL_CAPTURE_IDENTITY,
            predecessor_binding=predecessor,
            derived_outputs=_final_outputs(),
        )


def test_r2_final_rejects_wrong_external_kind_and_missing_predecessor(
    tmp_path: Path,
) -> None:
    source, predecessor = _source_capture_predecessor(tmp_path)
    with pytest.raises(ReportAssemblyCaptureError, match="FINAL_CAPTURE_IDENTITY"):
        build_report_assembly_final_capture(
            tmp_path,
            source_capture=source,
            expected_final_artifact_identity=RAC.SOURCE_CAPTURE_IDENTITY,
            predecessor_binding=predecessor,
            derived_outputs=_final_outputs(),
        )
    final = build_report_assembly_final_capture(
        tmp_path,
        source_capture=source,
        expected_final_artifact_identity=RAC.FINAL_CAPTURE_IDENTITY,
        predecessor_binding=predecessor,
        derived_outputs=_final_outputs(),
    )
    del final["predecessor_binding"]["commit_receipt_digest"]
    _resign_capture(final)
    with pytest.raises(
        ReportAssemblyCaptureError,
        match="PREDECESSOR_BINDING_SCHEMA",
    ):
        _validate_final(final, predecessor)


def test_r2_source_capture_output_extraction_is_forbidden(tmp_path: Path) -> None:
    source, predecessor = _source_capture_predecessor(tmp_path)
    with pytest.raises(ReportAssemblyCaptureError, match="CAPTURE_SCHEMA"):
        report_assembly_capture_output_bytes(
            source,
            expected_final_artifact_identity=(
                "scratchpad:report_assembly_final_capture.json"
            ),
            expected_predecessor_binding=predecessor,
        )


@pytest.mark.parametrize(
    "outputs",
    (
        (),
        ("AUDIT_REPORT.md",),
        ("AUDIT_REPORT.md", "report_quality.md"),
        (
            "AUDIT_REPORT.md",
            "report_quality.md",
            "report_traceability_internal.md",
        ),
        (
            "AUDIT_REPORT.md",
            "report_quality.md",
            "report_traceability_internal.md",
            "report_consolidation_internal.md",
            "report_evidence_quality_receipt.json",
            "report_assemble_retry_hint.md",
            "report_quality_debt.json",
            "unexpected.md",
        ),
    ),
)
def test_r2_captured_assembly_rejects_non_exact_output_denominator(
    outputs: tuple[str, ...],
) -> None:
    with pytest.raises(ValueError, match="exact seven-output denominator"):
        resolve_phase_io_contract(
            pipeline="sc",
            mode="thorough",
            ecosystem="evm",
            backend="claude",
            phase="report_assemble",
            work_unit_id="assembly",
            exact_inputs=("report_assembly_final_capture.json",),
            exact_outputs=outputs,
        )


def test_r2_final_capture_is_the_only_production_assembly_predecessor() -> None:
    outputs = (
        "AUDIT_REPORT.md",
        "report_quality.md",
        "report_traceability_internal.md",
        "report_consolidation_internal.md",
        "report_evidence_quality_receipt.json",
        "report_assemble_retry_hint.md",
        "report_quality_debt.json",
    )
    contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="report_assemble",
        work_unit_id="assembly",
        exact_inputs=("report_assembly_final_capture.json",),
        exact_outputs=outputs,
    )
    assert {row.identity for row in contract.outputs} == {
        "project:AUDIT_REPORT.md",
        *(f"scratchpad:{path}" for path in outputs[1:]),
    }
    assert contract.input_authority_requirements[0].identity == (
        "scratchpad:report_assembly_final_capture.json"
    )
    by_path = {row.path: row for row in contract.outputs}
    assert by_path["AUDIT_REPORT.md"].artifact_class == "DRIVER_GENERATED"
    assert by_path["report_quality.md"].artifact_class == "DRIVER_GENERATED"
    assert all(
        row.artifact_class == "CONDITIONAL" and row.condition_id
        for path, row in by_path.items()
        if path not in {"AUDIT_REPORT.md", "report_quality.md"}
    )
    assert all(
        row.schema_version
        in {
            "plamen.report_assembly_final_published_json.v1",
            "plamen.report_assembly_final_published_markdown.v1",
        }
        for row in contract.outputs
    )


def test_source_capture_and_appendix_projection_are_typed_predecessors() -> None:
    capture = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="report_assemble",
        work_unit_id="source_capture",
        exact_inputs=(
            "report_medium.md",
            "depth_finalization_receipt.json",
        ),
        exact_outputs=("report_assembly_source_capture.json",),
        exact_input_authorities={
            "report_medium.md": _source_authority("report_medium.md", 1),
            "depth_finalization_receipt.json": _source_authority(
                "depth_finalization_receipt.json", 2
            ),
        },
    )
    appendix = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="report_assemble",
        work_unit_id="appendix_projection",
        exact_inputs=("report_assembly_source_capture.json",),
        exact_outputs=(
            "report_human_review_appendix.json",
            "report_human_review_appendix.md",
        ),
    )
    final = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="report_assemble",
        work_unit_id="final_capture",
        exact_inputs=("report_assembly_source_capture.json",),
        exact_outputs=("report_assembly_final_capture.json",),
    )

    assert {row.identity for row in capture.outputs} == {
        "scratchpad:report_assembly_source_capture.json"
    }
    assert capture.outputs[0].schema_version == RAC.SOURCE_SCHEMA_VERSION
    assert {row.identity for row in final.outputs} == {
        "scratchpad:report_assembly_final_capture.json"
    }
    assert final.outputs[0].schema_version == RAC.FINAL_SCHEMA_VERSION
    assert final.input_authority_requirements[0].identity == (
        "scratchpad:report_assembly_source_capture.json"
    )
    assert {row.identity for row in appendix.outputs} == {
        "scratchpad:report_human_review_appendix.json",
        "scratchpad:report_human_review_appendix.md",
    }
    assert all(row.writer == "DRIVER" for row in (*capture.outputs, *appendix.outputs))
    assert {
        row.identity for row in capture.input_authority_requirements
    } == set(capture.immutable_inputs)
    assert all(
        not row.allow_raw
        and row.expected_producer_work_unit_key
        and row.expected_writer in {"MODEL", "DRIVER"}
        and row.expected_contract_digest
        and row.expected_launch_digest
        for row in capture.input_authority_requirements
    )
    assert all(not row.consumers for row in appendix.outputs)


def test_tier_capture_is_committed_before_pure_assembly() -> None:
    tier = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="report_assemble",
        work_unit_id="tier_capture",
        exact_inputs=("report_assembly_source_capture.json",),
        exact_outputs=(
            "report_assembly_tier_capture.json",
            "report_assembly_staged_index.md",
            "report_assembly_staged_critical_high.md",
            "report_assembly_staged_medium.md",
            "report_assembly_staged_low_info.md",
        ),
    )
    assert {row.identity for row in tier.outputs} == {
        "scratchpad:report_assembly_tier_capture.json",
        "scratchpad:report_assembly_staged_index.md",
        "scratchpad:report_assembly_staged_critical_high.md",
        "scratchpad:report_assembly_staged_medium.md",
        "scratchpad:report_assembly_staged_low_info.md",
    }
    assert all(row.writer == "DRIVER" for row in tier.outputs)
    assert all(not row.consumers for row in tier.outputs)


def test_source_capture_contract_rejects_raw_or_incomplete_input_authority() -> None:
    with pytest.raises(ValueError, match="exact producer authority"):
        resolve_phase_io_contract(
            pipeline="sc",
            mode="thorough",
            ecosystem="evm",
            backend="claude",
            phase="report_assemble",
            work_unit_id="source_capture",
            exact_inputs=("report_index.md",),
        )
    raw = InputAuthorityRequirement(
        identity="scratchpad:report_index.md",
        allow_raw=True,
        require_same_run=False,
        require_exact_contract=False,
        require_exact_launch=False,
    )
    with pytest.raises(ValueError, match="raw|producer authority"):
        resolve_phase_io_contract(
            pipeline="sc",
            mode="thorough",
            ecosystem="evm",
            backend="claude",
            phase="report_assemble",
            work_unit_id="source_capture",
            exact_inputs=("report_index.md",),
            exact_input_authorities={"report_index.md": raw},
        )


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("expected_producer_work_unit_key", "not/a/work/unit/key"),
        ("expected_contract_digest", "not-a-sha256"),
        ("expected_launch_digest", "not-a-sha256"),
        ("require_same_run", "yes"),
        ("require_exact_contract", 1),
        ("require_exact_launch", None),
    ],
)
def test_source_capture_revalidates_mutated_frozen_authority_objects(
    field: str,
    invalid: object,
) -> None:
    authority = _source_authority("report_index.md", 1)
    object.__setattr__(authority, field, invalid)
    with pytest.raises(ValueError, match="authority|boolean|SHA-256|work-unit"):
        resolve_phase_io_contract(
            pipeline="sc",
            mode="thorough",
            ecosystem="evm",
            backend="claude",
            phase="report_assemble",
            work_unit_id="source_capture",
            exact_inputs=("report_index.md",),
            exact_input_authorities={"report_index.md": authority},
        )


@pytest.mark.parametrize(
    "path",
    ("report. /index.md", "report /index.md", "nested/file.json. /child"),
)
def test_phaseio_shared_path_canonicalizer_rejects_windows_aliases(
    path: str,
) -> None:
    with pytest.raises(ValueError, match="Windows|alias|canonical"):
        PIO.canonical_artifact_identity("scratchpad", path)


def test_decomposed_projection_products_are_not_an_assembly_authority() -> None:
    inputs = (
        "report_assembly_source_capture.json",
        "report_assembly_tier_capture.json",
        "report_assembly_staged_index.md",
        "report_assembly_staged_critical_high.md",
        "report_assembly_staged_medium.md",
        "report_assembly_staged_low_info.md",
        "report_human_review_appendix.json",
        "report_human_review_appendix.md",
    )
    with pytest.raises(ValueError, match="sole production assembly predecessor"):
        resolve_phase_io_contract(
            pipeline="sc",
            mode="thorough",
            ecosystem="evm",
            backend="claude",
            phase="report_assemble",
            work_unit_id="assembly",
            exact_inputs=inputs,
        )


def test_captured_assembly_contract_rejects_partial_product_set() -> None:
    with pytest.raises(ValueError, match="sole production assembly predecessor"):
        resolve_phase_io_contract(
            pipeline="sc",
            mode="thorough",
            ecosystem="evm",
            backend="claude",
            phase="report_assemble",
            work_unit_id="assembly",
            exact_inputs=(
                "report_assembly_source_capture.json",
                "report_assembly_tier_capture.json",
            ),
        )


def test_monolithic_capture_is_a_closed_assembly_input() -> None:
    outputs = tuple(PIO._REPORT_ASSEMBLY_PUBLISH_OUTPUTS)
    contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="report_assemble",
        work_unit_id="assembly",
        exact_inputs=("report_assembly_final_capture.json",),
        exact_outputs=outputs,
    )
    assert contract.immutable_inputs == (
        "scratchpad:report_assembly_final_capture.json",
    )
    assert len(contract.input_authority_requirements) == 1
    assert contract.input_authority_requirements[0].expected_writer == "DRIVER"


def test_capture_records_present_absent_and_zero_member_namespaces(
    tmp_path: Path,
) -> None:
    (tmp_path / "report_index.md").write_text(
        "# Report index\n", encoding="utf-8"
    )
    expected_index_bytes = (tmp_path / "report_index.md").read_bytes()
    fixed = {
        "report_index.md": "REPORT_INDEX",
        "depth_finalization_receipt.json": "DEPTH_FINALIZATION_RECEIPT",
    }
    namespaces = {
        "report_semantic_*.md": "REPORT_SEMANTIC",
        "judge_*.md": "JUDGE_FALLBACK",
    }
    capture = build_report_assembly_source_capture(
        tmp_path,
        metadata=_CAPTURE_METADATA,
        fixed_source_roles=fixed,
        namespace_roles=namespaces,
    )
    validated = validate_report_assembly_source_capture(capture)

    rows = {row["path"]: row for row in validated["sources"]}
    assert rows["report_index.md"]["presence"] == "PRESENT"
    assert (
        base64.b64decode(rows["report_index.md"]["content_base64"])
        == expected_index_bytes
    )
    assert rows["depth_finalization_receipt.json"]["presence"] == "ABSENT"
    assert rows["depth_finalization_receipt.json"]["sha256"] == ""
    assert rows["depth_finalization_receipt.json"]["content_base64"] == ""
    assert validated["namespaces"] == sorted(
        validated["namespaces"], key=lambda row: row["pattern"]
    )
    assert all(row["member_count"] == 0 for row in validated["namespaces"])
    assert all(len(row["membership_digest"]) == 64 for row in validated["namespaces"])
    assert report_assembly_capture_exact_inputs(validated) == (
        "report_index.md",
    )
    assert report_assembly_capture_explicit_absences(validated) == (
        "depth_finalization_receipt.json",
    )


def test_capture_is_byte_deterministic_and_metadata_has_no_clock(
    tmp_path: Path,
) -> None:
    (tmp_path / "report_medium.md").write_bytes(b"# Medium\r\n")
    kwargs = {
        "metadata": _CAPTURE_METADATA,
        "fixed_source_roles": {"report_medium.md": "TIER_MEDIUM"},
        "namespace_roles": {"report_semantic_*.md": "REPORT_SEMANTIC"},
    }
    first = build_report_assembly_source_capture(tmp_path, **kwargs)
    second = build_report_assembly_source_capture(tmp_path, **kwargs)
    assert first == second
    assert set(first["metadata"]) == set(_CAPTURE_METADATA)
    assert not {"created_at", "captured_at", "timestamp"} & set(first["metadata"])


@pytest.mark.parametrize("mutation", ["change", "delete"])
def test_capture_replay_rejects_fixed_source_drift(
    tmp_path: Path, mutation: str
) -> None:
    source = tmp_path / "report_index.md"
    source.write_text("# Before\n", encoding="utf-8")
    capture = build_report_assembly_source_capture(
        tmp_path,
        metadata=_CAPTURE_METADATA,
        fixed_source_roles={"report_index.md": "REPORT_INDEX"},
        namespace_roles={"report_semantic_*.md": "REPORT_SEMANTIC"},
    )
    if mutation == "change":
        source.write_text("# After\n", encoding="utf-8")
    else:
        source.unlink()
    with pytest.raises(ReportAssemblyCaptureError, match="SOURCE_DRIFT"):
        replay_report_assembly_source_capture(tmp_path, capture)


def test_capture_replay_rejects_late_namespace_member(tmp_path: Path) -> None:
    capture = build_report_assembly_source_capture(
        tmp_path,
        metadata=_CAPTURE_METADATA,
        fixed_source_roles={"report_index.md": "REPORT_INDEX"},
        namespace_roles={"report_semantic_*.md": "REPORT_SEMANTIC"},
    )
    (tmp_path / "report_semantic_late.md").write_text(
        "# Late review debt\n", encoding="utf-8"
    )
    with pytest.raises(ReportAssemblyCaptureError, match="NAMESPACE_DRIFT"):
        replay_report_assembly_source_capture(tmp_path, capture)


@pytest.mark.parametrize("mutation", ["change", "delete"])
def test_capture_replay_rejects_namespace_member_drift(
    tmp_path: Path, mutation: str
) -> None:
    member = tmp_path / "report_semantic_existing.md"
    member.write_text("# Existing review debt\n", encoding="utf-8")
    capture = build_report_assembly_source_capture(
        tmp_path,
        metadata=_CAPTURE_METADATA,
        fixed_source_roles={},
        namespace_roles={"report_semantic_*.md": "REPORT_SEMANTIC"},
    )
    if mutation == "change":
        member.write_text("# Changed review debt\n", encoding="utf-8")
    else:
        member.unlink()
    with pytest.raises(ReportAssemblyCaptureError, match="NAMESPACE_DRIFT"):
        replay_report_assembly_source_capture(tmp_path, capture)


def test_capture_replay_rejects_fixed_absence_becoming_present(
    tmp_path: Path,
) -> None:
    capture = build_report_assembly_source_capture(
        tmp_path,
        metadata=_CAPTURE_METADATA,
        fixed_source_roles={"report_index.md": "REPORT_INDEX"},
        namespace_roles={},
    )
    (tmp_path / "report_index.md").write_text("# Late index\n", encoding="utf-8")
    with pytest.raises(ReportAssemblyCaptureError, match="SOURCE_DRIFT"):
        replay_report_assembly_source_capture(tmp_path, capture)


def test_capture_exact_replay_accepts_empty_input_denominator(
    tmp_path: Path,
) -> None:
    capture = build_report_assembly_source_capture(
        tmp_path,
        metadata=_CAPTURE_METADATA,
        fixed_source_roles={"report_index.md": "REPORT_INDEX"},
        namespace_roles={"report_semantic_*.md": "REPORT_SEMANTIC"},
    )
    assert capture["input_paths"] == []
    assert capture["explicit_absences"] == ["report_index.md"]
    assert replay_report_assembly_source_capture(tmp_path, capture) == capture


def test_capture_validation_rejects_content_and_digest_tamper(
    tmp_path: Path,
) -> None:
    (tmp_path / "report_index.md").write_text("# Index\n", encoding="utf-8")
    capture = build_report_assembly_source_capture(
        tmp_path,
        metadata=_CAPTURE_METADATA,
        fixed_source_roles={"report_index.md": "REPORT_INDEX"},
        namespace_roles={},
    )
    capture["sources"][0]["content_base64"] = base64.b64encode(
        b"tampered"
    ).decode("ascii")
    with pytest.raises(ReportAssemblyCaptureError, match="SOURCE_CONTENT"):
        validate_report_assembly_source_capture(capture)


def test_capture_carries_canonical_outputs_and_snapshot_location_decisions(
    tmp_path: Path,
) -> None:
    capture, predecessor = _build_final_capture(
        tmp_path,
        derived_outputs={
            "project:AUDIT_REPORT.md": ("CLIENT_REPORT", b"# Audit\r\n"),
            "scratchpad:report_quality.md": (
                "REPORT_QUALITY",
                b"# Quality\nPASS\n",
            ),
        },
        location_decisions=(
            {
                "decision": "RECOVERED_FROM_INDEX",
                "original_location": "missing/File.sol:L9",
                "report_id": "H-01",
                "resolved_location": "contracts/File.sol:L9",
                "source_paths": ["contracts/File.sol"],
                "source_snapshot_sha256": _CAPTURE_METADATA[
                    "source_snapshot_sha256"
                ],
            },
        ),
    )
    assert _output_bytes(capture, predecessor) == {
        "project:AUDIT_REPORT.md": b"# Audit\r\n",
        "scratchpad:report_quality.md": b"# Quality\nPASS\n",
    }
    assert capture["location_decisions"][0]["decision"] == (
        "RECOVERED_FROM_INDEX"
    )
    assert capture["location_decisions"][0]["source_snapshot_sha256"] == (
        capture["metadata"]["source_snapshot_sha256"]
    )


def test_source_capture_has_no_final_output_authority(tmp_path: Path) -> None:
    capture = build_report_assembly_source_capture(
        tmp_path,
        metadata=_CAPTURE_METADATA,
        fixed_source_roles={},
        namespace_roles={},
    )
    assert capture["schema_version"] == RAC.SOURCE_SCHEMA_VERSION
    assert "capture_kind" not in capture
    assert "derived_outputs" not in capture
    with pytest.raises(TypeError):
        build_report_assembly_source_capture(
            tmp_path,
            metadata=_CAPTURE_METADATA,
            fixed_source_roles={},
            namespace_roles={},
            derived_outputs=_final_outputs(),
        )


def test_final_capture_closes_exact_output_denominator(tmp_path: Path) -> None:
    capture, predecessor = _build_final_capture(tmp_path)
    rows = {
        f"{row['root']}:{row['path']}": row
        for row in capture["derived_outputs"]
    }
    assert set(rows) == set(RAC.ALLOWED_DERIVED_OUTPUT_ROLES)
    assert rows["project:AUDIT_REPORT.md"]["presence"] == "PRESENT"
    assert rows["scratchpad:report_quality.md"]["presence"] == "PRESENT"
    for identity in (
        "scratchpad:report_traceability_internal.md",
        "scratchpad:report_consolidation_internal.md",
        "scratchpad:report_evidence_quality_receipt.json",
        "scratchpad:report_assemble_retry_hint.md",
        "scratchpad:report_quality_debt.json",
    ):
        assert rows[identity]["presence"] == "ABSENT"
        assert rows[identity]["size"] == 0
        assert rows[identity]["sha256"] == ""
        assert rows[identity]["content_base64"] == ""
    assert _output_absences(capture, predecessor) == tuple(
        sorted(
            identity
            for identity, row in rows.items()
            if row["presence"] == "ABSENT"
        )
    )


def test_final_capture_promotes_conditional_to_present_bytes(tmp_path: Path) -> None:
    outputs = _final_outputs()
    conditional = "scratchpad:report_evidence_quality_receipt.json"
    outputs[conditional] = ("REPORT_EVIDENCE_QUALITY", b'{"status":"PASS"}\n')
    capture, predecessor = _build_final_capture(
        tmp_path, derived_outputs=outputs
    )
    assert _output_bytes(capture, predecessor)[conditional] == (
        b'{"status":"PASS"}\n'
    )
    assert conditional not in _output_absences(capture, predecessor)


@pytest.mark.parametrize(
    "missing",
    ("project:AUDIT_REPORT.md", "scratchpad:report_quality.md"),
)
def test_final_capture_rejects_absent_mandatory_output(
    tmp_path: Path, missing: str
) -> None:
    outputs = _final_outputs()
    del outputs[missing]
    with pytest.raises(
        ReportAssemblyCaptureError,
        match="OUTPUT_MANDATORY_ABSENT",
    ):
        _build_final_capture(tmp_path, derived_outputs=outputs)


@pytest.mark.parametrize("mutation", ("omit", "duplicate", "alias", "extra"))
def test_validator_rejects_non_exact_final_output_roster(
    tmp_path: Path, mutation: str
) -> None:
    capture, predecessor = _build_final_capture(tmp_path)
    rows = capture["derived_outputs"]
    if mutation == "omit":
        rows.pop(0)
    elif mutation == "duplicate":
        duplicate = dict(rows[0])
        duplicate["presence"] = "ABSENT"
        duplicate["size"] = 0
        duplicate["sha256"] = ""
        duplicate["content_base64"] = ""
        rows.append(duplicate)
    elif mutation == "alias":
        rows[0]["path"] = rows[0]["path"].upper()
    else:
        extra = dict(rows[0])
        extra["path"] = "unexpected.md"
        rows.append(extra)
    rows.sort(key=lambda row: (row["root"], row["path"]))
    _resign_capture(capture)
    with pytest.raises(
        ReportAssemblyCaptureError,
        match="OUTPUT_(DENOMINATOR|DUPLICATE|AUTHORITY)",
    ):
        _validate_final(capture, predecessor)


def test_validator_rejects_source_capture_with_output_rows(tmp_path: Path) -> None:
    source = build_report_assembly_source_capture(
        tmp_path,
        metadata=_CAPTURE_METADATA,
        fixed_source_roles={},
        namespace_roles={},
    )
    final, _ = _build_final_capture(tmp_path)
    source["derived_outputs"] = final["derived_outputs"]
    _resign_capture(source)
    with pytest.raises(ReportAssemblyCaptureError, match="CAPTURE_SCHEMA"):
        validate_report_assembly_source_capture(source)


def test_final_capture_fails_closed_on_stale_scratch_output_without_deleting(
    tmp_path: Path,
) -> None:
    stale = tmp_path / "report_quality_debt.json"
    original = b'{"old":true}\n'
    stale.write_bytes(original)
    with pytest.raises(ReportAssemblyCaptureError, match="OUTPUT_PREEXISTING"):
        _build_final_capture(tmp_path)
    assert stale.read_bytes() == original


def test_final_capture_replay_rejects_late_output_without_deleting(
    tmp_path: Path,
) -> None:
    capture, predecessor = _build_final_capture(tmp_path)
    late = tmp_path / "report_traceability_internal.md"
    original = b"# stale late output\n"
    late.write_bytes(original)
    with pytest.raises(ReportAssemblyCaptureError, match="OUTPUT_PREEXISTING"):
        replay_report_assembly_final_capture(
            tmp_path,
            capture,
            expected_final_artifact_identity=RAC.FINAL_CAPTURE_IDENTITY,
            expected_predecessor_binding=predecessor,
        )
    assert late.read_bytes() == original


def test_final_capture_replay_accepts_closed_output_namespace(
    tmp_path: Path,
) -> None:
    capture, predecessor = _build_final_capture(tmp_path)
    assert replay_report_assembly_final_capture(
        tmp_path,
        capture,
        expected_final_artifact_identity=RAC.FINAL_CAPTURE_IDENTITY,
        expected_predecessor_binding=predecessor,
    ) == capture


@pytest.mark.parametrize(
    "fixed",
    [
        {"Report.md": "FIRST", "report.md": "SECOND"},
        {"report. /index.md": "WINDOWS_ALIAS"},
        {"report /index.md": "WINDOWS_ALIAS"},
    ],
)
def test_capture_rejects_filesystem_equivalent_or_windows_aliased_fixed_paths(
    tmp_path: Path,
    fixed: dict[str, str],
) -> None:
    with pytest.raises(ReportAssemblyCaptureError, match="ALIAS|PATH"):
        build_report_assembly_source_capture(
            tmp_path,
            metadata=_CAPTURE_METADATA,
            fixed_source_roles=fixed,
            namespace_roles={},
        )


def test_capture_rejects_filesystem_equivalent_namespace_patterns(
    tmp_path: Path,
) -> None:
    with pytest.raises(ReportAssemblyCaptureError, match="ALIAS"):
        build_report_assembly_source_capture(
            tmp_path,
            metadata=_CAPTURE_METADATA,
            fixed_source_roles={},
            namespace_roles={
                "Judge_*.md": "JUDGE_ONE",
                "judge_*.md": "JUDGE_TWO",
            },
        )


def test_capture_rejects_filesystem_equivalent_location_source_paths(
    tmp_path: Path,
) -> None:
    with pytest.raises(ReportAssemblyCaptureError, match="LOCATION_SOURCE_PATHS"):
        _build_final_capture(
            tmp_path,
            location_decisions=(
                {
                    "decision": "RECOVERED_FROM_INDEX",
                    "original_location": "missing.sol:L1",
                    "report_id": "H-01",
                    "resolved_location": "Contracts/File.sol:L1",
                    "source_paths": [
                        "Contracts/File.sol",
                        "contracts/file.sol",
                    ],
                    "source_snapshot_sha256": _CAPTURE_METADATA[
                        "source_snapshot_sha256"
                    ],
                },
            ),
        )


@pytest.mark.parametrize(
    "alias",
    (
        "contracts/file.sol:L1",
        "contracts/file.sol:l1",
        "Contracts./File.sol:L1",
        "Contracts /File.sol:L1",
    ),
)
def test_capture_rejects_filesystem_equivalent_original_location_keys(
    tmp_path: Path,
    alias: str,
) -> None:
    def row(original: str, resolved: str) -> dict[str, object]:
        return {
            "decision": "RECOVERED_FROM_INDEX",
            "original_location": original,
            "report_id": "H-01",
            "resolved_location": resolved,
            "source_paths": ["Contracts/File.sol"],
            "source_snapshot_sha256": _CAPTURE_METADATA[
                "source_snapshot_sha256"
            ],
        }

    with pytest.raises(ReportAssemblyCaptureError, match="LOCATION.*ALIAS|PATH"):
        _build_final_capture(
            tmp_path,
            location_decisions=(
                row("Contracts/File.sol:L1", "Contracts/File.sol:L1"),
                row(alias, "Contracts/File.sol:L1"),
            ),
        )


def test_capture_rejects_source_and_scratch_output_identity_overlap(
    tmp_path: Path,
) -> None:
    with pytest.raises(ReportAssemblyCaptureError, match="OUTPUT.*SOURCE|OVERLAP"):
        _build_final_capture(
            tmp_path,
            fixed_source_roles={"report_quality.md": "OLD_REPORT_QUALITY"},
            derived_outputs={
                "project:AUDIT_REPORT.md": ("CLIENT_REPORT", b"# Audit\n"),
                "scratchpad:report_quality.md": (
                    "REPORT_QUALITY",
                    b"# New quality\n",
                ),
            },
        )


def test_validator_rejects_source_and_scratch_output_identity_overlap(
    tmp_path: Path,
) -> None:
    source_capture = build_report_assembly_source_capture(
        tmp_path,
        metadata=_CAPTURE_METADATA,
        fixed_source_roles={"report_quality.md": "OLD_REPORT_QUALITY"},
        namespace_roles={},
    )
    predecessor = {
        "artifact_identity": RAC.SOURCE_CAPTURE_IDENTITY,
        "content_sha256": hashlib.sha256(
            RAC._canonical_report_assembly_source_capture_bytes(source_capture)
        ).hexdigest(),
        "run_id": _CAPTURE_METADATA["run_id"],
        "producer_work_unit_key": (
            "sc/thorough/evm/claude/report_assemble/source_capture"
        ),
        "contract_digest": "b" * 64,
        "launch_digest": "c" * 64,
        "commit_receipt_digest": "d" * 64,
    }
    with pytest.raises(ReportAssemblyCaptureError, match="OUTPUT.*SOURCE|OVERLAP"):
        build_report_assembly_final_capture(
            tmp_path,
            source_capture=source_capture,
            expected_final_artifact_identity=RAC.FINAL_CAPTURE_IDENTITY,
            predecessor_binding=predecessor,
            derived_outputs=_final_outputs(),
        )


def test_capture_stats_size_before_reading_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "report_index.md"
    source.write_bytes(b"12345")
    monkeypatch.setattr(RAC, "_MAX_FILE_BYTES", 4)

    def forbidden_read(_self: Path) -> bytes:
        raise AssertionError("read_bytes called before stat size rejection")

    monkeypatch.setattr(Path, "read_bytes", forbidden_read)
    with pytest.raises(ReportAssemblyCaptureError, match="SOURCE_SIZE_LIMIT"):
        build_report_assembly_source_capture(
            tmp_path,
            metadata=_CAPTURE_METADATA,
            fixed_source_roles={"report_index.md": "REPORT_INDEX"},
            namespace_roles={},
        )


def _transient_same_size_symlink_read(
    source: Path,
    outside: Path,
):
    original_read = Path.read_bytes
    backup = source.with_name(f".{source.name}.safe-backup")

    def attacked_read(path: Path) -> bytes:
        if path != source:
            return original_read(path)
        source.replace(backup)
        try:
            source.symlink_to(outside)
            return original_read(source)
        finally:
            if source.is_symlink():
                source.unlink()
            backup.replace(source)

    return attacked_read


def test_capture_never_accepts_transient_same_size_symlink_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "report_index.md"
    outside = tmp_path.parent / f"{tmp_path.name}-outside.md"
    source.write_bytes(b"SAFE")
    outside.write_bytes(b"EVIL")
    probe = tmp_path / "symlink-probe"
    try:
        probe.symlink_to(outside)
        probe.unlink()
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")
    monkeypatch.setattr(
        Path,
        "read_bytes",
        _transient_same_size_symlink_read(source, outside),
    )

    capture = build_report_assembly_source_capture(
        tmp_path,
        metadata=_CAPTURE_METADATA,
        fixed_source_roles={"report_index.md": "REPORT_INDEX"},
        namespace_roles={},
    )
    observed = base64.b64decode(capture["sources"][0]["content_base64"])
    assert observed == b"SAFE"


def test_capture_replay_never_uses_path_following_read_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "report_index.md"
    outside = tmp_path.parent / f"{tmp_path.name}-outside.md"
    source.write_bytes(b"SAFE")
    outside.write_bytes(b"EVIL")
    capture = build_report_assembly_source_capture(
        tmp_path,
        metadata=_CAPTURE_METADATA,
        fixed_source_roles={"report_index.md": "REPORT_INDEX"},
        namespace_roles={},
    )
    probe = tmp_path / "symlink-probe"
    try:
        probe.symlink_to(outside)
        probe.unlink()
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")
    monkeypatch.setattr(
        Path,
        "read_bytes",
        _transient_same_size_symlink_read(source, outside),
    )

    assert replay_report_assembly_source_capture(tmp_path, capture) == capture


@pytest.mark.skipif(os.name != "nt", reason="Windows handle final-path contract")
def test_windows_source_handle_final_path_must_equal_requested_rooted_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "report_index.md").write_bytes(b"SAFE")
    outside = tmp_path.parent / f"{tmp_path.name}-outside.md"
    outside.write_bytes(b"EVIL")
    monkeypatch.setattr(
        RAC,
        "_windows_final_path",
        lambda _handle, *, relative: str(outside),
    )

    with pytest.raises(ReportAssemblyCaptureError, match="FINAL_PATH_ESCAPE"):
        build_report_assembly_source_capture(
            tmp_path,
            metadata=_CAPTURE_METADATA,
            fixed_source_roles={"report_index.md": "REPORT_INDEX"},
            namespace_roles={},
        )


@pytest.mark.skipif(os.name != "nt", reason="Windows handle identity contract")
def test_windows_source_handle_pre_post_identity_must_be_stable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "report_index.md").write_bytes(b"SAFE")
    original = RAC._windows_file_information
    calls = 0

    def drifted(handle, *, relative: str):
        nonlocal calls
        calls += 1
        info = original(handle, relative=relative)
        if calls == 2:
            info.nFileIndexLow ^= 1
        return info

    monkeypatch.setattr(RAC, "_windows_file_information", drifted)
    with pytest.raises(ReportAssemblyCaptureError, match="IDENTITY_DRIFT"):
        build_report_assembly_source_capture(
            tmp_path,
            metadata=_CAPTURE_METADATA,
            fixed_source_roles={"report_index.md": "REPORT_INDEX"},
            namespace_roles={},
        )


@pytest.mark.skipif(os.name != "nt", reason="Windows reparse handle contract")
def test_windows_source_handle_reparse_metadata_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "report_index.md").write_bytes(b"SAFE")
    original = RAC._windows_file_information

    def reparsed(handle, *, relative: str):
        info = original(handle, relative=relative)
        if relative != "<capture-root>":
            info.dwFileAttributes |= RAC._WIN_FILE_ATTRIBUTE_REPARSE_POINT
        return info

    monkeypatch.setattr(RAC, "_windows_file_information", reparsed)
    with pytest.raises(ReportAssemblyCaptureError, match="NOFOLLOW_REGULAR"):
        build_report_assembly_source_capture(
            tmp_path,
            metadata=_CAPTURE_METADATA,
            fixed_source_roles={"report_index.md": "REPORT_INDEX"},
            namespace_roles={},
        )


def test_capture_rejects_oversized_base64_before_decoder(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "report_index.md").write_bytes(b"x")
    capture = build_report_assembly_source_capture(
        tmp_path,
        metadata=_CAPTURE_METADATA,
        fixed_source_roles={"report_index.md": "REPORT_INDEX"},
        namespace_roles={},
    )
    capture["sources"][0]["content_base64"] = "A" * 100
    monkeypatch.setattr(RAC, "_MAX_FILE_BYTES", 1)

    def forbidden_decode(*_args, **_kwargs):
        raise AssertionError("base64 decoder called before encoded-size rejection")

    monkeypatch.setattr(RAC.base64, "b64decode", forbidden_decode)
    with pytest.raises(ReportAssemblyCaptureError, match="SOURCE_CONTENT_SIZE"):
        validate_report_assembly_source_capture(capture)


def test_capture_rejects_oversized_output_base64_before_decoder(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture, predecessor = _build_final_capture(
        tmp_path,
        derived_outputs={
            "project:AUDIT_REPORT.md": ("CLIENT_REPORT", b"x"),
            "scratchpad:report_quality.md": ("REPORT_QUALITY", b"q"),
        },
    )
    capture["derived_outputs"][0]["content_base64"] = "A" * 100
    monkeypatch.setattr(RAC, "_MAX_FILE_BYTES", 1)

    def forbidden_decode(*_args, **_kwargs):
        raise AssertionError("base64 decoder called before encoded-size rejection")

    monkeypatch.setattr(RAC.base64, "b64decode", forbidden_decode)
    with pytest.raises(ReportAssemblyCaptureError, match="OUTPUT_CONTENT_SIZE"):
        _validate_final(capture, predecessor)


def test_capture_rejects_bounded_path_roster_and_location_dimensions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with monkeypatch.context() as patch:
        patch.setattr(RAC, "_MAX_PATH_CHARS", 4)
        with pytest.raises(ReportAssemblyCaptureError, match="PATH_SIZE"):
            build_report_assembly_source_capture(
                tmp_path,
                metadata=_CAPTURE_METADATA,
                fixed_source_roles={"index.md": "INDEX"},
                namespace_roles={},
            )

    with monkeypatch.context() as patch:
        patch.setattr(RAC, "_MAX_NAMESPACE_COUNT", 1)
        with pytest.raises(ReportAssemblyCaptureError, match="NAMESPACE_SPEC_SCHEMA"):
            build_report_assembly_source_capture(
                tmp_path,
                metadata=_CAPTURE_METADATA,
                fixed_source_roles={},
                namespace_roles={"one_*.md": "ONE", "two_*.md": "TWO"},
            )

    with monkeypatch.context() as patch:
        patch.setattr(RAC, "_MAX_LOCATION_COUNT", 0)
        with pytest.raises(ReportAssemblyCaptureError, match="LOCATION_SCHEMA"):
            _build_final_capture(
                tmp_path,
                location_decisions=(
                    {
                        "decision": "NOT_APPLICABLE",
                        "original_location": "",
                        "report_id": "H-01",
                        "resolved_location": "",
                        "source_paths": [],
                        "source_snapshot_sha256": _CAPTURE_METADATA[
                            "source_snapshot_sha256"
                        ],
                    },
                ),
            )


def test_capture_rejects_oversized_whole_canonical_payload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(RAC, "_MAX_CANONICAL_BYTES", 512)
    with pytest.raises(ReportAssemblyCaptureError, match="CANONICAL_SIZE"):
        build_report_assembly_source_capture(
            tmp_path,
            metadata=_CAPTURE_METADATA,
            fixed_source_roles={},
            namespace_roles={},
        )


def test_capture_rejects_absent_path_below_symlinked_ancestor(
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    linked = tmp_path / "linked"
    try:
        linked.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")
    with pytest.raises(ReportAssemblyCaptureError, match="LINK_UNSAFE"):
        build_report_assembly_source_capture(
            tmp_path,
            metadata=_CAPTURE_METADATA,
            fixed_source_roles={"linked/missing.md": "ABSENT_BELOW_LINK"},
            namespace_roles={},
        )


@pytest.mark.skipif(os.name != "nt", reason="Windows descendant handle contract")
def test_capture_never_records_absence_from_reversible_deep_ancestor_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "root"
    parent = root / "a"
    original = parent / "b"
    replacement = parent / "replacement"
    backup = parent / "b-original"
    original.mkdir(parents=True)
    replacement.mkdir()
    source = original / "missing.md"
    source.write_bytes(b"PRESENT-BEFORE-AND-AFTER")
    original_create = RAC._CREATE_FILE_W
    attacked = False

    def reversible_swap_before_child_handle(*args):
        nonlocal attacked
        opened_path = os.path.normcase(str(args[0]).replace("\\\\?\\", ""))
        expected = os.path.normcase(str(original.absolute()))
        if not attacked and opened_path == expected:
            attacked = True
            original.rename(backup)
            replacement.rename(original)
            original.rename(replacement)
            backup.rename(original)
        return original_create(*args)

    monkeypatch.setattr(RAC, "_CREATE_FILE_W", reversible_swap_before_child_handle)
    with pytest.raises(ReportAssemblyCaptureError, match="PARENT|IDENTITY|DRIFT"):
        build_report_assembly_source_capture(
            root,
            metadata=_CAPTURE_METADATA,
            fixed_source_roles={"a/b/missing.md": "FIXED"},
            namespace_roles={},
        )

    assert attacked
    assert source.read_bytes() == b"PRESENT-BEFORE-AND-AFTER"


@pytest.mark.skipif(os.name != "nt", reason="Windows namespace handle contract")
def test_capture_namespace_does_not_use_reversible_fixed_prefix_path_glob(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "root"
    parent = root / "a"
    original = parent / "b"
    replacement = parent / "replacement"
    backup = parent / "b-original"
    original.mkdir(parents=True)
    replacement.mkdir()
    source = original / "report_1.json"
    source.write_bytes(b"PRESENT-BEFORE-AND-AFTER")
    original_scandir = RAC.os.scandir
    attacked = False

    def forbidden_legacy_glob(*_args, **_kwargs):
        raise AssertionError("capture namespace used path-based glob")

    def swap_during_handle_anchored_enumeration(path):
        nonlocal attacked
        normalized = os.path.normcase(str(path).replace("\\\\?\\", ""))
        if not attacked and normalized == os.path.normcase(str(original.absolute())):
            attacked = True
            original.rename(backup)
        return original_scandir(path)

    monkeypatch.setattr(Path, "glob", forbidden_legacy_glob)
    monkeypatch.setattr(RAC.os, "scandir", swap_during_handle_anchored_enumeration)
    with pytest.raises(ReportAssemblyCaptureError, match="NAMESPACE|IDENTITY|DRIFT"):
        build_report_assembly_source_capture(
            root,
            metadata=_CAPTURE_METADATA,
            fixed_source_roles={},
            namespace_roles={"a/b/report_*.json": "REPORTS"},
        )

    assert attacked
    assert source.read_bytes() == b"PRESENT-BEFORE-AND-AFTER"


@pytest.mark.skipif(os.name != "nt", reason="Windows handle lifecycle contract")
def test_capture_closes_every_root_directory_and_source_handle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "root"
    nested = root / "a" / "b" / "c"
    nested.mkdir(parents=True)
    (nested / "report_1.json").write_bytes(b"fixture")
    real_create = RAC._CREATE_FILE_W
    real_close = RAC._CLOSE_HANDLE
    outstanding: dict[int, int] = {}

    def tracked_create(*args):
        handle = real_create(*args)
        if handle != RAC._WIN_INVALID_HANDLE_VALUE:
            key = int(handle)
            outstanding[key] = outstanding.get(key, 0) + 1
        return handle

    def tracked_close(handle):
        key = int(handle)
        assert outstanding.get(key, 0) > 0
        outstanding[key] -= 1
        return real_close(handle)

    monkeypatch.setattr(RAC, "_CREATE_FILE_W", tracked_create)
    monkeypatch.setattr(RAC, "_CLOSE_HANDLE", tracked_close)
    capture = build_report_assembly_source_capture(
        root,
        metadata=_CAPTURE_METADATA,
        fixed_source_roles={"a/b/absent.md": "ABSENT"},
        namespace_roles={"a/b/**/*.json": "REPORTS"},
    )

    assert capture["namespaces"][0]["members"] == ["a/b/c/report_1.json"]
    assert all(count == 0 for count in outstanding.values())


def test_posix_child_directory_fstat_failure_closes_provisional_descriptor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed: list[int] = []
    monkeypatch.setattr(RAC.os, "open", lambda *_args, **_kwargs: 202)

    def failed_fstat(descriptor: int):
        assert descriptor == 202
        raise OSError("injected fstat failure")

    monkeypatch.setattr(RAC.os, "fstat", failed_fstat)
    monkeypatch.setattr(RAC.os, "close", closed.append)

    with pytest.raises(ReportAssemblyCaptureError, match="DIRECTORY|OPEN|STAT"):
        RAC._open_posix_child_directory(
            101,
            "child",
            0,
            error_code="TEST_DIRECTORY_OPEN",
            detail="fixture",
        )

    assert closed == [202]


def test_capture_rejects_lexical_root_swap_before_resolution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    backup = tmp_path / "root-backup"
    root.mkdir()
    outside.mkdir()
    (root / "report_index.md").write_bytes(b"SAFE")
    (outside / "report_index.md").write_bytes(b"EVIL")
    probe = tmp_path / "symlink-probe"
    try:
        probe.symlink_to(outside, target_is_directory=True)
        probe.unlink()
    except OSError as exc:
        pytest.skip(f"directory symlink creation unavailable: {exc}")
    original_is_dir = Path.is_dir
    swapped = False

    def swap_at_last_unpinned_root_check(path: Path) -> bool:
        nonlocal swapped
        if path == root.absolute() and not swapped:
            swapped = True
            root.rename(backup)
            root.symlink_to(outside, target_is_directory=True)
        return original_is_dir(path)

    monkeypatch.setattr(Path, "is_dir", swap_at_last_unpinned_root_check)
    with pytest.raises(ReportAssemblyCaptureError, match="ROOT|IDENTITY|LINK"):
        build_report_assembly_source_capture(
            root,
            metadata=_CAPTURE_METADATA,
            fixed_source_roles={"report_index.md": "REPORT_INDEX"},
            namespace_roles={},
        )
    assert swapped


def test_capture_rejects_in_root_hardlink_to_outside_file(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.md"
    outside.write_bytes(b"OUTSIDE-SECRET")
    try:
        os.link(outside, root / "report_index.md")
    except OSError as exc:
        pytest.skip(f"hardlink creation unavailable: {exc}")

    with pytest.raises(ReportAssemblyCaptureError, match="LINK|MULTI"):
        build_report_assembly_source_capture(
            root,
            metadata=_CAPTURE_METADATA,
            fixed_source_roles={"report_index.md": "REPORT_INDEX"},
            namespace_roles={},
        )


def test_source_aggregate_budget_rejects_before_any_base64_decode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "a.md").write_bytes(b"AAAA")
    (tmp_path / "b.md").write_bytes(b"BBBB")
    capture = build_report_assembly_source_capture(
        tmp_path,
        metadata=_CAPTURE_METADATA,
        fixed_source_roles={"a.md": "SOURCE_A", "b.md": "SOURCE_B"},
        namespace_roles={},
    )
    monkeypatch.setattr(RAC, "_MAX_TOTAL_BYTES", 4)

    def forbidden_decode(*_args, **_kwargs):
        raise AssertionError("source Base64 decoded before aggregate preflight")

    monkeypatch.setattr(RAC.base64, "b64decode", forbidden_decode)
    with pytest.raises(ReportAssemblyCaptureError, match="SOURCE_TOTAL_SIZE"):
        validate_report_assembly_source_capture(capture)


def test_output_aggregate_budget_rejects_before_any_base64_decode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture, predecessor = _build_final_capture(
        tmp_path,
        derived_outputs={
            "project:AUDIT_REPORT.md": ("CLIENT_REPORT", b"AAAA"),
            "scratchpad:report_quality.md": ("REPORT_QUALITY", b"BBBB"),
        },
    )
    monkeypatch.setattr(RAC, "_MAX_TOTAL_BYTES", 4)

    def forbidden_decode(*_args, **_kwargs):
        raise AssertionError("output Base64 decoded before aggregate preflight")

    monkeypatch.setattr(RAC.base64, "b64decode", forbidden_decode)
    with pytest.raises(ReportAssemblyCaptureError, match="CAPTURE_TOTAL_SIZE"):
        _validate_final(capture, predecessor)


@pytest.mark.parametrize(
    "path",
    tuple(
        [f"nested/{name}.report.md" for name in ("CON", "prn", "AuX", "nul")]
        + [f"nested/{prefix}{ordinal}.json" for prefix in ("com", "LPT") for ordinal in range(1, 10)]
        + [f"nested/{name}.json" for name in ("COM¹", "com²", "Com³", "LPT¹", "lpt²", "Lpt³")]
        + ["nested/CLOCK$.txt", "nested/conin$.md", "nested/CONOUT$.json"]
    ),
)
def test_capture_and_phaseio_reject_win32_reserved_device_components(
    tmp_path: Path,
    path: str,
) -> None:
    with pytest.raises(ReportAssemblyCaptureError, match="DEVICE|WINDOWS|PATH"):
        build_report_assembly_source_capture(
            tmp_path,
            metadata=_CAPTURE_METADATA,
            fixed_source_roles={path: "RESERVED_DEVICE"},
            namespace_roles={},
        )
    with pytest.raises(ValueError, match="device|Windows|path"):
        PIO.canonical_artifact_identity("scratchpad", path)


@pytest.mark.skipif(os.name != "nt", reason="Windows pre-open path identity")
def test_windows_source_rejects_same_size_replacement_before_handle_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "report_index.md"
    backup = tmp_path / "report_index.old.md"
    replacement = tmp_path / "report_index.new.md"
    source.write_bytes(b"SAFE")
    replacement.write_bytes(b"EVIL")
    original_create = RAC._CREATE_FILE_W
    swapped = False

    def swap_before_open(*args):
        nonlocal swapped
        opened_path = str(args[0]).replace("\\\\?\\", "")
        if not swapped and os.path.normcase(opened_path) == os.path.normcase(str(source.absolute())):
            swapped = True
            source.rename(backup)
            replacement.rename(source)
        return original_create(*args)

    monkeypatch.setattr(RAC, "_CREATE_FILE_W", swap_before_open)
    with pytest.raises(ReportAssemblyCaptureError, match="IDENTITY|DRIFT"):
        build_report_assembly_source_capture(
            tmp_path,
            metadata=_CAPTURE_METADATA,
            fixed_source_roles={"report_index.md": "REPORT_INDEX"},
            namespace_roles={},
        )
    assert swapped


@pytest.mark.skipif(os.name != "nt", reason="Windows post-read path identity")
def test_windows_source_rejects_same_size_path_identity_after_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "report_index.md"
    replacement = tmp_path / "report_index.replacement.md"
    source.write_bytes(b"SAFE")
    replacement.write_bytes(b"EVIL")
    original_read_once = RAC._windows_read_once
    original_lstat = RAC.os.lstat
    reads = 0

    def mark_post_read(*args, **kwargs):
        nonlocal reads
        result = original_read_once(*args, **kwargs)
        reads += 1
        return result

    def project_replacement_identity(path):
        if reads >= 2 and Path(path) == source:
            return original_lstat(replacement)
        return original_lstat(path)

    monkeypatch.setattr(RAC, "_windows_read_once", mark_post_read)
    monkeypatch.setattr(RAC.os, "lstat", project_replacement_identity)
    with pytest.raises(ReportAssemblyCaptureError, match="IDENTITY|DRIFT"):
        build_report_assembly_source_capture(
            tmp_path,
            metadata=_CAPTURE_METADATA,
            fixed_source_roles={"report_index.md": "REPORT_INDEX"},
            namespace_roles={},
        )
    assert reads == 2


@INTEGRATION_RED
def test_driver_assembly_input_enumerator_consumes_only_committed_capture_products(
    tmp_path: Path,
) -> None:
    (tmp_path / "report_assembly_final_capture.json").write_text(
        "{}\n", encoding="utf-8"
    )

    inputs = _driver()._report_assembly_input_paths(tmp_path)
    assert inputs == ("report_assembly_final_capture.json",)


@INTEGRATION_RED
def test_assembly_builder_is_pure_over_captured_inputs() -> None:
    """No live namespace, tier mutation, recovery, or appendix read remains."""

    forbidden = {
        "_build_sc_body_writer_manifests",
        "_normalize_tier_report_blocked_markers",
        "_build_human_review_appendix",
        "glob",
        "rglob",
    }
    assert not forbidden & _called_names(_mechanical()._assemble_report_python)


@INTEGRATION_RED
def test_no_quality_or_projection_writer_runs_between_assembly_arm_and_commit() -> None:
    """The armed assembly window contains only the pure assembly publication."""

    calls = _main_calls()
    arm_lines = [
        line for line, name in calls if name == "_arm_report_assembly_phase_io"
    ]
    commit_lines = [
        line for line, name in calls if name == "_commit_report_assembly_phase_io"
    ]
    assert arm_lines and commit_lines
    arm = min(arm_lines)
    commit = min(line for line in commit_lines if line > arm)
    between = {name for line, name in calls if arm < line < commit}
    assert not {
        "_project_exact_scope_coverage_limitations",
        "_project_report_evidence_file",
        "_run_report_quality_gate",
        "_normalize_tier_report_blocked_markers",
        "_build_sc_body_writer_manifests",
    } & between


def test_unknown_report_semantic_path_added_after_arm_is_detected(
    tmp_path: Path,
) -> None:
    """Source-capture replay rejects a namespace gain after its PhaseIO arm."""

    project, scratch, config, _snapshot, metadata = _authority_fixture(tmp_path)
    prepared = RCA.prepare_report_source_capture(
        scratchpad=scratch,
        project_root=project,
        run_id=_CAPTURE_METADATA["run_id"],
        expected_config=config,
        metadata=metadata,
        fixed_source_roles={},
        namespace_roles={
            "report_semantic_*.md": "REPORT_SEMANTIC_NAMESPACE"
        },
    )
    record_work_unit_inputs(
        scratch,
        project,
        prepared.contract,
        prepared.launch,
        run_id=_CAPTURE_METADATA["run_id"],
    )

    (scratch / "report_semantic_new_gap.md").write_text(
        "# New gap\n\nA substantive fixture debt appeared after capture.\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="NAMESPACE|SOURCE|drift"):
        RCA.validate_report_source_candidate_bytes(
            scratchpad=scratch,
            project_root=project,
            run_id=_CAPTURE_METADATA["run_id"],
            expected_config=config,
            source_capture_bytes=prepared.capture_bytes,
            expected_contract=prepared.contract,
            expected_launch=prepared.launch,
        )


@INTEGRATION_RED
def test_first_report_publication_requires_absent_project_report() -> None:
    from report_assembly_publication import (  # type: ignore[import-not-found]
        validate_project_report_publication_prestate,
    )

    assert validate_project_report_publication_prestate(
        {"status": "ABSENT", "sha256": "", "size": 0},
        run_id=_CAPTURE_METADATA["run_id"],
        predecessor=None,
    ) == "CREATE_EXCLUSIVE"
    with pytest.raises(ValueError, match="preexisting|foreign|prestate"):
        validate_project_report_publication_prestate(
            {"status": "PRESENT", "sha256": "a" * 64, "size": 7},
            run_id=_CAPTURE_METADATA["run_id"],
            predecessor=None,
        )


@INTEGRATION_RED
def test_report_republication_requires_registered_same_run_predecessor() -> None:
    from report_assembly_publication import (  # type: ignore[import-not-found]
        validate_project_report_publication_prestate,
    )

    prestate = {"status": "PRESENT", "sha256": "a" * 64, "size": 7}
    predecessor = {
        "owner_key": "sc/thorough/evm/claude/report_floor/assurance_projection",
        "run_id": _CAPTURE_METADATA["run_id"],
        "sha256": "a" * 64,
        "size": 7,
        "status": "ACTIVE",
    }
    assert validate_project_report_publication_prestate(
        prestate,
        run_id=_CAPTURE_METADATA["run_id"],
        predecessor=predecessor,
    ) == "REGISTERED_PREDECESSOR_CAS"
    with pytest.raises(ValueError, match="predecessor|same.run|registered"):
        validate_project_report_publication_prestate(
            prestate,
            run_id=_CAPTURE_METADATA["run_id"],
            predecessor={**predecessor, "run_id": "foreign-run"},
        )


def test_monolithic_assembly_declares_every_captured_report_side_effect() -> None:
    outputs = (
        "report_quality.md",
        "report_traceability_internal.md",
        "report_consolidation_internal.md",
        "report_evidence_quality_receipt.json",
        "report_assemble_retry_hint.md",
        "report_quality_debt.json",
        "AUDIT_REPORT.md",
    )
    contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="report_assemble",
        work_unit_id="assembly",
        exact_inputs=("report_assembly_final_capture.json",),
        exact_outputs=outputs,
    )
    identities = {row.identity for row in contract.outputs}
    assert "project:AUDIT_REPORT.md" in identities
    assert {
        f"scratchpad:{name}" for name in outputs if name != "AUDIT_REPORT.md"
    }.issubset(identities)


@INTEGRATION_RED
def test_report_records_recovery_is_removed_from_live_assembly() -> None:
    assert "_build_sc_body_writer_manifests" not in _called_names(
        _mechanical()._assemble_report_python
    )
