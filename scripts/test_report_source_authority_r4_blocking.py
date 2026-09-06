"""Blocking R4 fixtures for config-bound report-source authority.

These tests intentionally exercise the public P2 boundary.  A caller-created
capture/producer can be byte-consistent and committed while still disagreeing
with the audit snapshot's production-source roster; that disagreement must be
rejected before preparation and again before committed extraction.
"""
from __future__ import annotations

import ast
from pathlib import Path
import sys

import pytest


SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(ROOT))

from audit_snapshot import (  # noqa: E402
    build_audit_snapshot,
    build_production_source_path_authority,
    canonical_production_source_path_authority_bytes,
)
import plamen_driver as driver  # noqa: E402
import report_capture_phaseio_authority as RCA  # noqa: E402
from test_report_source_authority_r3_repair import (  # noqa: E402
    RUN_ID,
    _commit_contradictory_source_capture,
    _commit_contract,
    _fixture,
    _generic_commit,
    _launch,
    _redigest_authority,
)


def _commit_forged_registered_roster(
    tmp_path: Path,
):
    project, scratch, config, snapshot, metadata = _fixture(tmp_path)
    authority = build_production_source_path_authority(config, snapshot)
    forged = _redigest_authority(authority, ["src/Other.sol"])
    # The attack is internally canonical and snapshot-labelled.  Only the
    # authenticated config roster distinguishes it from the true Vault.sol
    # denominator.
    raw = canonical_production_source_path_authority_bytes(
        forged,
        expected_snapshot=snapshot,
    )
    contract, launch = driver._report_source_path_authority_contract_and_launch(
        config
    )
    _commit_contract(
        project,
        scratch,
        contract,
        launch,
        {"report_source_path_authority.json": raw},
    )
    return project, scratch, config, metadata, contract, launch


def test_config_roster_mismatch_rejected_during_prepare(tmp_path: Path) -> None:
    project, scratch, config, metadata, _contract, _launch_spec = (
        _commit_forged_registered_roster(tmp_path)
    )
    with pytest.raises(ValueError, match="roster|config|source"):
        RCA.prepare_report_source_capture(
            scratchpad=scratch,
            project_root=project,
            run_id=RUN_ID,
            expected_config=config,
            metadata=metadata,
            fixed_source_roles={
                "report_source_path_authority.json": (
                    "PRODUCTION_SOURCE_PATH_AUTHORITY"
                )
            },
            namespace_roles={},
        )


def test_config_roster_mismatch_rejected_during_committed_extraction(
    tmp_path: Path,
) -> None:
    project, scratch, config, metadata, contract, launch = (
        _commit_forged_registered_roster(tmp_path)
    )
    _commit_contradictory_source_capture(
        project,
        scratch,
        metadata,
        contract,
        launch,
    )
    with pytest.raises(ValueError, match="roster|config|source"):
        RCA.extract_committed_report_source_inputs(
            scratchpad=scratch,
            project_root=project,
            run_id=RUN_ID,
            expected_config=config,
        )


def test_different_expected_config_rejects_committed_capture_replay(
    tmp_path: Path,
) -> None:
    project, scratch, config, _snapshot, metadata = _fixture(tmp_path)
    assert driver._run_report_source_path_authority_transaction(
        scratch, config
    ) == []
    prepared = RCA.prepare_report_source_capture(
        scratchpad=scratch,
        project_root=project,
        run_id=RUN_ID,
        expected_config=config,
        metadata=metadata,
        fixed_source_roles={
            "report_source_path_authority.json": (
                "PRODUCTION_SOURCE_PATH_AUTHORITY"
            )
        },
        namespace_roles={},
    )
    _commit_contract(
        project,
        scratch,
        prepared.contract,
        prepared.launch,
        {"report_assembly_source_capture.json": prepared.capture_bytes},
    )

    # A second, internally valid config/snapshot for the same roots now has a
    # different production roster.  Replay must not accept the old capture.
    (project / "src" / "Other.sol").write_text("contract Other {}\n")
    changed = dict(config)
    changed.pop("_audit_snapshot")
    changed["_audit_snapshot"] = build_audit_snapshot(
        changed, tmp_path / "plamen"
    )
    with pytest.raises(ValueError, match="roster|snapshot|config|source"):
        RCA.extract_committed_report_source_inputs(
            scratchpad=scratch,
            project_root=project,
            run_id=RUN_ID,
            expected_config=changed,
        )


def test_roster_binding_metadata_is_adapter_owned(tmp_path: Path) -> None:
    project, scratch, config, _snapshot, metadata = _fixture(tmp_path)
    caller_metadata = dict(metadata)
    caller_metadata["source_roster_authority_sha256"] = "f" * 64
    with pytest.raises(ValueError, match="adapter-owned|caller"):
        RCA.prepare_report_source_capture(
            scratchpad=scratch,
            project_root=project,
            run_id=RUN_ID,
            expected_config=config,
            metadata=caller_metadata,
            fixed_source_roles={},
            namespace_roles={},
        )


@pytest.mark.parametrize(
    ("fixed", "namespaces", "relative"),
    [
        ({"caller_added.md": "CALLER_ADDED"}, {}, "caller_added.md"),
        ({}, {"caller_added/*.md": "CALLER_ADDED_NAMESPACE"}, "caller_added/x.md"),
    ],
)
def test_caller_added_selector_rejected_despite_committed_generic_producer(
    tmp_path: Path,
    fixed: dict[str, str],
    namespaces: dict[str, str],
    relative: str,
) -> None:
    project, scratch, config, _snapshot, metadata = _fixture(tmp_path)
    _generic_commit(
        project,
        scratch,
        relative,
        b"# caller-added\n",
        writer="DRIVER",
    )
    with pytest.raises(ValueError, match="selector|registry|role|policy"):
        RCA.prepare_report_source_capture(
            scratchpad=scratch,
            project_root=project,
            run_id=RUN_ID,
            expected_config=config,
            metadata=metadata,
            fixed_source_roles=fixed,
            namespace_roles=namespaces,
        )


def test_public_p2_source_consumers_require_expected_config() -> None:
    names = {
        "prepare_report_source_capture",
        "validate_report_source_candidate_bytes",
        "load_committed_report_source_capture_bytes",
        "extract_committed_report_source_inputs",
        "build_report_final_capture_bytes",
        "validate_report_final_candidate_bytes",
        "load_committed_report_final_capture_bytes",
        "extract_committed_report_outputs",
        "prepare_committed_report_publication",
        "resolve_exact_report_input_authorities",
    }
    tree = ast.parse(Path(RCA.__file__).read_text(encoding="utf-8"))
    functions = {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert names <= functions.keys()
    for name in sorted(names):
        assert "expected_config" in {
            argument.arg for argument in functions[name].args.kwonlyargs
        }, name


def test_production_driver_report_authority_calls_bind_expected_config() -> None:
    tree = ast.parse(Path(driver.__file__).read_text(encoding="utf-8"))
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "resolve_exact_report_input_authorities"
    ]
    # This non-vacuous denominator covers both current production callers.
    assert len(calls) == 2
    for call in calls:
        keywords = {row.arg: row.value for row in call.keywords if row.arg}
        assert isinstance(keywords.get("expected_config"), ast.Name)
        assert keywords["expected_config"].id == "config"


def test_r3_policy_inventory_digest_is_unchanged() -> None:
    rows = RCA.report_source_policy_inventory()
    import hashlib
    import json

    digest = hashlib.sha256(
        json.dumps(
            rows,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest().upper()
    assert digest == (
        "4E28E1F6925A53CF2B45B7318D892464"
        "4F3D92FDC8AD1F05C4107C77AB3704A1"
    )
