"""Fixture-first adversarial tests for the P0-P2 report authority repair."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import re
import sys

import pytest


SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(ROOT))

from artifact_ledger import (  # noqa: E402
    record_work_unit_artifacts,
    record_work_unit_inputs,
)
from audit_snapshot import (  # noqa: E402
    SnapshotInputError,
    build_audit_snapshot,
    build_production_source_path_authority,
    canonical_production_source_path_authority_bytes,
    validate_production_source_path_authority,
)
from phase_io_contracts import (  # noqa: E402
    ArtifactSpec,
    InputAuthorityRequirement,
    LaunchSpec,
    PhaseIOContract,
    resolve_phase_io_contract,
)
import plamen_driver as driver  # noqa: E402
import report_assembly_capture as codec  # noqa: E402
import report_capture_phaseio_authority as RCA  # noqa: E402


RUN_ID = "123e4567-e89b-42d3-a456-426614174000"
DIMS = {
    "pipeline": "sc",
    "mode": "thorough",
    "ecosystem": "evm",
    "backend": "claude",
}


def _implementation(root: Path) -> Path:
    for directory in ("scripts", "prompts", "rules", "agents"):
        (root / directory).mkdir(parents=True, exist_ok=True)
    (root / "scripts" / "plamen_driver.py").write_text("VERSION = 1\n")
    (root / "prompts" / "phase.md").write_text("method v1\n")
    (root / "rules" / "rule.md").write_text("rule v1\n")
    return root


def _fixture(tmp_path: Path):
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    (project / "src").mkdir(parents=True)
    (project / "src" / "Vault.sol").write_text("contract Vault {}\n")
    implementation = _implementation(tmp_path / "plamen")
    config = {
        "project_root": str(project),
        "scratchpad": str(scratch),
        "mode": "thorough",
        "pipeline": "sc",
        "language": "evm",
        "cli_backend": "claude",
        "_run_id": RUN_ID,
    }
    snapshot = build_audit_snapshot(config, implementation)
    config["_audit_snapshot"] = snapshot
    scratch.mkdir()
    metadata = {
        **DIMS,
        "project_name": "fixture-project",
        "report_date": "2026-08-04",
        "run_id": RUN_ID,
        "scope": "src/",
        "source_snapshot_sha256": snapshot["snapshot_digest"],
    }
    return project, scratch, config, snapshot, metadata


def _launch(contract: PhaseIOContract, *, model: str = "driver") -> LaunchSpec:
    return LaunchSpec(
        work_unit_key=contract.key,
        **DIMS,
        model=model,
        timeout_s=30,
        exec_mode="python",
        tool_policy=("filesystem",),
    )


def _commit_contract(
    project: Path,
    scratch: Path,
    contract: PhaseIOContract,
    launch: LaunchSpec,
    outputs: dict[str, bytes],
    *,
    actor: str = "DRIVER",
) -> None:
    record_work_unit_inputs(scratch, project, contract, launch, run_id=RUN_ID)
    for relative, raw in outputs.items():
        target = scratch / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    record_work_unit_artifacts(
        scratch,
        project,
        contract,
        launch,
        run_id=RUN_ID,
        actor=actor,
    )


def _generic_commit(
    project: Path,
    scratch: Path,
    relative: str,
    raw: bytes,
    *,
    writer: str,
) -> None:
    key = f"sc/thorough/evm/claude/report_fixture/generic_{writer.lower()}"
    contract = PhaseIOContract(
        **DIMS,
        phase="report_fixture",
        work_unit_id=f"generic_{writer.lower()}",
        outputs=(
            ArtifactSpec(
                root="scratchpad",
                path=relative,
                owner_key=key,
                artifact_class=("REQUIRED" if writer == "MODEL" else "DRIVER_GENERATED"),
                writer=writer,
                write_mode="CREATE",
            ),
        ),
        model_invoked=writer == "MODEL",
    )
    _commit_contract(
        project,
        scratch,
        contract,
        _launch(contract, model="sonnet" if writer == "MODEL" else "driver"),
        {relative: raw},
        actor=writer,
    )


def _input_requirement(
    contract: PhaseIOContract, launch: LaunchSpec, relative: str, writer: str
) -> InputAuthorityRequirement:
    return InputAuthorityRequirement(
        identity=f"scratchpad:{relative}",
        allow_raw=False,
        expected_producer_work_unit_key=contract.key,
        expected_writer=writer,
        require_same_run=True,
        expected_contract_digest=contract.digest,
        expected_launch_digest=launch.digest,
        require_exact_contract=True,
        require_exact_launch=True,
    )


def _commit_contradictory_source_capture(
    project: Path,
    scratch: Path,
    metadata: dict[str, str],
    producer_contract: PhaseIOContract,
    producer_launch: LaunchSpec,
) -> None:
    bound_metadata = dict(metadata)
    if "source_roster_authority_sha256" not in bound_metadata:
        authority = json.loads(
            (scratch / "report_source_path_authority.json").read_text(
                encoding="utf-8"
            )
        )
        bound_metadata["source_roster_authority_sha256"] = authority[
            "authority_digest"
        ]
    payload = codec._capture_report_assembly_source(
        scratch,
        metadata=bound_metadata,
        fixed_source_roles={
            "report_source_path_authority.json": (
                "PRODUCTION_SOURCE_PATH_AUTHORITY"
            )
        },
        namespace_roles={},
    )
    raw = codec._canonical_report_assembly_source_capture_bytes(payload)
    requirement = _input_requirement(
        producer_contract,
        producer_launch,
        "report_source_path_authority.json",
        "DRIVER",
    )
    contract = resolve_phase_io_contract(
        **DIMS,
        phase="report_assemble",
        work_unit_id="source_capture",
        exact_inputs=("report_source_path_authority.json",),
        exact_outputs=("report_assembly_source_capture.json",),
        exact_input_authorities={
            "report_source_path_authority.json": requirement
        },
    )
    launch = _launch(contract)
    _commit_contract(
        project,
        scratch,
        contract,
        launch,
        {"report_assembly_source_capture.json": raw},
    )


def _redigest_authority(authority: dict, paths: list[str]) -> dict:
    forged = copy.deepcopy(authority)
    forged["source_paths"] = paths
    forged["source_path_count"] = len(paths)
    canonical = json.dumps(
        paths, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    forged["source_path_set_digest"] = hashlib.sha256(canonical).hexdigest()
    unsigned = dict(forged)
    unsigned.pop("authority_digest")
    forged["authority_digest"] = hashlib.sha256(
        json.dumps(
            unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    ).hexdigest()
    return forged


def _valid_reserved_bytes(
    relative: str,
    scratch: Path,
    config: dict,
    snapshot: dict,
) -> bytes:
    if relative == "report_source_path_authority.json":
        authority = build_production_source_path_authority(config, snapshot)
        return canonical_production_source_path_authority_bytes(
            authority,
            expected_snapshot=snapshot,
            expected_config=config,
        )
    if relative == "depth_finalization_report_authority.json":
        return driver._depth_finalization_report_authority_bytes(
            scratch,
            {
                "status": "FINALIZED",
                "source_digest": "d" * 64,
                "processors": {
                    "enumeration_gate": {"status": "COMPLETE"},
                },
            },
            run_id=RUN_ID,
            phase_name="depth",
        )
    unsigned = {
        "schema": "plamen.report_human_review_authority.v1",
        "run_id": RUN_ID,
        "contract_digest": "a" * 64,
        "launch_digest": "b" * 64,
        "inputs": [
            {
                "identity": "scratchpad:report_coverage.md",
                "sha256": "c" * 64,
                "size": 1,
            },
            {
                "identity": "scratchpad:report_index.md",
                "sha256": "d" * 64,
                "size": 1,
            },
        ],
        "sections": [
            {
                "identity": "scratchpad:report_semantic_retention_risks.md",
                "presence": "ABSENT",
                "sha256": "",
                "size": 0,
            },
            {
                "identity": "scratchpad:report_semantic_severity_repairs.md",
                "presence": "ABSENT",
                "sha256": "",
                "size": 0,
            },
        ],
    }
    payload = {
        **unsigned,
        "authority_digest": hashlib.sha256(
            json.dumps(
                unsigned,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
        ).hexdigest(),
    }
    return (
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        + "\n"
    ).encode("utf-8")


def test_snapshot_authority_s_capture_metadata_t_rejected_before_prepare(
    tmp_path: Path,
) -> None:
    project, scratch, config, snapshot, metadata = _fixture(tmp_path)
    assert driver._run_report_source_path_authority_transaction(scratch, config) == []
    contradictory = dict(metadata)
    contradictory["source_snapshot_sha256"] = "f" * 64
    with pytest.raises(ValueError, match="snapshot|metadata|authority"):
        RCA.prepare_report_source_capture(
            scratchpad=scratch,
            project_root=project,
            run_id=RUN_ID,
            expected_config=config,
            metadata=contradictory,
            fixed_source_roles={
                "report_source_path_authority.json": (
                    "PRODUCTION_SOURCE_PATH_AUTHORITY"
                )
            },
            namespace_roles={},
        )


def test_extraction_never_surfaces_snapshot_metadata_contradiction(
    tmp_path: Path,
) -> None:
    project, scratch, config, _snapshot, metadata = _fixture(tmp_path)
    assert driver._run_report_source_path_authority_transaction(scratch, config) == []
    producer_contract, producer_launch = (
        driver._report_source_path_authority_contract_and_launch(config)
    )
    contradictory = dict(metadata)
    contradictory["source_snapshot_sha256"] = "f" * 64
    _commit_contradictory_source_capture(
        project,
        scratch,
        contradictory,
        producer_contract,
        producer_launch,
    )
    with pytest.raises(ValueError, match="snapshot|metadata|authority"):
        RCA.extract_committed_report_source_inputs(
            scratchpad=scratch,
            project_root=project,
            run_id=RUN_ID,
            expected_config=config,
        )


@pytest.mark.parametrize(
    "path",
    [
        "C:/Vault.sol",
        "C:\\Vault.sol",
        "//server/share/Vault.sol",
        "\\\\server\\share\\Vault.sol",
        "/src/Vault.sol",
        "src\\Vault.sol",
        "./src/Vault.sol",
        "src/../Vault.sol",
        "src//Vault.sol",
        "src/\x01Vault.sol",
        "src/Vault.sol.",
        "src/Vault.sol ",
        "src/NUL.sol",
        "",
    ],
)
def test_source_path_authority_rejects_cross_os_noncanonical_rosters(
    tmp_path: Path, path: str
) -> None:
    _project, _scratch, config, snapshot, _metadata = _fixture(tmp_path)
    authority = build_production_source_path_authority(config, snapshot)
    forged = _redigest_authority(authority, [path])
    with pytest.raises(SnapshotInputError, match="path|roster|content|authority"):
        validate_production_source_path_authority(
            forged,
            expected_snapshot=snapshot,
        )


def test_source_path_authority_accepts_canonical_relative_posix_cross_os(
    tmp_path: Path,
) -> None:
    _project, _scratch, config, snapshot, _metadata = _fixture(tmp_path)
    authority = build_production_source_path_authority(config, snapshot)
    canonical = _redigest_authority(authority, ["contracts/core/Vault.sol"])
    assert validate_production_source_path_authority(canonical)[
        "source_paths"
    ] == ["contracts/core/Vault.sol"]


def test_source_path_authority_recomputes_exact_bound_config_roster(
    tmp_path: Path,
) -> None:
    _project, _scratch, config, snapshot, _metadata = _fixture(tmp_path)
    authority = build_production_source_path_authority(config, snapshot)
    forged = _redigest_authority(authority, ["src/Other.sol"])
    with pytest.raises(SnapshotInputError, match="roster|source|config"):
        validate_production_source_path_authority(
            forged,
            expected_snapshot=snapshot,
            expected_config=config,
        )


@pytest.mark.parametrize(
    ("relative", "role"),
    [
        (
            "report_source_path_authority.json",
            "PRODUCTION_SOURCE_PATH_AUTHORITY",
        ),
        (
            "depth_finalization_report_authority.json",
            "DEPTH_FINALIZATION_REPORT_AUTHORITY",
        ),
        (
            "report_human_review_authority.json",
            "REPORT_HUMAN_REVIEW_AUTHORITY",
        ),
    ],
)
@pytest.mark.parametrize("writer", ["DRIVER", "MODEL", "RAW"])
def test_generic_or_raw_work_unit_cannot_impersonate_reserved_report_authority(
    tmp_path: Path, relative: str, role: str, writer: str
) -> None:
    project, scratch, config, snapshot, metadata = _fixture(tmp_path)
    raw = _valid_reserved_bytes(relative, scratch, config, snapshot)
    if writer == "RAW":
        (scratch / relative).write_bytes(raw)
    else:
        _generic_commit(project, scratch, relative, raw, writer=writer)
    with pytest.raises(ValueError, match="producer|owner|authority|content|RAW"):
        RCA.prepare_report_source_capture(
            scratchpad=scratch,
            project_root=project,
            run_id=RUN_ID,
            expected_config=config,
            metadata=metadata,
            fixed_source_roles={relative: role},
            namespace_roles={},
        )


@pytest.mark.parametrize(
    ("relative", "phase", "work_unit", "role"),
    [
        (
            "report_source_path_authority.json",
            "report_assemble",
            "source_path_authority",
            "PRODUCTION_SOURCE_PATH_AUTHORITY",
        ),
        (
            "depth_finalization_report_authority.json",
            "depth",
            "finalization_report_authority",
            "DEPTH_FINALIZATION_REPORT_AUTHORITY",
        ),
    ],
)
def test_registered_reserved_owner_with_invalid_content_is_rejected(
    tmp_path: Path,
    relative: str,
    phase: str,
    work_unit: str,
    role: str,
) -> None:
    project, scratch, config, _snapshot, metadata = _fixture(tmp_path)
    contract = resolve_phase_io_contract(
        **DIMS,
        phase=phase,
        work_unit_id=work_unit,
        exact_inputs=(),
        exact_outputs=(relative,),
    )
    _commit_contract(
        project, scratch, contract, _launch(contract), {relative: b'{}\n'}
    )
    with pytest.raises(ValueError, match="schema|content|authority"):
        RCA.prepare_report_source_capture(
            scratchpad=scratch,
            project_root=project,
            run_id=RUN_ID,
            expected_config=config,
            metadata=metadata,
            fixed_source_roles={relative: role},
            namespace_roles={},
        )


def test_registered_human_review_owner_with_invalid_content_is_rejected(
    tmp_path: Path,
) -> None:
    project, scratch, config, _snapshot, metadata = _fixture(tmp_path)
    input_key = "sc/thorough/evm/claude/report_fixture/human_inputs"
    input_contract = PhaseIOContract(
        **DIMS,
        phase="report_fixture",
        work_unit_id="human_inputs",
        outputs=tuple(
            ArtifactSpec(
                root="scratchpad",
                path=relative,
                owner_key=input_key,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="CREATE",
            )
            for relative in ("report_coverage.md", "report_index.md")
        ),
        model_invoked=False,
    )
    input_launch = _launch(input_contract)
    _commit_contract(
        project,
        scratch,
        input_contract,
        input_launch,
        {
            "report_coverage.md": b"# Coverage\n",
            "report_index.md": b"# Index\n",
        },
    )
    requirements = {
        relative: _input_requirement(
            input_contract, input_launch, relative, "DRIVER"
        )
        for relative in ("report_coverage.md", "report_index.md")
    }
    contract = resolve_phase_io_contract(
        **DIMS,
        phase="report_index",
        work_unit_id="human_review_authority",
        exact_inputs=("report_coverage.md", "report_index.md"),
        exact_outputs=("report_human_review_authority.json",),
        exact_input_authorities=requirements,
    )
    _commit_contract(
        project,
        scratch,
        contract,
        _launch(contract),
        {"report_human_review_authority.json": b"{}\n"},
    )
    with pytest.raises(ValueError, match="schema|content|authority"):
        RCA.prepare_report_source_capture(
            scratchpad=scratch,
            project_root=project,
            run_id=RUN_ID,
            expected_config=config,
            metadata=metadata,
            fixed_source_roles={
                "report_human_review_authority.json": (
                    "REPORT_HUMAN_REVIEW_AUTHORITY"
                )
            },
            namespace_roles={},
        )


def test_reserved_fixed_path_and_role_are_bijective_and_not_namespace_roles(
    tmp_path: Path,
) -> None:
    project, scratch, config, _snapshot, metadata = _fixture(tmp_path)
    _generic_commit(
        project, scratch, "report_source_path_authority.json", b'{}\n', writer="DRIVER"
    )
    with pytest.raises(ValueError, match="role|authority|path"):
        RCA.prepare_report_source_capture(
            scratchpad=scratch,
            project_root=project,
            run_id=RUN_ID,
            expected_config=config,
            metadata=metadata,
            fixed_source_roles={"report_source_path_authority.json": "WRONG_ROLE"},
            namespace_roles={},
        )
    with pytest.raises(ValueError, match="role|authority|path"):
        RCA.prepare_report_source_capture(
            scratchpad=scratch,
            project_root=project,
            run_id=RUN_ID,
            expected_config=config,
            metadata=metadata,
            fixed_source_roles={
                "other.json": "PRODUCTION_SOURCE_PATH_AUTHORITY"
            },
            namespace_roles={},
        )
    with pytest.raises(ValueError, match="role|authority|path"):
        RCA.prepare_report_source_capture(
            scratchpad=scratch,
            project_root=project,
            run_id=RUN_ID,
            expected_config=config,
            metadata=metadata,
            fixed_source_roles={},
            namespace_roles={"*.json": "PRODUCTION_SOURCE_PATH_AUTHORITY"},
        )


def _policy_schema_sample(patterns: tuple[str, ...]) -> str:
    candidates = (
        "unstructured.v1",
        "plamen.canonical_finding_inventory.v1",
        "plamen.depth_finalization_report_authority.v1",
        "plamen.finding_delivery_successor.v1",
        "plamen.judge_decisions.v1",
        "plamen.preverify_inventory_successor.v1",
        "plamen.report_disposition_proposals.v1",
        "plamen.report_evidence_bundle.v1",
        "plamen.report_evidence_manifest.v1",
        "plamen.report_evidence_projection.v1",
        "plamen.report_finding_bodies.v1",
        "plamen.report_human_review_authority.v1",
        "plamen.report_human_review_markdown.v1",
        "plamen.report_index_projection.v1",
        "plamen.report_index_status_projection.v1",
        "plamen.report_records.v1",
        "plamen.report_source_path_authority.v1",
        "plamen.security_obligation_authority.v2",
        "plamen.security_obligation_lifecycle.v1",
        "plamen.security_obligation_report_retention.v1",
        "plamen.skeptic_proposal_projection.v1",
        "plamen.some_registered_projection.v1",
    )
    for candidate in candidates:
        if any(re.fullmatch(pattern, candidate) for pattern in patterns):
            return candidate
    raise AssertionError(f"no schema sample for policy patterns: {patterns}")


def test_full_default_report_source_policy_denominator_is_closed_and_generic_safe(
) -> None:
    inventory = RCA.report_source_policy_inventory()
    fixed = {
        row["selector"]: row["role"]
        for row in inventory
        if row["kind"] == "FIXED"
    }
    namespaces = {
        row["selector"]: row["role"]
        for row in inventory
        if row["kind"] == "NAMESPACE"
    }
    assert fixed == codec.DEFAULT_FIXED_SOURCE_ROLES
    assert namespaces == codec.DEFAULT_NAMESPACE_ROLES
    assert len(fixed) == 43
    assert len(namespaces) == 5
    assert len(inventory) == 48

    for row in inventory:
        policy = RCA._report_source_policies(
            row["selector"] if row["kind"] == "FIXED" else "fixture.md",
            (row["role"],),
        )
        if row["kind"] == "NAMESPACE":
            policy = tuple(
                candidate
                for candidate in RCA._NAMESPACE_REPORT_SOURCE_POLICIES.values()
                if candidate.role == row["role"]
            )
        assert len(policy) == 1
        exact = policy[0]
        if row["blocker"]:
            assert exact.blocker
            assert exact.owner_suffix_patterns == ()
            assert exact.writers == ()
            assert exact.schema_patterns == ()
            continue
        schema = _policy_schema_sample(exact.schema_patterns)
        for writer in exact.writers:
            assert not RCA._policy_owner_allowed(
                exact,
                owner_suffix=f"/report_fixture/generic_{writer.lower()}",
                writer=writer,
                schema_version=schema,
            ), (row["kind"], row["selector"], row["role"], writer)


@pytest.mark.parametrize(
    ("relative", "role", "writer", "raw", "namespaces"),
    [
        (
            "report_index.md",
            "REPORT_INDEX",
            "DRIVER",
            b"# Index\n",
            {},
        ),
        (
            "disposition.md",
            "REPORT_DISPOSITION",
            "MODEL",
            b"# Disposition\n",
            {},
        ),
        (
            "body_manifests/report_fixture.json",
            "BODY_MANIFEST_NAMESPACE",
            "DRIVER",
            b"{}\n",
            {"body_manifests/report_*.json": "BODY_MANIFEST_NAMESPACE"},
        ),
        (
            "report_semantic_fixture.md",
            "REPORT_SEMANTIC_NAMESPACE",
            "DRIVER",
            b"# Semantic debt\n",
            {"report_semantic_*.md": "REPORT_SEMANTIC_NAMESPACE"},
        ),
    ],
)
def test_nonreserved_privileged_fixed_and_namespace_roles_reject_generic_owner(
    tmp_path: Path,
    relative: str,
    role: str,
    writer: str,
    raw: bytes,
    namespaces: dict[str, str],
) -> None:
    project, scratch, config, _snapshot, metadata = _fixture(tmp_path)
    _generic_commit(project, scratch, relative, raw, writer=writer)
    fixed = {} if namespaces else {relative: role}
    with pytest.raises(ValueError, match="producer|owner|permitted|blocked"):
        RCA.prepare_report_source_capture(
            scratchpad=scratch,
            project_root=project,
            run_id=RUN_ID,
            expected_config=config,
            metadata=metadata,
            fixed_source_roles=fixed,
            namespace_roles=namespaces,
        )
