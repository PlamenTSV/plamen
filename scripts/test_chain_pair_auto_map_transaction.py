"""Fixture-first contract for the journaled final chain-pair auto-map.

The transaction must never rely on two independent best-effort root writes.
It derives immutable postimages, journals one paired apply owner, and admits
recovery only from the receipt's exact before/after state lattice.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

import pytest

from artifact_ledger import (
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
)
from chain_pair_auto_map_transaction import (
    ENABLER,
    HYPOTHESES,
    MAPPING,
    PENDING,
    ROOT,
    run_chain_pair_auto_map_transaction,
)
from phase_io_contracts import (
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    canonical_work_unit_key,
)


RUN_ID = "f88af9bb-288e-4cf6-85b8-9e3f468c1265"
FOREIGN_RUN_ID = "796765ee-c8f8-4ca8-84a5-ad6a54facf4e"
BEFORE = {
    HYPOTHESES: (
        b"# Hypotheses\n\n"
        b"| Hypothesis ID | Severity | Title | Constituent Findings |\n"
        b"|---|---|---|---|\n"
        b"| H-1 | Medium | Existing candidate | INV-1 |\n"
    ),
    MAPPING: (
        b"# Finding Mapping\n\n"
        b"| Finding ID | Hypothesis ID | Mapping Status |\n"
        b"|---|---|---|\n"
        b"| INV-1 | H-1 | GROUPED |\n"
    ),
    ENABLER: (
        b"# Enabler Results\n\n"
        b"## EN-1\n\nExact model-derived enabling condition.\n"
    ),
}
AFTER = {
    HYPOTHESES: BEFORE[HYPOTHESES]
    + b"| H-2 | Medium | Recovered candidate | DA-2 |\n",
    MAPPING: BEFORE[MAPPING]
    + b"| DA-2 | H-2 | AUTO_MAPPED_DEPTH |\n",
    ENABLER: BEFORE[ENABLER],
}


def _claim(
    *,
    root: Path,
    project: Path,
    paths: Sequence[str],
    run_id: str,
    work_unit_id: str,
) -> None:
    owner = canonical_work_unit_key(
        "sc",
        "thorough",
        "evm",
        "claude",
        "chain",
        work_unit_id,
    )
    postimages = {
        relative: (root / relative).read_bytes()
        for relative in paths
    }
    for relative in paths:
        (root / relative).unlink()
    contract = PhaseIOContract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="chain",
        work_unit_id=work_unit_id,
        outputs=tuple(
            ArtifactSpec(
                root="scratchpad",
                path=relative,
                owner_key=owner,
                artifact_class="REQUIRED",
                writer="MODEL",
                write_mode="CREATE",
                schema_version="unstructured.v1",
                minimum_gate="FIXTURE_ACTUAL_CHAIN_MODEL_OUTPUT",
                consumers=("chain/final_pair_auto_map_stage",),
            )
            for relative in paths
        ),
        immutable_inputs=(),
        bounded_lookup_inputs=(),
        model_invoked=True,
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        model="fixture-chain-model",
        timeout_s=60,
        exec_mode="pty",
        tool_policy=("filesystem",),
    )
    record_work_unit_inputs(
        root,
        project,
        contract,
        launch,
        run_id=run_id,
    )
    for relative, raw in postimages.items():
        (root / relative).write_bytes(raw)
    record_work_unit_artifacts(
        root,
        project,
        contract,
        launch,
        run_id=run_id,
        actor="MODEL",
    )


def _seed(
    tmp_path: Path,
    *,
    authority: str = "paired",
) -> tuple[Path, Path]:
    project = tmp_path / "project"
    project.mkdir()
    root = project / ".scratchpad"
    root.mkdir()
    for relative, raw in BEFORE.items():
        (root / relative).write_bytes(raw)
    if authority == "paired":
        _claim(
            root=root,
            project=project,
            paths=(HYPOTHESES, MAPPING, ENABLER),
            run_id=RUN_ID,
            work_unit_id="model",
        )
    elif authority == "split":
        _claim(
            root=root,
            project=project,
            paths=(HYPOTHESES, ENABLER),
            run_id=RUN_ID,
            work_unit_id="chain_model_hypotheses",
        )
        _claim(
            root=root,
            project=project,
            paths=(MAPPING,),
            run_id=RUN_ID,
            work_unit_id="chain_model_mapping",
        )
    elif authority == "foreign":
        _claim(
            root=root,
            project=project,
            paths=(HYPOTHESES, MAPPING, ENABLER),
            run_id=FOREIGN_RUN_ID,
            work_unit_id="foreign_chain_model_pair",
        )
    elif authority != "unowned":
        raise AssertionError(f"unknown fixture authority {authority}")
    return root, project


def _config(project: Path) -> dict[str, Any]:
    return {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "project_root": str(project),
        "_run_id": RUN_ID,
    }


def _derive(_root: Path) -> tuple[list[str], Mapping[str, bytes]]:
    return ["DA-2"], dict(AFTER)


def _run(
    root: Path,
    project: Path,
    *,
    derive: Callable[[Path], tuple[list[str], Mapping[str, bytes]]] = _derive,
    failpoint: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    return run_chain_pair_auto_map_transaction(
        scratchpad=root,
        project_root=project,
        config=_config(project),
        run_id=RUN_ID,
        derive=derive,
        failpoint=failpoint,
    )


def _root_bytes(root: Path) -> dict[str, bytes]:
    return {
        relative: (root / relative).read_bytes()
        for relative in (HYPOTHESES, MAPPING, ENABLER)
    }


def _root_owner_keys(root: Path) -> dict[str, str]:
    ledger = read_artifact_ledger(root)
    bindings = ledger["artifact_bindings"]
    return {
        relative: str(
            bindings["scratchpad:" + relative]["owner_key"]
        )
        for relative in (HYPOTHESES, MAPPING, ENABLER)
    }


def test_fresh_pair_commits_under_actual_chain_model_source_authority(
    tmp_path: Path,
) -> None:
    root, project = _seed(tmp_path, authority="paired")
    source_owners = _root_owner_keys(root)
    assert len(set(source_owners.values())) == 1
    assert next(iter(source_owners.values())).endswith("/chain/model")

    result = _run(root, project)

    assert result["state"] == "OUTPUT_COMMITTED"
    assert result["safe_to_project"] is True
    assert result["recovered"] is False
    assert result["mapped_ids"] == ["DA-2"]
    assert result["issues"] == []
    assert _root_bytes(root) == AFTER
    assert not (root / PENDING).exists()
    generation = root / ROOT / (
        "generation_" + result["generation_digest"]
    )
    assert (generation / HYPOTHESES).read_bytes() == AFTER[HYPOTHESES]
    assert (generation / MAPPING).read_bytes() == AFTER[MAPPING]


def test_crash_after_hypotheses_apply_resumes_without_rederiving_mapping(
    tmp_path: Path,
) -> None:
    root, project = _seed(tmp_path, authority="paired")

    def crash(label: str) -> None:
        if label == f"after_chain_pair_apply_{HYPOTHESES}":
            raise RuntimeError("fixture crash after hypotheses apply")

    interrupted = _run(root, project, failpoint=crash)
    assert interrupted["state"] == "STAGE_DEBT"
    assert (root / PENDING).is_file()
    assert (root / HYPOTHESES).read_bytes() == AFTER[HYPOTHESES]
    assert (root / MAPPING).read_bytes() == BEFORE[MAPPING]
    assert (root / ENABLER).read_bytes() == BEFORE[ENABLER]

    def forbidden_derive(_root: Path):
        raise AssertionError("resume must use the journal, not rederive")

    resumed = _run(root, project, derive=forbidden_derive)

    assert resumed["state"] == "OUTPUT_COMMITTED"
    assert resumed["safe_to_project"] is True
    assert resumed["recovered"] is True
    assert resumed["mapped_ids"] == ["DA-2"]
    assert _root_bytes(root) == AFTER
    assert not (root / PENDING).exists()


def test_arbitrary_third_recovery_state_is_visible_debt_and_byte_preserving(
    tmp_path: Path,
) -> None:
    root, project = _seed(tmp_path, authority="paired")

    def crash(label: str) -> None:
        if label == f"after_chain_pair_apply_{HYPOTHESES}":
            raise RuntimeError("fixture crash after first pair member")

    _run(root, project, failpoint=crash)
    arbitrary_mapping = BEFORE[MAPPING] + b"| ARBITRARY | THIRD | STATE |\n"
    (root / MAPPING).write_bytes(arbitrary_mapping)
    before_recovery = _root_bytes(root)

    result = _run(
        root,
        project,
        derive=lambda _root: (_ for _ in ()).throw(
            AssertionError("pending recovery must not rederive")
        ),
    )

    assert result["state"] == "RECOVERY_DEBT"
    assert result["safe_to_project"] is False
    assert result["recovered"] is True
    assert any("arbitrary third state" in issue for issue in result["issues"])
    assert _root_bytes(root) == before_recovery
    assert (root / PENDING).is_file()


def test_both_mutable_roots_share_one_final_apply_phaseio_owner(
    tmp_path: Path,
) -> None:
    root, project = _seed(tmp_path, authority="paired")

    result = _run(root, project)

    assert result["state"] == "OUTPUT_COMMITTED"
    final_owners = _root_owner_keys(root)
    assert len(set(final_owners.values())) == 1
    owner = next(iter(final_owners.values()))
    assert "/chain/final_pair_auto_map_apply." in owner
    apply_unit = read_artifact_ledger(root)["work_units"][owner]
    assert apply_unit["execution_state"] == "OUTPUT_COMMITTED"
    assert set(apply_unit["artifacts"]) == {
        "scratchpad:" + HYPOTHESES,
        "scratchpad:" + MAPPING,
        "scratchpad:" + ENABLER,
    }


def test_pending_recovery_rejects_mutated_unchanged_enabler_member(
    tmp_path: Path,
) -> None:
    root, project = _seed(tmp_path, authority="paired")

    def crash(label: str) -> None:
        if label == f"after_chain_pair_apply_{HYPOTHESES}":
            raise RuntimeError("fixture crash before unchanged enabler check")

    _run(root, project, failpoint=crash)
    mutated = BEFORE[ENABLER] + b"\nforeign mutation\n"
    (root / ENABLER).write_bytes(mutated)
    frozen = _root_bytes(root)

    result = _run(
        root,
        project,
        derive=lambda _root: (_ for _ in ()).throw(
            AssertionError("pending recovery must not rederive")
        ),
    )

    assert result["state"] == "RECOVERY_DEBT"
    assert result["safe_to_project"] is False
    assert any("arbitrary third state" in issue for issue in result["issues"])
    assert _root_bytes(root) == frozen
    assert (root / PENDING).is_file()


def test_no_change_derivation_creates_no_transaction_or_new_owner(
    tmp_path: Path,
) -> None:
    root, project = _seed(tmp_path, authority="paired")
    before = _root_bytes(root)
    owners_before = _root_owner_keys(root)
    ledger_before = (root / "_artifact_state.json").read_bytes()

    result = _run(
        root,
        project,
        derive=lambda _root: ([], {}),
    )

    assert result == {
        "schema_version": "plamen.chain_pair_auto_map_transaction.v1",
        "state": "NOT_REQUIRED",
        "safe_to_project": True,
        "recovered": False,
        "mapped_ids": [],
        "generation_digest": None,
        "issues": [],
    }
    assert _root_bytes(root) == before
    assert _root_owner_keys(root) == owners_before
    assert (root / "_artifact_state.json").read_bytes() == ledger_before
    assert not (root / ROOT).exists()


@pytest.mark.parametrize("authority", ("split", "foreign", "unowned"))
def test_split_foreign_or_unowned_pair_fails_without_mutating_candidates(
    tmp_path: Path,
    authority: str,
) -> None:
    root, project = _seed(tmp_path, authority=authority)
    before = _root_bytes(root)
    owners_before = (
        _root_owner_keys(root) if authority != "unowned" else None
    )

    result = _run(root, project)

    assert result["state"] == "STAGE_DEBT"
    assert result["safe_to_project"] is False
    assert result["mapped_ids"] == []
    assert result["issues"]
    assert _root_bytes(root) == before
    if owners_before is not None:
        assert _root_owner_keys(root) == owners_before
    assert not (root / PENDING).exists()
