"""Regression coverage for the real recon-prepass canonical handoff."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

import artifact_ledger as ledger
import plamen_driver as driver
import plamen_mechanical as mechanical
import plamen_validators as validators
import recon_prepass
from phase_io_contracts import (
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    canonical_work_unit_key,
    registered_projection_handoff,
    resolve_phase_io_contract,
)


RUN_ID = "recon-prepass-canonical-handoff"
DIMENSIONS = {
    "pipeline": "sc",
    "mode": "thorough",
    "ecosystem": "evm",
    "backend": "claude",
}


def _driver_generation(
    scratchpad: Path,
    project: Path,
    *,
    work_unit_id: str,
    payloads: dict[str, bytes],
) -> dict:
    key = canonical_work_unit_key(
        DIMENSIONS["pipeline"],
        DIMENSIONS["mode"],
        DIMENSIONS["ecosystem"],
        DIMENSIONS["backend"],
        "recon",
        work_unit_id,
    )
    contract = PhaseIOContract(
        **DIMENSIONS,
        phase="recon",
        work_unit_id=work_unit_id,
        outputs=tuple(
            ArtifactSpec(
                root="scratchpad",
                path=name,
                owner_key=key,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="CREATE",
                minimum_gate="FIXTURE_EXACT_BYTES",
            )
            for name in payloads
        ),
        model_invoked=False,
    )
    launch = LaunchSpec(
        work_unit_key=key,
        **DIMENSIONS,
        model="driver",
        timeout_s=30,
        exec_mode="python",
        tool_policy=("filesystem",),
    )
    armed = ledger.record_work_unit_inputs(
        scratchpad, project, contract, launch, run_id=RUN_ID
    )
    assert armed["semantic_status"] == "INPUTS_BOUND"
    for name, raw in payloads.items():
        (scratchpad / name).write_bytes(raw)
    return ledger.record_work_unit_artifacts(
        scratchpad,
        project,
        contract,
        launch,
        run_id=RUN_ID,
        actor="DRIVER",
    )


def _workspace(
    tmp_path: Path, *, template_shard: bytes | None = None
) -> tuple[Path, Path, dict]:
    project = tmp_path / "project"
    source = project / "src"
    scratchpad = project / ".scratchpad"
    source.mkdir(parents=True)
    scratchpad.mkdir()
    (source / "Protocol.sol").write_text(
        "pragma solidity ^0.8.20; contract Protocol {}\n", encoding="utf-8"
    )
    config = {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "project_root": str(project),
        "scratchpad": str(scratchpad),
        "_run_id": RUN_ID,
        "run_id": RUN_ID,
    }
    prepass_payloads = {
        name: (f"# {name}\n\nexact prepass generation\n").encode()
        for name in recon_prepass._SC_PREPASS_PUBLIC_OUTPUTS
    }
    _driver_generation(
        scratchpad,
        project,
        work_unit_id="prepass",
        payloads=prepass_payloads,
    )
    shard_payloads = {
        name: (f"# {name}\n\nexact committed worker evidence\n").encode()
        for name in mechanical._canonical_merge_input_names("sc", "thorough")
    }
    if template_shard is not None:
        shard_payloads["recon_templates_patterns.md"] = template_shard
    _driver_generation(
        scratchpad,
        project,
        work_unit_id="canonical_shard_fixture",
        payloads=shard_payloads,
    )
    return project, scratchpad, config


def test_real_prepass_projection_and_public_output_denominator_are_exact() -> None:
    contract = resolve_phase_io_contract(
        **DIMENSIONS,
        phase="recon",
        work_unit_id="prepass",
    )
    assert tuple(spec.path for spec in contract.outputs[:-1]) == (
        recon_prepass._SC_PREPASS_PUBLIC_OUTPUTS
    )
    assert {"setter_list.md", "emit_list.md"}.issubset(
        recon_prepass._SC_PREPASS_PUBLIC_OUTPUTS
    )
    predecessor = canonical_work_unit_key(
        "sc", "thorough", "evm", "claude", "recon", "prepass"
    )
    successor = canonical_work_unit_key(
        "sc", "thorough", "evm", "claude", "recon", "canonical_merge"
    )
    for name in mechanical._RECON_CANONICAL_OUTPUTS:
        assert registered_projection_handoff(
            predecessor, successor, f"scratchpad:{name}"
        )
    dependency_successor = canonical_work_unit_key(
        "sc", "thorough", "evm", "claude", "recon", "dependency_reconcile"
    )
    assert registered_projection_handoff(
        predecessor,
        dependency_successor,
        "scratchpad:external_dependency_research.md",
    )
    for provider in ("claude", "codex"):
        provider_prepass = canonical_work_unit_key(
            "sc", "thorough", "evm", provider, "recon", "prepass"
        )
        neutral_reconcile = canonical_work_unit_key(
            "sc", "thorough", "evm", "backend-neutral", "recon",
            "dependency_reconcile",
        )
        assert registered_projection_handoff(
            provider_prepass,
            neutral_reconcile,
            "scratchpad:external_dependency_research.md",
        )
        assert not registered_projection_handoff(
            provider_prepass,
            neutral_reconcile,
            "scratchpad:attack_surface.md",
        )
    cross_backend = canonical_work_unit_key(
        "sc", "thorough", "evm", "codex", "recon", "canonical_merge"
    )
    assert not registered_projection_handoff(
        predecessor, cross_backend, "scratchpad:attack_surface.md"
    )
    l1_prepass = canonical_work_unit_key(
        "l1", "thorough", "rust", "claude", "recon", "prepass"
    )
    l1_merge = canonical_work_unit_key(
        "l1", "thorough", "rust", "claude", "recon", "canonical_merge"
    )
    l1_overlap = set(recon_prepass._L1_PREPASS_PUBLIC_OUTPUTS).intersection(
        mechanical._L1_RECON_CANONICAL_OUTPUTS
    )
    assert l1_overlap
    for name in l1_overlap:
        assert registered_projection_handoff(
            l1_prepass, l1_merge, f"scratchpad:{name}"
        )


def test_canonical_merge_replaces_exact_registered_prepass_generation(
    tmp_path: Path,
) -> None:
    _project, scratchpad, config = _workspace(tmp_path)
    assert mechanical._merge_recon_worker_shards(scratchpad, config) == list(
        mechanical._RECON_CANONICAL_OUTPUTS
    )
    state = ledger.read_artifact_ledger(scratchpad)
    unit = state["work_units"][
        canonical_work_unit_key(
            "sc", "thorough", "evm", "claude", "recon", "canonical_merge"
        )
    ]
    assert (unit["semantic_status"], unit["execution_state"]) == (
        "ACTIVE", "OUTPUT_COMMITTED"
    )
    for name in mechanical._RECON_CANONICAL_OUTPUTS:
        assert unit["output_prestates"][f"scratchpad:{name}"]["status"] == (
            "ACTIVE_REGISTERED_PREDECESSOR"
        )


def test_dependency_reconcile_replaces_real_provider_prepass_generation(
    tmp_path: Path,
) -> None:
    project, scratchpad, config = _workspace(tmp_path)
    driver._ensure_recon_dependency_parity(scratchpad, str(project), config)
    state = ledger.read_artifact_ledger(scratchpad)
    unit = state["work_units"][
        canonical_work_unit_key(
            "sc", "thorough", "evm", "backend-neutral", "recon",
            "dependency_reconcile",
        )
    ]
    assert (unit["semantic_status"], unit["execution_state"]) == (
        "ACTIVE", "OUTPUT_COMMITTED"
    )
    assert unit["output_prestates"][
        "scratchpad:external_dependency_research.md"
    ]["status"] == "ACTIVE_REGISTERED_PREDECESSOR"


def test_atomic_control_temps_stay_in_driver_private_namespace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    observed: list[str] = []

    def interrupt(source: Path, _destination: Path) -> None:
        observed.append(source.name)
        raise OSError("fixture publication interruption")

    monkeypatch.setattr(driver, "_durable_driver_replace", interrupt)
    with pytest.raises(OSError, match="fixture publication interruption"):
        driver._atomic_driver_bytes(scratchpad / "successor.json", b"{}\n")
    monkeypatch.setattr(ledger, "_durable_replace", interrupt)
    with pytest.raises(OSError, match="fixture publication interruption"):
        ledger.write_artifact_ledger(
            scratchpad, ledger.read_artifact_ledger(scratchpad)
        )
    assert len(observed) == 2
    assert all(name.startswith("_.p.") for name in observed)
    assert all(name.endswith(".tmp") for name in observed)
    assert not any(path.name.startswith("_.p.") for path in scratchpad.iterdir())


def test_mutated_prepass_bytes_remain_fail_closed(tmp_path: Path) -> None:
    _project, scratchpad, config = _workspace(tmp_path)
    (scratchpad / "attack_surface.md").write_text(
        "# unregistered mutation\n", encoding="utf-8"
    )
    with pytest.raises(
        mechanical.CanonicalMergeAuthorityError,
        match="clean preexecution arm",
    ):
        mechanical._merge_recon_worker_shards(scratchpad, config)
    state = ledger.read_artifact_ledger(scratchpad)
    unit = state["work_units"][
        canonical_work_unit_key(
            "sc", "thorough", "evm", "claude", "recon", "canonical_merge"
        )
    ]
    assert unit["semantic_status"] == "INPUT_DEBT"
    assert unit["output_prestates"]["scratchpad:attack_surface.md"]["status"] == (
        "UNREGISTERED_REPLACEMENT_PREDECESSOR"
    )


def test_worker_pool_returns_containment_failure_for_canonical_authority_debt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    config = {
        "pipeline": "sc",
        "mode": "thorough",
        "project_root": str(project),
        "scratchpad": str(scratchpad),
    }
    monkeypatch.setattr(
        driver, "_recon_worker_jobs", lambda _config: [{"output": "done.md"}]
    )
    monkeypatch.setattr(
        driver, "_recon_worker_complete", lambda *_args, **_kwargs: (True, [])
    )
    monkeypatch.setattr(
        driver,
        "_merge_recon_worker_shards",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            mechanical.CanonicalMergeAuthorityError("fixture debt")
        ),
    )
    rc = driver._run_recon_worker_pool_pty(
        scratchpad=scratchpad,
        project_root=str(project),
        config=config,
        phase=SimpleNamespace(name="recon"),
        base_cmd=["claude"],
        env={},
        timeout=30,
        quiescence_s=0.01,
        attempt=1,
    )
    assert rc == -4


def test_worker_pool_returns_containment_failure_for_dependency_authority_debt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    config = {
        "pipeline": "sc",
        "mode": "thorough",
        "project_root": str(project),
        "scratchpad": str(scratchpad),
    }
    monkeypatch.setattr(
        driver, "_recon_worker_jobs", lambda _config: [{"output": "done.md"}]
    )
    monkeypatch.setattr(
        driver, "_recon_worker_complete", lambda *_args, **_kwargs: (True, [])
    )
    monkeypatch.setattr(driver, "_merge_recon_worker_shards", lambda *_args: [])
    monkeypatch.setattr(
        driver,
        "_run_recon_dependency_research_wave",
        lambda **_kwargs: (_ for _ in ()).throw(
            driver.ArtifactLedgerError("fixture dependency authority debt")
        ),
    )
    rc = driver._run_recon_worker_pool_pty(
        scratchpad=scratchpad,
        project_root=str(project),
        config=config,
        phase=SimpleNamespace(name="recon"),
        base_cmd=["claude"],
        env={},
        timeout=30,
        quiescence_s=0.01,
        attempt=1,
    )
    assert rc == -4


def test_recon_coverage_accepts_code_formatted_acknowledged_module(
    tmp_path: Path,
) -> None:
    """The exact Markdown shape emitted by the live r15 repair is authority."""

    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    module = project / "lib" / "forge-std"
    scratchpad.mkdir(parents=True)
    module.mkdir(parents=True)
    for ordinal in range(17):
        (module / f"Fixture{ordinal}.sol").write_text(
            "pragma solidity ^0.8.20;\n", encoding="utf-8"
        )
    (scratchpad / "recon_summary.md").write_text(
        "- src/Protocol.sol\n", encoding="utf-8"
    )
    (scratchpad / "scope_leftover.md").write_text(
        "| File | Count | Status | Reason |\n"
        "|---|---:|---|---|\n"
        "| `lib/forge-std` | 17 files | ACKNOWLEDGED | representative files are pinned test utilities |\n",
        encoding="utf-8",
    )

    issues = validators._validate_recon_coverage(
        scratchpad,
        str(project),
        "evm",
        backend="claude",
        pipeline="sc",
    )
    assert not any("lib/forge-std" in issue for issue in issues)
