from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

import artifact_ledger as AL
import recon_prepass as RP
from phase_io_contracts import (
    registered_projection_handoff,
    resolve_phase_io_contract,
)


def _workspace(tmp_path: Path, *, contracts: bool = False):
    project = tmp_path / "project"
    source = project / ("contracts" if contracts else "src")
    scratchpad = project / ".scratchpad"
    source.mkdir(parents=True)
    scratchpad.mkdir()
    (source / "Protocol.sol").write_text(
        "pragma solidity ^0.8.20; contract Protocol {}\n",
        encoding="utf-8",
    )
    config = {
        "pipeline": "sc",
        "mode": "core",
        "language": "evm",
        "cli_backend": "codex",
        "project_root": str(project),
        "scratchpad": str(scratchpad),
        "run_id": "successor-resume",
        "_run_id": "successor-resume",
        "prepass_external_scanners": False,
    }
    return project, source, scratchpad, config


@pytest.fixture(autouse=True)
def _offline(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(RP.shutil, "which", lambda _name: None)
    monkeypatch.setattr(RP, "gate_supply_chain", lambda _root: None)
    monkeypatch.setattr(
        RP,
        "run_owned_process",
        lambda _args, **_kwargs: SimpleNamespace(
            returncode=127, stdout="", stderr="unavailable"
        ),
    )


def _active_prepass_rows(scratchpad: Path):
    rows = AL.read_artifact_ledger(scratchpad)["work_units"]
    return {
        key: row
        for key, row in rows.items()
        if "/recon/prepass" in key
        and row.get("semantic_status") == "ACTIVE"
        and row.get("execution_state") == "OUTPUT_COMMITTED"
    }


def test_failed_original_drift_executes_and_commits_exact_successor(tmp_path):
    project, source, scratchpad, config = _workspace(tmp_path)
    RP.run_recon_prepass(config)
    (source / "Protocol.sol").write_text(
        "pragma solidity ^0.8.20; contract Changed {}\n", encoding="utf-8"
    )

    result = RP.run_recon_prepass(config)

    assert result and "_authority" not in result
    active = _active_prepass_rows(scratchpad)
    assert list(active) == [
        "sc/core/evm/codex/recon/prepass.attempt-0002"
    ]
    ledger = AL.read_artifact_ledger(scratchpad)
    old = ledger["work_units"]["sc/core/evm/codex/recon/prepass"]
    assert (old["semantic_status"], old["execution_state"]) == (
        "INVALID", "FAILED"
    )
    assert old["superseded_by_work_unit_key"] == next(iter(active))
    assert all(
        row.get("owner_key") == next(iter(active))
        for identity, row in ledger["artifact_bindings"].items()
        if identity.startswith("scratchpad:")
        and identity in active[next(iter(active))]["artifacts"]
    )

    before = json.dumps(ledger, sort_keys=True)
    assert RP.run_recon_prepass(config) == result
    assert json.dumps(AL.read_artifact_ledger(scratchpad), sort_keys=True) == before


def test_resume_ephemeral_fields_do_not_mint_successor(tmp_path):
    _project, _source, scratchpad, config = _workspace(tmp_path)
    first = RP.run_recon_prepass(config)
    config.update({
        "_active_phase_names": ["recon"],
        "_active_model_attempts": {"recon": 9},
        "_auxiliary_writable_root_startup_binding": {"ephemeral": True},
    })
    assert RP.run_recon_prepass(config) == first
    assert list(_active_prepass_rows(scratchpad)) == [
        "sc/core/evm/codex/recon/prepass"
    ]


def test_contracts_tree_is_source_bound_and_edit_changes_authority(tmp_path):
    project, source, scratchpad, config = _workspace(
        tmp_path, contracts=True
    )
    first = RP._prepass_capture(scratchpad, project, config)
    assert first["production_source_capture_digest"] != RP._prepass_stable_digest({})
    assert first["source_root_authority"]["status"] == "PRESENT"
    assert first["source_root_authority"]["logical_identity"] == "project:root"
    (source / "Protocol.sol").write_text(
        "pragma solidity ^0.8.20; contract Edited {}\n", encoding="utf-8"
    )
    second = RP._prepass_capture(scratchpad, project, config)
    assert second["production_source_capture_digest"] != first[
        "production_source_capture_digest"
    ]


@pytest.mark.parametrize(
    ("limit_name", "limit", "prepare", "message"),
    (
        (
            "_PREPASS_CAPTURE_MAX_FILE_BYTES",
            32,
            lambda project, source: (source / "Huge.sol").write_bytes(b"x" * 33),
            "per-file byte budget",
        ),
        (
            "_PREPASS_CAPTURE_MAX_DEPTH",
            1,
            lambda project, source: (source / "nested" / "deeper").mkdir(
                parents=True
            ),
            "depth budget",
        ),
        (
            "_PREPASS_CAPTURE_MAX_ENTRIES",
            2,
            lambda project, source: (project / "wide.txt").write_text(
                "wide", encoding="utf-8"
            ),
            "entry budget",
        ),
    ),
)
def test_fallback_capture_fails_closed_on_hostile_repository_budgets(
    tmp_path, monkeypatch, limit_name, limit, prepare, message
):
    project, source, scratchpad, config = _workspace(tmp_path)
    prepare(project, source)
    monkeypatch.setattr(RP, limit_name, limit)
    with pytest.raises(RP.ReconPrepassAuthorityError, match=message):
        RP._prepass_capture(scratchpad, project, config)


def test_semantic_candidate_capture_is_bounded(tmp_path, monkeypatch):
    project, _source, scratchpad, config = _workspace(tmp_path)
    candidate = scratchpad / "recon_unplanned_semantic_oversize.md"
    with candidate.open("wb") as handle:
        handle.truncate(33)
    monkeypatch.setattr(RP, "_PREPASS_SEMANTIC_MAX_FILE_BYTES", 32)
    with pytest.raises(RP.ReconPrepassAuthorityError, match="authority budget"):
        RP._prepass_capture(scratchpad, project, config)


def test_successor_arm_crash_resumes_and_commits(tmp_path):
    _project, source, scratchpad, config = _workspace(tmp_path)
    RP.run_recon_prepass(config)
    (source / "Protocol.sol").write_text(
        "pragma solidity ^0.8.20; contract Changed {}\n", encoding="utf-8"
    )

    class Crash(RuntimeError):
        pass

    with pytest.raises(Crash):
        RP.run_recon_prepass(
            config,
            failure_injector=lambda point: (
                (_ for _ in ()).throw(Crash(point))
                if point == "after_arm"
                else None
            ),
        )
    RP.run_recon_prepass(config)
    assert list(_active_prepass_rows(scratchpad)) == [
        "sc/core/evm/codex/recon/prepass.attempt-0002"
    ]


def test_post_bind_drift_never_commits_the_stale_successor(tmp_path):
    _project, source, scratchpad, config = _workspace(tmp_path)
    RP.run_recon_prepass(config)
    (source / "Protocol.sol").write_text(
        "pragma solidity ^0.8.20; contract Second {}\n", encoding="utf-8"
    )

    class Crash(RuntimeError):
        pass

    with pytest.raises(Crash):
        RP.run_recon_prepass(
            config,
            failure_injector=lambda point: (
                (_ for _ in ()).throw(Crash(point))
                if point == "after_arm"
                else None
            ),
        )
    (source / "Protocol.sol").write_text(
        "pragma solidity ^0.8.20; contract Third {}\n", encoding="utf-8"
    )
    result = RP.run_recon_prepass(config)
    assert result and list(_active_prepass_rows(scratchpad)) == [
        "sc/core/evm/codex/recon/prepass.attempt-0003"
    ]
    before = json.dumps(AL.read_artifact_ledger(scratchpad), sort_keys=True)
    assert RP.run_recon_prepass(config) == result
    assert json.dumps(AL.read_artifact_ledger(scratchpad), sort_keys=True) == before


@pytest.mark.parametrize("fail_ordinal", (1, 2, 7, 14))
def test_each_partial_publication_crash_rerenders_whole_generation(
    tmp_path, monkeypatch, fail_ordinal
):
    _project, _source, scratchpad, config = _workspace(tmp_path)
    real_replace = RP._prepass_durable_replace_from_stage
    count = 0

    def crash_replace(source, target, **kwargs):
        nonlocal count
        if (
            Path(target).parent == scratchpad
            and Path(target).name
            in {*RP._SC_PREPASS_PUBLIC_OUTPUTS, RP._PREPASS_PUBLICATION_RECEIPT}
        ):
            count += 1
            if count == fail_ordinal:
                raise OSError("publication crash")
        return real_replace(source, target, **kwargs)

    monkeypatch.setattr(RP, "_prepass_durable_replace_from_stage", crash_replace)
    with pytest.raises(OSError, match="publication crash"):
        RP.run_recon_prepass(config)
    monkeypatch.setattr(RP, "_prepass_durable_replace_from_stage", real_replace)
    result = RP.run_recon_prepass(config)
    assert result and list(_active_prepass_rows(scratchpad)) == [
        "sc/core/evm/codex/recon/prepass"
    ]


def test_successor_commit_crash_finalizes_full_chain_on_resume(tmp_path):
    _project, source, scratchpad, config = _workspace(tmp_path)
    RP.run_recon_prepass(config)
    (source / "Protocol.sol").write_text(
        "pragma solidity ^0.8.20; contract Changed {}\n", encoding="utf-8"
    )

    class Crash(RuntimeError):
        pass

    with pytest.raises(Crash):
        RP.run_recon_prepass(
            config,
            failure_injector=lambda point: (
                (_ for _ in ()).throw(Crash(point))
                if point == "after_commit"
                else None
            ),
        )
    assert len(_active_prepass_rows(scratchpad)) == 2
    result = RP.run_recon_prepass(config)
    assert result and list(_active_prepass_rows(scratchpad)) == [
        "sc/core/evm/codex/recon/prepass.attempt-0002"
    ]
    before = json.dumps(AL.read_artifact_ledger(scratchpad), sort_keys=True)
    assert RP.run_recon_prepass(config) == result
    assert json.dumps(AL.read_artifact_ledger(scratchpad), sort_keys=True) == before


@pytest.mark.parametrize("fail_ordinal", (1, 7, 14))
def test_post_publish_drift_quarantine_resumes_after_each_move(
    tmp_path, monkeypatch, fail_ordinal
):
    _project, source, scratchpad, config = _workspace(tmp_path)

    class PublishCrash(RuntimeError):
        pass

    with pytest.raises(PublishCrash):
        RP.run_recon_prepass(
            config,
            failure_injector=lambda point: (
                (_ for _ in ()).throw(PublishCrash(point))
                if point == "after_publish" else None
            ),
        )
    (source / "Protocol.sol").write_text(
        "pragma solidity ^0.8.20; contract ChangedAfterPublish {}\n",
        encoding="utf-8",
    )
    real_replace = RP._prepass_durable_replace_from_stage
    moves = 0

    def crash_quarantine_move(source_path, target_path, **kwargs):
        nonlocal moves
        target = Path(target_path)
        if "_recon_prepass_uncommitted_quarantine" in target.parts:
            moves += 1
            if moves == fail_ordinal:
                raise OSError("uncommitted quarantine crash")
        return real_replace(source_path, target_path, **kwargs)

    monkeypatch.setattr(RP, "_prepass_durable_replace_from_stage", crash_quarantine_move)
    with pytest.raises(OSError, match="uncommitted quarantine crash"):
        RP.run_recon_prepass(config)
    monkeypatch.setattr(RP, "_prepass_durable_replace_from_stage", real_replace)
    result = RP.run_recon_prepass(config)
    assert result and list(_active_prepass_rows(scratchpad)) == [
        "sc/core/evm/codex/recon/prepass.attempt-0002"
    ]
    before = json.dumps(AL.read_artifact_ledger(scratchpad), sort_keys=True)
    assert RP.run_recon_prepass(config) == result
    assert json.dumps(AL.read_artifact_ledger(scratchpad), sort_keys=True) == before


def test_phase_io_registers_only_contiguous_six_component_prepass_successors():
    common = dict(
        pipeline="sc", mode="core", ecosystem="evm", backend="codex",
        phase="recon",
    )
    base = resolve_phase_io_contract(**common, work_unit_id="prepass")
    attempt2 = resolve_phase_io_contract(
        **common, work_unit_id="prepass.attempt-0002"
    )
    attempt3 = resolve_phase_io_contract(
        **common, work_unit_id="prepass.attempt-0003"
    )
    assert len(attempt2.key.split("/")) == 6
    assert all(output.write_mode == "CREATE" for output in base.outputs)
    assert all(output.writer == "DRIVER" for output in attempt2.outputs)
    assert all(output.write_mode == "REPLACE" for output in attempt2.outputs)
    for output in attempt2.outputs:
        assert registered_projection_handoff(base.key, attempt2.key, output.identity)
        assert registered_projection_handoff(
            attempt2.key, attempt3.key, output.identity
        )
        assert not registered_projection_handoff(
            base.key, attempt3.key, output.identity
        )
    with pytest.raises(ValueError):
        resolve_phase_io_contract(**common, work_unit_id="prepass.attempt-0001")
    with pytest.raises(ValueError):
        resolve_phase_io_contract(**common, work_unit_id="prepass.attempt-2")
    assert registered_projection_handoff(
        attempt2.key,
        "sc/core/evm/codex/recon/canonical_merge",
        "scratchpad:contract_inventory.md",
    )
    assert registered_projection_handoff(
        attempt2.key,
        "sc/core/evm/backend-neutral/recon/dependency_reconcile",
        "scratchpad:external_dependency_research.md",
    )
    assert not registered_projection_handoff(
        "sc/core/evm/claude/recon/prepass",
        attempt2.key,
        "scratchpad:contract_inventory.md",
    )
    assert not registered_projection_handoff(
        base.key, attempt2.key, "scratchpad:threat_model.md"
    )
    l1_base = resolve_phase_io_contract(
        pipeline="l1", mode="core", ecosystem="evm", backend="codex",
        phase="recon", work_unit_id="prepass",
    )
    l1_attempt = resolve_phase_io_contract(
        pipeline="l1", mode="core", ecosystem="evm", backend="codex",
        phase="recon", work_unit_id="prepass.attempt-0002",
    )
    assert not registered_projection_handoff(
        l1_base.key, l1_attempt.key, "scratchpad:contract_inventory.md"
    )
    for invalid_role in ("prepass.attempt-0000", "prepass.attempt-0001"):
        invalid_key = "/".join((*base.key.split("/")[:5], invalid_role))
        assert not registered_projection_handoff(
            base.key, invalid_key, "scratchpad:contract_inventory.md"
        )
        assert not registered_projection_handoff(
            invalid_key,
            "sc/core/evm/codex/recon/canonical_merge",
            "scratchpad:contract_inventory.md",
        )
    dependency_debt = resolve_phase_io_contract(
        **common,
        work_unit_id="dependency_research_debt",
        exact_outputs=("report_semantic_dependency_research.md",),
    )
    assert len(dependency_debt.outputs) == 1
    assert dependency_debt.outputs[0].write_mode == "REPLACE"


def test_orphan_attempt_9999_is_rejected_before_execution(tmp_path):
    project, _source, scratchpad, config = _workspace(tmp_path)
    contract = resolve_phase_io_contract(
        pipeline="sc", mode="core", ecosystem="evm", backend="codex",
        phase="recon", work_unit_id="prepass.attempt-9999",
    )
    launch = RP.LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="driver",
        timeout_s=RP._PREPASS_TIMEOUT_SECONDS,
        exec_mode="python",
        tool_policy=("filesystem",),
    )
    capture = RP._prepass_capture(scratchpad, project, config)
    authority = RP._prepass_preexecution_authority(
        contract, launch, run_id=config["_run_id"], capture=capture
    )
    AL.record_work_unit_inputs(
        scratchpad,
        project,
        contract,
        launch,
        run_id=config["_run_id"],
        preexecution_authority=authority,
    )
    with pytest.raises(RP.ReconPrepassAuthorityError, match="orphan|gap|future"):
        RP.run_recon_prepass(config)


def test_missing_middle_and_forged_terminal_ancestor_are_rejected(tmp_path):
    _project, source, scratchpad, config = _workspace(tmp_path)
    RP.run_recon_prepass(config)
    (source / "Protocol.sol").write_text(
        "pragma solidity ^0.8.20; contract Second {}\n", encoding="utf-8"
    )
    RP.run_recon_prepass(config)
    (source / "Protocol.sol").write_text(
        "pragma solidity ^0.8.20; contract Third {}\n", encoding="utf-8"
    )
    RP.run_recon_prepass(config)
    ledger = AL.read_artifact_ledger(scratchpad)
    attempt2 = "sc/core/evm/codex/recon/prepass.attempt-0002"
    saved_attempt2 = ledger["work_units"].pop(attempt2)
    AL.write_artifact_ledger(scratchpad, ledger)
    with pytest.raises(RP.ReconPrepassAuthorityError, match="orphan|gap|future"):
        RP.run_recon_prepass(config)

    ledger = AL.read_artifact_ledger(scratchpad)
    ledger["work_units"][attempt2] = saved_attempt2
    base = ledger["work_units"]["sc/core/evm/codex/recon/prepass"]
    base["preexecution_authority_digest"] = "0" * 64
    AL.write_artifact_ledger(scratchpad, ledger)
    with pytest.raises(RP.ReconPrepassAuthorityError, match="authority binding"):
        RP.run_recon_prepass(config)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("cli_backend", "claude"),
        ("mode", "light"),
        ("language", "solana"),
        ("pipeline", "l1"),
    ),
)
def test_current_config_never_adopts_wrong_dimension_owner(
    tmp_path, field, value
):
    _project, _source, _scratchpad, config = _workspace(tmp_path)
    RP.run_recon_prepass(config)
    config[field] = value
    with pytest.raises(RP.ReconPrepassAuthorityError, match="wrong-dimension"):
        RP.run_recon_prepass(config)


def _make_directory_alias(link: Path, target: Path) -> None:
    if os.name == "nt":
        completed = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(target)],
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            pytest.skip("Windows junction creation is unavailable")
    else:
        link.symlink_to(target, target_is_directory=True)


def test_quarantine_root_link_is_rejected_without_outside_write(tmp_path):
    _project, source, scratchpad, config = _workspace(tmp_path)

    class Crash(RuntimeError):
        pass

    with pytest.raises(Crash):
        RP.run_recon_prepass(
            config,
            failure_injector=lambda point: (
                (_ for _ in ()).throw(Crash(point))
                if point == "after_publish" else None
            ),
        )
    (source / "Protocol.sol").write_text(
        "pragma solidity ^0.8.20; contract LinkGuard {}\n", encoding="utf-8"
    )
    outside = tmp_path / "outside"
    outside.mkdir()
    alias = scratchpad / "_recon_prepass_uncommitted_quarantine"
    _make_directory_alias(alias, outside)
    try:
        with pytest.raises(
            RP.ReconPrepassAuthorityError, match="private directory.*unsafe"
        ):
            RP.run_recon_prepass(config)
        assert list(outside.iterdir()) == []
    finally:
        if os.name == "nt":
            os.rmdir(alias)
        else:
            alias.unlink()


def test_uncommitted_public_hardlink_is_never_classified_absent(tmp_path):
    _project, source, scratchpad, config = _workspace(tmp_path)

    class Crash(RuntimeError):
        pass

    with pytest.raises(Crash):
        RP.run_recon_prepass(
            config,
            failure_injector=lambda point: (
                (_ for _ in ()).throw(Crash(point))
                if point == "after_publish" else None
            ),
        )
    public = scratchpad / "attack_surface.md"
    outside_alias = tmp_path / "outside-hardlink.md"
    os.link(public, outside_alias)
    before = outside_alias.read_bytes()
    (source / "Protocol.sol").write_text(
        "pragma solidity ^0.8.20; contract HardlinkGuard {}\n",
        encoding="utf-8",
    )
    with pytest.raises(
        RP.ReconPrepassAuthorityError, match="safe single-link regular file"
    ):
        RP.run_recon_prepass(config)
    assert outside_alias.read_bytes() == before


def test_shared_classifier_rejects_dangling_file_alias(tmp_path):
    _project, _source, scratchpad, _config = _workspace(tmp_path)
    dangling = scratchpad / "dangling.md"
    try:
        dangling.symlink_to(tmp_path / "missing-target.md")
    except OSError:
        pytest.skip("file symlink creation is unavailable")
    with pytest.raises(
        RP.ReconPrepassAuthorityError, match="safe single-link regular file"
    ):
        RP._prepass_regular_file_present(
            dangling, label="test recon prepass alias"
        )


def test_renderer_cannot_publish_reserved_or_unknown_control_file(
    tmp_path, monkeypatch
):
    _project, _source, scratchpad, config = _workspace(tmp_path)

    class Crash(RuntimeError):
        pass

    with pytest.raises(Crash):
        RP.run_recon_prepass(
            config,
            failure_injector=lambda point: (
                (_ for _ in ()).throw(Crash(point))
                if point == "after_arm" else None
            ),
        )
    ledger_path = scratchpad / AL.LEDGER_NAME
    before = ledger_path.read_bytes()
    real_render = RP._render_recon_prepass

    def malicious_render(stage_config):
        result = real_render(stage_config)
        (Path(stage_config["scratchpad"]) / AL.LEDGER_NAME).write_text(
            "{}\n", encoding="utf-8"
        )
        return result

    monkeypatch.setattr(RP, "_render_recon_prepass", malicious_render)
    with pytest.raises(
        RP.ReconPrepassAuthorityError, match="unregistered auxiliary"
    ):
        RP.run_recon_prepass(config)
    assert ledger_path.read_bytes() == before


def test_dispatch_rejects_hardlinked_committed_public_output(tmp_path):
    _project, _source, scratchpad, config = _workspace(tmp_path)
    RP.run_recon_prepass(config)
    public = scratchpad / "attack_surface.md"
    outside = tmp_path / "outside-committed.md"
    os.link(public, outside)
    with pytest.raises(
        RP.ReconPrepassAuthorityError, match="single-link regular file"
    ):
        RP.assert_recon_prepass_dispatch_authority(config)


def test_successor_retires_authenticated_stale_auxiliary(tmp_path, monkeypatch):
    _project, source, scratchpad, config = _workspace(tmp_path)
    real_render = RP._render_recon_prepass
    emit_extra = True

    def render_with_generation_specific_aux(stage_config):
        result = real_render(stage_config)
        if emit_extra:
            (Path(stage_config["scratchpad"]) / "daml_prepass_noop.md").write_text(
                "generation-a-only\n", encoding="utf-8"
            )
        return result

    monkeypatch.setattr(
        RP, "_render_recon_prepass", render_with_generation_specific_aux
    )
    RP.run_recon_prepass(config)
    assert (scratchpad / "daml_prepass_noop.md").is_file()
    emit_extra = False
    (source / "Protocol.sol").write_text(
        "pragma solidity ^0.8.20; contract StaleAuxB {}\n", encoding="utf-8"
    )
    RP.run_recon_prepass(config)
    assert not (scratchpad / "daml_prepass_noop.md").exists()
    assert RP.assert_recon_prepass_dispatch_authority(config).endswith(
        "/recon/prepass.attempt-0002"
    )


def test_partial_auxiliary_generation_is_replayed_before_later_drift(
    tmp_path, monkeypatch
):
    _project, source, scratchpad, config = _workspace(tmp_path)
    real_render = RP._render_recon_prepass
    generation = "A"

    def render_generation_aux(stage_config):
        result = real_render(stage_config)
        stage = Path(stage_config["scratchpad"])
        if generation in {"A", "B"}:
            (stage / "daml_prepass_noop.md").write_text(
                f"generation-{generation}\n", encoding="utf-8"
            )
        if generation == "B":
            (stage / "opengrep_findings.md").write_text(
                "generation-B\n", encoding="utf-8"
            )
        return result

    monkeypatch.setattr(RP, "_render_recon_prepass", render_generation_aux)
    RP.run_recon_prepass(config)
    assert (scratchpad / "daml_prepass_noop.md").read_text(
        encoding="utf-8"
    ) == "generation-A\n"

    generation = "B"
    (source / "Protocol.sol").write_text(
        "pragma solidity ^0.8.20; contract AuxiliaryB {}\n", encoding="utf-8"
    )
    real_publish = RP._prepass_durable_replace_from_stage
    crashed = False

    def crash_after_first_auxiliary_publish(source_path, target_path, **kwargs):
        nonlocal crashed
        result = real_publish(source_path, target_path, **kwargs)
        if not crashed and Path(target_path) == scratchpad / "daml_prepass_noop.md":
            crashed = True
            raise OSError("crash after partial B auxiliary publication")
        return result

    monkeypatch.setattr(
        RP,
        "_prepass_durable_replace_from_stage",
        crash_after_first_auxiliary_publish,
    )
    with pytest.raises(OSError, match="partial B auxiliary"):
        RP.run_recon_prepass(config)
    monkeypatch.setattr(RP, "_prepass_durable_replace_from_stage", real_publish)
    assert (scratchpad / "daml_prepass_noop.md").read_text(
        encoding="utf-8"
    ) == "generation-B\n"

    generation = "C"
    (source / "Protocol.sol").write_text(
        "pragma solidity ^0.8.20; contract AuxiliaryC {}\n", encoding="utf-8"
    )
    result = RP.run_recon_prepass(config)
    assert result and list(_active_prepass_rows(scratchpad)) == [
        "sc/core/evm/codex/recon/prepass.attempt-0003"
    ]
    assert not (scratchpad / "daml_prepass_noop.md").exists()
    assert not (scratchpad / "opengrep_findings.md").exists()
    assert RP.assert_recon_prepass_dispatch_authority(config).endswith(
        "/recon/prepass.attempt-0003"
    )


def test_registered_renderer_private_directory_is_removed_not_published(
    tmp_path, monkeypatch
):
    _project, _source, scratchpad, config = _workspace(tmp_path)
    real_render = RP._render_recon_prepass

    def render_with_foundry_private_tree(stage_config):
        result = real_render(stage_config)
        private = Path(stage_config["scratchpad"]) / ".fb" / "out" / "Build.sol"
        private.mkdir(parents=True)
        (private / "Build.json").write_text("{}\n", encoding="utf-8")
        return result

    monkeypatch.setattr(
        RP, "_render_recon_prepass", render_with_foundry_private_tree
    )
    assert RP.run_recon_prepass(config)
    assert not (scratchpad / ".fb").exists()
    assert RP.assert_recon_prepass_dispatch_authority(config).endswith(
        "/recon/prepass"
    )


@pytest.mark.integration
def test_real_forge_successor_cleans_registered_build_directory(
    tmp_path, monkeypatch
):
    forge = Path.home() / ".foundry" / "bin" / (
        "forge.exe" if os.name == "nt" else "forge"
    )
    if not forge.is_file():
        pytest.skip("real Forge binary is unavailable")
    project, source, scratchpad, config = _workspace(tmp_path)
    (project / "foundry.toml").write_text(
        '[profile.default]\nsrc = "src"\n', encoding="utf-8"
    )
    monkeypatch.setattr(
        RP.shutil,
        "which",
        lambda name: str(forge) if name == "forge" else None,
    )
    RP.run_recon_prepass(config)
    (source / "Protocol.sol").write_text(
        "pragma solidity ^0.8.20; contract RealForgeSuccessor {}\n",
        encoding="utf-8",
    )
    assert RP.run_recon_prepass(config)
    assert list(_active_prepass_rows(scratchpad)) == [
        "sc/core/evm/codex/recon/prepass.attempt-0002"
    ]
    assert not (scratchpad / ".fb").exists()


def test_unknown_or_aliased_renderer_directory_fails_closed(tmp_path, monkeypatch):
    _project, _source, scratchpad, config = _workspace(tmp_path)
    real_render = RP._render_recon_prepass

    def render_unknown_tree(stage_config):
        result = real_render(stage_config)
        (Path(stage_config["scratchpad"]) / "unknown-private").mkdir()
        return result

    monkeypatch.setattr(RP, "_render_recon_prepass", render_unknown_tree)
    with pytest.raises(RP.ReconPrepassAuthorityError, match="staged artifact"):
        RP.run_recon_prepass(config)
    assert not (scratchpad / "unknown-private").exists()

    stage = tmp_path / "aliased-stage"
    outside = tmp_path / "outside-private"
    stage.mkdir()
    outside.mkdir()
    (outside / "sentinel").write_text("keep\n", encoding="utf-8")
    try:
        (stage / ".fb").symlink_to(outside, target_is_directory=True)
    except OSError:
        return
    with pytest.raises(RP.ReconPrepassAuthorityError, match="aliased"):
        RP._prepass_cleanup_renderer_private_stage(stage)
    assert (outside / "sentinel").read_text(encoding="utf-8") == "keep\n"

    wide_stage = tmp_path / "wide-stage"
    (wide_stage / ".fb").mkdir(parents=True)
    (wide_stage / ".fb" / "sentinel").write_text("keep", encoding="utf-8")
    (wide_stage / "extra-one").write_text("1", encoding="utf-8")
    monkeypatch.setattr(RP, "_PREPASS_STAGE_MAX_ENTRIES", 1)
    with pytest.raises(RP.ReconPrepassAuthorityError, match="top-level entry budget"):
        RP._prepass_cleanup_renderer_private_stage(wide_stage)
    assert (wide_stage / ".fb" / "sentinel").read_text(
        encoding="utf-8"
    ) == "keep"

    bounded_stage = tmp_path / "bounded-stage"
    private = bounded_stage / ".fb"
    private.mkdir(parents=True)
    (private / "one").write_text("1", encoding="utf-8")
    (private / "two").write_text("2", encoding="utf-8")
    monkeypatch.setattr(RP, "_PREPASS_STAGE_MAX_ENTRIES", 128)
    monkeypatch.setattr(RP, "_PREPASS_PRIVATE_TREE_MAX_ENTRIES", 1)
    with pytest.raises(RP.ReconPrepassAuthorityError, match="entry budget"):
        RP._prepass_cleanup_renderer_private_stage(bounded_stage)
    assert (private / "one").is_file() and (private / "two").is_file()

    nested_stage = tmp_path / "nested-budget-stage"
    nested_private = nested_stage / ".fb"
    (nested_private / "a").mkdir(parents=True)
    (nested_private / "b").mkdir()
    for relative in ("a/one", "a/two", "b/victim"):
        (nested_private / relative).write_text(relative, encoding="utf-8")
    monkeypatch.setattr(RP, "_PREPASS_PRIVATE_TREE_MAX_ENTRIES", 4)
    with pytest.raises(RP.ReconPrepassAuthorityError, match="entry budget"):
        RP._prepass_cleanup_renderer_private_stage(nested_stage)
    assert all(
        (nested_private / relative).is_file()
        for relative in ("a/one", "a/two", "b/victim")
    )

    unsafe_stage = tmp_path / "nested-unsafe-stage"
    unsafe_private = unsafe_stage / ".fb"
    (unsafe_private / "a").mkdir(parents=True)
    (unsafe_private / "b").mkdir()
    victim = unsafe_private / "b" / "victim"
    victim.write_text("victim", encoding="utf-8")
    outside_hardlink = tmp_path / "outside-hardlink"
    outside_hardlink.write_text("outside", encoding="utf-8")
    os.link(outside_hardlink, unsafe_private / "a" / "late-hardlink")
    monkeypatch.setattr(RP, "_PREPASS_PRIVATE_TREE_MAX_ENTRIES", 128)
    with pytest.raises(RP.ReconPrepassAuthorityError, match="non-regular"):
        RP._prepass_cleanup_renderer_private_stage(unsafe_stage)
    assert victim.read_text(encoding="utf-8") == "victim"
    assert outside_hardlink.read_text(encoding="utf-8") == "outside"

    multi_stage = tmp_path / "multi-private-stage"
    early_tree = multi_stage / ".fb"
    late_tree = multi_stage / ".og-bad"
    early_tree.mkdir(parents=True)
    late_tree.mkdir()
    early_victim = early_tree / "victim"
    early_victim.write_text("victim", encoding="utf-8")
    multi_outside = tmp_path / "multi-outside-hardlink"
    multi_outside.write_text("outside", encoding="utf-8")
    os.link(multi_outside, late_tree / "linked")
    with pytest.raises(RP.ReconPrepassAuthorityError, match="non-regular"):
        RP._prepass_cleanup_renderer_private_stage(multi_stage)
    assert early_victim.read_text(encoding="utf-8") == "victim"
    assert multi_outside.read_text(encoding="utf-8") == "outside"

    multi_budget_stage = tmp_path / "multi-budget-stage"
    budget_early = multi_budget_stage / ".fb"
    budget_late = multi_budget_stage / ".og-late"
    budget_early.mkdir(parents=True)
    budget_late.mkdir()
    (budget_early / "victim").write_text("victim", encoding="utf-8")
    (budget_late / "later").write_text("later", encoding="utf-8")
    monkeypatch.setattr(RP, "_PREPASS_PRIVATE_TREE_MAX_ENTRIES", 1)
    with pytest.raises(RP.ReconPrepassAuthorityError, match="entry budget"):
        RP._prepass_cleanup_renderer_private_stage(multi_budget_stage)
    assert (budget_early / "victim").read_text(encoding="utf-8") == "victim"
    assert (budget_late / "later").read_text(encoding="utf-8") == "later"

    late_change_stage = tmp_path / "late-change-stage"
    stable_private = late_change_stage / ".fb"
    changed_private = late_change_stage / ".og-late"
    stable_private.mkdir(parents=True)
    changed_private.mkdir()
    stable_victim = stable_private / "victim"
    stable_victim.write_text("victim", encoding="utf-8")
    excluded = RP._prepass_cleanup_renderer_private_stage(late_change_stage)
    assert {row[0] for row in excluded} == {".fb", ".og-late"}
    assert stable_victim.read_text(encoding="utf-8") == "victim"
    changed_private.rmdir()
    changed_private.write_text("late namespace change", encoding="utf-8")
    with pytest.raises(RP.ReconPrepassAuthorityError, match="attestation changed"):
        RP._prepass_auxiliary_output_sha256(
            late_change_stage,
            ("contract_inventory.md", "recon_prepass_receipt.json"),
            excluded,
        )
    assert stable_victim.read_text(encoding="utf-8") == "victim"

    swap_stage = tmp_path / "same-name-swap-stage"
    validated_root = swap_stage / ".fb"
    validated_root.mkdir(parents=True)
    (validated_root / "safe").write_text("safe", encoding="utf-8")
    sealed_exclusion = RP._prepass_cleanup_renderer_private_stage(swap_stage)
    moved_validated_root = tmp_path / "moved-validated-private"
    validated_root.rename(moved_validated_root)
    validated_root.mkdir()
    swap_outside = tmp_path / "swap-outside-hardlink"
    swap_outside.write_text("outside", encoding="utf-8")
    os.link(swap_outside, validated_root / "late-hardlink")
    with pytest.raises(RP.ReconPrepassAuthorityError, match="attestation changed"):
        RP._prepass_auxiliary_output_sha256(
            swap_stage,
            ("contract_inventory.md", "recon_prepass_receipt.json"),
            sealed_exclusion,
        )
    assert (moved_validated_root / "safe").read_text(encoding="utf-8") == "safe"
    assert swap_outside.read_text(encoding="utf-8") == "outside"


def test_same_authority_resume_publishes_sealed_bytes_not_fresh_rerender(
    tmp_path, monkeypatch
):
    _project, _source, scratchpad, config = _workspace(tmp_path)
    real_render = RP._render_recon_prepass
    generation = "OLD"

    def unstable_render(stage_config):
        if generation == "NEW":
            raise OSError("renderer unavailable after sealed crash")
        result = real_render(stage_config)
        stage = Path(stage_config["scratchpad"])
        (stage / "contract_inventory.md").write_text(
            "# sealed-OLD\n", encoding="utf-8"
        )
        if generation == "OLD":
            (stage / "daml_prepass_noop.md").write_text(
                "sealed-old-aux\n", encoding="utf-8"
            )
        return result

    monkeypatch.setattr(RP, "_render_recon_prepass", unstable_render)
    real_publish = RP._prepass_durable_replace_from_stage
    crashed = False

    def crash_after_first_publication(source_path, target_path, **kwargs):
        nonlocal crashed
        result = real_publish(source_path, target_path, **kwargs)
        if not crashed and Path(target_path).parent == scratchpad:
            crashed = True
            raise OSError("sealed generation publication crash")
        return result

    monkeypatch.setattr(
        RP, "_prepass_durable_replace_from_stage", crash_after_first_publication
    )
    with pytest.raises(OSError, match="sealed generation"):
        RP.run_recon_prepass(config)
    monkeypatch.setattr(RP, "_prepass_durable_replace_from_stage", real_publish)
    generation = "NEW"
    assert RP.run_recon_prepass(config)
    assert (scratchpad / "contract_inventory.md").read_text(
        encoding="utf-8"
    ) == "# sealed-OLD\n"
    assert (scratchpad / "daml_prepass_noop.md").read_text(
        encoding="utf-8"
    ) == "sealed-old-aux\n"
    assert RP.assert_recon_prepass_dispatch_authority(config).endswith(
        "/recon/prepass"
    )


def test_forged_future_aux_intent_has_zero_public_mutation(tmp_path):
    project, source, scratchpad, config = _workspace(tmp_path)
    RP.run_recon_prepass(config)
    before = {
        name: (scratchpad / name).read_bytes()
        for name in RP._PREPASS_AUXILIARY_OUTPUTS
        if (scratchpad / name).is_file()
    }
    contract = resolve_phase_io_contract(
        pipeline="sc", mode="core", ecosystem="evm", backend="codex",
        phase="recon", work_unit_id="prepass.attempt-9999",
    )
    launch = RP.LaunchSpec(
        work_unit_key=contract.key,
        pipeline="sc", mode="core", ecosystem="evm", backend="codex",
        model="driver", timeout_s=RP._PREPASS_TIMEOUT_SECONDS,
        exec_mode="python", tool_policy=("filesystem",),
    )
    authority = RP._prepass_preexecution_authority(
        contract,
        launch,
        run_id=config["_run_id"],
        capture=RP._prepass_capture(scratchpad, project, config),
    )
    valid_path = next((scratchpad / "_recon_prepass_auxiliary_transactions").glob(
        "*.intent.json"
    ))
    forged = json.loads(valid_path.read_text(encoding="utf-8"))
    forged.update({
        "successor_work_unit_key": contract.key,
        "successor_authority_digest": authority["authority_sha256"],
        "successor_preexecution_authority": authority,
    })
    forged_unsigned = dict(forged)
    forged_unsigned.pop("intent_digest", None)
    forged["intent_digest"] = RP._prepass_stable_digest(forged_unsigned)
    forged_path = valid_path.parent / f"{authority['authority_sha256']}.intent.json"
    forged_path.write_text(
        json.dumps(forged, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (source / "Protocol.sol").write_text(
        "pragma solidity ^0.8.20; contract ForgedIntentB {}\n", encoding="utf-8"
    )
    with pytest.raises(RP.ReconPrepassAuthorityError, match="ledger provenance"):
        RP.run_recon_prepass(config)
    assert {
        name: (scratchpad / name).read_bytes()
        for name in before
    } == before


def test_forged_committed_resolution_cannot_bypass_ledger_binding(tmp_path):
    _project, source, scratchpad, config = _workspace(tmp_path)
    RP.run_recon_prepass(config)
    before = {
        name: (scratchpad / name).read_bytes()
        for name in RP._PREPASS_AUXILIARY_OUTPUTS
        if (scratchpad / name).is_file()
    }
    transaction_root = scratchpad / "_recon_prepass_auxiliary_transactions"
    intent_path = next(transaction_root.glob("*.intent.json"))
    forged = json.loads(intent_path.read_text(encoding="utf-8"))
    forged["publication_members"] = {}
    forged["successor_auxiliary"] = {}
    forged["successor_receipt_sha256"] = "f" * 64
    unsigned = dict(forged)
    unsigned.pop("intent_digest", None)
    forged["intent_digest"] = RP._prepass_stable_digest(unsigned)
    intent_path.write_text(
        json.dumps(forged, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    resolution_unsigned = {
        "schema": "plamen.recon-prepass-auxiliary-resolution.v1",
        "intent_digest": forged["intent_digest"],
        "successor_authority_digest": forged["successor_authority_digest"],
        "status": "COMMITTED",
        "terminal_receipt_sha256": forged["successor_receipt_sha256"],
    }
    resolution = {
        **resolution_unsigned,
        "resolution_digest": RP._prepass_stable_digest(resolution_unsigned),
    }
    resolution_path = transaction_root / (
        forged["successor_authority_digest"] + ".resolved.json"
    )
    resolution_path.write_text(
        json.dumps(resolution, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (source / "Protocol.sol").write_text(
        "pragma solidity ^0.8.20; contract ForgedResolutionB {}\n",
        encoding="utf-8",
    )
    with pytest.raises(RP.ReconPrepassAuthorityError, match="ledger binding"):
        RP.run_recon_prepass(config)
    assert {
        name: (scratchpad / name).read_bytes()
        for name in before
    } == before


def test_atomic_json_ignores_precreated_fixed_temp_alias(tmp_path):
    _project, _source, scratchpad, _config = _workspace(tmp_path)
    outside = tmp_path / "outside.json"
    outside.write_bytes(b"sentinel")
    fixed_temp = scratchpad / "authority.json.tmp"
    os.link(outside, fixed_temp)
    destination = scratchpad / "authority.json"
    RP._prepass_write_json_atomic(
        scratchpad, destination, {"schema": "test.authority.v1"}
    )
    assert outside.read_bytes() == b"sentinel"
    assert fixed_temp.read_bytes() == b"sentinel"
    assert json.loads(destination.read_text(encoding="utf-8")) == {
        "schema": "test.authority.v1"
    }


def test_public_dispatch_verifier_replays_current_committed_authority(tmp_path):
    _project, source, scratchpad, config = _workspace(tmp_path)
    RP.run_recon_prepass(config)
    assert RP.assert_recon_prepass_dispatch_authority(config).endswith(
        "/recon/prepass"
    )
    (source / "Protocol.sol").write_text(
        "pragma solidity ^0.8.20; contract DispatchChanged {}\n",
        encoding="utf-8",
    )
    with pytest.raises(RP.ReconPrepassAuthorityError, match="capture changed"):
        RP.assert_recon_prepass_dispatch_authority(config)
    RP.run_recon_prepass(config)
    assert RP.assert_recon_prepass_dispatch_authority(config).endswith(
        "/recon/prepass.attempt-0002"
    )


def test_uncommitted_intent_rejects_predecessor_row_cas_change(
    tmp_path, monkeypatch
):
    _project, source, scratchpad, config = _workspace(tmp_path)

    class Crash(RuntimeError):
        pass

    with pytest.raises(Crash):
        RP.run_recon_prepass(
            config,
            failure_injector=lambda point: (
                (_ for _ in ()).throw(Crash(point))
                if point == "after_publish" else None
            ),
        )
    (source / "Protocol.sol").write_text(
        "pragma solidity ^0.8.20; contract IntentCAS {}\n", encoding="utf-8"
    )
    real_replace = RP._prepass_durable_replace_from_stage

    def stop_first_move(source_path, target_path, **kwargs):
        if "_recon_prepass_uncommitted_quarantine" in Path(target_path).parts:
            raise OSError("intent CAS boundary")
        return real_replace(source_path, target_path, **kwargs)

    monkeypatch.setattr(RP, "_prepass_durable_replace_from_stage", stop_first_move)
    with pytest.raises(OSError, match="intent CAS boundary"):
        RP.run_recon_prepass(config)
    monkeypatch.setattr(RP, "_prepass_durable_replace_from_stage", real_replace)
    ledger = AL.read_artifact_ledger(scratchpad)
    predecessor = ledger["work_units"]["sc/core/evm/codex/recon/prepass"]
    predecessor["forged_after_intent"] = True
    AL.write_artifact_ledger(scratchpad, ledger)
    with pytest.raises(RP.ReconPrepassAuthorityError, match="predecessor CAS"):
        RP.run_recon_prepass(config)


def test_uncommitted_quarantine_recovers_copy_before_unlink_power_loss(
    tmp_path, monkeypatch
):
    _project, source, scratchpad, config = _workspace(tmp_path)

    class Crash(RuntimeError):
        pass

    with pytest.raises(Crash):
        RP.run_recon_prepass(
            config,
            failure_injector=lambda point: (
                (_ for _ in ()).throw(Crash(point))
                if point == "after_publish" else None
            ),
        )
    (source / "Protocol.sol").write_text(
        "pragma solidity ^0.8.20; contract DurableMoveB {}\n",
        encoding="utf-8",
    )
    real_unlink = RP._rooted_io.durable_unlink
    crashed = False

    def lose_power_before_source_unlink(path):
        nonlocal crashed
        if not crashed and Path(path).name == "contract_inventory.md":
            crashed = True
            raise OSError("power loss before durable source unlink")
        return real_unlink(path)

    monkeypatch.setattr(
        RP._rooted_io, "durable_unlink", lose_power_before_source_unlink
    )
    with pytest.raises(
        RP.ReconPrepassAuthorityError,
        match="durable publication failed",
    ):
        RP.run_recon_prepass(config)
    monkeypatch.setattr(RP._rooted_io, "durable_unlink", real_unlink)
    assert list(
        (scratchpad / "_recon_prepass_uncommitted_quarantine").rglob(
            "contract_inventory.md"
        )
    )
    assert (scratchpad / "contract_inventory.md").exists()

    result = RP.run_recon_prepass(config)
    assert result and list(_active_prepass_rows(scratchpad)) == [
        "sc/core/evm/codex/recon/prepass.attempt-0002"
    ]
    assert not (scratchpad / "contract_inventory.md").is_symlink()
    assert RP.assert_recon_prepass_dispatch_authority(config).endswith(
        "/recon/prepass.attempt-0002"
    )


def test_commit_before_intent_rebind_resumes_without_provenance_gap(
    tmp_path
):
    _project, source, scratchpad, config = _workspace(tmp_path)

    class Crash(RuntimeError):
        pass

    with pytest.raises(Crash):
        RP.run_recon_prepass(
            config,
            failure_injector=lambda point: (
                (_ for _ in ()).throw(Crash(point))
                if point == "after_artifact_commit_before_publication_rebind"
                else None
            ),
        )
    row = AL.read_artifact_ledger(scratchpad)["work_units"][
        "sc/core/evm/codex/recon/prepass"
    ]
    assert row["execution_state"] == "OUTPUT_COMMITTED"
    assert row["auxiliary_publication_intent_digest"]
    assert row["auxiliary_publication_authority_digest"]
    assert row["commit_authority"][
        "auxiliary_publication_intent_digest"
    ] == row["auxiliary_publication_intent_digest"]
    assert row["commit_authority"][
        "auxiliary_publication_authority_digest"
    ] == row["auxiliary_publication_authority_digest"]
    (source / "Protocol.sol").write_text(
        "pragma solidity ^0.8.20; contract CommitGapB {}\n", encoding="utf-8"
    )
    result = RP.run_recon_prepass(config)
    assert result and list(_active_prepass_rows(scratchpad)) == [
        "sc/core/evm/codex/recon/prepass.attempt-0002"
    ]
    assert RP.assert_recon_prepass_dispatch_authority(config).endswith(
        "/recon/prepass.attempt-0002"
    )


def test_disposition_before_arm_replays_b_then_rolls_forward_to_c(tmp_path):
    _project, source, scratchpad, config = _workspace(tmp_path)
    RP.run_recon_prepass(config)
    (source / "Protocol.sol").write_text(
        "pragma solidity ^0.8.20; contract AuthorityB {}\n", encoding="utf-8"
    )
    capture_b = RP._prepass_capture(scratchpad, _project, config)

    class Crash(RuntimeError):
        pass

    with pytest.raises(Crash):
        RP.run_recon_prepass(
            config,
            failure_injector=lambda point: (
                (_ for _ in ()).throw(Crash(point))
                if point == "after_disposition" else None
            ),
        )
    (source / "Protocol.sol").write_text(
        "pragma solidity ^0.8.20; contract AuthorityC {}\n", encoding="utf-8"
    )
    capture_c = RP._prepass_capture(scratchpad, _project, config)
    result = RP.run_recon_prepass(config)
    assert result and list(_active_prepass_rows(scratchpad)) == [
        "sc/core/evm/codex/recon/prepass.attempt-0003"
    ]
    rows = AL.read_artifact_ledger(scratchpad)["work_units"]
    attempt2 = rows["sc/core/evm/codex/recon/prepass.attempt-0002"]
    attempt3 = rows["sc/core/evm/codex/recon/prepass.attempt-0003"]
    assert attempt2["preexecution_authority"]["authority_capture"] == capture_b
    assert attempt3["preexecution_authority"]["authority_capture"] == capture_c
    before = json.dumps(AL.read_artifact_ledger(scratchpad), sort_keys=True)
    assert RP.run_recon_prepass(config) == result
    assert json.dumps(AL.read_artifact_ledger(scratchpad), sort_keys=True) == before


def test_quarantine_intent_rejects_projection_row_cas_change(
    tmp_path, monkeypatch
):
    _project, source, scratchpad, config = _workspace(tmp_path)
    RP.run_recon_prepass(config)
    (source / "Protocol.sol").write_text(
        "pragma solidity ^0.8.20; contract ProjectionB {}\n", encoding="utf-8"
    )

    class Crash(RuntimeError):
        pass

    with pytest.raises(Crash):
        RP.run_recon_prepass(
            config,
            failure_injector=lambda point: (
                (_ for _ in ()).throw(Crash(point))
                if point == "after_arm" else None
            ),
        )
    (source / "Protocol.sol").write_text(
        "pragma solidity ^0.8.20; contract ProjectionC {}\n", encoding="utf-8"
    )
    real_replace = RP._prepass_durable_replace_from_stage

    def stop_first_move(source_path, target_path, **kwargs):
        if "_recon_prepass_uncommitted_quarantine" in Path(target_path).parts:
            raise OSError("projection CAS boundary")
        return real_replace(source_path, target_path, **kwargs)

    monkeypatch.setattr(RP, "_prepass_durable_replace_from_stage", stop_first_move)
    with pytest.raises(OSError, match="projection CAS boundary"):
        RP.run_recon_prepass(config)
    monkeypatch.setattr(RP, "_prepass_durable_replace_from_stage", real_replace)
    ledger = AL.read_artifact_ledger(scratchpad)
    binding = ledger["artifact_bindings"]["scratchpad:attack_surface.md"]
    binding["sha256"] = "0" * 64
    AL.write_artifact_ledger(scratchpad, ledger)
    with pytest.raises(RP.ReconPrepassAuthorityError, match="projection CAS"):
        RP.run_recon_prepass(config)


@pytest.mark.parametrize(
    ("crash_point", "post_crash_drift", "artifact_tamper"), (
        (None, False, None),
        ("legacy_after_intent", False, None),
        ("legacy_after_quarantine", False, None),
        ("legacy_after_ledger", False, None),
        ("legacy_after_intent", True, None),
        ("legacy_after_quarantine", True, None),
        ("legacy_after_ledger", True, None),
        ("legacy_after_intent", False, "delete_present"),
        ("legacy_after_intent", False, "appear_absent"),
    )
)
def test_legacy_seven_component_failure_is_quarantined_not_adopted(
    tmp_path, crash_point, post_crash_drift, artifact_tamper
):
    project, source, scratchpad, config = _workspace(tmp_path)
    RP.run_recon_prepass(config)
    publication_transactions = (
        scratchpad / "_recon_prepass_auxiliary_transactions"
    )
    if publication_transactions.exists():
        RP._prepass_remove_private_tree(
            scratchpad,
            publication_transactions,
            label="legacy fixture publication transaction removal",
        )
    ledger = AL.read_artifact_ledger(scratchpad)
    key = "sc/core/evm/codex/recon/prepass"
    old = ledger["work_units"][key]

    def legacy_authority(current, *, config_digest):
        value = dict(current)
        capture = dict(value["authority_capture"])
        capture = {
            name: capture[name]
            for name in (
                "source_capture_digest", "source_root_authority",
                "config_digest", "unexpected_semantic_outputs",
                "input_set_digest",
            )
        }
        capture["config_digest"] = config_digest
        capture["input_set_digest"] = RP._prepass_stable_digest({
            "source_capture_digest": capture["source_capture_digest"],
            "source_root_authority": capture["source_root_authority"],
            "config_digest": capture["config_digest"],
            "unexpected_semantic_outputs": capture[
                "unexpected_semantic_outputs"
            ],
        })
        value["authority_capture"] = capture
        unsigned = dict(value)
        unsigned.pop("authority_sha256")
        value["authority_sha256"] = RP._prepass_stable_digest(unsigned)
        return value

    original = legacy_authority(
        old["preexecution_authority"], config_digest="1" * 64
    )
    attempted = legacy_authority(
        old["preexecution_authority"], config_digest="2" * 64
    )
    old["preexecution_authority"] = original
    old["preexecution_authority_digest"] = original["authority_sha256"]
    old["semantic_status"] = "INVALID"
    old["execution_state"] = "FAILED"
    for row in ledger["artifact_bindings"].values():
        if row.get("owner_key") == key:
            row["status"] = "QUARANTINED"
            row["authority_level"] = "PROPOSAL_ONLY"
    legacy_key = key + "/attempt-2"
    ledger["work_units"][legacy_key] = {
        "work_unit_key": legacy_key,
        "semantic_status": "DEBT",
        "execution_state": "FAILED",
        "durable_disposition": {
            "schema": "plamen.recon-mutation-disposition.v1",
            "state": "FAILED",
            "reason_codes": ["PREPASS_INPUT_AUTHORITY_CHANGED"],
            "original_authority_digest": original["authority_sha256"],
            "original_preexecution_authority": original,
            "attempted_preexecution_authority_digest": attempted[
                "authority_sha256"
            ],
            "attempted_preexecution_authority": attempted,
        },
    }
    AL.write_artifact_ledger(scratchpad, ledger)
    old_hashes = {
        name: (scratchpad / name).read_bytes()
        for name in RP._SC_PREPASS_PUBLIC_OUTPUTS
    }
    mutated_legacy = b"externally mutated legacy output\n"
    (scratchpad / "attack_surface.md").write_bytes(mutated_legacy)
    (scratchpad / "emit_list.md").unlink()
    (source / "Protocol.sol").write_text(
        "pragma solidity ^0.8.20; contract Current {}\n", encoding="utf-8"
    )

    if crash_point is not None:
        class Crash(RuntimeError):
            pass

        with pytest.raises(Crash):
            RP.run_recon_prepass(
                config,
                failure_injector=lambda point: (
                    (_ for _ in ()).throw(Crash(point))
                    if point == crash_point else None
                ),
            )
    if post_crash_drift:
        (source / "Protocol.sol").write_text(
            "pragma solidity ^0.8.20; contract PostJournalDrift {}\n",
            encoding="utf-8",
        )
    if artifact_tamper == "delete_present":
        (scratchpad / "contract_inventory.md").unlink()
    elif artifact_tamper == "appear_absent":
        (scratchpad / "emit_list.md").write_bytes(b"appeared after journal\n")
    if artifact_tamper is not None:
        with pytest.raises(
            RP.ReconPrepassAuthorityError,
            match="artifact (?:disappeared|appeared)",
        ):
            RP.run_recon_prepass(config)
        return
    result = RP.run_recon_prepass(config)
    assert result and "_authority" not in result
    expected_ordinal = 3 if post_crash_drift else 2
    assert list(_active_prepass_rows(scratchpad)) == [
        f"sc/core/evm/codex/recon/prepass.attempt-{expected_ordinal:04d}"
    ]
    archive_root = scratchpad / "_recon_prepass_legacy_quarantine"
    archived = list(archive_root.glob("*/contract_inventory.md"))
    assert len(archived) == 1
    assert archived[0].read_bytes() == old_hashes["contract_inventory.md"]
    mutated_archived = list(archive_root.glob("*/attack_surface.md"))
    assert len(mutated_archived) == 1
    assert mutated_archived[0].read_bytes() == mutated_legacy
    assert list(archive_root.glob("*/emit_list.md")) == []
    assert (scratchpad / "contract_inventory.md").read_bytes() != b""
    ledger = AL.read_artifact_ledger(scratchpad)
    assert all(
        row.get("owner_key") != key
        for row in ledger["artifact_bindings"].values()
    )
    assert all(
        row.get("owner_key") != key
        for row in ledger["artifacts"].values()
        if isinstance(row, dict)
    )
