"""Driver wiring contract for R0-8c/d content-bound resume."""

from __future__ import annotations

import json
import hashlib
import hmac
import os
from pathlib import Path
import re

import pytest

import plamen_driver as D
import recon_prepass as RP
from audit_snapshot import LEGACY_UNBOUND, MATCH, MISMATCH, NEW


def _component(digest_char: str) -> dict:
    return {
        "digest": digest_char * 64,
        "path_set_digest": digest_char * 64,
        "file_count": 1,
        "byte_count": 1,
    }


def _bound_snapshot(digest_char: str = "a") -> dict:
    raw = {
        "schema": "plamen.audit-input-snapshot.v1",
        "components": {
            "source_scope": {
                **_component(digest_char),
                "language": "evm",
                "pipeline": "sc",
                "git_head": "UNAVAILABLE",
                "coverage_limitations": [],
            },
            "audit_config": {
                "digest": digest_char * 64,
                "field_count": 1,
            },
            "methodology": _component(digest_char),
            "toolchain": _component(digest_char),
        },
    }
    import hashlib

    payload = json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()
    raw["snapshot_digest"] = hashlib.sha256(payload).hexdigest()
    return raw


def _config(project: Path, scratchpad: Path) -> dict:
    return {
        "project_root": str(project),
        "scratchpad": str(scratchpad),
        "pipeline": "sc",
        "language": "evm",
        "mode": "thorough",
        "cli_backend": "codex",
    }


_RUN_ID = "11111111-2222-4333-8444-555555555555"


def test_new_audit_binds_snapshot_without_archive(tmp_path, monkeypatch):
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    config_path = scratchpad / "config.json"
    config_path.write_text("{}")
    current = _bound_snapshot("a")
    monkeypatch.setattr(D, "build_audit_snapshot", lambda *_a, **_k: current)

    checkpoint, verdict, archive = D._bind_checkpoint_audit_snapshot(
        D.Checkpoint(),
        scratchpad,
        _config(project, scratchpad),
        config_path=config_path,
        checkpoint_existed=False,
    )

    assert verdict.state == NEW
    assert archive is None
    assert checkpoint.audit_snapshot == current
    assert re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
        checkpoint.run_id,
    )
    assert config_path.exists()


def test_matching_resume_preserves_checkpoint_and_artifacts(tmp_path, monkeypatch):
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    config_path = scratchpad / "config.json"
    config_path.write_text("{}")
    inventory = scratchpad / "findings_inventory.md"
    inventory.write_text("preserve")
    current = _bound_snapshot("a")
    monkeypatch.setattr(D, "build_audit_snapshot", lambda *_a, **_k: current)
    checkpoint = D.Checkpoint(
        completed=["recon"], audit_snapshot=current, run_id=_RUN_ID,
    )

    rebound, verdict, archive = D._bind_checkpoint_audit_snapshot(
        checkpoint,
        scratchpad,
        _config(project, scratchpad),
        config_path=config_path,
        checkpoint_existed=True,
    )
    assert rebound is checkpoint
    assert verdict.state == MATCH
    assert archive is None
    assert inventory.read_text() == "preserve"


def test_matching_resume_resolves_build_root_before_snapshot(tmp_path, monkeypatch):
    """A resumed run must re-establish private derived build context.

    ``_resolved_build_root`` is intentionally absent from the user config and
    cannot be recovered by trusting the stored checkpoint config.  Resolution
    therefore has to run on every startup, while dependency materialization
    remains restricted to fresh/pre-recon runs.
    """
    project = tmp_path / "repo" / "contracts"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    current = _bound_snapshot("a")
    calls = []

    def _resolve(config):
        calls.append("resolve")
        config["_resolved_build_root"] = str(project.parent)
        return project.parent

    def _snapshot(config, _home):
        assert config["_resolved_build_root"] == str(project.parent)
        calls.append("snapshot")
        return current

    monkeypatch.setattr(D, "_resolve_snapshot_build_root", _resolve)
    monkeypatch.setattr(D, "build_audit_snapshot", _snapshot)
    monkeypatch.setattr(
        D,
        "_prepare_snapshot_bound_inputs",
        lambda _config: (_ for _ in ()).throw(AssertionError("resume mutated inputs")),
    )

    checkpoint = D.Checkpoint(
        completed=["recon"], audit_snapshot=current, run_id=_RUN_ID,
    )
    rebound, verdict, archive = D._bind_checkpoint_audit_snapshot(
        checkpoint,
        scratchpad,
        _config(project, scratchpad),
        config_path=scratchpad / "config.json",
        checkpoint_existed=True,
    )

    assert rebound is checkpoint
    assert verdict.state == MATCH
    assert archive is None
    assert calls == ["resolve", "snapshot"]


@pytest.mark.parametrize("legacy", [True, False])
def test_legacy_or_mismatched_resume_stops_without_mutating_evidence(
    tmp_path, monkeypatch, legacy
):
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    config_path = scratchpad / "config.json"
    config_path.write_text("{}")
    (scratchpad / "_plamen.log").write_text("preserve live log")
    (scratchpad / ".plamen_run.lock").write_text("preserve live lock")
    (scratchpad / "findings_inventory.md").write_text("stale answer")
    (scratchpad / "_v2_checkpoint.json").write_text("stale checkpoint")
    report = project / "AUDIT_REPORT.md"
    report.write_text("stale report")
    current = _bound_snapshot("b")
    monkeypatch.setattr(D, "build_audit_snapshot", lambda *_a, **_k: current)
    before = {
        path.relative_to(project).as_posix(): path.read_bytes()
        for path in project.rglob("*")
        if path.is_file()
    }
    monkeypatch.setattr(
        D,
        "archive_stale_scratchpad",
        lambda *_a, **_k: (_ for _ in ()).throw(
            AssertionError("ordinary resume attempted an archive")
        ),
    )
    monkeypatch.setattr(
        D,
        "_archive_prior_audit_artifacts",
        lambda *_a, **_k: (_ for _ in ()).throw(
            AssertionError("ordinary resume attempted root-output mutation")
        ),
    )
    stored = None if legacy else _bound_snapshot("a")
    old = D.Checkpoint(
        completed=["recon", "breadth"], audit_snapshot=stored, run_id=_RUN_ID,
    )

    with pytest.raises(D.StartupDecisionRequired) as raised:
        D._bind_checkpoint_audit_snapshot(
            old,
            scratchpad,
            _config(project, scratchpad),
            config_path=config_path,
            checkpoint_existed=True,
        )

    assert raised.value.payload["snapshot_verdict"] == (
        LEGACY_UNBOUND if legacy else MISMATCH
    )
    assert raised.value.payload["startup_intent"] == "RESUME_EXISTING"
    assert old.completed == ["recon", "breadth"]
    after = {
        path.relative_to(project).as_posix(): path.read_bytes()
        for path in project.rglob("*")
        if path.is_file()
    }
    # The runtime contract is a startup control written before classification;
    # all pre-existing evidence and root outputs must remain byte-identical.
    for relative, payload in before.items():
        assert after[relative] == payload
    assert report.read_text() == "stale report"
    assert not (project / ".plamen-stale-snapshots").exists()


def test_legacy_empty_checkpoint_is_not_silently_trusted(tmp_path, monkeypatch):
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    config_path = scratchpad / "config.json"
    config_path.write_text("{}")
    (scratchpad / "partial_recon.md").write_text("partial old evidence")
    current = _bound_snapshot("a")
    monkeypatch.setattr(D, "build_audit_snapshot", lambda *_a, **_k: current)

    with pytest.raises(D.StartupDecisionRequired) as raised:
        D._bind_checkpoint_audit_snapshot(
            D.Checkpoint(),
            scratchpad,
            _config(project, scratchpad),
            config_path=config_path,
            checkpoint_existed=True,
        )
    assert raised.value.payload["snapshot_verdict"] == LEGACY_UNBOUND
    assert (scratchpad / "partial_recon.md").read_text() == "partial old evidence"


def test_matching_snapshot_without_durable_run_identity_requires_migration(
    tmp_path, monkeypatch,
):
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    (scratchpad / "findings_inventory.md").write_text("prior evidence")
    current = _bound_snapshot("a")
    monkeypatch.setattr(D, "build_audit_snapshot", lambda *_a, **_k: current)

    mac_key = b"m" * 32
    with pytest.raises(D.StartupDecisionRequired) as raised:
        D._bind_checkpoint_audit_snapshot(
            D.Checkpoint(completed=["recon"], audit_snapshot=current),
            scratchpad,
            _config(project, scratchpad),
            config_path=scratchpad / "config.json",
            checkpoint_existed=True,
            startup_decision_mac_key=mac_key,
        )

    payload = raised.value.payload
    assert payload["snapshot_verdict"] == LEGACY_UNBOUND
    assert payload["changed_components"] == ["run_identity"]
    assert payload["run_id"] is None
    assert payload["exit_status"] == D.EXIT_STARTUP_DECISION
    authenticated = dict(payload)
    observed_mac = authenticated.pop("receipt_mac")
    assert observed_mac == hmac.new(
        mac_key,
        json.dumps(
            authenticated, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def test_driver_pops_startup_receipt_mac_key_before_discovery(
    monkeypatch, capsys,
):
    monkeypatch.setenv("PLAMEN_STARTUP_DECISION_MAC_KEY", "a" * 64)
    monkeypatch.setattr(D.sys, "argv", [str(D.__file__), "--version"])
    assert D.main() == 0
    assert "PLAMEN_STARTUP_DECISION_MAC_KEY" not in os.environ
    assert "plamen-driver" in capsys.readouterr().out


def test_checkpoint_run_identity_round_trips_and_rejects_malformed_value(
    tmp_path,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    checkpoint = D.Checkpoint(run_id=_RUN_ID, audit_snapshot=_bound_snapshot())
    checkpoint.save(scratchpad)
    assert D.Checkpoint.load(scratchpad).run_id == _RUN_ID

    payload = json.loads((scratchpad / "_v2_checkpoint.json").read_text())
    payload["run_id"] = "reused-project-name"
    (scratchpad / "_v2_checkpoint.json").write_text(json.dumps(payload))
    with pytest.raises(RuntimeError, match="run_id"):
        D.Checkpoint.load(scratchpad)


def test_typed_startup_cli_options_are_order_independent(tmp_path):
    config = tmp_path / "config.json"
    receipt = tmp_path / "decisions" / "receipt.json"
    parsed = D._parse_startup_cli_args([
        "--startup-intent", "MIGRATE_EXISTING",
        "--startup-decision-receipt", str(receipt),
        "--no-hibernate", str(config), "--force", "--unattended",
    ])
    assert parsed == {
        "config_path": config,
        "force_resume": True,
        "no_sleep": True,
        "unattended": True,
        "startup_intent": D.STARTUP_MIGRATE_EXISTING,
        "decision_receipt_path": receipt,
    }


def test_external_startup_decision_receipt_is_idempotent_and_out_of_tree(
    tmp_path,
):
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    destination = tmp_path / "operator-decisions" / "decision.json"
    payload = {
        "schema": "plamen.startup-decision.v3",
        "decision_id": "a" * 64,
        "run_id": _RUN_ID,
        "exit_status": D.EXIT_STARTUP_DECISION,
    }

    first = D._write_external_startup_decision_receipt(
        payload,
        requested_path=destination,
        project_root=project,
        scratchpad=scratchpad,
    )
    before = destination.read_bytes()
    second = D._write_external_startup_decision_receipt(
        payload,
        requested_path=destination,
        project_root=project,
        scratchpad=scratchpad,
    )

    assert first == second
    assert destination.read_bytes() == before
    with pytest.raises(D.SnapshotInputError, match="outside"):
        D._write_external_startup_decision_receipt(
            payload,
            requested_path=scratchpad / "decision.json",
            project_root=project,
            scratchpad=scratchpad,
        )


def test_mismatched_resume_never_calls_archive_path(
    tmp_path, monkeypatch
):
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    config_path = scratchpad / "config.json"
    config_path.write_text("{}")
    current = _bound_snapshot("b")
    monkeypatch.setattr(D, "build_audit_snapshot", lambda *_a, **_k: current)
    monkeypatch.setattr(
        D,
        "archive_stale_scratchpad",
        lambda *_a, **_k: (_ for _ in ()).throw(
            AssertionError("archive path must be unreachable on resume")
        ),
    )

    with pytest.raises(D.StartupDecisionRequired):
        D._bind_checkpoint_audit_snapshot(
            D.Checkpoint(completed=["recon"], audit_snapshot=_bound_snapshot("a")),
            scratchpad,
            _config(project, scratchpad),
            config_path=config_path,
            checkpoint_existed=True,
        )


def test_explicit_new_run_refuses_to_reuse_evidence_destination(
    tmp_path, monkeypatch
):
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    config_path = scratchpad / "config.json"
    config_path.write_text("{}")
    inventory = scratchpad / "findings_inventory.md"
    inventory.write_text("prior evidence")
    report = project / "AUDIT_REPORT.md"
    report.write_text("prior report")
    current = _bound_snapshot("b")
    monkeypatch.setattr(D, "build_audit_snapshot", lambda *_a, **_k: current)
    old = D.Checkpoint(completed=["recon"], audit_snapshot=_bound_snapshot("a"))

    with pytest.raises(D.StartupDecisionRequired) as raised:
        D._bind_checkpoint_audit_snapshot(
            old,
            scratchpad,
            _config(project, scratchpad),
            config_path=config_path,
            checkpoint_existed=True,
            startup_intent="START_NEW_RUN",
        )

    assert raised.value.payload["required_action"] == "USE_DISTINCT_RUN_DESTINATION"
    assert inventory.read_text() == "prior evidence"
    assert report.read_text() == "prior report"
    assert old.completed == ["recon"]


def test_explicit_new_run_uses_distinct_destination_and_preserves_prior_root(
    tmp_path, monkeypatch,
):
    prior = tmp_path / "prior-project"
    prior_sp = prior / ".scratchpad"
    prior_sp.mkdir(parents=True)
    (prior / "AUDIT_REPORT.md").write_text("prior report")
    (prior_sp / "_v2_checkpoint.json").write_text("prior checkpoint")
    prior_before = {
        path.relative_to(prior).as_posix(): path.read_bytes()
        for path in prior.rglob("*") if path.is_file()
    }

    project = tmp_path / "new-clean-project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    current = _bound_snapshot("c")
    monkeypatch.setattr(D, "build_audit_snapshot", lambda *_a, **_k: current)
    checkpoint, verdict, archive = D._bind_checkpoint_audit_snapshot(
        D.Checkpoint(),
        scratchpad,
        _config(project, scratchpad),
        config_path=scratchpad / "config.json",
        checkpoint_existed=False,
        startup_intent=D.STARTUP_START_NEW_RUN,
    )

    assert verdict.state == NEW
    assert archive is None
    assert checkpoint.run_id and checkpoint.run_id != _RUN_ID
    assert prior_before == {
        path.relative_to(prior).as_posix(): path.read_bytes()
        for path in prior.rglob("*") if path.is_file()
    }


def test_distinct_new_run_preserves_legacy_root_medusa_workspace(
    tmp_path, monkeypatch,
):
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad-new"
    scratchpad.mkdir(parents=True)
    legacy_harness = project / ".medusa-tests" / "LegacyHarness.sol"
    legacy_harness.parent.mkdir()
    legacy_harness.write_text("contract LegacyHarness {}\n", encoding="utf-8")
    before = legacy_harness.read_bytes()
    current = _bound_snapshot("c")
    monkeypatch.setattr(D, "build_audit_snapshot", lambda *_a, **_k: current)

    checkpoint, verdict, archive = D._bind_checkpoint_audit_snapshot(
        D.Checkpoint(),
        scratchpad,
        _config(project, scratchpad),
        config_path=scratchpad / "config.json",
        checkpoint_existed=False,
        startup_intent=D.STARTUP_START_NEW_RUN,
    )

    assert verdict.state == NEW
    assert archive is None
    assert checkpoint.run_id
    assert legacy_harness.read_bytes() == before


def test_authorized_migration_request_never_falls_through_to_recon(
    tmp_path, monkeypatch,
):
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    (scratchpad / "findings_inventory.md").write_text("legacy evidence")
    current = _bound_snapshot("a")
    monkeypatch.setattr(D, "build_audit_snapshot", lambda *_a, **_k: current)

    with pytest.raises(D.StartupDecisionRequired) as raised:
        D._bind_checkpoint_audit_snapshot(
            D.Checkpoint(completed=["recon"], audit_snapshot=current),
            scratchpad,
            _config(project, scratchpad),
            config_path=scratchpad / "config.json",
            checkpoint_existed=True,
            startup_intent=D.STARTUP_MIGRATE_EXISTING,
        )

    assert raised.value.payload["required_action"] == (
        "VERSIONED_MIGRATION_NOT_AUTHORIZED"
    )
    assert (scratchpad / "findings_inventory.md").read_text() == "legacy evidence"


@pytest.mark.parametrize("startup_flag", [[], ["--fresh"]])
def test_real_entrypoint_stops_before_model_or_evidence_mutation_on_mismatch(
    tmp_path, startup_flag, monkeypatch, capsys,
):
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    (project / "Vault.sol").write_text(
        "pragma solidity 0.8.20; contract Vault {}\n", encoding="utf-8"
    )
    (project / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
    report = project / "AUDIT_REPORT.md"
    report.write_text("prior report\n", encoding="utf-8")
    config = _config(project, scratchpad)
    config["cli_backend"] = "codex"
    config_path = scratchpad / "config.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    checkpoint = D.Checkpoint(
        completed=["recon"],
        audit_snapshot=_bound_snapshot("a"),
        config=config,
        run_id=_RUN_ID,
    )
    checkpoint.save(scratchpad)
    checkpoint_before = (scratchpad / "_v2_checkpoint.json").read_bytes()
    report_before = report.read_bytes()
    decision_receipt = tmp_path / "operator-decisions" / "decision.json"

    monkeypatch.setattr(
        D, "build_audit_snapshot", lambda *_a, **_k: _bound_snapshot("b"),
    )
    monkeypatch.setattr(D, "_admit_direct_driver_projection", lambda *_a, **_k: None)
    monkeypatch.setattr(D.display, "install_detached_output_guards", lambda: None)
    monkeypatch.setattr(
        D.sys,
        "argv",
        [
            str(Path(D.__file__)), str(config_path), *startup_flag,
            "--no-hibernate",
            "--startup-decision-receipt", str(decision_receipt),
        ],
    )

    with pytest.raises(SystemExit) as stopped:
        D.main()

    assert stopped.value.code == D.EXIT_STARTUP_DECISION
    assert "[startup-decision]" in capsys.readouterr().err
    assert decision_receipt.is_file()
    decision = json.loads(decision_receipt.read_text(encoding="utf-8"))
    assert decision["run_id"] == _RUN_ID
    assert decision["exit_status"] == D.EXIT_STARTUP_DECISION
    assert len(decision["decision_id"]) == 64
    assert decision["component_digests"]
    assert (scratchpad / "_v2_checkpoint.json").read_bytes() == checkpoint_before
    assert report.read_bytes() == report_before
    assert not (project / ".plamen-stale-snapshots").exists()
    assert not list(scratchpad.glob("_prompt_*.md"))
    assert not list(scratchpad.glob("_stdio_*.log"))


def test_snapshot_binding_precedes_recon_prepass_in_main_source():
    source = Path(D.__file__).read_text(encoding="utf-8", errors="replace")
    bind_call = source.index("_bind_checkpoint_audit_snapshot(", source.index("def main("))
    prepass_call = source.index("run_recon_prepass(config)", bind_call)
    assert bind_call < prepass_call


def test_new_bare_evm_bootstrap_is_inside_the_bound_input_set(
    tmp_path, monkeypatch
):
    """A driver-owned Foundry scaffold must not look like user source drift.

    Regression from the first live Release-0 canary: the driver bound a bare
    Solidity tree, the recon pre-pass wrote ``foundry.toml``, and the first
    phase-boundary check degraded the run on its own deterministic mutation.
    The bootstrap must instead finish before the NEW snapshot is established.
    """
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    (project / "Vault.sol").write_text(
        "pragma solidity 0.8.20;\ncontract Vault {}\n", encoding="utf-8"
    )
    config_path = scratchpad / "config.json"
    config = _config(project, scratchpad)
    config_path.write_text(json.dumps(config), encoding="utf-8")

    real_which = RP.shutil.which
    fake_forge = real_which("forge") or D.sys.executable
    monkeypatch.setattr(
        RP.shutil,
        "which",
        lambda name: fake_forge if name == "forge" else real_which(name),
    )
    monkeypatch.setattr(RP, "_run_forge", lambda *_a, **_k: (0, "ok"))
    observed_snapshot_after_bootstrap = []

    def bounded_snapshot(*_args, **_kwargs):
        assert (project / "foundry.toml").is_file()
        observed_snapshot_after_bootstrap.append(True)
        return _bound_snapshot("c")

    monkeypatch.setattr(D, "build_audit_snapshot", bounded_snapshot)

    checkpoint, verdict, archive = D._bind_checkpoint_audit_snapshot(
        D.Checkpoint(),
        scratchpad,
        config,
        config_path=config_path,
        checkpoint_existed=False,
    )
    assert verdict.state == NEW
    assert archive is None

    # This is the write that occurred inside run_recon_prepass on the failed
    # canary. Under the corrected lifecycle it is already present and this call
    # is an idempotent no-op, so the phase boundary remains content-bound.
    sources = [project / "Vault.sol"]
    RP._bootstrap_evm_foundry_env(project, sources)
    assert (project / "foundry.toml").exists()
    D._assert_audit_snapshot_still_bound(config, scratchpad, "recon:pre-execution")
    assert checkpoint.audit_snapshot == config["_audit_snapshot"]
    assert observed_snapshot_after_bootstrap


def test_phase_boundary_drift_fails_closed_with_durable_receipt(
    tmp_path, monkeypatch
):
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    config = _config(project, scratchpad)
    config["_audit_snapshot"] = _bound_snapshot("a")
    monkeypatch.setattr(D, "build_audit_snapshot", lambda *_a, **_k: _bound_snapshot("b"))

    with pytest.raises(D.AuditInputDriftError, match="source_scope"):
        D._assert_audit_snapshot_still_bound(config, scratchpad, "verify:pre")
    receipt = json.loads((scratchpad / "audit_input_drift.json").read_text())
    assert receipt["phase"] == "verify:pre"
    assert receipt["changed_components"] == ["source_scope", "audit_config", "methodology", "toolchain"]
    assert receipt["action"] == "stop and request an explicit startup decision"


def test_matching_phase_boundary_does_not_emit_drift_receipt(
    tmp_path, monkeypatch
):
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    current = _bound_snapshot("a")
    config = _config(project, scratchpad)
    config["_audit_snapshot"] = current
    monkeypatch.setattr(D, "build_audit_snapshot", lambda *_a, **_k: current)
    D._assert_audit_snapshot_still_bound(config, scratchpad, "report:pre")
    assert not (scratchpad / "audit_input_drift.json").exists()


def test_phase_validator_rechecks_snapshot_after_worker_execution():
    source = Path(D.__file__).read_text(encoding="utf-8", errors="replace")
    start = source.index("def _run_phase_validators(")
    end = source.index("\ndef ", start + 4)
    validator = source[start:end]
    assert "_assert_audit_snapshot_still_bound(" in validator


def test_process_entrypoint_degrades_cleanly_on_post_worker_input_drift(monkeypatch):
    """Post-execution drift must not escape as an unhandled traceback."""
    monkeypatch.setattr(
        D,
        "main",
        lambda: (_ for _ in ()).throw(D.AuditInputDriftError("source_scope")),
    )
    assert D._run_main_entrypoint() == D.EXIT_DEGRADED
