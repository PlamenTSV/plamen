from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import uuid

import pytest

from artifact_ledger import read_artifact_ledger
from audit_snapshot import build_audit_snapshot
from phase_io_contracts import resolve_phase_io_contract
import program_facts_driver_integration as INTEGRATION
from program_facts_driver_integration import (
    PROGRAM_FACTS_CHECKPOINT_CAPTURE_PATH,
    ProgramFactsDriverIntegrationError,
    ensure_program_facts_stage2_emit_only,
)
from program_facts_source_manifest import (
    build_program_facts_source_manifest,
    capture_program_facts_audit_snapshot_authority,
)
import program_facts_source_manifest as SOURCE_AUTHORITY
from program_facts_methodology_authority import (
    PROGRAM_FACTS_METHODOLOGY_INPUT_PATHS,
)
import program_facts_methodology_authority as METHODOLOGY_AUTHORITY
from program_facts_types import canonical_file_bytes, strict_json_loads


SIDE_CARS = (
    "mechanical_program_facts.v1.json",
    "mechanical_program_facts_receipt.v1.json",
    "mechanical_program_facts_debt.v1.json",
)


def _fixture(
    tmp_path: Path,
    *,
    language: str = "evm",
    controlled_authority: bool = True,
) -> dict[str, object]:
    project = tmp_path / "project"
    source = project / "src" / "Main.sol"
    source.parent.mkdir(parents=True)
    source.write_bytes(
        b"// SPDX-License-Identifier: MIT\n"
        b"pragma solidity ^0.8.20;\n"
        b"contract Main { uint256 public value; }\n"
    )
    (project / "foundry.toml").write_bytes(
        b"[profile.default]\nsrc = \"src\"\n"
    )
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir()
    config = {
        "project_root": str(project),
        "scratchpad": str(scratchpad),
        "mode": "thorough",
        "pipeline": "sc",
        "language": language,
        "cli_backend": "claude",
        "scope_notes": "Program Facts driver integration fixture",
    }
    installed_root = Path(__file__).resolve().parents[1]
    snapshot = (
        build_audit_snapshot(config, installed_root)
        if controlled_authority and language == "evm"
        else {}
    )
    snapshot_authority = None
    if controlled_authority and language == "evm":
        snapshot_config = INTEGRATION._snapshot_visible_config(config)
        # The shared repository is intentionally dirty and other workers can
        # update CI/toolchain files while this fixture runs. Pin only the
        # source-authority module's live implementation identity in this test
        # process to the already-built snapshot. Production has no such
        # argument or bypass and continues to fail closed on live-tree drift.
        with patch.object(
            SOURCE_AUTHORITY,
            "_live_audit_identity",
            side_effect=lambda _config: (
                SOURCE_AUTHORITY._audit_identity_from_snapshot(snapshot)
            ),
        ):
            snapshot_authority = (
                capture_program_facts_audit_snapshot_authority(
                    snapshot,
                    config=snapshot_config,
                )
            )
    run_id = str(uuid.uuid4())
    config["_audit_snapshot"] = snapshot
    config["_run_id"] = run_id
    checkpoint = {
        "completed": [],
        "degraded": [],
        "rate_limited_at": None,
        "config": config,
        "audit_snapshot": snapshot,
        "run_id": run_id,
    }
    (scratchpad / "_v2_checkpoint.json").write_text(
        json.dumps(checkpoint, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return {
        "project": project,
        "scratchpad": scratchpad,
        "config": config,
        "snapshot": snapshot,
        "run_id": run_id,
        "snapshot_authority": snapshot_authority,
    }


def _run(fixture: dict[str, object], **kwargs: object):
    call = {
        "config": fixture["config"],
        "scratchpad": fixture["scratchpad"],
        "project_root": fixture["project"],
        "run_id": fixture["run_id"],
        "audit_snapshot": fixture["snapshot"],
        **kwargs,
    }
    if fixture.get("snapshot_authority") is None:
        return ensure_program_facts_stage2_emit_only(**call)

    # A source-manifest capture capability is intentionally one-shot. Mint a
    # fresh capture inside each production call while pinning only this test
    # process's live installed-tree identity. Reusing a captured capability
    # here would make the replay fixture weaker than production.
    def fresh_source_capture(
        source_config: dict[str, object],
        audit_snapshot: dict[str, object],
        *,
        compiled_source_paths: object,
    ):
        return build_program_facts_source_manifest(
            source_config,
            audit_snapshot,
            compiled_source_paths=compiled_source_paths,
        )

    with (
        patch.object(
            SOURCE_AUTHORITY,
            "_live_audit_identity",
            side_effect=lambda _config: (
                SOURCE_AUTHORITY._audit_identity_from_snapshot(
                    fixture["snapshot"]
                )
            ),
        ),
        patch.object(
            INTEGRATION,
            "capture_program_facts_audit_snapshot_authority",
            return_value=fixture["snapshot_authority"],
        ),
        patch.object(
            INTEGRATION,
            "build_program_facts_source_manifest",
            side_effect=fresh_source_capture,
        ),
        patch.object(
            METHODOLOGY_AUTHORITY,
            "build_methodology_snapshot_component",
            return_value=dict(
                fixture["snapshot"]["components"]["methodology"]
            ),
        ),
    ):
        return ensure_program_facts_stage2_emit_only(**call)


def test_checkpoint_capture_is_zero_input_driver_phaseio_predecessor() -> None:
    capture = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="recon",
        work_unit_id="program_facts_checkpoint_capture",
        exact_inputs=(),
        exact_outputs=(PROGRAM_FACTS_CHECKPOINT_CAPTURE_PATH,),
        exact_writer="DRIVER",
    )
    methodology = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="recon",
        work_unit_id="program_facts_methodology_capture",
        exact_inputs=(PROGRAM_FACTS_CHECKPOINT_CAPTURE_PATH,),
        exact_outputs=PROGRAM_FACTS_METHODOLOGY_INPUT_PATHS,
        exact_writer="DRIVER",
    )
    bake = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="recon",
        work_unit_id="program_facts_bake",
        exact_inputs=(
            PROGRAM_FACTS_CHECKPOINT_CAPTURE_PATH,
            *PROGRAM_FACTS_METHODOLOGY_INPUT_PATHS,
        ),
        exact_outputs=SIDE_CARS,
        exact_writer="DRIVER",
    )

    assert capture.immutable_inputs == ()
    assert capture.model_invoked is False
    assert capture.required_commit_actor == "DRIVER"
    assert tuple(output.path for output in capture.outputs) == (
        PROGRAM_FACTS_CHECKPOINT_CAPTURE_PATH,
    )
    assert methodology.immutable_inputs == (
        f"scratchpad:{PROGRAM_FACTS_CHECKPOINT_CAPTURE_PATH}",
    )
    assert bake.immutable_inputs[0] == (
        f"scratchpad:{PROGRAM_FACTS_CHECKPOINT_CAPTURE_PATH}"
    )
    assert "scratchpad:_v2_checkpoint.json" not in bake.immutable_inputs


def test_evm_hook_commits_exact_sidecars_and_live_checkpoint_churn_is_irrelevant(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    first = _run(fixture)

    assert first.state == "UNSUPPORTED"
    assert first.consumer_activation is False
    assert first.valid is True
    assert first.reused is False
    scratchpad = fixture["scratchpad"]
    before = {
        name: (scratchpad / name).read_bytes() for name in SIDE_CARS
    }
    capture_raw = (
        scratchpad / PROGRAM_FACTS_CHECKPOINT_CAPTURE_PATH
    ).read_bytes()
    capture = strict_json_loads(
        capture_raw,
        require_final_lf=True,
        require_canonical=True,
    )
    assert set(capture) == {"audit_snapshot", "run_id"}
    assert capture["audit_snapshot"] == fixture["snapshot"]
    assert capture["run_id"] == fixture["run_id"]

    checkpoint_path = scratchpad / "_v2_checkpoint.json"
    checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    checkpoint["completed"] = ["recon"]
    checkpoint["phase_commits"] = {"fixture": {"state": "changed"}}
    checkpoint_path.write_text(
        json.dumps(checkpoint, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    fixture["config"]["_unrelated_runtime_nonce"] = "ignored-private-state"

    second = _run(fixture)
    assert second.valid is True
    assert second.reused is True
    assert {
        name: (scratchpad / name).read_bytes() for name in SIDE_CARS
    } == before
    assert (
        scratchpad / PROGRAM_FACTS_CHECKPOINT_CAPTURE_PATH
    ).read_bytes() == capture_raw

    ledger = read_artifact_ledger(scratchpad)
    expected_units = {
        "sc/thorough/evm/claude/recon/program_facts_checkpoint_capture",
        "sc/thorough/evm/claude/recon/program_facts_methodology_capture",
        "sc/thorough/evm/claude/recon/program_facts_bake",
    }
    assert expected_units <= set(ledger["work_units"])
    assert all(
        ledger["work_units"][key]["semantic_status"] == "ACTIVE"
        for key in expected_units
    )


def test_snapshot_visible_config_change_is_not_private_runtime_churn(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    _run(fixture)
    fixture["config"]["scope_notes"] = "semantically changed scope"

    with pytest.raises(
        ProgramFactsDriverIntegrationError,
        match="source snapshot|identity|config|drift|authority|emit-only",
    ):
        _run(fixture)


def test_snapshot_or_run_drift_cannot_reuse_immutable_capture(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    _run(fixture)

    with pytest.raises(
        ProgramFactsDriverIntegrationError,
        match="capture|snapshot|run|mismatch|drift",
    ):
        _run(fixture, run_id=str(uuid.uuid4()))

    forged = dict(fixture["snapshot"])
    forged["snapshot_digest"] = "f" * 64
    with pytest.raises(
        ProgramFactsDriverIntegrationError,
        match="capture|snapshot|mismatch|drift",
    ):
        _run(fixture, audit_snapshot=forged)


def test_crash_after_first_bake_publication_resumes_without_rearming(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    fired = False

    def crash(label: str) -> None:
        nonlocal fired
        if label == "program_facts_bake:published:1" and not fired:
            fired = True
            raise RuntimeError("forced crash after first bake publication")

    with pytest.raises(RuntimeError, match="forced crash"):
        _run(fixture, fault_injector=crash)

    scratchpad = fixture["scratchpad"]
    present = [name for name in SIDE_CARS if (scratchpad / name).exists()]
    assert present == [SIDE_CARS[0]]
    ledger_before = read_artifact_ledger(scratchpad)
    bake_key = "sc/thorough/evm/claude/recon/program_facts_bake"
    input_digest = ledger_before["work_units"][bake_key]["input_set_digest"]

    resumed = _run(fixture)
    assert resumed.valid is True
    assert resumed.reused is False
    assert all((scratchpad / name).is_file() for name in SIDE_CARS)
    ledger_after = read_artifact_ledger(scratchpad)
    assert ledger_after["work_units"][bake_key]["input_set_digest"] == input_digest
    assert ledger_after["work_units"][bake_key]["semantic_status"] == "ACTIVE"


@pytest.mark.parametrize(
    ("pipeline", "language"),
    (
        ("sc", "solana"),
        ("sc", "soroban"),
        ("sc", "aptos"),
        ("sc", "sui"),
        ("l1", "go"),
        ("l1", "rust"),
        ("l1", "daml"),
    ),
)
def test_non_evm_stage2_is_an_exact_noop(
    tmp_path: Path,
    pipeline: str,
    language: str,
) -> None:
    fixture = _fixture(
        tmp_path,
        language=language,
        controlled_authority=False,
    )
    fixture["config"]["pipeline"] = pipeline
    result = _run(fixture)

    assert result.state == "NOOP_UNSUPPORTED_ECOSYSTEM"
    assert result.valid is True
    assert result.consumer_activation is False
    assert not (
        fixture["scratchpad"] / PROGRAM_FACTS_CHECKPOINT_CAPTURE_PATH
    ).exists()
    assert not any((fixture["scratchpad"] / name).exists() for name in SIDE_CARS)


def test_driver_orders_program_facts_before_legacy_recon_prepass() -> None:
    source = (
        Path(__file__).with_name("plamen_driver.py")
        .read_text(encoding="utf-8", errors="strict")
    )
    main = source[source.index("def main(") :]
    hook = main.index("_ensure_program_facts_stage2_emit_only(")
    prepass = main.index("run_recon_prepass")
    assert hook < prepass
    assert main.index("_ensure_fresh_audit_sentinel(") < hook
    assert main.index("checkpoint.save(scratchpad)") < hook


def test_driver_cannot_continue_false_clean_when_debt_persistence_fails() -> None:
    source = (
        Path(__file__).with_name("plamen_driver.py")
        .read_text(encoding="utf-8", errors="strict")
    )
    main = source[source.index("def main(") :]
    hook = main.index("_ensure_program_facts_stage2_emit_only(")
    prepass = main.index("# Mechanical pre-pass", hook)
    failure_boundary = main[hook:prepass]

    runtime_debt = failure_boundary.index(
        "_record_program_facts_stage2_runtime_debt("
    )
    projection = failure_boundary.index("_append_phase_io_debt(")
    assert runtime_debt < projection
    assert "failed to persist runtime degradation" in failure_boundary
    assert "sys.exit(EXIT_DEGRADED)" in failure_boundary


def test_runtime_debt_survives_recon_projection_clear_and_exactly_clears(
    tmp_path: Path,
) -> None:
    import plamen_driver as DRIVER

    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    checkpoint = DRIVER.Checkpoint(run_id=str(uuid.uuid4()))
    checkpoint.save(scratchpad)

    receipt_sha256 = DRIVER._record_program_facts_stage2_runtime_debt(
        scratchpad,
        checkpoint,
        "controlled Program Facts publication failure",
    )
    debt_id = DRIVER._PROGRAM_FACTS_STAGE2_RUNTIME_DEBT_ID
    receipt_path = (
        scratchpad / DRIVER._PROGRAM_FACTS_STAGE2_RUNTIME_DEBT_PATH
    )
    assert checkpoint.runtime_debts == {debt_id: receipt_sha256}
    assert hashlib.sha256(receipt_path.read_bytes()).hexdigest() == (
        receipt_sha256
    )

    # A later clean recon commit may clear only its phase projection. The
    # process-level checkpoint binding remains authoritative and visible.
    recon_projection = scratchpad / "recon.degraded"
    recon_projection.write_text("projection\n", encoding="utf-8")
    recon_projection.unlink()
    replayed = DRIVER.Checkpoint.load(scratchpad)
    assert replayed.runtime_debts == {debt_id: receipt_sha256}

    assert DRIVER._clear_program_facts_stage2_runtime_debt(
        scratchpad,
        replayed,
    )
    final = DRIVER.Checkpoint.load(scratchpad)
    assert final.runtime_debts == {}
    assert not receipt_path.exists()


def test_checkpoint_capture_bytes_are_canonical_and_content_addressed(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    _run(fixture)
    path = fixture["scratchpad"] / PROGRAM_FACTS_CHECKPOINT_CAPTURE_PATH
    raw = path.read_bytes()
    value = strict_json_loads(
        raw,
        require_final_lf=True,
        require_canonical=True,
    )
    assert raw == canonical_file_bytes(value)
    assert hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize(
    ("os_name", "sys_platform", "machine", "expected"),
    (
        ("nt", "win32", "AMD64", ("windows", "amd64")),
        ("posix", "linux", "x86_64", ("linux", "amd64")),
        ("posix", "darwin", "arm64", ("macos", "arm64")),
        ("posix", "linux", "aarch64", ("linux", "arm64")),
    ),
)
def test_portable_platform_normalizes_supported_os_arch_pairs(
    os_name: str,
    sys_platform: str,
    machine: str,
    expected: tuple[str, str],
) -> None:
    fake_os = SimpleNamespace(
        name=os_name,
        sys=SimpleNamespace(platform=sys_platform),
    )
    fake_platform = SimpleNamespace(machine=lambda: machine)
    with (
        patch.object(INTEGRATION, "os", fake_os),
        patch.object(INTEGRATION, "host_platform", fake_platform),
    ):
        platform = INTEGRATION._portable_platform()

    assert (platform.os, platform.architecture) == expected


@pytest.mark.parametrize(
    ("os_name", "sys_platform", "machine"),
    (
        ("posix", "freebsd14", "x86_64"),
        ("posix", "linux", "riscv64"),
    ),
)
def test_portable_platform_rejects_unreviewed_host_identity(
    os_name: str,
    sys_platform: str,
    machine: str,
) -> None:
    fake_os = SimpleNamespace(
        name=os_name,
        sys=SimpleNamespace(platform=sys_platform),
    )
    fake_platform = SimpleNamespace(machine=lambda: machine)
    with (
        patch.object(INTEGRATION, "os", fake_os),
        patch.object(INTEGRATION, "host_platform", fake_platform),
        pytest.raises(
            ProgramFactsDriverIntegrationError,
            match="unsupported",
        ),
    ):
        INTEGRATION._portable_platform()


def test_atomic_materialize_is_idempotent_beyond_legacy_max_path(
    tmp_path: Path,
) -> None:
    nested = tmp_path
    for ordinal in range(5):
        nested /= f"program-facts-long-path-{ordinal}-" + ("x" * 48)
    target = nested / "mechanical_program_facts.v1.json"
    assert len(str(target)) > 260
    raw = b'{"schema_version":"program-facts-long-path-test.v1"}\n'

    INTEGRATION._atomic_materialize(target, raw)
    first_stat = INTEGRATION.rooted_path_io.lstat(target)
    INTEGRATION._atomic_materialize(target, raw)

    assert INTEGRATION.rooted_path_io.read_bytes(target) == raw
    assert (
        INTEGRATION.rooted_path_io.lstat(target).st_ino
        == first_stat.st_ino
    )
    assert not tuple(
        entry
        for entry in INTEGRATION.rooted_path_io.scandir(target.parent)
        if entry.name.startswith(".program-facts.")
        and entry.name.endswith(".publishing.tmp")
    )


def test_stage2_emit_only_sidecars_have_no_active_successor_consumer() -> None:
    scripts = Path(__file__).resolve().parent
    active_successor_sources = (
        "plamen_driver.py",
        "plamen_types.py",
        "plamen_prompt.py",
        "plamen_mechanical.py",
        "plamen_validators.py",
    )
    forbidden = (
        *SIDE_CARS,
        "program_facts_slicing",
        "program_facts_obligations",
    )
    for relative in active_successor_sources:
        source = (scripts / relative).read_text(
            encoding="utf-8",
            errors="strict",
        )
        assert not any(token in source for token in forbidden), relative

    driver_source = (scripts / "plamen_driver.py").read_text(
        encoding="utf-8",
        errors="strict",
    )
    hook_call = driver_source[
        driver_source.index(
            "program_facts_outcome = _ensure_program_facts_stage2_emit_only("
        ) :
        driver_source.index(
            "# Mechanical pre-pass",
            driver_source.index(
                "program_facts_outcome = "
                "_ensure_program_facts_stage2_emit_only("
            ),
        )
    ]
    assert "consumer_activation=%s" in hook_call
    assert "program_facts_outcome.consumer_activation" in hook_call
    assert 'config["program_facts' not in hook_call
    assert 'config["_program_facts' not in hook_call
