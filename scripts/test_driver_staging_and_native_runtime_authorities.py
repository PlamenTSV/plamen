from __future__ import annotations

import inspect
from pathlib import Path
from types import SimpleNamespace

import pytest

import plamen_driver as driver
import posix_v2_compat_runtime as compat


def test_codex_compat_leaf_uses_exact_staging_override(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratchpad = tmp_path / "scratchpad"
    project.mkdir()
    scratchpad.mkdir()
    override = object()
    observed: dict[str, object] = {}
    contract = SimpleNamespace(
        phase="axis_disposition", backend="codex", work_unit_id="repair.worker.0001",
        immutable_inputs=(), bounded_lookup_inputs=(),
    )
    launch = SimpleNamespace(timeout_s=60, model="gpt-test")

    monkeypatch.setattr(driver, "_posix_v2_compat_process_active", lambda: True)
    monkeypatch.setattr(
        driver, "_prepared_headless_transaction_authority",
        lambda **_kwargs: (contract, launch),
    )
    monkeypatch.setattr(
        compat, "run_codex_exec",
        lambda **kwargs: observed.update(kwargs) or 0,
    )
    monkeypatch.setattr(
        driver, "_surface_exact_worker_log_to_phase_canonical", lambda **_kwargs: None,
    )
    monkeypatch.setattr(
        driver.headless_phase_identity,
        "requires_standard_posix_model_incorporation",
        lambda **_kwargs: False,
    )
    rc = driver._run_one_codex_exec(
        prompt="repair",
        phase=SimpleNamespace(name="axis_disposition", needs_mcp=False),
        config={"project_root": str(project), "_run_id": "run-test"},
        scratchpad=scratchpad,
        attempt=1,
        label="axis_repair_worker_0001",
        expected_outputs=["axis_coverage_repair_findings.md"],
        timeout=60,
        effective_model="gpt-test",
        phase_io_contract=contract,
        phase_io_launch=launch,
        posix_v2_compat_session_override=override,
    )
    assert rc == 0
    assert observed["session_authority"] is override


def test_claude_breadth_chain_forwards_staging_override(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    override = object()
    observed: dict[str, object] = {}
    contract = object()
    launch = SimpleNamespace(timeout_s=60, model="claude-test")
    monkeypatch.setattr(
        driver, "_prepared_headless_transaction_authority",
        lambda **_kwargs: (contract, launch),
    )
    monkeypatch.setattr(
        driver, "_run_transactional_headless_leaf",
        lambda **kwargs: observed.update(kwargs) or 0,
    )
    rc = driver._run_one_claude_headless_breadth_worker(
        prompt="repair",
        job={"agent_id": "0001", "output": "repair.md"},
        phase=SimpleNamespace(name="axis_disposition"),
        config={"project_root": str(tmp_path)},
        scratchpad=tmp_path,
        attempt=1,
        timeout=60,
        effective_model="claude-test",
        phase_io_contract=contract,
        phase_io_launch=launch,
        posix_v2_compat_session_override=override,
    )
    assert rc == 0
    assert observed["posix_v2_compat_session_override"] is override


def test_axis_staging_derives_and_closes_before_temporary_lease_cleanup() -> None:
    source = inspect.getsource(driver._run_axis_disposition_repair)
    assert "derive_posix_v2_compat_staging_session(" in source
    assert "parent_session_authority=(" in source
    assert "staging_authorities.callback(staging_session.close)" in source
    assert source.count("posix_v2_compat_session_override=(") == 2


def test_driver_config_retains_exact_native_runtime_bundle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = object()
    request = object()
    backend = object()
    generation = SimpleNamespace(backend=None)
    monkeypatch.setattr(
        driver, "authenticated_native_guest_request",
        lambda value: request if value is bundle else (_ for _ in ()).throw(ValueError()),
    )
    monkeypatch.setattr(
        driver, "native_guest_backend_execution_authority",
        lambda value: backend if value is bundle else (_ for _ in ()).throw(ValueError()),
    )
    monkeypatch.setattr(
        driver, "require_native_backend_execution_authority", lambda value: value,
    )
    monkeypatch.setattr(
        driver,
        "native_guest_backend_install_generation_authority",
        lambda value: generation if value is bundle else (_ for _ in ()).throw(ValueError()),
    )
    monkeypatch.setattr(
        driver, "require_backend_install_generation", lambda value: value,
    )
    config = driver._DriverConfig(
        {"pipeline": "sc"}, native_guest_runtime_authorities=bundle,
    )
    assert driver._native_guest_runtime_authorities_for_launch(config) is bundle
    assert driver._native_guest_request_for_launch(config) is request
    assert driver._native_backend_execution_authority_for_launch(config) is backend
    session = object()
    driver._bind_evm_session_tool_authority(config, session)
    assert config.get("_native_guest_runtime_authority") is bundle
    assert config.get("_evm_session_tool_authority") is session
    assert "_evm_session_tool_authority" not in config
    with pytest.raises(driver.HeadlessWorkerRuntimeError):
        driver._bind_evm_session_tool_authority(config, object())
    with pytest.raises(driver.HeadlessWorkerRuntimeError):
        driver._native_guest_runtime_authorities_for_launch(dict(config))


def test_native_startup_acquires_complete_runtime_bundle() -> None:
    source = inspect.getsource(driver.main)
    assert "acquire_native_guest_runtime_authorities()" in source
    assert "native_guest_runtime_authorities=_native_guest_startup" in source
    assert "acquire_native_guest_backend_execution_authority" not in source


@pytest.mark.parametrize(
    ("pipeline", "mode", "expected"),
    (
        ("sc", "thorough", True),
        ("sc", "core", False),
        ("sc", "light", False),
        ("l1", "thorough", False),
    ),
)
def test_completion_receipt_eligibility_is_exact(
    pipeline: str, mode: str, expected: bool,
) -> None:
    assert driver._completion_receipt_required(
        {"pipeline": pipeline, "mode": mode},
    ) is expected


def test_compatibility_marker_cannot_waive_required_completion_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        driver, "_posix_v2_compat_process_active", lambda: True,
    )
    # Eligibility is a pipeline/mode obligation, not a claim that the current
    # process has native authority. A compatibility marker must not bypass
    # terminal publication/replay checks merely by making this return False.
    assert driver._completion_receipt_required(
        {"pipeline": "sc", "mode": "thorough"},
    ) is True


def test_operator_stop_before_phase_is_absent_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("PLAMEN_STOP_BEFORE_PHASE", raising=False)
    assert driver._admit_operator_stop_before_phase(driver.SC_PHASES) is None


def test_operator_stop_before_phase_admits_exact_active_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PLAMEN_STOP_BEFORE_PHASE", "sc_verify_queue")
    assert (
        driver._admit_operator_stop_before_phase(driver.SC_PHASES)
        == "sc_verify_queue"
    )


@pytest.mark.parametrize("value", (" sc_verify_queue", "verify", "SC_VERIFY_QUEUE"))
def test_operator_stop_before_phase_rejects_ambiguous_or_unknown_names(
    monkeypatch: pytest.MonkeyPatch, value: str,
) -> None:
    monkeypatch.setenv("PLAMEN_STOP_BEFORE_PHASE", value)
    with pytest.raises(ValueError, match="PLAMEN_STOP_BEFORE_PHASE"):
        driver._admit_operator_stop_before_phase(driver.SC_PHASES)
