from __future__ import annotations

from pathlib import Path
import sys

import pytest


sys.path.insert(0, str(Path(__file__).resolve().parent))

import posix_backend_execution as execution
import worker_execution_receipts as wer


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX boundary only")
@pytest.mark.parametrize("entrypoint", ["public", "direct"])
def test_native_gate_is_first_and_preserves_cause(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    entrypoint: str,
) -> None:
    events: list[str] = []
    supplied_authority = object()

    class Evil:
        def __getattribute__(self, name: str):
            events.append(f"get:{name}")
            return object.__getattribute__(self, name)

        def __eq__(self, _other: object) -> bool:
            events.append("eq")
            return False

        def __fspath__(self) -> str:
            events.append("fspath")
            return str(tmp_path)

        def __iter__(self):
            events.append("iter")
            return iter(())

    def gate(value: object) -> None:
        assert value is supplied_authority
        events.append("native-gate")
        raise execution.PosixBackendExecutionError(
            "NATIVE_BRIDGE_UNAVAILABLE", "no role-3 native authority"
        )

    monkeypatch.setattr(wer, "require_native_posix_backend_execution", gate)
    evil = Evil()
    runner = (
        wer.run_observed_worker
        if entrypoint == "public"
        else wer._run_observed_worker_direct
    )
    with pytest.raises(wer.NativePosixProcessAuthorityUnavailable) as caught:
        runner(
            scratchpad=evil,
            bindings=evil,
            argv=evil,
            cwd=evil,
            output_scope_relative=evil,
            expected_outputs=evil,
            parser_digest=evil,
            environment=evil,
            environment_allowlist=evil,
            posix_backend_execution=supplied_authority,
        )
    assert events == ["native-gate"]
    assert isinstance(caught.value.__cause__, execution.PosixBackendExecutionError)
    assert caught.value.__cause__.code == "NATIVE_BRIDGE_UNAVAILABLE"
    assert list(tmp_path.iterdir()) == []


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX boundary only")
@pytest.mark.parametrize("entrypoint", ["public", "direct"])
def test_real_absence_rejects_forged_execution_before_its_methods(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    entrypoint: str,
) -> None:
    marker = tmp_path / "forged-method-ran"
    forged = object.__new__(execution.PosixBackendExecution)

    def forged_preview(_self: object):
        marker.write_text("unsafe", encoding="utf-8")
        raise AssertionError("forged Python method must not run")

    monkeypatch.setattr(
        execution.PosixBackendExecution,
        "preview_physical_binding",
        forged_preview,
    )
    monkeypatch.setattr(
        execution, "_admitted_native_supervisor_module", lambda: None
    )
    runner = (
        wer.run_observed_worker
        if entrypoint == "public"
        else wer._run_observed_worker_direct
    )
    with pytest.raises(
        wer.NativePosixProcessAuthorityUnavailable,
        match="NATIVE_POSIX_PROCESS_AUTHORITY_UNAVAILABLE",
    ) as caught:
        runner(
            scratchpad=tmp_path,
            bindings=object(),
            argv=(),
            cwd=tmp_path,
            output_scope_relative="output",
            expected_outputs=(),
            parser_digest=lambda _path, _raw: "0" * 64,
            posix_backend_execution=forged,
        )
    assert isinstance(caught.value.__cause__, execution.PosixBackendExecutionError)
    assert caught.value.__cause__.code == "NATIVE_BRIDGE_UNAVAILABLE"
    assert not marker.exists()
    assert list(tmp_path.iterdir()) == []
