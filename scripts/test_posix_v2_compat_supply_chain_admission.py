from __future__ import annotations

import json
import hashlib
from pathlib import Path

import pytest

import posix_v2_compat_runtime as COMPAT
import supply_chain_gate as SC


@pytest.fixture(params=sorted(COMPAT._COMPAT_BACKENDS))
def compat_case(tmp_path: Path, request):
    """Exercise EVERY supported compatibility backend, not just the default.

    The gate previously hardcoded ``backend == "codex"`` while the runtime
    supported ``{"claude", "codex"}``, and this fixture never overrode the
    ``codex`` default -- so the Claude backend was never admitted and could not
    start an audit at all on POSIX compatibility.  Parametrizing here keeps any
    future backend-specific admission regression visible.
    """
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    project.mkdir()
    scratchpad.mkdir()
    session = COMPAT.issue_posix_v2_compat_session_for_installed_front(
        run_id="supply-chain-test", project_root=project, scratchpad=scratchpad,
        backend=request.param,
    )
    try:
        yield project, scratchpad, session
    finally:
        try:
            session.close()
        except COMPAT.PosixV2CompatRuntimeError:
            pass


def _install_harmless_osv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    binary_dir = tmp_path / "scanner-bin"
    binary_dir.mkdir()
    scanner = binary_dir / "osv-scanner"
    scanner.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' '{\"results\":[]}'\n",
        encoding="utf-8",
    )
    scanner.chmod(0o755)
    monkeypatch.setenv("PATH", str(binary_dir))
    return scanner


def test_real_compat_scanner_issues_replayable_bound_admission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, compat_case,
) -> None:
    project, _scratchpad, session = compat_case
    scan_root = project / "packages" / "app"
    scan_root.mkdir(parents=True)
    _install_harmless_osv(tmp_path, monkeypatch)
    (scan_root / "package-lock.json").write_text("{}\n", encoding="utf-8")

    admission = SC.gate_supply_chain(scan_root, posix_compat_session=session)
    assert type(admission) is SC.SupplyChainAdmission
    view = SC.project_supply_chain_admission(
        admission, posix_compat_session=session,
    )
    assert view["status"] == "ADMITTED"
    assert view["scanner_applicability"] == "APPLICABLE"
    assert view["run_id"] == "supply-chain-test"
    assert view["scan_root"] == str(scan_root)
    assert view["lockfile_count"] == 1
    assert len(view["scanner_evidence"]) == 1
    assert view["scanner_evidence"][0]["scanner_id"] == "osv-scanner"
    assert view["ordinary_vulnerability_count"] == 0
    assert len(view["admission_sha256"]) == 64
    implicit = [
        row for row in view["input_denominator"]
        if "SCANNER_IMPLICIT" in row["kinds"]
    ]
    assert implicit == [{
        "kinds": ("HEURISTIC_INPUT", "SCANNER_IMPLICIT"),
        "path": "package.json", "state": "ABSENT",
    }]


def test_no_lockfile_is_explicitly_not_applicable(compat_case) -> None:
    project, _scratchpad, session = compat_case
    admission = SC.gate_supply_chain(project, posix_compat_session=session)
    view = SC.project_supply_chain_admission(
        admission, posix_compat_session=session,
    )
    assert view["status"] == "ADMITTED"
    assert view["scanner_applicability"] == "NOT_APPLICABLE"
    assert "not proven safe" in view["scope_limit"]
    assert view["scanner_evidence"] == ()


def test_npm_offline_is_unavailable_before_any_transport(
    compat_case, monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, _scratchpad, session = compat_case
    lock = project / "package-lock.json"
    lock.write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(
        SC.subprocess, "Popen",
        lambda *_args, **_kwargs: pytest.fail("npm transport was reached"),
    )
    monkeypatch.setattr(
        SC, "run_owned_process",
        lambda *_args, **_kwargs: pytest.fail("owned npm transport was reached"),
    )
    binary = SC._AuthorizedScanner("npm", "/never/execute/npm")
    ordinary = SC._call_offline_scanner(binary, lock)
    compatible = SC._call_offline_scanner(
        binary, lock, posix_compat_session=session,
    )
    assert ordinary.state is SC.OfflineScanState.UNAVAILABLE
    assert compatible.state is SC.OfflineScanState.UNAVAILABLE
    assert "skips advisory lookup" in ordinary.reason


@pytest.mark.parametrize("use_compat", [False, True])
def test_npm_only_installation_cannot_admit_lockfile(
    compat_case, monkeypatch: pytest.MonkeyPatch, use_compat: bool,
) -> None:
    project, _scratchpad, session = compat_case
    (project / "package-lock.json").write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(
        SC.shutil, "which", lambda name: "/never/npm" if name == "npm" else None,
    )
    monkeypatch.setattr(
        SC, "_call_offline_scanner",
        lambda *_args, **_kwargs: pytest.fail("npm was selected as an offline scanner"),
    )
    kwargs = {"posix_compat_session": session} if use_compat else {}
    with pytest.raises(SC.SupplyChainAbortError, match="no offline scanner"):
        SC.gate_supply_chain(project, **kwargs)


def test_unsupported_shrinkwrap_is_not_silently_admitted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, compat_case,
) -> None:
    project, _scratchpad, session = compat_case
    _install_harmless_osv(tmp_path, monkeypatch)
    (project / "npm-shrinkwrap.json").write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(
        SC, "_call_offline_scanner",
        lambda *_args, **_kwargs: pytest.fail("unsupported lock was scanned"),
    )
    with pytest.raises(SC.SupplyChainAbortError, match="no compatible offline scanner"):
        SC.gate_supply_chain(project, posix_compat_session=session)


def test_not_applicable_denominator_drift_during_gate_fails_closed(
    compat_case, monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, _scratchpad, session = compat_case
    original = SC._compat_snapshot_heuristic_hit
    def mutate_after_snapshot(snapshot):
        result = original(snapshot)
        (project / "package.json").write_text("{}\n", encoding="utf-8")
        return result
    monkeypatch.setattr(SC, "_compat_snapshot_heuristic_hit", mutate_after_snapshot)
    with pytest.raises(SC.SupplyChainAbortError, match="drifted during admission"):
        SC.gate_supply_chain(project, posix_compat_session=session)


def test_input_drift_and_receipt_forgery_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, compat_case,
) -> None:
    project, scratchpad, session = compat_case
    _install_harmless_osv(tmp_path, monkeypatch)
    lock = project / "package-lock.json"
    lock.write_text("{}\n", encoding="utf-8")
    admission = SC.gate_supply_chain(project, posix_compat_session=session)
    view = SC.project_supply_chain_admission(admission, posix_compat_session=session)
    evidence = view["scanner_evidence"][0]
    receipt = scratchpad / evidence["receipt_path"]
    payload = json.loads(receipt.read_text(encoding="utf-8"))
    payload["scanner_id"] = "forged"
    receipt.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(SC.SupplyChainAbortError, match="evidence drifted"):
        SC.project_supply_chain_admission(admission, posix_compat_session=session)

    # A fresh run proves relevant source drift independently of receipt drift.
    receipt.unlink()
    admission = SC.gate_supply_chain(project, posix_compat_session=session)
    lock.write_text('{"changed":true}\n', encoding="utf-8")
    with pytest.raises(SC.SupplyChainAbortError, match="inputs drifted"):
        SC.project_supply_chain_admission(admission, posix_compat_session=session)


def test_typed_fake_scanner_result_has_no_live_lineage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, compat_case,
) -> None:
    project, _scratchpad, session = compat_case
    _install_harmless_osv(tmp_path, monkeypatch)
    (project / "package-lock.json").write_text("{}\n", encoding="utf-8")
    fake = SC.OfflineScanResult(
        SC.OfflineScanState.SUCCEEDED,
        output=json.dumps({"results": []}),
        returncode=0,
    )
    monkeypatch.setattr(SC, "_call_offline_scanner", lambda *_args, **_kwargs: fake)
    with pytest.raises(SC.SupplyChainAbortError, match="execution lineage"):
        SC.gate_supply_chain(project, posix_compat_session=session)


def test_successful_result_observed_before_gate_is_stale(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, compat_case,
) -> None:
    project, _scratchpad, session = compat_case
    scanner = _install_harmless_osv(tmp_path, monkeypatch)
    lock = project / "package-lock.json"
    lock.write_text("{}\n", encoding="utf-8")
    stale = SC._call_offline_scanner(
        SC._AuthorizedScanner("osv-scanner", str(scanner)), lock,
        posix_compat_session=session,
    )
    monkeypatch.setattr(SC, "_call_offline_scanner", lambda *_args, **_kwargs: stale)
    with pytest.raises(SC.SupplyChainAbortError, match="execution lineage"):
        SC.gate_supply_chain(project, posix_compat_session=session)


def test_repeated_scan_keeps_both_live_admissions_replayable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, compat_case,
) -> None:
    project, _scratchpad, session = compat_case
    _install_harmless_osv(tmp_path, monkeypatch)
    (project / "package-lock.json").write_text("{}\n", encoding="utf-8")
    first = SC.gate_supply_chain(project, posix_compat_session=session)
    second = SC.gate_supply_chain(project, posix_compat_session=session)
    first_view = SC.project_supply_chain_admission(first, posix_compat_session=session)
    second_view = SC.project_supply_chain_admission(second, posix_compat_session=session)
    assert first_view["scanner_evidence"][0]["receipt_path"] != (
        second_view["scanner_evidence"][0]["receipt_path"]
    )


def test_original_swap_during_scanner_cannot_change_staged_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, compat_case,
) -> None:
    project, _scratchpad, session = compat_case
    scanner = _install_harmless_osv(tmp_path, monkeypatch)
    scanner.write_text(
        "#!/bin/sh\ntarget=''\nprior=''\n"
        "for value do [ \"$prior\" = '-L' ] && target=$value; prior=$value; done\n"
        "expected='{\"admitted\":true}'\n"
        "[ \"$(/bin/cat \"$target\")\" = \"$expected\" ] || exit 9\n"
        "printf '%s\\n' '{\"results\":[]}'\n",
        encoding="utf-8",
    )
    scanner.chmod(0o755)
    lock = project / "package-lock.json"
    lock.write_text('{"admitted":true}\n', encoding="utf-8")
    real_popen = SC.subprocess.Popen
    swapped = False
    def swap_then_launch(*args, **kwargs):
        nonlocal swapped
        if not swapped:
            swapped = True
            lock.write_text('{"swapped":true}\n', encoding="utf-8")
        return real_popen(*args, **kwargs)
    monkeypatch.setattr(SC.subprocess, "Popen", swap_then_launch)
    with pytest.raises(SC.SupplyChainAbortError, match="drifted during admission"):
        SC.gate_supply_chain(project, posix_compat_session=session)


def test_invalid_utf8_scanner_stdout_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, compat_case,
) -> None:
    project, _scratchpad, session = compat_case
    scanner = _install_harmless_osv(tmp_path, monkeypatch)
    # Replacement decoding would turn this into valid, clean scanner JSON.
    # The regression must detect lossy admission, not merely malformed JSON.
    scanner.write_text(
        "#!/bin/sh\nprintf '{\"results\":[],\"diagnostic\":\"\\377\"}\\n'\n",
        encoding="utf-8",
    )
    scanner.chmod(0o755)
    (project / "package-lock.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(SC.SupplyChainAbortError, match="could verify"):
        SC.gate_supply_chain(project, posix_compat_session=session)


def test_receipt_hashes_exact_raw_stderr_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, compat_case,
) -> None:
    project, scratchpad, session = compat_case
    scanner = _install_harmless_osv(tmp_path, monkeypatch)
    script = scanner.read_text(encoding="utf-8")
    scanner.write_text(script + "printf '\\377' >&2\n", encoding="utf-8")
    scanner.chmod(0o755)
    (project / "package-lock.json").write_text("{}\n", encoding="utf-8")
    admission = SC.gate_supply_chain(project, posix_compat_session=session)
    view = SC.project_supply_chain_admission(admission, posix_compat_session=session)
    receipt_path = scratchpad / view["scanner_evidence"][0]["receipt_path"]
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt["stderr_sha256"] == hashlib.sha256(b"\xff").hexdigest()


def test_broken_heuristic_symlink_is_not_absent(compat_case) -> None:
    project, _scratchpad, session = compat_case
    (project / "package.json").symlink_to(project / "missing-package.json")
    with pytest.raises(SC.SupplyChainAbortError, match="type or size is unsafe"):
        SC.gate_supply_chain(project, posix_compat_session=session)

def test_forged_admission_and_expired_session_are_rejected(compat_case) -> None:
    project, _scratchpad, session = compat_case
    admission = SC.gate_supply_chain(project, posix_compat_session=session)
    forged = object.__new__(SC.SupplyChainAdmission)
    with pytest.raises(SC.SupplyChainAbortError, match="shell is incomplete"):
        SC.project_supply_chain_admission(forged, posix_compat_session=session)
    session.close()
    with pytest.raises(SC.SupplyChainAbortError, match="session"):
        SC.project_supply_chain_admission(admission, posix_compat_session=session)


def test_historical_no_session_return_is_none(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    assert SC.gate_supply_chain(project) is None
