"""Regressions for bounded POSIX-V2 prewarm publication."""
from __future__ import annotations
import json
import hashlib
import os
from pathlib import Path
import threading
import pytest
import audit_snapshot as S
import mechanical_prewarm as P
import posix_v2_compat_runtime as C
from supply_chain_gate import gate_supply_chain

DRIVER = "sha256:" + "d" * 64

def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path

def _setup(tmp_path, monkeypatch, request, language="evm", spaced=False, native_tools=None,
           solc_config=None):
    project, source = tmp_path / "project", tmp_path / "project/source"
    scratch, tools = project / ".scratchpad", tmp_path / ("tool directory" if spaced else "tools")
    source.mkdir(parents=True); scratch.mkdir(); tools.mkdir()
    _write(source / ("foundry.toml" if language == "evm" else "Cargo.toml"), "[profile.default]\n")
    _write(source / "unicodé.txt", "unchanged\n")
    if language == "evm":
        _write(source / "src/Example.sol", "pragma solidity ^0.8.26; contract Example {}\n")
    else:
        _write(source / "src/lib.rs", "pub fn example() {}\n")
    compiler = _write(tools / ("forge" if language == "evm" else "cargo"),
                      '#!/bin/sh\nmkdir -p "$XDG_CACHE_HOME/compiler"\nprintf "%s\\n" "$*" >> "$XDG_CACHE_HOME/compiler/invocations"\n')
    compiler.chmod(0o755)
    monkeypatch.setenv("PATH", os.pathsep.join((str(tools), "/usr/bin", "/bin")))
    if native_tools is not None:
        forge, solc = native_tools
        _write(source / "foundry.toml", (
            '[profile.default]\nsrc = "src"\nout = "out"\nlibs = []\n'
            + (f'solc = {json.dumps(str(solc))}\n' if solc_config is None else solc_config + '\n')
            + 'offline = true\n'
        ))
        monkeypatch.setenv("PATH", os.pathsep.join((str(forge.parent), "/usr/bin", "/bin")))
    monkeypatch.setattr(S, "_runtime_tool_entries", lambda **_k: [("@runtime/test", b"fixed")])
    session = C.issue_posix_v2_compat_session_for_installed_front(
        run_id="prewarm-test", project_root=project, scratchpad=scratch)
    request.addfinalizer(lambda: session.close() if id(session) in C._SESSIONS else None)
    implementation = tmp_path / "implementation"
    for name in ("scripts", "prompts", "rules", "agents"):
        (implementation / name).mkdir(parents=True)
    _write(implementation / "scripts/plamen_driver.py", "VERSION=1\n")
    _write(implementation / "prompts/p.md", "méthod\n")
    _write(implementation / "rules/r.md", "rule\n")
    config = {"project_root": str(source), "scratchpad": str(scratch), "mode": "light",
              "pipeline": "sc", "language": language, "cli_backend": "codex"}
    snapshot = S.build_audit_snapshot(config, implementation)
    guard = lambda: (_ for _ in ()).throw(AssertionError("snapshot drift")) if S.build_audit_snapshot(config, implementation) != snapshot else None
    admission = gate_supply_chain(source, posix_compat_session=session)
    quoted = f"'{compiler}'"
    registry = {} if language == "evm" else {language: {
        "build_command": f"{quoted} build", "test_prewarm_command": f"{quoted} test --no-run"}}
    return source, session, admission, snapshot, registry, guard

def _run(v, language="evm"):
    return P.run_compat_prewarm(session_authority=v[1], source_build_root=v[0].resolve(),
        language=language, registry=v[4], driver_identity=DRIVER, audit_snapshot=v[3],
        assert_snapshot_current=v[5], supply_chain_admission=v[2], timeout_seconds=10)

def test_identity_unicode_snapshot_and_exact_replay(tmp_path, monkeypatch, request):
    v = _setup(tmp_path, monkeypatch, request); count = 0
    real = P._compat.execute_posix_v2_compat_mechanical_poc
    def execute(**kwargs):
        nonlocal count
        count += 1; payload = json.loads(kwargs["request_bytes"])
        assert payload["purpose"] == "PREWARM_BUILD" and payload["subject_kind"] == "BUILD_MANIFEST"
        assert payload["finding_id"] is payload["policy_sha256"] is None
        assert payload["environment"]["FOUNDRY_OFFLINE"] == "true"
        return real(**kwargs)
    monkeypatch.setattr(P._compat, "execute_posix_v2_compat_mechanical_poc", execute)
    first, second = _run(v), _run(v)
    assert first is second and first.ok and count == 1
    assert (first.workspace_root / "unicodé.txt").read_text() == "unchanged\n"

def test_quoted_path_and_distinct_cargo_attempt(tmp_path, monkeypatch, request):
    result = _run(_setup(tmp_path, monkeypatch, request, "solana", True), "solana")
    assert result.ok and result.cargo_ok and len(result.terminals) == 2
    assert (result.workspace_root / ".prewarm-cache/compiler/invocations").read_text().splitlines() == ["build", "test --no-run"]

def test_forged_admission_and_closed_session(tmp_path, monkeypatch, request):
    v = list(_setup(tmp_path, monkeypatch, request)); v[2] = object()
    with pytest.raises(P.CompatPrewarmError, match="SUPPLY_CHAIN_ADMISSION"): _run(tuple(v))
    v = _setup(tmp_path / "closed", monkeypatch, request); v[1].close()
    with pytest.raises(P.CompatPrewarmError, match="SESSION_AUTHORITY"): _run(v)

def test_links_special_files_and_bounds(tmp_path, monkeypatch, request):
    v = _setup(tmp_path, monkeypatch, request); source = v[0]
    (source / "alias").symlink_to(source / "unicodé.txt")
    with pytest.raises(P.CompatPrewarmError, match="SOURCE_MEMBER"):
        P._census(source, None)
    with pytest.raises(P.CompatPrewarmError, match="SOURCE_MEMBER|AUDIT_SNAPSHOT"): _run(v)
    (source / "alias").unlink(); os.mkfifo(source / "special")
    with pytest.raises(P.CompatPrewarmError, match="SOURCE_MEMBER"):
        P._census(source, None)
    with pytest.raises(P.CompatPrewarmError, match="SOURCE_MEMBER|AUDIT_SNAPSHOT"): _run(v)
    (source / "special").unlink(); monkeypatch.setattr(P, "_MAX_FILES", 1)
    with pytest.raises(P.CompatPrewarmError, match="SOURCE_BOUND"): _run(v)

def test_stage_mismatch_and_walk_error(tmp_path, monkeypatch, request):
    v = _setup(tmp_path, monkeypatch, request); copy = P._copy_tree
    def corrupt(source, stage, excluded):
        result = copy(source, stage, excluded); (stage / "unicodé.txt").write_text("different\n"); return result
    monkeypatch.setattr(P, "_copy_tree", corrupt)
    with pytest.raises(P.CompatPrewarmError, match="COPY_DRIFT"): _run(v)
    monkeypatch.setattr(P, "_copy_tree", copy)
    def broken(*_a, **kw):
        kw["onerror"](PermissionError("denied")); yield from ()
    monkeypatch.setattr(P.os, "walk", broken)
    with pytest.raises(P.CompatPrewarmError, match="TREE_WALK"):
        P._census(v[0], None)
    with pytest.raises(P.CompatPrewarmError, match="TREE_WALK|AUDIT_SNAPSHOT"): _run(v)

def test_concurrent_calls_launch_once(tmp_path, monkeypatch, request):
    v = _setup(tmp_path, monkeypatch, request); count = 0; results = []; errors = []
    real = P._compat.execute_posix_v2_compat_mechanical_poc
    def execute(**kwargs):
        nonlocal count
        count += 1; return real(**kwargs)
    monkeypatch.setattr(P._compat, "execute_posix_v2_compat_mechanical_poc", execute)
    def invoke():
        try: results.append(_run(v))
        except BaseException as exc: errors.append(exc)
    threads = [threading.Thread(target=invoke) for _ in range(2)]
    [t.start() for t in threads]; [t.join() for t in threads]
    assert not errors and results[0] is results[1] and count == 1

def test_post_primary_failure_is_retained(tmp_path, monkeypatch, request):
    v = _setup(tmp_path, monkeypatch, request, "solana"); calls = 0
    real = P._compat.execute_posix_v2_compat_mechanical_poc
    def execute(**kwargs):
        nonlocal calls
        calls += 1
        if calls == 2: raise RuntimeError("second-attempt")
        return real(**kwargs)
    monkeypatch.setattr(P._compat, "execute_posix_v2_compat_mechanical_poc", execute)
    with pytest.raises(RuntimeError, match="second-attempt"): _run(v, "solana")
    retained = _run(v, "solana")
    assert retained.ok and retained.cargo_ok is False and "incomplete" in retained.cargo_note and calls == 2

def test_source_drift_rejected(tmp_path, monkeypatch, request):
    v = _setup(tmp_path, monkeypatch, request); _run(v)
    (v[0] / "unicodé.txt").write_text("changed\n")
    with pytest.raises((P.CompatPrewarmError, AssertionError)): _run(v)

def test_malformed_command_and_driver_rejected_before_publication(tmp_path, monkeypatch, request):
    v = list(_setup(tmp_path, monkeypatch, request, "solana"))
    v[4] = {"solana": {"build_command": "'unterminated"}}
    with pytest.raises(P.CompatPrewarmError, match="BUILD_COMMAND"): _run(tuple(v), "solana")
    assert not (v[1].binding["scratchpad"] and
                (Path(v[1].binding["scratchpad"]) / P._WORKSPACE_PARENT).exists())
    with pytest.raises(P.CompatPrewarmError, match="IDENTITY"):
        P.run_compat_prewarm(session_authority=v[1], source_build_root=v[0].resolve(),
            language="solana", registry={}, driver_identity="driver-test",
            audit_snapshot=v[3], assert_snapshot_current=v[5],
            supply_chain_admission=v[2], timeout_seconds=10)

def test_replay_rejects_workspace_tamper(tmp_path, monkeypatch, request):
    v = _setup(tmp_path, monkeypatch, request); result = _run(v)
    (result.workspace_root / "unicodé.txt").write_text("tampered\n")
    with pytest.raises(P.CompatPrewarmError, match="WORKSPACE_DRIFT"): _run(v)

def test_same_thread_callback_reentry_is_rejected(tmp_path, monkeypatch, request):
    v = list(_setup(tmp_path, monkeypatch, request)); observed = []
    original_guard = v[5]
    def guard():
        original_guard()
        try: _run(tuple(v))
        except P.CompatPrewarmError as exc: observed.append(exc.code)
    v[5] = guard
    _run(tuple(v))
    assert observed and set(observed) == {"REENTRANT_WORK"}


def test_failed_compiler_retains_authenticated_error_and_does_not_relaunch(tmp_path, monkeypatch, request):
    v = _setup(tmp_path, monkeypatch, request)
    compiler = Path(os.environ["PATH"].split(os.pathsep)[0]) / "forge"
    _write(compiler, '#!/bin/sh\nprintf "compiler-diagnostic" >&2\nexit 7\n')
    first = _run(v)
    assert not first.ok and "rc=7" in first.note and "compiler-diagnostic" in first.note
    monkeypatch.setattr(C, "execute_posix_v2_compat_mechanical_poc",
                        lambda **_kwargs: pytest.fail("failed compiler was relaunched"))
    assert _run(v) is first


def test_executable_drift_cannot_replay_stale_prewarm(tmp_path, monkeypatch, request):
    v = _setup(tmp_path, monkeypatch, request)
    assert _run(v).ok
    compiler = Path(os.environ["PATH"].split(os.pathsep)[0]) / "forge"
    _write(compiler, '#!/bin/sh\nprintf "different-compiler"\n')
    monkeypatch.setattr(C, "execute_posix_v2_compat_mechanical_poc",
                        lambda **_kwargs: pytest.fail("changed compiler was launched"))
    with pytest.raises(P.CompatPrewarmError, match="REPLAY_INPUT_DRIFT"):
        _run(v)


@pytest.mark.parametrize("case", ["relative", "conflicting", "target", "shim", "missing"])
def test_secondary_compiler_selection_rejects_unsafe_inputs(tmp_path, monkeypatch, request, case):
    v = _setup(tmp_path, monkeypatch, request)
    external = _write(tmp_path / "external-solc", "#!/usr/bin/env python3\n")
    external.chmod(0o755)
    target = _write(v[0] / "custom-solc", "not executed\n")
    target.chmod(0o755)
    selections = {
        "relative": 'solc = "./custom-solc"',
        "conflicting": 'solc = "0.8.26"\nsolc-version = "0.8.25"',
        "target": f'solc = {json.dumps(str(target))}',
        "shim": f'solc = {json.dumps(str(external))}',
        "missing": 'solc = "999.999.999"',
    }
    _write(v[0] / "foundry.toml", "[profile.default]\n" + selections[case] + "\n")
    monkeypatch.setenv("HOME", str(tmp_path / "empty-driver-home"))
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    with pytest.raises(P.CompatPrewarmError, match="SOLC_UNAVAILABLE" if case == "missing" else "SOLC_SELECTION"):
        P._select_solc(v[0], "evm", C._session_record(v[1]))


@pytest.mark.parametrize("platform", ["darwin", "linux"])
def test_secondary_compiler_platform_cache_selection_and_copy_drift(tmp_path, monkeypatch, request, platform):
    v = _setup(tmp_path, monkeypatch, request)
    home = tmp_path / "driver-home"
    data = home / ("Library/Application Support" if platform == "darwin" else ".local/share")
    binary = data / "svm/0.8.26/solc-0.8.26"
    binary.parent.mkdir(parents=True)
    # Structural admission fixture only: this binary is never executed.
    binary.write_bytes(b"\x7fELFfixture-not-executable-code")
    binary.chmod(0o500)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    monkeypatch.setattr(P.sys, "platform", platform)
    _write(v[0] / "foundry.toml", '[profile.default]\nsolc-version = "0.8.26"\n')
    selected = P._select_solc(v[0], "evm", C._session_record(v[1]))
    assert selected["source_path"] == str(binary)
    stage = tmp_path / "staged"
    (stage / ".prewarm-home").mkdir(parents=True)
    P._stage_solc(selected, stage)
    copied = stage / selected["workspace_relative_path"]
    binding = C._poc_file_binding(copied, label="test compiler", maximum=1024)
    P._check_solc(selected, stage, binding)
    copied.chmod(0o700)
    copied.write_bytes(b"changed")
    with pytest.raises(P.CompatPrewarmError, match="SOLC_DRIFT"):
        P._check_solc(selected, stage, binding)


@pytest.mark.integration
@pytest.mark.parametrize("selector_key", ["solc", "solc_version", "solc-version"])
def test_explicit_native_foundry_compiles_in_published_workspace(tmp_path, monkeypatch, request, selector_key):
    """Opt-in local tool canary, not DODO or candidate-PoC acceptance."""
    selected = [os.environ.get(name) for name in ("PLAMEN_TEST_FORGE", "PLAMEN_TEST_SOLC")]
    if not all(selected):
        pytest.skip("explicit native Forge and solc paths required for compiler canary")
    binaries = tuple(Path(value).resolve(strict=True) for value in selected)
    native_magic = {b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
                    b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
                    b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"}
    for binary in binaries:
        with binary.open("rb") as stream:
            assert stream.read(4) in native_magic, "compiler canary refuses scripts/shims"
        assert os.access(binary, os.X_OK)
    assert binaries[0].name == "forge"
    digests = tuple(hashlib.sha256(binary.read_bytes()).hexdigest() for binary in binaries)
    # Populate a private SVM cache from the explicitly selected native input.
    # No download or account-cache modification is performed.
    if selector_key == "solc":
        solc_config = None
    else:
        import shutil
        driver_home = tmp_path / "driver-home"
        cached = driver_home / ".svm/0.8.26/solc-0.8.26"
        cached.parent.mkdir(parents=True)
        shutil.copyfile(binaries[1], cached)
        cached.chmod(0o500)
        monkeypatch.setenv("HOME", str(driver_home))
        solc_config = f'{selector_key} = "0.8.26"'
    v = _setup(tmp_path, monkeypatch, request, native_tools=binaries, solc_config=solc_config)
    source_census = P._census(v[0], None)
    first = _run(v)
    assert first.ok, first.note
    assert _run(v) is first
    artifact = json.loads((first.workspace_root / "out/Example.sol/Example.json").read_text())
    assert artifact["bytecode"]["object"] not in ("", "0x")
    assert (first.workspace_root / "cache/solidity-files-cache.json").is_file()
    assert hashlib.sha256((first.workspace_root / ".prewarm-home/.plamen-solc/solc").read_bytes()).hexdigest() == digests[1]
    assert not (v[0] / "out").exists() and not (v[0] / "cache").exists()
    assert P._census(v[0], None) == source_census
    assert tuple(hashlib.sha256(binary.read_bytes()).hexdigest() for binary in binaries) == digests
    terminal = json.loads(C.project_posix_v2_compat_mechanical_poc_terminal(v[1], first.terminals[0]))
    assert terminal["returncode"] == 0 and terminal["poc_attempted"] is False
