"""Release gates for Plamen's universal, hash-locked Python runtime."""

from __future__ import annotations

import importlib.util
import inspect
import json
import os
import re
import subprocess
import sys
import unicodedata
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
LOCKS = (
    "requirements-runtime-core.lock",
    "requirements-runtime-rag.lock",
    "requirements-runtime-slither.lock",
    "requirements-runtime-full.lock",
)


def _load_front():
    spec = importlib.util.spec_from_file_location("plamen_python_lock_test", ROOT / "plamen.py")
    module = importlib.util.module_from_spec(spec)
    old_argv = sys.argv
    sys.argv = ["plamen.py"]
    try:
        spec.loader.exec_module(module)
    finally:
        sys.argv = old_argv
    return module


def _requirement_blocks(text: str) -> list[str]:
    blocks: list[str] = []
    current = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("--") and not line.startswith("--hash="):
            continue
        current = f"{current} {line}".strip()
        if not line.endswith("\\"):
            blocks.append(current)
            current = ""
    assert not current
    return blocks


def test_all_runtime_locks_are_universal_exact_wheel_only_and_hashed() -> None:
    exact = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*==[^ ;\\]+(?:\s*;[^\\]+)?\s*\\")
    for relative in LOCKS:
        text = (ROOT / relative).read_text(encoding="utf-8")
        assert "uv pip compile --universal --python-version 3.12" in text
        assert "--only-binary :all:" in text
        assert "--extra-index-url" not in text
        assert "git+" not in text and " @ http" not in text and "-e " not in text
        blocks = _requirement_blocks(text)
        assert blocks
        for block in blocks:
            assert exact.match(block), (relative, block[:160])
            assert "--hash=sha256:" in block, (relative, block[:160])


def test_universal_lock_carries_cross_os_dependency_branches() -> None:
    full = (ROOT / "requirements-runtime-full.lock").read_text(encoding="utf-8")
    assert "pywin32==312 ; sys_platform == 'win32'" in full
    assert "pywinpty==2.0.15 ; sys_platform == 'win32'" in full
    assert "triton==" in full and "sys_platform == 'linux'" in full
    assert "uvloop==" in full and "sys_platform != 'win32'" in full


def test_installer_mutates_only_the_owned_runtime_from_hash_locks() -> None:
    front = _load_front()
    pip_source = inspect.getsource(front._pip_install_args)
    setup_source = inspect.getsource(front._setup_python_deps)
    bootstrap_source = inspect.getsource(front._bootstrap)
    combined = pip_source + setup_source + bootstrap_source
    assert "--break-system-packages" not in combined
    assert '"--user"' not in combined and "pip install -e" not in combined
    assert "--require-hashes" in setup_source and "--only-binary=:all:" in setup_source
    assert "--require-hashes" in bootstrap_source and "--only-binary=:all:" in bootstrap_source
    assert "requirements-runtime-full.lock" in setup_source
    assert Path(front._managed_runtime_python()).name in {"python", "python.exe"}


def test_installer_orders_census_before_managed_third_party_probes() -> None:
    front = _load_front()
    setup_source = inspect.getsource(front._setup_python_deps)
    bootstrap_source = inspect.getsource(front._bootstrap)
    assert "import rich, InquirerPy" not in setup_source
    assert setup_source.index("_python_dependency_stamp_status") < setup_source.index(
        "_python_dependency_exact_probe"
    )
    installer_branch = bootstrap_source.index("if installer_command:")
    stamp_replay = bootstrap_source.index(
        "_python_dependency_stamp_status", installer_branch
    )
    managed_probe = bootstrap_source.index(
        "import InquirerPy, chromadb", stamp_replay
    )
    assert stamp_replay < managed_probe
    assert front._PYTHON_DEPENDENCY_TRUST_BOUNDARY == (
        "USER_WRITABLE_DRIFT_DETECTION_ONLY"
    )


def test_bootstrap_preserves_inherited_streams_and_propagates_windows_exit() -> None:
    front = _load_front()
    module_source = (ROOT / "plamen.py").read_text(encoding="utf-8")
    bootstrap_source = inspect.getsource(front._bootstrap)
    assert "io.TextIOWrapper(" not in module_source
    assert "raise SystemExit(subprocess.call(argv))" in bootstrap_source
    assert "read_only_package_check" in bootstrap_source
    assert bootstrap_source.index("if read_only_package_check") < bootstrap_source.index(
        "venv.EnvBuilder("
    )


def test_full_lock_and_reproducibility_inputs_are_runtime_assets() -> None:
    front = _load_front()
    assets = {row["path"] for row in front.PLAMEN_RUNTIME_ASSETS}
    assert {
        "requirements-runtime-core.in",
        "requirements-runtime-core.lock",
        "requirements-runtime-rag.in",
        "requirements-runtime-rag.lock",
        "requirements-runtime-slither.in",
        "requirements-runtime-slither.lock",
        "requirements-runtime-full.in",
        "requirements-runtime-full.lock",
        "requirements-ci.constraints",
    } <= assets


def _dependency_refresh(front, **overrides):
    values = {
        "force_refresh": False,
        "core_ok": True,
        "deep_ok": True,
        "protobuf_current": True,
        "runtime_healthy": True,
        "stamp_status": "VALID",
    }
    values.update(overrides)
    return front._python_dependency_refresh_required(**values)


def test_code_only_runtime_closure_change_does_not_refresh_python_lock() -> None:
    front = _load_front()
    # The full runtime-bundle digest is deliberately absent from this decision.
    # A changed source/policy asset is published by the package transaction,
    # while identical dependency authority skips pip.
    assert _dependency_refresh(front) is False


def test_code_only_setup_path_never_invokes_pip(tmp_path, monkeypatch) -> None:
    front = _load_front()
    for module_name in ("rich", "InquirerPy", "sentence_transformers", "chromadb"):
        monkeypatch.setitem(sys.modules, module_name, type(sys)(module_name))
    for relative in (
        "custom-mcp/solana-fender/solana_fender_mcp",
        "custom-mcp/slither-mcp/slither_mcp",
        "custom-mcp/unified-vuln-db/unified_vuln",
        "custom-mcp/farofino-mcp/farofino_mcp",
    ):
        (tmp_path / relative).mkdir(parents=True)
    monkeypatch.setattr(front, "PLAMEN_HOME", str(tmp_path))
    monkeypatch.setattr(front, "_installed_version", lambda: "older-code-release")
    monkeypatch.setattr(front, "_python_dependency_authority", lambda: "a" * 64)
    monkeypatch.setattr(front, "_python_dependency_stamp_status", lambda _digest: "VALID")
    monkeypatch.setattr(front, "_python_dependency_exact_probe", lambda *_a, **_k: True)
    monkeypatch.setattr(front, "_protobuf_runtime_is_current", lambda: True)
    monkeypatch.setattr(front, "_python_dependency_runtime_healthy", lambda: True)
    monkeypatch.setattr(
        front,
        "_pip_install_args",
        lambda: (_ for _ in ()).throw(AssertionError("code-only refresh invoked pip")),
    )

    assert front._setup_python_deps(lambda _text: None) is True


def _published_bootstrap_attestation(front, tmp_path, monkeypatch):
    source = (tmp_path / "source").absolute()
    runtime = (tmp_path / "runtime").absolute()
    interpreter = runtime / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    stamp = (tmp_path / "dependency-stamp.json").absolute()
    interpreter.parent.mkdir(parents=True)
    interpreter.write_bytes(b"managed-python")
    stamp.write_bytes(b'{"validated":true}\n')
    source.mkdir()
    for relative in (
        "custom-mcp/solana-fender/solana_fender_mcp",
        "custom-mcp/slither-mcp/slither_mcp",
        "custom-mcp/unified-vuln-db/unified_vuln",
        "custom-mcp/farofino-mcp/farofino_mcp",
    ):
        (source / relative).mkdir(parents=True)
    monkeypatch.setattr(front, "PLAMEN_HOME", str(source))
    monkeypatch.setattr(front, "_managed_runtime_root", lambda: runtime)
    monkeypatch.setattr(front, "_managed_runtime_python", lambda: interpreter)
    monkeypatch.setattr(front, "_python_dependency_stamp_path", lambda: stamp)
    authority = "a" * 64
    observation = front._python_dependency_stamp_observation()
    summary = {
        "census_sha256": "b" * 64,
        "directory_count": 7,
        "file_count": 11,
        "total_bytes": 13,
    }
    front._publish_python_dependency_bootstrap_attestation(
        source_root=source,
        authority_digest=authority,
        stamp_observation=observation,
        census_summary=summary,
    )
    return source, runtime, interpreter, stamp, authority, summary


def _make_attested_setup_health_pass(front, monkeypatch, authority):
    monkeypatch.setattr(front, "_installed_version", lambda: None)
    monkeypatch.setattr(front, "_python_dependency_authority", lambda: authority)
    monkeypatch.setattr(front, "_python_dependency_exact_probe", lambda *_a, **_k: True)
    monkeypatch.setattr(front, "_protobuf_runtime_is_current", lambda: True)
    monkeypatch.setattr(front, "_python_dependency_runtime_healthy", lambda: True)


def test_setup_consumes_valid_bootstrap_census_once_without_full_replay(
    tmp_path, monkeypatch,
) -> None:
    front = _load_front()
    _source, _runtime, _python, _stamp, authority, summary = (
        _published_bootstrap_attestation(front, tmp_path, monkeypatch)
    )
    _make_attested_setup_health_pass(front, monkeypatch, authority)
    monkeypatch.setattr(
        front,
        "_python_dependency_stamp_status",
        lambda *_a, **_k: (_ for _ in ()).throw(
            AssertionError("unchanged runtime was redundantly censused")
        ),
    )
    output = []

    assert front._setup_python_deps(output.append) is True
    assert front._PYTHON_DEPENDENCY_BOOTSTRAP_ATTESTATION is None
    assert f"{summary['file_count']:,} files" in "".join(output)


def test_bootstrap_census_attestation_is_strictly_one_use(tmp_path, monkeypatch) -> None:
    front = _load_front()
    source, _runtime, _python, _stamp, authority, summary = (
        _published_bootstrap_attestation(front, tmp_path, monkeypatch)
    )

    assert front._consume_python_dependency_bootstrap_attestation(
        source_root=source, authority_digest=authority,
    ) == summary
    assert front._consume_python_dependency_bootstrap_attestation(
        source_root=source, authority_digest=authority,
    ) is None


@pytest.mark.parametrize(
    "mismatch",
    ("pid", "source", "runtime", "interpreter", "authority", "stamp", "expiry"),
)
def test_bootstrap_attestation_mismatch_falls_back_to_full_stamp_replay(
    tmp_path, monkeypatch, mismatch,
) -> None:
    front = _load_front()
    source, _runtime, _python, stamp, authority, _summary = (
        _published_bootstrap_attestation(front, tmp_path, monkeypatch)
    )
    attestation = front._PYTHON_DEPENDENCY_BOOTSTRAP_ATTESTATION
    if mismatch == "pid":
        attestation["pid"] += 1
    elif mismatch == "source":
        attestation["source_root"] += "-different"
    elif mismatch == "runtime":
        attestation["runtime_root"] += "-different"
    elif mismatch == "interpreter":
        attestation["interpreter_path"] += "-different"
    elif mismatch == "authority":
        attestation["authority_sha256"] = "c" * 64
    elif mismatch == "stamp":
        stamp.write_bytes(b'{"validated":false}\n')
    elif mismatch == "expiry":
        attestation["validated_at_ns"] -= (
            front._PYTHON_DEPENDENCY_BOOTSTRAP_ATTESTATION_TTL_NS + 1
        )
    _make_attested_setup_health_pass(front, monkeypatch, authority)
    replayed = []
    monkeypatch.setattr(
        front, "_python_dependency_stamp_status",
        lambda digest: replayed.append(digest) or "VALID",
    )

    assert front._setup_python_deps(lambda _text: None) is True
    assert replayed == [authority]
    assert front._PYTHON_DEPENDENCY_BOOTSTRAP_ATTESTATION is None


def test_force_refresh_discards_bootstrap_attestation_and_replays_stamp(
    tmp_path, monkeypatch,
) -> None:
    front = _load_front()
    _source, _runtime, _python, _stamp, authority, _summary = (
        _published_bootstrap_attestation(front, tmp_path, monkeypatch)
    )
    _make_attested_setup_health_pass(front, monkeypatch, authority)
    replayed = []
    monkeypatch.setattr(
        front, "_python_dependency_stamp_status",
        lambda digest: replayed.append(digest) or "VALID",
    )
    # Isolate attestation routing from the separately tested locked refresh.
    monkeypatch.setattr(front, "_python_dependency_refresh_required", lambda **_k: False)

    assert front._setup_python_deps(lambda _text: None, force_refresh=True) is True
    assert replayed == [authority]
    assert front._PYTHON_DEPENDENCY_BOOTSTRAP_ATTESTATION is None


def test_bootstrap_repair_never_publishes_fast_path_and_suppresses_bytecode() -> None:
    front = _load_front()
    source = inspect.getsource(front._bootstrap)
    repair = source.index('if status != "VALID":')
    valid = source.index("\n            else:", repair)
    publication = source.index(
        "_publish_python_dependency_bootstrap_attestation", valid
    )

    assert "_publish_python_dependency_bootstrap_attestation" not in source[repair:valid]
    assert publication > valid
    assert "sys.dont_write_bytecode = True" in source
    assert 'str(managed_python), "-B", str(Path(__file__).resolve())' in source


def test_attestation_reuse_does_not_bypass_health_or_protobuf_repair_decisions() -> None:
    front = _load_front()

    assert _dependency_refresh(front, runtime_healthy=False) is True
    assert _dependency_refresh(front, protobuf_current=False) is True


def test_python_lock_or_managed_interpreter_change_refreshes_python_lock() -> None:
    front = _load_front()
    # An interpreter-byte/version change changes the dependency authority, so
    # the exact prior stamp no longer validates.
    assert _dependency_refresh(front, stamp_status="INVALID") is True


def test_missing_or_corrupt_dependency_runtime_refreshes_python_lock() -> None:
    front = _load_front()
    assert _dependency_refresh(front, runtime_healthy=False) is True
    assert _dependency_refresh(front, stamp_status="ABSENT") is True


def test_missing_old_stamp_always_forces_exact_locked_install() -> None:
    front = _load_front()
    assert _dependency_refresh(front, stamp_status="ABSENT") is True


def _runtime_fixture(tmp_path: Path):
    runtime = tmp_path / "runtime"
    site = runtime / "Lib" / "site-packages"
    dist = site / "demo-1.0.dist-info"
    package = site / "demo"
    dist.mkdir(parents=True)
    package.mkdir()
    (runtime / "pyvenv.cfg").write_text("home = C:/Python312\n", encoding="utf-8")
    (package / "__init__.py").write_text("VALUE = 1\n", encoding="utf-8")
    (dist / "METADATA").write_text("Name: demo\nVersion: 1.0\n", encoding="utf-8")
    (dist / "RECORD").write_text("demo/__init__.py,,\n", encoding="utf-8")
    return runtime, site, package, dist


@pytest.mark.parametrize(
    "relative,replacement",
    (
        ("Lib/site-packages/demo/__init__.py", "VALUE = 2\n"),
        ("Lib/site-packages/demo-1.0.dist-info/RECORD", "tampered,,\n"),
        ("pyvenv.cfg", "home = D:/redirected\n"),
    ),
)
def test_runtime_census_detects_byte_mutation(tmp_path, relative, replacement) -> None:
    front = _load_front()
    runtime, site, _package, _dist = _runtime_fixture(tmp_path)
    before = front._python_dependency_runtime_census(runtime, (site,))
    (runtime / relative).write_text(replacement, encoding="utf-8")
    after = front._python_dependency_runtime_census(runtime, (site,))
    assert after != before


def test_runtime_census_detects_file_addition_and_removal(tmp_path) -> None:
    front = _load_front()
    runtime, site, package, _dist = _runtime_fixture(tmp_path)
    before = front._python_dependency_runtime_census(runtime, (site,))
    added = package / "extra.py"
    added.write_text("EXTRA = True\n", encoding="utf-8")
    with_added = front._python_dependency_runtime_census(runtime, (site,))
    assert with_added != before
    (package / "__init__.py").unlink()
    with_removed = front._python_dependency_runtime_census(runtime, (site,))
    assert with_removed != with_added and with_removed != before


@pytest.mark.parametrize(
    "spellings",
    (
        ("Module.py", "module.py"),
        ("caf\N{LATIN SMALL LETTER E WITH ACUTE}.py", "cafe\N{COMBINING ACUTE ACCENT}.py"),
    ),
)
def test_runtime_census_rejects_dual_spelling_file_before_path_dedup(
    tmp_path, monkeypatch, spellings,
) -> None:
    front = _load_front()
    runtime, site, _package, _dist = _runtime_fixture(tmp_path)

    def dual_spelling_walk(_root, *, followlinks=False):
        assert followlinks is False
        yield os.fspath(site), [], list(spellings)

    monkeypatch.setattr(front.os, "walk", dual_spelling_walk)
    monkeypatch.setattr(
        front,
        "_python_dependency_census_alias",
        lambda value: unicodedata.normalize("NFC", value).casefold(),
    )
    with pytest.raises(RuntimeError, match="contains a path alias"):
        front._python_dependency_census_paths(runtime, (site,))


def test_runtime_census_rejects_dual_spelling_directory_before_path_dedup(
    tmp_path, monkeypatch,
) -> None:
    front = _load_front()
    runtime, site, package, _dist = _runtime_fixture(tmp_path)
    real_lstat = front.os.lstat

    def dual_spelling_walk(_root, *, followlinks=False):
        assert followlinks is False
        yield os.fspath(site), ["Demo", "demo"], []

    def alias_lstat(path):
        candidate = Path(path)
        return real_lstat(package if candidate.name == "Demo" else candidate)

    monkeypatch.setattr(front.os, "walk", dual_spelling_walk)
    monkeypatch.setattr(front.os, "lstat", alias_lstat)
    monkeypatch.setattr(
        front,
        "_python_dependency_census_alias",
        lambda value: value.casefold(),
    )
    with pytest.raises(RuntimeError, match="contains a directory path alias"):
        front._python_dependency_census_paths(runtime, (site,))


def test_runtime_census_never_omits_second_windows_path_spelling(
    tmp_path, monkeypatch,
) -> None:
    front = _load_front()
    runtime, site, _package, _dist = _runtime_fixture(tmp_path)
    upper = site / "Module.py"
    lower = site / "module.py"
    upper.write_bytes(b"first spelling")
    lower.write_bytes(b"second spelling")

    def dual_spelling_walk(_root, *, followlinks=False):
        assert followlinks is False
        yield os.fspath(site), [], [upper.name, lower.name]

    # Disable only the spelling guard to prove the roster itself retained both
    # candidates.  The old WindowsPath set discarded one before this point.
    monkeypatch.setattr(front.os, "walk", dual_spelling_walk)
    monkeypatch.setattr(
        front, "_python_dependency_census_alias", lambda value: value,
    )
    roster, _directories = front._python_dependency_census_paths(runtime, (site,))
    retained = [
        relative for _path, relative in roster
        if relative.lower().endswith("/module.py")
    ]
    assert retained == [
        "Lib/site-packages/Module.py",
        "Lib/site-packages/module.py",
    ]
    if os.name == "nt":
        with pytest.raises(RuntimeError, match="physical alias"):
            front._python_dependency_runtime_census(runtime, (site,))
    else:
        before = front._python_dependency_runtime_census(runtime, (site,))
        lower.write_bytes(b"mutated formerly omitted member")
        after = front._python_dependency_runtime_census(runtime, (site,))
        assert after != before


def test_runtime_census_rejects_dual_spelling_site_roots(
    tmp_path, monkeypatch,
) -> None:
    front = _load_front()
    runtime, site, _package, _dist = _runtime_fixture(tmp_path)
    alternate = site.with_name("SITE-PACKAGES")
    monkeypatch.setattr(
        front,
        "_python_dependency_census_alias",
        lambda value: value.casefold(),
    )
    with pytest.raises(RuntimeError, match="roots contain a spelling alias"):
        front._python_dependency_census_roots(runtime, (site, alternate))


def test_runtime_census_binds_pycache_and_pyc_bytes(tmp_path) -> None:
    front = _load_front()
    runtime, site, package, _dist = _runtime_fixture(tmp_path)
    cache = package / "__pycache__"
    cache.mkdir()
    bytecode = cache / "__init__.cpython-312.pyc"
    bytecode.write_bytes(b"pyc-v1")
    before = front._python_dependency_runtime_census(runtime, (site,))
    bytecode.write_bytes(b"pyc-v2")
    after = front._python_dependency_runtime_census(runtime, (site,))
    assert after != before


def test_bytecode_suppressed_read_only_import_preserves_census(tmp_path) -> None:
    front = _load_front()
    runtime, site, _package, _dist = _runtime_fixture(tmp_path)
    before = front._python_dependency_runtime_census(runtime, (site,))
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(site)
    subprocess.run(
        [sys.executable, "-B", "-c", "import demo"],
        env=environment,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    after = front._python_dependency_runtime_census(runtime, (site,))
    assert after == before


def test_public_and_audit_launchers_suppress_bytecode_writes() -> None:
    front = _load_front()
    windows = front._windows_plamen_command_bytes(sys.executable, ROOT / "plamen.py")
    assert b' -B "' in windows
    assert " -B " in inspect.getsource(front._ensure_posix_plamen_command)
    assert 'bytecode_flag = " -B"' in inspect.getsource(
        front._backend_shim_bytes
    )
    assert '[str(python), "-B", *arguments]' in inspect.getsource(
        front._mcp_server_launches
    )
    assert '"-B", "-m", "pip", "install"' in inspect.getsource(
        front._pip_install_args
    )
    assert " -B -m pip install" in inspect.getsource(front._setup_python_deps)


def test_runtime_census_rejects_byte_mutation_between_full_passes(
    tmp_path, monkeypatch,
) -> None:
    front = _load_front()
    runtime, site, package, _dist = _runtime_fixture(tmp_path)
    original = front._python_dependency_census_members
    calls = 0

    def mutating_replay(*args):
        nonlocal calls
        rows = original(*args)
        calls += 1
        if calls == 1:
            (package / "__init__.py").write_text("VALUE = 99\n", encoding="utf-8")
        return rows

    monkeypatch.setattr(front, "_python_dependency_census_members", mutating_replay)
    with pytest.raises(RuntimeError, match="changed during byte replay"):
        front._python_dependency_runtime_census(runtime, (site,))


def test_runtime_census_rejects_symlink_or_reparse_member(tmp_path) -> None:
    front = _load_front()
    runtime, site, package, _dist = _runtime_fixture(tmp_path)
    link = package / "alias.py"
    try:
        os.symlink(package / "__init__.py", link)
    except OSError:
        pytest.skip("host does not permit symlink creation")
    with pytest.raises(RuntimeError, match="linked or special"):
        front._python_dependency_runtime_census(runtime, (site,))


def test_runtime_census_rejects_linked_directory_ancestor(tmp_path) -> None:
    front = _load_front()
    runtime = tmp_path / "runtime"
    outside = tmp_path / "outside"
    runtime.mkdir(); outside.mkdir()
    (runtime / "pyvenv.cfg").write_text("home = C:/Python312\n", encoding="utf-8")
    linked = runtime / "Lib"
    try:
        os.symlink(outside, linked, target_is_directory=True)
    except OSError:
        pytest.skip("host does not permit directory symlink creation")
    site = linked / "site-packages"
    with pytest.raises(RuntimeError, match="linked or special"):
        front._python_dependency_runtime_census(runtime, (site,))


def test_runtime_census_rejects_hardlink_alias(tmp_path) -> None:
    front = _load_front()
    runtime, site, package, _dist = _runtime_fixture(tmp_path)
    try:
        os.link(package / "__init__.py", package / "alias.py")
    except OSError:
        pytest.skip("host does not permit hardlink creation")
    with pytest.raises(RuntimeError, match="linked or special"):
        front._python_dependency_runtime_census(runtime, (site,))


def test_stamp_requires_exact_census_replay(tmp_path, monkeypatch) -> None:
    front = _load_front()
    stamp = tmp_path / "stamp.json"
    authority = "a" * 64
    census = {
        "census_sha256": "b" * 64,
        "directory_count": 3,
        "file_count": 4,
        "total_bytes": 99,
    }
    stamp.write_bytes((json.dumps({
        "authority_sha256": authority,
        **census,
        "schema": front._PYTHON_DEPENDENCY_STAMP_SCHEMA,
        "trust_boundary": front._PYTHON_DEPENDENCY_TRUST_BOUNDARY,
    }, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"))
    monkeypatch.setattr(front, "_python_dependency_stamp_path", lambda: stamp)
    monkeypatch.setattr(
        front, "_python_dependency_runtime_census", lambda **_kwargs: census
    )
    assert front._python_dependency_stamp_status(authority) == "VALID"
    monkeypatch.setattr(
        front,
        "_python_dependency_runtime_census",
        lambda **_kwargs: {**census, "file_count": 5},
    )
    assert front._python_dependency_stamp_status(authority) == "INVALID"


def test_in_runtime_stamp_write_has_bounded_root_mtime_diagnostic(
    tmp_path,
) -> None:
    front = _load_front()
    runtime, site, _package, _dist = _runtime_fixture(tmp_path)
    before, before_manifest = front._python_dependency_runtime_census(
        runtime, (site,), include_manifest=True
    )
    front._atomic_write_bytes(runtime / ".old-dependency-stamp.json", b"{}\n")
    after, after_manifest = front._python_dependency_runtime_census(
        runtime, (site,), include_manifest=True
    )
    assert after != before
    assert front._python_dependency_census_bounded_diff(
        before_manifest, after_manifest
    ) == 'changed directory "." fields=mtime_ns'


def test_stamp_publication_is_outside_census_and_immediately_replays(
    tmp_path, monkeypatch,
) -> None:
    front = _load_front()
    runtime, site, _package, _dist = _runtime_fixture(tmp_path)
    monkeypatch.setattr(front, "_managed_runtime_root", lambda: runtime)
    monkeypatch.setattr(
        front,
        "_python_dependency_census_roots",
        lambda runtime_root=None, site_roots=None: (runtime, (site,)),
    )
    authority = "a" * 64
    root_before = os.lstat(runtime)
    candidate = front._write_python_dependency_stamp(
        authority, retain_manifest=True
    )
    root_after = os.lstat(runtime)
    assert front._python_dependency_stamp_path().parent == runtime.parent
    assert front._python_dependency_stamp_path().parent != runtime
    assert root_after.st_mtime_ns == root_before.st_mtime_ns
    diagnostics = []
    assert front._python_dependency_stamp_status(
        authority,
        expected_manifest=candidate,
        diagnostics=diagnostics,
    ) == "VALID"
    assert diagnostics == []


def test_legacy_in_runtime_stamp_retires_only_before_new_census(
    tmp_path, monkeypatch,
) -> None:
    front = _load_front()
    runtime, _site, _package, _dist = _runtime_fixture(tmp_path)
    monkeypatch.setattr(front, "_managed_runtime_root", lambda: runtime)
    legacy = runtime / ".plamen-dependency-runtime.json"
    legacy.write_bytes(b"legacy\n")
    assert front._retire_legacy_python_dependency_stamp() is True
    assert not legacy.exists()
    bootstrap = inspect.getsource(front._bootstrap)
    assert bootstrap.index("_retire_legacy_python_dependency_stamp") < bootstrap.index(
        "retain_manifest=True"
    )


def test_legacy_in_runtime_stamp_retirement_rejects_special_entry(
    tmp_path, monkeypatch,
) -> None:
    front = _load_front()
    runtime, _site, _package, _dist = _runtime_fixture(tmp_path)
    monkeypatch.setattr(front, "_managed_runtime_root", lambda: runtime)
    legacy = runtime / ".plamen-dependency-runtime.json"
    legacy.mkdir()
    assert front._retire_legacy_python_dependency_stamp() is False
    assert legacy.is_dir()


def test_dependency_authority_changes_with_lock_or_interpreter_bytes(
    tmp_path, monkeypatch,
) -> None:
    front = _load_front()
    root = tmp_path / "source"
    runtime = tmp_path / "runtime"
    root.mkdir(); runtime.mkdir()
    lock = root / "requirements-runtime-full.lock"
    python = runtime / "python.exe"
    lock.write_bytes(b"demo==1 --hash=sha256:first\n")
    python.write_bytes(b"interpreter-v1")
    monkeypatch.setattr(front, "PLAMEN_HOME", str(root))
    monkeypatch.setattr(front, "_managed_runtime_python", lambda: python)
    initial = front._python_dependency_authority(root)
    lock.write_bytes(b"demo==2 --hash=sha256:second\n")
    lock_changed = front._python_dependency_authority(root)
    assert lock_changed != initial
    lock.write_bytes(b"demo==1 --hash=sha256:first\n")
    python.write_bytes(b"interpreter-v2")
    assert front._python_dependency_authority(root) not in {initial, lock_changed}
