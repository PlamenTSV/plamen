"""POSIX no-follow authority tests for committed install artifact reads."""

import ast
import errno
import hashlib
import importlib.util
import os
import re
import stat
import sys
import unicodedata
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
PLAMEN = ROOT / "plamen.py"
POSIX_ONLY = pytest.mark.skipif(
    os.name == "nt", reason="requires real POSIX openat/O_NOFOLLOW semantics",
)


def _load():
    spec = importlib.util.spec_from_file_location(
        "plamen_posix_committed_read", PLAMEN,
    )
    module = importlib.util.module_from_spec(spec)
    saved = sys.argv
    sys.argv = ["plamen.py"]
    try:
        spec.loader.exec_module(module)
    finally:
        sys.argv = saved
    return module


def test_posix_branch_precedes_unchanged_windows_dispatcher_path():
    """This structural test runs on Windows while real openat tests run in CI."""
    tree = ast.parse(PLAMEN.read_text(encoding="utf-8"))
    function = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "_codex_install_committed_read"
    )
    posix_branch = next(
        node for node in function.body
        if isinstance(node, ast.If)
        and ast.unparse(node.test) == "os.name != 'nt'"
    )
    root_open = next(
        node for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_codex_dispatcher_open_root"
    )
    windows_calls = {
        node.func.id for node in ast.walk(function)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        and node.func.id in {
            "_codex_native_open_relative", "_codex_native_exact_component",
            "_codex_native_read", "_codex_native_directory_names",
            "_codex_native_close",
        }
        and node.lineno > posix_branch.end_lineno
    }
    assert posix_branch.lineno < root_open.lineno
    assert windows_calls == {
        "_codex_native_open_relative", "_codex_native_exact_component",
        "_codex_native_read", "_codex_native_directory_names",
        "_codex_native_close",
    }


def test_early_bootstrap_descriptor_routes_posix_before_late_dependencies():
    source = PLAMEN.read_text(encoding="utf-8")
    tree = ast.parse(source)
    functions = {
        node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)
    }
    raw_components = functions["_codex_install_raw_components"]
    posix_reader = functions["_codex_install_posix_committed_read"]
    descriptor = functions["_codex_install_committed_descriptor"]
    late_reader = functions["_codex_install_committed_read"]
    assert raw_components.lineno < posix_reader.lineno < descriptor.lineno
    assert descriptor.lineno < late_reader.lineno

    calls = []

    def simulated_posix_reader(
        root, components, *, directory=False, allow_stable_foreign_links=False,
    ):
        calls.append((root, components, directory, allow_stable_foreign_links))
        return {"kind": "file", "name": components[-1]}, b"bootstrap\n"

    namespace = {
        "os": SimpleNamespace(name="posix"),
        "re": re,
        "_codex_install_posix_committed_read": simulated_posix_reader,
    }
    executable = ast.Module(
        body=[raw_components, descriptor], type_ignores=[],
    )
    ast.fix_missing_locations(executable)
    exec(compile(executable, str(PLAMEN), "exec"), namespace)
    observed = namespace["_codex_install_committed_descriptor"](
        "/installed", ("receipt.json",), return_raw=True,
        allow_stable_foreign_links=True,
    )
    assert observed == (
        {"kind": "file", "name": "receipt.json"}, b"bootstrap\n",
    )
    assert calls == [
        ("/installed", ("receipt.json",), False, True),
    ]


@pytest.mark.skipif(os.name != "nt", reason="Windows dispatcher smoke test")
def test_windows_committed_reader_still_uses_native_dispatcher(tmp_path):
    module = _load()
    root = tmp_path / "installed"
    root.mkdir()
    raw = b"windows-native-branch\n"
    (root / "receipt.json").write_bytes(raw)
    descriptor, observed = module._codex_install_committed_read(
        root, ("receipt.json",),
    )
    assert observed == raw
    assert descriptor["name"] == "receipt.json"
    assert descriptor["kind"] == "file"
    assert descriptor["links"] == 1
    assert descriptor["reparse_tag"] == 0
    assert descriptor["sha256"] == hashlib.sha256(raw).hexdigest()


@POSIX_ONLY
def test_posix_committed_read_file_and_directory_are_same_handle_bound(tmp_path):
    module = _load()
    root = tmp_path / "installed"
    folder = root / "terminal-evidence"
    folder.mkdir(parents=True)
    payload = folder / "precommit.json"
    raw = b'{"authority":"exact"}\n'
    payload.write_bytes(raw)
    payload.chmod(0o444)

    descriptor, observed = module._codex_install_committed_read(
        root, ("terminal-evidence", "precommit.json"), directory=False,
    )
    assert observed == raw
    assert descriptor == {
        "kind": "file",
        "device": payload.stat().st_dev,
        "inode": payload.stat().st_ino,
        "mode": payload.stat().st_mode,
        "links": 1,
        "size": len(raw),
        "attributes": 0x1,
        "reparse_tag": 0,
        "name": "precommit.json",
        "sha256": hashlib.sha256(raw).hexdigest(),
        "streams": [],
    }

    directory_descriptor, names = module._codex_install_committed_read(
        root, ("terminal-evidence",), directory=True,
    )
    assert names == ("precommit.json",)
    assert directory_descriptor["kind"] == "directory"
    assert directory_descriptor["device"] == folder.stat().st_dev
    assert directory_descriptor["inode"] == folder.stat().st_ino
    assert directory_descriptor["links"] > 0
    assert directory_descriptor["attributes"] & 0x10
    assert "sha256" not in directory_descriptor
    assert "streams" not in directory_descriptor


@POSIX_ONLY
def test_posix_committed_read_preserves_exact_absence_contract(tmp_path):
    module = _load()
    root = tmp_path / "installed"
    root.mkdir()
    with pytest.raises(FileNotFoundError):
        module._codex_install_committed_read(root, ("missing.json",))


@POSIX_ONLY
def test_posix_committed_read_preserves_missing_root_contract(tmp_path):
    module = _load()
    missing_root = tmp_path / "not-installed"
    with pytest.raises(FileNotFoundError) as captured:
        module._codex_install_committed_read(
            missing_root,
            ("payload.json",),
        )
    assert captured.value.errno == errno.ENOENT
    assert captured.value.filename == missing_root.name


@POSIX_ONLY
def test_installed_runtime_clean_home_and_wrong_case_boundary(
    monkeypatch,
    tmp_path,
):
    module = _load()
    clean_home = tmp_path / "clean-home"
    clean_home.mkdir()
    monkeypatch.setenv("HOME", str(clean_home))
    monkeypatch.delenv("USERPROFILE", raising=False)
    assert module._installed_runtime_root() is None

    (clean_home / ".PLAMEN").mkdir()
    with pytest.raises(RuntimeError, match="case/NFC"):
        module._installed_runtime_root()


@POSIX_ONLY
@pytest.mark.parametrize("link_position", ["root", "parent", "leaf"])
def test_posix_committed_read_rejects_symlink_at_every_path_level(
    tmp_path, link_position,
):
    module = _load()
    real_root = tmp_path / "real"
    real_parent = real_root / "evidence"
    real_parent.mkdir(parents=True)
    (real_parent / "payload.json").write_bytes(b"{}\n")
    if link_position == "root":
        root = tmp_path / "installed"
        root.symlink_to(real_root, target_is_directory=True)
        components = ("evidence", "payload.json")
    elif link_position == "parent":
        root = tmp_path / "installed"
        root.mkdir()
        (root / "evidence").symlink_to(real_parent, target_is_directory=True)
        components = ("evidence", "payload.json")
    else:
        root = tmp_path / "installed"
        (root / "evidence").mkdir(parents=True)
        (root / "evidence" / "payload.json").symlink_to(
            real_parent / "payload.json",
        )
        components = ("evidence", "payload.json")
    with pytest.raises(RuntimeError, match="POSIX committed"):
        module._codex_install_committed_read(root, components)


@POSIX_ONLY
def test_posix_committed_read_rejects_noncanonical_root_spelling(tmp_path):
    module = _load()
    root = tmp_path / "installed"
    root.mkdir()
    (root / "payload.json").write_bytes(b"{}\n")
    ambiguous = os.path.join(str(root), ".")
    with pytest.raises(RuntimeError, match="root path is not canonical"):
        module._codex_install_committed_read(ambiguous, ("payload.json",))
    relative = os.path.relpath(root, Path.cwd())
    with pytest.raises(RuntimeError, match="root path is not canonical"):
        module._codex_install_committed_read(relative, ("payload.json",))


@POSIX_ONLY
@pytest.mark.parametrize("components", [("missing.json",), ("missing", "leaf")])
def test_posix_committed_read_preserves_file_not_found_contract(
    tmp_path, components,
):
    module = _load()
    root = tmp_path / "installed"
    root.mkdir()
    with pytest.raises(FileNotFoundError):
        module._codex_install_committed_read(root, components)
    with pytest.raises(FileNotFoundError):
        module._codex_install_committed_descriptor(
            root, components, return_raw=True,
        )


@POSIX_ONLY
def test_posix_committed_read_rejects_hardlink_unless_explicitly_authorized(
    tmp_path,
):
    module = _load()
    root = tmp_path / "installed"
    root.mkdir()
    payload = root / "payload.json"
    payload.write_bytes(b"bound\n")
    os.link(payload, root / "alias.json")
    with pytest.raises(RuntimeError, match="file identity differs"):
        module._codex_install_committed_read(root, ("payload.json",))
    descriptor, raw = module._codex_install_committed_read(
        root, ("payload.json",), allow_stable_foreign_links=True,
    )
    assert raw == b"bound\n"
    assert descriptor["links"] == 2


@POSIX_ONLY
def test_posix_committed_read_rejects_case_and_unicode_normalization_aliases(
    tmp_path,
):
    module = _load()
    root = tmp_path / "installed"
    root.mkdir()
    (root / "Payload.json").write_bytes(b"case\n")
    with pytest.raises(RuntimeError, match="case/NFC"):
        module._codex_install_committed_read(root, ("payload.json",))

    composed = "\N{LATIN SMALL LETTER E WITH ACUTE}.json"
    decomposed = unicodedata.normalize("NFD", composed)
    unicode_root = tmp_path / "unicode"
    unicode_root.mkdir()
    (unicode_root / decomposed).write_bytes(b"unicode\n")
    observed_name = os.listdir(unicode_root)[0]
    alternate = (
        unicodedata.normalize("NFC", observed_name)
        if unicodedata.normalize("NFC", observed_name) != observed_name
        else unicodedata.normalize("NFD", observed_name)
    )
    if alternate == observed_name:
        pytest.skip("filesystem exposes no distinct NFC/NFD spelling")
    with pytest.raises(RuntimeError, match="case/NFC"):
        module._codex_install_committed_read(unicode_root, (alternate,))


@POSIX_ONLY
def test_posix_committed_directory_roster_is_bounded_and_alias_free(tmp_path):
    module = _load()
    root = tmp_path / "installed"
    roster = root / "roster"
    roster.mkdir(parents=True)
    (roster / "A").write_bytes(b"A")
    try:
        (roster / "a").write_bytes(b"a")
    except OSError:
        pytest.skip("filesystem does not permit a case-distinct alias")
    if set(os.listdir(roster)) != {"A", "a"}:
        pytest.skip("filesystem collapses case-distinct aliases")
    with pytest.raises(RuntimeError, match="roster contains aliases"):
        module._codex_install_committed_read(root, ("roster",), directory=True)

    bounded = root / "bounded"
    bounded.mkdir()
    for ordinal in range(4097):
        (bounded / f"{ordinal:04x}").touch()
    with pytest.raises(RuntimeError, match="roster exceeds bound"):
        module._codex_install_committed_read(root, ("bounded",), directory=True)


@POSIX_ONLY
def test_posix_committed_read_detects_named_replacement_and_closes_all_fds(
    monkeypatch, tmp_path,
):
    module = _load()
    root = tmp_path / "installed"
    root.mkdir()
    payload = root / "payload.json"
    payload.write_bytes(b"predecessor\n")
    replacement = root / "replacement.json"
    replacement.write_bytes(b"successor--\n")

    real_open = os.open
    real_close = os.close
    real_pread = os.pread
    opened = []
    closed = []
    replaced = False

    def tracked_open(*args, **kwargs):
        descriptor = real_open(*args, **kwargs)
        opened.append(descriptor)
        return descriptor

    def tracked_close(descriptor):
        closed.append(descriptor)
        return real_close(descriptor)

    def replacing_pread(descriptor, size, offset):
        nonlocal replaced
        raw = real_pread(descriptor, size, offset)
        if not replaced:
            replaced = True
            os.replace(replacement, payload)
        return raw

    monkeypatch.setattr(module.os, "open", tracked_open)
    monkeypatch.setattr(module.os, "close", tracked_close)
    monkeypatch.setattr(module.os, "pread", replacing_pread)
    with pytest.raises(RuntimeError, match="authority changed"):
        module._codex_install_committed_read(root, ("payload.json",))
    assert opened
    assert set(opened) <= set(closed)
    for descriptor in opened:
        with pytest.raises(OSError):
            os.fstat(descriptor)
