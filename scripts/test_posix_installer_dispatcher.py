"""Fail-closed host-POSIX installer and retained-reader regressions."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

import pytest


ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX dispatcher only")


def _load_front():
    spec = importlib.util.spec_from_file_location(
        "plamen_posix_dispatcher_front", ROOT / "plamen.py"
    )
    module = importlib.util.module_from_spec(spec)
    saved = sys.argv
    sys.argv = ["plamen.py"]
    try:
        spec.loader.exec_module(module)
    finally:
        sys.argv = saved
    return module


def _fd_count():
    return len(os.listdir("/dev/fd"))


def _tree_snapshot(root):
    rows = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            rows.append((relative, "link", os.readlink(path)))
        elif path.is_dir():
            rows.append((relative, "directory", None))
        else:
            rows.append((relative, "file", path.read_bytes()))
    return rows


@pytest.fixture
def readonly_dispatcher(tmp_path):
    front = _load_front()
    source_root = (tmp_path / "source").absolute()
    plamen_root = (tmp_path / "plamen").absolute()
    codex_root = (tmp_path / "codex").absolute()
    for root in (source_root, plamen_root, codex_root):
        root.mkdir()
    anchor = codex_root / front._CODEX_INSTALL_ANCHOR
    anchor.write_bytes(b"retained-writer")

    root_handle, root_close = front._codex_dispatcher_open_root(
        codex_root, full_mutation=False,
    )
    writer_handle = front._codex_native_open_relative(
        root_handle, anchor.name, directory=False, create=False,
        access=0x80000000 | 0x40000000 | 0x00100000,
        share_delete=False,
    )
    root_close()

    value = object.__new__(front._CodexInstallMutationDispatcher)
    value.transaction_id = "a" * 32
    value.writer_generation = "posix-test-generation"
    value.writer_handle = writer_handle
    value.source_root = source_root
    value.plamen_root = plamen_root
    value.codex_home = codex_root
    value.anchor_identity = front._borrowed_reader_handle_identity(writer_handle)
    value.events = []
    value._native_descriptor_cache = {}
    value._transient_json_writes = 0
    value.closed = False
    value._address_owner = object()
    value._stable_b_keys = set()
    value._operation_policy = {
        ("plamen", ("tree",)): {"MKDIR"},
        ("plamen", ("new-tree",)): {"MKDIR"},
        ("plamen", ("tree", "payload.bin")): {
            "ATOMIC_BYTES", "EXCLUSIVE_BYTES", "MAKE_READONLY", "UNLINK",
            "REPLACE_DESTINATION",
        },
        ("plamen", ("tree", "stage.bin")): {
            "EXCLUSIVE_BYTES", "UNLINK", "REPLACE_SOURCE",
        },
        ("codex", ("plamen",)): {"ENSURE_JUNCTION", "REMOVE_LINK"},
    }
    value._roots = (codex_root, plamen_root, source_root)
    value._root_handles = {}
    value._root_identity = {}
    for root in value._roots:
        handle, close = front._codex_dispatcher_open_root(
            root, full_mutation=False,
        )
        value._root_handles[str(root)] = (handle, close)
        value._root_identity[str(root)] = {
            "handle": front._borrowed_reader_handle_identity(handle)
        }
    value._volatile_roots = {}

    try:
        yield front, value, plamen_root, codex_root
    finally:
        if not value.closed:
            value.close()
        front._codex_native_close(writer_handle)


def test_posix_mutating_root_admission_retains_and_releases_exact_roots(tmp_path):
    front = _load_front()
    existing = (tmp_path / "existing").absolute()
    existing.mkdir()
    missing = (tmp_path / "missing").absolute()
    before = _fd_count()

    handle, close = front._codex_dispatcher_open_root(
        existing, full_mutation=True,
    )
    assert os.fstat(handle).st_ino == os.lstat(existing).st_ino
    close()
    authority = front._codex_install_ensure_root(missing)

    assert missing.is_dir() and not missing.is_symlink()
    assert authority["file_id"] == os.lstat(missing).st_ino
    assert _fd_count() == before


def test_public_posix_unsupported_installer_selector_refuses_without_mutation(
    tmp_path,
):
    home = tmp_path / "home"
    home.mkdir()
    environment = {
        "HOME": str(home),
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONHASHSEED": "0",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": "",
    }

    completed = subprocess.run(
        [
            sys.executable, "-B", str(ROOT / "plamen.py"),
            "install", "--claude",
        ],
        cwd=ROOT,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 3
    assert "qualified only on Windows" in completed.stderr
    assert list(home.iterdir()) == []


def test_public_plan_json_is_prebootstrap_and_cold_home_read_only(tmp_path):
    home = tmp_path / "cold-home"
    target = tmp_path / "target"
    bin_root = tmp_path / "bin"
    home.mkdir()
    target.mkdir()
    bin_root.mkdir()
    (target / "Contract.sol").write_bytes(b"contract Contract {}\n")
    provider_marker = tmp_path / "provider-invoked"
    codex = bin_root / "codex"
    codex.write_text(
        '#!/bin/sh\n: > "$PLAMEN_TEST_PROVIDER_MARKER"\nexit 99\n',
        encoding="utf-8",
    )
    codex.chmod(0o700)
    before = _tree_snapshot(target)
    environment = {
        "HOME": str(home),
        "PATH": str(bin_root) + os.pathsep + os.defpath,
        "PIP_INDEX_URL": "https://invalid.example.test/no-bootstrap",
        "PLAMEN_TEST_PROVIDER_MARKER": str(provider_marker),
        "PYTHONHASHSEED": "0",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": "",
    }

    completed = subprocess.run(
        [
            sys.executable, "-B", str(ROOT / "plamen.py"),
            "plan", "core", str(target), "--codex", "--json",
        ],
        cwd=target,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stderr == ""
    plan = json.loads(completed.stdout)
    assert plan["schema"] == "plamen.public_plan.v1"
    assert plan["backend"] == "codex"
    assert plan["launchable"] is True
    assert plan["provider_invocations"] == 0
    assert not provider_marker.exists()
    assert _tree_snapshot(target) == before
    assert list(home.iterdir()) == []


@pytest.mark.skipif(
    sys.platform != "darwin" or not Path("/tmp").is_symlink(),
    reason="Darwin /tmp lexical-link admission regression",
)
def test_darwin_cold_lexical_tmp_home_is_absent_but_existing_candidate_rejects(
    monkeypatch,
):
    front = _load_front()
    with tempfile.TemporaryDirectory(
        prefix="plamen-cold-home-", dir="/private/tmp",
    ) as raw_root:
        canonical_root = Path(raw_root)
        canonical_home = canonical_root / "home"
        canonical_home.mkdir()
        lexical_home = Path("/tmp") / canonical_root.name / "home"
        assert os.path.realpath(lexical_home) == os.path.realpath(canonical_home)

        monkeypatch.setenv("HOME", str(canonical_home))
        assert front._installed_runtime_root() is None
        monkeypatch.setenv("HOME", str(lexical_home))
        assert front._installed_runtime_root() is None

        target = canonical_root / "target"
        bin_root = canonical_root / "bin"
        target.mkdir()
        bin_root.mkdir()
        (target / "Contract.sol").write_bytes(b"contract Contract {}\n")
        codex = bin_root / "codex"
        codex.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
        codex.chmod(0o700)
        completed = subprocess.run(
            [
                sys.executable, "-B", str(ROOT / "plamen.py"),
                "plan", "core", str(target), "--codex", "--json",
            ],
            cwd=target,
            env={
                "HOME": str(lexical_home),
                "PATH": str(bin_root) + os.pathsep + os.defpath,
                "PYTHONHASHSEED": "0",
                "PYTHONNOUSERSITE": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONPATH": "",
            },
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr
        assert json.loads(completed.stdout)["launchable"] is True
        assert list(canonical_home.iterdir()) == []

        (canonical_home / ".plamen").mkdir()
        with pytest.raises(RuntimeError, match="POSIX committed authority"):
            front._installed_runtime_root()


@pytest.mark.parametrize(
    ("route", "arguments"),
    (
        ("smart-contract", ("core", "{target}", "--yes", "--codex")),
        ("l1", ("l1", "core", "{target}", "--yes", "--codex")),
        ("resume", ("resume", "{target}/.scratchpad/config.json")),
        ("start-config", ("start-config", "{target}/.scratchpad/config.json")),
        ("setup", ("setup",)),
        ("uninstall", ("uninstall",)),
        ("rag", ("rag",)),
        ("compare", ("compare", "{report}")),
        ("private-config", ("config", "--create", "{target}")),
        ("wizard-dry", ("wizard", "--dry-run", "--codex", "{target}")),
        ("mcp-launch", ("mcp-launch",)),
        ("backend-launch", ("backend-launch",)),
        ("doctor-alias-verify", ("verify",)),
        ("doctor-alias-check", ("check",)),
        ("legacy-estimate", ("--estimate", "{target}", "core")),
    ),
)
def test_public_posix_mutating_route_matrix_refuses_without_residue(
    tmp_path, route, arguments,
):
    home = tmp_path / "home"
    target = tmp_path / "target"
    home.mkdir()
    target.mkdir()
    (target / "Contract.sol").write_bytes(b"contract Seed {}")
    report = target / "report.md"
    report.write_bytes(b"# report\n")
    before = _tree_snapshot(target)
    formatted = [
        item.format(target=target, report=report) for item in arguments
    ]
    environment = {
        "HOME": str(home),
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PLAMEN_POSIX_GOVERNED_RUNTIME": "forged-environment-bypass",
        "PYTHONHASHSEED": "0",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": "",
    }

    completed = subprocess.run(
        [sys.executable, "-B", str(ROOT / "plamen.py"), *formatted],
        cwd=target,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
        check=False,
    )

    native_audit_route = route in {"resume", "start-config"}
    expected_returncode = 75 if native_audit_route else 3
    expected_error = (
        "POSIX native audit admission denied."
        if native_audit_route
        else "qualified only on Windows"
    )
    assert completed.returncode == expected_returncode, (route, completed.stderr)
    assert expected_error in completed.stderr
    assert _tree_snapshot(target) == before
    assert list(home.iterdir()) == []


def test_posix_read_root_rejects_symlinked_ancestor(tmp_path):
    front = _load_front()
    outside = (tmp_path / "outside").absolute()
    target = outside / "root"
    target.mkdir(parents=True)
    alias = (tmp_path / "alias").absolute()
    alias.symlink_to(outside, target_is_directory=True)

    with pytest.raises((OSError, RuntimeError)):
        front._codex_dispatcher_open_root(
            alias / "root", full_mutation=False,
        )

    handle, close = front._codex_dispatcher_open_root(
        target, full_mutation=False,
    )
    try:
        assert os.fstat(handle).st_ino == os.lstat(target).st_ino
    finally:
        close()


def test_posix_governed_mutations_apply_only_to_exact_addresses(readonly_dispatcher):
    _front, value, plamen_root, codex_root = readonly_dispatcher
    tree_path = plamen_root / "tree"
    tree_path.mkdir()
    payload_path = tree_path / "payload.bin"
    stage_path = tree_path / "stage.bin"
    payload_path.write_bytes(b"authorized-destination")
    stage_path.write_bytes(b"authorized-source")
    payload = value.address("plamen", ("tree", "payload.bin"))
    stage = value.address("plamen", ("tree", "stage.bin"))

    value.mkdir(value.address("plamen", ("new-tree",)))
    value.publish_bytes(payload, b"governed-publication")
    value.replace(stage, payload)
    value.unlink(payload)
    assert value.ensure_junction() is True

    assert not payload_path.exists()
    assert not stage_path.exists()
    assert (plamen_root / "new-tree").is_dir()
    assert (codex_root / "plamen").is_symlink()
    assert os.readlink(codex_root / "plamen") == str(plamen_root)


def test_posix_low_level_rename_validates_before_namespace_effect(
    tmp_path, monkeypatch,
):
    front = _load_front()
    root = (tmp_path / "root").absolute()
    root.mkdir()
    (root / "source").write_bytes(b"source")
    (root / "destination").write_bytes(b"destination")
    parent, close = front._codex_dispatcher_open_root(
        root, full_mutation=False,
    )
    source = front._codex_native_open_relative(
        parent, "source", directory=False, create=False,
        access=0x80000000 | 0x40000000,
    )
    called = False

    def forbidden_validation(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("validation hook must not be reached")

    monkeypatch.setattr(
        front, "_codex_posix_require_named_handle", forbidden_validation,
    )
    try:
        with pytest.raises(AssertionError, match="validation hook"):
            front._codex_posix_rename(
                parent, "source", source, parent, "destination", replace=True,
            )
        assert called
        assert (root / "source").read_bytes() == b"source"
        assert (root / "destination").read_bytes() == b"destination"
    finally:
        front._codex_native_close(source)
        close()


def test_posix_low_level_create_reaches_namespace_only_after_census(
    tmp_path, monkeypatch,
):
    front = _load_front()
    root = (tmp_path / "root").absolute()
    root.mkdir()
    parent, close = front._codex_dispatcher_open_root(
        root, full_mutation=False,
    )
    events = []
    original_names = front._codex_native_directory_names

    def observed_names(*args, **kwargs):
        events.append("census")
        return original_names(*args, **kwargs)

    def forbidden_mkdir(*_args, **_kwargs):
        events.append("mkdir")
        raise AssertionError("first namespace effect intercepted")

    monkeypatch.setattr(front, "_codex_native_directory_names", observed_names)
    monkeypatch.setattr(front.os, "mkdir", forbidden_mkdir)
    try:
        with pytest.raises(AssertionError, match="first namespace effect"):
            front._codex_native_open_relative(
                parent, "created", directory=True, create=True,
            )
        assert events == ["census", "mkdir"]
        assert not (root / "created").exists()
    finally:
        close()


def test_posix_low_level_directory_open_failure_reports_retained_residue(
    tmp_path, monkeypatch,
):
    front = _load_front()
    root = (tmp_path / "root").absolute()
    root.mkdir()
    parent, close = front._codex_dispatcher_open_root(
        root, full_mutation=False,
    )
    created_identity = None

    def fail_after_mkdir(*_args, **_kwargs):
        nonlocal created_identity
        created = os.stat(
            "created", dir_fd=parent, follow_symlinks=False,
        )
        created_identity = (
            int(created.st_dev), int(created.st_ino),
            stat.S_IFMT(created.st_mode),
        )
        raise AssertionError("injected post-mkdir open failure")

    monkeypatch.setattr(front.os, "open", fail_after_mkdir)
    try:
        with pytest.raises(
            RuntimeError,
            match="failed before cleanup authority was retained",
        ) as stopped:
            front._codex_native_open_relative(
                parent, "created", directory=True, create=True,
            )
        assert isinstance(stopped.value.__cause__, AssertionError)
        assert (root / "created").is_dir()
        observed = os.lstat(root / "created")
        assert created_identity == (
            int(observed.st_dev), int(observed.st_ino),
            stat.S_IFMT(observed.st_mode),
        )
    finally:
        close()


def test_posix_low_level_directory_open_failure_never_deletes_substitution(
    tmp_path, monkeypatch,
):
    front = _load_front()
    root = (tmp_path / "root").absolute()
    outside = (tmp_path / "outside").absolute()
    root.mkdir()
    outside.mkdir()
    parent, close = front._codex_dispatcher_open_root(
        root, full_mutation=False,
    )

    def replace_then_fail(*_args, **_kwargs):
        created = root / "created"
        created.rmdir()
        created.symlink_to(outside, target_is_directory=True)
        raise OSError("injected substituted open failure")

    monkeypatch.setattr(front.os, "open", replace_then_fail)
    try:
        with pytest.raises(
            RuntimeError,
            match="namespace residue may remain",
        ) as stopped:
            front._codex_native_open_relative(
                parent, "created", directory=True, create=True,
            )
        assert isinstance(stopped.value.__cause__, OSError)
        assert (root / "created").is_symlink()
        assert os.readlink(root / "created") == str(outside)
        assert outside.is_dir()
    finally:
        close()


def test_posix_low_level_directory_open_interrupt_is_reraised_with_debt_note(
    tmp_path, monkeypatch,
):
    front = _load_front()
    root = (tmp_path / "root").absolute()
    root.mkdir()
    parent, close = front._codex_dispatcher_open_root(
        root, full_mutation=False,
    )

    def interrupt_open(*_args, **_kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(front.os, "open", interrupt_open)
    try:
        with pytest.raises(KeyboardInterrupt) as stopped:
            front._codex_native_open_relative(
                parent, "created", directory=True, create=True,
            )
        assert any(
            "namespace residue may remain" in note
            for note in getattr(stopped.value, "__notes__", ())
        )
        assert (root / "created").is_dir()
    finally:
        close()


@pytest.mark.parametrize(
    "component", (".", "..", "../foreign", "a/b", "contains\x00nul"),
)
def test_posix_low_level_open_rejects_noncomponent_before_census(
    tmp_path, monkeypatch, component,
):
    front = _load_front()
    root = (tmp_path / "root").absolute()
    root.mkdir()
    parent, close = front._codex_dispatcher_open_root(
        root, full_mutation=False,
    )
    reached = False

    def forbidden_census(*_args, **_kwargs):
        nonlocal reached
        reached = True
        raise AssertionError("directory census must not be reached")

    monkeypatch.setattr(
        front, "_codex_native_directory_names", forbidden_census,
    )
    try:
        with pytest.raises(
            RuntimeError, match="not one raw component",
        ):
            front._codex_native_open_relative(
                parent, component, directory=True, create=True,
            )
        assert not reached
        assert not (tmp_path / "foreign").exists()
    finally:
        close()


def test_posix_root_walk_preserves_colon_and_backslash_components(tmp_path):
    front = _load_front()
    root = (tmp_path / "colon:name" / "back\\slash").absolute()
    root.mkdir(parents=True)

    handle, close = front._codex_dispatcher_open_root(
        root, full_mutation=False,
    )
    try:
        observed = os.fstat(handle)
        expected = os.stat(root, follow_symlinks=False)
        assert stat.S_ISDIR(observed.st_mode)
        assert (int(observed.st_dev), int(observed.st_ino)) == (
            int(expected.st_dev), int(expected.st_ino),
        )
    finally:
        close()


def test_posix_low_level_unlink_validates_before_namespace_effect(
    readonly_dispatcher, monkeypatch,
):
    front, value, plamen_root, _codex_root = readonly_dispatcher
    tree = plamen_root / "tree"
    tree.mkdir()
    payload_path = tree / "payload.bin"
    payload_path.write_bytes(b"payload")
    payload = value.address("plamen", ("tree", "payload.bin"))
    called = False

    def forbidden(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("unlink authority must not be reached")

    monkeypatch.setattr(front, "_codex_posix_require_named_handle", forbidden)
    monkeypatch.setattr(front.os, "unlink", forbidden)
    with pytest.raises(AssertionError, match="unlink authority"):
        value._native_unlink_path(payload)

    assert called
    assert payload_path.read_bytes() == b"payload"


def test_posix_fd_bound_write_and_chmod_apply_to_retained_inode(tmp_path):
    front = _load_front()
    payload = tmp_path / "payload.bin"
    payload.write_bytes(b"original")
    payload.chmod(0o600)
    descriptor = os.open(payload, os.O_RDWR | os.O_NOFOLLOW)
    try:
        front._codex_native_write(descriptor, b"replacement")
        front._codex_native_set_readonly(descriptor)
    finally:
        os.close(descriptor)

    assert payload.read_bytes() == b"replacement"
    assert stat.S_IMODE(os.lstat(payload).st_mode) == 0o400


def test_posix_rejoin_detects_relocated_retained_parent(
    readonly_dispatcher, tmp_path,
):
    front, value, plamen_root, _codex_root = readonly_dispatcher
    tree = plamen_root / "tree"
    tree.mkdir()
    (tree / "payload.bin").write_bytes(b"payload")
    root, components = value._relative(
        value.address("plamen", ("tree", "payload.bin"))
    )
    _descriptor, retained = value._native_snapshot(root, components)
    outside = tmp_path / "outside"
    outside.mkdir()
    os.rename(tree, outside / "tree")
    tree.mkdir()
    try:
        with pytest.raises(RuntimeError, match="named identity differs"):
            value._native_rejoin_parents(retained)
    finally:
        handles = [retained["leaf"], *retained["parents"]]
        value._close_native_chain(handles)


def test_posix_root_chain_detects_relocated_retained_root(
    readonly_dispatcher, tmp_path,
):
    _front, value, plamen_root, _codex_root = readonly_dispatcher
    outside = tmp_path / "outside-root"
    os.rename(plamen_root, outside)
    plamen_root.mkdir()

    with pytest.raises(RuntimeError, match="named identity differs"):
        value._root_join(plamen_root)


def test_posix_source_snapshot_rejects_symlink_and_fifo(tmp_path):
    front = _load_front()
    source = (tmp_path / "source").absolute()
    source.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_bytes(b"print('outside')\n")
    (source / "inside.py").symlink_to(outside)

    with pytest.raises((OSError, RuntimeError)):
        front._codex_install_source_snapshot(
            source, exact_files={"inside.py"}, tree_roots=[],
        )

    fifo = source / "pipe.py"
    os.mkfifo(fifo)
    with pytest.raises((OSError, RuntimeError)):
        front._codex_install_source_snapshot(
            source, exact_files={"pipe.py"}, tree_roots=[],
        )


def test_posix_source_snapshot_identity_failure_closes_root_chain(
    tmp_path, monkeypatch,
):
    front = _load_front()
    source = (tmp_path / "source").absolute()
    source.mkdir()

    def injected_identity_failure(_handle):
        raise RuntimeError("injected source identity failure")

    monkeypatch.setattr(
        front, "_borrowed_reader_handle_identity", injected_identity_failure,
    )
    before = _fd_count()
    with pytest.raises(RuntimeError, match="injected source identity failure"):
        front._codex_install_source_snapshot(
            source, exact_files=set(), tree_roots=[],
        )
    assert _fd_count() == before


def test_posix_constructor_failure_closes_partially_acquired_roots(
    tmp_path, monkeypatch,
):
    front = _load_front()
    codex = (tmp_path / "codex").absolute()
    source = (tmp_path / "source").absolute()
    missing_plamen = (tmp_path / "missing-plamen").absolute()
    codex.mkdir()
    source.mkdir()
    anchor = codex / front._CODEX_INSTALL_ANCHOR
    anchor.write_bytes(b"writer")
    writer = os.open(anchor, os.O_RDWR | os.O_NOFOLLOW)
    real_open = front._codex_dispatcher_open_root

    def read_only_open(path, *, full_mutation=True):
        return real_open(path, full_mutation=False)

    monkeypatch.setattr(front, "_CODEX_INSTALL_SOURCE_COUNT", 0)
    monkeypatch.setattr(front, "_codex_dispatcher_open_root", read_only_open)
    monkeypatch.setattr(
        front, "_borrowed_reader_process_started_100ns", lambda: 1,
    )
    before = _fd_count()
    try:
        for _ in range(10):
            with pytest.raises((FileNotFoundError, RuntimeError, OSError)):
                front._CodexInstallMutationDispatcher(
                    front._CODEX_INSTALL_CONTEXT_AUTHORITY,
                    transaction_id="b" * 32,
                    writer_generation="generation",
                    writer_handle=writer,
                    source_root=source,
                    plamen_root=missing_plamen,
                    codex_home=codex,
                    source_rows=[],
                )
        assert _fd_count() == before
    finally:
        os.close(writer)


@pytest.mark.parametrize("identity_failure_call", (2, 3, 4))
def test_posix_constructor_identity_failure_closes_each_acquired_root_chain(
    tmp_path, monkeypatch, identity_failure_call,
):
    front = _load_front()
    codex = (tmp_path / "codex").absolute()
    plamen = (tmp_path / "plamen").absolute()
    source = (tmp_path / "source").absolute()
    for root in (codex, plamen, source):
        root.mkdir()
    anchor = codex / front._CODEX_INSTALL_ANCHOR
    anchor.write_bytes(b"writer")
    writer = os.open(anchor, os.O_RDWR | os.O_NOFOLLOW)
    real_open = front._codex_dispatcher_open_root
    real_identity = front._borrowed_reader_handle_identity
    identity_calls = 0

    def read_only_open(path, *, full_mutation=True):
        return real_open(path, full_mutation=False)

    def injected_identity_failure(handle):
        nonlocal identity_calls
        identity_calls += 1
        if identity_calls == identity_failure_call:
            raise RuntimeError("injected root identity failure")
        return real_identity(handle)

    monkeypatch.setattr(front, "_CODEX_INSTALL_SOURCE_COUNT", 0)
    monkeypatch.setattr(front, "_codex_dispatcher_open_root", read_only_open)
    monkeypatch.setattr(
        front, "_borrowed_reader_handle_identity", injected_identity_failure,
    )
    monkeypatch.setattr(
        front, "_borrowed_reader_process_started_100ns", lambda: 1,
    )
    before = _fd_count()
    try:
        with pytest.raises(RuntimeError, match="injected root identity failure"):
            front._CodexInstallMutationDispatcher(
                front._CODEX_INSTALL_CONTEXT_AUTHORITY,
                transaction_id="c" * 32,
                writer_generation="generation",
                writer_handle=writer,
                source_root=source,
                plamen_root=plamen,
                codex_home=codex,
                source_rows=[],
            )
        assert identity_calls == identity_failure_call
        assert _fd_count() == before
    finally:
        os.close(writer)


def test_darwin_strict_fsync_orders_fsync_before_fullfsync(monkeypatch):
    front = _load_front()
    import fcntl

    observed = []
    monkeypatch.setattr(front.sys, "platform", "darwin")
    monkeypatch.setattr(
        front.os, "fsync",
        lambda descriptor: observed.append(("fsync", descriptor)),
    )
    monkeypatch.setattr(
        fcntl, "fcntl",
        lambda descriptor, command, argument=0: observed.append(
            ("fcntl", descriptor, command, argument)
        ) or 0,
    )

    front._codex_posix_fsync_descriptor(17)

    assert observed == [("fsync", 17), ("fcntl", 17, 51, 0)]


def test_posix_xattr_aggregate_is_bounded(monkeypatch):
    front = _load_front()
    names = [f"user.value-{index}" for index in range(9)]

    def listxattr(_descriptor):
        return names

    def getxattr(_descriptor, _name):
        return b"x" * (1024 * 1024)

    monkeypatch.setattr(front.os, "listxattr", listxattr, raising=False)
    monkeypatch.setattr(front.os, "getxattr", getxattr, raising=False)
    monkeypatch.setattr(front.os, "supports_fd", {listxattr, getxattr})

    with pytest.raises(RuntimeError, match="aggregate xattr"):
        front._claude_projection_posix_fd_xattrs(17)


def test_posix_keeper_capabilities_refuse_without_endpoint_creation(
    tmp_path, monkeypatch,
):
    front = _load_front()
    called = False

    def forbidden_duplicate(_handle):
        nonlocal called
        called = True
        raise AssertionError("writer duplication must not occur")

    monkeypatch.setattr(
        front, "_duplicate_install_writer_for_child", forbidden_duplicate,
    )
    with pytest.raises(RuntimeError, match="POSIX install keeper is unavailable"):
        front._codex_install_keeper_channel("c" * 32)
    with pytest.raises(RuntimeError, match="POSIX install keeper is unavailable"):
        front._start_codex_install_keeper(
            transaction_id="c" * 32,
            writer_handle=17,
            writer_generation="generation",
            codex_home=tmp_path / "codex",
            plamen_root=tmp_path / "plamen",
            source_root=tmp_path / "source",
            descriptor_sha256="d" * 64,
            pipe=str(tmp_path / "keeper.sock"),
            authkey=b"a" * 32,
            pipe_instance_nonce="e" * 64,
            binding_publisher=lambda raw: raw,
        )
    assert not called
    assert list(tmp_path.iterdir()) == []


def test_windows_keeper_pipe_schema_remains_exact(monkeypatch):
    front = _load_front()
    transaction_id = "f" * 32
    monkeypatch.setattr(front.os, "name", "nt")

    pipe = front._codex_install_keeper_channel(transaction_id)

    assert pipe.startswith(r"\\.\pipe\plamen-install-" + transaction_id + "-")
    assert front._codex_keeper_pipe_valid(pipe, transaction_id)
    assert not front._codex_keeper_pipe_valid(pipe + "-foreign", transaction_id)


def test_posix_read_descriptor_hashes_exact_bytes(tmp_path):
    front = _load_front()
    root = (tmp_path / "root").absolute()
    root.mkdir()
    payload = b"retained-reader"
    (root / "payload.bin").write_bytes(payload)

    descriptor, raw = front._codex_install_posix_committed_read(
        root, ("payload.bin",), directory=False,
    )

    assert raw == payload
    assert descriptor["sha256"] == hashlib.sha256(payload).hexdigest()
    assert descriptor["links"] == 1
    assert stat.S_ISREG(descriptor["mode"])
