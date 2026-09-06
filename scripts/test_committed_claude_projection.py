"""Focused install-boundary regressions for the committed Claude projection."""

import ast
import hashlib
import contextlib
import importlib.util
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest


_PLAMEN = Path(__file__).resolve().parents[1] / "plamen.py"


def _load():
    import sys

    spec = importlib.util.spec_from_file_location(
        "plamen_committed_claude_projection", _PLAMEN,
    )
    module = importlib.util.module_from_spec(spec)
    saved = sys.argv
    sys.argv = ["plamen.py"]
    try:
        spec.loader.exec_module(module)
    finally:
        sys.argv = saved
    return module


def _receipt(source: Path, installed: Path, codex: Path):
    return {
        "schema": "plamen.codex_install.v2",
        "state": "COMMITTED",
        "transaction_id": "1" * 32,
        "source_count": 759,
        "runtime_count": 728,
        "adapter_count": 31,
        "source_manifest_sha256": "2" * 64,
        "runtime_manifest_sha256": "3" * 64,
        "adapter_manifest_sha256": "4" * 64,
        "source_root": str(source.absolute()),
        "plamen_root": str(installed.absolute()),
        "codex_root": str(codex.absolute()),
        "rows": [],
        "terminal_verification": {
            "verified_count": 759,
            "verified_manifest_sha256": "2" * 64,
            "completed_ns": 1,
            "projection_public_key": "5" * 64,
        },
    }


def _build_borrowed_legacy_candidate(module, tmp_path, *, probe_early_admission=False):
    """Build the current 762-row package carrying a legacy migration."""
    user_root = (tmp_path / "user").absolute()
    source = (tmp_path / "legacy-source").absolute()
    installed = user_root / ".plamen"
    codex = user_root / ".codex"
    claude = user_root / ".claude"
    cwd = tmp_path / "project"
    for directory in (source, installed, codex, claude, cwd):
        directory.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        managed_runtime = module._managed_runtime_root().resolve(strict=True)
        candidate_runtime = (
            user_root / ".local" / "share" / "plamen" / "runtime" / "py312"
        )
        candidate_runtime.parent.mkdir(parents=True)
        subprocess.run(
            [
                "cmd", "/c", "mklink", "/J",
                os.path.normpath(candidate_runtime),
                os.path.normpath(managed_runtime),
            ],
            check=True, capture_output=True,
        )
    transaction_id = "9" * 32
    transaction_root = codex / ".plamen-install-transactions" / transaction_id
    (transaction_root / "stage").mkdir(parents=True)

    # Derive the exact production 731/31 roster, but bind the current source
    # bytes instead of consulting the intentionally stale governance digests.
    # This makes the borrowed child execute the real driver and every real
    # local import while keeping this source-only regression hermetic.
    source_root = _PLAMEN.parent
    closure_raw = module._codex_install_committed_read(
        source_root,
        ("verification_policy", "toolchain_runtime_closure.v1.json"),
        directory=False,
    )[1]
    closure = module._strict_json_bytes(closure_raw)
    runtime_paths = {
        "verification_policy/toolchain_runtime_closure.v1.json",
        "verification_policy/__init__.py",
        "verification_policy/methodology_reachability.v1.json",
        "verification_policy/verification_method_registry.v1.json",
        *module._CODEX_INSTALL_TOP_LEVEL,
        *module._CODEX_INSTALL_MCP_FILES,
        *(row["path"] for row in closure["assets"]),
    }
    exact_files = set(runtime_paths) | {"codex-adapter/AGENTS.md"}
    tree_roots = list(module._CODEX_INSTALL_METHOD_ROOTS) + [
        "codex-adapter/" + root for root in module._CODEX_INSTALL_ADAPTER_ROOTS
    ]
    snapshot, _source_authority = module._codex_install_source_snapshot(
        source_root, exact_files=exact_files, tree_roots=tree_roots,
    )
    for root_name in module._CODEX_INSTALL_METHOD_ROOTS:
        prefix = root_name + "/"
        runtime_paths.update(
            path for path in snapshot if path.startswith(prefix)
        )
    adapter_paths = {"AGENTS.md"}
    for root_name in module._CODEX_INSTALL_ADAPTER_ROOTS:
        prefix = "codex-adapter/" + root_name + "/"
        adapter_paths.update(
            path[len("codex-adapter/"):] for path in snapshot
            if path.startswith(prefix)
        )
    installed_front_raw = snapshot["plamen.py"][0]
    if probe_early_admission:
        probe_callsite = b"\nif not _bootstrap():\n"
        assert installed_front_raw.count(probe_callsite) == 1
        probe = (
            b"\nif sys.argv[1:2] == ['--detect-language']:\n"
            b"    _probe_receipt = _early_internal_launcher_receipt()\n"
            b"    assert _probe_receipt['state'] == _CODEX_INSTALL_TERMINAL_STATE\n"
            b"    sys.stdout.buffer.write(b'REAL_ADMISSION_OK\\n')\n"
            b"    sys.stdout.buffer.flush()\n"
            b"    raise SystemExit(0)\n"
        )
        installed_front_raw = installed_front_raw.replace(
            probe_callsite, probe + probe_callsite, 1,
        )
    specs = [
        (
            relative,
            "plamen",
            relative,
            installed_front_raw if relative == "plamen.py" else snapshot[relative][0],
        )
        for relative in sorted(runtime_paths)
    ] + [
        (
            "codex-adapter/" + relative, "codex", relative,
            snapshot["codex-adapter/" + relative][0],
        )
        for relative in sorted(adapter_paths)
    ]
    assert len(runtime_paths) == module._CODEX_INSTALL_RUNTIME_COUNT
    assert len(adapter_paths) == module._CODEX_INSTALL_ADAPTER_COUNT
    assert len(specs) == module._CODEX_INSTALL_SOURCE_COUNT

    rows = []
    journal = []
    for index, (source_path, root_name, relative, raw) in enumerate(specs):
        base = installed if root_name == "plamen" else codex
        destination = base.joinpath(*relative.split("/"))
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
        authority = module._codex_install_committed_descriptor(
            base, tuple(relative.split("/")),
        )
        row = {
            "source_path": source_path,
            "install_kind": (
                "runtime" if root_name == "plamen" else "codex-adapter"
            ),
            "destination_root": root_name,
            "destination_path": relative,
            "destination_key": f"{root_name}/{relative}".casefold(),
            "size": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "destination": str(destination),
            "stage": str(transaction_root / "stage" / root_name / relative),
            "terminal_authority": authority,
        }
        rows.append(row)
        journal.append({
            "index": index,
            "destination": str(destination),
            "sha256": row["sha256"],
            "terminal_authority": authority,
        })

    _anchor, writer_handle, writer_close = module._open_install_admission_anchor(
        codex, writer=True, create=True,
    )
    native_lock = module._borrowed_reader_handle_identity(writer_handle)
    lock_identity = [native_lock["volume"], native_lock["file_id"]]
    roster = [{
        "destination": str(claude / "legacy.md"),
        "relative_path": "legacy.md",
        "install_mode": "link",
        "descriptor": {
            "kind": "symlink", "target": str(source / "legacy.md"),
        },
    }]
    migration = {
        "schema": module._CLAUDE_PROJECTION_LEGACY_MIGRATION_SCHEMA,
        "migration_id": "8" * 32,
        "prior_transaction_id": "7" * 32,
        "prior_receipt_sha256": "1" * 64,
        "legacy_source_root": str(source),
        "legacy_lock": {
            "path": str(claude / ".plamen-projection.lock"),
            "public_key": module._CLAUDE_PROJECTION_LEGACY_PUBLIC,
            "device": 1, "inode": 2, "links": 1, "size": 1,
            "sha256": hashlib.sha256(b"\x00").hexdigest(),
        },
        "successor_lock_sha256": "2" * 64,
        "legacy_manifest_sha256": "3" * 64,
        "legacy_projection_count": 1,
        "legacy_runtime_count": 1,
        "legacy_projection_roster": roster,
        "legacy_projection_roster_sha256": hashlib.sha256(json.dumps(
            roster, sort_keys=True, separators=(",", ":"),
        ).encode()).hexdigest(),
        "prior_anchor_identity": lock_identity,
        "prepackage_intent_sha256": "4" * 64,
    }


    runtime_rows = [row for row in rows if row["destination_root"] == "plamen"]
    adapter_rows = [row for row in rows if row["destination_root"] == "codex"]
    combined_sha = module._raw_rows_sha256(rows)
    receipt = {field: None for field in module._CODEX_COMMITTED_RECEIPT_FIELDS}
    receipt.update({
        "schema": module._CODEX_INSTALL_SCHEMA,
        "transaction_id": transaction_id,
        "state": "COMMITTED",
        "source_count": module._CODEX_INSTALL_SOURCE_COUNT,
        "runtime_count": module._CODEX_INSTALL_RUNTIME_COUNT,
        "adapter_count": module._CODEX_INSTALL_ADAPTER_COUNT,
        "source_manifest_sha256": combined_sha,
        "runtime_manifest_sha256": module._raw_rows_sha256(runtime_rows),
        "adapter_manifest_sha256": module._raw_rows_sha256(adapter_rows),
        "source_root": str(source),
        "plamen_root": str(installed),
        "codex_root": str(codex),
        "lock_identity": lock_identity,
        "owner": {
            "pid": os.getpid(), "executable": sys.executable,
            "executable_sha256": hashlib.sha256(
                Path(sys.executable).read_bytes()
            ).hexdigest(),
            "principal": os.environ.get("USERNAME") or "test",
            "started_ns": time.time_ns(),
        },
        "transaction_root": str(transaction_root),
        "stage_root": str(transaction_root / "stage"),
        "backup_root": str(transaction_root / "backup"),
        "inverse_path": str(transaction_root / "inverse.json"),
        "journal_path": str(transaction_root / "journal.json"),
        "rows": rows, "journal": journal,
        "created_junction": False,
        "last_transition_ns": time.time_ns(),
        "inverse_sha256": "5" * 64,
        "junction_identity": None,
        "terminal_verification": module._codex_install_terminal_verification(
            verified_manifest_sha256=combined_sha,
            completed_ns=time.time_ns(),
            projection_public_key="6" * 64,
            projection_lock_public_key="a" * 64,
            prior_lock_authority=migration["legacy_lock"],
            legacy_projection_migration=migration,
        ),
        "terminal_evidence": None,
    })
    receipt_path = codex / module._CODEX_INSTALL_RECEIPT
    receipt_path.write_bytes(module._borrowed_reader_canonical_bytes(receipt))
    return {
        "source": source, "installed": installed, "codex": codex,
        "claude": claude, "cwd": cwd, "transaction_id": transaction_id,
        "receipt": receipt, "receipt_path": receipt_path,
        "writer_handle": writer_handle, "writer_close": writer_close,
        "destination_snapshot": {
            row["destination"]: (row["size"], row["sha256"])
            for row in rows
        },
    }


def _borrowed_test_dispatcher(module, candidate, *, handle=None):
    dispatcher = object.__new__(module._CodexInstallMutationDispatcher)
    dispatcher.transaction_id = candidate["transaction_id"]
    dispatcher.writer_generation = "public:" + candidate["transaction_id"]
    dispatcher.writer_handle = (
        candidate["writer_handle"] if handle is None else handle
    )
    dispatcher.codex_home = candidate["codex"]
    dispatcher.plamen_root = candidate["installed"]
    dispatcher.closed = False
    dispatcher._installer_pid = os.getpid()
    dispatcher._installer_started_100ns = (
        module._borrowed_reader_process_started_100ns()
    )
    return dispatcher


@pytest.mark.skipif(os.name != "nt", reason="Windows borrowed-handle topology")
def test_borrowed_installed_legacy_migration_admission_is_prebootstrap_closed(
    tmp_path,
):
    module = _load()
    candidate = _build_borrowed_legacy_candidate(module, tmp_path)
    try:
        environment = module._codex_install_child_environment(candidate["codex"])
        managed_python = module._managed_runtime_python().resolve(strict=True)
        dispatcher = _borrowed_test_dispatcher(module, candidate)

        def run(kind, target, *arguments):
            return module._run_borrowed_install_child(
                dispatcher=dispatcher,
                argv=[str(managed_python), "-B", str(target), *arguments],
                command_kind=kind,
                cwd=candidate["cwd"],
                environment=environment,
                timeout=180,
            )

        front = candidate["installed"] / "plamen.py"
        driver = candidate["installed"] / "scripts" / "plamen_driver.py"
        for kind, target, arguments in (
            ("FRONT_VERSION", front, ("--version",)),
            ("FRONT_DETECT", front, ("--detect-language", str(candidate["cwd"]))),
            ("DRIVER_VERSION", driver, ("--version",)),
            ("DRIVER_HELP", driver, ("--help",)),
            ("DRIVER_DETECT", driver, ("--detect-language", str(candidate["cwd"]))),
        ):
            result = run(kind, target, *arguments)
            assert result["returncode"] == 0
            assert result["acknowledged"] is True

        for tamper in (
            "roster_digest", "lock_path", "projection_key",
            "lock_key", "lock_authority", "extra_field",
        ):
            tampered = json.loads(json.dumps(candidate["receipt"]))
            migration = tampered["terminal_verification"][
                "legacy_projection_migration"
            ]
            if tamper == "roster_digest":
                migration["legacy_projection_roster_sha256"] = "f" * 64
            elif tamper == "lock_path":
                migration["legacy_lock"]["path"] = str(
                    candidate["claude"] / "foreign.lock"
                )
            elif tamper == "projection_key":
                tampered["terminal_verification"]["projection_public_key"] = "z" * 64
            elif tamper == "lock_key":
                tampered["terminal_verification"]["projection_lock_public_key"] = None
            elif tamper == "lock_authority":
                tampered["terminal_verification"][
                    "projection_lock_authority_sha256"
                ] = "short"
            else:
                tampered["terminal_verification"]["unrecognized"] = True
            candidate["receipt_path"].write_bytes(
                module._borrowed_reader_canonical_bytes(tampered)
            )
            with pytest.raises(RuntimeError, match="returncode.*75"):
                run("DRIVER_VERSION", driver, "--version")

        modern = json.loads(json.dumps(candidate["receipt"]))
        modern["terminal_verification"] = (
            module._codex_install_terminal_verification(
                verified_manifest_sha256=modern["source_manifest_sha256"],
                completed_ns=time.time_ns(),
                projection_public_key="6" * 64,
                projection_lock_public_key="a" * 64,
                prior_lock_authority={"schema": "signed-idle-lock", "id": 1},
            )
        )
        candidate["receipt_path"].write_bytes(
            module._borrowed_reader_canonical_bytes(modern)
        )
        assert run("DRIVER_VERSION", driver, "--version")["returncode"] == 0
        valid_receipt_raw = module._borrowed_reader_canonical_bytes(
            candidate["receipt"]
        )
        candidate["receipt_path"].write_bytes(valid_receipt_raw)
        assert candidate["receipt_path"].read_bytes() == valid_receipt_raw
        for path, (size, digest) in candidate["destination_snapshot"].items():
            raw = Path(path).read_bytes()
            assert len(raw) == size
            assert hashlib.sha256(raw).hexdigest() == digest
    finally:
        candidate["writer_close"]()


@pytest.mark.skipif(os.name != "nt", reason="Windows borrowed-handle topology")
def test_early_launcher_receipt_requires_real_fully_admitted_borrowed_process(
    tmp_path,
):
    module = _load()
    candidate = _build_borrowed_legacy_candidate(
        module, tmp_path, probe_early_admission=True,
    )
    try:
        environment = module._codex_install_child_environment(candidate["codex"])
        managed_python = module._managed_runtime_python().resolve(strict=True)
        dispatcher = _borrowed_test_dispatcher(module, candidate)
        result = module._run_borrowed_install_child(
            dispatcher=dispatcher,
            argv=[
                str(managed_python), "-B",
                str(candidate["installed"] / "plamen.py"),
                "--detect-language", str(candidate["cwd"]),
            ],
            command_kind="FRONT_DETECT",
            cwd=candidate["cwd"],
            environment=environment,
            timeout=180,
        )
        assert result["returncode"] == 0
        assert result["acknowledged"] is True
        assert result["stdout"] == b"REAL_ADMISSION_OK\n"
    finally:
        candidate["writer_close"]()


@pytest.mark.skipif(os.name != "nt", reason="Windows borrowed-handle topology")
def test_ordinary_admission_reader_cannot_mint_borrowed_smoke(tmp_path):
    module = _load()
    candidate = _build_borrowed_legacy_candidate(module, tmp_path)
    candidate["writer_close"]()
    _anchor, reader, reader_close = module._open_install_admission_anchor(
        candidate["codex"], writer=False, create=False,
    )
    try:
        dispatcher = _borrowed_test_dispatcher(
            module, candidate, handle=reader,
        )
        environment = module._codex_install_child_environment(candidate["codex"])
        managed_python = module._managed_runtime_python().resolve(strict=True)
        with pytest.raises(RuntimeError, match="not the install writer"):
            module._run_borrowed_install_child(
                dispatcher=dispatcher,
                argv=[
                    str(managed_python), "-B",
                    str(candidate["installed"] / "plamen.py"), "--version",
                ],
                command_kind="FRONT_VERSION", cwd=candidate["cwd"],
                environment=environment, timeout=180,
            )
    finally:
        reader_close()


@pytest.mark.skipif(os.name != "nt", reason="Windows borrowed-handle topology")
def test_nonexclusive_writable_anchor_cannot_mint_borrowed_smoke(tmp_path):
    import ctypes
    from ctypes import wintypes

    module = _load()
    candidate = _build_borrowed_legacy_candidate(module, tmp_path)
    candidate["writer_close"]()
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.restype = wintypes.HANDLE
    for share_mask in range(1, 8):
        shared_writer = kernel32.CreateFileW(
            wintypes.LPCWSTR(str(
                candidate["codex"] / module._CODEX_INSTALL_ANCHOR
            )),
            wintypes.DWORD(0x80000000 | 0x40000000),
            wintypes.DWORD(share_mask), None, wintypes.DWORD(3),
            wintypes.DWORD(0x00000080 | 0x00200000 | 0x02000000), None,
        )
        assert shared_writer != wintypes.HANDLE(-1).value
        try:
            dispatcher = _borrowed_test_dispatcher(
                module, candidate, handle=int(shared_writer),
            )
            environment = module._codex_install_child_environment(candidate["codex"])
            managed_python = module._managed_runtime_python().resolve(strict=True)
            with pytest.raises(RuntimeError, match="lease is not exclusive"):
                module._run_borrowed_install_child(
                    dispatcher=dispatcher,
                    argv=[
                        str(managed_python), "-B",
                        str(candidate["installed"] / "plamen.py"), "--version",
                    ],
                    command_kind="FRONT_VERSION", cwd=candidate["cwd"],
                    environment=environment, timeout=180,
                )
        finally:
            kernel32.CloseHandle(shared_writer)


@pytest.mark.skipif(os.name != "nt", reason="Windows borrowed-handle topology")
def test_arbitrary_writer_generation_cannot_mint_borrowed_smoke(tmp_path):
    module = _load()
    candidate = _build_borrowed_legacy_candidate(module, tmp_path)
    try:
        dispatcher = _borrowed_test_dispatcher(module, candidate)
        dispatcher.writer_generation = "forged:" + candidate["transaction_id"]
        environment = module._codex_install_child_environment(candidate["codex"])
        managed_python = module._managed_runtime_python().resolve(strict=True)
        with pytest.raises(RuntimeError, match="generation is not transaction-bound"):
            module._run_borrowed_install_child(
                dispatcher=dispatcher,
                argv=[
                    str(managed_python), "-B",
                    str(candidate["installed"] / "plamen.py"), "--version",
                ],
                command_kind="FRONT_VERSION", cwd=candidate["cwd"],
                environment=environment, timeout=180,
            )
    finally:
        candidate["writer_close"]()


def test_migration_validator_is_defined_before_installed_admission():
    source = _PLAMEN.read_text(encoding="utf-8")
    admission = source.index("\n_admit_installed_runtime_before_bootstrap()\n")
    validator = source.index(
        "\ndef _validate_committed_legacy_projection_migration("
    )
    row_validator = source.index("\ndef _validate_committed_install_rows(")
    assert validator < row_validator < admission
    prebootstrap = source[:admission]
    assert "_claude_projection_legacy_migration(receipt)" not in prebootstrap


def test_installed_runtime_admission_uses_posix_home_without_userprofile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    front = _load()
    home = tmp_path / "home"
    installed = home / ".plamen"
    installed.mkdir(parents=True)
    module = installed / "plamen.py"
    raw = b"installed front"
    module.write_bytes(raw)
    authority = {
        "device": 1, "inode": 2, "attributes": 0, "reparse_tag": 0,
        "links": 1, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
        "streams": [], "name": "plamen.py",
    }

    monkeypatch.setattr(front.sys, "platform", "linux")
    monkeypatch.setattr(front, "__file__", str(module))
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("USERPROFILE", raising=False)
    monkeypatch.setattr(
        front, "_codex_install_committed_descriptor",
        lambda *_args, **_kwargs: (dict(authority), raw),
    )

    admitted = front._installed_runtime_root()
    assert admitted is not None
    assert admitted["address"] == installed


def test_prebootstrap_admission_selects_platform_home_variable():
    source = _PLAMEN.read_text(encoding="utf-8")
    tree = ast.parse(source)
    function = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "_admit_installed_runtime_before_bootstrap"
    )
    rendered = ast.unparse(function)
    assert (
        "home_variable = 'USERPROFILE' if sys.platform == 'win32' else 'HOME'"
        in rendered
    )
    assert "user_root = os.environ.get(home_variable)" in rendered
    assert "user_root = os.environ.get('USERPROFILE')" not in rendered


def test_installed_posix_doctor_derives_codex_sibling_without_userprofile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    front = _load()
    home = tmp_path / "home"
    installed = home / ".plamen"
    installed.mkdir(parents=True)
    observed = {}

    monkeypatch.setattr(front.sys, "platform", "linux")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("USERPROFILE", raising=False)
    monkeypatch.setattr(front, "show_banner", lambda: None)
    monkeypatch.setattr(front.console, "print", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(front, "_claude_projection_pending", lambda: False)
    monkeypatch.setattr(
        front, "_claude_projection_state_path",
        lambda: tmp_path / "no-projection-state",
    )
    monkeypatch.setattr(
        front, "_installed_runtime_root",
        lambda: {"address": installed},
    )

    def doctor_issues(*, codex_home, plamen_root):
        observed["codex_home"] = Path(codex_home)
        observed["plamen_root"] = Path(plamen_root)
        return []

    monkeypatch.setattr(front, "_codex_install_doctor_issues", doctor_issues)
    monkeypatch.setattr(front, "_CODEX_INSTALL_READER_COMMAND_KIND", "FRONT_DOCTOR")
    monkeypatch.setattr(
        front, "_has_admitted_install_command",
        lambda *kinds: "FRONT_DOCTOR" in kinds,
    )

    assert front.run_doctor() == 0
    assert observed == {
        "codex_home": home / ".codex",
        "plamen_root": installed,
    }


def test_legacy_projection_recovery_reuses_receipt_under_admission_writer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Recovery must not self-reopen the Windows admission anchor."""

    front = _load()
    claude_home = tmp_path / ".claude"
    claude_home.mkdir()
    monkeypatch.setattr(front, "CLAUDE_HOME", str(claude_home))
    journal_path = Path(front._claude_projection_journal_path())
    journal_path.write_text(
        json.dumps({"legacy_migration": {}}) + "\n", encoding="utf-8",
    )
    receipt = {"codex_root": str(tmp_path / ".codex")}
    prior_backup = claude_home / "prior-state.backup"
    prior_backup.write_text("{}\n", encoding="utf-8")
    receipt_reads = 0
    closed = False

    def validated_receipt():
        nonlocal receipt_reads
        receipt_reads += 1
        if receipt_reads > 1:
            raise AssertionError("admission anchor was reopened under writer lease")
        return receipt

    def open_anchor(*_args, **_kwargs):
        def close():
            nonlocal closed
            closed = True
        return {}, object(), close

    def validate_journal(_value, **kwargs):
        assert kwargs["_validated_receipt"] is receipt
        return {
            "state": "STAGING",
            "transaction_id": "1" * 32,
            "rows": [{
                "kind": "projection_state",
                "prior": {"kind": "file"},
                "backup": str(prior_backup),
                "destination": str(claude_home / ".plamen-projection-state.json"),
            }],
            "owner_pid": 2_000_000_000,
            "owner_started_100ns": 1,
            "root": str(claude_home / "missing-root"),
            "incoming_root": str(claude_home / "missing-incoming"),
        }

    monkeypatch.setattr(front, "_validated_committed_install_receipt", validated_receipt)
    monkeypatch.setattr(front, "_open_install_admission_anchor", open_anchor)
    monkeypatch.setattr(front, "_validate_claude_projection_journal", validate_journal)
    monkeypatch.setattr(front, "_claude_projection_descriptor_matches", lambda *_a: True)
    monkeypatch.setattr(
        front, "_validate_claude_projection_state",
        lambda _value, observed_receipt, **_kwargs: (
            {"rows": []}
            if observed_receipt is receipt
            else (_ for _ in ()).throw(AssertionError("retained receipt not reused"))
        ),
    )
    monkeypatch.setattr(front, "_borrowed_reader_parent_started_100ns", lambda _pid: None)

    assert front._recover_claude_projection_transaction() is True
    assert receipt_reads == 1
    assert closed is True
    assert not journal_path.exists()


def test_front_and_driver_terminal_field_shapes_are_ast_exact():
    def shapes(path):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in tree.body:
            if not isinstance(node, ast.Assign):
                continue
            if not any(
                isinstance(target, ast.Name)
                and target.id == "_CODEX_INSTALL_TERMINAL_FIELD_SHAPES"
                for target in node.targets
            ):
                continue
            assert isinstance(node.value, ast.Tuple)
            return tuple(
                frozenset(ast.literal_eval(item.args[0]))
                for item in node.value.elts
            )
        raise AssertionError("terminal field-shape authority is absent")

    assert shapes(_PLAMEN) == shapes(
        _PLAMEN.parent / "scripts" / "plamen_driver.py"
    )


def _transaction(monkeypatch, module, tmp_path):
    source = tmp_path / "source-authority"
    installed = tmp_path / "installed-authority"
    codex = tmp_path / "codex-authority"
    for directory in (source, installed, codex):
        directory.mkdir(exist_ok=True)
    generation = _receipt(source, installed, codex)
    monkeypatch.setattr(
        module, "_validated_committed_install_receipt", lambda: generation,
    )
    monkeypatch.setattr(module, "_toolchain_runtime_required_files", lambda *_a: [])
    monkeypatch.setattr(
        module, "_open_install_admission_anchor",
        lambda *_a, **_k: (Path("anchor"), object(), lambda: None),
    )
    monkeypatch.setattr(
        module, "_claude_projection_key_path",
        lambda *_a: str(codex / ".plamen-projection-authority.key"),
    )
    _private, public = module._claude_projection_private_key(create=True)
    generation["projection_public_key"] = public
    return module._ClaudeProjectionTransaction(generation)


def _trash_authority(module, transaction, trash, *, identity=None):
    marker_raw = b"1" * 32 + b"\n"
    transaction.mkdir(exist_ok=True)
    (transaction / ".plamen-transaction-owned").write_bytes(marker_raw)
    trash.mkdir(exist_ok=True)
    (trash / ".plamen-trash-owned").write_bytes(marker_raw)
    return {
        "path": module._claude_projection_canonical_path(str(trash)),
        "identity": identity or module._claude_projection_native_directory_identity(
            str(trash)
        ),
        "marker_sha256": hashlib.sha256(marker_raw).hexdigest(),
    }


def _patch_install_shell(monkeypatch, module, source: Path, *, has_claude=True):
    isolated_claude = source.parent / ".claude-shell"
    isolated_claude.mkdir(exist_ok=True)
    isolated_state = source.parent / ".state-shell"
    isolated_state.mkdir(exist_ok=True)
    monkeypatch.setattr(module, "PLAMEN_HOME", str(source))
    monkeypatch.setattr(module, "CLAUDE_HOME", str(isolated_claude))
    monkeypatch.setattr(
        module, "_claude_projection_key_path",
        lambda *_a: str(isolated_state / "projection-key.json"),
    )
    monkeypatch.setattr(
        module, "_validated_committed_install_receipt",
        lambda: (_ for _ in ()).throw(RuntimeError("no installed receipt")),
    )
    monkeypatch.setattr(
        module, "_toolchain_runtime_required_integrity_issues",
        lambda _root, **_kwargs: {"missing": [], "mismatched": []},
    )
    monkeypatch.setattr(module, "_heal_dangling_hooks", lambda _w: None)
    monkeypatch.setattr(module, "_go_bin_dir", lambda: None)
    monkeypatch.setattr(module, "_update_path_env", lambda *_a, **_k: None)
    monkeypatch.setattr(module, "_report_toolchain_visibility", lambda _w: None)
    monkeypatch.setattr(module, "_setup_python_deps", lambda *_a, **_k: True)
    monkeypatch.setattr(
        module, "_setup_config_files",
        lambda *_a, **_k: (_ for _ in ()).throw(
            AssertionError("config merge ran before committed projection")
        ),
    )
    monkeypatch.setattr(module, "_find_codex_bin", lambda: "codex")
    monkeypatch.setattr(
        module.shutil, "which",
        lambda name: "claude" if has_claude and name.startswith("claude") else None,
    )
    monkeypatch.setattr(module.console, "print", lambda *_a, **_k: None)
    monkeypatch.setattr(module, "_ensure_windows_plamen_command", lambda **_k: None)
    monkeypatch.setattr(module, "_ensure_posix_plamen_command", lambda **_k: None)
    monkeypatch.setattr(
        module,
        "_validated_managed_backend_paths",
        lambda _root: {
            "claude": source.parent / "plamen-claude",
            "codex": source.parent / "plamen-codex",
        },
    )
    monkeypatch.setattr(
        module,
        "_validated_managed_backend_authority",
        lambda _root: {
            "plamen_root": str(source),
            "paths": {
                "claude": source.parent / "plamen-claude",
                "codex": source.parent / "plamen-codex",
            },
            "selection": {"fixture": "signed-selection"},
        },
    )
    monkeypatch.setattr(
        module, "_assert_managed_backend_version_postcondition",
        lambda _paths: None,
    )
    monkeypatch.setattr(module, "_write_install_manifest", lambda **_k: None)


def test_source_closure_preflight_precedes_every_mutation(monkeypatch, tmp_path):
    module = _load()
    calls = []
    monkeypatch.setattr(module, "PLAMEN_HOME", str(tmp_path / "checkout"))
    claude = tmp_path / ".claude"
    claude.mkdir()
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    monkeypatch.setattr(
        module, "_claude_projection_key_path",
        lambda *_a: str(tmp_path / "projection-key.json"),
    )
    monkeypatch.setattr(
        module, "_validated_committed_install_receipt",
        lambda: (_ for _ in ()).throw(RuntimeError("no installed receipt")),
    )
    monkeypatch.setattr(
        module, "_toolchain_runtime_required_integrity_issues",
        lambda _root, **_kwargs: {
            "missing": [], "mismatched": ["scripts/plamen_driver.py"],
        },
    )
    monkeypatch.setattr(
        module, "_heal_dangling_hooks", lambda _w: calls.append("mutated"),
    )

    assert module.run_install() == 1
    assert calls == []


def test_failed_or_rolled_back_package_never_touches_prior_claude_projection(
    monkeypatch, tmp_path,
):
    module = _load()
    source = tmp_path / "checkout"
    claude = tmp_path / ".claude"
    source.mkdir()
    claude.mkdir()
    settings = claude / "settings.json"
    mcp = claude / "mcp.json"
    claude_md = claude / "CLAUDE.md"
    settings.write_bytes(b"old-settings\n")
    mcp.write_bytes(b"old-mcp\n")
    claude_md.write_bytes(b"old-claude-md\n")
    _patch_install_shell(monkeypatch, module, source)
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    calls = []
    monkeypatch.setattr(
        module, "_install_codex_adapter",
        lambda _w, **_kwargs: calls.append("transaction-failed") or False,
    )
    monkeypatch.setattr(
        module, "_run_symlink_install",
        lambda *_a, **_k: calls.append("projection"),
    )
    monkeypatch.setattr(
        module,
        "_ensure_windows_plamen_command",
        lambda **_k: calls.append("launcher"),
    )
    monkeypatch.setattr(
        module,
        "_ensure_posix_plamen_command",
        lambda **_k: calls.append("launcher"),
    )

    assert module.run_install() == 1
    assert calls == ["transaction-failed"]
    assert settings.read_bytes() == b"old-settings\n"
    assert mcp.read_bytes() == b"old-mcp\n"
    assert claude_md.read_bytes() == b"old-claude-md\n"


def test_success_projects_exact_committed_root_after_receipt_validation(
    monkeypatch, tmp_path,
):
    module = _load()
    source = tmp_path / "checkout"
    installed = tmp_path / ".plamen"
    codex = tmp_path / ".codex"
    source.mkdir()
    installed.mkdir()
    codex.mkdir()
    receipt = _receipt(source, installed, codex)
    generation = {"transaction_id": receipt["transaction_id"]}
    calls = []
    _patch_install_shell(monkeypatch, module, source)

    def install(_w, **kwargs):
        assert kwargs == {
            "return_receipt": True, "enable_claude_projection": True,
        }
        calls.append("commit")
        return receipt

    def authority(observed, observed_source):
        assert observed is receipt
        assert observed_source == str(source)
        calls.append("validate")
        return str(installed), (str(source),), generation

    def project(_w, **kwargs):
        calls.append("project")
        assert kwargs == {
            "source_root": str(installed),
            "committed_generation": generation,
            "authenticated_prior_roots": (str(source),),
            "mcp_generation_ready": True,
        }

    monkeypatch.setattr(module, "_install_codex_adapter", install)
    monkeypatch.setattr(module, "_committed_claude_projection_authority", authority)
    monkeypatch.setattr(module, "_run_symlink_install", project)

    assert module.run_install() == 0
    assert calls == ["commit", "validate", "project"]


def test_install_completes_legacy_projection_then_commits_current_generation(
    monkeypatch, tmp_path,
):
    module = _load()
    source = tmp_path / "checkout"
    predecessor = tmp_path / ".plamen-predecessor"
    installed = tmp_path / ".plamen"
    codex = tmp_path / ".codex"
    for directory in (source, predecessor, installed, codex):
        directory.mkdir()
    legacy_receipt = _receipt(source, predecessor, codex)
    current_receipt = _receipt(source, installed, codex)
    current_receipt["transaction_id"] = "2" * 32
    legacy_generation = {"transaction_id": legacy_receipt["transaction_id"]}
    current_generation = {"transaction_id": current_receipt["transaction_id"]}
    calls = []
    _patch_install_shell(monkeypatch, module, source)
    monkeypatch.setattr(
        module, "_claude_projection_incomplete_legacy_migration",
        lambda: legacy_receipt,
    )

    def authority(observed, observed_source):
        assert observed_source == str(source)
        if observed is legacy_receipt:
            calls.append("validate-legacy")
            return str(predecessor), (str(source),), legacy_generation
        assert observed is current_receipt
        calls.append("validate-current")
        return str(installed), (str(predecessor),), current_generation

    def project(_w, **kwargs):
        generation = kwargs["committed_generation"]
        if generation is legacy_generation:
            assert kwargs.pop("defer_mcp_config") is True
        else:
            assert "defer_mcp_config" not in kwargs
        calls.append("project-" + generation["transaction_id"][0])

    def install(_w, **kwargs):
        assert kwargs == {
            "return_receipt": True, "enable_claude_projection": True,
        }
        calls.append("commit-current")
        return current_receipt

    monkeypatch.setattr(module, "_committed_claude_projection_authority", authority)
    monkeypatch.setattr(module, "_run_symlink_install", project)
    monkeypatch.setattr(module, "_install_codex_adapter", install)

    assert module.run_install() == 0
    assert calls == [
        "validate-legacy", "project-1", "commit-current",
        "validate-current", "project-2",
    ]


def test_legacy_bridge_config_defers_only_mcp_consumers(monkeypatch):
    module = _load()
    calls = []
    monkeypatch.setattr(
        module, "_merge_settings_json", lambda _w: calls.append("settings"),
    )
    monkeypatch.setattr(
        module, "_merge_claude_md", lambda _w: calls.append("claude-md"),
    )
    monkeypatch.setattr(
        module, "_merge_mcp_json",
        lambda _w: (_ for _ in ()).throw(AssertionError("MCP config rendered")),
    )
    monkeypatch.setattr(
        module, "_setup_mcp_packages",
        lambda *_a, **_k: (_ for _ in ()).throw(
            AssertionError("MCP generation consumed")
        ),
    )

    assert module._setup_config_files(
        lambda _text: None,
        mcp_root="authenticated-predecessor",
        defer_mcp_config=True,
    ) is True
    assert calls == ["settings", "claude-md"]


def test_legacy_bridge_render_excludes_live_mcp_file(monkeypatch, tmp_path):
    module = _load()
    claude = tmp_path / ".claude"
    committed = tmp_path / ".plamen"
    transaction = tmp_path / "transaction"
    for directory in (claude, committed, transaction):
        directory.mkdir()
    (claude / "settings.json").write_bytes(b"old-settings\n")
    (claude / "mcp.json").write_bytes(b"foreign-mcp\n")
    (claude / "CLAUDE.md").write_bytes(b"old-claude\n")
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    monkeypatch.setattr(module, "_heal_dangling_hooks", lambda _w: None)

    def setup(_w, *, mcp_root, defer_mcp_config):
        assert mcp_root == committed
        assert defer_mcp_config is True
        shadow = Path(module.CLAUDE_HOME)
        assert not (shadow / "mcp.json").exists()
        (shadow / "settings.json").write_bytes(b"new-settings\n")
        (shadow / "CLAUDE.md").write_bytes(b"new-claude\n")
        return True

    monkeypatch.setattr(module, "_setup_config_files", setup)
    before = (claude / "mcp.json").stat(follow_symlinks=False)
    updates = module._render_claude_config_updates(
        lambda _text: None, committed,
        staging_root=str(transaction), defer_mcp_config=True,
    )
    after = (claude / "mcp.json").stat(follow_symlinks=False)

    assert [Path(destination).name for destination, _raw in updates] == [
        "settings.json", "CLAUDE.md",
    ]
    assert (claude / "mcp.json").read_bytes() == b"foreign-mcp\n"
    assert (before.st_dev, before.st_ino, before.st_size) == (
        after.st_dev, after.st_ino, after.st_size,
    )


def test_config_render_reuses_authenticated_mcp_generation(monkeypatch):
    module = _load()
    calls = []
    monkeypatch.setattr(
        module, "_merge_settings_json", lambda _w: calls.append("settings"),
    )
    monkeypatch.setattr(
        module, "_merge_mcp_json", lambda _w: calls.append("mcp"),
    )
    monkeypatch.setattr(
        module, "_merge_claude_md", lambda _w: calls.append("claude-md"),
    )
    monkeypatch.setattr(
        module, "_setup_mcp_packages",
        lambda *_a, **_k: (_ for _ in ()).throw(
            AssertionError("authenticated generation was redundantly censused")
        ),
    )

    assert module._setup_config_files(
        lambda _text: None,
        mcp_root="authenticated-current-generation",
        mcp_generation_ready=True,
    ) is True
    assert calls == ["settings", "mcp", "claude-md"]


def test_projection_prior_binding_consumes_sealed_terminal_evidence_once(
    monkeypatch, tmp_path,
):
    module = _load()
    receipt = {
        "codex_root": str(tmp_path / ".codex"),
        "transaction_id": "1" * 32,
        "source_count": 760,
        "source_manifest_sha256": "4" * 64,
        "inverse_sha256": "5" * 64,
        "terminal_evidence": {"schema": "plamen.install.terminal.pointer.v1"},
    }
    prior = {
        "transaction_id": "2" * 32,
        "size": 123,
        "sha256": "3" * 64,
        "terminal_authority": {
            "kind": "file", "name": module._CODEX_INSTALL_RECEIPT,
            "links": 1, "reparse_tag": 0, "size": 123,
            "sha256": "3" * 64, "streams": [],
        },
    }
    observed = []

    monkeypatch.setattr(
        module, "_claude_projection_current_receipt_raw", lambda value: b"receipt",
    )

    def terminal(value, raw, **kwargs):
        observed.append((value, raw, kwargs))
        return {
            "transaction_id": receipt["transaction_id"],
            "source_count": receipt["source_count"],
            "source_manifest_sha256": receipt["source_manifest_sha256"],
            "inverse_sha256": receipt["inverse_sha256"],
            "prior_receipt_authority": prior,
        }

    monkeypatch.setattr(module, "_validate_codex_install_terminal_evidence", terminal)
    monkeypatch.setattr(
        module, "_terminal_evidence_committed_read",
        lambda *_a, **_k: (_ for _ in ()).throw(
            AssertionError("precommit was reopened after sealed validation")
        ),
    )
    assert module._claude_projection_prior_receipt_binding(receipt) == {
        "transaction_id": "2" * 32,
        "size": 123,
        "sha256": "3" * 64,
    }
    assert observed[0][0] == receipt
    assert observed[0][1] == b"receipt"
    assert observed[0][2]["expected_outcome"] == "COMMITTED"

    poisoned = json.loads(json.dumps(prior))
    poisoned["terminal_authority"]["streams"] = [
        {"name": ":evil:$DATA", "size": 1, "allocation_size": 8},
    ]
    with pytest.raises(RuntimeError, match="authority is malformed"):
        module._claude_projection_precommit_binding(
            {"prior_receipt_authority": poisoned}
        )


@pytest.mark.parametrize("verified_count", (0.0, False))
def test_committed_terminal_verified_count_rejects_json_numeric_aliases(
    tmp_path, verified_count,
):
    module = _load()
    receipt = {
        "rows": [],
        "journal": [],
        "terminal_verification": {
            "verified_count": verified_count,
            "verified_manifest_sha256": "0" * 64,
            "completed_ns": 1,
        },
    }

    with pytest.raises(RuntimeError, match="terminal install verification"):
        module._validate_committed_install_rows(
            receipt,
            installed=tmp_path / ".plamen",
            codex_home=tmp_path / ".codex",
            expected_count=0,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("source_count", 759.0),
        ("source_count", True),
        ("runtime_count", 728.0),
        ("runtime_count", True),
        ("adapter_count", 31.0),
        ("adapter_count", True),
        ("verified_count", 759.0),
        ("verified_count", True),
    ),
)
def test_legacy_projection_receipt_rejects_json_numeric_aliases(field, value):
    module = _load()
    receipt = {
        "schema": module._CODEX_INSTALL_SCHEMA,
        "state": "COMMITTED",
        "source_count": module._CLAUDE_PROJECTION_LEGACY_SOURCE_COUNT,
        "runtime_count": module._CLAUDE_PROJECTION_LEGACY_RUNTIME_COUNT,
        "adapter_count": module._CLAUDE_PROJECTION_LEGACY_ADAPTER_COUNT,
        "terminal_verification": {
            "verified_count": module._CLAUDE_PROJECTION_LEGACY_SOURCE_COUNT,
            "verified_manifest_sha256": "0" * 64,
            "completed_ns": 1,
        },
    }
    if field == "verified_count":
        receipt["terminal_verification"][field] = value
    else:
        receipt[field] = value

    assert module._claude_projection_legacy_receipt(receipt) is False


def test_clean_install_materializes_locked_backends_without_ambient_cli(
    monkeypatch, tmp_path,
):
    module = _load()
    source = tmp_path / "checkout"
    installed = tmp_path / ".plamen"
    codex = tmp_path / ".codex"
    source.mkdir(); installed.mkdir(); codex.mkdir()
    receipt = _receipt(source, installed, codex)
    generation = {"transaction_id": receipt["transaction_id"]}
    calls = []
    _patch_install_shell(monkeypatch, module, source, has_claude=False)
    monkeypatch.setattr(module, "_find_codex_bin", lambda: "")
    monkeypatch.setattr(module.shutil, "which", lambda _name: None)

    def install(_w, **kwargs):
        assert kwargs == {
            "return_receipt": True,
            "enable_claude_projection": True,
        }
        calls.append("materialize")
        return receipt

    monkeypatch.setattr(module, "_install_codex_adapter", install)
    monkeypatch.setattr(
        module,
        "_committed_claude_projection_authority",
        lambda *_a: (str(installed), (), generation),
    )
    monkeypatch.setattr(
        module,
        "_run_symlink_install",
        lambda *_a, **_k: calls.append("project"),
    )

    assert module.run_install() == 0
    assert calls == ["materialize", "project"]


def test_clean_codex_only_install_ignores_ambient_claude_and_home_state(
    monkeypatch, tmp_path,
):
    module = _load()
    source = tmp_path / "checkout"
    installed = tmp_path / ".plamen"
    codex = tmp_path / ".codex"
    source.mkdir(); installed.mkdir(); codex.mkdir()
    receipt = _receipt(source, installed, codex)
    calls = []
    _patch_install_shell(monkeypatch, module, source, has_claude=False)
    monkeypatch.setattr(module, "_find_codex_bin", lambda: "")
    monkeypatch.setattr(
        module.shutil, "which",
        lambda name: str(tmp_path / "poison" / name)
        if name in {"claude", "claude.cmd"} else None,
    )
    monkeypatch.setattr(
        module.sys, "argv", ["plamen.py", "install", "--codex"]
    )

    def install(_w, **kwargs):
        assert kwargs == {
            "return_receipt": True,
            "enable_claude_projection": False,
        }
        calls.append("materialize")
        return receipt

    monkeypatch.setattr(module, "_install_codex_adapter", install)
    monkeypatch.setattr(
        module,
        "_run_symlink_install",
        lambda *_a, **_k: calls.append("unexpected-projection"),
    )

    assert module.run_install() == 0
    assert calls == ["materialize"]


def _run_codex_only_prior_projection_package(
    monkeypatch, tmp_path, *, fail_after_commit=False, observed=None,
):
    """Exercise real receipt commit/compensation with a zero-row package."""
    module = _load()
    source = tmp_path / "source"
    installed = tmp_path / "installed"
    codex = tmp_path / "codex"
    for directory in (source, installed, codex):
        directory.mkdir()
    wizard_root = codex / "skills" / "plamen"
    wizard_root.mkdir(parents=True)
    (wizard_root / "plamen-wizard.md").write_bytes(b"sc\n")
    (wizard_root / "plamen-l1-wizard.md").write_bytes(b"l1\n")
    prior = {
        "transaction_id": "1" * 32,
        "source_manifest_sha256": "2" * 64,
        "source_root": str(source.absolute()),
        "plamen_root": str(installed.absolute()),
        "codex_root": str(codex.absolute()),
        "terminal_verification": {
            "verified_count": 0,
            "verified_manifest_sha256": "2" * 64,
            "completed_ns": 1,
            "projection_public_key": "3" * 64,
            "projection_lock_public_key": "3" * 64,
            "projection_lock_authority_sha256": "4" * 64,
        },
    }
    prior_raw = module._borrowed_reader_canonical_bytes(prior)
    receipt_path = codex / module._CODEX_INSTALL_RECEIPT
    receipt_path.write_bytes(prior_raw)
    if observed is not None:
        observed.update({
            "module": module,
            "prior_raw": prior_raw,
            "receipt_path": receipt_path,
        })

    monkeypatch.setattr(module, "_CODEX_INSTALL_SOURCE_COUNT", 0)
    monkeypatch.setattr(module, "_CODEX_INSTALL_RUNTIME_COUNT", 0)
    monkeypatch.setattr(module, "_CODEX_INSTALL_ADAPTER_COUNT", 0)
    monkeypatch.setattr(
        module, "_toolchain_runtime_required_integrity_issues",
        lambda *_a, **_k: {"missing": [], "mismatched": []},
    )
    monkeypatch.setattr(module, "_codex_install_source_rows", lambda *_a, **_k: [])
    monkeypatch.setattr(module, "_validated_committed_install_receipt", lambda: prior)
    key_calls = []

    def private_key(**kwargs):
        assert kwargs == {
            "create": False,
            "expected_public": "3" * 64,
            "codex_home": codex,
        }
        key_calls.append(dict(kwargs))
        return object(), "3" * 64

    monkeypatch.setattr(module, "_claude_projection_private_key", private_key)
    monkeypatch.setattr(
        module, "_validated_prior_committed_receipt",
        lambda *_a, **_k: (prior, {}),
    )
    monkeypatch.setattr(module, "_legacy_plamen_root_is_owned", lambda *_a: False)
    monkeypatch.setattr(
        module, "_legacy_codex_adapter_is_owned", lambda *_a, **_k: False,
    )
    monkeypatch.setattr(
        module, "_capture_codex_install_sentinel",
        lambda **kwargs: {"label": kwargs["label"]},
    )
    monkeypatch.setattr(
        module, "_capture_codex_install_batch_boundary", lambda **_kwargs: None,
    )
    monkeypatch.setattr(
        module._CodexInstallMutationDispatcher,
        "ensure_junction", lambda _self: False,
    )
    monkeypatch.setattr(
        module._CodexInstallMutationDispatcher,
        "junction_authority", lambda *_a, **_k: None,
    )
    monkeypatch.setattr(
        module, "_codex_install_keeper_descriptor",
        lambda **_kwargs: {"pipe_instance_nonce": "5" * 32},
    )
    monkeypatch.setattr(
        module, "_start_codex_install_keeper",
        lambda **_kwargs: {"writer_generation": "test", "process": os.getpid()},
    )
    monkeypatch.setattr(module, "_release_codex_install_keeper", lambda _keeper: None)
    monkeypatch.setattr(
        module, "_run_codex_install_integrated_smoke", lambda **_kwargs: [],
    )
    monkeypatch.setattr(
        module, "_prepare_codex_install_terminal_evidence",
        lambda **_kwargs: {
            "pointer": {"schema": "plamen.install.terminal.pointer.v1"},
            "reservation": None,
        },
    )
    monkeypatch.setattr(
        module, "_finish_codex_install_terminal_evidence", lambda **_kwargs: {},
    )
    monkeypatch.setattr(
        module, "_validate_codex_install_terminal_evidence", lambda *_a, **_k: None,
    )
    failpoint = "after_committed" if fail_after_commit else None
    receipt = module._install_codex_package_transaction(
        source_root=source,
        plamen_root=installed,
        codex_home=codex,
        failpoint=failpoint,
        enable_claude_projection=False,
    )
    return module, prior_raw, receipt_path, receipt, key_calls


def test_codex_only_reinstall_preserves_public_key_without_claude_lock_access(
    monkeypatch, tmp_path,
):
    module, _prior_raw, receipt_path, receipt, key_calls = (
        _run_codex_only_prior_projection_package(monkeypatch, tmp_path)
    )

    assert receipt["state"] == "COMMITTED"
    assert set(receipt["terminal_verification"]) == {
        "verified_count", "verified_manifest_sha256", "completed_ns",
        "projection_public_key", "projection_lock_public_key",
        "projection_lock_authority_sha256",
    }
    assert receipt["terminal_verification"]["projection_public_key"] == "3" * 64
    assert receipt["terminal_verification"]["projection_lock_public_key"] == "3" * 64
    assert (
        receipt["terminal_verification"]["projection_lock_authority_sha256"]
        == "4" * 64
    )
    assert len(key_calls) == 1
    assert module._strict_json_bytes(receipt_path.read_bytes()) == receipt


def test_codex_only_reinstall_after_commit_failure_restores_prior_receipt(
    monkeypatch, tmp_path,
):
    observed = {}
    with pytest.raises(RuntimeError, match="R134_FAILPOINT:after_committed"):
        _run_codex_only_prior_projection_package(
            monkeypatch, tmp_path, fail_after_commit=True, observed=observed,
        )

    receipt_path = observed["receipt_path"]
    assert receipt_path.read_bytes() == observed["prior_raw"]
    rollback = next(
        (receipt_path.parent / ".plamen-install-transactions").glob(
            "*/rollback-result.json"
        )
    )
    assert json.loads(rollback.read_text(encoding="utf-8"))["state"] == "ROLLED_BACK"


def test_codex_only_legacy_receipt_fails_without_reading_claude_state(
    monkeypatch, tmp_path,
):
    module = _load()
    source = tmp_path / "checkout"
    installed = tmp_path / ".plamen"
    codex = tmp_path / ".codex"
    source.mkdir(); installed.mkdir(); codex.mkdir()
    receipt = _receipt(source, installed, codex)
    receipt["terminal_verification"] = {
        "verified_count": 759,
        "verified_manifest_sha256": "2" * 64,
        "completed_ns": 1,
    }
    _patch_install_shell(monkeypatch, module, source, has_claude=False)
    monkeypatch.setattr(module.sys, "argv", ["plamen.py", "install", "--codex"])
    monkeypatch.setattr(
        module, "_validated_committed_install_receipt", lambda: receipt,
    )
    monkeypatch.setattr(
        module, "_claude_projection_legacy_intent_path",
        lambda: (_ for _ in ()).throw(AssertionError("Claude intent probed")),
    )
    monkeypatch.setattr(
        module, "_claude_projection_pending",
        lambda: (_ for _ in ()).throw(AssertionError("Claude journal probed")),
    )
    monkeypatch.setattr(
        module, "_claude_projection_incomplete_legacy_migration",
        lambda: (_ for _ in ()).throw(AssertionError("Claude lock probed")),
    )
    monkeypatch.setattr(
        module, "_install_codex_adapter",
        lambda *_a, **_k: (_ for _ in ()).throw(
            AssertionError("shared receipt was replaced")
        ),
    )

    assert module.run_install() == 1


def test_codex_only_transaction_rechecks_legacy_receipt_under_writer(
    monkeypatch, tmp_path,
):
    module = _load()
    source = tmp_path / "source"
    installed = tmp_path / "installed"
    codex = tmp_path / "codex"
    for directory in (source, installed, codex):
        directory.mkdir()
    receipt_path = codex / module._CODEX_INSTALL_RECEIPT
    receipt_path.write_bytes(b"concurrent-legacy-receipt\n")
    legacy_receipt = _receipt(source, installed, codex)
    legacy_receipt["terminal_verification"] = {
        "verified_count": 759,
        "verified_manifest_sha256": "2" * 64,
        "completed_ns": 1,
    }
    monkeypatch.setattr(
        module, "_validated_committed_install_receipt",
        lambda: (_ for _ in ()).throw(RuntimeError("pre-writer receipt absent")),
    )
    monkeypatch.setattr(
        module, "_toolchain_runtime_required_integrity_issues",
        lambda *_a, **_k: {"missing": [], "mismatched": []},
    )
    monkeypatch.setattr(module, "_CODEX_INSTALL_SOURCE_COUNT", 0)
    monkeypatch.setattr(module, "_CODEX_INSTALL_RUNTIME_COUNT", 0)
    monkeypatch.setattr(module, "_CODEX_INSTALL_ADAPTER_COUNT", 0)
    monkeypatch.setattr(module, "_codex_install_source_rows", lambda *_a, **_k: [])
    monkeypatch.setattr(module, "_legacy_plamen_root_is_owned", lambda *_a: False)
    monkeypatch.setattr(module, "_legacy_codex_adapter_is_owned", lambda *_a, **_k: False)
    monkeypatch.setattr(
        module, "_capture_codex_install_sentinel", lambda **_k: {"label": "test"},
    )
    monkeypatch.setattr(
        module, "_validated_prior_committed_receipt",
        lambda *_a, **_k: (legacy_receipt, {}),
    )
    monkeypatch.setattr(
        module, "_claude_projection_validate_legacy_projection_ownership",
        lambda *_a, **_k: (_ for _ in ()).throw(
            AssertionError("Claude legacy census ran")
        ),
    )

    with pytest.raises(RuntimeError, match="Codex-only install cannot replace"):
        module._install_codex_package_transaction(
            source_root=source, plamen_root=installed, codex_home=codex,
            enable_claude_projection=False,
        )
    assert receipt_path.read_bytes() == b"concurrent-legacy-receipt\n"
    transactions = codex / ".plamen-install-transactions"
    assert not transactions.exists() or not any(transactions.iterdir())


def test_install_fails_when_signed_managed_backend_postcondition_is_absent(
    monkeypatch, tmp_path,
):
    module = _load()
    source = tmp_path / "checkout"
    installed = tmp_path / ".plamen"
    codex = tmp_path / ".codex"
    source.mkdir(); installed.mkdir(); codex.mkdir()
    receipt = _receipt(source, installed, codex)
    _patch_install_shell(monkeypatch, module, source, has_claude=False)
    monkeypatch.setattr(module, "_install_codex_adapter", lambda *_a, **_k: receipt)
    monkeypatch.setattr(
        module,
        "_committed_claude_projection_authority",
        lambda *_a: (str(installed), (), {"transaction_id": receipt["transaction_id"]}),
    )
    monkeypatch.setattr(module, "_run_symlink_install", lambda *_a, **_k: None)
    monkeypatch.setattr(
        module,
        "_validated_managed_backend_authority",
        lambda _root: (_ for _ in ()).throw(RuntimeError("selection absent")),
    )

    assert module.run_install() == 1


def test_install_requires_operational_backend_versions_after_borrowed_doctor(
    monkeypatch, tmp_path,
):
    module = _load()
    source = tmp_path / "checkout"
    installed = tmp_path / ".plamen"
    codex = tmp_path / ".codex"
    source.mkdir(); installed.mkdir(); codex.mkdir()
    receipt = _receipt(source, installed, codex)
    _patch_install_shell(monkeypatch, module, source, has_claude=False)
    monkeypatch.setattr(module, "_install_codex_adapter", lambda *_a, **_k: receipt)
    monkeypatch.setattr(
        module, "_CODEX_INSTALL_READER_COMMAND_KIND", "FRONT_DOCTOR",
    )
    observed = []

    def reject_versions(paths):
        observed.append(dict(paths))
        raise RuntimeError("backend shim exited nonzero")

    monkeypatch.setattr(
        module, "_assert_managed_backend_version_postcondition",
        reject_versions,
    )

    assert module.run_install() == 1
    assert observed == [{
        "plamen_root": str(source),
        "paths": {
            "claude": source.parent / "plamen-claude",
            "codex": source.parent / "plamen-codex",
        },
        "selection": {"fixture": "signed-selection"},
    }]


def test_projection_authority_binds_persisted_generation_without_checkout_capability(
    monkeypatch, tmp_path,
):
    module = _load()
    source = tmp_path / "checkout"
    installed = tmp_path / ".plamen"
    codex = tmp_path / ".codex"
    receipt = _receipt(source, installed, codex)
    real_expand = module.os.path.expanduser
    monkeypatch.setattr(
        module.os.path, "expanduser",
        lambda value: (
            str(installed) if value == "~/.plamen" else
            str(codex) if value == "~/.codex" else real_expand(value)
        ),
    )
    monkeypatch.setattr(
        module, "_validated_committed_install_receipt", lambda: dict(receipt),
    )

    root, prior_roots, generation = module._committed_claude_projection_authority(
        dict(receipt), source,
    )
    assert root == os.path.normpath(str(installed.absolute()))
    assert prior_roots == (os.path.normpath(str(installed.absolute())),)
    assert generation["transaction_id"] == receipt["transaction_id"]
    assert generation["source_manifest_sha256"] == receipt["source_manifest_sha256"]
    assert generation["runtime_manifest_sha256"] == receipt["runtime_manifest_sha256"]
    assert generation["rows"] is receipt["rows"]


def test_projection_authority_rows_drive_run_without_physical_category_enumeration(
    monkeypatch, tmp_path,
):
    module = _load()
    source = tmp_path / "checkout"
    installed = tmp_path / ".plamen"
    codex = tmp_path / ".codex"
    claude = tmp_path / ".claude"
    for directory in (source, installed, codex, claude):
        directory.mkdir()
    runtime = installed / "scripts" / "plamen_driver.py"
    runtime.parent.mkdir()
    runtime.write_bytes(b"receipt-only\n")
    receipt = _receipt(source, installed, codex)
    receipt["runtime_count"] = 1
    receipt["source_count"] = 1
    receipt["adapter_count"] = 0
    authority, raw = module._codex_install_committed_descriptor(
        installed, ("scripts", "plamen_driver.py"), return_raw=True,
    )
    receipt["rows"] = [{
        "destination_root": "plamen",
        "destination_path": "scripts/plamen_driver.py",
        "destination": str(runtime),
        "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "terminal_authority": authority,
    }]
    real_expand = module.os.path.expanduser
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    monkeypatch.setattr(
        module.os.path, "expanduser",
        lambda value: (
            str(installed) if value == "~/.plamen" else
            str(codex) if value == "~/.codex" else real_expand(value)
        ),
    )
    monkeypatch.setattr(
        module, "_validated_committed_install_receipt", lambda: receipt,
    )
    root, prior_roots, generation = module._committed_claude_projection_authority(
        receipt, source,
    )
    captured = []

    class Transaction:
        def __init__(self, observed):
            assert observed is generation
            self.rows = []
            self.root = str(tmp_path / "transaction")

        def add_receipt_tree(
            self, observed_root, relative, destination, rows, _writer,
            **_kwargs,
        ):
            captured.append((observed_root, relative, destination, rows))
            return "copied_dir"

        def commit(self, validator):
            captured.append("commit")

        def add_projection_state(self):
            captured.append("state")

    # Projection follows the authenticated predecessor receipt denominator,
    # not the newer source module's current package denominator.
    monkeypatch.setattr(module, "_CODEX_INSTALL_RUNTIME_COUNT", 2)
    monkeypatch.setattr(module, "_ClaudeProjectionTransaction", Transaction)
    monkeypatch.setattr(
        module, "_toolchain_runtime_required_integrity_issues",
        lambda *_a, **_k: {"missing": [], "mismatched": []},
    )
    monkeypatch.setattr(module, "_toolchain_runtime_asset_rows", lambda *_a: [])
    monkeypatch.setattr(module, "_toolchain_runtime_required_files", lambda *_a: [])
    monkeypatch.setattr(module, "_render_claude_config_updates", lambda *_a, **_k: [])
    monkeypatch.setattr(module, "_render_install_manifest_updates", lambda **_k: [])
    module._run_symlink_install(
        lambda *_a: None, source_root=root,
        committed_generation=generation,
        authenticated_prior_roots=prior_roots,
    )
    assert captured[:-2] == [(
        root, "scripts", str(claude / "scripts"), generation["rows"],
    )]
    assert captured[-2] == "state"
    assert captured[-1] == "commit"


def test_manifest_records_and_preserves_committed_generation(monkeypatch, tmp_path):
    module = _load()
    checkout = tmp_path / "checkout"
    installed = tmp_path / ".plamen"
    claude = tmp_path / ".claude"
    codex = tmp_path / ".codex"
    for path in (checkout, installed, claude, codex):
        path.mkdir()
    generation = {
        "schema": module._CODEX_INSTALL_SCHEMA,
        "transaction_id": "a" * 32,
        "source_manifest_sha256": "b" * 64,
        "runtime_manifest_sha256": "c" * 64,
    }
    real_expand = module.os.path.expanduser
    monkeypatch.setattr(module, "PLAMEN_HOME", str(checkout))
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    monkeypatch.setattr(
        module.os.path, "expanduser",
        lambda value: str(codex) if value == "~/.codex" else real_expand(value),
    )
    monkeypatch.setattr(
        module, "_toolchain_runtime_bundle_sha256",
        lambda root, **_kwargs: hashlib.sha256(os.fspath(root).encode()).hexdigest(),
    )

    module._write_install_manifest(
        installed=[str(claude / "scripts")],
        package_root=installed,
        committed_generation=generation,
    )
    # The final version/shim-only stamp must not silently rebind the manifest
    # to the mutable checkout.
    module._write_install_manifest()

    manifest = json.loads((claude / module._PLAMEN_MANIFEST).read_text())
    assert manifest["plamen_home"] == os.path.normpath(str(installed))
    assert manifest["committed_generation"] == generation
    assert manifest["runtime_bundle_sha256"] == hashlib.sha256(
        os.fspath(installed).encode()
    ).hexdigest()


def test_runtime_integrity_reports_absence_and_digest_drift_separately(
    monkeypatch, tmp_path,
):
    module = _load()
    expected = hashlib.sha256(b"expected\n").hexdigest()
    monkeypatch.setattr(
        module, "_toolchain_runtime_required_files", lambda _root=None: ("a", "b"),
    )
    monkeypatch.setattr(
        module, "_toolchain_runtime_asset_rows",
        lambda _root=None: (
            {"path": "a", "digest_mode": "raw-v1", "sha256": expected},
            {"path": "b", "digest_mode": "raw-v1", "sha256": expected},
        ),
    )
    (tmp_path / "a").write_bytes(b"wrong\n")
    assert module._toolchain_runtime_required_integrity_issues(tmp_path) == {
        "missing": ["b"], "mismatched": [],
    }
    (tmp_path / "b").write_bytes(b"expected\n")
    assert module._toolchain_runtime_required_integrity_issues(tmp_path) == {
        "missing": [], "mismatched": ["a"],
    }


def test_committed_projection_reads_its_own_typed_closure(tmp_path):
    module = _load()
    closure_relative = "verification_policy/toolchain_runtime_closure.v1.json"
    asset_relative = "scripts/runtime.py"
    asset = tmp_path / "scripts" / "runtime.py"
    asset.parent.mkdir(parents=True)
    asset.write_bytes(b"runtime\n")
    closure = tmp_path / Path(closure_relative)
    closure.parent.mkdir(parents=True)
    closure.write_text(json.dumps({
        "schema": "plamen.toolchain-runtime-closure.v1",
        "manifest_control": {"kind": "control", "path": closure_relative},
        "files": [asset_relative, closure_relative],
        "assets": [{
            "digest_mode": "raw-v1",
            "kind": "python-source",
            "path": asset_relative,
            "sha256": hashlib.sha256(b"runtime\n").hexdigest(),
        }],
        "derivation": {},
        "entrypoints": [],
    }), encoding="utf-8")

    files, rows = module._toolchain_runtime_closure_from_root(tmp_path)
    assert files == (asset_relative, closure_relative)
    assert rows[0]["path"] == asset_relative


def test_committed_projection_rejects_an_untyped_closure_file(tmp_path):
    module = _load()
    closure_relative = "verification_policy/toolchain_runtime_closure.v1.json"
    asset_relative = "scripts/runtime.py"
    untyped_relative = "scripts/untyped.py"
    closure = tmp_path / Path(closure_relative)
    closure.parent.mkdir(parents=True)
    closure.write_text(json.dumps({
        "schema": "plamen.toolchain-runtime-closure.v1",
        "manifest_control": {"kind": "control", "path": closure_relative},
        "files": [asset_relative, untyped_relative, closure_relative],
        "assets": [{
            "digest_mode": "raw-v1",
            "kind": "python-source",
            "path": asset_relative,
            "sha256": hashlib.sha256(b"runtime\n").hexdigest(),
        }],
        "derivation": {},
        "entrypoints": [],
    }), encoding="utf-8")

    with pytest.raises(
        RuntimeError,
        match="installed runtime closure asset denominator differs",
    ):
        module._toolchain_runtime_closure_from_root(tmp_path)


def test_legacy_link_migration_never_deletes_either_source(monkeypatch, tmp_path):
    module = _load()
    prior = tmp_path / "checkout" / "rule.md"
    committed = tmp_path / ".plamen" / "rule.md"
    destination = tmp_path / ".claude" / "rule.md"
    for path, content in ((prior, "local work\n"), (committed, "committed\n")):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    destination.parent.mkdir()
    destination.symlink_to(prior)

    assert module._safe_link(
        str(committed), str(destination), lambda *_a: None,
        authenticated_prior_targets=(str(prior),),
    ) == "linked"
    assert destination.resolve() == committed.resolve()
    assert prior.read_text(encoding="utf-8") == "local work\n"
    assert committed.read_text(encoding="utf-8") == "committed\n"


@pytest.mark.parametrize(
    ("seam", "ordinal"),
    (
        ("after_projection_staged", None),
        ("before_projection_replace", 0),
        ("after_projection_backup", 0),
        ("after_projection_replace", 0),
        ("before_projection_replace", 1),
        ("after_projection_backup", 1),
        ("after_projection_replace", 1),
    ),
)
def test_projection_failure_at_every_live_seam_restores_exact_prior(
    monkeypatch, tmp_path, seam, ordinal,
):
    module = _load()
    claude = tmp_path / ".claude"
    claude.mkdir()
    first = claude / "settings.json"
    second = claude / "mcp.json"
    first.write_bytes(b"old-settings\n")
    second.write_bytes(b"old-mcp\n")
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))

    transaction = _transaction(monkeypatch, module, tmp_path)
    transaction.add_bytes(str(first), b"new-settings\n", kind="config")
    transaction.add_bytes(str(second), b"new-mcp\n", kind="config")

    def failpoint(name, row):
        if name == seam and (ordinal is None or row == ordinal):
            raise RuntimeError("injected seam")

    monkeypatch.setattr(module, "_CLAUDE_PROJECTION_FAILPOINT", failpoint)
    with pytest.raises(RuntimeError, match="injected seam"):
        transaction.commit()
    assert first.read_bytes() == b"old-settings\n"
    assert second.read_bytes() == b"old-mcp\n"
    assert not os.path.exists(module._claude_projection_journal_path())


def _persist_midrow_crash(module, transaction, destination):
    transaction._journal("COMMITTING")
    row = transaction.rows[0]
    os.makedirs(os.path.dirname(row["backup"]), exist_ok=True)
    os.replace(destination, row["backup"])
    os.replace(row["staged"], destination)
    return row


def test_next_install_recovers_persisted_midrow_crash(monkeypatch, tmp_path):
    module = _load()
    claude = tmp_path / ".claude"
    claude.mkdir()
    destination = claude / "CLAUDE.md"
    destination.write_bytes(b"old\n")
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    transaction = _transaction(monkeypatch, module, tmp_path)
    transaction.add_bytes(str(destination), b"new\n", kind="config")
    _persist_midrow_crash(module, transaction, str(destination))

    assert destination.read_bytes() == b"new\n"
    assert module._claude_projection_pending()
    assert module._recover_claude_projection_transaction() is True
    assert destination.read_bytes() == b"old\n"
    assert not module._claude_projection_pending()


def test_run_install_recovers_signed_pending_projection_before_install_work(
    monkeypatch, tmp_path,
):
    module = _load()
    claude = tmp_path / ".claude"
    claude.mkdir()
    destination = claude / "CLAUDE.md"
    destination.write_bytes(b"old\n")
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    transaction = _transaction(monkeypatch, module, tmp_path)
    transaction.add_bytes(str(destination), b"new\n", kind="config")
    _persist_midrow_crash(module, transaction, str(destination))
    assert destination.read_bytes() == b"new\n"

    monkeypatch.setattr(module, "PLAMEN_HOME", str(tmp_path / "source-authority"))
    monkeypatch.setattr(
        module, "_toolchain_runtime_required_integrity_issues",
        lambda _root, **_kwargs: {"missing": [], "mismatched": []},
    )
    monkeypatch.setattr(
        module, "_claude_projection_incomplete_legacy_migration", lambda: None,
    )
    monkeypatch.setattr(module, "_go_bin_dir", lambda: None)
    monkeypatch.setattr(module, "_update_path_env", lambda *_a, **_k: None)

    class RecoveredStop(RuntimeError):
        pass

    monkeypatch.setattr(
        module, "_report_toolchain_visibility",
        lambda _w: (_ for _ in ()).throw(RecoveredStop("after recovery")),
    )
    monkeypatch.setattr(module.sys, "argv", ["plamen", "install"])
    with pytest.raises(RecoveredStop, match="after recovery"):
        module.run_install()
    assert destination.read_bytes() == b"old\n"
    assert not module._claude_projection_pending()


def test_recovery_refuses_foreign_third_state_and_keeps_backup(
    monkeypatch, tmp_path,
):
    module = _load()
    claude = tmp_path / ".claude"
    claude.mkdir()
    destination = claude / "settings.json"
    destination.write_bytes(b"old\n")
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    transaction = _transaction(monkeypatch, module, tmp_path)
    transaction.add_bytes(str(destination), b"new\n", kind="config")
    row = _persist_midrow_crash(module, transaction, str(destination))
    destination.write_bytes(b"foreign\n")

    with pytest.raises(RuntimeError, match="foreign destination bytes"):
        module._recover_claude_projection_transaction()
    assert destination.read_bytes() == b"foreign\n"
    assert os.path.exists(row["backup"])
    assert module._claude_projection_pending()


def test_public_use_refuses_pending_projection(monkeypatch, tmp_path):
    module = _load()
    claude = tmp_path / ".claude"
    claude.mkdir()
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    transaction = _transaction(monkeypatch, module, tmp_path)
    transaction._journal("PREPARED")

    with pytest.raises(RuntimeError, match="run `plamen install`"):
        module._refuse_pending_claude_projection()


def test_public_projection_preflight_bypasses_only_authenticated_borrowed_smoke(
    monkeypatch,
):
    module = _load()
    calls = []
    monkeypatch.setattr(
        module, "_refuse_pending_claude_projection", lambda: calls.append("gate"),
    )

    # Ordinary installed/source use still runs the public gate.
    monkeypatch.setattr(module, "_CODEX_INSTALL_READER", None)
    monkeypatch.setattr(module, "_CODEX_INSTALL_READER_COMMAND_KIND", None)
    module._enforce_public_claude_projection_preflight()
    assert calls == ["gate"]

    # A command-kind string by itself is not authority.
    monkeypatch.setattr(
        module, "_CODEX_INSTALL_READER_COMMAND_KIND", "FRONT_VERSION",
    )
    module._enforce_public_claude_projection_preflight()
    assert calls == ["gate", "gate"]

    # Even with a retained reader, an unrecognized kind fails closed.
    monkeypatch.setattr(module, "_CODEX_INSTALL_READER", object())
    monkeypatch.setattr(
        module, "_CODEX_INSTALL_READER_COMMAND_KIND", "FOREIGN_COMMAND",
    )
    module._enforce_public_claude_projection_preflight()
    assert calls == ["gate", "gate", "gate"]

    # Even a recognized string plus an arbitrary reader cannot bypass.
    monkeypatch.setattr(
        module, "_CODEX_INSTALL_READER_COMMAND_KIND", "FRONT_VERSION",
    )
    module._enforce_public_claude_projection_preflight()
    assert calls == ["gate", "gate", "gate", "gate"]

    # The opaque admission replayer is the sole bypass boundary.
    monkeypatch.setattr(
        module, "_has_admitted_install_command", lambda *_kinds: True,
    )
    module._enforce_public_claude_projection_preflight()
    assert calls == ["gate", "gate", "gate", "gate"]


def test_main_borrowed_smoke_does_not_reopen_public_projection_gate(monkeypatch):
    module = _load()
    monkeypatch.setattr(module.sys, "argv", ["plamen.py", "doctor"])
    monkeypatch.setattr(module, "_CODEX_INSTALL_READER", object())
    monkeypatch.setattr(
        module, "_CODEX_INSTALL_READER_COMMAND_KIND", "FRONT_DOCTOR",
    )
    monkeypatch.setattr(
        module, "_has_admitted_install_command",
        lambda *kinds: "FRONT_DOCTOR" in kinds,
    )
    monkeypatch.setattr(module, "run_doctor", lambda: 0)
    monkeypatch.setattr(
        module,
        "_refuse_pending_claude_projection",
        lambda: (_ for _ in ()).throw(AssertionError("public gate reopened")),
    )

    with pytest.raises(SystemExit) as exit_info:
        module.main()
    assert exit_info.value.code == 0


def test_borrowed_doctor_defers_only_claude_projection_checks(monkeypatch):
    module = _load()
    monkeypatch.setattr(module, "_CODEX_INSTALL_READER", object())
    monkeypatch.setattr(
        module, "_CODEX_INSTALL_READER_COMMAND_KIND", "FRONT_DOCTOR",
    )
    monkeypatch.setattr(
        module, "_has_admitted_install_command",
        lambda *kinds: "FRONT_DOCTOR" in kinds,
    )
    monkeypatch.setattr(module, "show_banner", lambda: None)
    monkeypatch.setattr(module.console, "print", lambda *_a, **_k: None)
    monkeypatch.setattr(
        module, "_claude_projection_pending",
        lambda: (_ for _ in ()).throw(AssertionError("projection probe reopened")),
    )
    monkeypatch.setattr(
        module, "_claude_projection_state_path",
        lambda: (_ for _ in ()).throw(AssertionError("projection path probed")),
    )
    # Stop immediately after the deferred projection boundary; the remaining
    # doctor matrix has its own focused tests and is not the subject here.
    monkeypatch.setattr(
        module, "_installed_runtime_root",
        lambda: (_ for _ in ()).throw(RuntimeError("after projection boundary")),
    )

    with pytest.raises(RuntimeError, match="after projection boundary"):
        module.run_doctor()


def test_main_codex_only_install_never_consults_claude_projection(monkeypatch):
    module = _load()
    monkeypatch.setattr(
        module.sys, "argv", ["plamen.py", "install", "--codex"],
    )
    monkeypatch.setattr(module, "show_banner", lambda: None)
    monkeypatch.setattr(module.console, "print", lambda *_a, **_k: None)
    calls = []
    monkeypatch.setattr(
        module, "_install_codex_adapter",
        lambda *_a, **_k: calls.append("adapter") or {"state": "COMMITTED"},
    )
    monkeypatch.setattr(
        module,
        "_refuse_pending_claude_projection",
        lambda: (_ for _ in ()).throw(AssertionError("Claude state consulted")),
    )

    module.main()
    assert calls == ["adapter"]


def test_main_codex_recovery_never_consults_claude_projection(monkeypatch):
    module = _load()
    transaction_id = "a" * 32
    monkeypatch.setattr(
        module.sys,
        "argv",
        ["plamen.py", "--recover-codex-install", transaction_id],
    )
    calls = []
    monkeypatch.setattr(
        module, "_recover_codex_package_transaction",
        lambda value: calls.append(value) or {"transaction_id": value},
    )
    monkeypatch.setattr(
        module,
        "_refuse_pending_claude_projection",
        lambda: (_ for _ in ()).throw(AssertionError("Claude state consulted")),
    )

    module.main()
    assert calls == [transaction_id]


def test_dangling_cleanup_is_staged_and_reversible(monkeypatch, tmp_path):
    module = _load()
    claude = tmp_path / ".claude"
    agents = claude / "agents"
    agents.mkdir(parents=True)
    prior_root = None
    destination = agents / "retired-agent.md"
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))

    transaction = _transaction(monkeypatch, module, tmp_path)
    prior_root = Path(transaction.authority["plamen_root"])
    missing_target = prior_root / "retired-agent.md"
    destination.symlink_to(missing_target)
    module._stage_dangling_plamen_link_cleanup(
        str(agents), transaction, lambda *_a: None,
        authenticated_roots=(str(prior_root),),
    )
    assert destination.is_symlink()
    assert transaction.rows[0]["successor"] == {"kind": "absent"}

    def fail_after_backup(name, row):
        if name == "after_projection_backup" and row == 0:
            raise RuntimeError("injected cleanup seam")

    monkeypatch.setattr(module, "_CLAUDE_PROJECTION_FAILPOINT", fail_after_backup)
    with pytest.raises(RuntimeError, match="injected cleanup seam"):
        transaction.commit()
    assert destination.is_symlink()
    assert os.path.normcase(os.path.realpath(destination)) == os.path.normcase(
        os.path.realpath(missing_target)
    )

    monkeypatch.setattr(module, "_CLAUDE_PROJECTION_FAILPOINT", None)
    transaction = _transaction(monkeypatch, module, tmp_path)
    module._stage_dangling_plamen_link_cleanup(
        str(agents), transaction, lambda *_a: None,
        authenticated_roots=(str(prior_root),),
    )
    transaction.commit()
    assert not os.path.lexists(destination)


def test_committed_mcp_runtime_is_verify_only(monkeypatch, tmp_path):
    module = _load()
    mcp = tmp_path / "committed" / "mcp-packages"
    mcp.mkdir(parents=True)
    (mcp / "package.json").write_text("{}", encoding="utf-8")
    (mcp / "package-lock.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(module, "_validate_mcp_lock", lambda *_a: (True, "a" * 64))
    monkeypatch.setattr(module, "_mcp_node_modules_valid", lambda *_a, **_k: False)
    monkeypatch.setattr(
        module.shutil, "which",
        lambda *_a: (_ for _ in ()).throw(AssertionError("npm must not run")),
    )

    assert module._setup_mcp_packages(
        lambda *_a: None,
        mcp_root=str(tmp_path / "committed"),
        update_claude=False,
        allow_materialization=False,
    ) is False
    assert not (mcp / "node_modules").exists()


@pytest.mark.parametrize(
    "mutation",
    ("outside", "inside", "root", "extended", "extra", "reordered", "removed"),
)
def test_signed_journal_rejects_path_and_row_forgery_without_changes(
    monkeypatch, tmp_path, mutation,
):
    module = _load()
    claude = tmp_path / ".claude"
    claude.mkdir()
    destination = claude / "settings.json"
    destination.write_bytes(b"old\n")
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    transaction = _transaction(monkeypatch, module, tmp_path)
    transaction.add_bytes(str(destination), b"new\n", kind="config")
    transaction.add_bytes(str(claude / "mcp.json"), b"new-mcp\n", kind="config")
    transaction._journal("PREPARED")
    journal_path = Path(module._claude_projection_journal_path())
    value = json.loads(journal_path.read_text(encoding="utf-8"))
    if mutation == "outside":
        value["rows"][0]["destination"] = str(tmp_path / "outside.txt")
    elif mutation == "inside":
        value["rows"][0]["destination"] = str(claude / "arbitrary-user-file")
    elif mutation == "root":
        value["rows"][0]["destination"] = str(claude)
    elif mutation == "extended":
        value["rows"][0]["destination"] = "\\\\?\\" + str(destination)
    elif mutation == "extra":
        value["rows"].append(dict(value["rows"][0]))
    elif mutation == "reordered":
        value["rows"].reverse()
    else:
        value["rows"].pop()
    journal_path.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(RuntimeError):
        module._recover_claude_projection_transaction()
    assert destination.read_bytes() == b"old\n"


def test_signed_zero_live_journal_cleans_after_generation_advance(
    monkeypatch, tmp_path,
):
    module = _load()
    claude = tmp_path / ".claude"
    claude.mkdir()
    destination = claude / "settings.json"
    destination.write_bytes(b"old\n")
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    transaction = _transaction(monkeypatch, module, tmp_path)
    transaction.add_bytes(str(destination), b"new\n", kind="config")
    transaction._journal("PREPARED")
    replayed = dict(transaction.authority)
    replayed["transaction_id"] = "9" * 32
    monkeypatch.setattr(module, "_validated_committed_install_receipt", lambda: replayed)

    assert module._recover_claude_projection_transaction() is True
    assert destination.read_bytes() == b"old\n"
    assert not module._claude_projection_pending()


def test_private_key_deletion_does_not_block_signed_recovery(monkeypatch, tmp_path):
    module = _load()
    claude = tmp_path / ".claude"
    claude.mkdir()
    destination = claude / "settings.json"
    destination.write_bytes(b"old\n")
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    transaction = _transaction(monkeypatch, module, tmp_path)
    transaction.add_bytes(str(destination), b"new\n", kind="config")
    _persist_midrow_crash(module, transaction, str(destination))
    os.remove(module._claude_projection_key_path())
    module._CLAUDE_PROJECTION_PRIVATE_KEY = None

    assert module._recover_claude_projection_transaction() is True
    assert destination.read_bytes() == b"old\n"


def test_private_key_substitution_cannot_sign_for_committed_generation(
    monkeypatch, tmp_path,
):
    module = _load()
    claude = tmp_path / ".claude"
    claude.mkdir()
    destination = claude / "settings.json"
    destination.write_bytes(b"old\n")
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    transaction = _transaction(monkeypatch, module, tmp_path)
    transaction.add_bytes(str(destination), b"new\n", kind="config")
    _persist_midrow_crash(module, transaction, str(destination))
    key_path = Path(module._claude_projection_key_path())
    key_path.unlink()
    module._CLAUDE_PROJECTION_PRIVATE_KEY = None
    module._claude_projection_private_key(create=True)

    assert module._recover_claude_projection_transaction() is True
    assert destination.read_bytes() == b"old\n"
    with pytest.raises(RuntimeError, match="differs from committed authority"):
        module._ClaudeProjectionTransaction(transaction.authority)


def test_projection_recovery_rejects_symlink_ancestor(monkeypatch, tmp_path):
    module = _load()
    claude = tmp_path / ".claude"
    claude.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    transaction = _transaction(monkeypatch, module, tmp_path)
    source = Path(transaction.authority["plamen_root"]) / "agents" / "new.md"
    source.parent.mkdir(); source.write_bytes(b"agent\n")
    transaction.add_bytes(
        str(claude / "agents" / "new.md"), b"agent\n", kind="projection",
    )
    transaction._journal("PREPARED")
    (claude / "agents").symlink_to(outside, target_is_directory=True)

    with pytest.raises(RuntimeError, match="reparse link"):
        module._recover_claude_projection_transaction()
    assert list(outside.iterdir()) == []


def test_signed_staging_intent_precedes_root_and_cleans_after_hard_stop(
    monkeypatch, tmp_path,
):
    module = _load()
    claude = tmp_path / ".claude"
    claude.mkdir()
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))

    def stop_after_intent(name, _row):
        if name == "after_projection_staging_intent":
            raise RuntimeError("hard stop")

    monkeypatch.setattr(module, "_CLAUDE_PROJECTION_FAILPOINT", stop_after_intent)
    with pytest.raises(RuntimeError, match="hard stop"):
        _transaction(monkeypatch, module, tmp_path)
    journal_path = Path(module._claude_projection_journal_path())
    value = json.loads(journal_path.read_text(encoding="utf-8"))
    assert value["state"] == "STAGING"
    assert not Path(value["root"]).exists()
    monkeypatch.setattr(module, "_CLAUDE_PROJECTION_FAILPOINT", None)
    assert module._recover_claude_projection_transaction() is True
    assert not journal_path.exists()


def test_staging_recovery_removes_config_shadow_and_never_journals_secret(
    monkeypatch, tmp_path,
):
    module = _load()
    claude = tmp_path / ".claude"
    claude.mkdir()
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    transaction = _transaction(monkeypatch, module, tmp_path)
    shadow = Path(transaction.root) / "config-shadow-test"
    shadow.mkdir()
    secret = "API_KEY=do-not-persist"
    (shadow / "settings.json").write_text(secret, encoding="utf-8")
    journal_raw = Path(module._claude_projection_journal_path()).read_text(encoding="utf-8")
    assert secret not in journal_raw

    assert module._recover_claude_projection_transaction() is True
    assert not Path(transaction.root).exists()


@pytest.mark.parametrize("foreign", ("empty", "nonempty", "marker"))
def test_foreign_directory_race_is_never_deleted(monkeypatch, tmp_path, foreign):
    module = _load()
    claude = tmp_path / ".claude"
    claude.mkdir()
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    transaction = _transaction(monkeypatch, module, tmp_path)
    source = Path(transaction.authority["plamen_root"]) / "agents" / "new.md"
    source.parent.mkdir(); source.write_bytes(b"agent\n")
    destination = claude / "agents" / "new.md"
    transaction.add_bytes(str(destination), b"agent\n", kind="projection")

    def race(name, _row):
        if name != "before_projection_directory_publish":
            return
        parent = destination.parent
        parent.mkdir()
        if foreign == "nonempty":
            (parent / "user.txt").write_bytes(b"user\n")
        elif foreign == "marker":
            (parent / (".plamen-created-" + transaction.transaction_id)).write_text(
                transaction.transaction_id + "\n", encoding="ascii",
            )

    monkeypatch.setattr(module, "_CLAUDE_PROJECTION_FAILPOINT", race)
    with pytest.raises(RuntimeError):
        transaction.commit()
    assert destination.parent.exists()
    if foreign == "nonempty":
        assert (destination.parent / "user.txt").read_bytes() == b"user\n"


def test_generation_switch_before_mutation_and_before_commit_rolls_back(
    monkeypatch, tmp_path,
):
    module = _load()
    claude = tmp_path / ".claude"
    claude.mkdir()
    destination = claude / "settings.json"
    destination.write_bytes(b"old\n")
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    transaction = _transaction(monkeypatch, module, tmp_path)
    generation_a = dict(transaction.authority)
    generation_b = dict(generation_a); generation_b["transaction_id"] = "8" * 32
    current = {"value": generation_a}
    monkeypatch.setattr(
        module, "_validated_committed_install_receipt", lambda: current["value"],
    )
    transaction.add_bytes(str(destination), b"new\n", kind="config")

    def switch_before_replace(name, row):
        if name == "before_projection_replace" and row == 0:
            current["value"] = generation_b

    monkeypatch.setattr(module, "_CLAUDE_PROJECTION_FAILPOINT", switch_before_replace)
    with pytest.raises(RuntimeError, match="generation changed"):
        transaction.commit()
    assert destination.read_bytes() == b"old\n"

    current["value"] = generation_a
    monkeypatch.setattr(module, "_CLAUDE_PROJECTION_FAILPOINT", None)
    transaction = _transaction(monkeypatch, module, tmp_path)
    monkeypatch.setattr(
        module, "_validated_committed_install_receipt", lambda: current["value"],
    )
    transaction.add_bytes(str(destination), b"new\n", kind="config")

    def validator_switch():
        current["value"] = generation_b

    with pytest.raises(RuntimeError, match="generation changed"):
        transaction.commit(validator=validator_switch)
    assert destination.read_bytes() == b"old\n"


def test_projection_lock_refuses_victim_hardlink_without_writing(
    monkeypatch, tmp_path,
):
    module = _load()
    claude = tmp_path / ".claude"
    claude.mkdir()
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    transaction = _transaction(monkeypatch, module, tmp_path)
    assert transaction is not None
    module._recover_claude_projection_transaction()
    lock_path = claude / ".plamen-projection.lock"
    lock_path.unlink()
    victim = tmp_path / "victim.txt"
    victim.write_bytes(b"victim-unchanged\n")
    os.link(victim, lock_path)

    with pytest.raises(RuntimeError, match="lock identity differs"):
        with module._claude_projection_lock():
            pass
    assert victim.read_bytes() == b"victim-unchanged\n"


def test_projection_lock_detects_named_path_split_inode(monkeypatch, tmp_path):
    module = _load()
    claude = tmp_path / ".claude"
    claude.mkdir()
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    transaction = _transaction(monkeypatch, module, tmp_path)
    module._recover_claude_projection_transaction()
    lock_path = claude / ".plamen-projection.lock"
    real_stat = module.os.stat
    hits = {"count": 0}

    def drifting_stat(path, *args, **kwargs):
        observed = real_stat(path, *args, **kwargs)
        if os.path.normcase(os.path.abspath(os.fspath(path))) == os.path.normcase(
            os.path.abspath(lock_path)
        ):
            hits["count"] += 1
            if hits["count"] >= 3:
                values = list(observed)
                values[1] += 1
                return os.stat_result(values)
        return observed

    monkeypatch.setattr(module.os, "stat", drifting_stat)
    with pytest.raises(RuntimeError, match="replaced|replacement|identity|split-inode"):
        with module._claude_projection_lock():
            pass


@pytest.mark.parametrize(
    "seam",
    (
        "before_projection_directory_publish",
        "after_projection_directory_publish",
    ),
)
def test_missing_parent_crash_seams_leave_no_orphan(
    monkeypatch, tmp_path, seam,
):
    module = _load()
    claude = tmp_path / ".claude"
    claude.mkdir()
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    transaction = _transaction(monkeypatch, module, tmp_path)
    source = Path(transaction.authority["plamen_root"]) / "agents" / "new.md"
    source.parent.mkdir(); source.write_bytes(b"agent\n")
    destination = claude / "agents" / "new.md"
    transaction.add_bytes(str(destination), b"agent\n", kind="projection")

    def failpoint(name, _row):
        if name == seam:
            raise RuntimeError("directory crash")

    monkeypatch.setattr(module, "_CLAUDE_PROJECTION_FAILPOINT", failpoint)
    with pytest.raises(RuntimeError, match="directory crash"):
        transaction.commit()
    assert not (claude / "agents").exists()
    assert not module._claude_projection_pending()


def test_committed_closure_verification_ignores_mutated_checkout(
    monkeypatch, tmp_path,
):
    module = _load()
    committed = tmp_path / ".plamen"
    checkout = tmp_path / "checkout"
    for root, raw in ((committed, b"committed\n"), (checkout, b"checkout\n")):
        asset = root / "scripts" / "runtime.py"
        asset.parent.mkdir(parents=True)
        asset.write_bytes(raw)
        closure = root / "verification_policy" / "toolchain_runtime_closure.v1.json"
        closure.parent.mkdir(parents=True)
        closure.write_text(json.dumps({
            "schema": "plamen.toolchain-runtime-closure.v1",
            "manifest_control": {
                "kind": "control",
                "path": "verification_policy/toolchain_runtime_closure.v1.json",
            },
            "files": [
                "scripts/runtime.py",
                "verification_policy/toolchain_runtime_closure.v1.json",
            ],
            "assets": [{
                "digest_mode": "raw-v1", "kind": "python-source",
                "path": "scripts/runtime.py",
                "sha256": hashlib.sha256(raw).hexdigest(),
            }],
            "derivation": {}, "entrypoints": [],
        }), encoding="utf-8")
    monkeypatch.setattr(module, "PLAMEN_HOME", str(checkout))

    issues = module._toolchain_runtime_required_integrity_issues(
        committed, closure_root=committed,
    )
    assert issues == {"missing": [], "mismatched": []}
    (checkout / "verification_policy" / "toolchain_runtime_closure.v1.json").write_text(
        "{}", encoding="utf-8",
    )
    assert module._toolchain_runtime_required_integrity_issues(
        committed, closure_root=committed,
    ) == {"missing": [], "mismatched": []}


def test_invalid_source_preflight_has_zero_filesystem_mutation(monkeypatch, tmp_path):
    module = _load()
    source = tmp_path / "checkout"
    source.mkdir()
    claude = tmp_path / "pristine-claude"
    state = tmp_path / "pristine-state"
    monkeypatch.setattr(module, "PLAMEN_HOME", str(source))
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    monkeypatch.setattr(
        module, "_claude_projection_key_path",
        lambda *_a: str(state / "projection-key.json"),
    )
    monkeypatch.setattr(
        module, "_toolchain_runtime_required_integrity_issues",
        lambda root, **_k: {"missing": ["invalid"], "mismatched": []},
    )
    monkeypatch.setattr(
        module, "_validated_committed_install_receipt",
        lambda: (_ for _ in ()).throw(RuntimeError("no installed receipt")),
    )
    before = sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*"))
    assert module.run_install() == 1
    after = sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*"))
    assert after == before
    assert not claude.exists()
    assert not state.exists()


def test_generation_advance_before_commit_lease_cleans_zero_live_state(
    monkeypatch, tmp_path,
):
    module = _load()
    claude = tmp_path / ".claude"
    claude.mkdir()
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    transaction = _transaction(monkeypatch, module, tmp_path)
    old = claude / "settings.json"
    old.write_bytes(b"old\n")
    transaction.add_bytes(str(old), b"new\n", kind="config")
    generation_b = dict(transaction.authority)
    generation_b["transaction_id"] = "b" * 32
    monkeypatch.setattr(
        module, "_validated_committed_install_receipt", lambda: generation_b,
    )
    monkeypatch.setattr(
        module, "_open_install_admission_anchor",
        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("generation changed")),
    )
    with pytest.raises(RuntimeError, match="generation changed"):
        transaction.commit()
    assert old.read_bytes() == b"old\n"
    assert not module._claude_projection_pending()
    assert not Path(transaction.root).exists()


@pytest.mark.parametrize(
    "seam", ("before_projection_root_publish", "after_projection_root_publish"),
)
def test_root_atomic_publish_crash_recovers_exact_owned_staging(
    monkeypatch, tmp_path, seam,
):
    module = _load()
    claude = tmp_path / ".claude"
    claude.mkdir()
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))

    def stop(name, _row):
        if name == seam:
            raise RuntimeError("root publish crash")

    monkeypatch.setattr(module, "_CLAUDE_PROJECTION_FAILPOINT", stop)
    with pytest.raises(RuntimeError, match="root publish crash"):
        _transaction(monkeypatch, module, tmp_path)
    monkeypatch.setattr(module, "_CLAUDE_PROJECTION_FAILPOINT", None)
    assert module._recover_claude_projection_transaction() is True
    assert not module._claude_projection_pending()
    transaction_container = claude / ".plamen-projection-transactions"
    assert not list(transaction_container.iterdir())


def test_projection_remove_and_noreplace_primitives(monkeypatch, tmp_path):
    module = _load()
    regular = tmp_path / "regular"
    regular.write_bytes(b"x")
    directory = tmp_path / "directory"
    directory.mkdir(); (directory / "inside").write_bytes(b"x")
    target = tmp_path / "target"
    target.write_bytes(b"target")
    link = tmp_path / "link"
    try:
        link.symlink_to(target)
    except OSError:
        link = None
    module._claude_projection_remove(str(regular))
    module._claude_projection_remove(str(directory))
    if link is not None:
        module._claude_projection_remove(str(link))
    assert not regular.exists() and not directory.exists()
    assert target.read_bytes() == b"target"
    source = tmp_path / "source"
    source.write_bytes(b"source")
    destination = tmp_path / "destination"
    destination.write_bytes(b"foreign")
    with pytest.raises(FileExistsError):
        module._claude_projection_rename_noreplace(str(source), str(destination))
    assert source.read_bytes() == b"source"
    assert destination.read_bytes() == b"foreign"


def test_linux_and_darwin_native_identity_paths_without_external_tools(
    monkeypatch, tmp_path,
):
    module = _load()
    monkeypatch.setattr(module.sys, "platform", "linux")
    monkeypatch.setattr(
        module.os, "stat", lambda path, **_k: SimpleNamespace(st_ctime_ns=123400),
    )
    assert module._posix_process_started_100ns(17) == 1234

    import ctypes
    real_cdll = ctypes.CDLL

    class _Call:
        def __call__(self, pid, _flavor, _arg, pointer, size):
            pointer._obj.pbi_pid = pid
            pointer._obj.pbi_start_tvsec = 11
            pointer._obj.pbi_start_tvusec = 22
            return size

    monkeypatch.setattr(module.sys, "platform", "darwin")
    monkeypatch.setattr(ctypes, "CDLL", lambda *_a, **_k: SimpleNamespace(proc_pidinfo=_Call()))
    try:
        assert module._posix_process_started_100ns(19) == 110000220
    finally:
        monkeypatch.setattr(ctypes, "CDLL", real_cdll)


def test_generation_independent_lock_survives_k1_to_k2_key_rotation(
    monkeypatch, tmp_path,
):
    module = _load()
    claude = tmp_path / ".claude"
    claude.mkdir()
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    transaction_a = _transaction(monkeypatch, module, tmp_path)
    module._recover_claude_projection_transaction()
    lock_payload = json.loads(
        (claude / ".plamen-projection.lock").read_text(encoding="utf-8")
    )
    k1 = lock_payload["public_key"]
    key_path = Path(module._claude_projection_key_path())
    key_path.unlink()
    module._CLAUDE_PROJECTION_PRIVATE_KEY = None
    _private_k2, k2 = module._claude_projection_private_key(create=True)
    assert k2 != k1
    generation_b = dict(transaction_a.authority)
    generation_b["transaction_id"] = "c" * 32
    generation_b["projection_public_key"] = k2
    generation_b["terminal_verification"] = {
        "projection_public_key": k2,
        "projection_lock_public_key": k1,
    }
    monkeypatch.setattr(
        module, "_validated_committed_install_receipt", lambda: generation_b,
    )
    with module._claude_projection_lock(create=False):
        pass
    transaction_b = module._ClaudeProjectionTransaction(generation_b)
    assert transaction_b.authority["projection_public_key"] == k2
    assert json.loads(
        (claude / ".plamen-projection.lock").read_text(encoding="utf-8")
    )["public_key"] == k1
    assert module._recover_claude_projection_transaction() is True


def test_direct_codex_package_invalid_source_mutates_nothing(monkeypatch, tmp_path):
    module = _load()
    source = tmp_path / "invalid-source"
    source.mkdir()
    installed = tmp_path / "installed"
    codex = tmp_path / "codex"
    state = tmp_path / "state"
    monkeypatch.setattr(
        module, "_claude_projection_key_path",
        lambda *_a: str(state / "projection-key.json"),
    )
    monkeypatch.setattr(
        module, "_toolchain_runtime_required_integrity_issues",
        lambda *_a, **_k: {"missing": ["closure"], "mismatched": []},
    )
    with pytest.raises(RuntimeError, match="source closure is not exact"):
        module._install_codex_package_transaction(
            source_root=source, plamen_root=installed, codex_home=codex,
        )
    assert not installed.exists()
    assert not codex.exists()
    assert not state.exists()


def test_public_codex_only_adapter_disables_claude_key_authority(
    monkeypatch, tmp_path,
):
    module = _load()
    source = tmp_path / "source"
    source.mkdir()
    installed = tmp_path / "installed"
    observed = []
    receipt = {
        "plamen_root": str(installed), "codex_root": str(tmp_path / "codex"),
        "source_count": 759, "transaction_id": "d" * 32,
    }
    monkeypatch.setattr(module, "PLAMEN_HOME", str(source))
    monkeypatch.setattr(module.sys, "argv", ["plamen.py", "install", "--codex"])
    monkeypatch.setattr(
        module, "_install_codex_package_transaction",
        lambda **kwargs: observed.append(kwargs) or receipt,
    )
    monkeypatch.setattr(module, "_sync_codex_adapter_source_cache", lambda _r: 0)
    monkeypatch.setattr(module, "_setup_mcp_packages", lambda *_a, **_k: True)
    monkeypatch.setattr(module, "_merge_codex_mcp_toml", lambda *_a, **_k: True)
    monkeypatch.setattr(module, "_ensure_windows_plamen_command", lambda **_k: None)
    assert module._install_codex_adapter(lambda _text: None, return_receipt=True) == receipt
    assert observed == [{"enable_claude_projection": False}]


def test_public_codex_only_ignores_out_of_scope_claude_projection_journal(
    monkeypatch, tmp_path,
):
    module = _load()
    claude = tmp_path / ".claude"
    claude.mkdir()
    (claude / ".plamen-projection-transaction.json").write_text(
        "pending", encoding="ascii",
    )
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    monkeypatch.setattr(module.sys, "argv", ["plamen.py", "install", "--codex"])
    calls = []
    monkeypatch.setattr(
        module, "_install_codex_adapter",
        lambda *_a, **_k: calls.append("adapter") or True,
    )
    monkeypatch.setattr(
        module, "_refuse_pending_claude_projection",
        lambda: (_ for _ in ()).throw(AssertionError("Claude state consulted")),
    )
    module.main()
    assert calls == ["adapter"]


@pytest.mark.parametrize("kind", ("key", "journal"))
def test_projection_partial_fsync_leaves_no_published_or_temp_file(
    monkeypatch, tmp_path, kind,
):
    module = _load()
    destination = tmp_path / ("key.json" if kind == "key" else "journal.json")
    monkeypatch.setattr(
        module.os, "fsync",
        lambda _fd: (_ for _ in ()).throw(OSError("fsync failure")),
    )
    with pytest.raises(OSError, match="fsync failure"):
        if kind == "key":
            module._claude_projection_publish_bytes_noreplace(
                str(destination), b"candidate\n",
            )
        else:
            module._claude_projection_atomic_json(
                str(destination), {"candidate": True},
            )
    assert not destination.exists()
    assert list(tmp_path.iterdir()) == []


def test_windows_projection_journal_replace_retries_transient_error_with_same_temp(
    monkeypatch, tmp_path,
):
    module = _load()
    import ctypes

    destination = tmp_path / "journal.json"
    destination.write_bytes(b"prior\n")
    calls = []
    sleeps = []

    class Function:
        restype = None

        def __call__(self, source, target, flags):
            calls.append((source.value, target.value, flags.value))
            if len(calls) == 1:
                return 0
            os.replace(source.value, target.value)
            return 1

    class Kernel:
        MoveFileExW = Function()

    monkeypatch.setattr(module.os, "name", "nt")
    monkeypatch.setattr(ctypes, "WinDLL", lambda *_a, **_k: Kernel())
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 32, raising=False)
    monkeypatch.setattr(module.time, "sleep", sleeps.append)

    module._claude_projection_atomic_json(
        str(destination), {"state": "PREPARED"},
    )

    assert len(calls) == 2
    assert calls[0][0] == calls[1][0]
    assert calls[0][1:] == calls[1][1:]
    assert calls[0][2] == 0x00000001 | 0x00000008
    assert sleeps == [0.01]
    assert json.loads(destination.read_text(encoding="utf-8")) == {
        "state": "PREPARED",
    }
    assert not list(tmp_path.glob(".projection-journal-*"))


def test_windows_projection_journal_replace_transient_exhaustion_fails_closed(
    monkeypatch, tmp_path,
):
    module = _load()
    import ctypes

    destination = tmp_path / "journal.json"
    destination.write_bytes(b"prior\n")
    calls = []
    sleeps = []

    class Function:
        restype = None

        def __call__(self, *_args):
            calls.append("move")
            return 0

    class Kernel:
        MoveFileExW = Function()

    monkeypatch.setattr(module.os, "name", "nt")
    monkeypatch.setattr(ctypes, "WinDLL", lambda *_a, **_k: Kernel())
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 5, raising=False)
    monkeypatch.setattr(module.time, "sleep", sleeps.append)

    with pytest.raises(OSError, match="durable journal replace failed") as caught:
        module._claude_projection_atomic_json(
            str(destination), {"state": "PREPARED"},
        )

    assert caught.value.errno == 5
    assert len(calls) == 9
    assert sleeps == [0.01, 0.02, 0.04, 0.08, 0.16, 0.25, 0.25, 0.25]
    assert destination.read_bytes() == b"prior\n"
    assert not list(tmp_path.glob(".projection-journal-*"))


def test_windows_projection_journal_replace_permanent_error_is_not_retried(
    monkeypatch, tmp_path,
):
    module = _load()
    import ctypes

    destination = tmp_path / "journal.json"
    destination.write_bytes(b"prior\n")
    calls = []
    sleeps = []

    class Function:
        restype = None

        def __call__(self, *_args):
            calls.append("move")
            return 0

    class Kernel:
        MoveFileExW = Function()

    monkeypatch.setattr(module.os, "name", "nt")
    monkeypatch.setattr(ctypes, "WinDLL", lambda *_a, **_k: Kernel())
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 87, raising=False)
    monkeypatch.setattr(module.time, "sleep", sleeps.append)

    with pytest.raises(OSError, match="durable journal replace failed") as caught:
        module._claude_projection_atomic_json(
            str(destination), {"state": "PREPARED"},
        )

    assert caught.value.errno == 87
    assert calls == ["move"]
    assert sleeps == []
    assert destination.read_bytes() == b"prior\n"
    assert not list(tmp_path.glob(".projection-journal-*"))


@pytest.mark.parametrize(
    ("substitution", "message"),
    (
        ("ordinary-file", "journal replace target changed during retry"),
        ("directory", "journal replace target is not an ordinary file"),
        ("reparse", "journal replace target is not an ordinary file"),
        ("absent-created", "journal replace target changed during retry"),
    ),
)
def test_windows_projection_journal_replace_rejects_target_substitution(
    monkeypatch, tmp_path, substitution, message,
):
    module = _load()
    import ctypes

    destination = tmp_path / "journal.json"
    if substitution != "absent-created":
        destination.write_bytes(b"prior\n")
    foreign = tmp_path / "foreign-journal"
    if substitution == "ordinary-file":
        foreign.write_bytes(b"foreign\n")
    state = {"substituted": False}
    calls = []
    sleeps = []

    class Function:
        restype = None

        def __call__(self, *_args):
            calls.append("move")
            return 0

    class Kernel:
        MoveFileExW = Function()

    real_is_junction = module._is_junction
    monkeypatch.setattr(module.os, "name", "nt")
    monkeypatch.setattr(ctypes, "WinDLL", lambda *_a, **_k: Kernel())
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 33, raising=False)

    def sleep(delay):
        sleeps.append(delay)
        state["substituted"] = True
        if substitution == "ordinary-file":
            os.replace(foreign, destination)
        elif substitution == "directory":
            os.remove(destination)
            os.mkdir(destination)
        elif substitution == "absent-created":
            with open(destination, "xb") as stream:
                stream.write(b"foreign\n")

    monkeypatch.setattr(module.time, "sleep", sleep)
    if substitution == "reparse":
        monkeypatch.setattr(
            module, "_is_junction",
            lambda path: (
                state["substituted"]
                and os.path.normcase(os.path.abspath(path))
                == os.path.normcase(os.path.abspath(destination))
            ) or real_is_junction(path),
        )

    with pytest.raises(
        RuntimeError,
        match=message,
    ):
        module._claude_projection_atomic_json(
            str(destination), {"state": "PREPARED"},
        )

    assert calls == ["move"]
    assert sleeps == [0.01]
    assert not list(tmp_path.glob(".projection-journal-*"))


def test_missing_k1_key_and_idle_lock_refuses_k2_without_mutation(
    monkeypatch, tmp_path,
):
    module = _load()
    claude = tmp_path / ".claude"
    claude.mkdir()
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    transaction = _transaction(monkeypatch, module, tmp_path)
    module._recover_claude_projection_transaction()
    k1 = json.loads(
        (claude / ".plamen-projection.lock").read_text(encoding="utf-8")
    )["public_key"]
    Path(module._claude_projection_key_path()).unlink()
    (claude / ".plamen-projection.lock").unlink()
    module._CLAUDE_PROJECTION_PRIVATE_KEY = None
    private_k2, k2 = module._claude_projection_private_key(create=True)
    assert k2 != k1
    before = {str(path): path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}
    with pytest.raises(
        RuntimeError,
        match="prior Claude projection lock is missing|recovery lock is unavailable",
    ):
        module._claude_projection_prepare_idle_lock(
            private_k2, k2, prior_lock_public_key=k1,
        )
    after = {str(path): path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}
    assert after == before
    assert not (claude / ".plamen-projection.lock").exists()


def test_receipt_a_rejects_substituted_k3_key_and_lock(
    monkeypatch, tmp_path,
):
    module = _load()
    claude = tmp_path / ".claude"
    claude.mkdir()
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    _transaction(monkeypatch, module, tmp_path)
    module._recover_claude_projection_transaction()
    receipt_a = module._validated_committed_install_receipt()
    k1 = receipt_a["projection_public_key"]

    Path(module._claude_projection_key_path()).unlink()
    (claude / ".plamen-projection.lock").unlink()
    module._CLAUDE_PROJECTION_PRIVATE_KEY = None
    foreign_private, foreign_public = module._claude_projection_private_key(create=True)
    assert foreign_public != k1
    foreign = module._claude_projection_lock_envelope(foreign_private, foreign_public)
    (claude / ".plamen-projection.lock").write_text(
        json.dumps(foreign, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(RuntimeError, match="lock authority differs"):
        with module._claude_projection_lock(create=False):
            pass
    assert module._validated_committed_install_receipt() is receipt_a


def test_package_missing_prior_lock_fails_before_any_install_mutation(
    monkeypatch, tmp_path,
):
    module = _load()
    source = tmp_path / "source"
    source.mkdir()
    codex = tmp_path / "codex"
    installed = tmp_path / "installed"
    claude = tmp_path / ".claude"
    generation = _receipt(source, installed, codex)
    generation["terminal_verification"]["projection_lock_public_key"] = "6" * 64
    generation["terminal_verification"]["projection_public_key"] = "7" * 64
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    monkeypatch.setattr(
        module, "_validated_committed_install_receipt", lambda: generation,
    )
    monkeypatch.setattr(
        module, "_toolchain_runtime_required_integrity_issues",
        lambda *_a, **_k: {"missing": [], "mismatched": []},
    )
    monkeypatch.setattr(module, "_codex_install_source_rows", lambda *_a: [])
    key_path = tmp_path / "state" / "key.json"
    monkeypatch.setattr(
        module, "_claude_projection_key_path", lambda *_a: str(key_path),
    )
    before = sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*"))
    with pytest.raises(
        RuntimeError,
        match="prior Claude projection lock is missing|recovery lock is unavailable",
    ):
        module._install_codex_package_transaction(
            source_root=source, plamen_root=installed, codex_home=codex,
            enable_claude_projection=True,
        )
    after = sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*"))
    assert after == before
    assert not key_path.exists()
    assert not claude.exists()
    assert not codex.exists()
    assert not installed.exists()


def test_package_retains_k1_lock_before_first_root_ensure(
    monkeypatch, tmp_path,
):
    module = _load()
    claude = tmp_path / ".claude"
    claude.mkdir()
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    transaction = _transaction(monkeypatch, module, tmp_path)
    module._recover_claude_projection_transaction()
    generation = module._validated_committed_install_receipt()
    public = generation["projection_public_key"]
    generation["terminal_verification"]["projection_public_key"] = public
    generation["terminal_verification"]["projection_lock_public_key"] = public
    source = Path(generation["source_root"])
    installed = Path(generation["plamen_root"])
    codex = Path(generation["codex_root"])
    lock_path = claude / ".plamen-projection.lock"
    monkeypatch.setattr(
        module, "_toolchain_runtime_required_integrity_issues",
        lambda *_a, **_k: {"missing": [], "mismatched": []},
    )
    monkeypatch.setattr(module, "_codex_install_source_rows", lambda *_a, **_k: [])
    real_ensure = module._codex_install_ensure_root
    attempted = {"value": False}

    def adversarial_ensure(path, **_kwargs):
        attempted["value"] = True
        try:
            lock_path.unlink()
        except OSError as exc:
            raise RuntimeError("retained K1 blocked deletion") from exc
        raise AssertionError("K1 lock deletion unexpectedly succeeded")

    before = {
        str(path.relative_to(tmp_path)): (
            path.read_bytes() if path.is_file() else None
        )
        for path in tmp_path.rglob("*")
    }
    monkeypatch.setattr(module, "_codex_install_ensure_root", adversarial_ensure)
    with pytest.raises(RuntimeError, match="retained K1 blocked deletion"):
        module._install_codex_package_transaction(
            source_root=source, plamen_root=installed, codex_home=codex,
            enable_claude_projection=True,
        )
    monkeypatch.setattr(module, "_codex_install_ensure_root", real_ensure)
    after = {
        str(path.relative_to(tmp_path)): (
            path.read_bytes() if path.is_file() else None
        )
        for path in tmp_path.rglob("*")
    }
    assert attempted["value"] is True
    assert after == before
    assert lock_path.is_file()


def test_posix_named_k1_revalidation_rejects_uncooperative_replacement(
    monkeypatch, tmp_path,
):
    module = _load()
    lock = tmp_path / "projection.lock"
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    ).hex()
    raw = (
        json.dumps(
            module._claude_projection_lock_envelope(private, public),
            sort_keys=True, separators=(",", ":"),
        ) + "\n"
    ).encode("utf-8")
    lock.write_bytes(raw)
    stat = os.stat(lock, follow_symlinks=False)
    authority = {
        "path": module._claude_projection_canonical_path(str(lock)),
        "public_key": public,
        "device": int(stat.st_dev), "inode": int(stat.st_ino),
        "links": int(stat.st_nlink), "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    monkeypatch.setattr(module.os, "name", "posix")
    module._claude_projection_revalidate_lock_authority(authority)
    displaced = tmp_path / "projection.lock.old"
    os.rename(lock, displaced)
    lock.write_bytes(raw)
    with pytest.raises(RuntimeError, match="path was replaced"):
        module._claude_projection_revalidate_lock_authority(authority)
    assert displaced.read_bytes() == raw


@pytest.mark.skipif(os.name == "nt", reason="POSIX retained-inode rename semantics")
def test_posix_exact_created_key_retirement_leaves_no_rejected_bytes(
    monkeypatch, tmp_path,
):
    module = _load()
    key = tmp_path / "candidate-key"
    key.write_bytes(b"candidate-k2\n")
    authority = module._claude_projection_created_file_authority(str(key))
    monkeypatch.setattr(module.os, "name", "posix")
    monkeypatch.setattr(
        module, "_claude_projection_rename_noreplace",
        lambda source, destination: os.rename(source, destination),
    )
    monkeypatch.setattr(module, "_claude_projection_fsync_parent", lambda *_a: None)
    module._claude_projection_retire_exact_created_file(str(key), authority)
    assert not key.exists()
    assert list(tmp_path.iterdir()) == []


def test_package_revalidates_k1_after_noncreating_root_admission(
    monkeypatch, tmp_path,
):
    module = _load()
    source = tmp_path / "source"
    installed = tmp_path / "installed"
    codex = tmp_path / "codex"
    for root in (source, installed, codex):
        root.mkdir()
    generation = _receipt(source, installed, codex)
    generation["terminal_verification"]["projection_public_key"] = "6" * 64
    generation["terminal_verification"]["projection_lock_public_key"] = "6" * 64
    monkeypatch.setattr(
        module, "_validated_committed_install_receipt", lambda: generation,
    )
    monkeypatch.setattr(
        module, "_toolchain_runtime_required_integrity_issues",
        lambda *_a, **_k: {"missing": [], "mismatched": []},
    )
    monkeypatch.setattr(module, "_codex_install_source_rows", lambda *_a, **_k: [])
    lease_authority = {
        "path": str(tmp_path / "lock"), "public_key": "6" * 64,
        "device": 1, "inode": 2, "links": 1, "size": 1,
        "sha256": "7" * 64,
    }

    @contextlib.contextmanager
    def lease(*, create=True):
        assert create is False
        yield lease_authority

    validations = {"count": 0}

    def revalidate(authority):
        assert authority is lease_authority
        validations["count"] += 1
        if validations["count"] == 2:
            raise RuntimeError("simulated uncooperative K1 replacement")

    admissions = []

    def validate_root(path, *, create=True):
        assert create is False
        admissions.append(Path(path))

    monkeypatch.setattr(module, "_claude_projection_lock", lease)
    monkeypatch.setattr(
        module, "_claude_projection_revalidate_lock_authority", revalidate,
    )
    monkeypatch.setattr(module, "_codex_install_ensure_root", validate_root)
    before = {
        str(path.relative_to(tmp_path)): (
            path.read_bytes() if path.is_file() else None
        )
        for path in tmp_path.rglob("*")
    }
    with pytest.raises(RuntimeError, match="uncooperative K1 replacement"):
        module._install_codex_package_transaction(
            source_root=source, plamen_root=installed, codex_home=codex,
            enable_claude_projection=True,
        )
    after = {
        str(path.relative_to(tmp_path)): (
            path.read_bytes() if path.is_file() else None
        )
        for path in tmp_path.rglob("*")
    }
    assert admissions == [codex]
    assert after == before


def test_k2_publication_is_exactly_retired_when_k1_drifts(
    monkeypatch, tmp_path,
):
    module = _load()
    source = tmp_path / "source"
    installed = tmp_path / "installed"
    codex = tmp_path / "codex"
    claude = tmp_path / ".claude"
    state = tmp_path / "state"
    for root in (source, installed, codex, claude):
        root.mkdir()
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    generation = _receipt(source, installed, codex)
    generation["terminal_verification"] = {
        "verified_count": 759,
        "verified_manifest_sha256": "2" * 64,
        "completed_ns": 1,
    }
    generation["lock_identity"] = [17, 18]
    receipt_raw = b"exact legacy receipt\n"
    lock_path = claude / ".plamen-projection.lock"
    lock_path.write_bytes(module._CLAUDE_PROJECTION_LEGACY_LOCK_RAW)
    census = {
        "manifest_sha256": "d" * 64,
        "projection_count": 4,
        "runtime_count": 10,
    }
    census["projection_roster"] = _synthetic_legacy_projection_roster(
        module, source, claude,
    )
    census["projection_roster_sha256"] = hashlib.sha256(json.dumps(
        census["projection_roster"], sort_keys=True, separators=(",", ":"),
    ).encode()).hexdigest()
    monkeypatch.setattr(
        module, "_validated_committed_install_receipt", lambda: generation,
    )
    monkeypatch.setattr(
        module, "_claude_projection_validate_legacy_projection_ownership",
        lambda *_a, **_k: dict(census),
    )
    monkeypatch.setattr(
        module, "_codex_install_committed_read",
        lambda *_a, **_k: ({}, receipt_raw),
    )
    monkeypatch.setattr(
        module, "_toolchain_runtime_required_integrity_issues",
        lambda *_a, **_k: {"missing": [], "mismatched": []},
    )
    monkeypatch.setattr(module, "_codex_install_source_rows", lambda *_a, **_k: [])
    key_path = state / "projection-key.json"
    monkeypatch.setattr(
        module, "_claude_projection_key_path", lambda *_a: str(key_path),
    )
    monkeypatch.setattr(
        module, "_claude_projection_rename_noreplace",
        lambda source_path, destination_path: os.rename(
            source_path, destination_path,
        ),
    )
    monkeypatch.setattr(
        module, "_claude_projection_fsync_parent", lambda *_a: None,
    )
    validations = {"count": 0}

    def revalidate(authority):
        assert authority["public_key"] == module._CLAUDE_PROJECTION_LEGACY_PUBLIC
        assert authority["path"] == module._claude_projection_canonical_path(
            str(lock_path),
        )
        validations["count"] += 1
        if validations["count"] == 6:
            assert key_path.is_file()
            raise RuntimeError("K1 replaced after K2 publication")

    monkeypatch.setattr(
        module, "_claude_projection_revalidate_lock_authority", revalidate,
    )
    monkeypatch.setattr(
        module, "_codex_install_ensure_root", lambda *_a, **_k: None,
    )
    before = {
        str(path.relative_to(tmp_path)): (
            path.read_bytes() if path.is_file() else None
        )
        for path in tmp_path.rglob("*")
    }
    with pytest.raises(RuntimeError, match="K1 replaced after K2 publication"):
        module._install_codex_package_transaction(
            source_root=source, plamen_root=installed, codex_home=codex,
            enable_claude_projection=True,
        )
    after = {
        str(path.relative_to(tmp_path)): (
            path.read_bytes() if path.is_file() else None
        )
        for path in tmp_path.rglob("*")
    }
    assert validations["count"] >= 6
    assert after == before
    assert not key_path.exists()
    assert not state.exists()


def test_k2_publish_authority_never_retires_name_substitution(
    monkeypatch, tmp_path,
):
    module = _load()
    state = tmp_path / "state"
    state.mkdir()
    key = state / "projection-key.json"
    monkeypatch.setattr(
        module, "_claude_projection_key_path", lambda *_a: str(key),
    )
    _private, _public, authority = module._claude_projection_private_key(
        create=True, codex_home=tmp_path / "codex",
        return_created_authority=True,
    )
    assert authority is not None
    exact = state / "exact-published-key"
    os.rename(key, exact)
    foreign = b"foreign replacement\n"
    key.write_bytes(foreign)
    with pytest.raises(RuntimeError, match="file was replaced"):
        module._claude_projection_retire_exact_created_file(
            str(key), authority,
        )
    assert key.read_bytes() == foreign
    assert exact.is_file()


def test_created_key_parent_retirement_preserves_foreign_content_and_identity(
    tmp_path,
):
    module = _load()
    parent = tmp_path / "state"
    authority = module._claude_projection_publish_exact_directory(str(parent))
    foreign = parent / "foreign"
    foreign.write_bytes(b"foreign\n")
    with pytest.raises(RuntimeError, match="foreign content"):
        module._claude_projection_retire_exact_created_directory(
            str(parent), authority,
        )
    assert foreign.read_bytes() == b"foreign\n"

    displaced = tmp_path / "state-owned"
    os.rename(parent, displaced)
    parent.mkdir()
    sentinel = parent / "sentinel"
    sentinel.write_bytes(b"replacement\n")
    with pytest.raises(RuntimeError, match="was replaced"):
        module._claude_projection_retire_exact_created_directory(
            str(parent), authority,
        )
    assert sentinel.read_bytes() == b"replacement\n"
    assert (displaced / "foreign").read_bytes() == b"foreign\n"


@pytest.mark.parametrize("seam", ("prepare_idle_lock", "legacy_admission"))
def test_pretransaction_failure_retires_candidate_key_and_parent_exactly(
    monkeypatch, tmp_path, seam,
):
    module = _load()
    source = tmp_path / "source"
    installed = tmp_path / "installed"
    codex = tmp_path / "codex"
    claude = tmp_path / ".claude"
    for root in (source, installed, codex, claude):
        root.mkdir()
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))

    def no_prior_receipt():
        raise RuntimeError("no prior receipt")

    monkeypatch.setattr(
        module, "_validated_committed_install_receipt", no_prior_receipt,
    )
    monkeypatch.setattr(
        module, "_toolchain_runtime_required_integrity_issues",
        lambda *_a, **_k: {"missing": [], "mismatched": []},
    )
    monkeypatch.setattr(module, "_codex_install_source_rows", lambda *_a, **_k: [])
    key = tmp_path / "state" / "candidate-key.json"
    monkeypatch.setattr(
        module, "_claude_projection_key_path", lambda *_a: str(key),
    )
    lease_authority = {
        "path": str(tmp_path / "lock"), "public_key": "6" * 64,
        "device": 1, "inode": 2, "links": 1, "size": 1,
        "sha256": "7" * 64,
    }

    @contextlib.contextmanager
    def lease(*, create=True):
        assert create is False
        yield lease_authority

    monkeypatch.setattr(module, "_claude_projection_lock", lease)
    monkeypatch.setattr(
        module, "_claude_projection_revalidate_lock_authority", lambda *_a: None,
    )
    monkeypatch.setattr(
        module, "_codex_install_ensure_root", lambda *_a, **_k: None,
    )
    if seam == "prepare_idle_lock":
        monkeypatch.setattr(
            module, "_claude_projection_prepare_idle_lock",
            lambda *_a, **_k: (_ for _ in ()).throw(
                RuntimeError("PRETRANSACTION_FAILURE")
            ),
        )
    else:
        monkeypatch.setattr(
            module, "_claude_projection_prepare_idle_lock",
            lambda *_a, **_k: ("6" * 64, None),
        )
        monkeypatch.setattr(
            module, "_legacy_plamen_root_is_owned",
            lambda *_a, **_k: (_ for _ in ()).throw(
                RuntimeError("PRETRANSACTION_FAILURE")
            ),
        )
    before = {
        str(path.relative_to(tmp_path)): (
            path.read_bytes() if path.is_file() else None
        )
        for path in tmp_path.rglob("*")
    }
    with pytest.raises(RuntimeError, match="PRETRANSACTION_FAILURE"):
        module._install_codex_package_transaction(
            source_root=source, plamen_root=installed, codex_home=codex,
            enable_claude_projection=True,
        )
    after = {
        str(path.relative_to(tmp_path)): (
            path.read_bytes() if path.is_file() else None
        )
        for path in tmp_path.rglob("*")
    }
    assert after == before
    assert not key.exists() and not key.parent.exists()


def test_fresh_pretransaction_failure_retires_key_idle_lock_and_owned_roots(
    monkeypatch, tmp_path,
):
    module = _load()
    source = tmp_path / "source"
    installed = tmp_path / "installed"
    codex = tmp_path / "codex"
    for root in (source, installed, codex):
        root.mkdir()
    claude = tmp_path / ".claude"
    key = tmp_path / ".plamen-state" / "candidate-key.json"
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    monkeypatch.setattr(
        module, "_claude_projection_key_path", lambda *_a: str(key),
    )
    monkeypatch.setattr(
        module, "_validated_committed_install_receipt",
        lambda: (_ for _ in ()).throw(RuntimeError("no prior receipt")),
    )
    monkeypatch.setattr(
        module, "_toolchain_runtime_required_integrity_issues",
        lambda *_a, **_k: {"missing": [], "mismatched": []},
    )
    monkeypatch.setattr(module, "_codex_install_source_rows", lambda *_a, **_k: [])
    monkeypatch.setattr(
        module, "_codex_install_ensure_root", lambda *_a, **_k: None,
    )
    lease_authority = {
        "path": str(claude / ".plamen-projection.lock"),
        "public_key": "6" * 64, "device": 1, "inode": 2,
        "links": 1, "size": 1, "sha256": "7" * 64,
    }

    @contextlib.contextmanager
    def lease(*, create=True):
        assert create is False
        yield lease_authority

    monkeypatch.setattr(module, "_claude_projection_lock", lease)
    monkeypatch.setattr(
        module, "_claude_projection_revalidate_lock_authority", lambda *_a: None,
    )
    monkeypatch.setattr(
        module, "_legacy_plamen_root_is_owned",
        lambda *_a, **_k: (_ for _ in ()).throw(
            RuntimeError("FRESH_PRETRANSACTION_FAILURE")
        ),
    )
    before = {
        str(path.relative_to(tmp_path)): (
            path.read_bytes() if path.is_file() else None
        )
        for path in tmp_path.rglob("*")
    }
    with pytest.raises(RuntimeError, match="FRESH_PRETRANSACTION_FAILURE"):
        module._install_codex_package_transaction(
            source_root=source, plamen_root=installed, codex_home=codex,
            enable_claude_projection=True,
        )
    after = {
        str(path.relative_to(tmp_path)): (
            path.read_bytes() if path.is_file() else None
        )
        for path in tmp_path.rglob("*")
    }
    assert after == before
    assert not claude.exists() and not key.parent.exists()


def test_combined_foreign_idle_lock_does_not_short_circuit_owned_cleanup(
    monkeypatch, tmp_path,
):
    module = _load()
    source = tmp_path / "source"
    installed = tmp_path / "installed"
    codex = tmp_path / "codex"
    for root in (source, installed, codex):
        root.mkdir()
    claude = tmp_path / ".claude"
    key = tmp_path / ".plamen-state" / "candidate-key.json"
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    monkeypatch.setattr(
        module, "_claude_projection_key_path", lambda *_a: str(key),
    )
    monkeypatch.setattr(
        module, "_validated_committed_install_receipt",
        lambda: (_ for _ in ()).throw(RuntimeError("no prior receipt")),
    )
    monkeypatch.setattr(
        module, "_toolchain_runtime_required_integrity_issues",
        lambda *_a, **_k: {"missing": [], "mismatched": []},
    )
    monkeypatch.setattr(module, "_codex_install_source_rows", lambda *_a, **_k: [])
    monkeypatch.setattr(
        module, "_codex_install_ensure_root", lambda *_a, **_k: None,
    )
    lease_authority = {
        "path": str(claude / ".plamen-projection.lock"),
        "public_key": "6" * 64, "device": 1, "inode": 2,
        "links": 1, "size": 1, "sha256": "7" * 64,
    }

    @contextlib.contextmanager
    def lease(*, create=True):
        assert create is False
        yield lease_authority

    monkeypatch.setattr(module, "_claude_projection_lock", lease)
    monkeypatch.setattr(
        module, "_claude_projection_revalidate_lock_authority", lambda *_a: None,
    )
    foreign = b"foreign lock replacement\n"

    def combined_attack(*_args, **_kwargs):
        lock = claude / ".plamen-projection.lock"
        displaced = claude / ".plamen-projection.lock.displaced"
        os.rename(lock, displaced)
        lock.write_bytes(foreign)
        raise RuntimeError("COMBINED_ATTACK")

    monkeypatch.setattr(module, "_legacy_plamen_root_is_owned", combined_attack)
    with pytest.raises(RuntimeError) as captured:
        module._install_codex_package_transaction(
            source_root=source, plamen_root=installed, codex_home=codex,
            enable_claude_projection=True,
        )
    message = str(captured.value)
    assert "COMBINED_ATTACK" in message
    assert "idle_lock:RuntimeError:created projection authority file was replaced" in message
    assert "claude_home:RuntimeError:created projection directory gained foreign content" in message
    assert message.index("idle_lock:") < message.index("claude_home:")
    assert (claude / ".plamen-projection.lock").read_bytes() == foreign
    assert (claude / ".plamen-projection.lock.displaced").is_file()
    assert not key.exists() and not key.parent.exists()
    assert not (codex / module._CODEX_INSTALL_RECEIPT).exists()


def _synthetic_legacy_projection_roster(module, source, claude, count=4):
    roster = []
    for ordinal in range(count):
        relative = f"legacy-{ordinal}.md"
        roster.append({
            "destination": module._claude_projection_canonical_path(
                str(claude / relative)
            ),
            "relative_path": relative,
            "install_mode": "link",
            "descriptor": {
                "kind": "symlink",
                "target": module._claude_projection_canonical_path(
                    str(source / relative)
                ),
            },
        })
    roster.sort(key=lambda row: os.path.normcase(row["destination"]))
    return roster


def _legacy_projection_transaction(monkeypatch, module, tmp_path):
    source = tmp_path / "source-authority"
    installed = tmp_path / "installed-authority"
    codex = tmp_path / "codex-authority"
    claude = tmp_path / ".claude"
    for directory in (source, installed, codex, claude):
        directory.mkdir(exist_ok=True)
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    monkeypatch.setattr(
        module, "_claude_projection_key_path",
        lambda *_a: str(codex / ".plamen-projection-authority.key"),
    )
    private, public = module._claude_projection_private_key(create=True)
    lock_path = claude / ".plamen-projection.lock"
    lock_path.write_bytes(b"\x00")
    lock_stat = lock_path.stat(follow_symlinks=False)
    legacy_authority = module._claude_projection_legacy_lock_authority(
        str(lock_path), b"\x00", lock_stat,
    )
    migration_id = "a" * 32
    nonce = hashlib.sha256((migration_id + ":lock").encode("ascii")).hexdigest()
    payload = module._claude_projection_lock_envelope(
        private, public, nonce=nonce,
    )
    successor_raw = (
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    roster = _synthetic_legacy_projection_roster(module, source, claude)
    migration = {
        "schema": module._CLAUDE_PROJECTION_LEGACY_MIGRATION_SCHEMA,
        "migration_id": migration_id,
        "prior_transaction_id": "b" * 32,
        "prior_receipt_sha256": "c" * 64,
        "legacy_source_root": str(source.absolute()),
        "legacy_lock": legacy_authority,
        "successor_lock_sha256": hashlib.sha256(successor_raw).hexdigest(),
        "legacy_manifest_sha256": "d" * 64,
        "legacy_projection_count": 4,
        "legacy_runtime_count": 10,
        "legacy_projection_roster": roster,
        "legacy_projection_roster_sha256": hashlib.sha256(json.dumps(
            roster, sort_keys=True, separators=(",", ":"),
        ).encode()).hexdigest(),
        "prior_anchor_identity": [1, 2],
        "prepackage_intent_sha256": None,
    }
    generation = _receipt(source, installed, codex)
    generation["projection_public_key"] = public
    generation["terminal_verification"] = {
        "verified_count": 759,
        "verified_manifest_sha256": "2" * 64,
        "completed_ns": 1,
        "projection_public_key": public,
        "projection_lock_public_key": public,
        "projection_lock_authority_sha256": hashlib.sha256(
            json.dumps(
                legacy_authority, sort_keys=True, separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest(),
        "legacy_projection_migration": migration,
    }
    monkeypatch.setattr(
        module, "_validated_committed_install_receipt", lambda: generation,
    )
    monkeypatch.setattr(
        module, "_open_install_admission_anchor",
        lambda *_a, **_k: (Path("anchor"), object(), lambda: None),
    )
    monkeypatch.setattr(module, "_toolchain_runtime_required_files", lambda *_a: [])
    return module._ClaudeProjectionTransaction(generation), lock_path, successor_raw


def test_legacy_nul_lock_migrates_only_with_projection_commit(
    monkeypatch, tmp_path,
):
    module = _load()
    transaction, lock_path, successor_raw = _legacy_projection_transaction(
        monkeypatch, module, tmp_path,
    )
    destination = Path(module.CLAUDE_HOME) / "settings.json"
    destination.write_bytes(b"old\n")
    transaction.add_bytes(str(destination), b"new\n", kind="config")
    transaction.commit()
    assert destination.read_bytes() == b"new\n"
    assert lock_path.read_bytes() == successor_raw
    assert not module._claude_projection_pending()


@pytest.mark.parametrize(
    "seam",
    ("after_projection_legacy_lock_backup", "after_projection_legacy_lock_replace"),
)
def test_legacy_lock_migration_failure_restores_exact_nul_preimage(
    monkeypatch, tmp_path, seam,
):
    module = _load()
    transaction, lock_path, _successor_raw = _legacy_projection_transaction(
        monkeypatch, module, tmp_path,
    )
    destination = Path(module.CLAUDE_HOME) / "settings.json"
    destination.write_bytes(b"old\n")
    transaction.add_bytes(str(destination), b"new\n", kind="config")
    monkeypatch.setattr(module, "_CLAUDE_PROJECTION_FAILPOINT", seam)
    with pytest.raises(RuntimeError, match="CLAUDE_PROJECTION_FAILPOINT"):
        transaction.commit()
    assert destination.read_bytes() == b"old\n"
    assert lock_path.read_bytes() == b"\x00"
    assert not module._claude_projection_pending()


def test_legacy_lock_substitution_before_commit_is_preserved_and_refused(
    monkeypatch, tmp_path,
):
    module = _load()
    transaction, lock_path, _successor_raw = _legacy_projection_transaction(
        monkeypatch, module, tmp_path,
    )
    displaced = lock_path.with_suffix(".owned")
    os.rename(lock_path, displaced)
    foreign = b"foreign\n"
    lock_path.write_bytes(foreign)
    with pytest.raises(RuntimeError, match="authority|drifted|replaced"):
        transaction.commit()
    assert lock_path.read_bytes() == foreign
    assert displaced.read_bytes() == b"\x00"


@pytest.mark.parametrize("raw", (b"\x00\x00", b"{}", b"foreign\n"))
def test_legacy_lock_admission_rejects_noncanonical_bytes(
    monkeypatch, tmp_path, raw,
):
    module = _load()
    claude = tmp_path / ".claude"
    claude.mkdir()
    lock_path = claude / ".plamen-projection.lock"
    lock_path.write_bytes(raw)
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    receipt = {
        "schema": module._CODEX_INSTALL_SCHEMA,
        "state": "COMMITTED",
        "source_count": 759, "runtime_count": 728, "adapter_count": 31,
        "terminal_verification": {
            "verified_count": 759,
            "verified_manifest_sha256": "1" * 64,
            "completed_ns": 1,
        },
    }
    monkeypatch.setattr(
        module, "_validated_committed_install_receipt", lambda: receipt,
    )
    monkeypatch.setattr(
        module, "_claude_projection_validate_legacy_projection_ownership",
        lambda _receipt: {},
    )
    with pytest.raises(RuntimeError, match="lock|authority|malformed"):
        with module._claude_projection_lock(
            create=False, allow_legacy_receipt=receipt,
        ):
            pass
    assert lock_path.read_bytes() == raw


def test_live_shape_legacy_lease_prepares_successor_without_named_reopen(
    monkeypatch, tmp_path,
):
    module = _load()
    source = tmp_path / "checkout"
    installed = tmp_path / ".plamen"
    codex = tmp_path / ".codex"
    claude = tmp_path / ".claude"
    for directory in (source, installed, codex, claude):
        directory.mkdir()
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    receipt = _receipt(source, installed, codex)
    receipt["terminal_verification"] = {
        "verified_count": 759,
        "verified_manifest_sha256": "2" * 64,
        "completed_ns": 1,
    }
    receipt["lock_identity"] = [11, 12]
    monkeypatch.setattr(
        module, "_validated_committed_install_receipt", lambda: receipt,
    )
    monkeypatch.setattr(
        module, "_claude_projection_validate_legacy_projection_ownership",
        lambda *_a, **_k: {
            "manifest_sha256": "3" * 64,
            "projection_count": 48, "runtime_count": 288,
            "projection_roster": [],
            "projection_roster_sha256": hashlib.sha256(b"[]").hexdigest(),
        },
    )
    lock_path = claude / ".plamen-projection.lock"
    lock_path.write_bytes(b"\x00")
    private, public, _encoded = module._claude_projection_new_private_key_material()
    with module._claude_projection_lock(
        create=False, allow_legacy_receipt=receipt,
    ) as retained:
        import copy
        with pytest.raises(TypeError, match="cannot be copied"):
            copy.copy(retained)
        with pytest.raises(TypeError, match="cannot be copied"):
            copy.deepcopy(retained)
        with pytest.raises(TypeError, match="immutable"):
            retained["public_key"] = public
        original_public = retained["public_key"]
        dict.__setitem__(retained, "public_key", public)
        with pytest.raises(RuntimeError, match="authority was modified"):
            module._claude_projection_prepare_idle_lock(
                private, public, prior_lock_public_key=None,
                prior_lock_authority=retained,
            )
        dict.__setitem__(retained, "public_key", original_public)
        with pytest.raises(RuntimeError, match="retained lease is unavailable"):
            module._claude_projection_prepare_idle_lock(
                private, public, prior_lock_public_key=None,
                prior_lock_authority=dict(retained),
            )
        selected, created = module._claude_projection_prepare_idle_lock(
            private, public, prior_lock_public_key=None,
            return_created_authority=True,
            prior_lock_authority=retained,
        )
        assert selected == public
        assert created is None
        displaced = lock_path.with_suffix(".retained")
        if os.name == "nt":
            with pytest.raises(OSError):
                os.rename(lock_path, displaced)
            named = lock_path.stat(follow_symlinks=False)
            assert (int(named.st_dev), int(named.st_ino)) == (
                retained["device"], retained["inode"],
            )
        else:
            os.rename(lock_path, displaced)
            lock_path.write_bytes(b"foreign\n")
            try:
                with pytest.raises(RuntimeError, match="retained lease identity"):
                    module._claude_projection_prepare_idle_lock(
                        private, public, prior_lock_public_key=None,
                        prior_lock_authority=retained,
                    )
            finally:
                lock_path.unlink()
                os.rename(displaced, lock_path)
        assert not hasattr(module, "_CLAUDE_PROJECTION_ACTIVE_LEASES")
        retained_descriptor = None
        close_observed = []
        real_close = module.os.close

        def checked_close(descriptor):
            nonlocal retained_descriptor
            try:
                module._claude_projection_validate_active_lease(retained)
            except RuntimeError as exc:
                if "unavailable" in str(exc):
                    retained_descriptor = descriptor
                    close_observed.append(True)
            return real_close(descriptor)

        monkeypatch.setattr(module.os, "close", checked_close)
        fabricated = module._ClaudeProjectionRetainedLease(dict(retained))
        setattr(module, "_CLAUDE_PROJECTION_ACTIVE_LEASES", {
            id(fabricated): (fabricated, 3, dict(fabricated)),
        })
        with pytest.raises(RuntimeError, match="retained lease is unavailable"):
            module._claude_projection_prepare_idle_lock(
                private, public, prior_lock_public_key=None,
                prior_lock_authority=fabricated,
            )
        delattr(module, "_CLAUDE_PROJECTION_ACTIVE_LEASES")
    with pytest.raises(RuntimeError, match="retained lease is unavailable"):
        module._claude_projection_prepare_idle_lock(
            private, public, prior_lock_public_key=None,
            prior_lock_authority=retained,
        )
    assert close_observed == [True]
    assert isinstance(retained_descriptor, int)
    aba_path = tmp_path / "aba"
    aba_path.write_bytes(b"x")
    aba_descriptor = module.os.open(aba_path, os.O_RDONLY)
    try:
        assert aba_descriptor == retained_descriptor
        with pytest.raises(RuntimeError, match="retained lease is unavailable"):
            module._claude_projection_prepare_idle_lock(
                private, public, prior_lock_public_key=None,
                prior_lock_authority=retained,
            )
    finally:
        module.os.close(aba_descriptor)
    assert lock_path.read_bytes() == b"\x00"


def test_held_lease_descriptor_byte_mutation_is_rejected(monkeypatch, tmp_path):
    module = _load()
    source = tmp_path / "checkout"
    installed = tmp_path / ".plamen"
    codex = tmp_path / ".codex"
    claude = tmp_path / ".claude"
    for directory in (source, installed, codex, claude):
        directory.mkdir()
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    receipt = _receipt(source, installed, codex)
    receipt["terminal_verification"] = {
        "verified_count": 759,
        "verified_manifest_sha256": "2" * 64,
        "completed_ns": 1,
    }
    receipt["lock_identity"] = [11, 12]
    monkeypatch.setattr(
        module, "_validated_committed_install_receipt", lambda: receipt,
    )
    monkeypatch.setattr(
        module, "_claude_projection_validate_legacy_projection_ownership",
        lambda *_a, **_k: {},
    )
    lock_path = claude / ".plamen-projection.lock"
    lock_path.write_bytes(b"\x00")
    private, public, _encoded = module._claude_projection_new_private_key_material()
    with module._claude_projection_lock(
        create=False, allow_legacy_receipt=receipt,
    ) as retained:
        retained_descriptor = None
        for candidate in range(3, 2048):
            try:
                observed = module.os.fstat(candidate)
            except OSError:
                continue
            if (int(observed.st_dev), int(observed.st_ino)) == (
                retained["device"], retained["inode"],
            ):
                retained_descriptor = candidate
                break
        assert retained_descriptor is not None
        module.os.lseek(retained_descriptor, 0, os.SEEK_SET)
        assert module.os.write(retained_descriptor, b"X") == 1
        with pytest.raises(RuntimeError, match="retained lease identity"):
            module._claude_projection_prepare_idle_lock(
                private, public, prior_lock_public_key=None,
                prior_lock_authority=retained,
            )
    assert lock_path.read_bytes() == b"X"


def test_signed_held_lease_prepares_without_second_open(monkeypatch, tmp_path):
    module = _load()
    source = tmp_path / "source"
    installed = tmp_path / ".plamen"
    codex = tmp_path / ".codex"
    claude = tmp_path / ".claude"
    for directory in (source, installed, codex, claude):
        directory.mkdir()
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    monkeypatch.setattr(
        module, "_claude_projection_key_path",
        lambda *_a: str(codex / ".plamen-projection-authority.key"),
    )
    private, public = module._claude_projection_private_key(create=True)
    receipt = _receipt(source, installed, codex)
    receipt["terminal_verification"].update({
        "projection_public_key": public,
        "projection_lock_public_key": public,
    })
    monkeypatch.setattr(
        module, "_validated_committed_install_receipt", lambda: receipt,
    )
    payload = module._claude_projection_lock_envelope(private, public)
    lock_path = claude / ".plamen-projection.lock"
    lock_path.write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    with module._claude_projection_lock(create=False) as retained:
        selected, created = module._claude_projection_prepare_idle_lock(
            private, public, prior_lock_public_key=public,
            return_created_authority=True,
            prior_lock_authority=retained,
        )
        assert selected == public
        assert created is None
    assert json.loads(lock_path.read_text(encoding="utf-8"))["public_key"] == public


def _legacy_prepackage_intent(monkeypatch, module, tmp_path, *, publish_key):
    source = tmp_path / "legacy-source"
    installed = tmp_path / "installed"
    codex = tmp_path / ".codex"
    claude = tmp_path / ".claude"
    for directory in (source, installed, codex, claude):
        directory.mkdir()
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    key_path = codex / ".plamen-projection-authority.key"
    monkeypatch.setattr(
        module, "_claude_projection_key_path", lambda *_a: str(key_path),
    )
    receipt = _receipt(source, installed, codex)
    receipt["terminal_verification"] = {
        "verified_count": 759,
        "verified_manifest_sha256": "2" * 64,
        "completed_ns": 1,
    }
    receipt["lock_identity"] = [11, 12]
    receipt_raw = b"authenticated legacy receipt\n"
    lock_path = claude / ".plamen-projection.lock"
    lock_path.write_bytes(b"\x00")
    lock_authority = module._claude_projection_legacy_lock_authority(
        str(lock_path), b"\x00", lock_path.stat(follow_symlinks=False),
    )
    private, public, key_raw = module._claude_projection_new_private_key_material()
    migration_id = "a" * 32
    successor = module._claude_projection_lock_envelope(
        private, public,
        nonce=hashlib.sha256((migration_id + ":lock").encode()).hexdigest(),
    )
    successor_raw = (
        json.dumps(successor, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    census = {
        "manifest_sha256": "d" * 64,
        "projection_count": 4,
        "runtime_count": 10,
    }
    census["projection_roster"] = _synthetic_legacy_projection_roster(
        module, source, claude,
    )
    census["projection_roster_sha256"] = hashlib.sha256(json.dumps(
        census["projection_roster"], sort_keys=True, separators=(",", ":"),
    ).encode()).hexdigest()
    intent = {
        "schema": module._CLAUDE_PROJECTION_LEGACY_INTENT_SCHEMA,
        "migration_id": migration_id,
        "prior_transaction_id": receipt["transaction_id"],
        "prior_receipt_sha256": hashlib.sha256(receipt_raw).hexdigest(),
        "prior_anchor_identity": receipt["lock_identity"],
        "legacy_source_root": receipt["source_root"],
        "legacy_lock": lock_authority,
        "successor_lock_sha256": hashlib.sha256(successor_raw).hexdigest(),
        "legacy_manifest_sha256": census["manifest_sha256"],
        "legacy_projection_count": census["projection_count"],
        "legacy_runtime_count": census["runtime_count"],
        "legacy_projection_roster": census["projection_roster"],
        "legacy_projection_roster_sha256": census[
            "projection_roster_sha256"
        ],
        "candidate_public_key": public,
        "candidate_key_path": module._claude_projection_canonical_path(
            str(key_path)
        ),
        "candidate_key_stage_path": (
            module._claude_projection_canonical_path(str(key_path))
            + ".migration-" + migration_id
        ),
        "candidate_key_sha256": hashlib.sha256(key_raw).hexdigest(),
    }
    intent["signature"] = private.sign(
        module._claude_projection_legacy_intent_bytes(intent)
    ).hex()
    intent_path = Path(module._claude_projection_legacy_intent_path())
    intent_path.write_text(
        json.dumps(intent, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    if publish_key:
        key_path.write_bytes(key_raw)
    monkeypatch.setattr(
        module, "_validated_committed_install_receipt", lambda: receipt,
    )
    monkeypatch.setattr(
        module, "_codex_install_committed_read",
        lambda *_a, **_k: ({}, receipt_raw),
    )
    monkeypatch.setattr(
        module, "_claude_projection_validate_legacy_projection_ownership",
        lambda *_a, **_k: dict(census),
    )
    return intent_path, key_path, intent


@pytest.mark.parametrize("publish_key", (False, True))
def test_legacy_prepackage_intent_recovers_a_and_retires_candidate(
    monkeypatch, tmp_path, publish_key,
):
    module = _load()
    intent_path, key_path, _intent = _legacy_prepackage_intent(
        monkeypatch, module, tmp_path, publish_key=publish_key,
    )
    assert module._claude_projection_pending()
    assert module._recover_claude_projection_legacy_intent()
    assert not intent_path.exists()
    assert not key_path.exists()
    assert not module._claude_projection_pending()


def test_legacy_prepackage_intent_refuses_foreign_candidate_without_deletion(
    monkeypatch, tmp_path,
):
    module = _load()
    intent_path, key_path, _intent = _legacy_prepackage_intent(
        monkeypatch, module, tmp_path, publish_key=False,
    )
    foreign = b"foreign candidate\n"
    key_path.write_bytes(foreign)
    with pytest.raises(RuntimeError, match="foreign key"):
        module._recover_claude_projection_legacy_intent()
    assert key_path.read_bytes() == foreign
    assert intent_path.is_file()


def test_legacy_prepackage_intent_recovers_exact_key_stage_after_hard_kill(
    monkeypatch, tmp_path,
):
    module = _load()
    intent_path, key_path, intent = _legacy_prepackage_intent(
        monkeypatch, module, tmp_path, publish_key=True,
    )
    stage_path = Path(intent["candidate_key_stage_path"])
    os.rename(key_path, stage_path)
    assert module._recover_claude_projection_legacy_intent()
    assert not stage_path.exists()
    assert not key_path.exists()
    assert not intent_path.exists()


def test_legacy_prepackage_intent_is_adopted_only_by_exact_terminal_b(
    monkeypatch, tmp_path,
):
    module = _load()
    intent_path, key_path, intent = _legacy_prepackage_intent(
        monkeypatch, module, tmp_path, publish_key=True,
    )
    intent_raw = intent_path.read_bytes()
    migration = {
        key: intent[key] for key in (
            "migration_id", "prior_transaction_id", "prior_receipt_sha256",
            "prior_anchor_identity", "legacy_source_root", "legacy_lock",
            "successor_lock_sha256", "legacy_manifest_sha256",
            "legacy_projection_count", "legacy_runtime_count",
            "legacy_projection_roster", "legacy_projection_roster_sha256",
        )
    }
    migration.update({
        "schema": module._CLAUDE_PROJECTION_LEGACY_MIGRATION_SCHEMA,
        "prepackage_intent_sha256": hashlib.sha256(intent_raw).hexdigest(),
    })
    receipt = _receipt(
        Path(intent["legacy_source_root"]), tmp_path / "installed", key_path.parent,
    )
    receipt["lock_identity"] = intent["prior_anchor_identity"]
    receipt["terminal_verification"] = {
        "verified_count": 759,
        "verified_manifest_sha256": "2" * 64,
        "completed_ns": 2,
        "projection_public_key": intent["candidate_public_key"],
        "projection_lock_public_key": intent["candidate_public_key"],
        "projection_lock_authority_sha256": "e" * 64,
        "legacy_projection_migration": migration,
    }
    monkeypatch.setattr(
        module, "_validated_committed_install_receipt", lambda: receipt,
    )
    assert module._recover_claude_projection_legacy_intent()
    assert key_path.is_file()
    assert not intent_path.exists()


def test_legacy_package_failure_after_candidate_publication_restores_exact_a(
    monkeypatch, tmp_path,
):
    module = _load()
    source = tmp_path / "source"
    installed = tmp_path / "installed"
    codex = tmp_path / "codex"
    claude = tmp_path / ".claude"
    for directory in (source, installed, codex, claude):
        directory.mkdir()
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    key_path = codex / ".plamen-projection-authority.key"
    monkeypatch.setattr(
        module, "_claude_projection_key_path", lambda *_a: str(key_path),
    )
    receipt = _receipt(source, installed, codex)
    receipt["terminal_verification"] = {
        "verified_count": 759,
        "verified_manifest_sha256": "2" * 64,
        "completed_ns": 1,
    }
    receipt["lock_identity"] = [17, 18]
    receipt_raw = b"exact A receipt\n"
    lock_path = claude / ".plamen-projection.lock"
    lock_path.write_bytes(b"\x00")
    census = {
        "manifest_sha256": "d" * 64,
        "projection_count": 4,
        "runtime_count": 10,
    }
    census["projection_roster"] = _synthetic_legacy_projection_roster(
        module, source, claude,
    )
    census["projection_roster_sha256"] = hashlib.sha256(json.dumps(
        census["projection_roster"], sort_keys=True, separators=(",", ":"),
    ).encode()).hexdigest()
    monkeypatch.setattr(
        module, "_validated_committed_install_receipt", lambda: receipt,
    )
    monkeypatch.setattr(
        module, "_claude_projection_validate_legacy_projection_ownership",
        lambda *_a, **_k: dict(census),
    )
    monkeypatch.setattr(
        module, "_codex_install_committed_read",
        lambda *_a, **_k: ({}, receipt_raw),
    )
    monkeypatch.setattr(
        module, "_toolchain_runtime_required_integrity_issues",
        lambda *_a, **_k: {"missing": [], "mismatched": []},
    )
    monkeypatch.setattr(module, "_codex_install_source_rows", lambda *_a: [])
    monkeypatch.setattr(
        module, "_codex_install_ensure_root", lambda *_a, **_k: None,
    )

    monkeypatch.setattr(
        module, "_legacy_plamen_root_is_owned",
        lambda *_a, **_k: (_ for _ in ()).throw(
            RuntimeError("AFTER_CANDIDATE_PUBLICATION")
        ),
    )
    before = {
        str(path.relative_to(tmp_path)): (
            path.read_bytes() if path.is_file() else None
        )
        for path in tmp_path.rglob("*")
    }
    with pytest.raises(RuntimeError, match="AFTER_CANDIDATE_PUBLICATION"):
        module._install_codex_package_transaction(
            source_root=source, plamen_root=installed, codex_home=codex,
            enable_claude_projection=True,
        )
    after = {
        str(path.relative_to(tmp_path)): (
            path.read_bytes() if path.is_file() else None
        )
        for path in tmp_path.rglob("*")
    }
    assert after == before
    assert lock_path.read_bytes() == b"\x00"
    assert not key_path.exists()
    assert not Path(module._claude_projection_legacy_intent_path()).exists()


def test_legacy_intent_foreign_path_type_is_pending_and_fails_closed(
    monkeypatch, tmp_path,
):
    module = _load()
    claude = tmp_path / ".claude"
    claude.mkdir()
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    intent = Path(module._claude_projection_legacy_intent_path())
    intent.mkdir()
    assert module._claude_projection_pending()
    with pytest.raises(RuntimeError, match="intent is not an ordinary file"):
        module._recover_claude_projection_legacy_intent()
    assert intent.is_dir()


@pytest.mark.parametrize("checkout_state", ("missing", "mutated"))
def test_incomplete_b_recovery_accepts_installed_entrypoint_without_checkout(
    monkeypatch, tmp_path, checkout_state,
):
    module = _load()
    source = tmp_path / "historical-checkout"
    installed = tmp_path / ".plamen"
    codex = tmp_path / ".codex"
    claude = tmp_path / ".claude"
    for directory in (source, installed, codex, claude):
        directory.mkdir()
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    lock_path = claude / ".plamen-projection.lock"
    lock_path.write_bytes(b"\x00")
    legacy_lock = module._claude_projection_legacy_lock_authority(
        str(lock_path), b"\x00", lock_path.stat(follow_symlinks=False),
    )
    roster = _synthetic_legacy_projection_roster(module, source, claude)
    migration = {
        "schema": module._CLAUDE_PROJECTION_LEGACY_MIGRATION_SCHEMA,
        "migration_id": "a" * 32,
        "prior_transaction_id": "b" * 32,
        "prior_receipt_sha256": "c" * 64,
        "legacy_source_root": str(source.absolute()),
        "legacy_lock": legacy_lock,
        "successor_lock_sha256": "d" * 64,
        "legacy_manifest_sha256": "e" * 64,
        "legacy_projection_count": len(roster),
        "legacy_runtime_count": 10,
        "legacy_projection_roster": roster,
        "legacy_projection_roster_sha256": hashlib.sha256(json.dumps(
            roster, sort_keys=True, separators=(",", ":"),
        ).encode()).hexdigest(),
        "prior_anchor_identity": [11, 12],
        "prepackage_intent_sha256": None,
    }
    receipt = _receipt(source, installed, codex)
    receipt["lock_identity"] = [11, 12]
    receipt["terminal_verification"] = {
        "verified_count": 759, "verified_manifest_sha256": "2" * 64,
        "completed_ns": 2, "projection_public_key": "5" * 64,
        "projection_lock_public_key": "5" * 64,
        "projection_lock_authority_sha256": "6" * 64,
        "legacy_projection_migration": migration,
    }
    if checkout_state == "missing":
        source.rmdir()
    else:
        (source / "foreign-mutation").write_bytes(b"changed\n")
    monkeypatch.setattr(
        module, "_validated_committed_install_receipt", lambda: receipt,
    )
    monkeypatch.setattr(
        module, "_claude_projection_incomplete_legacy_migration",
        lambda: receipt,
    )
    real_expand = module.os.path.expanduser
    monkeypatch.setattr(
        module.os.path, "expanduser",
        lambda value: str(installed) if value == "~/.plamen" else real_expand(value),
    )
    root, prior_roots, generation = (
        module._committed_claude_projection_authority(receipt, installed)
    )
    assert os.path.normcase(root) == os.path.normcase(str(installed))
    assert prior_roots == (os.path.normpath(str(source.absolute())),)
    assert generation["transaction_id"] == receipt["transaction_id"]


def test_legacy_migration_rejects_extra_same_relative_checkout_link(
    monkeypatch, tmp_path,
):
    module = _load()
    transaction, _lock_path, _successor_raw = _legacy_projection_transaction(
        monkeypatch, module, tmp_path,
    )
    legacy_root = Path(transaction.legacy_lock_migration["legacy_source_root"])
    committed_root = Path(transaction.authority["plamen_root"])
    destination = Path(module.CLAUDE_HOME) / "extra.md"
    legacy_source = legacy_root / "extra.md"
    committed_source = committed_root / "extra.md"
    legacy_source.write_bytes(b"same\n")
    committed_source.write_bytes(b"same\n")
    os.symlink(legacy_source, destination)
    with pytest.raises(RuntimeError, match="outside its exact roster"):
        transaction.add_link_or_copy(
            str(committed_source), str(destination), lambda *_a: None,
            admitted_prior_targets=(str(legacy_source),),
        )
    assert destination.is_symlink()
    assert os.path.samefile(destination, legacy_source)


@pytest.mark.parametrize(
    ("install_mode", "directory"),
    (("copied", False), ("copied_dir", True)),
)
def test_legacy_exact_roster_authorizes_copied_predecessor_without_backup(
    monkeypatch, tmp_path, install_mode, directory,
):
    module = _load()
    transaction, _lock_path, _successor_raw = _legacy_projection_transaction(
        monkeypatch, module, tmp_path,
    )
    relative = "copied-tree" if directory else "copied.md"
    source = Path(transaction.authority["plamen_root"]) / relative
    destination = Path(module.CLAUDE_HOME) / relative
    if directory:
        source.mkdir(); destination.mkdir()
        (source / "payload").write_bytes(b"exact\n")
        (destination / "payload").write_bytes(b"exact\n")
    else:
        source.write_bytes(b"exact\n")
        destination.write_bytes(b"exact\n")
    descriptor = module._claude_projection_descriptor(str(destination))
    transaction.legacy_projection_roster[
        os.path.normcase(module._claude_projection_canonical_path(str(destination)))
    ] = {
        "destination": module._claude_projection_canonical_path(str(destination)),
        "relative_path": relative,
        "install_mode": install_mode,
        "descriptor": descriptor,
    }
    assert not Path(str(destination) + ".pre-plamen").exists()
    status = transaction.add_link_or_copy(
        str(source), str(destination), lambda *_a: None,
    )
    assert status
    assert transaction.rows[-1]["prior"] == descriptor
    assert module._claude_projection_descriptor(str(destination)) == descriptor


@pytest.mark.parametrize(
    ("install_mode", "directory"),
    (("copied", False), ("copied_dir", True)),
)
@pytest.mark.parametrize("mutation", ("descriptor", "mode"))
def test_legacy_copied_roster_descriptor_or_mode_mutation_is_rejected_unchanged(
    monkeypatch, tmp_path, install_mode, directory, mutation,
):
    module = _load()
    transaction, _lock_path, _successor_raw = _legacy_projection_transaction(
        monkeypatch, module, tmp_path,
    )
    relative = "copied-tree" if directory else "copied.md"
    source = Path(transaction.authority["plamen_root"]) / relative
    destination = Path(module.CLAUDE_HOME) / relative
    if directory:
        source.mkdir(); destination.mkdir()
        (source / "payload").write_bytes(b"exact\n")
        (destination / "payload").write_bytes(b"exact\n")
    else:
        source.write_bytes(b"exact\n")
        destination.write_bytes(b"exact\n")
    descriptor = module._claude_projection_descriptor(str(destination))
    roster_descriptor = dict(descriptor)
    roster_mode = install_mode
    if mutation == "descriptor":
        roster_descriptor["sha256"] = "f" * 64
    else:
        roster_mode = "copied_dir" if install_mode == "copied" else "copied"
    transaction.legacy_projection_roster[
        os.path.normcase(module._claude_projection_canonical_path(str(destination)))
    ] = {
        "destination": module._claude_projection_canonical_path(str(destination)),
        "relative_path": relative,
        "install_mode": roster_mode,
        "descriptor": roster_descriptor,
    }
    before = module._claude_projection_descriptor(str(destination))
    row_count = len(transaction.rows)
    with pytest.raises(RuntimeError, match="outside its exact roster"):
        transaction.add_link_or_copy(
            str(source), str(destination), lambda *_a: None,
        )
    assert module._claude_projection_descriptor(str(destination)) == before
    assert len(transaction.rows) == row_count


def test_nonlegacy_copy_still_requires_authenticated_pre_plamen_backup(
    monkeypatch, tmp_path,
):
    module = _load()
    claude = tmp_path / ".claude"
    claude.mkdir()
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    transaction = _transaction(monkeypatch, module, tmp_path)
    source = tmp_path / "source-copy"
    destination = tmp_path / "ordinary-copy"
    source.write_bytes(b"same\n")
    destination.write_bytes(b"same\n")
    before = destination.read_bytes()
    with pytest.raises(RuntimeError, match="foreign or modified"):
        transaction.add_link_or_copy(
            str(source), str(destination), lambda *_a: None,
        )
    assert destination.read_bytes() == before
    assert not transaction.rows


def test_exact_legacy_manifest_projection_census_is_single_source_bound(
    monkeypatch, tmp_path,
):
    module = _load()
    source = tmp_path / "checkout"
    installed = tmp_path / "installed"
    claude = tmp_path / ".claude"
    for root in (source, installed, claude):
        root.mkdir()
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    relative_paths = (
        "plamen.py", "scripts", "verification_policy", "agents/skills",
    )
    installed_paths = []
    copied = []
    copied_dirs = []
    for relative in relative_paths:
        source_path = source / Path(relative)
        committed_path = installed / Path(relative)
        destination = claude / Path(relative)
        if "." in Path(relative).name:
            for parent in (source_path.parent, committed_path.parent, destination.parent):
                parent.mkdir(parents=True, exist_ok=True)
            source_path.write_bytes(b"exact-runtime\n")
            committed_path.write_bytes(b"exact-runtime\n")
            destination.write_bytes(b"exact-runtime\n")
            copied.append(str(destination.absolute()))
        else:
            for directory in (source_path, committed_path, destination):
                directory.mkdir(parents=True, exist_ok=True)
            for directory in (source_path, committed_path, destination):
                (directory / "owned.txt").write_bytes(b"exact-runtime\n")
            copied_dirs.append(str(destination.absolute()))
        installed_paths.append(str(destination.absolute()))
    runtime_raw = (installed / "plamen.py").read_bytes()
    bundle = "e" * 64
    manifest = {
        "plamen_home": str(source.absolute()), "version": "2.2.4",
        "runtime_bundle_sha256": bundle,
        "installed": installed_paths, "copied": copied,
        "copied_dirs": copied_dirs, "shims": [], "created_dirs": [],
        "runtime_assets": [{
            "relative_path": "plamen.py",
            "destination": str((claude / "plamen.py").absolute()),
            "source_sha256": hashlib.sha256(runtime_raw).hexdigest(),
            "digest_mode": "raw-v1", "install_mode": "copied",
            "owned": True, "backup_disposition": "none",
        }],
    }
    (claude / module._PLAMEN_MANIFEST).write_text(
        json.dumps(manifest), encoding="utf-8",
    )
    monkeypatch.setattr(
        module, "_toolchain_runtime_bundle_sha256", lambda *_a, **_k: bundle,
    )
    receipt = {
        "schema": module._CODEX_INSTALL_SCHEMA, "state": "COMMITTED",
        "transaction_id": "1" * 32,
        "source_count": 759, "runtime_count": 728, "adapter_count": 31,
        "source_root": str(source.absolute()),
        "plamen_root": str(installed.absolute()),
        "terminal_verification": {
            "verified_count": 759,
            "verified_manifest_sha256": "2" * 64,
            "completed_ns": 1,
        },
    }
    census = module._claude_projection_validate_legacy_projection_ownership(
        receipt
    )
    assert census["projection_count"] == 4
    assert census["runtime_count"] == 1
    assert len(census["projection_roster"]) == 4
    assert census["projection_roster_sha256"] == hashlib.sha256(json.dumps(
        census["projection_roster"], sort_keys=True, separators=(",", ":"),
    ).encode()).hexdigest()

    # A post-B restart is rooted in the committed runtime and the signed A
    # preimage roster. Broken historical checkout targets remain describable;
    # recovery must not read their current bytes or require that root to exist.
    displaced_source = tmp_path / "historical-checkout-removed"
    os.rename(source, displaced_source)
    restarted_census = (
        module._claude_projection_validate_legacy_projection_ownership(receipt)
    )
    assert restarted_census == census

    manifest["plamen_home"] = str((tmp_path / "foreign").absolute())
    (claude / module._PLAMEN_MANIFEST).write_text(
        json.dumps(manifest), encoding="utf-8",
    )
    with pytest.raises(RuntimeError, match="manifest source differs"):
        module._claude_projection_validate_legacy_projection_ownership(receipt)


def test_post_b_replay_uses_signed_a_descriptors_while_staging_changed_b(
    monkeypatch, tmp_path,
):
    module = _load()
    source = tmp_path / "checkout-a"
    installed = tmp_path / "installed-b"
    claude = tmp_path / ".claude"
    codex = tmp_path / ".codex"
    for directory in (source, installed, claude, codex):
        directory.mkdir()
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    installed_paths = []
    copied = []
    copied_dirs = []
    modes = {
        "plamen.py": "copied",
        "scripts": "link",
        "verification_policy": "copied_dir",
        "agents/skills": "copied_dir",
    }
    for relative, mode in modes.items():
        a_source = source / Path(relative)
        b_source = installed / Path(relative)
        destination = claude / Path(relative)
        if mode == "copied":
            for parent in (a_source.parent, b_source.parent, destination.parent):
                parent.mkdir(parents=True, exist_ok=True)
            a_source.write_bytes(b"A-runtime\n")
            b_source.write_bytes(b"A-runtime\n")
            destination.write_bytes(b"A-runtime\n")
            copied.append(str(destination.absolute()))
        else:
            a_source.mkdir(parents=True, exist_ok=True)
            b_source.mkdir(parents=True, exist_ok=True)
            (a_source / "owned").write_bytes(b"A-runtime\n")
            (b_source / "owned").write_bytes(b"A-runtime\n")
            destination.parent.mkdir(parents=True, exist_ok=True)
            if mode == "link":
                os.symlink(a_source, destination, target_is_directory=True)
            else:
                destination.mkdir()
                (destination / "owned").write_bytes(b"A-runtime\n")
                copied_dirs.append(str(destination.absolute()))
        installed_paths.append(str(destination.absolute()))
    runtime_raw = (installed / "plamen.py").read_bytes()
    manifest = {
        "plamen_home": str(source.absolute()), "version": "2.2.4",
        "runtime_bundle_sha256": "e" * 64,
        "installed": installed_paths, "copied": copied,
        "copied_dirs": copied_dirs, "shims": [], "created_dirs": [],
        "runtime_assets": [{
            "relative_path": "plamen.py",
            "destination": str((claude / "plamen.py").absolute()),
            "source_sha256": hashlib.sha256(runtime_raw).hexdigest(),
            "digest_mode": "raw-v1", "install_mode": "copied",
            "owned": True, "backup_disposition": "none",
        }],
    }
    manifest_path = claude / module._PLAMEN_MANIFEST
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(
        module, "_toolchain_runtime_bundle_sha256",
        lambda *_a, **_k: "e" * 64,
    )
    receipt_a = {
        "schema": module._CODEX_INSTALL_SCHEMA, "state": "COMMITTED",
        "transaction_id": "1" * 32,
        "source_count": 759, "runtime_count": 728, "adapter_count": 31,
        "source_root": str(source.absolute()),
        "plamen_root": str(installed.absolute()),
        "terminal_verification": {
            "verified_count": 759, "verified_manifest_sha256": "2" * 64,
            "completed_ns": 1,
        },
    }
    census_a = module._claude_projection_validate_legacy_projection_ownership(
        receipt_a
    )
    lock_path = claude / ".plamen-projection.lock"
    lock_path.write_bytes(b"\x00")
    lock_authority = module._claude_projection_legacy_lock_authority(
        str(lock_path), b"\x00", lock_path.stat(follow_symlinks=False),
    )
    migration = {
        "schema": module._CLAUDE_PROJECTION_LEGACY_MIGRATION_SCHEMA,
        "migration_id": "a" * 32,
        "prior_transaction_id": "1" * 32,
        "prior_receipt_sha256": "3" * 64,
        "legacy_source_root": str(source.absolute()),
        "legacy_lock": lock_authority,
        "successor_lock_sha256": "4" * 64,
        "legacy_manifest_sha256": census_a["manifest_sha256"],
        "legacy_projection_count": census_a["projection_count"],
        "legacy_runtime_count": census_a["runtime_count"],
        "legacy_projection_roster": census_a["projection_roster"],
        "legacy_projection_roster_sha256": census_a[
            "projection_roster_sha256"
        ],
        "prior_anchor_identity": [11, 12],
        "prepackage_intent_sha256": None,
    }
    receipt_b = dict(receipt_a)
    receipt_b.update({
        "source_count": module._CODEX_INSTALL_SOURCE_COUNT,
        "runtime_count": module._CODEX_INSTALL_RUNTIME_COUNT,
        "adapter_count": module._CODEX_INSTALL_ADAPTER_COUNT,
    })
    receipt_b["lock_identity"] = [11, 12]
    receipt_b["terminal_verification"] = {
        "verified_count": module._CODEX_INSTALL_SOURCE_COUNT,
        "verified_manifest_sha256": "2" * 64,
        "completed_ns": 2, "projection_public_key": "5" * 64,
        "projection_lock_public_key": "5" * 64,
        "projection_lock_authority_sha256": "6" * 64,
        "legacy_projection_migration": migration,
    }
    # B is independently authenticated by its package receipt and may differ
    # everywhere from the signed A predecessor descriptors.
    (installed / "plamen.py").write_bytes(b"B-runtime\n")
    for relative in ("scripts", "verification_policy", "agents/skills"):
        (installed / Path(relative) / "owned").write_bytes(b"B-runtime\n")
    assert module._claude_projection_validate_legacy_projection_ownership(
        receipt_b, require_legacy_receipt=False,
    ) == census_a

    transaction = object.__new__(module._ClaudeProjectionTransaction)
    transaction.legacy_lock_migration = migration
    transaction.legacy_projection_roster = {
        os.path.normcase(row["destination"]): row
        for row in census_a["projection_roster"]
    }
    transaction.rows = []
    transaction.stage_root = str(tmp_path / "stage")
    transaction.backup_root = str(tmp_path / "backup")
    for relative in ("plamen.py", "scripts", "verification_policy"):
        destination = claude / Path(relative)
        before = module._claude_projection_descriptor(str(destination))
        assert transaction.add_link_or_copy(
            str(installed / Path(relative)), str(destination), lambda *_a: None,
            admitted_prior_targets=(str(source / Path(relative)),),
        )
        assert module._claude_projection_descriptor(str(destination)) == before

    (claude / "plamen.py").write_bytes(b"A-drift\n")
    with pytest.raises(RuntimeError, match="replay roster differs"):
        module._claude_projection_validate_legacy_projection_ownership(
            receipt_b, require_legacy_receipt=False,
        )
    assert (claude / "plamen.py").read_bytes() == b"A-drift\n"


@pytest.mark.skipif(os.name != "nt", reason="Windows extended-path junction replay")
def test_incomplete_b_long_receipt_snapshot_stages_and_crash_recovers(
    monkeypatch, tmp_path,
):
    module = _load()
    transaction, lock_path, _successor_raw = _legacy_projection_transaction(
        monkeypatch, module, tmp_path,
    )
    legacy_root = Path(transaction.legacy_lock_migration["legacy_source_root"])
    committed_root = Path(transaction.authority["plamen_root"])
    legacy_scripts = legacy_root / "scripts"
    committed_scripts = committed_root / "scripts"
    legacy_scripts.mkdir(); committed_scripts.mkdir()
    nested = Path(
        "bounty_targets/sparklend/target_src/a5/lib/aave-v3-core/"
        "contracts/protocol/libraries/aave-upgradeability/"
        "InitializableImmutableAdminUpgradeabilityProxy.sol"
    )
    for root, raw in (
        (legacy_scripts, b"legacy-A\n"),
        (committed_scripts, b"committed-B\n"),
    ):
        leaf = root / nested
        os.makedirs(module._fs_path(leaf.parent), exist_ok=True)
        with open(module._fs_path(leaf), "wb") as stream:
            stream.write(raw)

    destination = Path(module.CLAUDE_HOME) / "scripts"
    subprocess.run(
        [
            "cmd", "/c", "mklink", "/J",
            os.path.normpath(destination), os.path.normpath(legacy_scripts),
        ],
        check=True, capture_output=True,
    )
    prior = module._claude_projection_descriptor(str(destination))
    assert prior == {"kind": "junction", "target": str(legacy_scripts)}
    transaction.legacy_projection_roster[
        os.path.normcase(module._claude_projection_canonical_path(str(destination)))
    ] = {
        "destination": module._claude_projection_canonical_path(str(destination)),
        "relative_path": "scripts", "install_mode": "link",
        "descriptor": prior,
    }

    source_leaf = committed_scripts / nested
    terminal_authority, source_raw = module._codex_install_committed_descriptor(
        committed_root, tuple(("scripts/" + nested.as_posix()).split("/")),
        return_raw=True,
    )
    receipt_rows = [{
        "destination_root": "plamen",
        "destination_path": "scripts/" + nested.as_posix(),
        "destination": str(source_leaf),
        "size": len(source_raw),
        "sha256": hashlib.sha256(source_raw).hexdigest(),
        "terminal_authority": terminal_authority,
    }]
    unbound_paths = (
        committed_scripts / "foreign-shadow.py",
        committed_scripts / "sitecustomize.py",
        committed_scripts / "plamen_driver.pyd",
        committed_scripts / "plamen_driver.pyc",
        committed_scripts / "stale-launcher.exe",
    )
    for unbound in unbound_paths:
        unbound.write_bytes(b"must-not-project\n")
    (committed_scripts / "unbound-package" / "nested").mkdir(parents=True)
    (committed_scripts / "unbound-package" / "nested" / "__init__.py").write_bytes(
        b"must-not-project\n"
    )
    status = transaction.add_receipt_tree(
        committed_root, "scripts", str(destination), receipt_rows,
        lambda *_a: None,
        admitted_prior_targets=(str(legacy_scripts),),
    )
    staged = Path(transaction.rows[-1]["staged"])
    staged_leaf = staged / nested
    assert len(str(staged_leaf)) > 260
    assert status == "copied_dir"
    assert not module._is_junction(str(staged))
    for unbound in unbound_paths:
        assert not (staged / unbound.name).exists()
    assert not (staged / "unbound-package").exists()
    with open(module._fs_path(staged_leaf), "rb") as stream:
        assert stream.read() == b"committed-B\n"

    # Model the exact observed crash seam: the signed STAGING journal contains
    # only the legacy lock row while an unjournaled projection artifact exists
    # beneath the authenticated transaction root. A restart must remove only
    # that root and preserve committed B plus the exact legacy preimage.
    staged_rows = transaction.rows
    transaction.rows = []
    transaction.owner_pid = 2_000_000_000
    transaction.owner_started_100ns = 1
    transaction._journal("STAGING")
    transaction.rows = staged_rows
    assert module._recover_claude_projection_transaction(
        _locked=True, _expected_authority=transaction.authority,
    )
    assert not Path(transaction.root).exists()
    assert not Path(module._claude_projection_journal_path()).exists()
    assert lock_path.read_bytes() == b"\x00"
    assert module._claude_projection_descriptor(str(destination)) == prior
    with open(module._fs_path(committed_scripts / nested), "rb") as stream:
        assert stream.read() == b"committed-B\n"


@pytest.mark.skipif(os.name != "nt", reason="Windows extended-path copy fallback")
def test_long_nested_copy_dir_fallback_and_verification_use_extended_paths(
    monkeypatch, tmp_path,
):
    module = _load()
    source = tmp_path / "committed" / "scripts"
    destination = tmp_path / ("staging-prefix-" + "x" * 70) / "scripts"
    nested = Path(
        "bounty_targets/sparklend/target_src/a5/lib/aave-v3-core/"
        "contracts/protocol/libraries/aave-upgradeability/"
        "InitializableImmutableAdminUpgradeabilityProxy.sol"
    )
    leaf = source / nested
    os.makedirs(module._fs_path(leaf.parent), exist_ok=True)
    with open(module._fs_path(leaf), "wb") as stream:
        stream.write(b"committed-copy\n")
    destination.parent.mkdir(parents=True)

    def reject_junction(*_args, **_kwargs):
        raise subprocess.CalledProcessError(1, "mklink")

    monkeypatch.setattr(module.subprocess, "run", reject_junction)
    assert module._safe_link(
        str(source), str(destination), lambda *_a: None,
    ) == "copied_dir"
    assert len(str(destination / nested)) > 260
    assert module._same_install_content(str(source), str(destination))
    with open(module._fs_path(destination / nested), "rb") as stream:
        assert stream.read() == b"committed-copy\n"


@pytest.mark.parametrize("injected_kind", ["file", "empty_dir", "reparse"])
def test_receipt_snapshot_rejects_unbound_staged_entries(
    monkeypatch, tmp_path, injected_kind,
):
    module = _load()
    transaction, _lock_path, _successor = _legacy_projection_transaction(
        monkeypatch, module, tmp_path,
    )
    committed_root = Path(transaction.authority["plamen_root"])
    source = committed_root / "scripts" / "plamen_driver.py"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"bound-runtime\n")
    authority, raw = module._codex_install_committed_descriptor(
        committed_root, ("scripts", "plamen_driver.py"), return_raw=True,
    )
    rows = [{
        "destination_root": "plamen",
        "destination_path": "scripts/plamen_driver.py",
        "destination": str(source),
        "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "terminal_authority": authority,
    }]
    destination = Path(module.CLAUDE_HOME) / "scripts"
    staged = Path(transaction.stage_root) / "000000" / "scripts"
    outside = tmp_path / "outside"
    outside.mkdir()

    def inject(name, _row):
        if name != "before_projection_snapshot_census":
            return
        if injected_kind == "file":
            (staged / "sitecustomize.py").write_bytes(b"shadow\n")
        elif injected_kind == "empty_dir":
            (staged / "shadow-package").mkdir()
        elif os.name == "nt":
            subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(staged / "shadow"), str(outside)],
                check=True, capture_output=True,
            )
        else:
            os.symlink(outside, staged / "shadow", target_is_directory=True)

    monkeypatch.setattr(module, "_CLAUDE_PROJECTION_FAILPOINT", inject)
    with pytest.raises(RuntimeError, match="snapshot contains|snapshot census"):
        transaction.add_receipt_tree(
            committed_root, "scripts", str(destination), rows,
            lambda *_a: None,
        )
    assert transaction.rows == []
    assert source.read_bytes() == b"bound-runtime\n"


def test_receipt_snapshot_rejects_authenticated_hardlink_source(
    monkeypatch, tmp_path,
):
    module = _load()
    transaction, _lock_path, _successor = _legacy_projection_transaction(
        monkeypatch, module, tmp_path,
    )
    committed_root = Path(transaction.authority["plamen_root"])
    source = committed_root / "scripts" / "plamen_driver.py"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"bound-runtime\n")
    alias = committed_root / "scripts" / "driver-alias.py"
    os.link(source, alias)
    authority, raw = module._codex_install_committed_descriptor(
        committed_root, ("scripts", "plamen_driver.py"), return_raw=True,
        allow_stable_foreign_links=True,
    )
    assert authority["links"] == 2
    rows = [{
        "destination_root": "plamen",
        "destination_path": "scripts/plamen_driver.py",
        "destination": str(source),
        "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "terminal_authority": authority,
    }]
    with pytest.raises(RuntimeError, match="hardlinked|snapshot row differs"):
        transaction.add_receipt_tree(
            committed_root, "scripts",
            str(Path(module.CLAUDE_HOME) / "scripts"), rows,
            lambda *_a: None,
        )
    assert transaction.rows == []
    assert source.read_bytes() == alias.read_bytes() == b"bound-runtime\n"


def _signed_projection_state(module, private, receipt, binding, rows):
    rows = [dict(row) for row in rows]
    for row in rows:
        if "authority" not in row:
            row["authority"] = module._claude_projection_state_native_authority(
                row["destination"],
                "directory" if row["install_mode"] == "copied_dir" else "file",
            )
    value = {
        "schema": module._CLAUDE_PROJECTION_STATE_SCHEMA,
        "generation": module._claude_projection_generation_authority(receipt),
        "committed_receipt": binding,
        "rows": sorted(rows, key=lambda row: os.path.normcase(row["destination"])),
        "row_count": len(rows),
    }
    value["roster_sha256"] = hashlib.sha256(json.dumps(
        value["rows"], sort_keys=True, separators=(",", ":"),
    ).encode()).hexdigest()
    value["signature"] = private.sign(
        module._claude_projection_state_bytes(value)
    ).hex()
    return value


def test_signed_projection_state_accepts_only_exact_authenticated_multihop_ancestor(
    monkeypatch, tmp_path,
):
    module = _load()
    claude = tmp_path / ".claude"
    installed = tmp_path / ".plamen"
    codex = tmp_path / ".codex"
    source = tmp_path / "checkout"
    for path in (claude, installed, codex, source):
        path.mkdir()
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    monkeypatch.setattr(
        module, "_claude_projection_key_path",
        lambda *_a: str(tmp_path / "projection-key.json"),
    )
    private, public = module._claude_projection_private_key(create=True)
    receipts = []
    for ordinal, transaction in enumerate(("a", "b", "c", "d"), start=1):
        receipt = _receipt(source, installed, codex)
        receipt["transaction_id"] = transaction * 32
        receipt["source_manifest_sha256"] = f"{ordinal:x}" * 64
        receipt["runtime_manifest_sha256"] = f"{ordinal + 4:x}" * 64
        receipt["adapter_manifest_sha256"] = f"{ordinal + 8:x}" * 64
        receipt["terminal_verification"]["projection_public_key"] = public
        receipts.append(receipt)
    receipt_a, receipt_b, receipt_c, receipt_d = receipts

    def binding(receipt):
        raw = json.dumps(receipt, sort_keys=True).encode()
        return {
            "transaction_id": receipt["transaction_id"],
            "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
        }

    bindings = {receipt["transaction_id"]: binding(receipt) for receipt in receipts}
    walked = []

    def ancestor(receipt, target):
        walked.append((receipt["transaction_id"], target["transaction_id"]))
        return receipt_a if target == bindings[receipt_a["transaction_id"]] else None

    monkeypatch.setattr(module, "_claude_projection_authenticated_ancestor", ancestor)
    raw_d = json.dumps(receipt_d, sort_keys=True).encode()
    (codex / module._CODEX_INSTALL_RECEIPT).write_bytes(raw_d)
    destination = claude / "plamen.py"
    destination.write_bytes(b"projected A\n")
    state_a = _signed_projection_state(
        module, private, receipt_a, bindings[receipt_a["transaction_id"]], [{
            "destination": module._claude_projection_canonical_path(str(destination)),
            "install_mode": "copied",
            "descriptor": module._claude_projection_descriptor(str(destination)),
            "census": None,
        }],
    )
    unsigned_claim = json.loads(json.dumps(state_a))
    unsigned_claim["signature"] = "0" * 128
    with pytest.raises(RuntimeError, match="signature differs"):
        module._validate_claude_projection_state(
            unsigned_claim, receipt_d, allow_direct_predecessor=True,
        )
    assert walked == []
    assert module._validate_claude_projection_state(
        state_a, receipt_d, allow_direct_predecessor=True,
    ) == state_a
    assert walked == [(receipt_d["transaction_id"], receipt_a["transaction_id"])]

    historical_state = json.loads(json.dumps(state_a))
    historical_state["generation"]["version"] = "2.2.4"
    historical_state["signature"] = private.sign(
        module._claude_projection_state_bytes(historical_state)
    ).hex()
    assert module._validate_claude_projection_state(
        historical_state, receipt_d, allow_direct_predecessor=True,
    ) == historical_state
    with pytest.raises(RuntimeError, match="direct predecessor"):
        module._validate_claude_projection_state(state_a, receipt_d)

    forged = json.loads(json.dumps(state_a))
    forged["generation"]["source_manifest_sha256"] = "f" * 64
    forged["signature"] = private.sign(
        module._claude_projection_state_bytes(forged)
    ).hex()
    with pytest.raises(RuntimeError, match="direct predecessor"):
        module._validate_claude_projection_state(
            forged, receipt_d, allow_direct_predecessor=True,
        )


def test_retained_projection_predecessor_binds_exact_bytes_and_roots(
    monkeypatch, tmp_path,
):
    module = _load()
    installed = tmp_path / ".plamen"
    codex = tmp_path / ".codex"
    source = tmp_path / "checkout"
    for path in (installed, codex, source):
        path.mkdir()
    current = _receipt(source, installed, codex)
    current["transaction_id"] = "c" * 32
    predecessor = json.loads(json.dumps(current))
    predecessor["transaction_id"] = "b" * 32
    predecessor["inverse_sha256"] = "e" * 64
    predecessor["terminal_evidence"] = {}
    predecessor["rows"] = [{} for _ in range(predecessor["source_count"])]
    predecessor["journal"] = [{} for _ in range(predecessor["source_count"])]
    raw = json.dumps(predecessor, sort_keys=True).encode()
    binding = {
        "transaction_id": predecessor["transaction_id"],
        "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
    }
    retained = (
        codex / ".plamen-install-transactions" / current["transaction_id"]
        / "receipt-prestate.raw"
    )
    retained.parent.mkdir(parents=True)
    retained.write_bytes(raw)
    validated = []
    def terminal(receipt, receipt_raw, **kwargs):
        validated.append(
            (receipt["transaction_id"], hashlib.sha256(receipt_raw).hexdigest(), kwargs)
        )
        return {
            "transaction_id": receipt["transaction_id"],
            "source_count": receipt["source_count"],
            "source_manifest_sha256": receipt["source_manifest_sha256"],
            "inverse_sha256": receipt["inverse_sha256"],
            "prior_receipt_authority": None,
        }

    monkeypatch.setattr(module, "_validate_codex_install_terminal_evidence", terminal)
    assert module._claude_projection_retained_predecessor_receipt(
        current, binding,
    ) == predecessor
    assert validated[0][0] == predecessor["transaction_id"]
    assert validated[0][1] == binding["sha256"]
    assert validated[0][2]["expected_outcome"] == "COMMITTED"

    retained.write_bytes(raw + b" ")
    with pytest.raises(RuntimeError, match="retained predecessor bytes differ"):
        module._claude_projection_retained_predecessor_receipt(current, binding)


def test_projection_predecessor_walk_rejects_cycles_and_overdepth(
    monkeypatch, tmp_path,
):
    module = _load()
    source = tmp_path / "source"
    installed = tmp_path / ".plamen"
    codex = tmp_path / ".codex"
    for path in (source, installed, codex):
        path.mkdir()

    def receipt(transaction_id):
        value = _receipt(source, installed, codex)
        value["transaction_id"] = transaction_id
        return value

    def binding(value):
        raw = json.dumps(value, sort_keys=True).encode()
        return {
            "transaction_id": value["transaction_id"],
            "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
        }

    first = receipt("a" * 32)
    second = receipt("b" * 32)
    cycle = {
        first["transaction_id"]: second,
        second["transaction_id"]: first,
    }
    monkeypatch.setattr(
        module, "_claude_projection_current_receipt_raw", lambda _current: b"{}",
    )
    monkeypatch.setattr(
        module, "_claude_projection_terminal_precommit",
        lambda current, _raw: {"cursor": current["transaction_id"]},
    )
    monkeypatch.setattr(
        module, "_claude_projection_precommit_binding",
        lambda precommit: binding(cycle[precommit["cursor"]]),
    )
    monkeypatch.setattr(
        module, "_claude_projection_retained_predecessor_receipt",
        lambda current, _binding, return_precommit=False: (
            cycle[current["transaction_id"]],
            {"cursor": cycle[current["transaction_id"]]["transaction_id"]},
        ),
    )
    with pytest.raises(RuntimeError, match="chain cycles"):
        module._claude_projection_authenticated_ancestor(
            first, binding(receipt("c" * 32)),
        )

    chain = [receipt(f"{ordinal:032x}") for ordinal in range(9)]
    next_by_id = {
        chain[index]["transaction_id"]: chain[index + 1]
        for index in range(len(chain) - 1)
    }
    reads = []
    monkeypatch.setattr(
        module, "_claude_projection_precommit_binding",
        lambda precommit: binding(next_by_id[precommit["cursor"]]),
    )

    def retained(current, _binding, return_precommit=False):
        reads.append(current["transaction_id"])
        predecessor = next_by_id[current["transaction_id"]]
        return predecessor, {"cursor": predecessor["transaction_id"]}

    monkeypatch.setattr(
        module, "_claude_projection_retained_predecessor_receipt", retained,
    )
    with pytest.raises(RuntimeError, match="exceeds its bound"):
        module._claude_projection_authenticated_ancestor(
            chain[0], binding(receipt("f" * 32)),
        )
    assert len(reads) == module._CLAUDE_PROJECTION_MAX_PREDECESSOR_HOPS == 8

    budget_chain = [receipt(f"{ordinal + 32:032x}") for ordinal in range(6)]
    budget_next = {
        budget_chain[index]["transaction_id"]: budget_chain[index + 1]
        for index in range(len(budget_chain) - 1)
    }

    def budget_binding(precommit):
        successor = budget_next[precommit["cursor"]]
        return {
            "transaction_id": successor["transaction_id"],
            "size": module._CLAUDE_PROJECTION_MAX_RETAINED_RECEIPT_BYTES,
            "sha256": "e" * 64,
        }

    budget_reads = []
    monkeypatch.setattr(
        module, "_claude_projection_precommit_binding", budget_binding,
    )

    def budget_retained(current, _binding, return_precommit=False):
        budget_reads.append(current["transaction_id"])
        predecessor = budget_next[current["transaction_id"]]
        return predecessor, {"cursor": predecessor["transaction_id"]}

    monkeypatch.setattr(
        module, "_claude_projection_retained_predecessor_receipt",
        budget_retained,
    )
    with pytest.raises(RuntimeError, match="byte budget exceeded"):
        module._claude_projection_authenticated_ancestor(
            budget_chain[0], binding(receipt("f" * 32)),
        )
    assert len(budget_reads) == 4


def test_signed_projection_state_authorizes_changed_direct_successor_and_empty_dirs(
    monkeypatch, tmp_path,
):
    module = _load()
    claude = tmp_path / ".claude"
    installed = tmp_path / ".plamen"
    codex = tmp_path / ".codex"
    source = tmp_path / "checkout"
    for path in (claude, installed, codex, source):
        path.mkdir()
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    monkeypatch.setattr(
        module, "_claude_projection_key_path",
        lambda *_a: str(tmp_path / "projection-key.json"),
    )
    private, public = module._claude_projection_private_key(create=True)
    receipt_c = _receipt(source, installed, codex)
    receipt_c["transaction_id"] = "c" * 32
    receipt_c["terminal_verification"]["projection_public_key"] = public
    receipt_b = json.loads(json.dumps(receipt_c))
    receipt_b["transaction_id"] = "b" * 32
    receipt_b["source_manifest_sha256"] = "6" * 64
    receipt_b["runtime_manifest_sha256"] = "7" * 64
    receipt_b["adapter_manifest_sha256"] = "8" * 64
    raw_b = json.dumps(receipt_b, sort_keys=True).encode()
    binding_b = {
        "transaction_id": receipt_b["transaction_id"],
        "size": len(raw_b), "sha256": hashlib.sha256(raw_b).hexdigest(),
    }
    raw_c = json.dumps(receipt_c, sort_keys=True).encode()
    (codex / module._CODEX_INSTALL_RECEIPT).write_bytes(raw_c)
    destination = claude / "scripts"
    destination.mkdir()
    (destination / "empty-owned").mkdir()
    (destination / "plamen_driver.py").write_bytes(b"B\n")
    removed_destination = claude / "removed-command.md"
    removed_destination.write_bytes(b"removed in C\n")
    prior_descriptor = module._claude_projection_descriptor(str(destination))
    prior_census = module._claude_projection_census_authority(str(destination))
    state_b = _signed_projection_state(module, private, receipt_b, binding_b, [
        {
            "destination": module._claude_projection_canonical_path(
                str(destination)
            ),
            "install_mode": "copied_dir",
            "descriptor": prior_descriptor,
            "census": prior_census,
        },
        {
            "destination": module._claude_projection_canonical_path(
                str(removed_destination)
            ),
            "install_mode": "copied",
            "descriptor": module._claude_projection_descriptor(
                str(removed_destination)
            ),
            "census": None,
        },
    ])
    (claude / ".plamen-projection-state.json").write_text(
        json.dumps(state_b, sort_keys=True), encoding="utf-8",
    )
    monkeypatch.setattr(
        module, "_claude_projection_prior_receipt_binding", lambda _r: binding_b,
    )
    monkeypatch.setattr(
        module, "_claude_projection_authenticated_ancestor",
        lambda receipt, target: (
            receipt_b
            if receipt.get("transaction_id") == receipt_c["transaction_id"]
            and target == binding_b else None
        ),
    )
    with pytest.raises(RuntimeError, match="direct predecessor"):
        module._load_claude_projection_state(receipt_c, required=True)
    monkeypatch.setattr(
        module, "_validated_committed_install_receipt", lambda: receipt_c,
    )
    with pytest.raises(RuntimeError, match="direct predecessor"):
        module._refuse_pending_claude_projection()
    loaded = module._load_claude_projection_state(
        receipt_c, required=True, allow_direct_predecessor=True,
    )
    assert loaded == state_b
    collision = json.loads(json.dumps(state_b))
    collision["rows"].append(dict(collision["rows"][0]))
    collision["row_count"] = len(collision["rows"])
    collision["roster_sha256"] = hashlib.sha256(json.dumps(
        collision["rows"], sort_keys=True, separators=(",", ":"),
    ).encode()).hexdigest()
    collision["signature"] = private.sign(
        module._claude_projection_state_bytes(collision)
    ).hex()
    with pytest.raises(RuntimeError, match="aliased or unordered"):
        module._validate_claude_projection_state(
            collision, receipt_c, allow_direct_predecessor=True,
        )

    (destination / "empty-owned").rmdir()
    with pytest.raises(RuntimeError, match="destination drifted"):
        module._load_claude_projection_state(
            receipt_c, required=True, allow_direct_predecessor=True,
        )
    (destination / "empty-owned").mkdir()
    assert module._load_claude_projection_state(
        receipt_c, required=True, allow_direct_predecessor=True,
    ) == state_b

    committed_file = installed / "scripts" / "plamen_driver.py"
    committed_file.parent.mkdir()
    committed_file.write_bytes(b"C\n")
    authority, raw = module._codex_install_committed_descriptor(
        installed, ("scripts", "plamen_driver.py"), return_raw=True,
    )
    transaction = object.__new__(module._ClaudeProjectionTransaction)
    transaction.rows = []
    transaction.stage_root = str(tmp_path / "stage")
    transaction.backup_root = str(tmp_path / "backup")
    transaction.legacy_lock_migration = None
    transaction.legacy_projection_roster = {}
    transaction.prior_projection_state = loaded
    transaction.prior_projection_rows = {
        os.path.normcase(row["destination"]): row for row in loaded["rows"]
    }
    transaction.committed_receipt = receipt_c
    transaction.authority = module._claude_projection_generation_authority(
        receipt_c
    )
    transaction._signing_key = private
    rows = [{
        "destination_root": "plamen",
        "destination_path": "scripts/plamen_driver.py",
        "destination": str(committed_file),
        "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
        "terminal_authority": authority,
    }]
    assert transaction.add_receipt_tree(
        installed, "scripts", str(destination), rows, lambda *_a: None,
    ) == "copied_dir"
    assert destination.joinpath("plamen_driver.py").read_bytes() == b"B\n"
    assert Path(transaction.rows[-1]["staged"]).joinpath(
        "plamen_driver.py"
    ).read_bytes() == b"C\n"
    transaction.add_projection_state()
    removed_rows = [
        row for row in transaction.rows
        if os.path.normcase(row["destination"])
        == os.path.normcase(str(removed_destination))
    ]
    assert len(removed_rows) == 1
    assert removed_rows[0]["successor"] == {"kind": "absent"}
    staged_state = json.loads(
        Path(transaction.rows[-1]["staged"]).read_text(encoding="utf-8")
    )
    assert all(
        os.path.normcase(row["destination"])
        != os.path.normcase(str(removed_destination))
        for row in staged_state["rows"]
    )
    assert removed_destination.read_bytes() == b"removed in C\n"
    binding_c = {
        "transaction_id": receipt_c["transaction_id"], "size": len(raw_c),
        "sha256": hashlib.sha256(raw_c).hexdigest(),
    }
    receipt_d = json.loads(json.dumps(receipt_c))
    receipt_d["transaction_id"] = "d" * 32
    raw_d = json.dumps(receipt_d, sort_keys=True).encode()
    (codex / module._CODEX_INSTALL_RECEIPT).write_bytes(raw_d)
    monkeypatch.setattr(
        module, "_claude_projection_prior_receipt_binding", lambda _r: binding_c,
    )
    with pytest.raises(RuntimeError, match="direct predecessor"):
        module._validate_claude_projection_state(
            state_b, receipt_d, allow_direct_predecessor=True,
        )


@pytest.mark.parametrize("directory", [False, True])
def test_receipt_snapshot_rejects_identical_unmanaged_ordinary_path(
    monkeypatch, tmp_path, directory,
):
    module = _load()
    transaction, _lock_path, _successor = _legacy_projection_transaction(
        monkeypatch, module, tmp_path,
    )
    transaction.legacy_lock_migration = None
    transaction.legacy_projection_roster = {}
    transaction.prior_projection_state = None
    transaction.prior_projection_rows = {}
    installed = Path(transaction.authority["plamen_root"])
    relative = "scripts/plamen_driver.py"
    source = installed / Path(relative)
    source.parent.mkdir(parents=True)
    source.write_bytes(b"identical\n")
    authority, raw = module._codex_install_committed_descriptor(
        installed, tuple(relative.split("/")), return_raw=True,
    )
    rows = [{
        "destination_root": "plamen", "destination_path": relative,
        "destination": str(source), "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "terminal_authority": authority,
    }]
    if directory:
        destination = Path(module.CLAUDE_HOME) / "scripts"
        destination.mkdir()
        (destination / "plamen_driver.py").write_bytes(raw)
        call = lambda: transaction.add_receipt_tree(
            installed, "scripts", str(destination), rows, lambda *_a: None,
        )
    else:
        destination = Path(module.CLAUDE_HOME) / "plamen_driver.py"
        destination.write_bytes(raw)
        file_rows = [dict(rows[0], destination_path="plamen_driver.py")]
        direct = installed / "plamen_driver.py"
        direct.write_bytes(raw)
        direct_authority, direct_raw = module._codex_install_committed_descriptor(
            installed, ("plamen_driver.py",), return_raw=True,
        )
        file_rows[0].update({
            "destination": str(direct), "terminal_authority": direct_authority,
            "size": len(direct_raw),
            "sha256": hashlib.sha256(direct_raw).hexdigest(),
        })
        call = lambda: transaction.add_receipt_file(
            installed, "plamen_driver.py", str(destination), file_rows,
        )
    before = module._claude_projection_descriptor(str(destination))
    with pytest.raises(RuntimeError, match="foreign or modified"):
        call()
    assert module._claude_projection_descriptor(str(destination)) == before


def test_projection_state_rejects_self_key_tamper_before_live_traversal(
    monkeypatch, tmp_path,
):
    module = _load()
    claude = tmp_path / ".claude"; installed = tmp_path / ".plamen"
    codex = tmp_path / ".codex"; source = tmp_path / "source"
    for path in (claude, installed, codex, source): path.mkdir()
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    monkeypatch.setattr(
        module, "_claude_projection_key_path",
        lambda *_a: str(tmp_path / "trusted-key.json"),
    )
    trusted_private, trusted_public = module._claude_projection_private_key(
        create=True,
    )
    receipt = _receipt(source, installed, codex)
    receipt["terminal_verification"]["projection_public_key"] = trusted_public
    raw = json.dumps(receipt, sort_keys=True).encode()
    (codex / module._CODEX_INSTALL_RECEIPT).write_bytes(raw)
    binding = {
        "transaction_id": receipt["transaction_id"], "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    victim = claude / "victim.py"; victim.write_bytes(b"trusted\n")
    row = {
        "destination": str(victim), "install_mode": "copied",
        "descriptor": module._claude_projection_descriptor(str(victim)),
        "census": None,
    }
    state = _signed_projection_state(
        module, trusted_private, receipt, binding, [row],
    )
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    attacker = Ed25519PrivateKey.generate()
    attacker_public = attacker.public_key().public_bytes_raw().hex()
    state["generation"] = dict(state["generation"])
    state["generation"]["projection_public_key"] = attacker_public
    state["signature"] = attacker.sign(
        module._claude_projection_state_bytes(state)
    ).hex()
    monkeypatch.setattr(
        module, "_claude_projection_state_row_matches",
        lambda *_a: (_ for _ in ()).throw(AssertionError("live traversal")),
    )
    with pytest.raises(RuntimeError, match="direct predecessor"):
        module._validate_claude_projection_state(state, receipt)
    assert victim.read_bytes() == b"trusted\n"


@pytest.mark.parametrize("directory", [False, True])
def test_projection_state_rejects_same_byte_hardlink_substitution(
    monkeypatch, tmp_path, directory,
):
    module = _load()
    claude = tmp_path / ".claude"; installed = tmp_path / ".plamen"
    codex = tmp_path / ".codex"; source = tmp_path / "source"
    for path in (claude, installed, codex, source): path.mkdir()
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    monkeypatch.setattr(
        module, "_claude_projection_key_path",
        lambda *_a: str(tmp_path / "trusted-key.json"),
    )
    private, public = module._claude_projection_private_key(create=True)
    receipt = _receipt(source, installed, codex)
    receipt["terminal_verification"]["projection_public_key"] = public
    raw = json.dumps(receipt, sort_keys=True).encode()
    (codex / module._CODEX_INSTALL_RECEIPT).write_bytes(raw)
    binding = {
        "transaction_id": receipt["transaction_id"], "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    if directory:
        destination = claude / "scripts"
        destination.mkdir()
        owned = destination / "owned.py"
        install_mode = "copied_dir"
    else:
        destination = claude / "plamen.py"
        owned = destination
        install_mode = "copied"
    owned.write_bytes(b"same bytes\n")
    row = {
        "destination": str(destination), "install_mode": install_mode,
        "descriptor": module._claude_projection_descriptor(str(destination)),
        "census": (
            module._claude_projection_census_authority(str(destination))
            if directory else None
        ),
    }
    state = _signed_projection_state(
        module, private, receipt, binding, [row],
    )
    Path(module._claude_projection_state_path()).write_text(
        json.dumps(state, sort_keys=True), encoding="utf-8",
    )
    assert module._load_claude_projection_state(receipt, required=True) == state
    monkeypatch.setattr(
        module, "_validated_committed_install_receipt", lambda: receipt,
    )
    assert module._assert_claude_projection_current() == {
        "schema": "plamen.claude_projection_current.v1",
        "state": "CURRENT",
    }

    donor = claude / "same-byte-donor"
    donor.write_bytes(owned.read_bytes())
    owned.unlink()
    os.link(donor, owned)
    assert module._claude_projection_descriptor(str(destination)) == row["descriptor"]
    with pytest.raises(RuntimeError, match="destination drifted"):
        module._load_claude_projection_state(receipt, required=True)
    with pytest.raises(RuntimeError, match="destination drifted"):
        module._assert_claude_projection_current()
    assert donor.read_bytes() == owned.read_bytes() == b"same bytes\n"


def test_projection_state_posix_dispatch_never_uses_windows_descriptor(
    monkeypatch, tmp_path,
):
    module = _load()
    target = tmp_path / "owned.py"
    target.write_bytes(b"owned\n")
    sentinel = {"posix": True}
    calls = []
    monkeypatch.setattr(module.os, "name", "posix")
    monkeypatch.setattr(
        module, "_claude_projection_posix_native_authority",
        lambda path, kind: calls.append((path, kind)) or sentinel,
    )
    monkeypatch.setattr(
        module, "_codex_install_committed_descriptor",
        lambda *_a, **_k: (_ for _ in ()).throw(
            AssertionError("Windows/native dispatcher reached on POSIX")
        ),
    )
    assert module._claude_projection_state_native_authority(
        str(target), "file",
    ) is sentinel
    assert calls == [(str(target), "file")]
    source = _PLAMEN.read_text(encoding="utf-8")
    body = source[source.index(
        "def _claude_projection_posix_native_authority("
    ):source.index("\ndef _claude_projection_state_native_authority(")]
    for required in (
        "O_NOFOLLOW", "dir_fd=parent", "follow_symlinks=False",
        "os.fstat", "os.pread", "st_nlink", "st_mode",
        "_claude_projection_posix_fd_xattrs",
    ):
        assert required in body
    assert "_codex_install_committed_descriptor" not in body
    xattr_body = source[source.index(
        "def _claude_projection_posix_fd_xattrs("
    ):source.index("\ndef _claude_projection_posix_native_authority(")]
    assert 'sys.platform != "darwin"' in xattr_body
    assert "libc.flistxattr" in xattr_body
    assert "libc.fgetxattr" in xattr_body


@pytest.mark.skipif(os.name == "nt", reason="real POSIX fd-relative authority")
def test_posix_projection_state_rejects_symlink_hardlink_and_mode_drift(
    tmp_path,
):
    module = _load()
    owned = tmp_path / "owned.py"
    owned.write_bytes(b"owned\n")
    authority = module._claude_projection_state_native_authority(
        str(owned), "file",
    )
    assert authority["kind"] == "file"
    assert authority["links"] == 1
    assert authority["reparse_tag"] == 0

    original_mode = owned.stat(follow_symlinks=False).st_mode
    os.chmod(owned, original_mode ^ 0o100)
    assert module._claude_projection_state_native_authority(
        str(owned), "file",
    ) != authority
    os.chmod(owned, original_mode)

    symlink = tmp_path / "linked.py"
    symlink.symlink_to(owned)
    with pytest.raises(RuntimeError, match="authority is unavailable"):
        module._claude_projection_state_native_authority(str(symlink), "file")

    alias = tmp_path / "alias.py"
    os.link(owned, alias)
    with pytest.raises(RuntimeError, match="hardlinked"):
        module._claude_projection_state_native_authority(str(owned), "file")

    tree = tmp_path / "scripts"
    tree.mkdir()
    nested = tree / "nested.py"
    nested.write_bytes(b"nested\n")
    census = module._claude_projection_census_authority(str(tree))
    nested_mode = nested.stat(follow_symlinks=False).st_mode
    os.chmod(nested, nested_mode ^ 0o100)
    assert module._claude_projection_census_authority(str(tree)) != census


def test_internal_current_projection_command_has_exact_read_only_contract(
    monkeypatch, capsys,
):
    module = _load()
    calls = []
    monkeypatch.setattr(
        module, "_assert_claude_projection_current",
        lambda: calls.append("asserted") or {
            "schema": "plamen.claude_projection_current.v1",
            "state": "CURRENT",
        },
    )
    command = "--codex-install-assert-claude-projection-current"
    monkeypatch.setattr(module.sys, "argv", ["plamen.py", command])
    module.main()
    assert calls == ["asserted"]
    assert capsys.readouterr().out == (
        '{"schema":"plamen.claude_projection_current.v1",'
        '"state":"CURRENT"}\n'
    )

    monkeypatch.setattr(module.sys, "argv", ["plamen.py", command, "extra"])
    with pytest.raises(SystemExit) as denied:
        module.main()
    assert denied.value.code == 75
    assert calls == ["asserted"]


def test_projection_state_final_row_crash_rolls_back_runtime_state_and_legacy_lock(
    monkeypatch, tmp_path,
):
    module = _load()
    transaction, lock_path, _successor = _legacy_projection_transaction(
        monkeypatch, module, tmp_path,
    )
    receipt = transaction.committed_receipt
    receipt_path = Path(receipt["codex_root"]) / module._CODEX_INSTALL_RECEIPT
    receipt_path.write_text(json.dumps(receipt, sort_keys=True), encoding="utf-8")
    source = Path(receipt["plamen_root"]) / "plamen.py"
    source.write_bytes(b"committed-runtime\n")
    authority, raw = module._codex_install_committed_descriptor(
        Path(receipt["plamen_root"]), ("plamen.py",), return_raw=True,
    )
    destination = Path(module.CLAUDE_HOME) / "plamen.py"
    rows = [{
        "destination_root": "plamen", "destination_path": "plamen.py",
        "destination": str(source), "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "terminal_authority": authority,
    }]
    transaction.add_receipt_file(
        Path(receipt["plamen_root"]), "plamen.py", str(destination), rows,
    )
    transaction.add_projection_state()
    state_ordinal = len(transaction.rows) - 1

    def crash(name, ordinal):
        if name == "after_projection_replace" and ordinal == state_ordinal:
            raise RuntimeError("crash-after-state")

    monkeypatch.setattr(module, "_CLAUDE_PROJECTION_FAILPOINT", crash)
    with pytest.raises(RuntimeError, match="crash-after-state"):
        transaction.commit()
    assert not destination.exists()
    assert not Path(module._claude_projection_state_path()).exists()
    assert lock_path.read_bytes() == b"\x00"
    assert not Path(module._claude_projection_journal_path()).exists()


def test_signed_state_removed_destination_crash_restores_exact_predecessor(
    monkeypatch, tmp_path,
):
    module = _load()
    claude = tmp_path / ".claude"
    claude.mkdir()
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    transaction = _transaction(monkeypatch, module, tmp_path)
    receipt = transaction.committed_receipt
    receipt_raw = json.dumps(receipt, sort_keys=True).encode()
    receipt_path = Path(receipt["codex_root"]) / module._CODEX_INSTALL_RECEIPT
    receipt_path.write_bytes(receipt_raw)
    binding = {
        "transaction_id": receipt["transaction_id"],
        "size": len(receipt_raw),
        "sha256": hashlib.sha256(receipt_raw).hexdigest(),
    }

    retained = claude / "plamen.py"
    retired = claude / "retired.py"
    retained.write_bytes(b"B retained\n")
    retired.write_bytes(b"B retired\n")
    state = _signed_projection_state(
        module, transaction._signing_key, receipt, binding,
        [
            {
                "destination": str(retained), "install_mode": "copied",
                "descriptor": module._claude_projection_descriptor(
                    str(retained)
                ),
                "census": None,
            },
            {
                "destination": str(retired), "install_mode": "copied",
                "descriptor": module._claude_projection_descriptor(str(retired)),
                "census": None,
            },
        ],
    )
    state_path = Path(module._claude_projection_state_path())
    state_raw = (json.dumps(
        state, sort_keys=True, separators=(",", ":"),
    ) + "\n").encode()
    state_path.write_bytes(state_raw)
    transaction.prior_projection_state = state
    transaction.prior_projection_rows = {
        os.path.normcase(row["destination"]): row for row in state["rows"]
    }

    committed = Path(receipt["plamen_root"]) / "plamen.py"
    committed.write_bytes(b"C retained\n")
    authority, raw = module._codex_install_committed_descriptor(
        Path(receipt["plamen_root"]), ("plamen.py",), return_raw=True,
    )
    transaction.add_receipt_file(
        Path(receipt["plamen_root"]), "plamen.py", str(retained), [{
            "destination_root": "plamen", "destination_path": "plamen.py",
            "destination": str(committed), "size": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "terminal_authority": authority,
        }],
    )
    transaction.add_projection_state()
    retired_ordinal = next(
        ordinal for ordinal, row in enumerate(transaction.rows)
        if os.path.normcase(row["destination"]) == os.path.normcase(str(retired))
    )

    def failpoint(name, ordinal):
        if name == "after_projection_replace" and ordinal == retired_ordinal:
            raise RuntimeError("crash-after-retired-row")

    monkeypatch.setattr(module, "_CLAUDE_PROJECTION_FAILPOINT", failpoint)
    with pytest.raises(RuntimeError, match="crash-after-retired-row"):
        transaction.commit()
    assert retained.read_bytes() == b"B retained\n"
    assert retired.read_bytes() == b"B retired\n"
    assert state_path.read_bytes() == state_raw
    assert not module._claude_projection_pending()


def test_posix_legacy_lock_retained_move_preserves_exact_inode(
    tmp_path,
):
    if os.name == "nt":
        pytest.skip("POSIX retained-inode rename semantics")
    module = _load()
    lock = tmp_path / "legacy.lock"
    backup = tmp_path / "transaction" / "legacy.preimage"
    backup.parent.mkdir()
    lock.write_bytes(b"\x00")
    descriptor = os.open(lock, os.O_RDWR)
    try:
        stat = os.fstat(descriptor)
        authority = module._claude_projection_legacy_lock_authority(
            str(lock), b"\x00", stat,
        )
        module._claude_projection_move_retained_lock(
            descriptor, authority, str(backup),
        )
        moved = backup.stat(follow_symlinks=False)
        assert not lock.exists()
        assert backup.read_bytes() == b"\x00"
        assert (int(moved.st_dev), int(moved.st_ino)) == (
            authority["device"], authority["inode"],
        )
    finally:
        os.close(descriptor)


def test_projection_cleanup_durably_unlinks_journal_last(monkeypatch, tmp_path):
    module = _load()
    claude = tmp_path / ".claude"
    claude.mkdir()
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    transaction = _transaction(monkeypatch, module, tmp_path)
    destination = claude / "settings.json"
    transaction.add_bytes(str(destination), b"successor\n", kind="config")
    events = []
    real_unlink = module._claude_projection_durable_unlink
    real_rmtree = module._claude_projection_durable_rmtree

    def unlink(path):
        events.append(("unlink", os.path.abspath(path)))
        return real_unlink(path)

    def rmtree(path):
        events.append(("rmtree", os.path.abspath(path)))
        return real_rmtree(path)

    monkeypatch.setattr(module, "_claude_projection_durable_unlink", unlink)
    monkeypatch.setattr(module, "_claude_projection_durable_rmtree", rmtree)
    transaction.commit()
    journal = os.path.abspath(module._claude_projection_journal_path())
    assert ("unlink", journal) in events
    journal_retirement = events.index(("unlink", journal))
    assert all(kind == "rmtree" for kind, _path in events[journal_retirement + 1:])
    assert not os.path.exists(journal)
    assert destination.read_bytes() == b"successor\n"


def test_projection_rollback_durably_unlinks_journal_only_after_poststate(
    monkeypatch, tmp_path,
):
    module = _load()
    claude = tmp_path / ".claude"
    claude.mkdir()
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    transaction = _transaction(monkeypatch, module, tmp_path)
    destination = claude / "settings.json"
    destination.write_bytes(b"prior\n")
    transaction.add_bytes(str(destination), b"successor\n", kind="config")
    events = []
    real_unlink = module._claude_projection_durable_unlink
    real_replace = module._claude_projection_replace

    def unlink(path):
        events.append(("unlink", os.path.abspath(path)))
        return real_unlink(path)

    def replace(source, destination_path):
        result = real_replace(source, destination_path)
        events.append(("replace", os.path.abspath(destination_path)))
        return result

    monkeypatch.setattr(module, "_claude_projection_durable_unlink", unlink)
    monkeypatch.setattr(module, "_claude_projection_replace", replace)
    monkeypatch.setattr(
        module, "_CLAUDE_PROJECTION_FAILPOINT", "after_projection_replace",
    )
    with pytest.raises(RuntimeError, match="CLAUDE_PROJECTION_FAILPOINT"):
        transaction.commit()
    journal = os.path.abspath(module._claude_projection_journal_path())
    assert events[-1] == ("unlink", journal)
    assert destination.read_bytes() == b"prior\n"
    assert not os.path.exists(journal)


def test_windows_trash_and_journal_retirement_use_write_through(
    monkeypatch, tmp_path,
):
    module = _load()
    import ctypes

    calls = []

    class Function:
        def __init__(self, call):
            self.call = call
            self.restype = None

        def __call__(self, *args):
            return self.call(*args)

    def move(source, destination, flags):
        calls.append((source.value, destination.value, flags.value))
        os.rename(source.value, destination.value)
        return 1

    class Kernel:
        def __init__(self):
            self.CreateFileW = Function(lambda *_a: 123)
            self.MoveFileExW = Function(move)
            self.CloseHandle = Function(lambda *_a: 1)

    monkeypatch.setattr(module.os, "name", "nt")
    monkeypatch.setattr(ctypes, "WinDLL", lambda *_a, **_k: Kernel())
    monkeypatch.setattr(
        module, "_borrowed_reader_handle_identity",
        lambda _handle: {
            "volume": 1, "file_id": 2, "attributes": 0x10,
            "reparse_tag": 0, "links": 1, "size": 0,
        },
    )
    source = str(tmp_path / "live")
    trash = str(tmp_path / "transaction" / "trash")
    Path(source).write_bytes(b"live")
    authority = _trash_authority(
        module, tmp_path / "transaction", Path(trash),
        identity={
            "volume": 1, "file_id": 2, "attributes": 0x10,
            "reparse_tag": 0,
        },
    )
    moved = module._claude_projection_move_to_trash(
        source, trash, expected_authority=authority,
    )
    assert moved.startswith(trash)
    journal = tmp_path / "journal"
    journal.write_bytes(b"journal")
    module._claude_projection_durable_unlink(str(journal))
    assert [flags for _source, _destination, flags in calls] == [0x8, 0x8]
    assert calls[0][1].startswith(trash)
    assert ".plamen-retired-" in calls[1][1]


@pytest.mark.parametrize("kind", ("symlink", "junction"))
def test_windows_trash_reparse_to_outside_is_rejected_without_source_change(
    monkeypatch, tmp_path, kind,
):
    module = _load()
    transaction = tmp_path / "transaction"
    transaction.mkdir()
    (transaction / ".plamen-transaction-owned").write_bytes(
        b"1" * 32 + b"\n",
    )
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel"
    sentinel.write_bytes(b"outside\n")
    trash = transaction / "trash"
    if kind == "symlink":
        try:
            os.symlink(outside, trash, target_is_directory=True)
        except OSError as exc:
            pytest.skip(f"directory symlink unavailable: {exc}")
    else:
        trash.mkdir()
        (trash / ".plamen-trash-owned").write_bytes(b"1" * 32 + b"\n")
        real_is_junction = module._is_junction
        monkeypatch.setattr(
            module, "_is_junction",
            lambda path: (
                os.path.normcase(os.path.abspath(path))
                == os.path.normcase(os.path.abspath(trash))
                or real_is_junction(path)
            ),
        )
    source = tmp_path / "source"
    source.write_bytes(b"source\n")
    with pytest.raises(RuntimeError, match="reparse|authority"):
        module._claude_projection_move_to_trash(
            str(source), str(trash), expected_authority={
                "path": module._claude_projection_canonical_path(str(trash)),
                "identity": {
                    "volume": 1, "file_id": 2, "attributes": 0x10,
                    "reparse_tag": 0,
                },
                "marker_sha256": hashlib.sha256(b"1" * 32 + b"\n").hexdigest(),
            },
        )
    assert source.read_bytes() == b"source\n"
    assert sentinel.read_bytes() == b"outside\n"


def test_windows_retained_trash_handle_blocks_replacement_race(
    monkeypatch, tmp_path,
):
    module = _load()
    import ctypes
    from ctypes import wintypes

    transaction = tmp_path / "transaction"
    trash = transaction / "trash"
    transaction.mkdir()
    authority = _trash_authority(
        module, transaction, trash,
        identity={
            "volume": 1, "file_id": 2, "attributes": 0x10,
            "reparse_tag": 0,
        },
    )
    source = tmp_path / "source"
    source.write_bytes(b"source\n")
    moved_root = tmp_path / "replaced-trash"
    real = ctypes.WinDLL("kernel32", use_last_error=True)
    real.CreateFileW.restype = wintypes.HANDLE
    blocked = {"value": False}

    class Function:
        def __init__(self, call):
            self.call = call
            self.restype = None

        def __call__(self, *args):
            return self.call(*args)

    def adversarial_move(_source, _destination, _flags):
        try:
            os.rename(trash, moved_root)
        except OSError:
            blocked["value"] = True
        return 0

    class Kernel:
        def __init__(self):
            self.CreateFileW = Function(lambda *args: real.CreateFileW(*args))
            self.MoveFileExW = Function(adversarial_move)
            self.CloseHandle = Function(lambda handle: real.CloseHandle(handle))

    monkeypatch.setattr(ctypes, "WinDLL", lambda *_a, **_k: Kernel())
    monkeypatch.setattr(
        module, "_borrowed_reader_handle_identity",
        lambda _handle: {
            "volume": 1, "file_id": 2, "attributes": 0x10,
            "reparse_tag": 0, "links": 1, "size": 0,
        },
    )
    with pytest.raises(OSError, match="trash move failed"):
        module._claude_projection_move_to_trash(
            str(source), str(trash), expected_authority=authority,
        )
    assert blocked["value"] is True
    assert source.read_bytes() == b"source\n"
    assert trash.is_dir()
    assert not moved_root.exists()


def test_windows_trash_createfile_gap_replacement_aborts_before_source_move(
    monkeypatch, tmp_path,
):
    module = _load()
    import ctypes

    transaction = tmp_path / "transaction"
    trash = transaction / "trash"
    transaction.mkdir()
    authority = _trash_authority(module, transaction, trash)
    source = tmp_path / "source"
    source.write_bytes(b"source\n")
    replaced = tmp_path / "old-trash"
    calls = {"open": 0, "move": 0}

    from ctypes import wintypes
    real = ctypes.WinDLL("kernel32", use_last_error=True)
    real.CreateFileW.restype = wintypes.HANDLE

    class Function:
        def __init__(self, call):
            self.call = call
            self.restype = None

        def __call__(self, *args):
            return self.call(*args)

    def create(*args):
        calls["open"] += 1
        if calls["open"] == 1:
            os.rename(trash, replaced)
            trash.mkdir()
        return real.CreateFileW(*args)

    class Kernel:
        def __init__(self):
            self.CreateFileW = Function(create)
            self.MoveFileExW = Function(
                lambda *_a: calls.__setitem__("move", calls["move"] + 1) or 1
            )
            self.CloseHandle = Function(lambda handle: real.CloseHandle(handle))

    monkeypatch.setattr(ctypes, "WinDLL", lambda *_a, **_k: Kernel())
    with pytest.raises(RuntimeError, match="trash root (?:was replaced|is a reparse link)"):
        module._claude_projection_move_to_trash(
            str(source), str(trash), expected_authority=authority,
        )
    assert calls["move"] == 0
    assert source.read_bytes() == b"source\n"
    assert trash.is_dir() and list(trash.iterdir()) == []
    assert (replaced / ".plamen-trash-owned").is_file()


def test_windows_created_directory_trash_crash_recovers_on_second_pass(
    monkeypatch, tmp_path,
):
    module = _load()
    claude = tmp_path / ".claude"
    claude.mkdir()
    monkeypatch.setattr(module, "CLAUDE_HOME", str(claude))
    transaction = _transaction(monkeypatch, module, tmp_path)
    destination = claude / "commands" / "owned.md"
    monkeypatch.setattr(
        module, "_claude_projection_allowed_destinations",
        lambda _authority: {os.path.normcase(os.path.abspath(destination))},
    )
    transaction.add_bytes(str(destination), b"successor\n", kind="projection")
    monkeypatch.setattr(
        module, "_CLAUDE_PROJECTION_FAILPOINT", "after_projection_replace",
    )
    real_move = module._claude_projection_move_to_trash
    crashed = {"done": False}

    def move(path, trash_root, *, name=None, expected_authority=None):
        result = real_move(
            path, trash_root, name=name,
            expected_authority=expected_authority,
        )
        if name == "created-000000" and not crashed["done"]:
            crashed["done"] = True
            raise RuntimeError("simulated hard stop after directory trash move")
        return result

    monkeypatch.setattr(module, "_claude_projection_move_to_trash", move)
    with pytest.raises(RuntimeError, match="simulated hard stop"):
        transaction.commit()
    assert crashed["done"] is True
    assert not destination.exists()
    assert not (claude / "commands").exists()
    assert not os.path.exists(module._claude_projection_journal_path())


def test_projection_authority_short_write_and_eintr_complete_exactly(
    monkeypatch, tmp_path,
):
    module = _load()
    destination = tmp_path / "authority"
    raw = b"complete-authority\n"
    real_write = module.os.write
    calls = {"count": 0}

    def short_write(fd, view):
        calls["count"] += 1
        if calls["count"] == 2:
            raise InterruptedError()
        return real_write(fd, bytes(view[:1] if calls["count"] == 1 else view))

    monkeypatch.setattr(module.os, "write", short_write)
    assert module._claude_projection_publish_bytes_noreplace(
        str(destination), raw,
    ) is True
    assert destination.read_bytes() == raw


@pytest.mark.parametrize("progress", (0, -1, True, 9999))
def test_projection_authority_invalid_write_progress_never_publishes(
    monkeypatch, tmp_path, progress,
):
    module = _load()
    destination = tmp_path / "authority"
    monkeypatch.setattr(module.os, "write", lambda *_a: progress)
    with pytest.raises(OSError, match="invalid progress"):
        module._claude_projection_publish_bytes_noreplace(
            str(destination), b"authority\n",
        )
    assert not destination.exists()
    assert list(tmp_path.iterdir()) == []
