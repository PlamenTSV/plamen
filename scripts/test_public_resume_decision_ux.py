import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import stat
import sys
import tempfile
import types
import uuid

import pytest


ROOT = Path(__file__).resolve().parents[1]
MAC_KEY = bytes.fromhex("9" * 64)


def _load_front():
    spec = importlib.util.spec_from_file_location(
        "plamen_public_resume_decision_front", ROOT / "plamen.py"
    )
    module = importlib.util.module_from_spec(spec)
    saved = sys.argv
    sys.argv = ["plamen.py"]
    try:
        spec.loader.exec_module(module)
    finally:
        sys.argv = saved
    return module


@pytest.fixture(scope="module")
def front():
    return _load_front()


def _decision(*, changed=("toolchain_runtime",), mac_key=MAC_KEY):
    changed = list(changed)
    components = {
        name: {
            "stored_digest": "a" * 64,
            "current_digest": "b" * 64,
            "changed": True,
        }
        for name in changed
    }
    components["unchanged"] = {
        "stored_digest": "c" * 64,
        "current_digest": "c" * 64,
        "changed": False,
    }
    value = {
        "schema": "plamen.startup-decision.v3",
        "run_id": str(uuid.UUID("12345678-1234-5678-9234-567812345678")),
        "startup_intent": "RESUME_EXISTING",
        "snapshot_verdict": "MISMATCH",
        "changed_components": changed,
        "component_digests": components,
        "stored_snapshot_digest": "d" * 64,
        "current_snapshot_digest": "e" * 64,
        "required_action": "RESTORE_EXACT_INPUTS_OR_USE_DISTINCT_RUN_DESTINATION",
        "allowed_actions": [
            "RESUME_EXISTING", "START_NEW_RUN", "MIGRATE_EXISTING",
        ],
        "evidence_preserved": True,
        "model_launch_allowed": False,
        "exit_status": 5,
    }
    return _resign(value, mac_key=mac_key)


def _resign(value, *, mac_key=MAC_KEY):
    value = dict(value)
    value.pop("decision_id", None)
    value.pop("receipt_mac", None)
    unsigned = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")
    value["decision_id"] = hashlib.sha256(unsigned).hexdigest()
    value["receipt_mac"] = hmac.new(
        mac_key,
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return value


def _write_decision(path: Path, value=None):
    value = _decision() if value is None else value
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        (
            json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False)
            + "\n"
        ).encode("utf-8")
    )


def test_verified_mismatch_renders_non_looping_preserved_evidence(
    front, tmp_path, capsys,
):
    receipt = tmp_path / "outside" / "decision.json"
    _write_decision(receipt, _decision(changed=("source_scope", "toolchain")))

    assert front._render_driver_result(
        5, str(tmp_path / "run" / "config.json"), str(tmp_path / "project"),
        decision_receipt_path=receipt,
        decision_mac_key=MAC_KEY,
    ) == 5

    output = capsys.readouterr().out
    assert "This resume attempt stopped during startup" in output
    assert "driver reported that it launched no new audit-model generation" in output
    assert "driver reported that existing audit evidence was preserved" in output
    assert "does not defend against same-user process compromise" in output
    assert "source_scope, toolchain" in output
    assert "Restore the exact original input bytes" in output
    assert "distinct clean scratchpad/config destination" in output
    assert "Repeating the current resume" in output
    assert str(receipt) in output
    assert "completed in a degraded state" not in output
    assert "Resume:" not in output


@pytest.mark.parametrize("kind", ("missing", "invalid", "tampered"))
def test_missing_or_invalid_receipt_uses_uncertainty_fallback(
    front, tmp_path, capsys, kind,
):
    receipt = tmp_path / kind / "decision.json"
    if kind == "invalid":
        receipt.parent.mkdir(parents=True)
        receipt.write_text("not-json", encoding="utf-8")
    elif kind == "tampered":
        value = _decision()
        value["decision_id"] = "0" * 64
        _write_decision(receipt, value)

    assert front._render_driver_result(
        5, str(tmp_path / "config.json"), str(tmp_path / "project"),
        decision_receipt_path=receipt,
        decision_mac_key=MAC_KEY,
    ) == 5

    output = capsys.readouterr().out
    assert "no valid typed startup-decision receipt" in output
    assert "cannot certify whether audit execution began" in output
    assert "do not repeat resume blindly" in output
    assert str(receipt) in output
    assert "completed in a degraded state" not in output
    assert "Resume:" not in output


def test_normal_degraded_result_without_resume_receipt_is_unchanged(
    front, tmp_path, capsys,
):
    config = tmp_path / "scratch" / "config.json"
    absent = tmp_path / "always-supplied-but-absent.json"
    assert front._render_driver_result(
        3, str(config), str(tmp_path), decision_receipt_path=absent,
    ) == 3
    output = capsys.readouterr().out
    assert "completed in a degraded state" in output
    assert f"Resume: plamen resume \"{config}\"" in output
    assert "startup-decision" not in output


def test_exit5_without_receipt_destination_uses_uncertainty_fallback(
    front, tmp_path, capsys,
):
    assert front._render_driver_result(
        5, str(tmp_path / "config.json"), str(tmp_path),
    ) == 5
    output = capsys.readouterr().out
    assert "no valid typed startup-decision receipt" in output
    assert "No decision-receipt destination was supplied" in output
    assert "completed in a degraded state" not in output


def test_canonical_preexisting_receipt_with_wrong_one_use_mac_is_uncertain(
    front, tmp_path, capsys,
):
    receipt = tmp_path / "preexisting.json"
    _write_decision(receipt, _decision(mac_key=b"x" * 32))
    assert front._render_driver_result(
        5, str(tmp_path / "config.json"), str(tmp_path),
        decision_receipt_path=receipt,
        decision_mac_key=MAC_KEY,
    ) == 5
    output = capsys.readouterr().out
    assert "no valid typed startup-decision receipt" in output
    assert "This resume attempt stopped during startup" not in output


def test_resume_passes_external_receipt_path_as_one_argv_with_spaces(
    front, tmp_path, monkeypatch,
):
    project = tmp_path / "project with spaces"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    config = scratchpad / "config.json"
    config.write_text(json.dumps({
        "project_root": str(project), "pipeline": "sc", "mode": "core",
    }), encoding="utf-8")
    receipt = tmp_path / "external decisions with spaces" / "decision.json"
    calls = []
    monkeypatch.setattr(
        front, "_resume_startup_decision_destination",
        lambda config_path, target: receipt,
    )
    monkeypatch.setattr(front.secrets, "token_bytes", lambda size: MAC_KEY)
    monkeypatch.setattr(
        front.subprocess, "run",
        lambda command, **kwargs: calls.append(
            (command, dict(kwargs.get("env", {})))
        ) or subprocess.CompletedProcess(
            command, 3,
        ),
    )
    rendered = []
    monkeypatch.setattr(
        front, "_render_driver_result",
        lambda code, config_path, target, **kwargs: rendered.append(
            (code, config_path, target, kwargs)
        ) or code,
    )
    monkeypatch.setattr(front.console, "print", lambda *_a, **_k: None)

    with pytest.raises(SystemExit) as stopped:
        front.resume_v2(str(config))

    assert stopped.value.code == 3
    assert len(calls) == 1
    assert calls[0][0][-5:] == [
        "--startup-intent", "RESUME_EXISTING",
        "--startup-decision-receipt", str(receipt), str(config),
    ]
    assert "PLAMEN_STARTUP_DECISION_MAC_KEY" not in calls[0][0]
    assert calls[0][1]["PLAMEN_STARTUP_DECISION_MAC_KEY"] == MAC_KEY.hex()
    assert rendered == [(
        3, str(config), str(project), {
            "decision_receipt_path": receipt,
            "decision_mac_key": MAC_KEY,
        },
    )]


def test_real_resume_v2_ordinary_exit3_with_absent_receipt_is_normal_degraded(
    front, tmp_path, monkeypatch, capsys,
):
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    config = scratchpad / "config.json"
    config.write_text(json.dumps({
        "project_root": str(project), "pipeline": "sc", "mode": "core",
    }), encoding="utf-8")
    receipt = tmp_path / "outside" / "absent.json"
    monkeypatch.setattr(
        front, "_resume_startup_decision_destination",
        lambda *_a, **_k: receipt,
    )
    monkeypatch.setattr(front.secrets, "token_bytes", lambda size: MAC_KEY)
    monkeypatch.setattr(
        front.subprocess, "run",
        lambda command, **kwargs: subprocess.CompletedProcess(command, 3),
    )
    monkeypatch.setattr(front.console, "print", lambda *_a, **_k: None)

    with pytest.raises(SystemExit) as stopped:
        front.resume_v2(str(config))

    assert stopped.value.code == 3
    output = capsys.readouterr().out
    assert "completed in a degraded state" in output
    assert "no valid typed startup-decision receipt" not in output


def test_generated_receipt_destination_escapes_project_and_preserves_spaces(
    front, tmp_path, monkeypatch,
):
    project = tmp_path / "project with spaces"
    config = project / ".scratchpad" / "config.json"
    external = tmp_path / "outside decisions with spaces"
    if os.name == "nt":
        front._win_launcher_create_directory_secure(external)
    else:
        external.mkdir(mode=0o700)
    preowned_shared = external / "plamen-startup-decisions"
    preowned_shared.mkdir()
    sentinel = preowned_shared / "foreign.txt"
    sentinel.write_text("foreign", encoding="utf-8")
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(external))
    monkeypatch.setattr(
        front, "_startup_decision_ensure_user_base", lambda: external,
    )
    front._startup_decision_directory_chain_authority(external)

    destination = front._resume_startup_decision_destination(
        str(config), str(project),
    )

    destination.relative_to(external)
    with pytest.raises(ValueError):
        destination.relative_to(project)
    assert " " in str(destination)
    assert not destination.exists()
    assert destination.name == "decision.json"
    assert destination.parent.name.startswith("plamen-startup-decision-")
    assert destination.parent != preowned_shared
    assert sentinel.read_text(encoding="utf-8") == "foreign"
    info = front.os.stat(destination.parent, follow_symlinks=False)
    assert not front._python_dependency_census_reparse(info)
    if front.os.name == "nt":
        front._win_launcher_security_snapshot_path(
            destination.parent,
            directory=True,
            dangerous_mask=front._WIN_LAUNCHER_EXACT_DANGEROUS,
        )
    else:
        assert info.st_uid == front.os.geteuid()
        assert stat.S_IMODE(info.st_mode) == 0o700


def test_protected_preferred_base_is_skipped_before_creation(
    front, tmp_path, monkeypatch,
):
    project = tmp_path / "project"
    project.mkdir()
    config = project / ".scratchpad" / "config.json"
    preferred = project / "must-not-be-created"
    external = tmp_path / "external"
    if os.name == "nt":
        front._win_launcher_create_directory_secure(external)
    else:
        external.mkdir(mode=0o700)
    ensure_calls = []

    def forbidden_ensure():
        ensure_calls.append(True)
        preferred.mkdir()
        return preferred

    monkeypatch.setattr(front, "_startup_decision_user_base", lambda: preferred)
    monkeypatch.setattr(front, "_startup_decision_ensure_user_base", forbidden_ensure)
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(external))

    destination = front._resume_startup_decision_destination(
        str(config), str(project),
    )

    assert ensure_calls == []
    assert not preferred.exists()
    destination.relative_to(external.resolve(strict=True))


def test_all_protected_bases_fail_without_creating_any_artifact(
    front, tmp_path, monkeypatch,
):
    project = tmp_path / "project"
    project.mkdir()
    config = project / ".scratchpad" / "config.json"
    preferred = project / "state-must-not-exist"
    temporary = project / "existing-temp"
    temporary.mkdir()
    before = tuple(sorted(str(path.relative_to(project)) for path in project.rglob("*")))
    calls = []

    monkeypatch.setattr(front, "_startup_decision_user_base", lambda: preferred)
    monkeypatch.setattr(
        front, "_startup_decision_ensure_user_base",
        lambda: calls.append("ensure") or preferred,
    )
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(temporary))
    monkeypatch.setattr(
        tempfile, "mkdtemp", lambda **_kwargs: calls.append("mkdtemp") or "",
    )

    with pytest.raises(RuntimeError, match="no fresh startup-decision"):
        front._resume_startup_decision_destination(str(config), str(project))

    after = tuple(sorted(str(path.relative_to(project)) for path in project.rglob("*")))
    assert calls == []
    assert before == after
    assert not preferred.exists()


def test_darwin_temp_alias_is_canonicalized_before_safe_fallback(
    front, tmp_path, monkeypatch,
):
    project = tmp_path / "project"
    project.mkdir()
    config = project / ".scratchpad" / "config.json"
    preferred = project / "protected-state"
    canonical = tmp_path / "private" / "var" / "folders" / "safe"
    canonical.parent.mkdir(parents=True)
    if os.name == "nt":
        front._win_launcher_create_directory_secure(canonical)
    else:
        canonical.mkdir(mode=0o700)
    alias = "/var/folders/mock-plamen-safe"
    observed = []

    monkeypatch.setattr(front, "_startup_decision_user_base", lambda: preferred)
    monkeypatch.setattr(
        front, "_startup_decision_ensure_user_base",
        lambda: pytest.fail("protected preferred base must not be created"),
    )
    monkeypatch.setattr(tempfile, "gettempdir", lambda: alias)

    def resolve_alias(raw):
        observed.append(os.fspath(raw))
        return canonical.resolve(strict=True)

    monkeypatch.setattr(
        front, "_startup_decision_canonical_temp_base", resolve_alias,
    )

    destination = front._resume_startup_decision_destination(
        str(config), str(project),
    )

    assert observed == [alias]
    destination.relative_to(canonical.resolve(strict=True))


def test_posix_nonsticky_world_writable_tmpdir_is_rejected(front):
    hostile = types.SimpleNamespace(
        st_mode=stat.S_IFDIR | 0o777,
        st_uid=1000,
        st_nlink=1,
        st_dev=1,
        st_ino=2,
        st_ctime_ns=3,
        st_file_attributes=0,
    )
    with pytest.raises(RuntimeError, match="ancestry is unsafe"):
        front._startup_decision_posix_directory_row(
            Path("/hostile-tmp"), hostile, effective_uid=1000,
        )


@pytest.mark.parametrize("dangerous_right", [
    0x00010000,  # DELETE
    0x00040000,  # WRITE_DAC
    0x00080000,  # WRITE_OWNER
    0x00000040,  # FILE_DELETE_CHILD
])
@pytest.mark.skipif(sys.platform != "win32", reason="Windows ACL policy")
def test_windows_parent_chain_rejects_each_foreign_integrity_right(
    front, tmp_path, monkeypatch, dangerous_right,
):
    observed_masks = []
    monkeypatch.setattr(
        front, "_win_launcher_require_persistent_acls", lambda _path: None,
    )

    def reject_delete_child(_path, *, directory, dangerous_mask, **_kwargs):
        assert directory
        observed_masks.append(dangerous_mask)
        if dangerous_mask & dangerous_right:
            raise RuntimeError("foreign ancestor mutation right")
        return ("trusted", 0, "0" * 64, False)

    monkeypatch.setattr(
        front, "_win_launcher_security_snapshot_path", reject_delete_child,
    )
    with pytest.raises(RuntimeError, match="foreign ancestor mutation right"):
        front._startup_decision_directory_chain_authority(
            tmp_path, platform_name="nt",
        )
    assert observed_masks == [front._WIN_LAUNCHER_ANCESTOR_DANGEROUS]


@pytest.mark.parametrize("icacls_right", ["D", "WDAC", "WO", "DC"])
@pytest.mark.skipif(sys.platform != "win32", reason="Windows ACL policy")
def test_windows_parent_chain_native_acl_rejects_each_integrity_right(
    front, tmp_path, icacls_right,
):
    directory = tmp_path / ("foreign-right-" + icacls_right)
    front._win_launcher_create_directory_secure(directory)
    icacls = Path(os.environ["SystemRoot"]) / "System32" / "icacls.exe"
    granted = subprocess.run(
        [str(icacls), str(directory), "/grant", f"*S-1-5-11:({icacls_right})"],
        stdin=subprocess.DEVNULL, capture_output=True, timeout=10,
    )
    assert granted.returncode == 0, granted.stderr.decode(errors="replace")
    with pytest.raises(RuntimeError, match="foreign mutation rights"):
        front._startup_decision_directory_chain_authority(
            directory, platform_name="nt",
        )


def test_darwin_acl_marker_free_directory_is_admitted(front, monkeypatch):
    monkeypatch.setattr(
        front, "_startup_decision_darwin_ls",
        lambda _path: (0, b"drwx------  2 user  staff  64 Sep  2 12:00 /safe\n", b""),
    )
    assert front._startup_decision_darwin_acl_authority(
        Path("/safe")
    ) == "DARWIN_NO_ACL"


def test_darwin_acl_marker_is_rejected(front, monkeypatch):
    monkeypatch.setattr(
        front, "_startup_decision_darwin_ls",
        lambda _path: (
            0,
            b"drwx------+ 2 user  staff  64 Sep  2 12:00 /unsafe\n"
            b" 0: group:everyone deny delete\n",
            b"",
        ),
    )
    with pytest.raises(RuntimeError, match="carries an ACL"):
        front._startup_decision_darwin_acl_authority(Path("/unsafe"))


def test_darwin_acl_inspection_error_is_rejected(front, monkeypatch):
    monkeypatch.setattr(
        front, "_startup_decision_darwin_ls",
        lambda _path: (1, b"", b"ls: authority unavailable\n"),
    )
    with pytest.raises(RuntimeError, match="inspection is ambiguous"):
        front._startup_decision_darwin_acl_authority(Path("/unavailable"))


@pytest.mark.parametrize("argv", [
    ["plamen.py", "resume", "--force"],
    ["plamen.py", "resume", "config.json", "--force"],
])
def test_public_resume_rejects_options_and_extra_arguments_before_dispatch(
    front, monkeypatch, capsys, argv,
):
    calls = []
    monkeypatch.setattr(
        front, "_enforce_public_claude_projection_preflight", lambda: None,
    )
    monkeypatch.setattr(front, "resume_v2", lambda *_a: calls.append("resume"))
    monkeypatch.setattr(front, "show_banner", lambda: calls.append("banner"))
    monkeypatch.setattr(
        front.sys, "argv",
        argv,
    )

    with pytest.raises(SystemExit) as stopped:
        front.main()

    assert stopped.value.code == 2
    assert calls == []
    assert "resume accepts zero or one non-option config.json path" in capsys.readouterr().err


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.update(schema="plamen.startup-decision.v2"),
        lambda value: value.update(exit_status=3.0),
        lambda value: value.update(current_snapshot_digest=None),
        lambda value: value.update(
            required_action="AUTHORIZE_VERSIONED_MIGRATION_OR_USE_DISTINCT_RUN_DESTINATION"
        ),
        lambda value: value.update(run_id="not-a-uuid"),
        lambda value: value.update(evidence_preserved=1),
        lambda value: value["component_digests"]["toolchain_runtime"].update(
            changed=1
        ),
    ],
    ids=(
        "legacy-schema", "float-exit", "null-current-digest", "cross-field-action",
        "malformed-uuid", "non-bool-preservation", "non-bool-component",
    ),
)
def test_receipt_strict_types_and_cross_field_relationships_reject(
    front, tmp_path, mutate,
):
    value = _decision()
    mutate(value)
    receipt = tmp_path / "decision.json"
    _write_decision(receipt, _resign(value))
    with pytest.raises(ValueError):
        front._load_resume_startup_decision(receipt, receipt_mac_key=MAC_KEY)


@pytest.mark.parametrize(
    ("action", "run_id", "changed"),
    [
        (
            "AUTHORIZE_VERSIONED_MIGRATION_OR_USE_DISTINCT_RUN_DESTINATION",
            None,
            ("run_identity",),
        ),
        (
            "USE_EMPTY_CHECKPOINT_FOR_NEW_DESTINATION",
            str(uuid.UUID("12345678-1234-5678-9234-567812345678")),
            ("run_identity_collision",),
        ),
    ],
)
def test_valid_legacy_relationships_are_accepted(
    front, tmp_path, action, run_id, changed,
):
    value = _decision(changed=changed)
    value.update(
        snapshot_verdict="LEGACY_UNBOUND",
        required_action=action,
        run_id=run_id,
        stored_snapshot_digest=None,
    )
    receipt = tmp_path / (changed[0] + ".json")
    _write_decision(receipt, _resign(value))
    assert front._load_resume_startup_decision(
        receipt, receipt_mac_key=MAC_KEY,
    )["required_action"] == action


def test_retained_reader_swap_failure_is_rejected(front, tmp_path, monkeypatch):
    receipt = tmp_path / "decision.json"
    _write_decision(receipt)
    monkeypatch.setattr(
        front,
        "_codex_install_committed_read",
        lambda *_a, **_k: (_ for _ in ()).throw(
            RuntimeError("committed authority changed during read")
        ),
    )
    with pytest.raises(ValueError):
        front._load_resume_startup_decision(receipt, receipt_mac_key=MAC_KEY)


def test_receipt_windows_reparse_attribute_is_rejected(
    front, tmp_path, monkeypatch,
):
    receipt = tmp_path / "decision.json"
    _write_decision(receipt)
    raw = receipt.read_bytes()
    monkeypatch.setattr(
        front,
        "_codex_install_committed_read",
        lambda *_a, **_k: ({
            "kind": "file", "links": 1, "reparse_tag": 0xA000000C,
            "size": len(raw),
        }, raw),
    )
    with pytest.raises(ValueError):
        front._load_resume_startup_decision(receipt, receipt_mac_key=MAC_KEY)


def test_receipt_reader_is_rooted_and_bounded_across_all_components(
    front, tmp_path, monkeypatch,
):
    receipt = tmp_path / "nested" / "decision.json"
    _write_decision(receipt)
    raw = receipt.read_bytes()
    calls = []

    def retained(root, components, **kwargs):
        calls.append((root, components, kwargs))
        return ({
            "kind": "file", "links": 1, "reparse_tag": 0,
            "size": len(raw),
        }, raw)

    monkeypatch.setattr(front, "_codex_install_committed_read", retained)
    assert front._load_resume_startup_decision(
        receipt, receipt_mac_key=MAC_KEY,
    )["exit_status"] == 5
    absolute = Path(front.os.path.abspath(receipt))
    assert calls == [(
        Path(absolute.anchor),
        tuple(absolute.relative_to(Path(absolute.anchor)).parts),
        {"maximum": 1024 * 1024},
    )]


def test_posix_receipt_read_location_uses_parent_and_exact_leaf(front, tmp_path):
    receipt = tmp_path / "nested" / "decision.json"
    absolute = Path(front.os.path.abspath(receipt))
    observed = front._resume_startup_decision_read_location(
        receipt, platform_name="posix",
    )
    assert observed == (absolute, absolute.parent, (absolute.name,))


@pytest.mark.skipif(sys.platform != "win32", reason="native Windows authority")
def test_windows_receipt_cap_precedes_descriptor_hashing(
    front, tmp_path, monkeypatch,
):
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"x" * (1024 * 1024 + 1))
    absolute, root, components = front._resume_startup_decision_read_location(
        oversized, platform_name="nt",
    )
    calls = []

    def forbidden(*_args, **_kwargs):
        calls.append(True)
        raise AssertionError("descriptor hashing must not run above the byte cap")

    monkeypatch.setattr(
        front._CodexInstallMutationDispatcher,
        "_native_handle_descriptor",
        staticmethod(forbidden),
    )
    with pytest.raises(RuntimeError, match="size exceeds bound"):
        front._codex_install_committed_read(
            root, components, maximum=1024 * 1024,
        )
    assert absolute == oversized
    assert calls == []


@pytest.mark.skipif(sys.platform != "win32", reason="native Windows authority")
def test_windows_receipt_growth_after_precheck_hashes_and_reads_zero_bytes(
    front, tmp_path, monkeypatch,
):
    receipt = tmp_path / "growth-race.json"
    receipt.write_bytes(b"x")
    _absolute, root, components = front._resume_startup_decision_read_location(
        receipt, platform_name="nt",
    )
    original = front._codex_native_exact_component
    grown = False

    def grow_after_identity(handle, expected):
        nonlocal grown
        identity = original(handle, expected)
        if expected == receipt.name and not grown:
            grown = True
            with receipt.open("ab") as stream:
                stream.write(b"y" * (1024 * 1024))
                stream.flush()
                front.os.fsync(stream.fileno())
        return identity

    before_hash = front._CODEX_INSTALL_MEMORY_COUNTERS["native_hash_bytes"]
    before_read = front._CODEX_INSTALL_MEMORY_COUNTERS["native_read_bytes"]
    monkeypatch.setattr(
        front, "_codex_native_exact_component", grow_after_identity,
    )
    with pytest.raises(RuntimeError, match="identity changed|size exceeds bound"):
        front._codex_install_committed_read(
            root, components, maximum=1024 * 1024,
        )
    assert grown
    assert receipt.stat().st_size == 1024 * 1024 + 1
    assert (
        front._CODEX_INSTALL_MEMORY_COUNTERS["native_hash_bytes"] - before_hash
    ) == 0
    assert (
        front._CODEX_INSTALL_MEMORY_COUNTERS["native_read_bytes"] - before_read
    ) == 0


@pytest.mark.skipif(sys.platform != "win32", reason="native Windows authority")
def test_windows_receipt_read_replays_full_descriptor_after_bytes(
    front, tmp_path, monkeypatch,
):
    receipt = tmp_path / "decision.json"
    _write_decision(receipt)
    _absolute, root, components = front._resume_startup_decision_read_location(
        receipt, platform_name="nt",
    )
    original = front._CodexInstallMutationDispatcher._native_handle_descriptor
    calls = []

    def counted(*args, **kwargs):
        calls.append(True)
        return original(*args, **kwargs)

    monkeypatch.setattr(
        front._CodexInstallMutationDispatcher,
        "_native_handle_descriptor",
        staticmethod(counted),
    )
    descriptor, raw = front._codex_install_committed_read(
        root, components, maximum=1024 * 1024,
    )
    assert descriptor["size"] == len(raw)
    assert len(calls) == 2


@pytest.mark.skipif(sys.platform != "win32", reason="native Windows authority")
def test_windows_receipt_rejects_invalid_root_anchor_before_leaf(
    front, tmp_path, monkeypatch,
):
    receipt = tmp_path / "decision.json"
    _write_decision(receipt)
    _absolute, root, components = front._resume_startup_decision_read_location(
        receipt, platform_name="nt",
    )
    original = front._borrowed_reader_handle_identity
    calls = 0

    def invalid_root(handle):
        nonlocal calls
        calls += 1
        identity = dict(original(handle))
        if calls == 1:
            identity["reparse_tag"] = 0xA000000C
        return identity

    monkeypatch.setattr(front, "_borrowed_reader_handle_identity", invalid_root)
    with pytest.raises(RuntimeError, match="root authority differs"):
        front._codex_install_committed_read(
            root, components, maximum=1024 * 1024,
        )


def test_receipt_hardlink_is_rejected(front, tmp_path):
    receipt = tmp_path / "decision.json"
    alias = tmp_path / "decision-alias.json"
    _write_decision(receipt)
    try:
        front.os.link(receipt, alias)
    except OSError as exc:
        pytest.skip(f"hardlinks unavailable: {exc}")
    with pytest.raises(ValueError):
        front._load_resume_startup_decision(receipt, receipt_mac_key=MAC_KEY)
