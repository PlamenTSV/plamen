from __future__ import annotations

import copy
import gc
import json
import os
from pathlib import Path
import pickle
import subprocess
import sys
import traceback

import pytest

import codex_stored_auth_source as S


_ACQUIRE = S.acquire_codex_stored_auth


@pytest.fixture(autouse=True)
def _trusted_synthetic_darwin_verifier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep normal fixtures synthetic; production Darwin fails without one."""

    if sys.platform != "darwin":
        return

    def acquire(path: object, **kwargs: object) -> S.CodexStoredAuthCapability:
        kwargs.setdefault("darwin_descriptor_security_verifier", lambda _fd: True)
        return _ACQUIRE(path, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(S, "acquire_codex_stored_auth", acquire)


def _raw(secret: str = "fixture-codex-secret") -> bytes:
    return json.dumps(
        {
            "auth_mode": "chatgpt",
            "tokens": {
                "access_token": secret,
                "refresh_token": f"{secret}-refresh",
            },
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _source(tmp_path: Path, raw: bytes | None = None) -> Path:
    directory = tmp_path / "profile" / ".codex"
    directory.mkdir(parents=True)
    path = directory / "auth.json"
    path.write_bytes(_raw() if raw is None else raw)
    path.chmod(0o600)
    return path


def _traceback_local_text(error: BaseException) -> str:
    rows: list[str] = []
    captured = traceback.TracebackException.from_exception(
        error,
        capture_locals=True,
    )
    for frame in captured.stack:
        if Path(frame.filename).name == Path(S.__file__).name:
            rows.extend((frame.locals or {}).values())
    return "\n".join(rows)


def test_acquire_and_consume_exact_bytes_once_then_zeroizes(tmp_path: Path) -> None:
    raw = _raw()
    path = _source(tmp_path, raw)
    capability = S.acquire_codex_stored_auth(path)
    held: list[bytearray] = []
    copied: list[bytes] = []

    def sink(material: bytearray) -> None:
        assert type(material) is bytearray
        held.append(material)
        copied.append(bytes(material))

    capability.consume_into_private_sink(sink)

    assert copied == [raw]
    assert held and held[0] == bytearray(len(raw))
    assert repr(capability) == "<CodexStoredAuthCapability opaque>"
    with pytest.raises(S.CodexStoredAuthSourceError) as raised:
        capability.consume_into_private_sink(sink)
    assert raised.value.reason_code == "CAPABILITY_CONSUMED"


def test_discard_is_one_shot_and_erases_material(tmp_path: Path) -> None:
    capability = S.acquire_codex_stored_auth(_source(tmp_path))
    capability.discard()
    with pytest.raises(S.CodexStoredAuthSourceError):
        capability.discard()


def test_capability_has_no_public_constructor_copy_or_pickle(tmp_path: Path) -> None:
    with pytest.raises(TypeError):
        S.CodexStoredAuthCapability()

    capability = S.acquire_codex_stored_auth(_source(tmp_path))
    try:
        with pytest.raises(TypeError):
            copy.copy(capability)
        with pytest.raises(TypeError):
            copy.deepcopy(capability)
        with pytest.raises(TypeError):
            pickle.dumps(capability)
        with pytest.raises(TypeError):
            vars(capability)
        referents = gc.get_referents(capability)
        assert not any(isinstance(value, bytearray) for value in referents)
        assert not any(isinstance(value, S._SourceLease) for value in referents)
        with pytest.raises(TypeError):
            type("ForgedSubclass", (S.CodexStoredAuthCapability,), {})
        with pytest.raises(TypeError):
            S.CodexStoredAuthCapability(_issuance_id="known-seal")
        forged = object.__new__(S.CodexStoredAuthCapability)
        with pytest.raises(S.CodexStoredAuthSourceError):
            forged.consume_into_private_sink(lambda _material: None)
    finally:
        capability.discard()


def test_private_sink_failure_is_redacted_and_material_is_zeroized(tmp_path: Path) -> None:
    secret = "sink-exception-fixture-secret"
    capability = S.acquire_codex_stored_auth(_source(tmp_path, _raw(secret)))
    held: list[bytearray] = []

    def sink(material: bytearray) -> None:
        held.append(material)
        raise RuntimeError(bytes(material).decode("utf-8"))

    with pytest.raises(S.CodexStoredAuthSourceError) as raised:
        capability.consume_into_private_sink(sink)

    assert raised.value.reason_code == "SINK_FAILED"
    assert secret not in str(raised.value)
    assert secret not in _traceback_local_text(raised.value)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert held[0] == bytearray(len(_raw(secret)))
    with pytest.raises(S.CodexStoredAuthSourceError):
        capability.consume_into_private_sink(lambda _material: None)


def test_private_sink_cannot_return_material(tmp_path: Path) -> None:
    capability = S.acquire_codex_stored_auth(_source(tmp_path))
    held: list[bytearray] = []

    def sink(material: bytearray) -> bytearray:
        held.append(material)
        return material

    with pytest.raises(S.CodexStoredAuthSourceError) as raised:
        capability.consume_into_private_sink(sink)  # type: ignore[arg-type]
    assert raised.value.reason_code == "SINK_RETURNED_VALUE"
    assert held[0] == bytearray(len(_raw()))


def test_callback_cannot_replace_capability_slot_and_original_is_zeroed(
    tmp_path: Path,
) -> None:
    capability = S.acquire_codex_stored_auth(_source(tmp_path))
    issuer_material = S._ISSUED[id(capability)][3]
    assert isinstance(issuer_material, bytearray)
    assert issuer_material == bytearray(_raw())
    held: list[bytearray] = []

    def sink(material: bytearray) -> None:
        held.append(material)
        assert issuer_material == bytearray(len(_raw()))
        with pytest.raises(AttributeError):
            object.__setattr__(
                capability,
                "_CodexStoredAuthCapability__material",
                bytearray(b"replacement"),
            )
        with pytest.raises(S.CodexStoredAuthSourceError) as raised:
            capability.consume_into_private_sink(lambda _value: None)
        assert raised.value.reason_code == "CAPABILITY_CONSUMED"

    capability.consume_into_private_sink(sink)
    assert issuer_material == bytearray(len(_raw()))
    assert held[0] == bytearray(len(_raw()))


@pytest.mark.parametrize(
    "payload",
    (
        b"not-json",
        b"[]",
        b'[{"a":1}]',
        b'{"a":1,"a":2}',
        b'{"value":NaN}',
        b"\xef\xbb\xbf{}",
        '{"token":"fixture"}'.encode("utf-16"),
        b'{"token":"\xff"}',
        b'"string"',
    ),
)
def test_invalid_json_shapes_fail_closed_without_secret_traceback(
    tmp_path: Path, payload: bytes
) -> None:
    secret = b"invalid-json-fixture-secret"
    path = _source(tmp_path, payload + secret)
    with pytest.raises(S.CodexStoredAuthSourceError) as raised:
        S.acquire_codex_stored_auth(path)
    assert raised.value.reason_code == "INVALID_JSON"
    assert secret.decode() not in str(raised.value)
    assert secret.decode() not in _traceback_local_text(raised.value)
    assert str(path) not in _traceback_local_text(raised.value)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


def test_strict_json_accepts_nested_object(tmp_path: Path) -> None:
    capability = S.acquire_codex_stored_auth(_source(tmp_path, b'{"tokens":{}}'))
    capability.discard()


@pytest.mark.parametrize("mode", (0o400, 0o640, 0o660, 0o700, 0o644))
def test_requires_exact_mode_0600(tmp_path: Path, mode: int) -> None:
    path = _source(tmp_path)
    path.chmod(mode)
    with pytest.raises(S.CodexStoredAuthSourceError) as raised:
        S.acquire_codex_stored_auth(path)
    assert raised.value.reason_code == "SOURCE_MODE"


def test_requires_exact_current_real_uid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _source(tmp_path)
    real_uid = os.getuid()
    monkeypatch.setattr(S.os, "getuid", lambda: real_uid + 1)
    with pytest.raises(S.CodexStoredAuthSourceError) as raised:
        S.acquire_codex_stored_auth(path)
    assert raised.value.reason_code == "SOURCE_OWNER"


def test_rejects_leaf_symlink(tmp_path: Path) -> None:
    target = _source(tmp_path / "target")
    alias_dir = tmp_path / "alias" / ".codex"
    alias_dir.mkdir(parents=True)
    alias = alias_dir / "auth.json"
    alias.symlink_to(target)
    with pytest.raises(S.CodexStoredAuthSourceError) as raised:
        S.acquire_codex_stored_auth(alias)
    assert raised.value.reason_code == "SOURCE_OPEN"


def test_rejects_symlink_in_ancestry(tmp_path: Path) -> None:
    target_dir = tmp_path / "real"
    path = _source(target_dir)
    alias = tmp_path / "profile-link"
    alias.symlink_to(path.parent.parent, target_is_directory=True)
    linked_path = alias / ".codex" / "auth.json"
    with pytest.raises(S.CodexStoredAuthSourceError) as raised:
        S.acquire_codex_stored_auth(linked_path)
    assert raised.value.reason_code == "SOURCE_OPEN"


def test_rejects_hardlink(tmp_path: Path) -> None:
    path = _source(tmp_path)
    os.link(path, path.parent / "backup")
    with pytest.raises(S.CodexStoredAuthSourceError) as raised:
        S.acquire_codex_stored_auth(path)
    assert raised.value.reason_code == "SOURCE_HARDLINK"


def test_rejects_sparse_oversize_before_read(tmp_path: Path) -> None:
    path = _source(tmp_path)
    with path.open("r+b") as handle:
        handle.truncate(S.MAX_CODEX_AUTH_BYTES + 1)
    path.chmod(0o600)
    with pytest.raises(S.CodexStoredAuthSourceError) as raised:
        S.acquire_codex_stored_auth(path)
    assert raised.value.reason_code == "SOURCE_SIZE"


@pytest.mark.parametrize(
    "spelling",
    (
        "relative/auth.json",
        "/tmp/../tmp/auth.json",
        "/tmp//auth.json",
        "/tmp/not-auth.json",
        "/tmp/auth.json/",
    ),
)
def test_rejects_nonexact_paths(spelling: str) -> None:
    with pytest.raises(S.CodexStoredAuthSourceError) as raised:
        S.acquire_codex_stored_auth(spelling)
    assert raised.value.reason_code == "INVALID_PATH"
    assert spelling not in str(raised.value)


def test_windows_rejects_before_filesystem_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(S.sys, "platform", "win32")
    monkeypatch.setattr(
        S.os,
        "open",
        lambda *_args, **_kwargs: pytest.fail("Windows route touched filesystem"),
    )
    with pytest.raises(S.CodexStoredAuthSourceError) as raised:
        S.acquire_codex_stored_auth("C:/Users/fixture/.codex/auth.json")
    assert raised.value.reason_code == "UNSUPPORTED_HOST"


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin-only custody gate")
def test_darwin_fails_closed_without_descriptor_security_verifier(
    tmp_path: Path,
) -> None:
    path = _source(tmp_path)
    with pytest.raises(S.CodexStoredAuthSourceError) as raised:
        _ACQUIRE(path)
    assert raised.value.reason_code == "DARWIN_SECURITY_VERIFIER_REQUIRED"
    assert str(path) not in _traceback_local_text(raised.value)


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin verifier contract")
def test_darwin_descriptor_verifier_is_replayed_and_compression_denial_closes(
    tmp_path: Path,
) -> None:
    path = _source(tmp_path)
    calls = 0

    def verifier(_descriptor: int) -> bool:
        nonlocal calls
        calls += 1
        # Model a compiled flistxattr(XATTR_SHOWCOMPRESSION) denial on replay.
        return calls < 3

    with pytest.raises(S.CodexStoredAuthSourceError) as raised:
        _ACQUIRE(path, darwin_descriptor_security_verifier=verifier)
    assert raised.value.reason_code == "SOURCE_CHANGED"
    assert calls == 3


def test_native_custody_requirement_fails_before_filesystem_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        S,
        "_acquire_from_path_token",
        lambda _token: pytest.fail("native custody gate touched the filesystem"),
    )
    with pytest.raises(S.CodexStoredAuthSourceError) as raised:
        S.acquire_codex_stored_auth(
            "/synthetic/private/path/auth.json",
            require_native_custody=True,
        )
    assert raised.value.reason_code == "NATIVE_CUSTODY_REQUIRED"


def test_linux_descriptor_xattr_or_acl_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _source(tmp_path)
    monkeypatch.setattr(S.sys, "platform", "linux")
    monkeypatch.setattr(
        S.os,
        "listxattr",
        lambda descriptor: ["system.posix_acl_access"]
        if isinstance(descriptor, int)
        else pytest.fail("xattr check reopened a path"),
        raising=False,
    )
    with pytest.raises(S.CodexStoredAuthSourceError) as raised:
        _ACQUIRE(path)
    assert raised.value.reason_code == "SOURCE_XATTR"


def test_linux_unavailable_descriptor_metadata_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _source(tmp_path)
    monkeypatch.setattr(S.sys, "platform", "linux")
    monkeypatch.delattr(S.os, "listxattr", raising=False)
    with pytest.raises(S.CodexStoredAuthSourceError) as raised:
        _ACQUIRE(path)
    assert raised.value.reason_code == "SOURCE_METADATA_UNPROVEN"


def test_fstat_fault_at_every_acquisition_stage_has_no_fd_leak(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _source(tmp_path)
    original_fstat = S.os.fstat
    observed = 0

    def count_fstat(descriptor: int) -> os.stat_result:
        nonlocal observed
        observed += 1
        return original_fstat(descriptor)

    monkeypatch.setattr(S.os, "fstat", count_fstat)
    capability = S.acquire_codex_stored_auth(path)
    capability.discard()
    total_calls = observed
    monkeypatch.setattr(S.os, "fstat", original_fstat)
    assert total_calls >= len(path.parts)

    for fail_at in range(1, total_calls + 1):
        calls = 0

        def injected_fstat(descriptor: int) -> os.stat_result:
            nonlocal calls
            calls += 1
            if calls == fail_at:
                raise OSError("synthetic fstat fault")
            return original_fstat(descriptor)

        monkeypatch.setattr(S.os, "fstat", injected_fstat)
        before = len(os.listdir("/dev/fd"))
        with pytest.raises(S.CodexStoredAuthSourceError):
            S.acquire_codex_stored_auth(path)
        after = len(os.listdir("/dev/fd"))
        assert after == before, f"descriptor leak at fstat call {fail_at}"
        monkeypatch.setattr(S.os, "fstat", original_fstat)


@pytest.mark.skipif(sys.platform != "darwin", reason="APFS metadata fixture")
def test_real_darwin_xattr_is_rejected_by_external_descriptor_verifier(
    tmp_path: Path,
) -> None:
    path = _source(tmp_path)
    installed = subprocess.run(
        ["/usr/bin/xattr", "-w", "user.plamen-fixture", "present", str(path)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=5,
        env={},
    )
    if installed.returncode != 0:
        pytest.skip("temporary filesystem does not support Darwin xattrs")

    def verifier(descriptor: int) -> bool:
        result = subprocess.run(
            ["/usr/bin/xattr", f"/dev/fd/{descriptor}"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=(descriptor,),
            check=False,
            timeout=5,
            env={},
        )
        return result.returncode == 0 and not result.stdout

    with pytest.raises(S.CodexStoredAuthSourceError) as raised:
        _ACQUIRE(path, darwin_descriptor_security_verifier=verifier)
    assert raised.value.reason_code == "SOURCE_EXTENDED_SECURITY"


@pytest.mark.skipif(sys.platform != "darwin", reason="APFS ACL fixture")
def test_real_darwin_acl_is_rejected_by_external_verifier(tmp_path: Path) -> None:
    path = _source(tmp_path)
    installed = subprocess.run(
        ["/bin/chmod", "+a", "everyone allow read", str(path)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=5,
        env={},
    )
    if installed.returncode != 0:
        pytest.skip("temporary filesystem does not support Darwin ACLs")

    def verifier(_descriptor: int) -> bool:
        result = subprocess.run(
            ["/bin/ls", "-lde", str(path)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=5,
            env={"LC_ALL": "C"},
        )
        first = result.stdout.splitlines()[0] if result.stdout else b""
        return result.returncode == 0 and not first.split(maxsplit=1)[0].endswith(b"+")

    with pytest.raises(S.CodexStoredAuthSourceError) as raised:
        _ACQUIRE(path, darwin_descriptor_security_verifier=verifier)
    assert raised.value.reason_code == "SOURCE_EXTENDED_SECURITY"


def test_read_fault_closes_every_acquired_descriptor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _source(tmp_path)
    before = len(os.listdir("/dev/fd"))

    def fail_readv(_descriptor: int, _buffers: object) -> int:
        raise OSError("injected read failure with path that must not escape")

    monkeypatch.setattr(S.os, "readv", fail_readv)
    with pytest.raises(S.CodexStoredAuthSourceError) as raised:
        S.acquire_codex_stored_auth(path)
    after = len(os.listdir("/dev/fd"))
    assert raised.value.reason_code == "SOURCE_READ"
    assert before == after
    assert str(path) not in str(raised.value)


def test_mode_race_after_read_is_rejected_and_buffer_zeroed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _source(tmp_path)
    original = S._read_bounded_material
    captured: list[bytearray] = []

    def racing_read(descriptor: int) -> bytearray:
        result = original(descriptor)
        captured.append(result)
        path.chmod(0o644)
        return result

    monkeypatch.setattr(S, "_read_bounded_material", racing_read)
    with pytest.raises(S.CodexStoredAuthSourceError) as raised:
        S.acquire_codex_stored_auth(path)
    assert raised.value.reason_code == "SOURCE_CHANGED"
    assert captured[0] == bytearray(len(_raw()))


def test_namespace_race_after_read_is_rejected_and_buffer_zeroed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _source(tmp_path)
    original = S._read_bounded_material
    captured: list[bytearray] = []

    def racing_read(descriptor: int) -> bytearray:
        result = original(descriptor)
        captured.append(result)
        replacement = path.with_name("replacement")
        replacement.write_bytes(_raw("replacement-secret"))
        replacement.chmod(0o600)
        os.replace(replacement, path)
        return result

    monkeypatch.setattr(S, "_read_bounded_material", racing_read)
    with pytest.raises(S.CodexStoredAuthSourceError) as raised:
        S.acquire_codex_stored_auth(path)
    assert raised.value.reason_code == "SOURCE_CHANGED"
    assert captured[0] == bytearray(len(_raw()))


def test_source_security_is_replayed_at_consumption(tmp_path: Path) -> None:
    path = _source(tmp_path)
    capability = S.acquire_codex_stored_auth(path)
    path.chmod(0o644)
    called = False

    def sink(_material: bytearray) -> None:
        nonlocal called
        called = True

    with pytest.raises(S.CodexStoredAuthSourceError) as raised:
        capability.consume_into_private_sink(sink)
    assert raised.value.reason_code == "SOURCE_CHANGED"
    assert called is False
    assert str(path) not in _traceback_local_text(raised.value)


@pytest.mark.skipif(
    not (sys.platform == "darwin" or sys.platform.startswith("linux")),
    reason="descriptor-zero fixture is POSIX-only",
)
def test_descriptor_zero_is_owned_and_closed_without_live_auth(tmp_path: Path) -> None:
    path = _source(tmp_path)
    code = """
import os
import sys
sys.path.insert(0, sys.argv[1])
import codex_stored_auth_source as source
os.close(0)
kwargs = {}
if sys.platform == "darwin":
    kwargs["darwin_descriptor_security_verifier"] = lambda descriptor: True
capability = source.acquire_codex_stored_auth(sys.argv[2], **kwargs)
capability.consume_into_private_sink(lambda material: None)
try:
    os.fstat(0)
except OSError:
    raise SystemExit(0)
raise SystemExit(9)
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", code, str(Path(S.__file__).parent), str(path)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=10,
        env={},
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
