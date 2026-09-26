"""Native Darwin write-once CAS publication and recovery contracts."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

import pytest

import rooted_path_io as RIO


pytestmark = pytest.mark.skipif(
    sys.platform != "darwin",
    reason="Darwin fclonefileat publication contract",
)


def _write_private(path: Path, raw: bytes) -> None:
    path.write_bytes(raw)
    path.chmod(0o600)


def test_darwin_typed_helper_publishes_clone_and_quarantines_exact_stage(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "verification_queue.json"
    expected = b'{"darwin":"descriptor-bound-clone"}\n'
    stage = RIO._write_once_stage_path(destination, expected)
    quarantine = RIO._darwin_cas_quarantine_path(stage)

    RIO.durable_write_once_bytes(destination, expected)
    RIO.durable_write_once_bytes(destination, expected)

    assert destination.read_bytes() == expected
    assert destination.stat().st_nlink == 1
    assert not RIO.lexists(stage)
    assert quarantine.read_bytes() == expected
    assert quarantine.stat().st_nlink == 1
    assert quarantine.stat().st_ino != destination.stat().st_ino
    assert not list(tmp_path.glob(".plamen-darwin-cas-*"))


def test_darwin_helper_call_cardinality_is_bounded_for_create_and_resume(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "verification_queue.json"
    expected = b'{"darwin":"bounded-helper-cardinality"}\n'
    calls: list[str] = []
    real_helper = RIO._darwin_run_cas_helper

    def _counted_helper(mode: str, *args: object, **kwargs: object) -> None:
        calls.append(mode)
        real_helper(mode, *args, **kwargs)

    monkeypatch.setattr(RIO, "_darwin_run_cas_helper", _counted_helper)

    RIO.durable_write_once_bytes(destination, expected)
    assert calls.count("validate") == 5
    assert calls.count("publish") == 1
    assert calls.count("retire") == 0

    calls.clear()
    RIO.durable_write_once_bytes(destination, expected)
    assert calls.count("validate") == 5
    assert calls.count("publish") == 0
    assert calls.count("retire") == 0


def test_darwin_native_validate_owns_one_ordered_durability_barrier() -> None:
    source = Path(RIO.__file__).with_name("darwin_cas_helper.c").read_text(
        encoding="utf-8"
    )
    branch_start = source.index('if (strcmp(mode, "validate") == 0) {')
    branch_end = source.index(
        '} else if (strcmp(mode, "publish") == 0) {', branch_start
    )
    branch = source[branch_start:branch_end]

    first_validation = branch.index("validate_named_destination(")
    source_fsync = branch.index("fsync(source_fd)")
    directory_barrier = branch.index("durable_sync(directory_fd)")
    second_validation = branch.rindex("validate_named_destination(")

    assert first_validation < source_fsync < directory_barrier < second_validation
    assert "durable_sync(source_fd)" not in branch


def test_darwin_stage_name_swap_never_becomes_accepted_final(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "verification_queue.json"
    expected = b"darwin-held-source\n"
    foreign = b"darwin-name-racer\n"
    stage = RIO._write_once_stage_path(destination, expected)
    displaced = tmp_path / ".displaced-exact-stage"
    _write_private(stage, expected)

    def _swap(source: Path, _destination: Path) -> None:
        os.replace(source, displaced)
        _write_private(source, foreign)

    monkeypatch.setattr(RIO, "_write_once_pre_publish_hook", _swap)

    with pytest.raises(RIO.DurableWriteOnceStageError):
        RIO.durable_write_once_bytes(destination, expected)

    # The helper clones the already-held exact descriptor, not the swapped
    # pathname.  The foreign stage is rolled back or retained in quarantine;
    # neither outcome can make foreign bytes an accepted final postimage.
    assert destination.read_bytes() == expected
    assert displaced.read_bytes() == expected
    surviving_foreign = [
        path
        for path in (stage, RIO._darwin_cas_quarantine_path(stage))
        if RIO.lexists(path)
    ]
    assert len(surviving_foreign) == 1
    assert surviving_foreign[0].read_bytes() == foreign


def test_darwin_helper_failure_preserves_exact_recoverable_stage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "verification_queue.json"
    expected = b"darwin-helper-crash\n"
    stage = RIO._write_once_stage_path(destination, expected)
    def _false_helper() -> tuple[Path, int]:
        helper = Path("/usr/bin/false")
        return helper, os.open(helper, os.O_RDONLY | os.O_CLOEXEC)

    monkeypatch.setattr(RIO, "_darwin_open_cas_helper_executable", _false_helper)

    with pytest.raises(RIO.DurableWriteOnceDebtError) as caught:
        RIO.durable_write_once_bytes(destination, expected)

    assert caught.value.cleanup_state == (
        "DARWIN_CAS_PUBLICATION_FAILED_PRESERVED"
    )
    assert not destination.exists()
    assert stage.read_bytes() == expected


def test_darwin_exact_concurrent_winner_is_accepted_without_stage_name(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "verification_queue.json"
    expected = b"darwin-exact-concurrent-winner\n"
    stage = RIO._write_once_stage_path(destination, expected)

    monkeypatch.setattr(
        RIO,
        "_write_once_pre_publish_hook",
        lambda _stage, target: _write_private(target, expected),
    )

    RIO.durable_write_once_bytes(destination, expected)

    assert destination.read_bytes() == expected
    assert not RIO.lexists(stage)
    assert RIO._darwin_cas_quarantine_path(stage).read_bytes() == expected


def test_darwin_retained_quarantine_cannot_mask_foreign_bytes(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "verification_queue.json"
    expected = b"darwin-exact-final\n"
    _write_private(destination, expected)
    stage = RIO._write_once_stage_path(destination, expected)
    quarantine = RIO._darwin_cas_quarantine_path(stage)
    _write_private(quarantine, b"foreign-retained-stage\n")

    with pytest.raises(RIO.DurableWriteOnceStageError):
        RIO.durable_write_once_bytes(destination, expected)

    assert destination.read_bytes() == expected
    assert quarantine.read_bytes() == b"foreign-retained-stage\n"


def test_darwin_parent_name_swap_cannot_redirect_held_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "verification_queue.json"
    expected = b"darwin-parent-capability\n"
    stage = RIO._write_once_stage_path(destination, expected)
    displaced = tmp_path.parent / f"{tmp_path.name}-displaced"

    def _swap_parent(source: Path, _destination: Path) -> None:
        os.rename(tmp_path, displaced)
        tmp_path.mkdir(mode=0o700)
        os.replace(displaced / source.name, tmp_path / source.name)

    monkeypatch.setattr(RIO, "_write_once_pre_publish_hook", _swap_parent)
    try:
        with pytest.raises(RIO.RootedPathIOError, match="parent"):
            RIO.durable_write_once_bytes(destination, expected)
        assert not destination.exists()
        assert not (displaced / destination.name).exists()
        assert stage.read_bytes() == expected
    finally:
        if displaced.exists():
            shutil.rmtree(displaced)


def test_darwin_case_distinct_destination_alias_is_rejected(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "verification_queue.json"
    alias = tmp_path / "Verification_Queue.json"
    expected = b"darwin-case-authority\n"
    _write_private(alias, expected)
    if not destination.exists() or not os.path.samefile(alias, destination):
        pytest.skip("test volume is case-sensitive")

    with pytest.raises(RIO.RootedPathIOError, match="alias"):
        RIO.durable_write_once_bytes(destination, expected)


def test_darwin_unicode_normalization_destination_alias_is_rejected(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "caf\N{LATIN SMALL LETTER E WITH ACUTE}.json"
    alias = tmp_path / "cafe\N{COMBINING ACUTE ACCENT}.json"
    expected = b"darwin-unicode-authority\n"
    _write_private(alias, expected)
    if not destination.exists() or not os.path.samefile(alias, destination):
        pytest.skip("test volume is normalization-sensitive")

    with pytest.raises(RIO.RootedPathIOError, match="alias"):
        RIO.durable_write_once_bytes(destination, expected)


def test_darwin_stage_recreation_during_final_sync_is_never_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_sync = RIO._fsync_file_descriptor
    armed: dict[str, Path | None] = {"stage": None}

    def _sync_and_recreate(descriptor: int) -> None:
        real_sync(descriptor)
        stage = armed["stage"]
        if stage is None:
            return
        quarantine = RIO._darwin_cas_quarantine_path(stage)
        try:
            os.stat(quarantine.name, dir_fd=descriptor, follow_symlinks=False)
        except OSError:
            return
        try:
            os.stat(stage.name, dir_fd=descriptor, follow_symlinks=False)
            return
        except FileNotFoundError:
            pass
        racer = os.open(
            stage.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=descriptor,
        )
        try:
            os.write(racer, b"foreign-stage-recreation\n")
            os.fsync(racer)
        finally:
            os.close(racer)

    monkeypatch.setattr(RIO, "_fsync_file_descriptor", _sync_and_recreate)
    for attempt in range(5):
        parent = tmp_path / f"attempt-{attempt}"
        parent.mkdir(mode=0o700)
        destination = parent / "verification_queue.json"
        expected = f"darwin-stage-race-{attempt}\n".encode()
        stage = RIO._write_once_stage_path(destination, expected)
        armed["stage"] = stage

        with pytest.raises(RIO.DurableWriteOnceDebtError) as caught:
            RIO.durable_write_once_bytes(destination, expected)

        assert caught.value.cleanup_state == (
            "DARWIN_STAGE_RECREATED_DURING_RETIREMENT"
        )
        assert destination.read_bytes() == expected
        assert stage.read_bytes() == b"foreign-stage-recreation\n"


def test_darwin_acl_inheriting_parent_is_rejected(tmp_path: Path) -> None:
    destination = tmp_path / "verification_queue.json"
    expected = b"darwin-parent-acl\n"
    subprocess.run(
        (
            "/bin/chmod",
            "+a",
            "everyone allow write,file_inherit",
            os.fspath(tmp_path),
        ),
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        with pytest.raises(RIO.DurableWriteOnceDebtError):
            RIO.durable_write_once_bytes(destination, expected)
        assert not destination.exists()
    finally:
        subprocess.run(
            ("/bin/chmod", "-N", os.fspath(tmp_path)),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )


@pytest.mark.parametrize("target_kind", ("stage", "destination"))
def test_darwin_extended_attribute_is_rejected(
    tmp_path: Path,
    target_kind: str,
) -> None:
    destination = tmp_path / "verification_queue.json"
    expected = b"darwin-xattr-authority\n"
    target = (
        RIO._write_once_stage_path(destination, expected)
        if target_kind == "stage"
        else destination
    )
    _write_private(target, expected)
    subprocess.run(
        (
            "/usr/bin/xattr",
            "-w",
            "com.plamen.untrusted",
            "foreign-metadata",
            os.fspath(target),
        ),
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    with pytest.raises(RIO.DurableWriteOnceDebtError):
        RIO.durable_write_once_bytes(destination, expected)


def test_darwin_broad_exact_destination_mode_is_rejected(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "verification_queue.json"
    expected = b"darwin-mode-authority\n"
    destination.write_bytes(expected)
    destination.chmod(0o666)

    with pytest.raises(RIO.DurableWriteOnceDebtError):
        RIO.durable_write_once_bytes(destination, expected)


def test_darwin_flagged_exact_destination_is_rejected(tmp_path: Path) -> None:
    destination = tmp_path / "verification_queue.json"
    expected = b"darwin-flags-authority\n"
    _write_private(destination, expected)
    os.chflags(destination, stat.UF_NODUMP)
    try:
        with pytest.raises(RIO.DurableWriteOnceDebtError):
            RIO.durable_write_once_bytes(destination, expected)
    finally:
        os.chflags(destination, 0)


def test_darwin_helper_is_unambiguous_when_parent_opens_as_fd_zero(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "verification_queue.json"
    expected = b"darwin-closed-stdio\n"
    program = "\n".join(
        (
            "import os, sys",
            "sys.path.insert(0, sys.argv[1])",
            "import rooted_path_io as rio",
            "os.close(0)",
            "rio.durable_write_once_bytes(sys.argv[2], bytes.fromhex(sys.argv[3]))",
        )
    )
    completed = subprocess.run(
        (
            sys.executable,
            "-c",
            program,
            os.fspath(Path(RIO.__file__).parent),
            os.fspath(destination),
            expected.hex(),
        ),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr.decode(
        "utf-8", errors="replace"
    )
    assert destination.read_bytes() == expected


def test_darwin_cached_helper_symlink_substitution_is_rejected(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "verification_queue.json"
    expected = b"darwin-helper-identity\n"
    program = "\n".join(
        (
            "import os, sys",
            "sys.path.insert(0, sys.argv[1])",
            "import rooted_path_io as rio",
            "helper = rio._darwin_cas_helper_executable()",
            "helper.parent.chmod(0o700)",
            "helper.unlink()",
            "helper.symlink_to('/usr/bin/false')",
            "helper.parent.chmod(0o500)",
            "try:",
            "    rio.durable_write_once_bytes(sys.argv[2], bytes.fromhex(sys.argv[3]))",
            "except rio.DurableWriteOnceDebtError as exc:",
            "    assert 'identity validation failed' in str(exc)",
            "    assert not os.path.exists(sys.argv[2])",
            "else:",
            "    raise AssertionError('substituted helper was accepted')",
        )
    )
    completed = subprocess.run(
        (
            sys.executable,
            "-c",
            program,
            os.fspath(Path(RIO.__file__).parent),
            os.fspath(destination),
            expected.hex(),
        ),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr.decode(
        "utf-8", errors="replace"
    )
    assert not destination.exists()


@pytest.mark.parametrize(
    ("arguments", "executable", "stream"),
    (
        (("/usr/bin/yes", "x"), Path("/usr/bin/yes"), "stdout"),
        (
            ("/bin/sh", "-c", "while :; do echo x >&2; done"),
            Path("/bin/sh"),
            "stderr",
        ),
    ),
)
def test_darwin_helper_output_capture_is_bounded(
    arguments: tuple[str, ...],
    executable: Path,
    stream: str,
) -> None:
    with pytest.raises(RIO.RootedPathIOError, match=f"bounded {stream}"):
        RIO._darwin_run_bounded_helper_process(
            arguments,
            executable=executable,
            input_bytes=b"",
            pass_fds=(),
        )


def test_darwin_python_protocol_rejects_oversized_payload_before_stage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "verification_queue.json"
    monkeypatch.setattr(RIO, "_DARWIN_CAS_MAX_PAYLOAD_BYTES", 32)

    with pytest.raises(RIO.RootedPathIOError, match="payload exceeds"):
        RIO.durable_write_once_bytes(destination, b"x" * 33)

    assert not destination.exists()
    assert not list(tmp_path.glob(".plamen-write-once-*.stage"))


def test_darwin_native_protocol_rejects_oversized_stdin(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "darwin-cas-helper-limited"
    compiled = subprocess.run(
        (
            "/usr/bin/clang",
            "-x",
            "c",
            "-std=c11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-DPLAMEN_MAX_PAYLOAD_BYTES=32ULL",
            os.fspath(Path(RIO.__file__).with_name("darwin_cas_helper.c")),
            "-o",
            os.fspath(executable),
        ),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        check=False,
    )
    assert compiled.returncode == 0, compiled.stderr.decode(
        "utf-8", errors="replace"
    )
    raw = b"x" * 33
    source = tmp_path / "source.bin"
    _write_private(source, raw)
    directory_descriptor = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    source_descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        source_row = os.fstat(source_descriptor)
        completed = subprocess.run(
            (
                os.fspath(executable),
                "validate",
                str(directory_descriptor),
                source.name,
                str(source_descriptor),
                str(source_row.st_dev),
                str(source_row.st_ino),
                "-",
                str(len(raw)),
            ),
            input=raw,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            pass_fds=(directory_descriptor, source_descriptor),
            timeout=60,
            check=False,
        )
    finally:
        os.close(source_descriptor)
        os.close(directory_descriptor)

    assert completed.returncode != 0
    assert b"stage=stdin" in completed.stderr
