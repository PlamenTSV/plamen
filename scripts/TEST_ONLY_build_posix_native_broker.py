#!/usr/bin/env python3
"""Build the native broker for focused tests only.

This helper is intentionally not a production builder.  Its basename, result
schema, and metadata all carry TEST_ONLY, and it never claims packaging or
execution authority.  The production native-builder/descriptor-handoff gate
remains closed in ``build_posix_native_supervisor.py``.
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
if os.name == "posix":
    import fcntl
else:
    fcntl = None  # type: ignore[assignment]
from pathlib import Path
import stat
import subprocess
import sys
from types import MappingProxyType
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SOURCE = REPOSITORY_ROOT / "native" / "posix" / "plamen_native_broker.c"
SOURCE_INCLUDE_ROOT = REPOSITORY_ROOT / "native" / "posix"
SHARED_BROKER_HEADER = (
    REPOSITORY_ROOT / "native" / "include" / "plamen_broker_v2.h"
)
COMPILER = Path("/Library/Developer/CommandLineTools/usr/bin/clang")
XCRUN = Path("/usr/bin/xcrun")
ENVIRONMENT = {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"}
OUTPUT_NAME = "plamen_native_broker_TEST_ONLY"


class TestOnlyBuildError(RuntimeError):
    pass


def _require_posix() -> None:
    if fcntl is None:
        raise TestOnlyBuildError(
            "the TEST_ONLY native broker builder requires POSIX descriptor APIs"
        )


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        ).encode("ascii")
        + b"\n"
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sha256_fd(descriptor: int) -> str:
    info = os.fstat(descriptor)
    digest = hashlib.sha256()
    offset = 0
    while offset < info.st_size:
        chunk = os.pread(descriptor, min(65536, info.st_size - offset), offset)
        if not chunk:
            raise TestOnlyBuildError("retained TEST_ONLY input was truncated")
        digest.update(chunk)
        offset += len(chunk)
    if os.pread(descriptor, 1, info.st_size):
        raise TestOnlyBuildError("retained TEST_ONLY input grew during hashing")
    return digest.hexdigest()


def _identity(descriptor: int) -> dict[str, int | str]:
    info = os.fstat(descriptor)
    return {
        "device": int(info.st_dev), "inode": int(info.st_ino),
        "mode": int(info.st_mode), "uid": int(info.st_uid),
        "gid": int(info.st_gid), "size": int(info.st_size),
        "nlink": int(info.st_nlink), "mtime_ns": int(info.st_mtime_ns),
        "ctime_ns": int(info.st_ctime_ns),
        "flags": int(getattr(info, "st_flags", 0)),
        "sha256": _sha256_fd(descriptor),
    }


def _copy_exact(source: int, destination: int, size: int) -> None:
    offset = 0
    while offset < size:
        chunk = os.pread(source, min(65536, size - offset), offset)
        if not chunk:
            raise TestOnlyBuildError("source changed while snapshotting")
        view = memoryview(chunk)
        while view:
            amount = os.write(destination, view)
            if amount <= 0:
                raise TestOnlyBuildError("source snapshot write failed")
            view = view[amount:]
        offset += len(chunk)
    if os.pread(source, 1, size):
        raise TestOnlyBuildError("source grew while snapshotting")


def _freeze_descriptor(
    descriptor: int, mode: int, *, expected_nlink: int,
) -> dict[str, int | str]:
    info = os.fstat(descriptor)
    if stat.S_IMODE(info.st_mode) != mode:
        raise TestOnlyBuildError("TEST_ONLY read-only descriptor mode changed")
    _require_read_only(descriptor)
    immutable = getattr(stat, "UF_IMMUTABLE", 0)
    if not immutable or not hasattr(os, "chflags"):
        raise TestOnlyBuildError("TEST_ONLY Darwin immutable descriptor authority is absent")
    os.chflags(f"/dev/fd/{descriptor}", immutable)
    identity = _identity(descriptor)
    if (
        identity["nlink"] != expected_nlink
        or stat.S_IMODE(int(identity["mode"])) != mode
        or not int(identity["flags"]) & immutable
    ):
        raise TestOnlyBuildError("TEST_ONLY retained descriptor did not freeze")
    return identity


def _require_read_only(descriptor: int) -> None:
    flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
    if flags & os.O_ACCMODE != os.O_RDONLY:
        raise TestOnlyBuildError("TEST_ONLY retained descriptor has a writable alias")
    try:
        os.pwrite(descriptor, b"\0", 0)
    except OSError as exc:
        if exc.errno != errno.EBADF:
            raise TestOnlyBuildError(
                "TEST_ONLY read-only descriptor write rejection was ambiguous"
            ) from exc
    else:
        raise TestOnlyBuildError("TEST_ONLY retained descriptor accepted pwrite")


def _same_inode(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev,
        left.st_ino,
        stat.S_IFMT(left.st_mode),
        left.st_uid,
        left.st_gid,
    ) == (
        right.st_dev,
        right.st_ino,
        stat.S_IFMT(right.st_mode),
        right.st_uid,
        right.st_gid,
    )


def _directory_identity(descriptor: int) -> tuple[int, int, int, int, int]:
    observed = os.fstat(descriptor)
    if not stat.S_ISDIR(observed.st_mode):
        raise TestOnlyBuildError("TEST_ONLY include root is not a directory")
    return (
        int(observed.st_dev), int(observed.st_ino), int(observed.st_mode),
        int(observed.st_uid), int(observed.st_gid),
    )


class UNAUTHENTICATED_TEST_HARNESS_BrokerProcess:
    """Explicitly non-authoritative wrapper around a wire-test subprocess."""

    __slots__ = ("_process",)

    def __init__(self, process: subprocess.Popen[bytes]) -> None:
        self._process = process

    @property
    def pid(self) -> int:
        return self._process.pid

    @property
    def returncode(self) -> int | None:
        return self._process.returncode

    def poll(self) -> int | None:
        return self._process.poll()

    def wait(self, timeout: float | None = None) -> int:
        return self._process.wait(timeout=timeout)

    def kill(self) -> None:
        self._process.kill()


def _clear_immutable(descriptor: int) -> None:
    os.chflags(f"/dev/fd/{descriptor}", 0)


class TEST_ONLY_BrokerArtifact:
    """A retained, immutable, unlinked test artifact; never production authority."""

    __slots__ = (
        "_descriptor", "_identity", "_root_fd", "_build_fd", "_root_path",
        "_output_name", "_root_anchor", "_build_anchor", "metadata",
        "build_key_sha256",
    )

    def __init__(
        self, descriptor: int, identity: dict[str, int | str],
        metadata: dict[str, Any], build_key: str, root_fd: int, build_fd: int,
        root_path: Path, output_name: str,
    ) -> None:
        self._descriptor = descriptor
        self._identity = MappingProxyType(dict(identity))
        self.metadata = MappingProxyType(dict(metadata))
        self.build_key_sha256 = build_key
        self._root_fd = root_fd
        self._build_fd = build_fd
        self._root_path = root_path
        self._output_name = output_name
        root_info = os.fstat(root_fd)
        self._root_anchor = (
            root_info.st_dev, root_info.st_ino, root_info.st_mode,
            root_info.st_uid, root_info.st_gid,
        )
        info = os.fstat(build_fd)
        self._build_anchor = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)

    def fileno(self) -> int:
        if self._descriptor < 0:
            raise TestOnlyBuildError("TEST_ONLY broker artifact is closed")
        return self._descriptor

    def revalidate(self) -> None:
        _require_read_only(self.fileno())
        if _identity(self.fileno()) != dict(self._identity):
            raise TestOnlyBuildError("retained TEST_ONLY broker artifact changed")
        root_path_fd = rebound_fd = -1
        try:
            root_path_fd = os.open(
                self._root_path,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
            root_named = os.fstat(root_path_fd)
            root_anchor = (
                root_named.st_dev, root_named.st_ino, root_named.st_mode,
                root_named.st_uid, root_named.st_gid,
            )
            if root_anchor != self._root_anchor:
                raise TestOnlyBuildError(
                    "TEST_ONLY output-root pathname left its retained descriptor"
                )
            rebound_fd = os.open(
                self.build_key_sha256,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=self._root_fd,
            )
            rebound = os.fstat(rebound_fd)
            rebound_anchor = (
                rebound.st_dev, rebound.st_ino, rebound.st_mode,
                rebound.st_uid, rebound.st_gid,
            )
            named = os.stat(
                self._output_name, dir_fd=rebound_fd, follow_symlinks=False,
            )
            retained = os.fstat(self.fileno())
            if rebound_anchor != self._build_anchor or (
                named.st_dev, named.st_ino, named.st_mode, named.st_uid,
                named.st_gid, named.st_size, named.st_nlink,
                named.st_mtime_ns, named.st_ctime_ns,
            ) != (
                retained.st_dev, retained.st_ino, retained.st_mode,
                retained.st_uid, retained.st_gid, retained.st_size,
                retained.st_nlink, retained.st_mtime_ns, retained.st_ctime_ns,
            ):
                raise TestOnlyBuildError("TEST_ONLY published name left its retained descriptor")
        except OSError as exc:
            raise TestOnlyBuildError("TEST_ONLY publication pathname changed") from exc
        finally:
            if rebound_fd >= 0:
                os.close(rebound_fd)
            if root_path_fd >= 0:
                os.close(root_path_fd)

    def read_bytes(self) -> bytes:
        self.revalidate()
        size = int(self._identity["size"])
        return os.pread(self.fileno(), size, 0)

    def TEST_ONLY_spawn_path(self) -> str:
        raise TestOnlyBuildError(
            "TEST_ONLY pathname execution is forbidden; consume the retained handle"
        )

    def TEST_ONLY_spawn(self, _control_fd: object) -> None:
        """Hard-stop: Darwin has no non-bypassable retained-FD exec primitive."""
        raise TestOnlyBuildError(
            "TEST_ONLY authority-claiming spawn is unavailable on Darwin"
        )

    def UNAUTHENTICATED_TEST_HARNESS_spawn(
        self, control_fd: int,
    ) -> UNAUTHENTICATED_TEST_HARNESS_BrokerProcess:
        """Path-launch the broker solely for non-authoritative wire-core tests."""
        if type(control_fd) is not int:
            raise TestOnlyBuildError("test-harness control descriptor must be exact int")
        control_info = os.fstat(control_fd)
        if not stat.S_ISSOCK(control_info.st_mode):
            raise TestOnlyBuildError("test-harness control descriptor is not a socket")
        self.revalidate()
        observed_path = self._root_path / self.build_key_sha256 / self._output_name
        process = subprocess.Popen(
            ["plamen_native_broker_UNAUTHENTICATED_TEST_HARNESS",
             "--control-fd", str(control_fd)],
            executable=str(observed_path), stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            close_fds=True, pass_fds=(control_fd,), env={}, cwd="/",
        )
        return UNAUTHENTICATED_TEST_HARNESS_BrokerProcess(process)

    def public_result(self) -> dict[str, object]:
        self.revalidate()
        return {
            "schema": "plamen.native_broker.TEST_ONLY_result.v2",
            "production_packaging_allowed": False,
            "build_key_sha256": self.build_key_sha256,
            "artifact_descriptor_handoff": "RETAINED_IMMUTABLE_TEST_ONLY_FD",
            "artifact_identity": dict(self._identity),
            "metadata_sha256": hashlib.sha256(_canonical(dict(self.metadata))).hexdigest(),
        }

    def close(self) -> None:
        if self._descriptor >= 0:
            try:
                _clear_immutable(self._descriptor)
            finally:
                try:
                    os.unlink(self._output_name, dir_fd=self._build_fd)
                    os.fsync(self._build_fd)
                except OSError:
                    pass
                os.close(self._descriptor)
                self._descriptor = -1
        if self._build_fd >= 0:
            os.close(self._build_fd)
            self._build_fd = -1
        if self._root_fd >= 0:
            try:
                os.rmdir(self.build_key_sha256, dir_fd=self._root_fd)
                os.fsync(self._root_fd)
            except OSError:
                pass
            os.close(self._root_fd)
            self._root_fd = -1

    def __enter__(self) -> TEST_ONLY_BrokerArtifact:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def build_for_testing(output_root: Path) -> TEST_ONLY_BrokerArtifact:
    _require_posix()
    if sys.platform != "darwin" or os.geteuid() == 0:
        raise TestOnlyBuildError("TEST_ONLY broker build requires unprivileged macOS")
    absolute = Path(os.path.abspath(os.fspath(output_root)))
    resolved = output_root.resolve(strict=True)
    if absolute != resolved:
        raise TestOnlyBuildError("TEST_ONLY output root has a symlink alias")
    root_info = resolved.stat()
    if root_info.st_uid != os.geteuid() or stat.S_IMODE(root_info.st_mode) != 0o700:
        raise TestOnlyBuildError("TEST_ONLY output root must be owned with mode 0700")
    environment = MappingProxyType(dict(ENVIRONMENT))
    source_path = SOURCE.resolve(strict=True)
    source_fd = os.open(source_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    include_root_path = SOURCE_INCLUDE_ROOT.resolve(strict=True)
    header_path = SHARED_BROKER_HEADER.resolve(strict=True)
    include_root_fd = os.open(
        include_root_path,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    header_fd = os.open(
        header_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        source_before = _identity(source_fd)
        include_root_before = _directory_identity(include_root_fd)
        header_before = _identity(header_fd)
        named_header_before = os.stat(header_path, follow_symlinks=False)
        if not _same_inode(os.fstat(header_fd), named_header_before):
            raise TestOnlyBuildError(
                "TEST_ONLY shared broker header pathname was substituted"
            )
        completed = subprocess.run(
            (str(XCRUN), "--show-sdk-path"),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, env=environment, close_fds=True,
            check=False, timeout=10,
        )
        if completed.returncode != 0 or not 1 <= len(completed.stdout) <= 4096:
            raise TestOnlyBuildError("TEST_ONLY SDK lookup failed")
        sdk = Path(completed.stdout.decode("utf-8", "strict").strip()).resolve(strict=True)
        metadata = {
            "schema": "plamen.native_broker.TEST_ONLY_build.v1",
            "production_packaging_allowed": False,
            "source_path_observation": str(source_path),
            "source_identity": source_before,
            "source_include_root_path_observation": str(include_root_path),
            "source_include_root_identity": list(include_root_before),
            "shared_broker_header_path_observation": str(header_path),
            "shared_broker_header_identity": header_before,
            "compiler_source_input": (
                "RETAINED_UNLINKED_READ_ONLY_UF_IMMUTABLE_FD"
            ),
            "builder_path_observation": str(Path(__file__).resolve()),
            "builder_sha256": _sha256(Path(__file__).resolve()),
            "compiler_path_observation": str(COMPILER.resolve(strict=True)),
            "compiler_sha256": _sha256(COMPILER.resolve(strict=True)),
            "sdk_path_observation": str(sdk),
            "sdk_settings_sha256": _sha256(sdk / "SDKSettings.json"),
            "closed_environment": dict(environment),
            "command_template": [
                "{OBSERVED_CLT_CLANG}", "-isysroot", "{OBSERVED_SDK}",
                "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wconversion",
                "-O2", "-DPLAMEN_NATIVE_BROKER_TEST_ONLY=1",
                "-I", "{ADMITTED_NATIVE_POSIX_INCLUDE_ROOT}", "-x", "c",
                "{RETAINED_UNLINKED_READ_ONLY_IMMUTABLE_SOURCE_FD}", "-o",
                "{RETAINED_UNLINKED_PREOWNED_OUTPUT_FD}",
            ],
            "output_basename": OUTPUT_NAME,
        }
        build_key = hashlib.sha256(_canonical(metadata)).hexdigest()
        root_fd = os.open(
            resolved,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
    except BaseException:
        os.close(source_fd)
        os.close(header_fd)
        os.close(include_root_fd)
        raise
    build_fd = snapshot_writer_fd = snapshot_fd = -1
    artifact_writer_fd = artifact_fd = published_writer_fd = published_fd = -1
    completed_successfully = False
    try:
        os.mkdir(build_key, 0o700, dir_fd=root_fd)
        build_fd = os.open(
            build_key, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=root_fd,
        )
        os.fsync(root_fd)
        snapshot_writer_fd = os.open(
            "source.snapshot.c",
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600, dir_fd=build_fd,
        )
        _copy_exact(source_fd, snapshot_writer_fd, int(source_before["size"]))
        if _identity(source_fd) != source_before:
            raise TestOnlyBuildError("source changed while its snapshot was created")
        os.fchmod(snapshot_writer_fd, 0o400)
        os.fsync(snapshot_writer_fd)
        snapshot_fd = os.open(
            "source.snapshot.c", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=build_fd,
        )
        if not _same_inode(os.fstat(snapshot_writer_fd), os.fstat(snapshot_fd)):
            raise TestOnlyBuildError("source snapshot pathname was substituted")
        os.unlink("source.snapshot.c", dir_fd=build_fd)
        os.close(snapshot_writer_fd)
        snapshot_writer_fd = -1
        snapshot_identity = _freeze_descriptor(snapshot_fd, 0o400, expected_nlink=0)
        if snapshot_identity["sha256"] != source_before["sha256"]:
            raise TestOnlyBuildError("source snapshot differs from the authenticated input")
        artifact_writer_fd = os.open(
            "artifact.output",
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600, dir_fd=build_fd,
        )
        os.fsync(build_fd)
        command = (
            str(COMPILER), "-isysroot", str(sdk), "-std=c11", "-Wall",
            "-Wextra", "-Werror", "-Wconversion", "-O2",
            "-DPLAMEN_NATIVE_BROKER_TEST_ONLY=1",
            "-I", str(include_root_path), "-x", "c",
            f"/dev/fd/{snapshot_fd}", "-o", f"/dev/fd/{artifact_writer_fd}",
        )
        completed = subprocess.run(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, env=environment, close_fds=True,
            pass_fds=(snapshot_fd, artifact_writer_fd), check=False, timeout=120,
        )
        if completed.returncode != 0 or len(completed.stdout) > 65536:
            raise TestOnlyBuildError(
                "TEST_ONLY native broker compile failed: "
                + completed.stdout.decode("utf-8", "replace")[:4096]
            )
        if _identity(snapshot_fd) != snapshot_identity:
            raise TestOnlyBuildError("immutable compiler source descriptor changed")
        if (
            _directory_identity(include_root_fd) != include_root_before
            or _identity(header_fd) != header_before
            or not _same_inode(
                os.fstat(header_fd), os.stat(header_path, follow_symlinks=False)
            )
        ):
            raise TestOnlyBuildError(
                "TEST_ONLY admitted include authority changed during compilation"
            )
        os.fchmod(artifact_writer_fd, 0o400)
        os.fsync(artifact_writer_fd)
        artifact_fd = os.open(
            "artifact.output", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=build_fd,
        )
        if not _same_inode(os.fstat(artifact_writer_fd), os.fstat(artifact_fd)):
            raise TestOnlyBuildError("compiler output pathname was substituted")
        os.unlink("artifact.output", dir_fd=build_fd)
        os.close(artifact_writer_fd)
        artifact_writer_fd = -1
        compiler_output_identity = _freeze_descriptor(
            artifact_fd, 0o400, expected_nlink=0,
        )
        if (
            not stat.S_ISREG(int(compiler_output_identity["mode"]))
            or not compiler_output_identity["size"]
        ):
            raise TestOnlyBuildError("compiler did not create a regular retained artifact")
        if _identity(source_fd) != source_before:
            raise TestOnlyBuildError("original source changed during the TEST_ONLY build")
        published_writer_fd = os.open(
            OUTPUT_NAME,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600, dir_fd=build_fd,
        )
        _copy_exact(
            artifact_fd, published_writer_fd, int(compiler_output_identity["size"]),
        )
        os.fchmod(published_writer_fd, 0o500)
        os.fsync(published_writer_fd)
        published_fd = os.open(
            OUTPUT_NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=build_fd,
        )
        if not _same_inode(os.fstat(published_writer_fd), os.fstat(published_fd)):
            raise TestOnlyBuildError("published broker pathname was substituted")
        os.close(published_writer_fd)
        published_writer_fd = -1
        artifact_identity = _freeze_descriptor(
            published_fd, 0o500, expected_nlink=1,
        )
        if artifact_identity["sha256"] != compiler_output_identity["sha256"]:
            raise TestOnlyBuildError("published descriptor differs from compiler output")
        os.fsync(build_fd)
        os.fsync(root_fd)
        _clear_immutable(artifact_fd)
        os.close(artifact_fd)
        artifact_fd = -1
        os.close(snapshot_fd)
        snapshot_fd = -1
        artifact = TEST_ONLY_BrokerArtifact(
            published_fd, artifact_identity, metadata, build_key,
            root_fd, build_fd, resolved, OUTPUT_NAME,
        )
        artifact.revalidate()
        published_fd = root_fd = build_fd = -1
        completed_successfully = True
        return artifact
    finally:
        os.close(source_fd)
        os.close(header_fd)
        os.close(include_root_fd)
        for descriptor in (
            snapshot_writer_fd, snapshot_fd, artifact_writer_fd, artifact_fd,
            published_writer_fd, published_fd,
        ):
            if descriptor >= 0:
                try:
                    _clear_immutable(descriptor)
                except OSError:
                    pass
                os.close(descriptor)
        if build_fd >= 0:
            for name in ("source.snapshot.c", "artifact.output", OUTPUT_NAME):
                try:
                    os.unlink(name, dir_fd=build_fd)
                except OSError:
                    pass
            os.close(build_fd)
        if not completed_successfully:
            try:
                os.rmdir(build_key, dir_fd=root_fd)
                os.fsync(root_fd)
            except OSError:
                pass
        if root_fd >= 0:
            os.close(root_fd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build TEST_ONLY native broker")
    parser.add_argument("--output-root", required=True, type=Path)
    arguments = parser.parse_args(sys.argv[1:] if argv is None else argv)
    try:
        artifact = build_for_testing(arguments.output_root)
    except (OSError, ValueError, TestOnlyBuildError) as exc:
        print(f"TEST_ONLY broker build failed: {exc}", file=sys.stderr)
        return 2
    try:
        sys.stdout.buffer.write(_canonical(artifact.public_result()))
    finally:
        artifact.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
