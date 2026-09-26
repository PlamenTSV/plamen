"""Central, bounded subprocess execution with owned-tree termination.

This is the non-interactive execution primitive for mechanically invoked
toolchains.  Stdout and stderr are drained continuously into fixed-capacity
in-memory head/tail buffers.  A noisy child therefore cannot grow a temporary
file without bound or deadlock on pipe backpressure.  The provider-owned
process scope is still terminated before the bounded observations are read.

Containment is capability-specific. Windows uses suspended creation plus a
non-breakaway kill-on-close Job Object and a low-integrity write boundary.
Linux requires an explicitly delegated cgroup-v2 root plus Landlock. Other
platforms fail closed because a process group alone is not exhaustive.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import threading
import time
from typing import Any, Mapping, Sequence

from owned_process_scope import (
    OwnedProcessScope,
    OwnedProcessScopeError,
    process_tree_termination_capability,
)


DEFAULT_OUTPUT_LIMIT_BYTES = 8 * 1024 * 1024
_CAPTURE_READ_CHUNK_BYTES = 64 * 1024
_CAPTURE_EOF_TIMEOUT_SECONDS = 10.0


class OwnedProcessRunnerError(RuntimeError):
    """A command could not be launched or contained by the owned runner."""


class _OwnedProcessCancelled(RuntimeError):
    """Internal signal that a caller revoked an active execution."""


def resolve_owned_process_command(
    command: Sequence[str],
    *,
    env: Mapping[str, str] | None = None,
) -> tuple[str, ...]:
    """Resolve argv[0] under the exact environment delegated to the child."""

    argv = tuple(str(value) for value in command)
    if not argv or any(not value for value in argv):
        raise ValueError("owned process command must contain non-empty argv")
    executable = Path(argv[0])
    if not executable.is_absolute():
        authority = dict(os.environ) if env is None else dict(env)

        def environment_value(name: str) -> str | None:
            if os.name != "nt":
                return authority.get(name)
            matches = [
                value
                for key, value in authority.items()
                if key.casefold() == name.casefold()
            ]
            if len(matches) > 1:
                raise ValueError(
                    f"owned process environment has ambiguous {name} keys"
                )
            return matches[0] if matches else None

        search_path = environment_value("PATH")
        if search_path is None:
            raise FileNotFoundError(argv[0])
        if os.name == "nt":
            requested = argv[0]
            if Path(requested).name != requested:
                raise ValueError(
                    "owned process relative executable must be a bare name"
                )
            pathext = environment_value("PATHEXT")
            if pathext is None:
                raise FileNotFoundError(argv[0])
            executable_suffixes = [
                value if value.startswith(".") else f".{value}"
                for value in pathext.split(os.pathsep)
                if value
            ]
            requested_casefolded = requested.casefold()
            suffixes = (
                [""]
                if any(
                    requested_casefolded.endswith(value.casefold())
                    for value in executable_suffixes
                )
                else executable_suffixes
            )
            resolved = None
            for raw_root in search_path.split(os.pathsep):
                root = Path(raw_root)
                if not raw_root or not root.is_absolute():
                    raise ValueError(
                        "owned process PATH entries must be absolute"
                    )
                for suffix in suffixes:
                    candidate = root / f"{requested}{suffix}"
                    if candidate.is_file() and os.access(candidate, os.X_OK):
                        resolved = str(candidate)
                        break
                if resolved is not None:
                    break
        else:
            resolved = shutil.which(argv[0], path=search_path)
        if not resolved:
            raise FileNotFoundError(argv[0])
        argv = (str(Path(resolved).resolve()), *argv[1:])
    return argv


def _transaction_write_authority(capability: Mapping[str, Any]) -> str | None:
    if capability.get("exhaustive_write_confinement_authority") is True:
        return "EXHAUSTIVE"
    lease = capability.get("low_integrity_lease")
    if (
        capability.get("platform") == "WINDOWS"
        and capability.get("exhaustive_write_confinement_authority") is False
        and capability.get("serialized_low_integrity_stage_authority") is True
        and capability.get(
            "medium_integrity_source_and_canonical_protection"
        )
        is True
        and capability.get("write_confinement")
        == "LOW_INTEGRITY_TOKEN_PLUS_SERIALIZED_PLAMEN_STAGE_LEASE"
        and capability.get("write_confinement_limitation")
        == "UNRELATED_PREEXISTING_LOW_INTEGRITY_OBJECTS_OUT_OF_SCOPE"
        and isinstance(lease, Mapping)
        and lease.get("protocol")
        == "PLAMEN_WINDOWS_LOW_INTEGRITY_GLOBAL_LEASE_V1"
        and lease.get("namespace_authority")
        == "WINDOWS_KNOWN_FOLDER_LOCAL_APP_DATA"
        and lease.get("namespace_limitation")
        == "SAME_USER_MEDIUM_INTEGRITY_MUTATION_OUT_OF_SCOPE"
        and lease.get("scope")
        == "ALL_PLAMEN_LOW_INTEGRITY_LIFETIMES_FOR_THIS_WINDOWS_USER_PROFILE"
    ):
        return "SERIALIZED_PLAMEN_STAGE"
    return None


@dataclass(frozen=True)
class OwnedCompletedProcess:
    """CompletedProcess-compatible result plus containment observations."""

    args: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    duration_s: float
    process_tree_terminated: bool
    containment_capability: Mapping[str, Any]
    stdout_observed_bytes: int
    stderr_observed_bytes: int
    stdout_retained_bytes: int
    stderr_retained_bytes: int
    stdout_sha256: str
    stderr_sha256: str
    stdout_truncated: bool
    stderr_truncated: bool
    executable_binding_sha256: str


def _authority_mapping_sha256(value: Mapping[str, Any]) -> str:
    """Return a deterministic public digest without exposing guard handles."""

    return hashlib.sha256(
        json.dumps(
            dict(value),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()


def _attach_timeout_observations(
    error: subprocess.TimeoutExpired,
    *,
    argv: tuple[str, ...],
    duration_s: float,
    stdout_capture: "_BoundedPipeCapture",
    stderr_capture: "_BoundedPipeCapture",
    process_tree_terminated: bool,
    containment_capability: Mapping[str, Any],
    executable_binding_sha256: str,
) -> subprocess.TimeoutExpired:
    """Attach bounded raw-stream and execution authority to timeout debt."""

    error.args_resolved = argv  # type: ignore[attr-defined]
    error.duration_s = float(duration_s)  # type: ignore[attr-defined]
    error.stdout_observed_bytes = stdout_capture.observed_bytes  # type: ignore[attr-defined]
    error.stderr_observed_bytes = stderr_capture.observed_bytes  # type: ignore[attr-defined]
    error.stdout_retained_bytes = stdout_capture.retained_bytes  # type: ignore[attr-defined]
    error.stderr_retained_bytes = stderr_capture.retained_bytes  # type: ignore[attr-defined]
    error.stdout_sha256 = stdout_capture.sha256  # type: ignore[attr-defined]
    error.stderr_sha256 = stderr_capture.sha256  # type: ignore[attr-defined]
    error.stdout_truncated = stdout_capture.overflowed  # type: ignore[attr-defined]
    error.stderr_truncated = stderr_capture.overflowed  # type: ignore[attr-defined]
    error.process_tree_terminated = bool(process_tree_terminated)  # type: ignore[attr-defined]
    error.containment_capability = dict(containment_capability)  # type: ignore[attr-defined]
    error.executable_binding_sha256 = executable_binding_sha256  # type: ignore[attr-defined]
    return error


def _cancel_windows_synchronous_reader(reader: threading.Thread) -> bool:
    """Cancel one blocked Windows pipe read through its exact native thread.

    Microsoft documents ``CancelSynchronousIo`` for this case.  The helper is
    Windows-only and binds the public Kernel32 ABI explicitly; POSIX readers
    use ``select`` readiness instead.
    """

    if os.name != "nt" or reader.native_id is None:
        return False
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenThread.restype = wintypes.HANDLE
    kernel32.CancelSynchronousIo.argtypes = [wintypes.HANDLE]
    kernel32.CancelSynchronousIo.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    thread_terminate = 0x0001
    handle = kernel32.OpenThread(thread_terminate, False, int(reader.native_id))
    if not handle:
        return False
    try:
        ctypes.set_last_error(0)
        if kernel32.CancelSynchronousIo(handle):
            return True
        # ERROR_NOT_FOUND means no synchronous request was pending; the stop
        # event and subsequent join still decide whether cleanup succeeded.
        return int(ctypes.get_last_error()) == 1168
    finally:
        kernel32.CloseHandle(handle)


class _BoundedPipeCapture:
    """Continuously drain one child stream into a fixed-capacity byte buffer.

    Before overflow, the exact stream is retained.  After overflow, the same
    byte budget is divided deterministically between the beginning and end of
    the stream.  The reader never stops draining, so discarded bytes cannot
    exert pipe backpressure on the child.  Storage remains proportional to
    ``limit`` and independent of the total stream size; the one-time overflow
    transition may temporarily hold additional retained slices.
    """

    def __init__(self, *, limit: int, label: str) -> None:
        self._limit = limit
        self._label = label
        self._head_limit = limit // 2
        self._tail_limit = limit - self._head_limit
        self._exact = bytearray()
        self._head = bytearray()
        self._tail = bytearray()
        self._observed_bytes = 0
        self._sha256 = hashlib.sha256()
        self._overflowed = False
        self._reader_error: BaseException | None = None
        self._finished = False
        self._reader_stop = threading.Event()
        self._read_descriptor, write_descriptor = os.pipe()
        try:
            self._writer = os.fdopen(write_descriptor, "wb", buffering=0)
        except BaseException:
            os.close(self._read_descriptor)
            os.close(write_descriptor)
            raise
        self._reader = threading.Thread(
            target=self._drain,
            name=f"plamen-{label}-capture",
            daemon=True,
        )
        try:
            self._reader.start()
        except BaseException:
            self._writer.close()
            os.close(self._read_descriptor)
            raise

    @property
    def child_stream(self) -> Any:
        """Return the write endpoint to bind as a child's standard stream."""

        return self._writer

    @property
    def observed_bytes(self) -> int:
        return self._observed_bytes

    @property
    def retained_bytes(self) -> int:
        if self._overflowed:
            return len(self._head) + len(self._tail)
        return len(self._exact)

    @property
    def overflowed(self) -> bool:
        return self._overflowed

    @property
    def sha256(self) -> str:
        """SHA-256 of every raw byte drained, including discarded bytes."""

        return self._sha256.hexdigest()

    def close_parent_writer(self) -> None:
        if not self._writer.closed:
            self._writer.close()

    def _record(self, chunk: bytes) -> None:
        self._observed_bytes += len(chunk)
        self._sha256.update(chunk)
        if not self._overflowed and self._observed_bytes <= self._limit:
            self._exact.extend(chunk)
            return
        if not self._overflowed:
            exact = self._exact
            # Build the final tail without materializing byte slices, then
            # repurpose the exact buffer as the head.  The overflow transition
            # therefore does not temporarily duplicate both retained halves.
            tail = bytearray()
            if self._tail_limit:
                if len(chunk) >= self._tail_limit:
                    tail.extend(memoryview(chunk)[-self._tail_limit :])
                else:
                    old_needed = self._tail_limit - len(chunk)
                    tail.extend(memoryview(exact)[-old_needed:])
                    tail.extend(chunk)
            if len(exact) > self._head_limit:
                del exact[self._head_limit :]
            elif len(exact) < self._head_limit:
                missing = self._head_limit - len(exact)
                exact.extend(memoryview(chunk)[:missing])
            self._head = exact
            self._tail = tail
            self._exact = bytearray()
            self._overflowed = True
            return

        if self._tail_limit:
            if len(chunk) >= self._tail_limit:
                self._tail.clear()
                self._tail.extend(memoryview(chunk)[-self._tail_limit :])
            else:
                excess = len(self._tail) + len(chunk) - self._tail_limit
                if excess > 0:
                    del self._tail[:excess]
                self._tail.extend(chunk)

    def _drain(self) -> None:
        readiness = None
        try:
            if os.name != "nt":
                import selectors

                readiness = selectors.DefaultSelector()
                readiness.register(
                    self._read_descriptor,
                    selectors.EVENT_READ,
                )
            while not self._reader_stop.is_set():
                if readiness is not None:
                    # DefaultSelector uses kqueue/epoll/poll where available,
                    # avoiding select(2)'s FD_SETSIZE ceiling.
                    if not readiness.select(timeout=0.1):
                        continue
                try:
                    chunk = os.read(
                        self._read_descriptor,
                        _CAPTURE_READ_CHUNK_BYTES,
                    )
                except OSError:
                    if self._reader_stop.is_set():
                        break
                    raise
                if not chunk:
                    break
                self._record(chunk)
        except BaseException as exc:
            self._reader_error = exc
        finally:
            if readiness is not None:
                try:
                    readiness.close()
                except OSError:
                    pass
            try:
                os.close(self._read_descriptor)
            except OSError:
                pass

    def finish(self) -> None:
        """Close provider ownership and prove the stream reached EOF."""

        if self._finished:
            return
        self.close_parent_writer()
        self._reader.join(timeout=_CAPTURE_EOF_TIMEOUT_SECONDS)
        if self._reader.is_alive():
            self._reader_stop.set()
            if os.name == "nt":
                _cancel_windows_synchronous_reader(self._reader)
            self._reader.join(timeout=1.0)
            if self._reader.is_alive():
                raise OwnedProcessRunnerError(
                    f"bounded {self._label} capture reader could not be stopped"
                )
            self._finished = True
            raise OwnedProcessRunnerError(
                f"bounded {self._label} capture did not reach EOF after "
                "process-scope termination"
            )
        self._finished = True
        if self._reader_error is not None:
            raise OwnedProcessRunnerError(
                f"bounded {self._label} capture failed: "
                f"{type(self._reader_error).__name__}: {self._reader_error}"
            ) from self._reader_error

    def text(self, *, encoding: str, errors: str) -> str:
        self.finish()
        if not self._overflowed:
            return self._exact.decode(encoding, errors=errors)
        omitted = self._observed_bytes - self.retained_bytes
        marker = (
            f"\n[plamen: output truncated; omitted {omitted} bytes; "
            f"retained first {len(self._head)} and final "
            f"{len(self._tail)} bytes]\n"
        )
        return "".join(
            (
                self._head.decode(encoding, errors=errors),
                marker,
                self._tail.decode(encoding, errors=errors),
            )
        )


def _bounded_text(
    handle: Any,
    *,
    limit: int,
    encoding: str,
    errors: str,
) -> str:
    handle.flush()
    size = handle.tell()
    start = max(0, size - limit)
    handle.seek(start)
    raw = handle.read(limit)
    prefix = (
        f"[plamen: output truncated; retained final {limit} bytes]\n"
        if start else ""
    )
    return prefix + bytes(raw).decode(encoding, errors=errors)


def _finish_captures(*captures: _BoundedPipeCapture) -> None:
    """Finish every capture even when one stream reports an error."""

    first_error: BaseException | None = None
    for capture in captures:
        try:
            capture.finish()
        except BaseException as exc:
            if first_error is None:
                first_error = exc
    if first_error is not None:
        raise first_error


def _diagnostic_capture_text(
    capture: _BoundedPipeCapture,
    *,
    encoding: str,
    errors: str,
) -> str:
    """Render secondary stop evidence without masking timeout/cancellation."""

    try:
        return capture.text(encoding=encoding, errors=errors)
    except (LookupError, UnicodeError):
        # Head/tail retention can split an otherwise valid multibyte sequence
        # at either truncation boundary.  Diagnostics are secondary to the
        # stop classification, so render them safely and state the fallback.
        rendered = capture.text(encoding="utf-8", errors="replace")
        return (
            "[plamen: requested diagnostic decoding failed; rendered as "
            "UTF-8 with replacement]\n" + rendered
        )


def _cancellation_requested(token: Any) -> bool:
    if token is None:
        return False
    is_set = getattr(token, "is_set", None)
    if callable(is_set):
        return bool(is_set())
    cancelled = getattr(token, "cancelled", None)
    if callable(cancelled):
        return bool(cancelled())
    if callable(token):
        return bool(token())
    return bool(token)


def _wait_for_owned_process(
    process: subprocess.Popen[bytes],
    *,
    argv: tuple[str, ...],
    timeout: float,
    deadline: float,
    cancel_token: Any,
) -> int:
    """Wait within one deadline while making cancellation observable."""

    if cancel_token is None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(list(argv), timeout)
        return int(process.wait(timeout=remaining))

    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(list(argv), timeout)
        if _cancellation_requested(cancel_token):
            raise _OwnedProcessCancelled(
                "owned process execution was cancelled"
            )
        returncode = process.poll()
        if returncode is not None:
            return int(returncode)
        try:
            return int(process.wait(timeout=min(remaining, 0.05)))
        except subprocess.TimeoutExpired:
            continue


def _emergency_close_scope(
    tree: OwnedProcessScope,
    process: subprocess.Popen[bytes] | None,
) -> None:
    """Consume containment authority after the proof-grade close path fails.

    A successful emergency close is deliberately not completion evidence:
    callers still raise.  On Windows the Job's kill-on-close policy is the
    final descendant-stop mechanism.  Other backends retain their recovery
    state or perform only their documented diagnostic best effort.
    """

    try:
        tree.emergency_close()
    except OwnedProcessScopeError as exc:
        if process is not None and process.poll() is None:
            try:
                process.kill()
            except Exception:
                pass
        raise OwnedProcessRunnerError(
            "owned process controller could not be emergency-closed"
        ) from exc
    if process is not None and process.poll() is None:
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired as exc:
            raise OwnedProcessRunnerError(
                "process leader did not exit after emergency controller close"
            ) from exc


def run_owned_process(
    command: Sequence[str],
    *,
    cwd: str | Path | None = None,
    env: Mapping[str, str] | None = None,
    timeout: float,
    encoding: str = "utf-8",
    errors: str = "replace",
    output_limit_bytes: int = DEFAULT_OUTPUT_LIMIT_BYTES,
    writable_roots: Sequence[str | Path] = (),
    lease_cancel_token: Any = None,
    executable_guard: Mapping[str, Any] | None = None,
) -> OwnedCompletedProcess:
    """Run one command and terminate its owned process scope before return.

    ``subprocess.TimeoutExpired`` is intentionally retained as the timeout API
    so existing mechanical classifiers preserve their public status semantics.
    Its ``output`` and ``stderr`` fields contain bounded decoded head/tail
    observations when their streams overflow.
    """

    argv = resolve_owned_process_command(command, env=env)
    try:
        timeout_n = float(timeout)
    except (TypeError, ValueError) as exc:
        raise ValueError("owned process timeout must be positive") from exc
    if timeout_n <= 0:
        raise ValueError("owned process timeout must be positive")
    if (
        isinstance(output_limit_bytes, bool)
        or not isinstance(output_limit_bytes, int)
        or output_limit_bytes <= 0
    ):
        raise ValueError("owned process output limit must be positive")
    if _cancellation_requested(lease_cancel_token):
        raise OwnedProcessRunnerError(
            "owned process execution was cancelled before launch"
        )

    capability = process_tree_termination_capability()
    write_authority = _transaction_write_authority(capability)
    if (
        capability.get("pre_execution_assignment") is not True
        or capability.get("exhaustive_descendant_termination_authority") is not True
        or write_authority is None
    ):
        raise OwnedProcessRunnerError(
            "process-tree containment is unsupported or lacks "
            "pre-execution assignment"
        )

    from locked_executable_guard import (
        acquire_locked_executable_launch,
        bind_locked_executable,
        validate_locked_executable_binding,
    )

    guard_binding = (
        bind_locked_executable(argv[0])
        if executable_guard is None
        else validate_locked_executable_binding(argv[0], dict(executable_guard))
    )
    executable_binding_sha256 = _authority_mapping_sha256(guard_binding)

    started = time.monotonic()
    deadline = started + timeout_n
    tree: OwnedProcessScope | None = None
    process: subprocess.Popen[bytes] | None = None
    stdout_capture = _BoundedPipeCapture(
        limit=output_limit_bytes,
        label="stdout",
    )
    try:
        stderr_capture = _BoundedPipeCapture(
            limit=output_limit_bytes,
            label="stderr",
        )
    except BaseException:
        stdout_capture.close_parent_writer()
        stdout_capture.finish()
        raise
    try:
        try:
            tree = OwnedProcessScope(
                writable_roots=tuple(Path(item) for item in writable_roots),
                lease_acquisition_deadline_monotonic=deadline,
                lease_cancel_token=lease_cancel_token,
            )
            # Lease recovery is part of the same budget.  Do not even create a
            # suspended/gated child after that budget has already expired.
            if time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired(list(argv), timeout_n)
            launch_name, launch_descriptor = acquire_locked_executable_launch(
                argv[0],
                guard_binding,
            )
            try:
                physical_argv = tree.wrap_argv((launch_name, *argv[1:]))
                popen_options = tree.popen_kwargs()
                if launch_descriptor is not None:
                    popen_options["pass_fds"] = tuple(
                        dict.fromkeys(
                            (*popen_options.get("pass_fds", ()), launch_descriptor)
                        )
                    )
                process = tree.create_process(
                    physical_argv,
                    popen_factory=None,
                    cwd=(str(cwd) if cwd is not None else None),
                    env=(dict(env) if env is not None else None),
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_capture.child_stream,
                    stderr=stderr_capture.child_stream,
                    shell=False,
                    close_fds=True,
                    **popen_options,
                )
            finally:
                # Popen owns duplicated standard-stream handles after a
                # successful launch.  Closing the parent's copies here makes
                # EOF observable after the owned process population reaches
                # zero, including every error-before-attachment path.
                stdout_capture.close_parent_writer()
                stderr_capture.close_parent_writer()
                if launch_descriptor is not None:
                    os.close(launch_descriptor)
            validate_locked_executable_binding(argv[0], guard_binding)
            # Windows returns a Job-owned suspended child and Linux returns a
            # cgroup-gated helper.  Re-check while user code is still unable to
            # run.  If creation itself consumed the deadline, kill and reap
            # that exact process without ever releasing its execution gate.
            if time.monotonic() >= deadline:
                try:
                    tree.terminate_created_process()
                except OwnedProcessScopeError as exc:
                    _emergency_close_scope(tree, process)
                    raise OwnedProcessRunnerError(
                        "expired pre-attachment process could not be reaped; "
                        "its controller was emergency-closed"
                    ) from exc
                raise subprocess.TimeoutExpired(list(argv), timeout_n)
            tree.attach(process)
            observed_write_authority = (
                tree.write_confinement_proven
                if write_authority == "EXHAUSTIVE"
                else getattr(
                    tree,
                    "serialized_stage_write_confinement_proven",
                    False,
                )
            )
            if observed_write_authority is not True:
                raise OwnedProcessRunnerError(
                    "owned process write-confinement proof failed"
                )
            # ``timeout`` is one end-to-end execution budget.  Acquiring the
            # serialized Windows low-integrity lease may consume part of it;
            # granting the child another full budget made the isolated
            # coordinator's ``timeout + grace`` deadline race the executor.
            # Preserve one monotonic deadline across lease setup and runtime.
            try:
                returncode = _wait_for_owned_process(
                    process,
                    argv=argv,
                    timeout=timeout_n,
                    deadline=deadline,
                    cancel_token=lease_cancel_token,
                )
            except (
                subprocess.TimeoutExpired,
                _OwnedProcessCancelled,
            ) as stop_error:
                try:
                    tree.terminate()
                except OwnedProcessScopeError as exc:
                    _emergency_close_scope(tree, process)
                    raise OwnedProcessRunnerError(
                        "stopped process scope could not be terminated; "
                        "its controller was emergency-closed"
                    ) from exc
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired as exc:
                    raise OwnedProcessRunnerError(
                        "process leader did not exit after tree termination"
                    ) from exc
                try:
                    tree.close()
                except OwnedProcessScopeError as exc:
                    raise OwnedProcessRunnerError(
                        "stopped process scope cleanup failed"
                    ) from exc
                stdout = _diagnostic_capture_text(
                    stdout_capture,
                    encoding=encoding,
                    errors=errors,
                )
                stderr = _diagnostic_capture_text(
                    stderr_capture,
                    encoding=encoding,
                    errors=errors,
                )
                if isinstance(stop_error, _OwnedProcessCancelled):
                    cancelled = OwnedProcessRunnerError(
                        "owned process execution was cancelled"
                    )
                    # Match TimeoutExpired's useful diagnostic surface without
                    # changing the public timeout classification.
                    cancelled.stdout = stdout  # type: ignore[attr-defined]
                    cancelled.stderr = stderr  # type: ignore[attr-defined]
                    raise cancelled from stop_error
                timeout_error = subprocess.TimeoutExpired(
                    list(argv),
                    timeout_n,
                    output=stdout,
                    stderr=stderr,
                )
                raise _attach_timeout_observations(
                    timeout_error,
                    argv=argv,
                    duration_s=time.monotonic() - started,
                    stdout_capture=stdout_capture,
                    stderr_capture=stderr_capture,
                    process_tree_terminated=tree.terminated,
                    containment_capability=capability,
                    executable_binding_sha256=executable_binding_sha256,
                ) from stop_error

            # The direct child may return while background descendants remain.
            # Close the process scope before finalizing output or reporting
            # completion so inherited handles cannot survive the result.  The
            # capture threads have drained continuously throughout execution.
            try:
                tree.terminate()
            except OwnedProcessScopeError as exc:
                _emergency_close_scope(tree, process)
                raise OwnedProcessRunnerError(
                    "completed command's descendant scope could not be "
                    "terminated; its controller was emergency-closed"
                ) from exc
            try:
                tree.close()
            except OwnedProcessScopeError as exc:
                raise OwnedProcessRunnerError(
                    "completed command's process scope cleanup failed"
                ) from exc
            stdout = stdout_capture.text(
                encoding=encoding,
                errors=errors,
            )
            stderr = stderr_capture.text(
                encoding=encoding,
                errors=errors,
            )
            return OwnedCompletedProcess(
                args=argv,
                returncode=int(returncode),
                stdout=stdout,
                stderr=stderr,
                duration_s=time.monotonic() - started,
                process_tree_terminated=tree.terminated,
                containment_capability=dict(capability),
                stdout_observed_bytes=stdout_capture.observed_bytes,
                stderr_observed_bytes=stderr_capture.observed_bytes,
                stdout_retained_bytes=stdout_capture.retained_bytes,
                stderr_retained_bytes=stderr_capture.retained_bytes,
                stdout_sha256=stdout_capture.sha256,
                stderr_sha256=stderr_capture.sha256,
                stdout_truncated=stdout_capture.overflowed,
                stderr_truncated=stderr_capture.overflowed,
                executable_binding_sha256=executable_binding_sha256,
            )
        except (subprocess.TimeoutExpired, OwnedProcessRunnerError):
            raise
        except Exception as exc:
            if tree is not None:
                if tree.attached:
                    try:
                        tree.terminate()
                    except Exception:
                        _emergency_close_scope(tree, process)
                else:
                    # Popen may fail before any process exists, or pre-execution
                    # attachment may reject a still-suspended leader.  In both
                    # cases the scope itself proves that it never accepted a
                    # process population.  Do not call terminate(), whose
                    # attached-only contract would force an unnecessary
                    # emergency quarantine of the global Windows lease.
                    if process is not None and process.poll() is None:
                        try:
                            process.kill()
                        except Exception:
                            pass
                        try:
                            process.wait(timeout=10)
                        except Exception:
                            pass
                    try:
                        tree.close()
                    except OwnedProcessScopeError:
                        _emergency_close_scope(tree, process)
            elif process is not None:
                try:
                    process.kill()
                except Exception:
                    pass
            if process is not None:
                try:
                    process.wait(timeout=10)
                except Exception:
                    pass
            raise OwnedProcessRunnerError(
                f"owned process execution failed: {type(exc).__name__}: {exc}"
            ) from exc
        finally:
            if tree is not None:
                try:
                    tree.close()
                except OwnedProcessScopeError as exc:
                    # A failed proof-grade close invalidates completion even
                    # when kill-on-close can still stop descendants.
                    _emergency_close_scope(tree, process)
                    raise OwnedProcessRunnerError(
                        "owned process controller could not be cleanly closed; "
                        "it was emergency-closed"
                    ) from exc
    finally:
        stdout_capture.close_parent_writer()
        stderr_capture.close_parent_writer()
        _finish_captures(stdout_capture, stderr_capture)


def run_owned_process_isolated(
    command: Sequence[str],
    *,
    cwd: str | Path | None = None,
    env: Mapping[str, str] | None = None,
    timeout: float,
    encoding: str = "utf-8",
    errors: str = "replace",
    output_limit_bytes: int = DEFAULT_OUTPUT_LIMIT_BYTES,
    writable_roots: Sequence[str | Path] = (),
    lease_cancel_token: Any = None,
    coordinator_timeout: float | None = None,
) -> OwnedCompletedProcess:
    """Run the existing primitive inside one disposable executor process.

    This lazy adapter keeps the legacy direct runner unchanged.  The isolated
    host imports this module only inside its short-lived child, so importing
    the runner does not create a cycle or start an executor.
    """

    argv = tuple(str(value) for value in command)
    if not argv or any(not value for value in argv):
        raise ValueError("owned process command must contain non-empty argv")

    from isolated_execution_host import (
        IsolatedExecutionHostError,
        run_isolated_owned_process,
    )

    try:
        return run_isolated_owned_process(
            argv,
            cwd=cwd,
            env=env,
            timeout=timeout,
            encoding=encoding,
            errors=errors,
            output_limit_bytes=output_limit_bytes,
            writable_roots=writable_roots,
            coordinator_timeout=coordinator_timeout,
            cancel_token=lease_cancel_token,
        )
    except IsolatedExecutionHostError as exc:
        payload = exc.receipt.get("payload")
        reason = (
            payload.get("reason_code")
            if isinstance(payload, Mapping)
            else None
        )
        if not isinstance(reason, str) or not reason:
            reason = "ISOLATED_EXECUTION_FAILED"
        raise OwnedProcessRunnerError(
            f"isolated owned-process debt: {reason}"
        ) from exc


__all__ = [
    "DEFAULT_OUTPUT_LIMIT_BYTES",
    "OwnedCompletedProcess",
    "OwnedProcessRunnerError",
    "resolve_owned_process_command",
    "run_owned_process",
    "run_owned_process_isolated",
]
