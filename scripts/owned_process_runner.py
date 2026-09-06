"""Central, bounded subprocess execution with owned-tree termination.

This is the non-interactive execution primitive for mechanically invoked
toolchains.  It deliberately avoids ``PIPE`` capture: descendants which
inherit stdout/stderr therefore cannot keep a reader blocked after the direct
child exits or times out.  Output is spooled to regular temporary files, and
the provider-owned process scope is terminated before those files are read.

Containment is capability-specific. Windows uses suspended creation plus a
non-breakaway kill-on-close Job Object and a low-integrity write boundary.
Linux requires an explicitly delegated cgroup-v2 root plus Landlock. Other
platforms fail closed because a process group alone is not exhaustive.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
from typing import Any, Mapping, Sequence

from owned_process_scope import (
    OwnedProcessScope,
    OwnedProcessScopeError,
    process_tree_termination_capability,
)


DEFAULT_OUTPUT_LIMIT_BYTES = 8 * 1024 * 1024


class OwnedProcessRunnerError(RuntimeError):
    """A command could not be launched or contained by the owned runner."""


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
    Its ``output`` and ``stderr`` fields contain bounded decoded tails.
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

    started = time.monotonic()
    deadline = started + timeout_n
    tree: OwnedProcessScope | None = None
    process: subprocess.Popen[bytes] | None = None
    with tempfile.TemporaryFile(mode="w+b") as stdout_file, (
        tempfile.TemporaryFile(mode="w+b")
    ) as stderr_file:
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
            physical_argv = tree.wrap_argv((launch_name, *argv[1:]))
            popen_options = tree.popen_kwargs()
            if launch_descriptor is not None:
                popen_options["pass_fds"] = tuple(
                    dict.fromkeys(
                        (*popen_options.get("pass_fds", ()), launch_descriptor)
                    )
                )
            try:
                process = tree.create_process(
                    physical_argv,
                    popen_factory=None,
                    cwd=(str(cwd) if cwd is not None else None),
                    env=(dict(env) if env is not None else None),
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    shell=False,
                    close_fds=(os.name != "nt"),
                    **popen_options,
                )
            finally:
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
            remaining = deadline - time.monotonic()
            try:
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(list(argv), timeout_n)
                returncode = process.wait(timeout=remaining)
            except subprocess.TimeoutExpired as timeout_error:
                try:
                    tree.terminate()
                except OwnedProcessScopeError as exc:
                    _emergency_close_scope(tree, process)
                    raise OwnedProcessRunnerError(
                        "timed-out process scope could not be terminated; "
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
                        "timed-out process scope cleanup failed"
                    ) from exc
                stdout = _bounded_text(
                    stdout_file,
                    limit=output_limit_bytes,
                    encoding=encoding,
                    errors=errors,
                )
                stderr = _bounded_text(
                    stderr_file,
                    limit=output_limit_bytes,
                    encoding=encoding,
                    errors=errors,
                )
                raise subprocess.TimeoutExpired(
                    list(argv),
                    timeout_n,
                    output=stdout,
                    stderr=stderr,
                ) from timeout_error

            # The direct child may return while background descendants remain.
            # Close the process scope before reading output or reporting
            # completion so inherited handles cannot survive the result.
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
            stdout = _bounded_text(
                stdout_file,
                limit=output_limit_bytes,
                encoding=encoding,
                errors=errors,
            )
            stderr = _bounded_text(
                stderr_file,
                limit=output_limit_bytes,
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
