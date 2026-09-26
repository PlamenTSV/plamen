"""Deterministic provider and crash/resume harness for source-only E2E tests.

The harness deliberately does not know about ``plamen_driver``.  A production
workflow test supplies only two callbacks: one that drives a run and one that
captures its durable post-state.  This keeps provider behavior, crash timing,
and convergence assertions deterministic while letting tests exercise the
real public workflow boundary.

The fake process adapter models the property required from a retry-safe
provider boundary: an idempotency key is forever bound to one exact request.
Repeated delivery of that request replays the first immutable result without
recording another logical execution; key reuse with different bytes is a hard
error.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping


class OutcomeKind(str, Enum):
    """Closed outcome taxonomy understood by the deterministic adapter."""

    COMPLETED = "COMPLETED"
    TIMED_OUT = "TIMED_OUT"
    TRANSIENT_ERROR = "TRANSIENT_ERROR"
    TERMINAL_ERROR = "TERMINAL_ERROR"


@dataclass(frozen=True)
class ProcessRequest:
    """Exact logical provider request used for idempotent replay."""

    idempotency_key: str
    argv: tuple[str, ...]
    cwd: str
    stdin: bytes = b""
    environment: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not self.idempotency_key.strip():
            raise ValueError("idempotency_key must be non-empty")
        if not self.argv or any(not item for item in self.argv):
            raise ValueError("argv must contain non-empty strings")
        if tuple(sorted(self.environment)) != self.environment:
            raise ValueError("environment must be sorted for exact replay")
        if len({key for key, _value in self.environment}) != len(
            self.environment
        ):
            raise ValueError("environment contains duplicate keys")

    @property
    def digest(self) -> str:
        payload = {
            "argv": list(self.argv),
            "cwd": self.cwd,
            "environment": [list(item) for item in self.environment],
            "stdin_bytes": len(self.stdin),
            "stdin_sha256": hashlib.sha256(self.stdin).hexdigest(),
        }
        raw = json.dumps(
            payload, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class ProcessResult:
    """Immutable result returned by a deterministic provider route."""

    kind: OutcomeKind
    returncode: int | None
    stdout: bytes = b""
    stderr: bytes = b""

    def __post_init__(self) -> None:
        if type(self.kind) is not OutcomeKind:
            raise TypeError("kind must be an exact OutcomeKind")
        if self.kind is OutcomeKind.COMPLETED and self.returncode is None:
            raise ValueError("completed result requires a returncode")
        if (
            self.kind is not OutcomeKind.COMPLETED
            and self.returncode is not None
        ):
            raise ValueError("non-completed result cannot claim a returncode")


@dataclass(frozen=True)
class DeliveryRecord:
    """One delivery to the adapter, including cache/replay disposition."""

    idempotency_key: str
    request_digest: str
    replayed: bool


class IdempotencyConflict(RuntimeError):
    """Raised when a logical key is reused for a different exact request."""


Route = ProcessResult | Callable[[ProcessRequest], ProcessResult]


class DeterministicProcessAdapter:
    """In-memory exact-request provider with observable delivery semantics."""

    def __init__(self, routes: Mapping[tuple[str, ...], Route]) -> None:
        self._routes = dict(routes)
        self._cache: dict[str, tuple[str, ProcessResult]] = {}
        self.deliveries: list[DeliveryRecord] = []
        self.executions: list[DeliveryRecord] = []

    def run(self, request: ProcessRequest) -> ProcessResult:
        digest = request.digest
        cached = self._cache.get(request.idempotency_key)
        if cached is not None:
            bound_digest, result = cached
            if bound_digest != digest:
                raise IdempotencyConflict(
                    "idempotency key is already bound to a different request: "
                    f"{request.idempotency_key}"
                )
            record = DeliveryRecord(request.idempotency_key, digest, True)
            self.deliveries.append(record)
            return result

        try:
            route = self._routes[request.argv]
        except KeyError as exc:
            raise KeyError(
                f"no deterministic route for argv={request.argv!r}"
            ) from exc
        result = route(request) if callable(route) else route
        if type(result) is not ProcessResult:
            raise TypeError("deterministic route must return exact ProcessResult")
        self._cache[request.idempotency_key] = (digest, result)
        record = DeliveryRecord(request.idempotency_key, digest, False)
        self.deliveries.append(record)
        self.executions.append(record)
        return result


class InjectedCrash(BaseException):
    """Process-death analogue that broad ``except Exception`` cannot swallow."""

    def __init__(self, point: str) -> None:
        super().__init__(f"injected crash at {point}")
        self.point = point


class CrashOnce:
    """Crash exactly once when the named durable transition is observed."""

    def __init__(self, point: str) -> None:
        if not point:
            raise ValueError("crash point must be non-empty")
        self.point = point
        self.observed: list[str] = []
        self.fired = False

    def __call__(self, point: str) -> None:
        self.observed.append(point)
        if not self.fired and point == self.point:
            self.fired = True
            raise InjectedCrash(point)


@dataclass(frozen=True)
class CrashResumeObservation:
    """Evidence returned for one generated crash/resume matrix cell."""

    crash_point: str
    delivery_count: int
    execution_count: int
    replay_count: int
    final_snapshot: Any


Drive = Callable[[Path, DeterministicProcessAdapter, Callable[[str], None]], None]
Snapshot = Callable[[Path], Any]


def run_crash_resume_case(
    *,
    root: Path,
    adapter: DeterministicProcessAdapter,
    crash_point: str,
    drive: Drive,
    snapshot: Snapshot,
    expected_snapshot: Any,
) -> CrashResumeObservation:
    """Crash at one transition, resume, and require baseline convergence.

    The same adapter instance spans both invocations to model an external
    provider's durable idempotency boundary.  The workflow itself must derive
    all resume behavior from files under ``root``.
    """

    root.mkdir(parents=True, exist_ok=False)
    injector = CrashOnce(crash_point)
    try:
        drive(root, adapter, injector)
    except InjectedCrash as exc:
        if exc.point != crash_point:
            raise AssertionError(
                f"wrong crash point: expected {crash_point}, got {exc.point}"
            ) from exc
    else:
        raise AssertionError(f"crash point was not reached: {crash_point}")
    if not injector.fired:
        raise AssertionError(f"crash point was not fired: {crash_point}")

    drive(root, adapter, lambda _point: None)
    observed = snapshot(root)
    if observed != expected_snapshot:
        raise AssertionError(
            f"crash/resume state diverged at {crash_point}: "
            f"expected {expected_snapshot!r}, got {observed!r}"
        )
    replay_count = sum(record.replayed for record in adapter.deliveries)
    return CrashResumeObservation(
        crash_point=crash_point,
        delivery_count=len(adapter.deliveries),
        execution_count=len(adapter.executions),
        replay_count=replay_count,
        final_snapshot=observed,
    )


def snapshot_files(
    root: Path, relative_paths: Iterable[str]
) -> tuple[tuple[str, bytes], ...]:
    """Capture an exact, ordered durable post-state for convergence checks."""

    paths = tuple(sorted(relative_paths))
    if len(paths) != len(set(paths)):
        raise ValueError("snapshot paths must be unique")
    return tuple((relative, (root / relative).read_bytes()) for relative in paths)


def snapshot_tree(root: Path) -> tuple[tuple[str, bytes], ...]:
    """Capture every durable file, including otherwise unnoticed leftovers."""

    files = sorted(
        candidate for candidate in root.rglob("*") if candidate.is_file()
    )
    return tuple(
        (path.relative_to(root).as_posix(), path.read_bytes())
        for path in files
    )
