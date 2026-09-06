"""V7 live-entry RED denominator for recon fanout, dependency, and merge.

Every semantic route below calls the current production symbol.  Only the
external model/PTY process is replaced.  ArtifactLedger preparation, commit,
validation, deterministic dependency enumeration, merge rendering, and
consumer binding are never mocked.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
import threading
from types import SimpleNamespace
from typing import Any, Mapping
import unicodedata

import pytest


SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(ROOT))

import artifact_ledger as AL  # noqa: E402
import plamen_driver as D  # noqa: E402
import plamen_mechanical as M  # noqa: E402
from phase_io_contracts import (  # noqa: E402
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    canonical_work_unit_key,
    resolve_phase_io_contract,
)


RUN_ID = "cut4-recon-v7"
_REASON_CODE_RE = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*$")
_CANONICAL_REASON_CODES = frozenset({"CANONICAL_INPUT_AUTHORITY_CHANGED"})
_DISPOSITION_LINKAGE = {
    "QUARANTINED": frozenset({("QUARANTINED", "OUTPUT_QUARANTINED")}),
    "DEBT": frozenset({("DEBT", "FAILED")}),
    "REJECTED": frozenset({
        ("REJECTED", "INPUT_REJECTED"),
        ("REJECTED", "PUBLICATION_REJECTED"),
    }),
    "FAILED": frozenset({("DEBT", "FAILED")}),
}
SC_CANONICAL = (
    "recon_summary.md",
    "design_context.md",
    "attack_surface.md",
    "state_variables.md",
    "function_list.md",
    "contract_inventory.md",
    "template_recommendations.md",
    "detected_patterns.md",
    "setter_list.md",
    "emit_list.md",
    "build_status.md",
)
EXACT_RECON_CONSUMER_EIGHT = (
    "template_recommendations.md",
    "detected_patterns.md",
    "design_context.md",
    "attack_surface.md",
    "contract_inventory.md",
    "function_list.md",
    "state_variables.md",
    "recon_summary.md",
)
L1_CANONICAL = (
    "recon_summary.md",
    "threat_model.md",
    "subsystem_map.md",
    "attack_surface.md",
    "trust_boundaries.md",
    "template_recommendations.md",
    "scope_leftover.md",
)
BREADTH_RECON_SIX = (
    "recon_summary.md",
    "attack_surface.md",
    "contract_inventory.md",
    "function_list.md",
    "state_variables.md",
    "template_recommendations.md",
)


def _stable_digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _source_capture_digest(project: Path) -> str:
    source = project / "src"
    records = {
        path.relative_to(source).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(source.rglob("*"))
        if path.is_file()
    }
    return _stable_digest(records)


def _expected_attempt_binding(
    old_key: str,
    old: Mapping[str, Any],
    *,
    input_set_digest: str,
    config_digest: str,
    source_capture_digest: str,
) -> dict[str, Any]:
    old_commit = old.get("commit_authority")
    old_attempt = (
        old_commit.get("attempt_ordinal")
        if isinstance(old_commit, Mapping)
        else None
    )
    assert isinstance(old_attempt, int) and not isinstance(old_attempt, bool)
    attempt_ordinal = old_attempt + 1
    attempt_identity = f"{old_key}/attempt-{attempt_ordinal}"
    binding: dict[str, Any] = {
        "producer_attempt_identity": attempt_identity,
        "attempt_ordinal": attempt_ordinal,
        "input_set_digest": input_set_digest,
        "config_digest": config_digest,
        "source_capture_digest": source_capture_digest,
    }
    binding["attempted_authority_digest"] = _stable_digest(binding)
    return binding


def _observed_canonical_attempt_binding(
    project: Path,
    scratchpad: Path,
    config: Mapping[str, Any],
    old_key: str,
    old: Mapping[str, Any],
    input_names: tuple[str, ...],
) -> dict[str, Any]:
    source_digest = _source_capture_digest(project)
    config_digest = _stable_digest(dict(config))
    worker_inputs = {
        name: hashlib.sha256((scratchpad / name).read_bytes()).hexdigest()
        for name in input_names
        if (scratchpad / name).is_file()
    }
    input_digest = _stable_digest(
        {
            "worker_inputs": worker_inputs,
            "source_capture_digest": source_digest,
            "config_digest": config_digest,
        }
    )
    return _expected_attempt_binding(
        old_key,
        old,
        input_set_digest=input_digest,
        config_digest=config_digest,
        source_capture_digest=source_digest,
    )


def _workspace(
    tmp_path: Path,
    *,
    pipeline: str = "sc",
    mode: str = "thorough",
    route: str = "codex",
    dependency: bool = True,
) -> tuple[Path, Path, dict[str, Any]]:
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    source = project / "src"
    source.mkdir(parents=True)
    scratchpad.mkdir()
    if pipeline == "l1":
        (source / "node.rs").write_text(
            "pub fn process_block(height: u64) -> bool { height > 0 }\n",
            encoding="utf-8",
        )
        language = "rust"
    else:
        import_line = 'import "@vendor/protocol/Oracle.sol";\n' if dependency else ""
        (source / "Protocol.sol").write_text(
            "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\n"
            + import_line
            + "contract Protocol { function ready() external pure returns (bool) { return true; } }\n",
            encoding="utf-8",
        )
        language = "evm"
    config = {
        "pipeline": pipeline,
        "mode": mode,
        "language": language,
        "cli_backend": "codex" if route == "codex" else "claude",
        "project_root": str(project),
        "scratchpad": str(scratchpad),
        "_run_id": RUN_ID,
        "run_id": RUN_ID,
    }
    return project, scratchpad, config


def _phase(config: Mapping[str, Any], name: str = "recon") -> Any:
    phases = D.L1_PHASES if config["pipeline"] == "l1" else D.SC_PHASES
    return next(row for row in phases if row.name == name)


def _shard(job: Mapping[str, str]) -> str:
    return (
        f"<!-- PLAMEN_ARTIFACT: {job['output']} -->\n"
        f"<!-- PLAMEN_OWNER: {job['agent_id']} -->\n"
        "<!-- PLAMEN_STATUS: IN_PROGRESS -->\n"
        "<!-- PLAMEN_PHASE: recon -->\n"
        "<!-- PLAMEN_VERSION: 1 -->\n"
        f"<!-- RECON_ROLE: {job['role']} -->\n"
        f"<!-- EXPECTED_OUTPUT: {job['output']} -->\n\n"
        f"# Recon worker {job['role']}\n\n"
        "## Evidence\n\n"
        "- `src/Protocol.sol:L1` is the concrete production source denominator.\n"
        "- Entry points, state, trust boundaries, build capability, dependency "
        "questions, and downstream implications were enumerated without a "
        "safety conclusion. This body is intentionally nonempty and exceeds "
        "the current worker content threshold.\n\n"
        "## Canonical Merge Hints\n\n"
        f"- Merge the bounded {job['role']} evidence without inventing facts.\n\n"
        "<!-- PLAMEN_STATUS: COMPLETE -->\n"
    )


def _write_worker_output(kwargs: Mapping[str, Any], config: Mapping[str, Any]) -> int:
    jobs = D._recon_worker_jobs(dict(config))
    job = kwargs.get("job")
    if not isinstance(job, Mapping):
        output = str((kwargs.get("expected_outputs") or [""])[0])
        job = next(
            (row for row in jobs if row["output"] == output),
            {
                "agent_id": "R-EXT",
                "role": "external_dependency_research",
                "output": output,
            },
        )
    root = Path(str(config["scratchpad"]))
    (root / str(job["output"])).write_text(_shard(job), encoding="utf-8")
    return 0


_REAL_RUN_SINGLE_RECON_WORKER_PTY = D._run_single_recon_worker_pty


class _PtyLifecycleInstallation:
    """Fresh synchronization and bounded diagnostics for one fake PTY install."""

    def __init__(self, *, acquire_timeout_s: float = 5.0) -> None:
        self.lifecycle_mutex = threading.Lock()
        self.diagnostic_lock = threading.Lock()
        self.acquire_timeout_s = acquire_timeout_s
        self.results: list[dict[str, Any]] = []
        self.events: list[tuple[str, str]] = []
        self.active_owners = 0
        self.max_active_owners = 0
        self.write_failures: set[str] = set()
        self.poll_failures: set[str] = set()

    def event(self, name: str, output: str) -> None:
        with self.diagnostic_lock:
            self.events.append((name, output))

    def owner_entered(self, output: str) -> None:
        with self.diagnostic_lock:
            self.active_owners += 1
            self.max_active_owners = max(self.max_active_owners, self.active_owners)
            self.events.append(("acquired", output))

    def owner_left(self, output: str) -> None:
        with self.diagnostic_lock:
            assert self.active_owners > 0
            self.active_owners -= 1
            self.lifecycle_mutex.release()
            self.events.append(("released", output))

    def observe(self, result: Mapping[str, Any], *, attempt: int) -> None:
        bounded = {
            "output": str(result.get("output") or ""),
            "attempt": attempt,
            "rc": result.get("rc"),
            "status": str(result.get("status") or ""),
            "reasons": tuple(copy.deepcopy(list(result.get("reasons") or []))),
        }
        with self.diagnostic_lock:
            self.results.append(bounded)


class _FakePtySession:
    """External PTY-only replacement; all surrounding transaction code is real."""

    jobs: list[dict[str, str]] = []
    scratchpad: Path
    installation: _PtyLifecycleInstallation

    def __init__(self, _cmd: Any, **kwargs: Any) -> None:
        self.prompt_path = Path(kwargs["prompt_path"])
        self.transcript_path = self.prompt_path.with_suffix(".transcript.absent")
        self._owns_lifecycle_mutex = False
        self.acquire_started = threading.Event()
        self._job = next(
            (
                job for job in self.jobs
                if Path(job["output"]).stem in self.prompt_path.name
            ),
            {
                "agent_id": "R-EXT",
                "role": "external_dependency_research",
                "output": "recon_external_dependency_research.md",
            },
        )

    def spawn(self) -> None:
        output = self._job["output"]
        self.installation.event("acquire_started", output)
        self.acquire_started.set()
        if not self.installation.lifecycle_mutex.acquire(
            timeout=self.installation.acquire_timeout_s
        ):
            self.installation.event("acquire_timeout", output)
            raise RuntimeError("fixture PTY lifecycle acquire timeout")
        self._owns_lifecycle_mutex = True
        self.installation.owner_entered(output)
        if output in self.installation.write_failures:
            self.installation.event("write_failed", output)
            raise RuntimeError("fixture PTY output write failure")
        (self.scratchpad / self._job["output"]).write_text(
            _shard(self._job), encoding="utf-8"
        )
        self.installation.event("wrote", output)

    def send_bootstrap(self) -> None:
        return None

    def wait_for_turn_complete(self, _timeout: float, **kwargs: Any) -> Any:
        output = self._job["output"]
        if output in self.installation.poll_failures:
            self.installation.event("poll_failed", output)
            raise RuntimeError("fixture PTY poll failure")
        on_poll = kwargs.get("on_poll")
        state = SimpleNamespace(rate_limited=False, overloaded=False)
        if on_poll is not None:
            on_poll(0.0, state)
        self.installation.event("polled", output)
        return state

    def terminate(self, **_kwargs: Any) -> None:
        if not self._owns_lifecycle_mutex:
            return None
        self._owns_lifecycle_mutex = False
        output = self._job["output"]
        self.installation.owner_left(output)
        return None


def _installed_fake_pty_session(
    installation: _PtyLifecycleInstallation,
    *,
    jobs: list[dict[str, str]],
    scratchpad: Path,
) -> type[_FakePtySession]:
    return type(
        "_InstalledFakePtySession",
        (_FakePtySession,),
        {
            "installation": installation,
            "jobs": copy.deepcopy(jobs),
            "scratchpad": scratchpad,
        },
    )


def _install_external_boundary(
    monkeypatch: pytest.MonkeyPatch,
    config: dict[str, Any],
    route: str,
    *,
    pty_installation: _PtyLifecycleInstallation | None = None,
) -> _PtyLifecycleInstallation | None:
    if route == "codex":
        monkeypatch.setattr(
            D, "_run_one_codex_exec",
            lambda **kwargs: _write_worker_output(kwargs, config),
        )
    elif route == "claude-headless":
        monkeypatch.setattr(
            D, "_run_one_claude_headless_breadth_worker",
            lambda **kwargs: _write_worker_output(kwargs, config),
        )
    else:
        installation = pty_installation or _PtyLifecycleInstallation()
        installed_session = _installed_fake_pty_session(
            installation,
            jobs=D._recon_worker_jobs(config),
            scratchpad=Path(config["scratchpad"]),
        )

        def observed_worker(**kwargs: Any) -> dict[str, Any]:
            result = _REAL_RUN_SINGLE_RECON_WORKER_PTY(**kwargs)
            installation.observe(result, attempt=int(kwargs.get("attempt") or 0))
            return result

        monkeypatch.setattr(D, "ClaudePtySession", installed_session)
        monkeypatch.setattr(D, "_run_single_recon_worker_pty", observed_worker)
        return installation
    return None


def _active_unit(root: Path, suffix: str) -> Mapping[str, Any]:
    ledger = AL.read_artifact_ledger(root)
    rows = [
        row for key, row in ledger.get("work_units", {}).items()
        if str(key).endswith(suffix)
        and isinstance(row, Mapping)
        and row.get("semantic_status") == "ACTIVE"
        and row.get("execution_state") == "OUTPUT_COMMITTED"
    ]
    assert len(rows) == 1, f"expected one committed work unit *{suffix}; got {len(rows)}"
    return rows[0]


def _bound_unit(root: Path, suffix: str) -> Mapping[str, Any]:
    rows = [
        row for key, row in AL.read_artifact_ledger(root).get("work_units", {}).items()
        if str(key).endswith(suffix)
        and isinstance(row, Mapping)
        and row.get("semantic_status") == "INPUTS_BOUND"
        and row.get("execution_state") == "INPUTS_BOUND_PREEXECUTION"
    ]
    assert len(rows) == 1, f"expected one prelaunch-bound unit *{suffix}; got {len(rows)}"
    return rows[0]


def _publication_rows(root: Path, suffix: str) -> list[Mapping[str, Any]]:
    return [
        row for key, row in AL.read_artifact_ledger(root).get("work_units", {}).items()
        if str(key).endswith(suffix) or f"{suffix}/attempt-" in str(key)
        if isinstance(row, Mapping)
    ]


def _valid_reason_codes(value: Any, allowed: frozenset[str]) -> bool:
    if type(value) not in {list, tuple} or not value:
        return False
    codes = tuple(value)
    if not all(type(code) is str for code in codes):
        return False
    return bool(
        len(codes) == len(set(codes))
        and all(
            code == code.strip()
            and code == unicodedata.normalize("NFC", code)
            and _REASON_CODE_RE.fullmatch(code) is not None
            and code in allowed
            for code in codes
        )
    )


def _registered_expected_output_denominator(
    old: Mapping[str, Any],
) -> tuple[Mapping[str, Any], ...]:
    """Replay the ordered, typed output denominator from the old contract."""
    manifest = old.get("contract_manifest")
    outputs = manifest.get("outputs") if isinstance(manifest, Mapping) else None
    old_artifacts = old.get("artifacts")
    if (
        not isinstance(manifest, Mapping)
        or type(outputs) is not list
        or not outputs
        or not isinstance(old_artifacts, Mapping)
        or manifest.get("key") != old.get("work_unit_key")
        or old.get("contract_digest") != _stable_digest(manifest)
    ):
        return ()

    required = {
        "artifact_class",
        "condition_id",
        "consumers",
        "identity",
        "minimum_gate",
        "owner_key",
        "schema_version",
        "write_mode",
        "writer",
    }
    optional = {"external_preimage_validator"}
    typed: list[Mapping[str, Any]] = []
    for value in outputs:
        if not isinstance(value, Mapping) or not (
            required <= set(value) <= required | optional
        ):
            return ()
        if not all(
            type(value.get(field)) is str
            for field in required - {"consumers"}
        ) or type(value.get("consumers")) is not list:
            return ()
        consumers = value["consumers"]
        if not all(type(consumer) is str for consumer in consumers):
            return ()
        identity = value["identity"]
        if (
            not identity.startswith("scratchpad:")
            or identity != identity.strip()
            or identity != unicodedata.normalize("NFC", identity)
            or value.get("owner_key") != manifest.get("key")
        ):
            return ()
        relative = identity.removeprefix("scratchpad:")
        pure = PurePosixPath(relative)
        if (
            not relative
            or pure.is_absolute()
            or str(pure) != relative
            or any(part in {"", ".", ".."} for part in pure.parts)
        ):
            return ()
        typed.append(value)

    identities = tuple(value["identity"] for value in typed)
    if (
        identities != tuple(sorted(identities))
        or len(identities) != len(set(identities))
        or len(identities) != len({identity.casefold() for identity in identities})
        or set(old_artifacts) != set(identities)
    ):
        return ()
    return tuple(typed)


def _owns_committed_expected_output(
    root: Path,
    after: Mapping[str, Any],
    old: Mapping[str, Any],
    row: Mapping[str, Any],
    authority: Mapping[str, Any],
    expected_attempt: Mapping[str, Any],
) -> bool:
    artifacts = row.get("artifacts")
    bindings = after.get("artifact_bindings")
    expected_records = authority.get("expected_output_records")
    recorded = authority.get("recorded_output_identities")
    denominator = _registered_expected_output_denominator(old)
    if (
        not denominator
        or not all(
            isinstance(value, Mapping)
            for value in (artifacts, bindings, expected_records)
        )
        or type(recorded) is not list
    ):
        return False
    expected_identities = tuple(spec["identity"] for spec in denominator)
    if (
        tuple(artifacts) != expected_identities
        or tuple(recorded) != expected_identities
        or tuple(expected_records) != expected_identities
    ):
        return False
    producer = expected_attempt["producer_attempt_identity"]
    attempt = expected_attempt["attempt_ordinal"]
    generation = expected_attempt["attempted_authority_digest"]
    lineage = {
        "producer_attempt_identity": producer,
        "attempt_ordinal": attempt,
        "generation_identity": generation,
    }
    descriptor_fields = (
        "artifact_class",
        "condition_id",
        "consumers",
        "minimum_gate",
        "schema_version",
        "write_mode",
        "writer",
    )
    for spec in denominator:
        identity = spec["identity"]
        record = artifacts.get(identity)
        binding = bindings.get(identity)
        expected = expected_records.get(identity)
        if not all(isinstance(value, Mapping) for value in (record, binding, expected)):
            return False
        relative = identity.removeprefix("scratchpad:")
        path = root / relative
        raw = path.read_bytes() if path.is_file() else b""
        digest = hashlib.sha256(raw).hexdigest() if raw else ""
        size = len(raw)
        if (
            raw
            and set(expected) == {"sha256", "size"}
            and expected.get("sha256") == digest
            and type(expected.get("size")) is int
            and expected.get("size") == size
            and record.get("identity") == identity
            and record.get("root") == "scratchpad"
            and record.get("path") == relative
            and record.get("owner_key") == producer
            and record.get("status") == "ACTIVE"
            and record.get("authority_level") == "ACTIVE_AUTHORITY"
            and record.get("sha256") == digest
            and type(record.get("size")) is int
            and record.get("size") == size
            and binding.get("identity") == identity
            and binding.get("root") == "scratchpad"
            and binding.get("path") == relative
            and binding.get("owner_key") == producer
            and binding.get("status") == "ACTIVE"
            and binding.get("authority_level") == "ACTIVE_AUTHORITY"
            and binding.get("sha256") == digest
            and type(binding.get("size")) is int
            and binding.get("size") == size
            and all(record.get(key) == value for key, value in lineage.items())
            and all(binding.get(key) == value for key, value in lineage.items())
            and all(record.get(key) == spec.get(key) for key in descriptor_fields)
            and all(binding.get(key) == spec.get(key) for key in descriptor_fields)
        ):
            continue
        return False
    return True


def _assert_changed_authority_transition(
    root: Path,
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    suffix: str,
    mutation: str,
    expected_attempt: Mapping[str, Any],
) -> None:
    before_rows = [
        (str(key), row) for key, row in before.get("work_units", {}).items()
        if (str(key).endswith(suffix) or f"{suffix}/attempt-" in str(key))
        and isinstance(row, Mapping)
    ]
    after_rows = [
        (str(key), row) for key, row in after.get("work_units", {}).items()
        if (str(key).endswith(suffix) or f"{suffix}/attempt-" in str(key))
        and isinstance(row, Mapping)
    ]
    first_active = [
        (key, row) for key, row in before_rows
        if row.get("semantic_status") == "ACTIVE"
        and row.get("execution_state") == "OUTPUT_COMMITTED"
    ]
    assert len(first_active) == 1, "control lacks one genuine first ACTIVE generation"
    assert after != before, (
        f"complete ledger no-op after canonical {mutation} drift preserves stale authority"
    )

    old_key, old = first_active[0]
    old_after = next(
        (row for key, row in after_rows if key == old_key), None
    )
    invalidated_old = isinstance(old_after, Mapping) and (
        old_after.get("semantic_status") != "ACTIVE"
        or old_after.get("execution_state") != "OUTPUT_COMMITTED"
    )
    assert invalidated_old, (
        f"canonical {mutation} drift left the first ACTIVE generation authoritative"
    )

    required = (
        "producer_attempt_identity",
        "attempt_ordinal",
        "input_set_digest",
        "config_digest",
        "source_capture_digest",
        "attempted_authority_digest",
    )
    expected_identity = str(expected_attempt.get("producer_attempt_identity") or "")
    assert expected_identity and all(expected_attempt.get(field) not in (None, "") for field in required)
    candidates = [
        row
        for key, row in after_rows
        if key == expected_identity
        and row.get("work_unit_key") == expected_identity
        and all(row.get(field) == expected_attempt.get(field) for field in required)
    ]

    def _bound_disposition(row: Mapping[str, Any]) -> bool:
        disposition = row.get("durable_disposition")
        state = disposition.get("state") if isinstance(disposition, Mapping) else None
        linkage = (row.get("semantic_status"), row.get("execution_state"))
        return (
            isinstance(disposition, Mapping)
            and disposition.get("schema") == "plamen.recon-mutation-disposition.v1"
            and type(state) is str
            and state in _DISPOSITION_LINKAGE
            and linkage in _DISPOSITION_LINKAGE[state]
            and _valid_reason_codes(
                disposition.get("reason_codes"), _CANONICAL_REASON_CODES
            )
            and all(disposition.get(field) == expected_attempt.get(field) for field in required)
        )

    def _registered_successor(row: Mapping[str, Any]) -> bool:
        authority = row.get("commit_authority")
        return (
            row.get("semantic_status") == "ACTIVE"
            and row.get("execution_state") == "OUTPUT_COMMITTED"
            and isinstance(authority, Mapping)
            and authority.get("schema") == "plamen.recon-mutation-authority.v1"
            and authority.get("state") == "ACTIVE"
            and authority.get("work_unit_key") == expected_identity
            and authority.get("reason_codes") == []
            and all(authority.get(field) == expected_attempt.get(field) for field in required)
            and row.get("generation_identity")
            == expected_attempt.get("attempted_authority_digest")
            and authority.get("generation_identity")
            == expected_attempt.get("attempted_authority_digest")
            and authority.get("authority_digest")
            == expected_attempt.get("attempted_authority_digest")
            and _owns_committed_expected_output(
                root, after, old, row, authority, expected_attempt
            )
        )

    assert any(_bound_disposition(row) or _registered_successor(row) for row in candidates), (
        f"canonical {mutation}: no exact bound successor attempt with durable "
        "disposition or registered successor authority"
    )


def _assert_active_artifact(root: Path, name: str, owner: Mapping[str, Any]) -> None:
    raw = (root / name).read_bytes()
    assert raw, f"{name} is zero bytes"
    identity = f"scratchpad:{name}"
    record = owner.get("artifacts", {}).get(identity)
    assert isinstance(record, Mapping), f"{identity} absent from committed work unit"
    assert record.get("sha256") == hashlib.sha256(raw).hexdigest()
    assert int(record.get("size") or 0) == len(raw)
    binding = AL.read_artifact_ledger(root).get("artifact_bindings", {}).get(identity)
    assert isinstance(binding, Mapping) and binding.get("status") == "ACTIVE"
    assert binding.get("owner_key") == owner.get("work_unit_key")


def _prepare_l1_bake(
    monkeypatch: pytest.MonkeyPatch,
    scratchpad: Path,
    config: dict[str, Any],
) -> None:
    monkeypatch.setattr(
        D.shutil,
        "which",
        lambda _name, *_args, **_kwargs: None,
    )
    issues = D._run_l1_bake_capability_transaction(scratchpad, config)
    assert issues == []
    unit = _active_unit(scratchpad, "/bake/capability_status")
    _assert_active_artifact(scratchpad, "primitive_status.md", unit)


def _prepare_sc_prepass_inputs(scratchpad: Path, config: dict[str, Any]) -> None:
    names = (
        "contract_inventory.md",
        "function_list.md",
        "state_variables.md",
        "meta_buffer.md",
    )
    for name in names:
        (scratchpad / name).write_text(
            f"# {name}\n\ncommitted deterministic prepass input\n" + "p" * 180 + "\n",
            encoding="utf-8",
        )
    unit = _commit_fixture_driver_outputs(
        scratchpad,
        Path(config["project_root"]),
        work_unit_id="prepass_fixture_prerequisite",
        names=names,
    )
    for name in names:
        _assert_active_artifact(scratchpad, name, unit)


def _run_fanout(
    monkeypatch: pytest.MonkeyPatch,
    config: dict[str, Any],
    route: str,
    *,
    pty_installation: _PtyLifecycleInstallation | None = None,
) -> int:
    scratchpad = Path(config["scratchpad"])
    phase = _phase(config)
    _install_external_boundary(
        monkeypatch,
        config,
        route,
        pty_installation=pty_installation,
    )
    if config["pipeline"] == "l1":
        _prepare_l1_bake(monkeypatch, scratchpad, config)
    else:
        _prepare_sc_prepass_inputs(scratchpad, config)
    if route == "pty":
        return D._run_recon_worker_pool_pty(
            scratchpad=scratchpad,
            project_root=config["project_root"],
            config=config,
            phase=phase,
            base_cmd=["claude"],
            env={},
            timeout=30,
            quiescence_s=0.01,
            attempt=1,
        )
    return D._run_recon_backend_fanout(
        backend=route,
        phase=phase,
        config=config,
        scratchpad=scratchpad,
        attempt=1,
        timeout=30,
        effective_model="fixture-model",
    )


@pytest.mark.parametrize(
    ("pipeline", "mode", "route"),
    (
        ("sc", "light", "codex"),
        ("sc", "core", "claude-headless"),
        ("sc", "thorough", "pty"),
        ("l1", "light", "pty"),
        ("l1", "core", "codex"),
        ("l1", "thorough", "claude-headless"),
    ),
)
def test_live_fanout_matrix_commits_shards_before_canonical_driver_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pipeline: str,
    mode: str,
    route: str,
) -> None:
    _project, scratchpad, config = _workspace(
        tmp_path, pipeline=pipeline, mode=mode, route=route
    )
    installation = _PtyLifecycleInstallation() if route == "pty" else None
    result = _run_fanout(
        monkeypatch,
        config,
        route,
        pty_installation=installation,
    )
    diagnostic = None if installation is None else {
        "results": installation.results,
        "events": installation.events,
    }
    assert result == 0, diagnostic

    # Positive control: every model row is a real current PhaseIO/ledger commit.
    jobs = D._recon_worker_jobs(config)
    if installation is not None:
        observed_by_output = {
            str(row["output"]): row for row in installation.results
            if str(row["output"]) in {str(job["output"]) for job in jobs}
        }
        expected_outputs = [str(job["output"]) for job in jobs]
        assert set(observed_by_output) == set(expected_outputs), diagnostic
        observed = [observed_by_output[output] for output in expected_outputs]
        assert len(observed_by_output) == len(expected_outputs), diagnostic
        assert sum(
            str(row["output"]) in set(expected_outputs)
            for row in installation.results
        ) == len(expected_outputs), diagnostic
        assert all(
            row["attempt"] == 1
            and row["rc"] == 0
            and row["status"] == "complete"
            and row["reasons"] == ()
            for row in observed
        ), diagnostic
        assert installation.active_owners == 0, diagnostic
        assert installation.max_active_owners == 1, diagnostic
    for job in jobs:
        unit = _active_unit(scratchpad, f"/recon/worker.{job['agent_id'].lower()}")
        _assert_active_artifact(scratchpad, job["output"], unit)

    canonical = L1_CANONICAL if pipeline == "l1" else SC_CANONICAL
    for name in canonical:
        assert (scratchpad / name).read_bytes(), name
    assert (scratchpad / "recon_signal_transform_receipt.json").read_bytes()

    # RED target: the current mechanical merge writes bytes but has no DRIVER
    # publication work unit or artifact bindings.
    unit = _active_unit(scratchpad, "/recon/canonical_merge")
    for name in (*canonical, "recon_signal_transform_receipt.json"):
        _assert_active_artifact(scratchpad, name, unit)


def test_fake_pty_lifecycle_adversary_is_bounded_and_installation_local(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def job(agent: str, output: str) -> dict[str, str]:
        return {"agent_id": agent, "role": f"fixture_{agent.lower()}", "output": output}

    def session(
        session_type: type[_FakePtySession],
        output: str,
    ) -> _FakePtySession:
        prompt = session_type.scratchpad / f"_prompt_{Path(output).stem}.md"
        return session_type([], prompt_path=prompt)

    def active_owner_count(root: Path, agent_id: str) -> int:
        suffix = f"/recon/worker.{agent_id.lower()}"
        return sum(
            1
            for key, row in AL.read_artifact_ledger(root).get("work_units", {}).items()
            if str(key).endswith(suffix)
            and isinstance(row, Mapping)
            and row.get("semantic_status") == "ACTIVE"
            and row.get("execution_state") == "OUTPUT_COMMITTED"
        )

    def assert_no_merge_owner(root: Path) -> None:
        assert not any(
            str(key).endswith("/recon/canonical_merge")
            for key in AL.read_artifact_ledger(root).get("work_units", {})
        )

    def real_leaf(
        case: str,
        installation: _PtyLifecycleInstallation,
    ) -> tuple[Path, dict[str, Any], dict[str, str]]:
        project, scratchpad, config = _workspace(
            tmp_path / case,
            pipeline="l1",
            mode="light",
            route="pty",
        )
        _prepare_l1_bake(monkeypatch, scratchpad, config)
        selected = D._recon_worker_jobs(config)[0]
        _install_external_boundary(
            monkeypatch,
            config,
            "pty",
            pty_installation=installation,
        )
        result = D._run_single_recon_worker_pty(
            job=selected,
            scratchpad=scratchpad,
            project_root=str(project),
            config=config,
            phase=_phase(config),
            base_cmd=["claude"],
            env={},
            timeout=30,
            quiescence_s=0.01,
            attempt=1,
        )
        return scratchpad, result, selected

    # Blocked second session: output B cannot appear before A's lifecycle ends.
    blocked_root = tmp_path / "blocked"
    blocked_root.mkdir()
    blocked_jobs = [job("A", "worker_a.md"), job("B", "worker_b.md")]
    blocked = _PtyLifecycleInstallation()
    blocked_type = _installed_fake_pty_session(
        blocked,
        jobs=blocked_jobs,
        scratchpad=blocked_root,
    )
    first = session(blocked_type, "worker_a.md")
    second = session(blocked_type, "worker_b.md")
    first.spawn()
    second_thread = threading.Thread(target=second.spawn, name="fixture-pty-blocked")
    second_thread.start()
    assert second.acquire_started.wait(1.0), "blocked second session never reached gate"
    assert second_thread.is_alive()
    assert not (blocked_root / "worker_b.md").exists()
    first.terminate()
    second_thread.join(2.0)
    assert not second_thread.is_alive()
    assert (blocked_root / "worker_b.md").read_text(encoding="utf-8") == _shard(
        blocked_jobs[1]
    )
    second.terminate()
    assert blocked.max_active_owners == 1 and blocked.active_owners == 0

    # A bounded acquisition failure cannot write, mint authority, or unlock A.
    timeout_root = tmp_path / "timeout"
    timeout_root.mkdir()
    timeout_jobs = [job("A", "timeout_a.md"), job("B", "timeout_b.md")]
    timeout_installation = _PtyLifecycleInstallation(acquire_timeout_s=0.05)
    timeout_type = _installed_fake_pty_session(
        timeout_installation,
        jobs=timeout_jobs,
        scratchpad=timeout_root,
    )
    timeout_owner = session(timeout_type, "timeout_a.md")
    timeout_waiter = session(timeout_type, "timeout_b.md")
    timeout_owner.spawn()
    with pytest.raises(RuntimeError, match="fixture PTY lifecycle acquire timeout"):
        timeout_waiter.spawn()
    timeout_waiter.terminate()
    assert not (timeout_root / "timeout_b.md").exists()
    assert active_owner_count(timeout_root, "B") == 0
    assert timeout_installation.active_owners == 1
    timeout_owner.terminate()
    assert timeout_installation.active_owners == 0

    # A fake write exception is contained by the real runner's finally/terminate.
    real_record = D._record_typed_model_worker_artifact
    write_installation = _PtyLifecycleInstallation()
    write_installation.write_failures.add("recon_l1_threat_fork.md")
    write_root, write_result, write_job = real_leaf("write_failure", write_installation)
    assert write_result["status"] == "error"
    assert write_result["reasons"] == ["fixture PTY output write failure"]
    assert active_owner_count(write_root, write_job["agent_id"]) == 0
    assert_no_merge_owner(write_root)
    assert len(write_installation.results) == 1
    assert write_installation.results[0]["attempt"] == 1
    assert write_installation.active_owners == 0
    assert not write_installation.lifecycle_mutex.locked()
    write_installation.write_failures.clear()
    write_type = _installed_fake_pty_session(
        write_installation,
        jobs=[write_job],
        scratchpad=write_root,
    )
    later = session(write_type, write_job["output"])
    later.spawn()
    later.terminate()

    # Poll failure is observed without ACTIVE authority and releases the gate.
    poll_installation = _PtyLifecycleInstallation()
    poll_installation.poll_failures.add("recon_l1_threat_fork.md")
    poll_root, poll_result, poll_job = real_leaf("poll_failure", poll_installation)
    assert poll_result["status"] == "error"
    assert poll_result["reasons"] == ["fixture PTY poll failure"]
    assert poll_installation.results == [{
        "output": poll_job["output"],
        "attempt": 1,
        "rc": D.EXIT_ERROR,
        "status": "error",
        "reasons": ("fixture PTY poll failure",),
    }]
    assert active_owner_count(poll_root, poll_job["agent_id"]) == 0
    assert_no_merge_owner(poll_root)
    assert poll_installation.active_owners == 0

    # A sentinel real-record failure remains inside the owned lifecycle window.
    record_installation = _PtyLifecycleInstallation()

    def fail_record(**kwargs: Any) -> list[str]:
        assert record_installation.active_owners == 1
        record_installation.event("record_failed", str(kwargs["output"]))
        raise RuntimeError("fixture PTY record sentinel")

    monkeypatch.setattr(
        D,
        "_record_typed_model_worker_artifact",
        fail_record,
    )
    record_root, record_result, record_job = real_leaf(
        "record_failure", record_installation
    )
    assert record_result["status"] == "error"
    assert record_result["reasons"] == ["fixture PTY record sentinel"]
    assert active_owner_count(record_root, record_job["agent_id"]) == 0
    assert_no_merge_owner(record_root)
    assert len(record_installation.results) == 1
    assert record_installation.results[0]["attempt"] == 1
    assert record_installation.active_owners == 0
    monkeypatch.setattr(D, "_record_typed_model_worker_artifact", real_record)

    # Termination before acquisition and a second termination cannot over-release.
    terminate_root = tmp_path / "terminate"
    terminate_root.mkdir()
    terminate_jobs = [job("A", "terminate_a.md"), job("B", "terminate_b.md")]
    terminate_installation = _PtyLifecycleInstallation()
    terminate_type = _installed_fake_pty_session(
        terminate_installation,
        jobs=terminate_jobs,
        scratchpad=terminate_root,
    )
    never_started = session(terminate_type, "terminate_a.md")
    never_started.terminate()
    never_started.terminate()
    assert not terminate_installation.lifecycle_mutex.locked()
    actual_owner = session(terminate_type, "terminate_b.md")
    actual_owner.spawn()
    actual_owner.terminate()
    actual_owner.terminate()
    assert terminate_installation.active_owners == 0
    assert not terminate_installation.lifecycle_mutex.locked()

    # Installation state is root-local: an old held gate cannot block a new root.
    old_root = tmp_path / "old_installation"
    new_root = tmp_path / "new_installation"
    old_root.mkdir()
    new_root.mkdir()
    isolated_job = job("ISO", "isolated.md")
    old_installation = _PtyLifecycleInstallation()
    new_installation = _PtyLifecycleInstallation()
    old_type = _installed_fake_pty_session(
        old_installation, jobs=[isolated_job], scratchpad=old_root
    )
    new_type = _installed_fake_pty_session(
        new_installation, jobs=[isolated_job], scratchpad=new_root
    )
    old_owner = session(old_type, isolated_job["output"])
    new_owner = session(new_type, isolated_job["output"])
    old_owner.spawn()
    new_owner.spawn()
    assert (new_root / isolated_job["output"]).read_bytes()
    new_owner.terminate()
    old_owner.terminate()
    assert old_installation.active_owners == new_installation.active_owners == 0

    # Success retains the mutex through the real record, then returns unchanged.
    success_installation = _PtyLifecycleInstallation()
    record_events: list[str] = []

    def observed_record(**kwargs: Any) -> list[str]:
        output = str(kwargs["output"])
        assert success_installation.active_owners == 1
        record_events.append(f"record_started:{output}")
        success_installation.event("record_started", output)
        result = real_record(**kwargs)
        record_events.append(f"recorded:{output}")
        success_installation.event("recorded", output)
        return result

    monkeypatch.setattr(D, "_record_typed_model_worker_artifact", observed_record)
    success_root, success_result, success_job = real_leaf(
        "success", success_installation
    )
    assert success_result["rc"] == 0
    assert success_result["status"] == "complete"
    assert success_result["reasons"] == []
    assert success_installation.results == [{
        "output": success_job["output"],
        "attempt": 1,
        "rc": 0,
        "status": "complete",
        "reasons": (),
    }]
    assert record_events == [
        f"record_started:{success_job['output']}",
        f"recorded:{success_job['output']}",
    ]
    assert [name for name, _output in success_installation.events] == [
        "acquire_started",
        "acquired",
        "wrote",
        "polled",
        "record_started",
        "recorded",
        "released",
    ]
    assert success_installation.max_active_owners == 1
    assert success_installation.active_owners == 0
    owner = _active_unit(
        success_root,
        f"/recon/worker.{success_job['agent_id'].lower()}",
    )
    _assert_active_artifact(success_root, success_job["output"], owner)
    assert_no_merge_owner(success_root)


@pytest.mark.parametrize("route", ("codex", "claude-headless", "pty"))
def test_dependency_wave_without_committed_base_reconciles_unresolved_without_rext(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    route: str,
) -> None:
    _project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="thorough", route=route, dependency=True
    )
    phase = _phase(config)
    _install_external_boundary(monkeypatch, config, route)
    _prepare_sc_prepass_inputs(scratchpad, config)
    if route == "pty":
        result = D._run_recon_dependency_research_wave(
            scratchpad=scratchpad,
            project_root=config["project_root"],
            config=config,
            phase=phase,
            base_cmd=["claude"],
            env={},
            timeout=30,
            quiescence_s=0.01,
            attempt=1,
        )
    else:
        result = D._run_recon_dependency_research_headless(
            backend=route,
            phase=phase,
            config=config,
            scratchpad=scratchpad,
            attempt=1,
            timeout=30,
            effective_model="fixture-model",
        )

    assert result.get("observed", result.get("total", 0)) or result.get("unresolved", 0)
    for name in (
        "external_dependency_obligations.json",
        "external_dependency_research.md",
    ):
        assert (scratchpad / name).read_bytes(), name
    # R-EXT is wave B.  None of these direct calls has committed the selected
    # mode's base recon shards, so every route must make zero unsafe provider
    # calls and must not create a MODEL-owned conditional output.  Codex and
    # legacy PTY additionally have no equivalent typed web receipts.
    assert result["unresolved"] > 0
    assert result["provider_invocations"] == 0
    assert not (scratchpad / "recon_external_dependency_research.md").exists()
    assert not any(
        "/recon/dependency_research" in str(key)
        and isinstance(row, Mapping)
        and row.get("semantic_status") == "ACTIVE"
        for key, row in AL.read_artifact_ledger(scratchpad).get(
            "work_units", {}
        ).items()
    )

    D._ensure_recon_dependency_parity(scratchpad, config["project_root"], config)
    reconciler = _active_unit(scratchpad, "/recon/dependency_reconcile")
    _assert_active_artifact(scratchpad, "external_dependency_research.md", reconciler)


def test_dependency_zero_is_nonempty_typed_zero_not_zero_ledger(
    tmp_path: Path,
) -> None:
    _project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="light", route="codex", dependency=False
    )
    result = D._ensure_recon_dependency_parity(
        scratchpad, config["project_root"], config
    )
    assert result.get("unresolved") == 0
    assert (scratchpad / "external_dependency_obligations.json").read_bytes()
    assert (scratchpad / "external_dependency_research.md").read_bytes()

    obligations = _active_unit(scratchpad, "/recon/dependency_obligations")
    reconcile = _active_unit(scratchpad, "/recon/dependency_reconcile")
    _assert_active_artifact(
        scratchpad, "external_dependency_obligations.json", obligations
    )
    _assert_active_artifact(scratchpad, "external_dependency_research.md", reconcile)


def test_authenticated_malformed_dependency_reconcile_is_refreshed_unresolved(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="light", route="codex", dependency=True
    )
    original = D.reconcile_dependency_research_ledger

    def malformed(*args, **kwargs):
        result = original(*args, **kwargs)
        outputs = dict(result["_rendered_outputs"])
        outputs["external_dependency_research.md"] = (
            b"# External Dependency Research\n\n"
            b"| Obligation ID | Dependency | Integration Surface | Assumed Behavior | Real Behavior | Source | Conformance | Fetch Status |\n"
            b"|---|---|---|---|---|---|---|---|\n"
        )
        return {**result, "_rendered_outputs": outputs}

    monkeypatch.setattr(D, "reconcile_dependency_research_ledger", malformed)
    with pytest.raises(RuntimeError, match="ledger parity failed"):
        D._ensure_recon_dependency_parity(
            scratchpad, config["project_root"], config
        )

    # The malformed bytes are now genuinely same-run DRIVER-authenticated.
    # Restoring the deterministic renderer must not replay them or loop.
    monkeypatch.setattr(D, "reconcile_dependency_research_ledger", original)
    repaired = D._ensure_recon_dependency_parity(
        scratchpad, config["project_root"], config
    )
    obligations = json.loads(
        (scratchpad / "external_dependency_obligations.json").read_text()
    )
    ledger = (scratchpad / "external_dependency_research.md").read_text()
    ok, issues = D.validate_dependency_ledger_parity(obligations, ledger)
    assert ok, issues
    assert repaired["researched"] == 0
    assert repaired["unresolved"] == len(obligations["obligations"])
    assert D._ensure_recon_dependency_parity(
        scratchpad, config["project_root"], config
    )["unresolved"] == repaired["unresolved"]


def _commit_fixture_driver_outputs(
    root: Path,
    project: Path,
    *,
    work_unit_id: str,
    names: tuple[str, ...],
) -> Mapping[str, Any]:
    payloads = {name: (root / name).read_bytes() for name in names}
    key = canonical_work_unit_key(
        "sc", "thorough", "evm", "claude", "recon", work_unit_id
    )
    contract = PhaseIOContract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="recon",
        work_unit_id=work_unit_id,
        outputs=tuple(
            ArtifactSpec(
                root="scratchpad",
                path=name,
                owner_key=key,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="CREATE",
                minimum_gate="FIXTURE_PREREQUISITE",
            )
            for name in names
        ),
        model_invoked=False,
    )
    launch = LaunchSpec(
        work_unit_key=key,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        model="driver",
        timeout_s=30,
        exec_mode="python",
        tool_policy=("filesystem",),
    )
    # Arm against true absence, then publish the already-derived fixture bytes.
    # This uses the real ledger transaction and therefore exercises output
    # prestates instead of blessing files that predated the receipt.
    for name in names:
        (root / name).unlink()
    AL.record_work_unit_inputs(root, project, contract, launch, run_id=RUN_ID)
    for name, raw in payloads.items():
        (root / name).write_bytes(raw)
    AL.record_work_unit_artifacts(
        root, project, contract, launch, run_id=RUN_ID, actor="DRIVER"
    )
    return _active_unit(root, f"/recon/{work_unit_id}")


def _prepare_real_sc_worker_shards(
    scratchpad: Path,
    project: Path,
    config: dict[str, Any],
) -> tuple[dict[str, str], ...]:
    phase = _phase(config)
    _prepare_sc_prepass_inputs(scratchpad, config)
    jobs = tuple(D._recon_worker_jobs(config))
    for job in jobs:
        assert D._prepare_typed_model_worker_launch(
            phase=phase,
            config=config,
            scratchpad=scratchpad,
            project_root=str(project),
            agent_id=job["agent_id"],
            output=job["output"],
            timeout_s=30,
        ) == []
        (scratchpad / job["output"]).write_text(_shard(job), encoding="utf-8")
        assert D._record_typed_model_worker_artifact(
            phase=phase,
            config=config,
            scratchpad=scratchpad,
            project_root=str(project),
            agent_id=job["agent_id"],
            output=job["output"],
            timeout_s=30,
        ) == []
        _assert_active_artifact(
            scratchpad,
            job["output"],
            _active_unit(scratchpad, f"/recon/worker.{job['agent_id'].lower()}"),
        )
    return jobs


def _commit_fixture_canonical_generation(
    scratchpad: Path,
    project: Path,
) -> Mapping[str, Any]:
    names = (*SC_CANONICAL, "recon_signal_transform_receipt.json")
    for name in SC_CANONICAL:
        (scratchpad / name).write_text(
            f"# {name}\n\nmanual first canonical generation\n" + "c" * 180 + "\n",
            encoding="utf-8",
        )
    (scratchpad / "recon_signal_transform_receipt.json").write_text(
        json.dumps(
            {
                "schema": "plamen.recon_signal_transform_set.v1",
                "transforms": [{"kind": "fixture", "source": "committed"}],
            },
            sort_keys=True,
        ) + "\n",
        encoding="utf-8",
    )
    return _commit_fixture_driver_outputs(
        scratchpad,
        project,
        work_unit_id="canonical_merge",
        names=names,
    )


def _registered_successor_from_committed_readback(
    root: Path,
    before: Mapping[str, Any],
    old_key: str,
    expected_attempt: Mapping[str, Any],
) -> tuple[dict[str, Any], tuple[str, ...]]:
    """Rebind the complete real contract denominator to the future attempt."""
    assert AL.read_artifact_ledger(root) == before
    old = before["work_units"][old_key]
    denominator = _registered_expected_output_denominator(old)
    assert denominator
    expected_identities = tuple(spec["identity"] for spec in denominator)

    producer = expected_attempt["producer_attempt_identity"]
    generation = expected_attempt["attempted_authority_digest"]
    lineage = {
        "producer_attempt_identity": producer,
        "attempt_ordinal": expected_attempt["attempt_ordinal"],
        "generation_identity": generation,
    }
    records: dict[str, dict[str, Any]] = {}
    successor_bindings: dict[str, dict[str, Any]] = {}
    expected_records: dict[str, dict[str, Any]] = {}
    for identity in expected_identities:
        source_record = old["artifacts"][identity]
        source_binding = before["artifact_bindings"][identity]
        raw = (root / identity.removeprefix("scratchpad:")).read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        assert raw and source_record.get("sha256") == digest
        assert source_binding.get("sha256") == digest
        records[identity] = {
            **copy.deepcopy(source_record),
            **lineage,
            "owner_key": producer,
            "status": "ACTIVE",
            "authority_level": "ACTIVE_AUTHORITY",
        }
        successor_bindings[identity] = {
            **copy.deepcopy(source_binding),
            **lineage,
            "owner_key": producer,
            "status": "ACTIVE",
            "authority_level": "ACTIVE_AUTHORITY",
        }
        expected_records[identity] = {"sha256": digest, "size": len(raw)}
    after = copy.deepcopy(before)
    after["work_units"][old_key]["semantic_status"] = "SUPERSEDED"
    after["work_units"][old_key]["execution_state"] = "FAILED"
    successor = {
        **expected_attempt,
        "generation_identity": generation,
        "work_unit_key": producer,
        "semantic_status": "ACTIVE",
        "execution_state": "OUTPUT_COMMITTED",
        "artifacts": records,
    }
    successor["commit_authority"] = {
        **expected_attempt,
        "schema": "plamen.recon-mutation-authority.v1",
        "state": "ACTIVE",
        "generation_identity": generation,
        "work_unit_key": producer,
        "authority_digest": generation,
        "reason_codes": [],
        "recorded_output_identities": list(expected_identities),
        "expected_output_records": expected_records,
    }
    after["work_units"][producer] = successor
    after["artifact_bindings"].update(successor_bindings)
    return after, expected_identities


def test_instantiate_binds_exact_eight_recon_consumers_and_separate_skill_row(
    tmp_path: Path,
) -> None:
    project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="thorough", route="pty"
    )
    # This setup is a real ArtifactLedger control, not a transaction mock: it
    # isolates the downstream current consumer from the missing merge producer.
    for name in EXACT_RECON_CONSUMER_EIGHT:
        (scratchpad / name).write_text(
            f"# {name}\n\ncommitted canonical fixture bytes\n" + "x" * 180 + "\n",
            encoding="utf-8",
        )
    producer = _commit_fixture_driver_outputs(
        scratchpad,
        project,
        work_unit_id="canonical_fixture_prerequisite",
        names=EXACT_RECON_CONSUMER_EIGHT,
    )
    for name in EXACT_RECON_CONSUMER_EIGHT:
        _assert_active_artifact(scratchpad, name, producer)

    selection_issues = D._materialize_live_skill_selection_boundary(
        scratchpad, config
    )
    assert selection_issues == []
    selection = _active_unit(scratchpad, "/recon/skill_selection_authority")
    _assert_active_artifact(scratchpad, "skill_selection_catalog.json", selection)

    instantiate = _phase(config, "instantiate")
    exact = D._instantiate_exact_inputs(scratchpad)
    assert set(EXACT_RECON_CONSUMER_EIGHT).issubset(exact)
    assert "skill_selection_catalog.json" in exact
    assert len([name for name in exact if name in EXACT_RECON_CONSUMER_EIGHT]) == 8
    issues = D._bind_typed_model_phase_inputs(instantiate, scratchpad, config)
    assert issues == []
    unit = _bound_unit(scratchpad, "/instantiate/model")
    assert set(unit.get("input_bindings", {})) == {
        f"scratchpad:{name}" for name in (*EXACT_RECON_CONSUMER_EIGHT, "skill_selection_catalog.json")
    }


def test_breadth_real_binding_rejects_uncommitted_mechanical_merge(
    tmp_path: Path,
) -> None:
    project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="core", route="codex"
    )
    jobs = D._recon_worker_jobs(config)
    phase = _phase(config)
    _prepare_sc_prepass_inputs(scratchpad, config)
    for job in jobs:
        assert D._prepare_typed_model_worker_launch(
            phase=phase,
            config=config,
            scratchpad=scratchpad,
            project_root=str(project),
            agent_id=job["agent_id"],
            output=job["output"],
            timeout_s=30,
        ) == []
        (scratchpad / job["output"]).write_text(_shard(job), encoding="utf-8")
        assert D._record_typed_model_worker_artifact(
            phase=phase,
            config=config,
            scratchpad=scratchpad,
            project_root=str(project),
            agent_id=job["agent_id"],
            output=job["output"],
            timeout_s=30,
        ) == []
    M._merge_recon_worker_shards(scratchpad, config)
    for job in jobs:
        _assert_active_artifact(
            scratchpad,
            job["output"],
            _active_unit(scratchpad, f"/recon/worker.{job['agent_id'].lower()}"),
        )

    producer = _active_unit(scratchpad, "/recon/canonical_merge")
    assert set(producer.get("artifacts", {})) == {
        f"scratchpad:{name}"
        for name in (*SC_CANONICAL, "recon_signal_transform_receipt.json")
    }

    breadth = _phase(config, "breadth")
    output = "analysis_fixture.md"
    issues = D._prepare_typed_model_worker_launch(
        phase=breadth,
        config=config,
        scratchpad=scratchpad,
        project_root=str(project),
        agent_id="B1",
        output=output,
        timeout_s=30,
    )
    assert issues == []
    unit = _bound_unit(scratchpad, "/breadth/worker.b1")
    assert unit.get("artifacts") == {}
    assert set(unit.get("input_bindings", {})) == {
        f"scratchpad:{name}" for name in BREADTH_RECON_SIX
    }
    receipt_digest = producer["commit_authority"]["receipt_digest"]
    for name in BREADTH_RECON_SIX:
        binding = unit["input_bindings"][f"scratchpad:{name}"]
        raw = (scratchpad / name).read_bytes()
        assert binding.get("status") == "ACTIVE"
        assert binding.get("producer_run_id") == RUN_ID
        assert binding.get("producer_work_unit_key") == producer.get("work_unit_key")
        assert binding.get("producer_contract_digest") == producer.get("contract_digest")
        assert binding.get("producer_launch_digest") == producer.get("launch_digest")
        assert binding.get("producer_commit_receipt_digest") == receipt_digest
        assert binding.get("sha256") == hashlib.sha256(raw).hexdigest()
        assert binding.get("size") == len(raw)


def test_breadth_prelaunch_binds_six_active_recon_inputs_before_output_commit(
    tmp_path: Path,
) -> None:
    project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="thorough", route="claude-headless"
    )
    for name in BREADTH_RECON_SIX:
        (scratchpad / name).write_text(
            f"# {name}\n\ncommitted canonical prerequisite\n" + "b" * 180 + "\n",
            encoding="utf-8",
        )
    producer = _commit_fixture_driver_outputs(
        scratchpad,
        project,
        work_unit_id="canonical_merge",
        names=BREADTH_RECON_SIX,
    )
    for name in BREADTH_RECON_SIX:
        _assert_active_artifact(scratchpad, name, producer)

    breadth = _phase(config, "breadth")
    output = "analysis_fixture.md"
    issues = D._prepare_typed_model_worker_launch(
        phase=breadth,
        config=config,
        scratchpad=scratchpad,
        project_root=str(project),
        agent_id="B1",
        output=output,
        timeout_s=30,
    )
    assert issues == []
    unit = _bound_unit(scratchpad, "/breadth/worker.b1")
    assert unit.get("semantic_status") == "INPUTS_BOUND"
    assert unit.get("execution_state") == "INPUTS_BOUND_PREEXECUTION"
    assert unit.get("artifacts") == {}
    assert set(unit.get("input_bindings", {})) == {
        f"scratchpad:{name}" for name in BREADTH_RECON_SIX
    }
    assert all(
        binding.get("status") == "ACTIVE"
        for binding in unit["input_bindings"].values()
    )

    (scratchpad / output).write_text(
        "# Breadth fixture\n\nexternal model output\n" + "o" * 220 + "\n",
        encoding="utf-8",
    )
    assert D._record_typed_model_worker_artifact(
        phase=breadth,
        config=config,
        scratchpad=scratchpad,
        project_root=str(project),
        agent_id="B1",
        output=output,
        timeout_s=30,
    ) == []
    committed = _active_unit(scratchpad, "/breadth/worker.b1")
    _assert_active_artifact(scratchpad, output, committed)


def test_transform_receipt_is_a_real_canonical_contract_output(
    tmp_path: Path,
) -> None:
    project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="thorough", route="codex"
    )
    jobs = D._recon_worker_jobs(config)
    for job in jobs:
        (scratchpad / job["output"]).write_text(_shard(job), encoding="utf-8")
    M._merge_recon_worker_shards(scratchpad, config)
    receipt = scratchpad / "recon_signal_transform_receipt.json"
    payload = json.loads(receipt.read_text(encoding="utf-8"))
    assert payload.get("schema") == "plamen.recon_signal_transform_set.v1"
    assert payload.get("transforms")

    try:
        contract = resolve_phase_io_contract(
            pipeline="sc",
            mode="thorough",
            ecosystem="evm",
            backend="claude",
            phase="recon",
            work_unit_id="canonical_merge",
            exact_inputs=tuple(job["output"] for job in jobs),
            exact_outputs=(*SC_CANONICAL, "recon_signal_transform_receipt.json"),
            exact_writer="DRIVER",
        )
    except (KeyError, TypeError, ValueError) as exc:
        pytest.fail(f"canonical merge contract/receipt output is absent: {exc}", pytrace=False)
    assert "scratchpad:recon_signal_transform_receipt.json" in {
        row.identity for row in contract.outputs
    }


@pytest.mark.parametrize(
    "failpoint",
    (
        "after_capture",
        "after_arm",
        "after_stage",
        "after_publish",
        "before_commit",
    ),
)
def test_live_canonical_merge_executes_named_crash_and_recovers_same_publisher(
    tmp_path: Path,
    failpoint: str,
) -> None:
    project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="core", route="codex"
    )
    _prepare_real_sc_worker_shards(scratchpad, project, config)
    names = (*SC_CANONICAL, "recon_signal_transform_receipt.json")
    before = {
        name: ((scratchpad / name).read_bytes() if (scratchpad / name).is_file() else None)
        for name in names
    }
    hits: list[str] = []

    class InjectedCrash(RuntimeError):
        pass

    def injector(point: str, *_args: Any, **_kwargs: Any) -> None:
        hits.append(str(point))
        if str(point) == failpoint:
            raise InjectedCrash(failpoint)

    try:
        M._merge_recon_worker_shards(
            scratchpad,
            config,
            failure_injector=injector,
        )
    except InjectedCrash:
        pass
    except TypeError as exc:
        pytest.fail(
            f"real canonical merge cannot execute named injector {failpoint}: {exc}",
            pytrace=False,
        )
    assert failpoint in hits, f"publisher accepted but never executed {failpoint}"

    # Resume through the same production merge entry point.
    M._merge_recon_worker_shards(scratchpad, config)
    final = {
        name: ((scratchpad / name).read_bytes() if (scratchpad / name).is_file() else None)
        for name in names
    }
    all_old = final == before
    all_new = all(isinstance(raw, bytes) and raw for raw in final.values())
    assert all_old or all_new, "canonical crash recovery exposed a mixed postimage"
    if all_new:
        unit = _active_unit(scratchpad, "/recon/canonical_merge")
        for name in names:
            _assert_active_artifact(scratchpad, name, unit)
    else:
        assert any(
            row.get("semantic_status") in {"QUARANTINED", "DEBT", "REJECTED"}
            for row in _publication_rows(scratchpad, "/recon/canonical_merge")
        )


@pytest.mark.parametrize("drift", ("shard_bytes", "source_bytes"))
def test_live_canonical_drift_never_leaves_first_generation_active(
    tmp_path: Path,
    drift: str,
) -> None:
    project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="thorough", route="codex"
    )
    jobs = _prepare_real_sc_worker_shards(scratchpad, project, config)
    M._merge_recon_worker_shards(scratchpad, config)
    _active_unit(scratchpad, "/recon/canonical_merge")
    before_ledger = AL.read_artifact_ledger(scratchpad)
    if drift == "shard_bytes":
        (scratchpad / jobs[0]["output"]).write_text(
            _shard(jobs[0]) + "\nchanged source shard\n", encoding="utf-8"
        )
    elif drift == "source_bytes":
        (Path(config["project_root"]) / "src" / "Protocol.sol").write_text(
            "pragma solidity ^0.8.20; contract Drift {}\n", encoding="utf-8"
        )
    old_key, old = next(
        (str(key), row)
        for key, row in before_ledger.get("work_units", {}).items()
        if str(key).endswith("/recon/canonical_merge")
        and isinstance(row, Mapping)
        and row.get("semantic_status") == "ACTIVE"
        and row.get("execution_state") == "OUTPUT_COMMITTED"
    )
    expected_attempt = _observed_canonical_attempt_binding(
        project,
        scratchpad,
        config,
        old_key,
        old,
        tuple(job["output"] for job in jobs),
    )
    M._merge_recon_worker_shards(scratchpad, config)
    after_ledger = AL.read_artifact_ledger(scratchpad)
    _assert_changed_authority_transition(
        scratchpad,
        before_ledger,
        after_ledger,
        suffix="/recon/canonical_merge",
        mutation=drift,
        expected_attempt=expected_attempt,
    )


@pytest.mark.parametrize("drift", ("shard_bytes", "source_bytes"))
def test_v6_rejects_v3_canonical_second_call_noop_counterexample(
    tmp_path: Path,
    drift: str,
) -> None:
    project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="thorough", route="pty"
    )
    _commit_fixture_canonical_generation(scratchpad, project)
    before = AL.read_artifact_ledger(scratchpad)
    old_key, old = next(
        (str(key), row)
        for key, row in before.get("work_units", {}).items()
        if str(key).endswith("/recon/canonical_merge")
        and isinstance(row, Mapping)
    )
    expected_attempt = _observed_canonical_attempt_binding(
        project, scratchpad, config, old_key, old, ()
    )
    # Fileless counterexample: model the V3 false green, where a drifted retry
    # simply returns and leaves the complete first ledger generation untouched.
    after = AL.read_artifact_ledger(scratchpad)
    with pytest.raises(AssertionError, match="complete ledger no-op"):
        _assert_changed_authority_transition(
            scratchpad,
            before,
            after,
            suffix="/recon/canonical_merge",
            mutation=drift,
            expected_attempt=expected_attempt,
        )


def _canonical_control_preimage(
    tmp_path: Path,
) -> tuple[
    Path,
    dict[str, Any],
    Mapping[str, Any],
    str,
    Mapping[str, Any],
    dict[str, Any],
]:
    project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="thorough", route="pty"
    )
    _commit_fixture_canonical_generation(scratchpad, project)
    before = AL.read_artifact_ledger(scratchpad)
    old_key, old = next(
        (str(key), row)
        for key, row in before.get("work_units", {}).items()
        if str(key).endswith("/recon/canonical_merge")
        and isinstance(row, Mapping)
    )
    expected_attempt = _observed_canonical_attempt_binding(
        project, scratchpad, config, old_key, old, ()
    )
    return scratchpad, config, before, old_key, old, expected_attempt


def test_v6_rejects_v4_canonical_unbound_debt_false_green(
    tmp_path: Path,
) -> None:
    scratchpad, _config, before, old_key, _old, expected_attempt = (
        _canonical_control_preimage(tmp_path)
    )
    after = copy.deepcopy(before)
    identity = expected_attempt["producer_attempt_identity"]
    after["work_units"][identity] = {
        "work_unit_key": identity,
        "semantic_status": "DEBT",
        "execution_state": "FAILED",
    }

    # This is the exact V4 false green: the old ACTIVE row remains and the
    # appended terminal labels contain no authority identity or digest fields.
    with pytest.raises(AssertionError, match="first ACTIVE generation authoritative"):
        _assert_changed_authority_transition(
            scratchpad,
            before,
            after,
            suffix="/recon/canonical_merge",
            mutation="shard_bytes",
            expected_attempt=expected_attempt,
        )

    # Even if a publisher invalidates the old row, omitted canonical digests
    # are absence, not evidence that the attempted binding changed.
    after["work_units"][old_key]["semantic_status"] = "INVALID"
    after["work_units"][old_key]["execution_state"] = "FAILED"
    with pytest.raises(AssertionError, match="no exact bound successor attempt"):
        _assert_changed_authority_transition(
            scratchpad,
            before,
            after,
            suffix="/recon/canonical_merge",
            mutation="shard_bytes",
            expected_attempt=expected_attempt,
        )


@pytest.mark.parametrize(
    "reason_codes",
    (["CANONICAL_INPUT_AUTHORITY_CHANGED"], ("CANONICAL_INPUT_AUTHORITY_CHANGED",)),
    ids=("list", "tuple"),
)
def test_v6_accepts_exact_bound_canonical_debt_failed_attempt_control(
    tmp_path: Path,
    reason_codes: list[str] | tuple[str, ...],
) -> None:
    scratchpad, _config, before, old_key, _old, expected_attempt = (
        _canonical_control_preimage(tmp_path)
    )
    after = copy.deepcopy(before)
    after["work_units"][old_key]["semantic_status"] = "INVALID"
    after["work_units"][old_key]["execution_state"] = "FAILED"
    identity = expected_attempt["producer_attempt_identity"]
    successor = {
        **expected_attempt,
        "work_unit_key": identity,
        "semantic_status": "DEBT",
        "execution_state": "FAILED",
    }
    successor["durable_disposition"] = {
        **expected_attempt,
        "schema": "plamen.recon-mutation-disposition.v1",
        "state": "FAILED",
        "reason_codes": reason_codes,
    }
    after["work_units"][identity] = successor

    _assert_changed_authority_transition(
        scratchpad,
        before,
        after,
        suffix="/recon/canonical_merge",
        mutation="shard_bytes",
        expected_attempt=expected_attempt,
    )


@pytest.mark.parametrize(
    "reason_codes",
    (
        [],
        [""],
        ["   "],
        [None],
        [7],
        [["CANONICAL_INPUT_AUTHORITY_CHANGED"]],
        ["CANONICAL_INPUT_AUTHORITY_CHANGED", "CANONICAL_INPUT_AUTHORITY_CHANGED"],
        [" canonical_INPUT_AUTHORITY_CHANGED"],
        ["CANONICAL-INPUT-AUTHORITY-CHANGED"],
        ["UNKNOWN_AUTHORITY_CHANGED"],
    ),
    ids=(
        "empty",
        "blank",
        "whitespace",
        "null",
        "number",
        "nested",
        "duplicate",
        "unnormalized",
        "malformed",
        "unknown",
    ),
)
def test_v6_rejects_malformed_canonical_durable_reason_denominator(
    tmp_path: Path,
    reason_codes: Any,
) -> None:
    scratchpad, _config, before, old_key, _old, expected_attempt = (
        _canonical_control_preimage(tmp_path)
    )
    after = copy.deepcopy(before)
    after["work_units"][old_key]["semantic_status"] = "INVALID"
    after["work_units"][old_key]["execution_state"] = "FAILED"
    producer = expected_attempt["producer_attempt_identity"]
    after["work_units"][producer] = {
        **expected_attempt,
        "work_unit_key": producer,
        "semantic_status": "DEBT",
        "execution_state": "FAILED",
        "durable_disposition": {
            **expected_attempt,
            "schema": "plamen.recon-mutation-disposition.v1",
            "state": "FAILED",
            "reason_codes": reason_codes,
        },
    }
    with pytest.raises(AssertionError, match="no exact bound successor attempt"):
        _assert_changed_authority_transition(
            scratchpad,
            before,
            after,
            suffix="/recon/canonical_merge",
            mutation="shard_bytes",
            expected_attempt=expected_attempt,
        )


@pytest.mark.parametrize(
    ("state", "semantic_status", "execution_state"),
    (
        ("FAILED", "QUARANTINED", "OUTPUT_QUARANTINED"),
        ("QUARANTINED", "DEBT", "FAILED"),
        ("REJECTED", "REJECTED", "FAILED"),
    ),
)
def test_v6_rejects_mismatched_canonical_typed_disposition_linkage(
    tmp_path: Path,
    state: str,
    semantic_status: str,
    execution_state: str,
) -> None:
    scratchpad, _config, before, old_key, _old, expected_attempt = (
        _canonical_control_preimage(tmp_path)
    )
    after = copy.deepcopy(before)
    after["work_units"][old_key]["semantic_status"] = "INVALID"
    after["work_units"][old_key]["execution_state"] = "FAILED"
    producer = expected_attempt["producer_attempt_identity"]
    after["work_units"][producer] = {
        **expected_attempt,
        "work_unit_key": producer,
        "semantic_status": semantic_status,
        "execution_state": execution_state,
        "durable_disposition": {
            **expected_attempt,
            "schema": "plamen.recon-mutation-disposition.v1",
            "state": state,
            "reason_codes": ["CANONICAL_INPUT_AUTHORITY_CHANGED"],
        },
    }
    with pytest.raises(AssertionError, match="no exact bound successor attempt"):
        _assert_changed_authority_transition(
            scratchpad,
            before,
            after,
            suffix="/recon/canonical_merge",
            mutation="shard_bytes",
            expected_attempt=expected_attempt,
        )


def test_v7_accepts_complete_registered_canonical_successor_from_real_ledger(
    tmp_path: Path,
) -> None:
    scratchpad, _config, before, old_key, _old, expected_attempt = (
        _canonical_control_preimage(tmp_path)
    )
    after, expected_identities = _registered_successor_from_committed_readback(
        scratchpad, before, old_key, expected_attempt
    )
    producer = expected_attempt["producer_attempt_identity"]
    denominator = _registered_expected_output_denominator(before["work_units"][old_key])
    assert len(expected_identities) == len(denominator) > 1
    assert tuple(after["work_units"][producer]["artifacts"]) == expected_identities
    assert tuple(
        after["work_units"][producer]["commit_authority"][
            "recorded_output_identities"
        ]
    ) == expected_identities
    _assert_changed_authority_transition(
        scratchpad,
        before,
        after,
        suffix="/recon/canonical_merge",
        mutation="shard_bytes",
        expected_attempt=expected_attempt,
    )


@pytest.mark.parametrize(
    "fault",
    (
        "one_of_n",
        "n_minus_one",
        "n_plus_one",
        "duplicate",
        "alias",
        "wrong_identity",
        "wrong_order",
        "zero_artifacts",
        "zero_byte",
        "unrelated_owner",
        "wrong_attempt",
        "wrong_generation",
        "wrong_path",
        "bad_bytes",
    ),
)
def test_v7_rejects_incomplete_or_misbound_canonical_successor_denominator(
    tmp_path: Path,
    fault: str,
) -> None:
    scratchpad, _config, before, old_key, _old, expected_attempt = (
        _canonical_control_preimage(tmp_path)
    )
    after, expected_identities = _registered_successor_from_committed_readback(
        scratchpad, before, old_key, expected_attempt
    )
    producer = expected_attempt["producer_attempt_identity"]
    successor = after["work_units"][producer]
    authority = successor["commit_authority"]
    first = expected_identities[0]
    last = expected_identities[-1]
    assert len(expected_identities) > 2

    def _retain(identities: tuple[str, ...]) -> None:
        successor["artifacts"] = {
            identity: successor["artifacts"][identity] for identity in identities
        }
        authority["recorded_output_identities"] = list(identities)
        authority["expected_output_records"] = {
            identity: authority["expected_output_records"][identity]
            for identity in identities
        }

    if fault == "one_of_n":
        _retain(expected_identities[:1])
    elif fault == "n_minus_one":
        _retain(expected_identities[:-1])
    elif fault == "n_plus_one":
        extra = "scratchpad:v7_unregistered_extra.md"
        raw = b"unregistered but otherwise byte-exact V7 output\n"
        (scratchpad / extra.removeprefix("scratchpad:")).write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest()
        successor["artifacts"][extra] = {
            **copy.deepcopy(successor["artifacts"][last]),
            "identity": extra,
            "path": extra.removeprefix("scratchpad:"),
            "sha256": digest,
            "size": len(raw),
        }
        after["artifact_bindings"][extra] = {
            **copy.deepcopy(after["artifact_bindings"][last]),
            "identity": extra,
            "path": extra.removeprefix("scratchpad:"),
            "sha256": digest,
            "size": len(raw),
        }
        authority["recorded_output_identities"].append(extra)
        authority["expected_output_records"][extra] = {
            "sha256": digest,
            "size": len(raw),
        }
    elif fault == "duplicate":
        authority["recorded_output_identities"].append(first)
    elif fault == "alias":
        alias = f"scratchpad:./{first.removeprefix('scratchpad:')}"
        successor["artifacts"] = {
            (alias if identity == first else identity): (
                {
                    **record,
                    "identity": alias,
                    "path": alias.removeprefix("scratchpad:"),
                }
                if identity == first else record
            )
            for identity, record in successor["artifacts"].items()
        }
        authority["recorded_output_identities"] = [
            alias if identity == first else identity
            for identity in authority["recorded_output_identities"]
        ]
        authority["expected_output_records"] = {
            (alias if identity == first else identity): record
            for identity, record in authority["expected_output_records"].items()
        }
        after["artifact_bindings"][alias] = {
            **after["artifact_bindings"].pop(first),
            "identity": alias,
            "path": alias.removeprefix("scratchpad:"),
        }
    elif fault == "wrong_identity":
        authority["recorded_output_identities"][0] = (
            "scratchpad:v7_wrong_identity.md"
        )
    elif fault == "wrong_order":
        reordered = (
            expected_identities[1], expected_identities[0], *expected_identities[2:]
        )
        successor["artifacts"] = {
            identity: successor["artifacts"][identity] for identity in reordered
        }
        authority["recorded_output_identities"] = list(reordered)
        authority["expected_output_records"] = {
            identity: authority["expected_output_records"][identity]
            for identity in reordered
        }
    if fault == "zero_artifacts":
        successor["artifacts"] = {}
    elif fault == "zero_byte":
        (scratchpad / first.removeprefix("scratchpad:")).write_bytes(b"")
    elif fault == "unrelated_owner":
        successor["artifacts"][first]["owner_key"] = old_key
        after["artifact_bindings"][first]["owner_key"] = old_key
    elif fault == "wrong_attempt":
        successor["artifacts"][first]["attempt_ordinal"] += 1
        after["artifact_bindings"][first]["attempt_ordinal"] += 1
    elif fault == "wrong_generation":
        successor["artifacts"][first]["generation_identity"] = "f" * 64
        after["artifact_bindings"][first]["generation_identity"] = "f" * 64
    elif fault == "wrong_path":
        successor["artifacts"][first]["path"] = "v7_wrong_path.md"
        after["artifact_bindings"][first]["path"] = "v7_wrong_path.md"
    elif fault == "bad_bytes":
        path = scratchpad / first.removeprefix("scratchpad:")
        path.write_bytes(path.read_bytes() + b"tampered-after-commit\n")
    with pytest.raises(AssertionError, match="no exact bound successor attempt"):
        _assert_changed_authority_transition(
            scratchpad,
            before,
            after,
            suffix="/recon/canonical_merge",
            mutation="shard_bytes",
            expected_attempt=expected_attempt,
        )


def test_exact_canonical_noop_reuses_generation_without_semantic_write(
    tmp_path: Path,
) -> None:
    project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="thorough", route="codex"
    )
    _prepare_real_sc_worker_shards(scratchpad, project, config)
    M._merge_recon_worker_shards(scratchpad, config)
    unit_before = dict(_active_unit(scratchpad, "/recon/canonical_merge"))
    names = (*SC_CANONICAL, "recon_signal_transform_receipt.json")
    files_before = {
        name: (
            hashlib.sha256((scratchpad / name).read_bytes()).hexdigest(),
            (scratchpad / name).stat().st_mtime_ns,
        )
        for name in names
    }
    ledger_before = AL.read_artifact_ledger(scratchpad)
    M._merge_recon_worker_shards(scratchpad, config)
    unit_after = _active_unit(scratchpad, "/recon/canonical_merge")
    files_after = {
        name: (
            hashlib.sha256((scratchpad / name).read_bytes()).hexdigest(),
            (scratchpad / name).stat().st_mtime_ns,
        )
        for name in names
    }
    assert files_after == files_before, "exact canonical retry performed a semantic write"
    assert unit_after.get("publication_generation") == unit_before.get(
        "publication_generation"
    )
    assert AL.read_artifact_ledger(scratchpad) == ledger_before


def test_supplementary_fallback_is_an_explicit_missing_production_seam() -> None:
    # The current inline validator fallback is not called through a fake future
    # route.  Its missing typed contract is the precise RED condition.
    try:
        contract = resolve_phase_io_contract(
            pipeline="sc",
            mode="core",
            ecosystem="evm",
            backend="codex",
            phase="recon",
            work_unit_id="supplementary_disposition",
            exact_inputs=(
                "recon_summary.md",
                "recon_supplementary_disposition_input_authority.json",
            ),
            exact_outputs=(
                "recon_supplementary_disposition.json",
                "recon_supplementary_disposition_receipt.json",
            ),
            exact_writer="DRIVER",
        )
    except (KeyError, TypeError, ValueError) as exc:
        pytest.fail(
            f"supplementary fallback has no registered production publication seam: {exc}",
            pytrace=False,
        )
    assert contract.model_invoked is False
    assert all(row.writer == "DRIVER" for row in contract.outputs)
    assert tuple(row.path for row in contract.outputs) == (
        "recon_supplementary_disposition.json",
        "recon_supplementary_disposition_receipt.json",
    )
