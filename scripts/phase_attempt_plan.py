"""Immutable, durable authority for one model-worker attempt.

The plan freezes the PhaseIO contract, launch specification, selected input
paths, input denominator, and output manifest before a provider is started.
Later lifecycle seams replay these bytes instead of resolving authority from a
mutable scratchpad a second time.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
from typing import Any, Mapping, Sequence

from phase_io_contracts import (
    ArtifactSpec,
    InputAuthorityRequirement,
    LaunchSpec,
    PhaseIOContract,
)
import rooted_path_io as rooted_io


SCHEMA = "plamen.phase_attempt_plan.v1"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_PLAN_BYTES = 2 * 1024 * 1024


class PhaseAttemptPlanError(ValueError):
    """The immutable attempt plan is missing, malformed, or inconsistent."""


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(
            dict(value),
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _selected_input_path(value: object) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise PhaseAttemptPlanError("selected input path is malformed")
    if "\\" in value or ":" in value:
        raise PhaseAttemptPlanError("selected input path is not relative POSIX")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise PhaseAttemptPlanError("selected input path is not canonical")
    return value


def _artifact_from_dict(value: object) -> ArtifactSpec:
    if not isinstance(value, Mapping):
        raise PhaseAttemptPlanError("attempt output manifest row is not an object")
    identity = value.get("identity")
    if not isinstance(identity, str) or ":" not in identity:
        raise PhaseAttemptPlanError("attempt output identity is malformed")
    root, path = identity.split(":", 1)
    artifact = ArtifactSpec(
        root=root,
        path=path,
        owner_key=value.get("owner_key"),
        artifact_class=value.get("artifact_class"),
        writer=value.get("writer"),
        write_mode=value.get("write_mode"),
        schema_version=value.get("schema_version"),
        minimum_gate=value.get("minimum_gate"),
        consumers=tuple(value.get("consumers") or ()),
        condition_id=value.get("condition_id"),
        external_preimage_validator=value.get(
            "external_preimage_validator", ""
        ),
    )
    if artifact.to_dict() != dict(value):
        raise PhaseAttemptPlanError("attempt output manifest is non-canonical")
    return artifact


def _requirement_from_dict(value: object) -> InputAuthorityRequirement:
    if not isinstance(value, Mapping):
        raise PhaseAttemptPlanError(
            "attempt input authority requirement is not an object"
        )
    try:
        requirement = InputAuthorityRequirement(**dict(value))
    except TypeError as exc:
        raise PhaseAttemptPlanError(
            "attempt input authority requirement fields are malformed"
        ) from exc
    if requirement.to_dict() != dict(value):
        raise PhaseAttemptPlanError(
            "attempt input authority requirement is non-canonical"
        )
    return requirement


def _contract_from_dict(value: object) -> PhaseIOContract:
    if not isinstance(value, Mapping):
        raise PhaseAttemptPlanError("attempt PhaseIO contract is not an object")
    key = value.get("key")
    if not isinstance(key, str) or len(key.split("/")) != 6:
        raise PhaseAttemptPlanError("attempt PhaseIO work-unit key is malformed")
    pipeline, mode, ecosystem, backend, phase, work_unit_id = key.split("/")
    contract = PhaseIOContract(
        pipeline=pipeline,
        mode=mode,
        ecosystem=ecosystem,
        backend=backend,
        phase=phase,
        work_unit_id=work_unit_id,
        outputs=tuple(_artifact_from_dict(row) for row in value.get("outputs") or ()),
        immutable_inputs=tuple(value.get("immutable_inputs") or ()),
        bounded_lookup_inputs=tuple(value.get("bounded_lookup_inputs") or ()),
        model_invoked=value.get("model_invoked"),
        input_authority_requirements=tuple(
            _requirement_from_dict(row)
            for row in value.get("input_authority_requirements") or ()
        ),
        launch_profile=value.get("launch_profile", ""),
        required_commit_actor=value.get("required_commit_actor", ""),
        contract_version=value.get("contract_version"),
    )
    if contract.to_dict() != dict(value):
        raise PhaseAttemptPlanError("attempt PhaseIO contract is non-canonical")
    return contract


def _launch_from_dict(value: object) -> LaunchSpec:
    if not isinstance(value, Mapping):
        raise PhaseAttemptPlanError("attempt launch specification is not an object")
    try:
        launch = LaunchSpec(
            work_unit_key=value.get("work_unit_key"),
            pipeline=value.get("pipeline"),
            mode=value.get("mode"),
            ecosystem=value.get("ecosystem"),
            backend=value.get("backend"),
            model=value.get("model"),
            timeout_s=value.get("timeout_s"),
            exec_mode=value.get("exec_mode"),
            tool_policy=tuple(value.get("tool_policy") or ()),
            launch_version=value.get("launch_version"),
        )
    except TypeError as exc:
        raise PhaseAttemptPlanError(
            "attempt launch specification fields are malformed"
        ) from exc
    if launch.to_dict() != dict(value):
        raise PhaseAttemptPlanError("attempt launch specification is non-canonical")
    return launch


@dataclass(frozen=True)
class PhaseAttemptPlan:
    """One replayable worker authority, frozen before provider execution."""

    run_id: str
    attempt: int
    agent_id: str
    agent_role: str
    work_category: str
    focus_area: str
    selected_inputs: tuple[str, ...]
    contract: PhaseIOContract
    launch: LaunchSpec

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, str) or not self.run_id.strip():
            raise PhaseAttemptPlanError("attempt plan run_id is malformed")
        if (
            not isinstance(self.attempt, int)
            or isinstance(self.attempt, bool)
            or self.attempt < 1
            or self.attempt > 9999
        ):
            raise PhaseAttemptPlanError("attempt plan ordinal is outside 1..9999")
        for label, value in (
            ("agent_id", self.agent_id),
            ("agent_role", self.agent_role),
            ("work_category", self.work_category),
            ("focus_area", self.focus_area),
        ):
            if not isinstance(value, str):
                raise PhaseAttemptPlanError(f"attempt plan {label} is malformed")
        selected = tuple(_selected_input_path(value) for value in self.selected_inputs)
        if selected != tuple(sorted(set(selected))):
            raise PhaseAttemptPlanError(
                "attempt plan selected input denominator is not sorted/unique"
            )
        if type(self.contract) is not PhaseIOContract:
            raise PhaseAttemptPlanError("attempt plan contract type is invalid")
        if type(self.launch) is not LaunchSpec:
            raise PhaseAttemptPlanError("attempt plan launch type is invalid")
        if self.launch.work_unit_key != self.contract.key:
            raise PhaseAttemptPlanError("attempt plan launch/contract keys differ")
        object.__setattr__(self, "run_id", self.run_id.strip())
        object.__setattr__(self, "selected_inputs", selected)

    @property
    def input_denominator(self) -> tuple[str, ...]:
        return tuple(sorted({
            *self.contract.immutable_inputs,
            *self.contract.bounded_lookup_inputs,
        }))

    @property
    def output_manifest(self) -> tuple[dict[str, object], ...]:
        return tuple(
            item.to_dict()
            for item in sorted(
                self.contract.outputs, key=lambda row: row.identity
            )
        )

    @property
    def digest(self) -> str:
        return _digest(self._unsigned_dict())

    def _unsigned_dict(self) -> dict[str, Any]:
        denominator = list(self.input_denominator)
        outputs = [dict(row) for row in self.output_manifest]
        return {
            "schema_version": SCHEMA,
            "run_id": self.run_id,
            "attempt": self.attempt,
            "agent_id": self.agent_id,
            "agent_role": self.agent_role,
            "work_category": self.work_category,
            "focus_area": self.focus_area,
            "work_unit_key": self.contract.key,
            "selected_inputs": list(self.selected_inputs),
            "selected_inputs_sha256": _digest(list(self.selected_inputs)),
            "input_denominator": denominator,
            "input_denominator_sha256": _digest(denominator),
            "output_manifest": outputs,
            "output_manifest_sha256": _digest(outputs),
            "contract": self.contract.to_dict(),
            "contract_digest": self.contract.digest,
            "launch": self.launch.to_dict(),
            "launch_digest": self.launch.digest,
        }

    def to_dict(self) -> dict[str, Any]:
        payload = self._unsigned_dict()
        payload["plan_digest"] = self.digest
        return payload


def phase_attempt_plan_path(
    scratchpad: Path, *, phase: str, work_unit_id: str, attempt: int
) -> Path:
    for label, token in (("phase", phase), ("work_unit_id", work_unit_id)):
        if not isinstance(token, str) or not re.fullmatch(
            r"[a-z0-9][a-z0-9_.-]*", token
        ):
            raise PhaseAttemptPlanError(f"attempt plan {label} is non-canonical")
    if not isinstance(attempt, int) or isinstance(attempt, bool) or not 1 <= attempt <= 9999:
        raise PhaseAttemptPlanError("attempt plan ordinal is outside 1..9999")
    return (
        Path(scratchpad)
        / "_phase_attempt_plans"
        / f"{phase}.{work_unit_id}.attempt-{attempt:04d}.json"
    )


def phase_attempt_plan_from_dict(value: object) -> PhaseAttemptPlan:
    if not isinstance(value, Mapping):
        raise PhaseAttemptPlanError("phase attempt plan is not an object")
    payload = dict(value)
    plan_digest = payload.pop("plan_digest", None)
    if not isinstance(plan_digest, str) or not _SHA256_RE.fullmatch(plan_digest):
        raise PhaseAttemptPlanError("phase attempt plan digest is malformed")
    if payload.get("schema_version") != SCHEMA or _digest(payload) != plan_digest:
        raise PhaseAttemptPlanError("phase attempt plan digest mismatch")
    contract = _contract_from_dict(payload.get("contract"))
    launch = _launch_from_dict(payload.get("launch"))
    plan = PhaseAttemptPlan(
        run_id=payload.get("run_id"),
        attempt=payload.get("attempt"),
        agent_id=payload.get("agent_id"),
        agent_role=payload.get("agent_role"),
        work_category=payload.get("work_category"),
        focus_area=payload.get("focus_area"),
        selected_inputs=tuple(payload.get("selected_inputs") or ()),
        contract=contract,
        launch=launch,
    )
    if plan.to_dict() != dict(value):
        raise PhaseAttemptPlanError("phase attempt plan fields are non-canonical")
    return plan


def load_phase_attempt_plan(path: Path) -> PhaseAttemptPlan:
    target = Path(path)
    try:
        row = target.lstat()
        if not target.is_file() or target.is_symlink() or row.st_size > _MAX_PLAN_BYTES:
            raise PhaseAttemptPlanError("phase attempt plan path is unsafe")
        raw = target.read_bytes()
        if len(raw) != row.st_size:
            raise PhaseAttemptPlanError("phase attempt plan changed during read")
        payload = json.loads(raw.decode("utf-8", errors="strict"))
    except PhaseAttemptPlanError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PhaseAttemptPlanError("phase attempt plan cannot be loaded") from exc
    return phase_attempt_plan_from_dict(payload)


def publish_phase_attempt_plan(path: Path, plan: PhaseAttemptPlan) -> None:
    """Publish once, or accept only an already-identical durable plan."""

    target = Path(path)
    rooted_io.ensure_directory(
        target.parent, parents=True, label="phase attempt plan directory"
    )
    raw = _canonical_bytes(plan.to_dict())
    fd = -1
    temporary: Path | None = None
    try:
        fd, temporary = rooted_io.exclusive_temp_file(
            target.parent, prefix="_.phase-attempt.", suffix=".tmp"
        )
        with os.fdopen(fd, "wb") as handle:
            fd = -1
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            rooted_io.durable_publish_new(temporary, target)
            temporary = None
        except FileExistsError:
            existing = load_phase_attempt_plan(target)
            if existing.to_dict() != plan.to_dict():
                raise PhaseAttemptPlanError(
                    "immutable phase attempt plan already exists with different authority"
                )
    finally:
        if fd >= 0:
            os.close(fd)
        if temporary is not None and rooted_io.lexists(temporary):
            rooted_io.unlink(temporary)


def require_phase_attempt_plan_identity(
    plan: PhaseAttemptPlan,
    *,
    run_id: str,
    attempt: int,
    phase: str,
    work_unit_id: str,
    agent_id: str,
    agent_role: str,
    work_category: str,
) -> PhaseAttemptPlan:
    expected_key_tail = f"/{phase}/{work_unit_id}"
    if (
        plan.run_id != str(run_id)
        or plan.attempt != int(attempt)
        or not plan.contract.key.endswith(expected_key_tail)
        or plan.agent_id != str(agent_id)
        or plan.agent_role != str(agent_role)
        or plan.work_category != str(work_category)
    ):
        raise PhaseAttemptPlanError(
            "phase attempt plan identity differs from scheduled worker"
        )
    return plan


__all__ = [
    "PhaseAttemptPlan",
    "PhaseAttemptPlanError",
    "load_phase_attempt_plan",
    "phase_attempt_plan_path",
    "publish_phase_attempt_plan",
    "require_phase_attempt_plan_identity",
]
