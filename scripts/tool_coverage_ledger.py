"""Typed, durable coverage receipts for optional mechanical audit tools.

The audit pipeline is intentionally haltless when an optional tool is missing
or fails.  Haltless must not mean "clean": every attempted capability records
one schema-validated outcome in ``tool_coverage_ledger.json``.  The JSON file is
the machine authority; the Markdown file is a deterministic human projection.

This module is stdlib-only so recon can use it before any Python dependencies
are installed.
"""

from __future__ import annotations

import json
import hashlib
import os
import re
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Mapping

import toolchain_control_authority as _toolchain_controls


LEDGER_SCHEMA = "plamen.tool-coverage-ledger"
LEDGER_SCHEMA_VERSION = 1
LEDGER_FILENAME = "tool_coverage_ledger.json"
LEDGER_MARKDOWN_FILENAME = "tool_coverage_ledger.md"
_CAPABILITY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,127}$")
TOOLCHAIN_GOVERNANCE_SCHEMA = "plamen.toolchain_governance.v1"
TOOLCHAIN_GOVERNANCE_FILENAME = "toolchain_governance.v1.json"
TOOLCHAIN_VERSION_LOCK_SCHEMA = "plamen.toolchain_version_lock.v1"
TOOLCHAIN_VERSION_LOCK_FILENAME = "toolchain_version_lock.v1.json"
CONTEXT_BOUND_OUTCOME_SCHEMA = "plamen.tool-outcome-envelope.v1"
GENERIC_SUCCESS_OUTCOME_SCHEMA = "plamen.tool-success-envelope.v1"
TOOLCHAIN_COVERAGE_DEBT_SCHEMA = "plamen.toolchain-coverage-debt.v1"
TOOLCHAIN_COVERAGE_DEBT_FILENAME = "toolchain_coverage_debt.json"
TOOLCHAIN_COVERAGE_REPORT_FILENAME = (
    "report_semantic_toolchain_coverage.md"
)
PRECISE_GRAPH_CAPABILITIES = frozenset(
    {
        "slither.evm-reference-graph",
        "scip-go.reference-graph",
        "scip-rust.reference-graph",
        "protobuf.scip-graph-parser",
    }
)
PRECISE_GRAPH_ARTIFACTS = (
    "caller_map.md",
    "callee_map.md",
    "state_write_map.md",
    "function_summary.md",
    "_mechanical_graph.json",
)
PRECISE_GRAPH_GENERATION_MANIFEST = (
    "_mechanical_graph_generation.json"
)
PRECISE_GRAPH_GENERATION_SCHEMA = (
    "plamen.mechanical_graph_generation.v1"
)
_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_GOVERNANCE_PATH = (
    _REPOSITORY_ROOT
    / "verification_policy"
    / TOOLCHAIN_GOVERNANCE_FILENAME
)
_HEX_SHA256 = re.compile(r"[0-9a-f]{64}")
_SAFE_CONTEXT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}")
_KNOWN_CVE_CAPABILITIES = frozenset(
    {
        "cargo-audit.dependency-audit",
        "govulncheck.dependency-audit",
    }
)
_KNOWN_CVE_ADVISORY_SOURCES = {
    "cargo-audit.dependency-audit": "rustsec-local",
    "govulncheck.dependency-audit": "govulndb-local",
}


def _source_provider_ref(provider_ref: str) -> str:
    """Return a success envelope's original provider reference when wrapped."""

    try:
        payload = json.loads(provider_ref)
    except Exception:
        return provider_ref
    if (
        isinstance(payload, dict)
        and payload.get("schema_version") == GENERIC_SUCCESS_OUTCOME_SCHEMA
        and isinstance(payload.get("source_provider_ref"), str)
    ):
        return str(payload["source_provider_ref"])
    return provider_ref


class ToolCoverageLedgerError(ValueError):
    """Raised when a typed outcome or existing ledger violates its schema."""


class ToolOutcomeState(str, Enum):
    SUCCEEDED = "SUCCEEDED"
    SKIPPED = "SKIPPED"
    UNAVAILABLE = "UNAVAILABLE"
    FAILED = "FAILED"


def _artifact_name(value: str) -> str:
    normalized = str(value).replace("\\", "/").strip()
    path = Path(normalized)
    if (
        not normalized
        or path.is_absolute()
        or normalized == ".."
        or normalized.startswith("../")
        or "/../" in f"/{normalized}/"
    ):
        raise ToolCoverageLedgerError(
            f"artifact must be a scratchpad-relative path: {value!r}"
        )
    return normalized


@dataclass(frozen=True)
class ToolOutcome:
    """One capability result with enough evidence to distinguish clean from debt."""

    capability_id: str
    tool: str
    state: ToolOutcomeState
    reason: str
    finding_count: int | None = None
    schema_validated: bool = False
    artifacts: tuple[str, ...] = ()
    provider_ref: str = ""

    def __post_init__(self) -> None:
        if not _CAPABILITY_ID_RE.fullmatch(self.capability_id):
            raise ToolCoverageLedgerError(
                f"invalid capability_id: {self.capability_id!r}"
            )
        if not self.tool.strip():
            raise ToolCoverageLedgerError("tool must be non-empty")
        if not isinstance(self.state, ToolOutcomeState):
            raise ToolCoverageLedgerError("state must be ToolOutcomeState")
        if not self.reason.strip():
            raise ToolCoverageLedgerError("reason must be non-empty")
        if self.state is ToolOutcomeState.SUCCEEDED:
            if (
                isinstance(self.finding_count, bool)
                or not isinstance(self.finding_count, int)
                or self.finding_count < 0
            ):
                raise ToolCoverageLedgerError(
                    "SUCCEEDED requires a non-negative integer finding_count"
                )
            if not self.schema_validated:
                raise ToolCoverageLedgerError(
                    "SUCCEEDED requires schema_validated=true"
                )
            if (
                self.capability_id in _KNOWN_CVE_CAPABILITIES
                and not self.provider_ref.strip()
            ):
                raise ToolCoverageLedgerError(
                    "known-CVE SUCCEEDED requires advisory provenance"
                )
            if self.capability_id in _KNOWN_CVE_CAPABILITIES:
                try:
                    advisory = json.loads(
                        _source_provider_ref(self.provider_ref)
                    )
                except Exception as exc:
                    raise ToolCoverageLedgerError(
                        "known-CVE advisory provenance is malformed"
                    ) from exc
                expected_fields = {
                    "schema_version",
                    "source_id",
                    "provider",
                    "content_sha256",
                    "as_of",
                    "expires_at",
                }
                if (
                    not isinstance(advisory, dict)
                    or set(advisory) != expected_fields
                    or advisory.get("schema_version")
                    != "plamen.advisory_source.v1"
                    or advisory.get("source_id")
                    != _KNOWN_CVE_ADVISORY_SOURCES[self.capability_id]
                    or not str(advisory.get("provider") or "").strip()
                    or not re.fullmatch(
                        r"[0-9a-f]{64}",
                        str(advisory.get("content_sha256") or ""),
                    )
                    or not str(advisory.get("as_of") or "").strip()
                    or not str(advisory.get("expires_at") or "").strip()
                ):
                    raise ToolCoverageLedgerError(
                        "known-CVE advisory provenance schema is invalid"
                    )
        elif self.finding_count is not None:
            raise ToolCoverageLedgerError(
                f"{self.state.value} must not claim a finding_count"
            )
        for artifact in self.artifacts:
            _artifact_name(artifact)

    @classmethod
    def succeeded(
        cls,
        capability_id: str,
        tool: str,
        finding_count: int,
        *,
        artifacts: Iterable[str] = (),
        provider_ref: str = "",
    ) -> "ToolOutcome":
        return cls(
            capability_id=capability_id,
            tool=tool,
            state=ToolOutcomeState.SUCCEEDED,
            reason="validated output accepted",
            finding_count=finding_count,
            schema_validated=True,
            artifacts=tuple(artifacts),
            provider_ref=provider_ref,
        )

    @classmethod
    def debt(
        cls,
        capability_id: str,
        tool: str,
        state: ToolOutcomeState,
        reason: str,
        *,
        provider_ref: str = "",
    ) -> "ToolOutcome":
        if state is ToolOutcomeState.SUCCEEDED:
            raise ToolCoverageLedgerError("debt outcome cannot be SUCCEEDED")
        return cls(
            capability_id=capability_id,
            tool=tool,
            state=state,
            reason=reason,
            provider_ref=provider_ref,
        )

    def legacy_status(self, *, unavailable_token: str = "SKIPPED") -> str:
        """Compatibility projection for callers that still consume status strings."""
        if self.state is ToolOutcomeState.SUCCEEDED:
            return f"WRITTEN:{self.finding_count} findings"
        if self.state is ToolOutcomeState.UNAVAILABLE:
            return f"{unavailable_token}:{self.reason}"
        return f"{self.state.value}:{self.reason}"

    def to_record(self) -> dict[str, Any]:
        return {
            "capability_id": self.capability_id,
            "tool": self.tool,
            "state": self.state.value,
            "reason": self.reason,
            "finding_count": self.finding_count,
            "schema_validated": self.schema_validated,
            "artifacts": [_artifact_name(item) for item in self.artifacts],
            "provider_ref": self.provider_ref,
        }

    @classmethod
    def from_record(cls, record: Mapping[str, Any]) -> "ToolOutcome":
        expected = {
            "capability_id",
            "tool",
            "state",
            "reason",
            "finding_count",
            "schema_validated",
            "artifacts",
            "provider_ref",
        }
        if set(record) != expected:
            raise ToolCoverageLedgerError(
                "outcome fields do not match the v1 schema"
            )
        artifacts = record["artifacts"]
        if not isinstance(artifacts, list) or not all(
            isinstance(item, str) for item in artifacts
        ):
            raise ToolCoverageLedgerError("artifacts must be a list of strings")
        if not isinstance(record["schema_validated"], bool):
            raise ToolCoverageLedgerError("schema_validated must be boolean")
        try:
            state = ToolOutcomeState(str(record["state"]))
        except ValueError as exc:
            raise ToolCoverageLedgerError("unknown tool outcome state") from exc
        return cls(
            capability_id=str(record["capability_id"]),
            tool=str(record["tool"]),
            state=state,
            reason=str(record["reason"]),
            finding_count=record["finding_count"],
            schema_validated=record["schema_validated"],
            artifacts=tuple(artifacts),
            provider_ref=str(record["provider_ref"]),
        )


def _empty_ledger() -> dict[str, Any]:
    return {
        "schema": LEDGER_SCHEMA,
        "schema_version": LEDGER_SCHEMA_VERSION,
        "capabilities": {},
    }


def _canonical_json(payload: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        + "\n"
    ).encode("utf-8")


def _compact_canonical_json(payload: Any) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
            size += len(block)
    return digest.hexdigest(), size


_EXECUTION_CONTEXT_FIELDS = frozenset(
    {
        "run_id",
        "phase",
        "snapshot_sha256",
        "project_root_sha256",
        "ecosystem",
        "pipeline",
        "mode",
        "platform",
    }
)


def _normalized_execution_context(
    context: Mapping[str, Any],
) -> dict[str, str]:
    normalized = {
        key: str(context.get(key) or "")
        for key in sorted(_EXECUTION_CONTEXT_FIELDS)
    }
    if (
        set(context) != _EXECUTION_CONTEXT_FIELDS
        or any(
            _SAFE_CONTEXT.fullmatch(normalized[key]) is None
            for key in (
                "run_id",
                "phase",
                "ecosystem",
                "pipeline",
                "mode",
                "platform",
            )
        )
        or any(
            _HEX_SHA256.fullmatch(normalized[key]) is None
            for key in ("snapshot_sha256", "project_root_sha256")
        )
    ):
        raise ToolCoverageLedgerError(
            "tool execution context is incomplete"
        )
    return normalized


def build_tool_execution_context(
    config: Mapping[str, Any],
    *,
    phase: str,
) -> dict[str, str]:
    """Derive one canonical run/snapshot/project identity for every tool."""

    snapshot = config.get("_audit_snapshot") or config.get(
        "audit_snapshot"
    ) or {}
    snapshot_sha256 = (
        str(snapshot.get("snapshot_digest") or "")
        if isinstance(snapshot, Mapping)
        else ""
    )
    project = Path(str(config.get("project_root") or "")).resolve()
    project_identity = os.path.normcase(str(project)).replace("\\", "/")
    return _normalized_execution_context(
        {
            "run_id": str(config.get("_run_id") or ""),
            "phase": str(phase),
            "snapshot_sha256": snapshot_sha256,
            "project_root_sha256": hashlib.sha256(
                project_identity.encode("utf-8")
            ).hexdigest(),
            "ecosystem": str(
                config.get("language") or ""
            ).strip().lower(),
            "pipeline": (
                "l1" if config.get("pipeline") == "l1" else "sc"
            ),
            "mode": str(
                config.get("mode") or "core"
            ).strip().lower(),
            "platform": (
                "windows"
                if sys.platform == "win32"
                else "macos"
                if sys.platform == "darwin"
                else "linux"
                if sys.platform.startswith("linux")
                else sys.platform
            ),
        }
    )


def _governed_capability(
    capability_id: str,
    tool: str,
    *,
    registry_path: Path | None = None,
) -> dict[str, Any]:
    governance = load_toolchain_governance(
        registry_path or _DEFAULT_GOVERNANCE_PATH
    )
    matches = [
        dict(row)
        for row in governance["capabilities"]
        if row.get("capability_id") == capability_id
    ]
    if len(matches) != 1:
        raise ToolCoverageLedgerError(
            "context-bound outcome capability is not uniquely governed"
        )
    row = matches[0]
    invoked_tools = {
        str(tool_id)
        for invocation in row.get("invocations", [])
        if isinstance(invocation, Mapping)
        for tool_id in invocation.get("tool_ids", [])
    }
    if tool not in invoked_tools:
        raise ToolCoverageLedgerError(
            "context-bound outcome tool is outside governed capability"
        )
    return row


def build_context_bound_tool_outcome_envelope(
    scratch: Path,
    *,
    capability_id: str,
    tool: str,
    authority: Mapping[str, Any],
    context: Mapping[str, Any],
    artifacts: Iterable[str],
    upstream_outcomes: Iterable[Mapping[str, Any]] = (),
    registry_path: Path | None = None,
) -> dict[str, Any]:
    """Bind one precise result to its full execution and artifact context."""

    root = Path(scratch)
    if capability_id not in PRECISE_GRAPH_CAPABILITIES:
        raise ToolCoverageLedgerError(
            "context-bound envelope is only defined for precise graph tools"
        )
    if not isinstance(authority, Mapping):
        raise ToolCoverageLedgerError("provider authority is not an object")
    provider = dict(authority)
    provider_digest = str(provider.get("authority_digest") or "")
    unsigned_provider = {
        key: value for key, value in provider.items()
        if key != "authority_digest"
    }
    if (
        provider.get("tool_id") != tool
        or provider.get("deterministic_provider_authority") is not True
        or _HEX_SHA256.fullmatch(provider_digest) is None
        or hashlib.sha256(
            _compact_canonical_json(unsigned_provider)
        ).hexdigest()
        != provider_digest
    ):
        raise ToolCoverageLedgerError(
            "provider authority does not replay exactly"
        )
    lock_sha256 = str(
        provider.get("toolchain_version_lock_sha256") or ""
    )
    governance_sha256 = str(
        provider.get("toolchain_governance_sha256") or ""
    )
    if (
        _HEX_SHA256.fullmatch(lock_sha256) is None
        or _HEX_SHA256.fullmatch(governance_sha256) is None
    ):
        raise ToolCoverageLedgerError(
            "provider authority omits exact toolchain control digests"
        )
    controls = _toolchain_controls.load_toolchain_controls(
        registry_path or _DEFAULT_GOVERNANCE_PATH
    )
    if (
        controls.lock_sha256 != lock_sha256
        or controls.governance_sha256 != governance_sha256
    ):
        raise ToolCoverageLedgerError(
            "provider authority toolchain controls drifted"
        )

    normalized_context = _normalized_execution_context(context)

    artifact_names = tuple(_artifact_name(value) for value in artifacts)
    if artifact_names != PRECISE_GRAPH_ARTIFACTS:
        raise ToolCoverageLedgerError(
            "precise graph artifact denominator is incomplete or reordered"
        )
    artifact_rows: list[dict[str, Any]] = []
    for relative in artifact_names:
        path = root / relative
        if not path.is_file():
            raise ToolCoverageLedgerError(
                f"precise graph artifact is missing: {relative}"
            )
        digest, size = _sha256_file(path)
        if size <= 0:
            raise ToolCoverageLedgerError(
                f"precise graph artifact is empty: {relative}"
            )
        artifact_rows.append(
            {"path": relative, "sha256": digest, "bytes": size}
        )

    # Mixed-language graph publication is a projection of two independently
    # produced lane artifacts.  A status string from a lane is not authority:
    # bind and replay the exact lane ledger and its context-bound envelope.
    # Non-mixed providers carry the same closed field with an empty list.
    upstream_rows: list[dict[str, Any]] = []
    for raw in upstream_outcomes:
        if not isinstance(raw, Mapping) or set(raw) != {
            "ledger_path",
            "capability_id",
        }:
            raise ToolCoverageLedgerError(
                "upstream graph outcome binding is malformed"
            )
        ledger_relative = _artifact_name(str(raw["ledger_path"]))
        upstream_capability = str(raw["capability_id"] or "")
        expected_prefix = "_graph_providers/"
        if (
            not ledger_relative.startswith(expected_prefix)
            or not ledger_relative.endswith(f"/{LEDGER_FILENAME}")
            or upstream_capability not in PRECISE_GRAPH_CAPABILITIES
        ):
            raise ToolCoverageLedgerError(
                "upstream graph outcome binding is outside the mixed lanes"
            )
        ledger_path = root / ledger_relative
        ledger_sha256, ledger_bytes = _sha256_file(ledger_path)
        if ledger_bytes <= 0:
            raise ToolCoverageLedgerError(
                "upstream graph outcome ledger is empty"
            )
        lane_root = ledger_path.parent
        lane_outcomes = load_tool_coverage_ledger(lane_root)
        lane_outcome = lane_outcomes.get(upstream_capability)
        if (
            lane_outcome is None
            or lane_outcome.state is not ToolOutcomeState.SUCCEEDED
        ):
            raise ToolCoverageLedgerError(
                "upstream graph outcome is not a replayed success"
            )
        try:
            lane_envelope = json.loads(lane_outcome.provider_ref)
        except (TypeError, json.JSONDecodeError) as exc:
            raise ToolCoverageLedgerError(
                "upstream graph outcome envelope is malformed"
            ) from exc
        lane_envelope_sha256 = str(
            lane_envelope.get("envelope_sha256") or ""
        )
        if _HEX_SHA256.fullmatch(lane_envelope_sha256) is None:
            raise ToolCoverageLedgerError(
                "upstream graph outcome envelope digest is absent"
            )
        lane_context = lane_envelope.get("context")
        lane_ecosystem = Path(ledger_relative).parts[-2]
        shared_fields = (
            "run_id",
            "phase",
            "snapshot_sha256",
            "project_root_sha256",
            "pipeline",
            "mode",
            "platform",
        )
        if (
            normalized_context.get("ecosystem") != "mixed"
            or lane_ecosystem not in {"go", "rust"}
            or not isinstance(lane_context, Mapping)
            or lane_context.get("ecosystem") != lane_ecosystem
            or any(
                lane_context.get(field)
                != normalized_context.get(field)
                for field in shared_fields
            )
        ):
            raise ToolCoverageLedgerError(
                "upstream graph outcome context does not project from the "
                "current mixed execution"
            )
        upstream_rows.append(
            {
                "ledger_path": ledger_relative,
                "capability_id": upstream_capability,
                "ledger_sha256": ledger_sha256,
                "outcome_envelope_sha256": lane_envelope_sha256,
            }
        )
    if len(
        {
            (row["ledger_path"], row["capability_id"])
            for row in upstream_rows
        }
    ) != len(upstream_rows):
        raise ToolCoverageLedgerError(
            "upstream graph outcome binding is duplicated"
        )
    upstream_rows.sort(
        key=lambda row: (row["ledger_path"], row["capability_id"])
    )

    capability = _governed_capability(
        capability_id,
        tool,
        registry_path=registry_path,
    )
    applicability = capability.get("applicability")
    actual = {
        "pipelines": normalized_context["pipeline"],
        "ecosystems": normalized_context["ecosystem"],
        "platforms": normalized_context["platform"],
        "modes": normalized_context["mode"],
        "phases": normalized_context["phase"],
    }
    if (
        not isinstance(applicability, Mapping)
        or any(
            not _applicability_matches(
                applicability.get(field),
                value,
            )
            for field, value in actual.items()
        )
    ):
        raise ToolCoverageLedgerError(
            "execution context is outside governed capability applicability"
        )
    capability_digest = hashlib.sha256(
        _compact_canonical_json(capability)
    ).hexdigest()
    artifact_denominator_sha256 = hashlib.sha256(
        _compact_canonical_json(list(artifact_names))
    ).hexdigest()
    unsigned = {
        "schema_version": CONTEXT_BOUND_OUTCOME_SCHEMA,
        "context": normalized_context,
        "capability_id": capability_id,
        "governed_capability": capability,
        "governed_capability_sha256": capability_digest,
        "tool": tool,
        "provider_authority": provider,
        "provider_authority_sha256": provider_digest,
        "toolchain_version_lock_sha256": lock_sha256,
        "toolchain_governance_sha256": governance_sha256,
        "artifact_denominator": list(artifact_names),
        "artifact_denominator_sha256": artifact_denominator_sha256,
        "artifacts": artifact_rows,
        "upstream_outcomes": upstream_rows,
    }
    return {
        **unsigned,
        "envelope_sha256": hashlib.sha256(
            _canonical_json(unsigned)
        ).hexdigest(),
    }


def replay_committed_graph_generation(
    scratch: Path,
    *,
    artifact_rows: Iterable[Mapping[str, Any]] | None = None,
) -> list[str]:
    """Replay the written-last commit manifest over the precise five-file set."""

    root = Path(scratch)
    if artifact_rows is None:
        rows: list[dict[str, Any]] = []
        for relative in PRECISE_GRAPH_ARTIFACTS:
            try:
                digest, size = _sha256_file(root / relative)
            except OSError:
                return [
                    f"precise graph committed artifact is missing: {relative}"
                ]
            rows.append(
                {"path": relative, "sha256": digest, "bytes": size}
            )
    else:
        rows = [dict(row) for row in artifact_rows]
    unsigned = {
        "schema_version": PRECISE_GRAPH_GENERATION_SCHEMA,
        "state": "COMMITTED",
        "artifact_denominator": list(PRECISE_GRAPH_ARTIFACTS),
        "artifacts": rows,
    }
    expected = {
        **unsigned,
        "generation_sha256": hashlib.sha256(
            _canonical_json(unsigned)
        ).hexdigest(),
    }
    path = root / PRECISE_GRAPH_GENERATION_MANIFEST
    try:
        observed = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return ["precise graph committed-set manifest is missing"]
    if observed != expected:
        return ["precise graph committed-set manifest drifted"]
    return []


def quarantine_invalid_committed_graph_generation(
    scratch: Path,
) -> tuple[bool, tuple[str, ...]]:
    """Fail closed before any phase consumes a drifted precise generation."""

    root = Path(scratch)
    manifest = root / PRECISE_GRAPH_GENERATION_MANIFEST
    if not manifest.exists():
        # Approximate providers intentionally publish only the machine graph.
        return False, ()
    issues = replay_committed_graph_generation(root)
    if not issues:
        return False, ()
    failures: list[str] = []
    # Invalidate the written-last authority first.  Root files are compatibility
    # projections and cannot remain consumer-visible after this point.
    for relative in (
        PRECISE_GRAPH_GENERATION_MANIFEST,
        *PRECISE_GRAPH_ARTIFACTS,
    ):
        path = root / relative
        try:
            path.unlink(missing_ok=True)
        except OSError as exc:
            failures.append(f"{relative}:{type(exc).__name__}")
            try:
                if relative.endswith(".json"):
                    path.write_text("{}\n", encoding="utf-8")
                else:
                    path.write_text(
                        "# Graph Artifact\n\n"
                        "> **Status**: UNAVAILABLE: committed generation "
                        "failed replay.\n",
                        encoding="utf-8",
                    )
            except OSError as write_exc:
                failures.append(
                    f"{relative}:invalidate:{type(write_exc).__name__}"
                )
    return True, tuple((*issues, *failures))


def replay_context_bound_tool_outcome_envelope(
    scratch: Path,
    envelope: Mapping[str, Any],
    *,
    expected_context: Mapping[str, Any] | None = None,
    registry_path: Path | None = None,
) -> list[str]:
    """Replay an outcome without trusting capability presence or prose."""

    issues: list[str] = []
    if not isinstance(envelope, Mapping):
        return ["context-bound outcome envelope is not an object"]
    candidate = dict(envelope)
    expected_fields = {
        "schema_version",
        "context",
        "capability_id",
        "governed_capability",
        "governed_capability_sha256",
        "tool",
        "provider_authority",
        "provider_authority_sha256",
        "toolchain_version_lock_sha256",
        "toolchain_governance_sha256",
        "artifact_denominator",
        "artifact_denominator_sha256",
        "artifacts",
        "upstream_outcomes",
        "envelope_sha256",
    }
    if set(candidate) != expected_fields:
        return ["context-bound outcome envelope fields drifted"]
    unsigned = {
        key: value for key, value in candidate.items()
        if key != "envelope_sha256"
    }
    if (
        candidate.get("schema_version") != CONTEXT_BOUND_OUTCOME_SCHEMA
        or candidate.get("envelope_sha256")
        != hashlib.sha256(_canonical_json(unsigned)).hexdigest()
    ):
        issues.append("context-bound outcome envelope digest drifted")

    capability_id = str(candidate.get("capability_id") or "")
    tool = str(candidate.get("tool") or "")
    capability = candidate.get("governed_capability")
    if not isinstance(capability, Mapping):
        issues.append("governed capability is malformed")
    else:
        capability_digest = hashlib.sha256(
            _compact_canonical_json(dict(capability))
        ).hexdigest()
        if (
            candidate.get("governed_capability_sha256")
            != capability_digest
            or capability.get("capability_id") != capability_id
        ):
            issues.append("governed capability digest drifted")
        try:
            current = _governed_capability(
                capability_id,
                tool,
                registry_path=registry_path,
            )
            if dict(capability) != current:
                issues.append("governed capability control drifted")
        except ToolCoverageLedgerError as exc:
            issues.append(str(exc))

    provider = candidate.get("provider_authority")
    if not isinstance(provider, Mapping):
        issues.append("provider authority is malformed")
    else:
        provider_dict = dict(provider)
        provider_digest = str(
            provider_dict.get("authority_digest") or ""
        )
        unsigned_provider = {
            key: value for key, value in provider_dict.items()
            if key != "authority_digest"
        }
        if (
            provider_dict.get("tool_id") != tool
            or provider_dict.get(
                "deterministic_provider_authority"
            )
            is not True
            or candidate.get("provider_authority_sha256")
            != provider_digest
            or hashlib.sha256(
                _compact_canonical_json(unsigned_provider)
            ).hexdigest()
            != provider_digest
        ):
            issues.append("provider authority digest drifted")
        if (
            provider_dict.get("toolchain_version_lock_sha256")
            != candidate.get("toolchain_version_lock_sha256")
            or provider_dict.get("toolchain_governance_sha256")
            != candidate.get("toolchain_governance_sha256")
        ):
            issues.append("provider control digest binding drifted")
    try:
        controls = _toolchain_controls.load_toolchain_controls(
            registry_path or _DEFAULT_GOVERNANCE_PATH
        )
        if (
            controls.lock_sha256
            != candidate.get("toolchain_version_lock_sha256")
            or controls.governance_sha256
            != candidate.get("toolchain_governance_sha256")
        ):
            issues.append("toolchain control pair drifted")
    except Exception as exc:
        issues.append(
            "toolchain control pair is not replayable: "
            f"{type(exc).__name__}"
        )

    context = candidate.get("context")
    if (
        not isinstance(context, Mapping)
        or set(context) != _EXECUTION_CONTEXT_FIELDS
    ):
        issues.append("precise graph execution context drifted")
    else:
        if any(
            _SAFE_CONTEXT.fullmatch(str(context.get(key) or "")) is None
            for key in (
                "run_id",
                "phase",
                "ecosystem",
                "pipeline",
                "mode",
                "platform",
            )
        ):
            issues.append("precise graph execution context is invalid")
        if any(
            _HEX_SHA256.fullmatch(str(context.get(key) or "")) is None
            for key in ("snapshot_sha256", "project_root_sha256")
        ):
            issues.append("precise graph context digest is invalid")
        if isinstance(capability, Mapping):
            applicability = capability.get("applicability")
            actual = {
                "pipelines": str(context.get("pipeline") or ""),
                "ecosystems": str(context.get("ecosystem") or ""),
                "platforms": str(context.get("platform") or ""),
                "modes": str(context.get("mode") or ""),
                "phases": str(context.get("phase") or ""),
            }
            if (
                not isinstance(applicability, Mapping)
                or any(
                    not _applicability_matches(
                        applicability.get(field),
                        value,
                    )
                    for field, value in actual.items()
                )
            ):
                issues.append(
                    "execution context is outside governed capability "
                    "applicability"
                )
        if expected_context is not None:
            try:
                current_context = _normalized_execution_context(
                    expected_context
                )
            except ToolCoverageLedgerError as exc:
                issues.append(str(exc))
            else:
                if dict(context) != current_context:
                    issues.append(
                        "STALE_CONTEXT: precise graph outcome belongs to "
                        "another run, snapshot, project, or execution boundary"
                    )

    denominator = candidate.get("artifact_denominator")
    if denominator != list(PRECISE_GRAPH_ARTIFACTS):
        issues.append("precise graph artifact denominator drifted")
    if candidate.get("artifact_denominator_sha256") != hashlib.sha256(
        _compact_canonical_json(list(PRECISE_GRAPH_ARTIFACTS))
    ).hexdigest():
        issues.append("precise graph artifact denominator digest drifted")
    rows = candidate.get("artifacts")
    if not isinstance(rows, list) or len(rows) != len(
        PRECISE_GRAPH_ARTIFACTS
    ):
        issues.append("precise graph artifact evidence is incomplete")
    else:
        observed_names: list[str] = []
        for row in rows:
            if not isinstance(row, Mapping):
                issues.append("precise graph artifact evidence is malformed")
                continue
            relative = str(row.get("path") or "")
            observed_names.append(relative)
            try:
                normalized = _artifact_name(relative)
                path = Path(scratch) / normalized
                digest, size = _sha256_file(path)
            except (OSError, ToolCoverageLedgerError):
                issues.append(f"precise graph artifact is missing: {relative}")
                continue
            if (
                row.get("sha256") != digest
                or row.get("bytes") != size
                or size <= 0
            ):
                issues.append(f"precise graph artifact drifted: {relative}")
        if observed_names != list(PRECISE_GRAPH_ARTIFACTS):
            issues.append("precise graph artifact evidence reordered")
        issues.extend(
            replay_committed_graph_generation(
                scratch,
                artifact_rows=rows,
            )
        )

    upstream_rows = candidate.get("upstream_outcomes")
    if not isinstance(upstream_rows, list):
        issues.append("upstream graph outcome evidence is malformed")
    else:
        observed_upstream: list[tuple[str, str]] = []
        for row in upstream_rows:
            if not isinstance(row, Mapping) or set(row) != {
                "ledger_path",
                "capability_id",
                "ledger_sha256",
                "outcome_envelope_sha256",
            }:
                issues.append("upstream graph outcome evidence is malformed")
                continue
            relative = str(row.get("ledger_path") or "")
            upstream_capability = str(row.get("capability_id") or "")
            observed_upstream.append((relative, upstream_capability))
            if (
                not relative.startswith("_graph_providers/")
                or not relative.endswith(f"/{LEDGER_FILENAME}")
                or upstream_capability not in PRECISE_GRAPH_CAPABILITIES
            ):
                issues.append(
                    "upstream graph outcome evidence is outside mixed lanes"
                )
                continue
            try:
                normalized = _artifact_name(relative)
                ledger_path = Path(scratch) / normalized
                ledger_sha256, ledger_bytes = _sha256_file(ledger_path)
                lane_outcomes = load_tool_coverage_ledger(
                    ledger_path.parent
                )
                lane_outcome = lane_outcomes.get(upstream_capability)
                lane_envelope = (
                    json.loads(lane_outcome.provider_ref)
                    if lane_outcome is not None
                    and lane_outcome.state is ToolOutcomeState.SUCCEEDED
                    else {}
                )
            except (
                OSError,
                TypeError,
                json.JSONDecodeError,
                ToolCoverageLedgerError,
            ):
                issues.append(
                    "upstream graph outcome evidence is not replayable: "
                    f"{relative}"
                )
                continue
            if (
                ledger_bytes <= 0
                or row.get("ledger_sha256") != ledger_sha256
                or row.get("outcome_envelope_sha256")
                != lane_envelope.get("envelope_sha256")
            ):
                issues.append(
                    "upstream graph outcome evidence drifted: "
                    f"{relative}"
                )
            root_context = candidate.get("context")
            lane_context = lane_envelope.get("context")
            lane_ecosystem = Path(relative).parts[-2]
            shared_fields = (
                "run_id",
                "phase",
                "snapshot_sha256",
                "project_root_sha256",
                "pipeline",
                "mode",
                "platform",
            )
            if (
                not isinstance(root_context, Mapping)
                or root_context.get("ecosystem") != "mixed"
                or lane_ecosystem not in {"go", "rust"}
                or not isinstance(lane_context, Mapping)
                or lane_context.get("ecosystem") != lane_ecosystem
                or any(
                    lane_context.get(field) != root_context.get(field)
                    for field in shared_fields
                )
            ):
                issues.append(
                    "upstream graph outcome context drifted: "
                    f"{relative}"
                )
        if observed_upstream != sorted(set(observed_upstream)):
            issues.append("upstream graph outcome evidence reordered")
    return list(dict.fromkeys(issues))


def build_generic_success_outcome_envelope(
    scratch: Path,
    outcome: ToolOutcome,
    *,
    context: Mapping[str, Any],
    registry_path: Path | None = None,
) -> dict[str, Any]:
    """Bind a non-graph success to current context and exact artifact bytes."""

    if outcome.state is not ToolOutcomeState.SUCCEEDED:
        raise ToolCoverageLedgerError(
            "only a SUCCEEDED outcome can be context-bound"
        )
    if outcome.capability_id in PRECISE_GRAPH_CAPABILITIES:
        raise ToolCoverageLedgerError(
            "precise graph outcomes require provider-authority envelopes"
        )
    normalized_context = _normalized_execution_context(context)
    capability = _governed_capability(
        outcome.capability_id,
        outcome.tool,
        registry_path=registry_path,
    )
    applicability = capability.get("applicability")
    actual = {
        "pipelines": normalized_context["pipeline"],
        "ecosystems": normalized_context["ecosystem"],
        "platforms": normalized_context["platform"],
        "modes": normalized_context["mode"],
        "phases": normalized_context["phase"],
    }
    if (
        not isinstance(applicability, Mapping)
        or any(
            not _applicability_matches(
                applicability.get(field), value
            )
            for field, value in actual.items()
        )
    ):
        raise ToolCoverageLedgerError(
            "execution context is outside governed capability applicability"
        )
    artifact_names = tuple(
        _artifact_name(value) for value in outcome.artifacts
    )
    if not artifact_names:
        raise ToolCoverageLedgerError(
            "SUCCEEDED requires a non-empty artifact denominator"
        )
    artifact_rows: list[dict[str, Any]] = []
    for relative in artifact_names:
        try:
            digest, size = _sha256_file(Path(scratch) / relative)
        except OSError as exc:
            raise ToolCoverageLedgerError(
                f"success artifact is missing: {relative}"
            ) from exc
        if size <= 0:
            raise ToolCoverageLedgerError(
                f"success artifact is empty: {relative}"
            )
        artifact_rows.append(
            {"path": relative, "sha256": digest, "bytes": size}
        )
    controls = _toolchain_controls.load_toolchain_controls(
        registry_path or _DEFAULT_GOVERNANCE_PATH
    )
    capability_digest = hashlib.sha256(
        _compact_canonical_json(capability)
    ).hexdigest()
    unsigned = {
        "schema_version": GENERIC_SUCCESS_OUTCOME_SCHEMA,
        "context": normalized_context,
        "capability_id": outcome.capability_id,
        "governed_capability": capability,
        "governed_capability_sha256": capability_digest,
        "tool": outcome.tool,
        "finding_count": outcome.finding_count,
        "toolchain_version_lock_sha256": controls.lock_sha256,
        "toolchain_governance_sha256": controls.governance_sha256,
        "artifact_denominator": list(artifact_names),
        "artifact_denominator_sha256": hashlib.sha256(
            _compact_canonical_json(list(artifact_names))
        ).hexdigest(),
        "artifacts": artifact_rows,
        "source_provider_ref": outcome.provider_ref,
    }
    return {
        **unsigned,
        "envelope_sha256": hashlib.sha256(
            _canonical_json(unsigned)
        ).hexdigest(),
    }


def replay_generic_success_outcome_envelope(
    scratch: Path,
    envelope: Mapping[str, Any],
    *,
    expected_context: Mapping[str, Any] | None = None,
    registry_path: Path | None = None,
) -> list[str]:
    """Replay a non-graph success against controls, context, and artifacts."""

    if not isinstance(envelope, Mapping):
        return ["generic success outcome envelope is not an object"]
    candidate = dict(envelope)
    expected_fields = {
        "schema_version",
        "context",
        "capability_id",
        "governed_capability",
        "governed_capability_sha256",
        "tool",
        "finding_count",
        "toolchain_version_lock_sha256",
        "toolchain_governance_sha256",
        "artifact_denominator",
        "artifact_denominator_sha256",
        "artifacts",
        "source_provider_ref",
        "envelope_sha256",
    }
    if set(candidate) != expected_fields:
        return ["generic success outcome envelope fields drifted"]
    issues: list[str] = []
    unsigned = {
        key: value
        for key, value in candidate.items()
        if key != "envelope_sha256"
    }
    if (
        candidate.get("schema_version")
        != GENERIC_SUCCESS_OUTCOME_SCHEMA
        or candidate.get("envelope_sha256")
        != hashlib.sha256(_canonical_json(unsigned)).hexdigest()
    ):
        issues.append("generic success outcome envelope digest drifted")
    capability_id = str(candidate.get("capability_id") or "")
    tool = str(candidate.get("tool") or "")
    capability = candidate.get("governed_capability")
    if not isinstance(capability, Mapping):
        issues.append("governed capability is malformed")
    else:
        capability_dict = dict(capability)
        if (
            candidate.get("governed_capability_sha256")
            != hashlib.sha256(
                _compact_canonical_json(capability_dict)
            ).hexdigest()
            or capability_dict.get("capability_id") != capability_id
        ):
            issues.append("governed capability digest drifted")
        try:
            current = _governed_capability(
                capability_id,
                tool,
                registry_path=registry_path,
            )
            if capability_dict != current:
                issues.append("governed capability control drifted")
        except ToolCoverageLedgerError as exc:
            issues.append(str(exc))
    try:
        controls = _toolchain_controls.load_toolchain_controls(
            registry_path or _DEFAULT_GOVERNANCE_PATH
        )
        if (
            candidate.get("toolchain_version_lock_sha256")
            != controls.lock_sha256
            or candidate.get("toolchain_governance_sha256")
            != controls.governance_sha256
        ):
            issues.append("toolchain control pair drifted")
    except Exception as exc:
        issues.append(
            "toolchain control pair is not replayable: "
            f"{type(exc).__name__}"
        )
    context = candidate.get("context")
    if not isinstance(context, Mapping):
        issues.append("generic success execution context drifted")
    else:
        try:
            normalized_context = _normalized_execution_context(context)
        except ToolCoverageLedgerError as exc:
            issues.append(str(exc))
        else:
            if isinstance(capability, Mapping):
                applicability = capability.get("applicability")
                actual = {
                    "pipelines": normalized_context["pipeline"],
                    "ecosystems": normalized_context["ecosystem"],
                    "platforms": normalized_context["platform"],
                    "modes": normalized_context["mode"],
                    "phases": normalized_context["phase"],
                }
                if (
                    not isinstance(applicability, Mapping)
                    or any(
                        not _applicability_matches(
                            applicability.get(field), value
                        )
                        for field, value in actual.items()
                    )
                ):
                    issues.append(
                        "execution context is outside governed capability "
                        "applicability"
                    )
            if expected_context is not None:
                try:
                    current_context = _normalized_execution_context(
                        expected_context
                    )
                except ToolCoverageLedgerError as exc:
                    issues.append(str(exc))
                else:
                    if normalized_context != current_context:
                        issues.append(
                            "STALE_CONTEXT: tool outcome belongs to another "
                            "run, snapshot, project, or execution boundary"
                        )
    denominator = candidate.get("artifact_denominator")
    if (
        not isinstance(denominator, list)
        or not denominator
        or not all(isinstance(value, str) for value in denominator)
    ):
        issues.append("success artifact denominator is incomplete")
        artifact_names: list[str] = []
    else:
        try:
            artifact_names = [
                _artifact_name(value) for value in denominator
            ]
        except ToolCoverageLedgerError as exc:
            issues.append(str(exc))
            artifact_names = []
    if candidate.get("artifact_denominator_sha256") != hashlib.sha256(
        _compact_canonical_json(artifact_names)
    ).hexdigest():
        issues.append("success artifact denominator digest drifted")
    rows = candidate.get("artifacts")
    if not isinstance(rows, list) or len(rows) != len(artifact_names):
        issues.append("success artifact evidence is incomplete")
    else:
        observed_names: list[str] = []
        for row in rows:
            if not isinstance(row, Mapping):
                issues.append("success artifact evidence is malformed")
                continue
            relative = str(row.get("path") or "")
            observed_names.append(relative)
            try:
                normalized = _artifact_name(relative)
                digest, size = _sha256_file(Path(scratch) / normalized)
            except (OSError, ToolCoverageLedgerError):
                issues.append(
                    f"ARTIFACT_REPLAY: success artifact is missing: {relative}"
                )
                continue
            if (
                row.get("sha256") != digest
                or row.get("bytes") != size
                or size <= 0
            ):
                issues.append(
                    f"ARTIFACT_REPLAY: success artifact drifted: {relative}"
                )
        if observed_names != artifact_names:
            issues.append("success artifact evidence reordered")
    return list(dict.fromkeys(issues))


def bind_succeeded_tool_outcome(
    scratch: Path,
    outcome: ToolOutcome,
    *,
    context: Mapping[str, Any],
    registry_path: Path | None = None,
) -> ToolOutcome:
    """Return a SUCCEEDED outcome carrying replayable non-graph authority."""

    envelope = build_generic_success_outcome_envelope(
        scratch,
        outcome,
        context=context,
        registry_path=registry_path,
    )
    return ToolOutcome.succeeded(
        outcome.capability_id,
        outcome.tool,
        int(outcome.finding_count or 0),
        artifacts=outcome.artifacts,
        provider_ref=json.dumps(
            envelope,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ),
    )


def _success_outcome_replay_issues(
    scratch: Path,
    outcome: ToolOutcome,
    *,
    expected_context: Mapping[str, Any] | None = None,
    registry_path: Path | None = None,
) -> list[str]:
    if outcome.state is not ToolOutcomeState.SUCCEEDED:
        return []
    try:
        envelope = json.loads(outcome.provider_ref)
    except (TypeError, json.JSONDecodeError):
        return [
            "LEGACY_UNBOUND_SUCCESS: SUCCEEDED outcome lacks a "
            "context-bound envelope"
        ]
    expected_schema = (
        CONTEXT_BOUND_OUTCOME_SCHEMA
        if outcome.capability_id in PRECISE_GRAPH_CAPABILITIES
        else GENERIC_SUCCESS_OUTCOME_SCHEMA
    )
    if not isinstance(envelope, Mapping):
        return [
            "LEGACY_UNBOUND_SUCCESS: SUCCEEDED provider reference is "
            "not a context-bound envelope"
        ]
    observed_schema = str(envelope.get("schema_version") or "")
    if observed_schema != expected_schema:
        if observed_schema in {
            "",
            "plamen.advisory_source.v1",
        }:
            return [
                "LEGACY_UNBOUND_SUCCESS: SUCCEEDED provider reference "
                "predates the context-bound envelope"
            ]
        return [
            "SUCCESS_ENVELOPE_SCHEMA_DRIFT: expected "
            f"{expected_schema}, got {observed_schema or '<missing>'}"
        ]
    if outcome.capability_id in PRECISE_GRAPH_CAPABILITIES:
        issues = replay_context_bound_tool_outcome_envelope(
            scratch,
            envelope,
            expected_context=expected_context,
            registry_path=registry_path,
        )
        if outcome.artifacts != PRECISE_GRAPH_ARTIFACTS:
            issues.append(
                "precise graph ledger artifact denominator drifted"
            )
        return list(dict.fromkeys(issues))
    issues = replay_generic_success_outcome_envelope(
        scratch,
        envelope,
        expected_context=expected_context,
        registry_path=registry_path,
    )
    if isinstance(envelope, Mapping):
        denominator = envelope.get("artifact_denominator")
        if list(outcome.artifacts) != denominator:
            issues.append("ledger artifact denominator drifted")
        if envelope.get("finding_count") != outcome.finding_count:
            issues.append("ledger finding count drifted")
        if envelope.get("capability_id") != outcome.capability_id:
            issues.append("ledger capability id drifted")
        if envelope.get("tool") != outcome.tool:
            issues.append("ledger tool id drifted")
    return list(dict.fromkeys(issues))


def _load_tool_coverage_ledger_records(
    scratch: Path,
) -> dict[str, ToolOutcome]:
    path = Path(scratch) / LEDGER_FILENAME
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ToolCoverageLedgerError(
            f"{LEDGER_FILENAME} is not valid JSON: {type(exc).__name__}"
        ) from exc
    if not isinstance(raw, dict) or set(raw) != {
        "schema",
        "schema_version",
        "capabilities",
        "ledger_sha256",
    }:
        raise ToolCoverageLedgerError("ledger fields do not match the v1 schema")
    if (
        raw["schema"] != LEDGER_SCHEMA
        or raw["schema_version"] != LEDGER_SCHEMA_VERSION
        or not isinstance(raw["capabilities"], dict)
    ):
        raise ToolCoverageLedgerError("unsupported tool coverage ledger schema")
    supplied_digest = raw.get("ledger_sha256")
    unsigned = {
        key: value for key, value in raw.items() if key != "ledger_sha256"
    }
    expected_digest = hashlib.sha256(_canonical_json(unsigned)).hexdigest()
    if supplied_digest != expected_digest:
        raise ToolCoverageLedgerError("tool coverage ledger digest mismatch")
    outcomes: dict[str, ToolOutcome] = {}
    for key, value in raw["capabilities"].items():
        if not isinstance(key, str) or not isinstance(value, dict):
            raise ToolCoverageLedgerError("invalid capability ledger entry")
        outcome = ToolOutcome.from_record(value)
        if outcome.capability_id != key:
            raise ToolCoverageLedgerError(
                f"capability key/id mismatch for {key!r}"
            )
        outcomes[key] = outcome
    return outcomes


def load_tool_coverage_ledger(
    scratch: Path,
    *,
    expected_context: Mapping[str, Any] | None = None,
    registry_path: Path | None = None,
) -> dict[str, ToolOutcome]:
    """Load a ledger only when every success replays against current bytes."""

    outcomes = _load_tool_coverage_ledger_records(scratch)
    for outcome in outcomes.values():
        issues = _success_outcome_replay_issues(
            Path(scratch),
            outcome,
            expected_context=expected_context,
            registry_path=registry_path,
        )
        if issues:
            raise ToolCoverageLedgerError(
                f"{outcome.capability_id} outcome envelope does not replay: "
                + "; ".join(issues)
            )
    return outcomes


def capability_success_replays(
    scratch: Path,
    capability_id: str,
    *,
    expected_context: Mapping[str, Any],
    registry_path: Path | None = None,
) -> bool:
    """Return whether one capability has a current, artifact-valid success."""

    try:
        outcome = _load_tool_coverage_ledger_records(scratch).get(
            capability_id
        )
        return (
            outcome is not None
            and outcome.state is ToolOutcomeState.SUCCEEDED
            and not _success_outcome_replay_issues(
                Path(scratch),
                outcome,
                expected_context=expected_context,
                registry_path=registry_path,
            )
        )
    except (OSError, ToolCoverageLedgerError, ValueError):
        return False


def _render_markdown(
    outcomes: Mapping[str, ToolOutcome],
    ledger_sha256: str,
) -> str:
    lines = [
        "# Tool Coverage Ledger",
        "",
        (
            "> Machine authority: `tool_coverage_ledger.json` "
            f"(SHA-256 `{ledger_sha256}`)."
        ),
        "> `FAILED`, `UNAVAILABLE`, and `SKIPPED` are coverage debt, never clean scans.",
        "",
        "| Capability | Tool | State | Schema validated | Findings | Reason |",
        "|---|---|---|---:|---:|---|",
    ]
    for capability_id in sorted(outcomes):
        outcome = outcomes[capability_id]
        reason = outcome.reason.replace("|", "\\|").replace("\n", " ")
        findings = (
            str(outcome.finding_count)
            if outcome.finding_count is not None
            else "-"
        )
        lines.append(
            f"| `{capability_id}` | `{outcome.tool}` | {outcome.state.value} | "
            f"{str(outcome.schema_validated).lower()} | {findings} | {reason} |"
        )
    return "\n".join(lines) + "\n"


def record_tool_outcome(scratch: Path, outcome: ToolOutcome) -> None:
    """Atomically upsert one validated capability without erasing its peers."""
    root = Path(scratch)
    root.mkdir(parents=True, exist_ok=True)
    if outcome.state is ToolOutcomeState.SUCCEEDED:
        issues = _success_outcome_replay_issues(root, outcome)
        if issues:
            raise ToolCoverageLedgerError(
                "SUCCEEDED outcome envelope does not replay: "
                + "; ".join(issues)
            )
    # Existing successes may belong to an older context or have lost an
    # artifact.  Upserting typed repair debt must not be blocked by precisely
    # the stale row it is repairing.
    outcomes = _load_tool_coverage_ledger_records(root)
    outcomes[outcome.capability_id] = outcome

    payload = _empty_ledger()
    payload["capabilities"] = {
        key: outcomes[key].to_record() for key in sorted(outcomes)
    }
    payload["ledger_sha256"] = hashlib.sha256(
        _canonical_json(payload)
    ).hexdigest()
    encoded = json.dumps(
        payload, indent=2, sort_keys=True, ensure_ascii=False
    ) + "\n"

    json_path = root / LEDGER_FILENAME
    md_path = root / LEDGER_MARKDOWN_FILENAME
    token = f"{os.getpid()}.{outcome.capability_id.replace(':', '_')}"
    json_tmp = root / f".{LEDGER_FILENAME}.{token}.tmp"
    md_tmp = root / f".{LEDGER_MARKDOWN_FILENAME}.{token}.tmp"
    try:
        json_tmp.write_text(encoded, encoding="utf-8")
        md_tmp.write_text(
            _render_markdown(outcomes, payload["ledger_sha256"]),
            encoding="utf-8",
        )
        os.replace(json_tmp, json_path)
        os.replace(md_tmp, md_path)
    finally:
        for path in (json_tmp, md_tmp):
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass


def deliver_unresolved_tool_coverage_debt(
    scratch: Path,
    *,
    phase_name: str,
    expected_context: Mapping[str, Any] | None = None,
) -> tuple[str, ...]:
    """Publish lossless machine debt plus the final-report human projection."""

    root = Path(scratch)
    if _SAFE_CONTEXT.fullmatch(str(phase_name or "")) is None:
        raise ToolCoverageLedgerError("tool coverage debt phase is invalid")
    outcomes = load_tool_coverage_ledger(
        root,
        expected_context=expected_context,
    )
    rows = [
        {
            "capability_id": outcome.capability_id,
            "tool": outcome.tool,
            "state": outcome.state.value,
            "reason": outcome.reason,
            "provider_ref_sha256": (
                hashlib.sha256(
                    outcome.provider_ref.encode("utf-8")
                ).hexdigest()
                if outcome.provider_ref
                else None
            ),
        }
        for outcome in (
            outcomes[key] for key in sorted(outcomes)
        )
        if outcome.state is not ToolOutcomeState.SUCCEEDED
    ]
    if not rows:
        for name in (
            TOOLCHAIN_COVERAGE_DEBT_FILENAME,
            TOOLCHAIN_COVERAGE_REPORT_FILENAME,
        ):
            try:
                (root / name).unlink(missing_ok=True)
            except OSError:
                pass
        return ()
    unsigned = {
        "schema_version": TOOLCHAIN_COVERAGE_DEBT_SCHEMA,
        "phase": str(phase_name),
        "unresolved_count": len(rows),
        "rows": rows,
    }
    payload = {
        **unsigned,
        "debt_sha256": hashlib.sha256(
            _canonical_json(unsigned)
        ).hexdigest(),
    }
    root.mkdir(parents=True, exist_ok=True)
    json_path = root / TOOLCHAIN_COVERAGE_DEBT_FILENAME
    report_path = root / TOOLCHAIN_COVERAGE_REPORT_FILENAME
    token = f"{os.getpid()}.toolchain-debt"
    json_tmp = root / f".{json_path.name}.{token}.tmp"
    report_tmp = root / f".{report_path.name}.{token}.tmp"
    report_lines = [
        "# Toolchain Coverage Requiring Human Review",
        "",
        (
            "These are unresolved mechanical-tool coverage obligations. "
            "They are not vulnerability findings and cannot support a clean "
            "negative conclusion for the affected capability."
        ),
        "",
        "| Capability | Tool | State | Limitation |",
        "|---|---|---|---|",
    ]
    for row in rows:
        reason = str(row["reason"]).replace("|", "\\|").replace("\n", " ")
        report_lines.append(
            f"| `{row['capability_id']}` | `{row['tool']}` | "
            f"{row['state']} | {reason} |"
        )
    try:
        json_tmp.write_text(
            json.dumps(
                payload,
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
            )
            + "\n",
            encoding="utf-8",
        )
        report_tmp.write_text(
            "\n".join(report_lines) + "\n",
            encoding="utf-8",
        )
        os.replace(json_tmp, json_path)
        os.replace(report_tmp, report_path)
    finally:
        for path in (json_tmp, report_tmp):
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
    return tuple(row["capability_id"] for row in rows)


def _load_toolchain_governance_legacy(
    registry_path: Path | None = None,
) -> dict[str, Any]:
    """Load the machine denominator for applicable mechanical capabilities."""

    path = (
        Path(registry_path)
        if registry_path is not None
        else Path(__file__).resolve().parent.parent
        / "verification_policy"
        / TOOLCHAIN_GOVERNANCE_FILENAME
    )
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ToolCoverageLedgerError(
            f"toolchain governance is unreadable: {type(exc).__name__}"
        ) from exc
    if not isinstance(payload, dict):
        raise ToolCoverageLedgerError("toolchain governance root must be an object")
    if payload.get("schema_version") != TOOLCHAIN_GOVERNANCE_SCHEMA:
        raise ToolCoverageLedgerError("unsupported toolchain governance schema")
    reviewed_lock = payload.get("reviewed_version_lock")
    if (
        not isinstance(reviewed_lock, dict)
        or reviewed_lock.get("path")
        != f"verification_policy/{TOOLCHAIN_VERSION_LOCK_FILENAME}"
        or reviewed_lock.get("schema_version")
        != TOOLCHAIN_VERSION_LOCK_SCHEMA
        or re.fullmatch(
            r"[0-9a-f]{64}",
            str(reviewed_lock.get("sha256") or ""),
        )
        is None
    ):
        raise ToolCoverageLedgerError(
            "toolchain governance reviewed lock binding is invalid"
        )
    runtime_statuses = reviewed_lock.get("runtime_statuses")
    if (
        not isinstance(runtime_statuses, list)
        or len(runtime_statuses) != len(set(runtime_statuses))
        or set(runtime_statuses)
        != {
            "MATCH",
            "MISMATCH",
            "UNAVAILABLE",
            "EXTERNAL_MANAGER",
            "DEBT",
            "UNREGISTERED",
            "REVOKED",
        }
    ):
        raise ToolCoverageLedgerError(
            "toolchain governance runtime statuses are invalid"
        )
    lock_path = path.parent / TOOLCHAIN_VERSION_LOCK_FILENAME
    try:
        lock_raw = lock_path.read_bytes()
        lock_payload = json.loads(lock_raw)
    except Exception as exc:
        raise ToolCoverageLedgerError(
            f"toolchain version lock is unreadable: {type(exc).__name__}"
        ) from exc
    if hashlib.sha256(lock_raw).hexdigest() != reviewed_lock["sha256"]:
        raise ToolCoverageLedgerError(
            "toolchain version-lock digest does not match governance"
        )
    identities = (
        lock_payload.get("identities")
        if isinstance(lock_payload, dict)
        else None
    )
    if (
        not isinstance(lock_payload, dict)
        or lock_payload.get("schema_version")
        != TOOLCHAIN_VERSION_LOCK_SCHEMA
        or not isinstance(identities, list)
        or not identities
    ):
        raise ToolCoverageLedgerError(
            "toolchain version-lock schema is invalid"
        )
    locked_ids: list[str] = []
    for row in identities:
        if not isinstance(row, dict):
            raise ToolCoverageLedgerError(
                "toolchain version-lock identity is invalid"
            )
        identity_id = str(row.get("identity_id") or "")
        identity_kind = str(row.get("identity_kind") or "")
        package_name = str(row.get("package_name") or "")
        expected = str(row.get("expected_version") or "")
        install_spec = str(row.get("install_spec") or "")
        probe = row.get("version_probe")
        parser = str(row.get("version_output_parser") or "")
        if (
            not identity_id
            or re.fullmatch(r"\d+\.\d+\.\d+", expected) is None
            or not package_name
            or not isinstance(probe, list)
            or not probe
        ):
            raise ToolCoverageLedgerError(
                "toolchain version-lock identity is invalid"
            )
        if identity_kind == "python_distribution":
            valid_binding = (
                parser == "PYTHON_METADATA_EXACT"
                and bool(str(row.get("python_module") or ""))
                and install_spec == f"{package_name}=={expected}"
                and probe == ["python-importlib-metadata", package_name]
            )
            generated_text = str(
                row.get("generated_code_version") or ""
            )
            if generated_text:
                generated_match = re.fullmatch(
                    r"(\d+)\.(\d+)\.(\d+)", generated_text
                )
                runtime_match = re.fullmatch(
                    r"(\d+)\.(\d+)\.(\d+)", expected
                )
                generated = (
                    tuple(map(int, generated_match.groups()))
                    if generated_match
                    else ()
                )
                runtime = (
                    tuple(map(int, runtime_match.groups()))
                    if runtime_match
                    else ()
                )
                valid_binding = valid_binding and bool(
                    generated
                    and runtime
                    and generated[0] == runtime[0]
                    and generated <= runtime
                    and (
                        identity_id != "protobuf"
                        or row.get("generated_module_path")
                        == "plamen_l1/scip_pb2.py"
                    )
                )
            if identity_id == "protobuf" and not generated_text:
                valid_binding = False
        elif identity_kind == "command":
            valid_binding = (
                parser == "SCIP_GO_EXACT_V1"
                and install_spec == f"{package_name}@v{expected}"
                and probe[0] == identity_id
            )
        else:
            valid_binding = False
        if identity_id == "scip-go":
            valid_binding = valid_binding and (
                row.get("go_command_path")
                == "github.com/scip-code/scip-go/cmd/scip-go"
                and row.get("go_module_path")
                == "github.com/scip-code/scip-go"
                and package_name == row.get("go_command_path")
            )
        if not valid_binding:
            raise ToolCoverageLedgerError(
                "toolchain version-lock identity/install binding is invalid"
            )
        locked_ids.append(identity_id)
    if (
        len(locked_ids) != len(identities)
        or any(not identity_id for identity_id in locked_ids)
        or len(set(locked_ids)) != len(locked_ids)
    ):
        raise ToolCoverageLedgerError(
            "toolchain version-lock identities are invalid"
        )
    for field in ("capabilities", "tools", "advisory_sources"):
        if not isinstance(payload.get(field), list) or not payload[field]:
            raise ToolCoverageLedgerError(
                f"toolchain governance {field} must be a non-empty list"
            )
    seen: set[str] = set()
    for row in payload["capabilities"]:
        if not isinstance(row, dict):
            raise ToolCoverageLedgerError("capability governance row must be an object")
        capability_id = str(row.get("capability_id") or "")
        if not _CAPABILITY_ID_RE.fullmatch(capability_id):
            raise ToolCoverageLedgerError(
                f"invalid governed capability_id: {capability_id!r}"
            )
        if capability_id in seen:
            raise ToolCoverageLedgerError(
                f"duplicate governed capability_id: {capability_id}"
            )
        seen.add(capability_id)
        if row.get("necessity") not in {"REQUIRED", "CONDITIONAL", "OPTIONAL"}:
            raise ToolCoverageLedgerError(
                f"invalid necessity for governed capability: {capability_id}"
            )
        applicability = row.get("applicability")
        if not isinstance(applicability, dict):
            raise ToolCoverageLedgerError(
                f"missing applicability for governed capability: {capability_id}"
            )
        for field in ("pipelines", "ecosystems", "platforms", "modes", "phases"):
            values = applicability.get(field)
            if not isinstance(values, list) or not all(
                isinstance(value, str) and value.strip() for value in values
            ):
                raise ToolCoverageLedgerError(
                    f"invalid {field} applicability for {capability_id}"
                )
        if not isinstance(row.get("invocations"), list) or not row["invocations"]:
            raise ToolCoverageLedgerError(
                f"missing invocations for governed capability: {capability_id}"
            )
    tool_ids: set[str] = set()
    lock_references: dict[str, list[str]] = {}
    for row in payload["tools"]:
        if not isinstance(row, dict):
            raise ToolCoverageLedgerError("tool governance row must be an object")
        tool_id = str(row.get("tool_id") or "").strip()
        if not tool_id or tool_id in tool_ids:
            raise ToolCoverageLedgerError(
                f"invalid or duplicate governed tool_id: {tool_id!r}"
            )
        tool_ids.add(tool_id)
        for field in ("version_policy", "integrity_policy"):
            if not str(row.get(field) or "").strip():
                raise ToolCoverageLedgerError(
                    f"missing {field} for governed tool: {tool_id}"
                )
        update_policy = row.get("update_policy")
        if not isinstance(update_policy, dict) or not str(
            update_policy.get("state") or ""
        ).strip():
            raise ToolCoverageLedgerError(
                f"invalid update_policy for governed tool: {tool_id}"
            )
        runtime_authority = row.get("runtime_authority")
        if not isinstance(runtime_authority, dict):
            raise ToolCoverageLedgerError(
                f"invalid runtime authority for governed tool: {tool_id}"
            )
        state = str(update_policy["state"])
        acquisition_scope = str(
            update_policy.get("acquisition_scope") or ""
        )
        semantic_match = False
        if state == "EXACT_REVIEWED_RELEASE":
            reference = str(
                update_policy.get("version_lock_identity") or ""
            )
            semantic_match = (
                acquisition_scope == "SETUP_ONLY"
                and runtime_authority
                == {
                    "identity_status": "MATCH",
                    "deterministic_provider_authority": True,
                    "mismatch_effect": "FAIL_PROVIDER_SELECTION",
                }
                and bool(reference)
            )
            if reference:
                lock_references.setdefault(reference, []).append(tool_id)
        elif state == "GOVERNED_DEBT":
            semantic_match = (
                acquisition_scope == "SETUP_ONLY"
                and update_policy.get("unresolved_debt") is True
                and bool(str(update_policy.get("reason") or "").strip())
                and runtime_authority
                == {
                    "identity_status": "DEBT",
                    "deterministic_provider_authority": False,
                    "mismatch_effect": "CAPABILITY_DEBT_NO_CLEAN_AUTHORITY",
                }
            )
        elif state in {
            "EXTERNAL_TOOLCHAIN_MANAGER",
            "EXTERNAL_PLATFORM_MANAGER",
        }:
            semantic_match = (
                acquisition_scope == "EXTERNAL_OPERATOR_SETUP"
                and runtime_authority
                == {
                    "identity_status": "EXTERNAL_MANAGER",
                    "deterministic_provider_authority": False,
                    "mismatch_effect": "SNAPSHOT_OBSERVED_IDENTITY_ONLY",
                }
            )
        elif state == "HUMAN_REVIEWED_DIGEST_REQUIRED":
            semantic_match = (
                acquisition_scope == "EXTERNAL_OPERATOR_SETUP"
                and runtime_authority
                == {
                    "identity_status": "DEBT",
                    "deterministic_provider_authority": False,
                    "mismatch_effect": "FAIL_WITHOUT_REVIEWED_DIGEST",
                }
            )
        if not semantic_match:
            raise ToolCoverageLedgerError(
                f"toolchain governance semantics are invalid: {tool_id}"
            )
        revocation = row.get("revocation_policy")
        if not isinstance(revocation, dict) or set(revocation) != {
            "blocked_version_substrings",
            "blocked_executable_sha256",
        }:
            raise ToolCoverageLedgerError(
                f"invalid revocation_policy for governed tool: {tool_id}"
            )
        blocked_versions = revocation["blocked_version_substrings"]
        if not isinstance(blocked_versions, list) or any(
            not isinstance(value, str)
            or not value.strip()
            or len(value) > 128
            for value in blocked_versions
        ):
            raise ToolCoverageLedgerError(
                f"invalid blocked version token for governed tool: {tool_id}"
            )
        blocked_hashes = revocation["blocked_executable_sha256"]
        if not isinstance(blocked_hashes, list) or any(
            not isinstance(value, str)
            or not re.fullmatch(r"[0-9a-fA-F]{64}", value)
            for value in blocked_hashes
        ):
            raise ToolCoverageLedgerError(
                f"invalid blocked executable digest for governed tool: {tool_id}"
            )
    for identity_id in locked_ids:
        if lock_references.get(identity_id) != [identity_id]:
            raise ToolCoverageLedgerError(
                "each version-lock identity must have exactly one matching "
                f"governance row: {identity_id}"
            )
    if set(lock_references) != set(locked_ids):
        raise ToolCoverageLedgerError(
            "toolchain governance references an unknown version-lock identity"
        )
    for row in payload["capabilities"]:
        for invocation in row["invocations"]:
            if not isinstance(invocation, dict):
                raise ToolCoverageLedgerError(
                    "governed invocation must be an object"
                )
            invoked = invocation.get("tool_ids")
            if (
                not isinstance(invoked, list)
                or not invoked
                or any(str(tool_id) not in tool_ids for tool_id in invoked)
            ):
                raise ToolCoverageLedgerError(
                    f"unknown tool in invocation for {row['capability_id']}"
                )
            if not str(invocation.get("argv_contract") or "").strip():
                raise ToolCoverageLedgerError(
                    f"missing argv contract for {row['capability_id']}"
                )
    advisory_ids: set[str] = set()
    for row in payload["advisory_sources"]:
        if not isinstance(row, dict):
            raise ToolCoverageLedgerError(
                "advisory-source governance row must be an object"
            )
        source_id = str(row.get("source_id") or "").strip()
        if not source_id or source_id in advisory_ids:
            raise ToolCoverageLedgerError(
                f"invalid or duplicate advisory source: {source_id!r}"
            )
        advisory_ids.add(source_id)
        for field in ("provider", "offline_policy", "unavailable_policy"):
            if not str(row.get(field) or "").strip():
                raise ToolCoverageLedgerError(
                    f"missing {field} for advisory source: {source_id}"
                )
        if not isinstance(row.get("freshness_policy"), dict):
            raise ToolCoverageLedgerError(
                f"missing freshness policy for advisory source: {source_id}"
            )
    return payload


def _validate_governance_denominator_sections(
    payload: Mapping[str, Any],
    governed_tool_ids: set[str],
) -> None:
    """Validate non-identity governance after the shared control-pair load."""

    for field in ("capabilities", "advisory_sources"):
        if not isinstance(payload.get(field), list) or not payload[field]:
            raise ToolCoverageLedgerError(
                f"toolchain governance {field} must be a non-empty list"
            )
    seen_capabilities: set[str] = set()
    for row in payload["capabilities"]:
        if not isinstance(row, dict):
            raise ToolCoverageLedgerError(
                "capability governance row must be an object"
            )
        capability_id = str(row.get("capability_id") or "")
        if (
            not _CAPABILITY_ID_RE.fullmatch(capability_id)
            or capability_id in seen_capabilities
        ):
            raise ToolCoverageLedgerError(
                f"invalid or duplicate governed capability_id: "
                f"{capability_id!r}"
            )
        seen_capabilities.add(capability_id)
        if row.get("necessity") not in {
            "REQUIRED",
            "CONDITIONAL",
            "OPTIONAL",
        }:
            raise ToolCoverageLedgerError(
                f"invalid necessity for governed capability: "
                f"{capability_id}"
            )
        applicability = row.get("applicability")
        if not isinstance(applicability, dict):
            raise ToolCoverageLedgerError(
                f"missing applicability for governed capability: "
                f"{capability_id}"
            )
        for field in (
            "pipelines",
            "ecosystems",
            "platforms",
            "modes",
            "phases",
        ):
            values = applicability.get(field)
            if not isinstance(values, list) or not all(
                isinstance(value, str) and value.strip()
                for value in values
            ):
                raise ToolCoverageLedgerError(
                    f"invalid {field} applicability for {capability_id}"
                )
        invocations = row.get("invocations")
        if not isinstance(invocations, list) or not invocations:
            raise ToolCoverageLedgerError(
                f"missing invocations for governed capability: "
                f"{capability_id}"
            )
        for invocation in invocations:
            if not isinstance(invocation, dict):
                raise ToolCoverageLedgerError(
                    "governed invocation must be an object"
                )
            invoked = invocation.get("tool_ids")
            if (
                not isinstance(invoked, list)
                or not invoked
                or any(
                    not isinstance(tool_id, str)
                    or tool_id not in governed_tool_ids
                    for tool_id in invoked
                )
                or not str(invocation.get("argv_contract") or "").strip()
            ):
                raise ToolCoverageLedgerError(
                    f"invalid invocation for {capability_id}"
                )

    expected_freshness = {
        "osv-offline": {
            "claim_scope": "blocking-signal-only",
            "clean_zero_authority": False,
        },
        "npm-offline-cache": {
            "claim_scope": "blocking-signal-only",
            "clean_zero_authority": False,
        },
        "rustsec-local": {
            "max_age_seconds": 604800,
            "future_clock_skew_seconds": 300,
        },
        "govulndb-local": {
            "max_age_seconds": 604800,
            "future_clock_skew_seconds": 300,
        },
    }
    seen_sources: set[str] = set()
    for row in payload["advisory_sources"]:
        if not isinstance(row, dict):
            raise ToolCoverageLedgerError(
                "advisory-source governance row must be an object"
            )
        source_id = str(row.get("source_id") or "").strip()
        expected = expected_freshness.get(source_id)
        if (
            expected is None
            or source_id in seen_sources
            or any(
                not str(row.get(field) or "").strip()
                for field in (
                    "provider",
                    "offline_policy",
                    "unavailable_policy",
                )
            )
        ):
            raise ToolCoverageLedgerError(
                f"invalid or duplicate advisory source: {source_id!r}"
            )
        freshness = row.get("freshness_policy")
        if not isinstance(freshness, dict) or freshness != expected:
            raise ToolCoverageLedgerError(
                f"invalid freshness policy for advisory source: "
                f"{source_id}"
            )
        # JSON booleans are integers in Python.  Exact type checks prevent
        # True, False, strings, negative/zero, or unreviewed huge values from
        # silently becoming temporal authority.
        for field in ("max_age_seconds", "future_clock_skew_seconds"):
            if field in expected and type(freshness.get(field)) is not int:
                raise ToolCoverageLedgerError(
                    f"invalid freshness bound for advisory source: "
                    f"{source_id}"
                )
        if "clean_zero_authority" in expected and type(
            freshness.get("clean_zero_authority")
        ) is not bool:
            raise ToolCoverageLedgerError(
                f"invalid freshness authority for advisory source: "
                f"{source_id}"
            )
        seen_sources.add(source_id)
    if seen_sources != set(expected_freshness):
        raise ToolCoverageLedgerError(
            "toolchain advisory freshness denominator is incomplete"
        )


def load_toolchain_governance(
    registry_path: Path | None = None,
) -> dict[str, Any]:
    """Load one single-read, content-bound governance/version-lock pair."""

    path = (
        Path(registry_path)
        if registry_path is not None
        else Path(__file__).resolve().parent.parent
        / "verification_policy"
        / TOOLCHAIN_GOVERNANCE_FILENAME
    )
    try:
        controls = _toolchain_controls.load_toolchain_controls(path)
    except _toolchain_controls.ToolchainControlError as exc:
        raise ToolCoverageLedgerError(str(exc)) from exc
    payload = dict(controls.governance)
    _validate_governance_denominator_sections(
        payload,
        set(controls.governed),
    )
    return payload


def tool_identity_policy_issues(
    tool_id: str,
    fingerprint: bytes | str,
    *,
    registry_path: Path | None = None,
) -> list[str]:
    """Evaluate a captured runtime identity against explicit revocations."""

    payload = load_toolchain_governance(registry_path)
    row = next(
        (
            item
            for item in payload["tools"]
            if item.get("tool_id") == tool_id
        ),
        None,
    )
    if row is None:
        return []
    try:
        identity = json.loads(
            fingerprint.decode("utf-8")
            if isinstance(fingerprint, bytes)
            else fingerprint
        )
    except Exception as exc:
        return [f"runtime identity is malformed: {type(exc).__name__}"]
    if not isinstance(identity, dict):
        return ["runtime identity root is not an object"]
    policy = row["revocation_policy"]
    version = str(identity.get("version") or "")
    digest = str(identity.get("executable_sha256") or "").casefold()
    issues: list[str] = []
    for token in policy["blocked_version_substrings"]:
        if token.casefold() in version.casefold():
            issues.append(f"version matches revoked token {token!r}")
    if digest and digest in {
        value.casefold()
        for value in policy["blocked_executable_sha256"]
    }:
        issues.append(f"executable digest is revoked: {digest}")
    return issues


def _governance_platform(value: str) -> str:
    normalized = str(value or "").strip().casefold()
    if normalized.startswith(("win", "cygwin", "msys")):
        return "windows"
    if normalized in {"darwin", "mac", "macos"}:
        return "macos"
    if normalized.startswith("linux"):
        return "linux"
    return normalized


def _applicability_matches(values: Any, actual: str) -> bool:
    normalized = {
        str(value).strip().casefold()
        for value in (values or [])
        if str(value).strip()
    }
    return "*" in normalized or actual.casefold() in normalized


def applicable_tool_capabilities(
    *,
    pipeline: str,
    ecosystem: str,
    platform_name: str,
    mode: str,
    phase: str,
    registry_path: Path | None = None,
) -> list[dict[str, Any]]:
    """Return the exact applicable capability denominator for one boundary."""

    payload = load_toolchain_governance(registry_path)
    actual = {
        "pipelines": str(pipeline or "").strip().casefold(),
        "ecosystems": str(ecosystem or "").strip().casefold(),
        "platforms": _governance_platform(platform_name),
        "modes": str(mode or "").strip().casefold(),
        "phases": str(phase or "").strip().casefold(),
    }
    rows: list[dict[str, Any]] = []
    for row in payload["capabilities"]:
        applicability = row["applicability"]
        if all(
            _applicability_matches(applicability[field], actual[field])
            for field in actual
        ):
            rows.append(dict(row))
    return sorted(rows, key=lambda row: row["capability_id"])


def reconcile_expected_tool_capabilities(
    scratch: Path,
    *,
    pipeline: str,
    ecosystem: str,
    platform_name: str,
    mode: str,
    phase: str,
    execution_context: Mapping[str, Any] | None = None,
    registry_path: Path | None = None,
) -> list[str]:
    """Materialize debt for applicable capabilities that emitted no outcome.

    This is denominator reconciliation, not execution. Existing outcomes are
    preserved byte-for-byte; only absent applicable rows are added.
    """

    expected = applicable_tool_capabilities(
        pipeline=pipeline,
        ecosystem=ecosystem,
        platform_name=platform_name,
        mode=mode,
        phase=phase,
        registry_path=registry_path,
    )
    current_context: dict[str, str] | None = None
    if execution_context is not None:
        current_context = _normalized_execution_context(
            execution_context
        )
        expected_boundary = {
            "pipeline": str(pipeline or "").strip().casefold(),
            "ecosystem": str(ecosystem or "").strip().casefold(),
            "platform": _governance_platform(platform_name),
            "mode": str(mode or "").strip().casefold(),
            "phase": str(phase or "").strip().casefold(),
        }
        for key, value in expected_boundary.items():
            if current_context[key].casefold() != value:
                raise ToolCoverageLedgerError(
                    "tool reconciliation execution context does not match "
                    f"the {key} boundary"
                )
    present = _load_tool_coverage_ledger_records(scratch)
    added: list[str] = []
    # Revalidate every success, not only graph providers and not only rows in
    # the current applicability denominator.  A prior-run success is coverage
    # debt until the capability executes in this exact run and snapshot.
    for capability_id in sorted(present):
        outcome = present[capability_id]
        issues = _success_outcome_replay_issues(
            Path(scratch),
            outcome,
            expected_context=current_context,
            registry_path=registry_path,
        )
        if not issues:
            continue
        issue_text = "; ".join(issues)
        category = (
            "STALE_CONTEXT"
            if any("STALE_CONTEXT" in issue for issue in issues)
            else "ARTIFACT_REPLAY"
            if any(
                "ARTIFACT" in issue.upper() for issue in issues
            )
            else "SUCCESS_REPLAY"
        )
        replacement = ToolOutcome.debt(
            capability_id,
            outcome.tool,
            ToolOutcomeState.FAILED,
            f"{category}: {issue_text}",
            provider_ref=(
                "invalid-success-envelope-sha256:"
                + hashlib.sha256(
                    outcome.provider_ref.encode("utf-8")
                ).hexdigest()
            ),
        )
        record_tool_outcome(scratch, replacement)
        present[capability_id] = replacement
        added.append(capability_id)
    for row in expected:
        capability_id = str(row["capability_id"])
        if capability_id in present:
            continue
        necessity = str(row["necessity"])
        state = (
            ToolOutcomeState.SKIPPED
            if necessity == "OPTIONAL"
            else ToolOutcomeState.UNAVAILABLE
        )
        outcome = ToolOutcome.debt(
            capability_id,
            "/".join(
                sorted(
                    {
                        str(tool_id)
                        for invocation in row["invocations"]
                        if isinstance(invocation, Mapping)
                        for tool_id in invocation.get("tool_ids", [])
                    }
                )
            )
            or "governed-capability",
            state,
            (
                f"applicable {necessity.lower()} capability emitted no outcome "
                f"before {phase} reconciliation"
            ),
            provider_ref=f"governance:{TOOLCHAIN_GOVERNANCE_SCHEMA}",
        )
        record_tool_outcome(scratch, outcome)
        present[capability_id] = outcome
        added.append(capability_id)
    return list(dict.fromkeys(added))
