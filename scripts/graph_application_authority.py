"""Typed graph availability, application, and outcome reconciliation.

The historical graph-consumption gate searched model prose for four filenames.
That made an absent graph, absent depth output, or a bare filename mention a
vacuous success.  This module is the pure authority boundary that replaces
that convention.  Pure builders return deterministic payloads, while the only
production-authoritative loaders replay exact files through PhaseIO and the
ArtifactLedger before issuing committed tokens.  Structural byte decoders are
explicitly TEST_ONLY and cannot issue those tokens.

Three canonical artifacts form the ABI:

* ``graph_application_authority.v1.json`` freezes graph nodes, edges, routed
  leads, the workspace/snapshot/generation lineage, and each required
  consumer's complete availability denominator.
* ``graph_application_observations.v1.json`` records structured claims about
  what a consumer referenced or applied.  Claims bind exact evidence bytes.
* ``graph_application_reconciliation.v1.json`` independently compares every
  required consumer/element pair and emits typed debt for every omission.

Only a debt-free READY authority with exact observations can reconcile to
COMPLETE.  Empty graphs and empty consumer rosters are representable for
diagnostics but are always DEGRADED; they never pass vacuously.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import threading
from typing import Any, Mapping, Sequence
import weakref

from portable_path_contract import assert_lexically_bounded_relative_path

from artifact_ledger import (
    ArtifactLedgerError,
    active_committed_work_unit_authority_issues,
    read_artifact_ledger,
    validate_work_unit_artifacts,
    validate_work_unit_inputs,
)
from evm_analysis_workspace_authority import (
    EVMAnalysisWorkspaceAuthorityError,
    WORKSPACE_SCHEMA,
    validate_evm_analysis_workspace_receipt,
    workspace_public_reference,
)
from phase_io_contracts import (
    InputAuthorityRequirement,
    LaunchSpec,
    PhaseIOContract,
    replay_phase_io_authority_pair,
)
import rooted_path_io


AUTHORITY_ARTIFACT = "graph_application_authority.v1.json"
CONSUMER_ROSTER_ARTIFACT = "graph_application_consumer_roster.v1.json"
OBSERVATIONS_ARTIFACT = "graph_application_observations.v1.json"
RECONCILIATION_ARTIFACT = "graph_application_reconciliation.v1.json"
SCHEDULE_ARTIFACT = "graph_application_schedule.v1.json"

AUTHORITY_SCHEMA = "plamen.graph_application_authority.v1"
CONSUMER_ROSTER_SCHEMA = "plamen.graph_application_consumer_roster.v1"
OBSERVATIONS_SCHEMA = "plamen.graph_application_observations.v1"
RECONCILIATION_SCHEMA = "plamen.graph_application_reconciliation.v1"
SCHEDULE_SCHEMA = "plamen.graph_application_schedule.v1"

# This typed machinery is staged but no production consumer cutover exists.
# Mere presence of the active mechanical graph or shadow controls is not
# consumer-activation authority.
GRAPH_APPLICATION_CONSUMER_ACTIVATION = False

AUTHORITY_STATES = frozenset({"READY", "DEGRADED"})
DISPOSITIONS = frozenset({"APPLIED", "REFERENCED", "NOT_APPLIED"})
MINIMUM_DISPOSITIONS = frozenset({"APPLIED", "REFERENCED"})
RECONCILIATION_STATES = frozenset({"COMPLETE", "DEGRADED", "FAILED"})
ELEMENT_KINDS = frozenset({"NODE", "EDGE", "LEAD"})

_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_RUN_ID = re.compile(r"^[A-Za-z0-9._:/+-]{1,512}$", re.ASCII)
_CONSUMER_ID = re.compile(r"^[a-z0-9][a-z0-9._/-]{0,127}$", re.ASCII)
_ROLE_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$", re.ASCII)
_ELEMENT_ID = re.compile(r"^G[ NEL]-[0-9a-f]{24}$".replace(" ", ""), re.ASCII)
_FINDING_ID = re.compile(r"^INV-[0-9]{1,9}$", re.ASCII)
_LOCUS = re.compile(r"^L[0-9]{1,10}(?:-L?[0-9]{1,10})?$", re.ASCII)
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")

_MAX_SOURCE_BYTES = 64 * 1024 * 1024
_MAX_CONTROL_BYTES = 16 * 1024 * 1024
_MAX_ELEMENTS = 50_000
_MAX_CONSUMERS = 128
_MAX_ASSIGNMENT_PAIRS = 200_000
_MAX_ARTIFACT_BYTES = 32 * 1024 * 1024
_MAX_TEXT = 2_048
_MAX_EVIDENCE_ARTIFACTS_PER_CONSUMER = 256
_MAX_EVIDENCE_BINDINGS = 4_096
_MAX_EVIDENCE_ROWS_PER_OUTCOME = 256
_MAX_EVIDENCE_LOCI_PER_ROW = 1_024
_MAX_OBSERVATION_EVIDENCE_ROWS = _MAX_ASSIGNMENT_PAIRS
_MAX_OBSERVATION_EVIDENCE_LOCI = _MAX_ASSIGNMENT_PAIRS * 2
_GRAPH_ARTIFACT = "scratchpad:_mechanical_graph.json"
_GRAPH_GENERATION_ARTIFACT = "scratchpad:_mechanical_graph_generation.json"
_HANDOFF_ARTIFACT = "scratchpad:depth_handoff_receipt.json"
_DEPTH_CANDIDATES_ARTIFACT = "scratchpad:depth_candidates.md"
_WORKSPACE_ARTIFACT = "scratchpad:evm_analysis_workspace_receipt.v1.json"
_CONSUMER_ROSTER_IDENTITY = f"scratchpad:{CONSUMER_ROSTER_ARTIFACT}"
_SCHEDULE_IDENTITY = f"scratchpad:{SCHEDULE_ARTIFACT}"
_HANDOFF_GRAPH_VIEWS = (
    "caller_map.md",
    "callee_map.md",
    "state_write_map.md",
    "function_summary.md",
)
_PRECISE_GRAPH_DENOMINATOR = (
    "caller_map.md",
    "callee_map.md",
    "state_write_map.md",
    "function_summary.md",
    "_mechanical_graph.json",
)
_ROUTE_SECTIONS = frozenset({"Token Flow", "State Trace", "Edge Case", "External"})
_ALLOWED_DEBT_CODES = frozenset({
    "CONSUMER_DECLINED",
    "CONSUMER_OUTPUT_UNAVAILABLE",
    "EVIDENCE_UNAVAILABLE",
    "ELEMENT_NOT_RELEVANT",
    "INSUFFICIENT_CONTEXT",
    "PROVIDER_FACT_UNCERTAIN",
    "TOOLCHAIN_UNAVAILABLE",
})


class GraphApplicationAuthorityError(ValueError):
    """Graph application authority is malformed, stale, or conflicting."""


@dataclass(frozen=True)
class _CommittedReplayContext:
    scratchpad: Path
    project_root: Path
    contract: PhaseIOContract
    launch: LaunchSpec
    run_id: str
    artifact_identity: str
    schema_version: str
    phase: str
    work_unit_id: str
    limit: int
    fixed_input_producers: tuple[
        tuple[str, tuple[str, str, str, str]], ...
    ]
    fixed_inputs_exact: bool

    @property
    def digest(self) -> str:
        return _digest({
            "scratchpad": os.path.abspath(os.fspath(self.scratchpad)),
            "project_root": os.path.abspath(os.fspath(self.project_root)),
            "contract_digest": self.contract.digest,
            "launch_digest": self.launch.digest,
            "run_id": self.run_id,
            "artifact_identity": self.artifact_identity,
            "schema_version": self.schema_version,
            "phase": self.phase,
            "work_unit_id": self.work_unit_id,
            "limit": self.limit,
            "fixed_input_producers": [
                [identity, list(producer)]
                for identity, producer in self.fixed_input_producers
            ],
            "fixed_inputs_exact": self.fixed_inputs_exact,
        })


def _committed_token_boundary():
    """Return closure-held issuers/verifiers for loader-authenticated tokens.

    The former module-global sentinel was a public mint credential: importing
    this module was sufficient to fabricate every committed token.  The new
    boundary records exact object identity outside token fields and MACs the
    canonical issuance payload with process-local entropy.  Its mint function
    is removed from module scope after the production loaders close over it.
    """

    secret = os.urandom(32)
    lock = threading.RLock()
    issued: dict[int, tuple[weakref.ReferenceType[object], str, str]] = {}

    def payload(value: object) -> dict[str, Any]:
        return {
            "artifact_sha256": getattr(value, "artifact_sha256", None),
            "canonical_bytes_sha256": _raw_digest(
                getattr(value, "canonical_bytes", b"")
            ),
            "contract_digest": getattr(value, "contract_digest", None),
            "launch_digest": getattr(value, "launch_digest", None),
            "commit_context_sha256": (
                getattr(value, "_commit_context", None).digest
                if type(getattr(value, "_commit_context", None))
                is _CommittedReplayContext
                else None
            ),
        }

    def issue(cls: type[object], *, kind: str, **fields: Any) -> object:
        value = object.__new__(cls)
        for name, field_value in fields.items():
            object.__setattr__(value, name, field_value)
        body = canonical_file_bytes({"kind": kind, "payload": payload(value)})
        tag = hmac.new(secret, body, hashlib.sha256).hexdigest()
        object.__setattr__(value, "_authority_tag", tag)
        key = id(value)

        def cleanup(reference: weakref.ReferenceType[object]) -> None:
            with lock:
                current = issued.get(key)
                if current is not None and current[0] is reference:
                    issued.pop(key, None)

        reference = weakref.ref(value, cleanup)
        with lock:
            issued[key] = (reference, kind, tag)
        return value

    def require(value: object, *, cls: type[object], kind: str) -> None:
        if type(value) is not cls:
            _fail(f"{kind} requires its exact committed token type")
        body = canonical_file_bytes({"kind": kind, "payload": payload(value)})
        expected = hmac.new(secret, body, hashlib.sha256).hexdigest()
        with lock:
            authority = issued.get(id(value))
        if (
            authority is None
            or authority[0]() is not value
            or authority[1] != kind
            or not hmac.compare_digest(authority[2], expected)
            or not hmac.compare_digest(
                str(getattr(value, "_authority_tag", "")), expected
            )
        ):
            _fail(f"{kind} token was not issued by committed loader replay")

    return issue, require


_issue_committed_token, _require_committed_token = _committed_token_boundary()
del _committed_token_boundary


@dataclass(frozen=True, init=False)
class CommittedGraphConsumerRoster:
    """ArtifactLedger-authenticated required-consumer denominator."""

    payload: Mapping[str, Any]
    canonical_bytes: bytes
    artifact_sha256: str
    contract_digest: str
    launch_digest: str

    def __init__(self, **_fields: Any) -> None:
        _fail("committed consumer-roster tokens are loader-issued only")


@dataclass(frozen=True, init=False)
class CommittedGraphApplicationAuthority:
    payload: Mapping[str, Any]
    canonical_bytes: bytes
    artifact_sha256: str
    contract_digest: str
    launch_digest: str

    def __init__(self, **_fields: Any) -> None:
        _fail("committed graph-authority tokens are loader-issued only")


@dataclass(frozen=True, init=False)
class CommittedGraphApplicationObservations:
    payload: Mapping[str, Any]
    canonical_bytes: bytes
    artifact_sha256: str
    contract_digest: str
    launch_digest: str

    def __init__(self, **_fields: Any) -> None:
        _fail("committed graph-observations tokens are loader-issued only")


@dataclass(frozen=True, init=False)
class CommittedGraphApplicationReconciliation:
    payload: Mapping[str, Any]
    canonical_bytes: bytes
    artifact_sha256: str
    contract_digest: str
    launch_digest: str

    def __init__(self, **_fields: Any) -> None:
        _fail("committed graph-reconciliation tokens are loader-issued only")


def _fail(message: str, exc: BaseException | None = None) -> None:
    if exc is None:
        raise GraphApplicationAuthorityError(message)
    raise GraphApplicationAuthorityError(message) from exc


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_file_bytes(value: object) -> bytes:
    """Return the sole accepted on-disk representation for ABI artifacts."""

    return _canonical_json(value) + b"\n"


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _raw_digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _bounded_bytes(raw: bytes, *, label: str, limit: int) -> bytes:
    if not isinstance(raw, bytes) or not raw or len(raw) > limit:
        _fail(f"{label} is empty, non-bytes, or exceeds {limit} bytes")
    return raw


def _reject_constant(token: str) -> None:
    _fail(f"JSON contains non-finite number: {token}")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"JSON object contains duplicate key: {key}")
        result[key] = value
    return result


def _strict_json(raw: bytes, *, label: str, limit: int) -> dict[str, Any]:
    raw = _bounded_bytes(raw, label=label, limit=limit)
    try:
        value = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=_pairs,
            parse_constant=_reject_constant,
        )
    except GraphApplicationAuthorityError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        _fail(f"{label} is not strict JSON", exc)
    if not isinstance(value, dict):
        _fail(f"{label} root is not an object")
    return value


def _canonical_artifact(raw: bytes, *, label: str) -> dict[str, Any]:
    value = _strict_json(raw, label=label, limit=_MAX_CONTROL_BYTES)
    if canonical_file_bytes(value) != raw:
        _fail(f"{label} is not canonical ABI JSON")
    return value


def _text(value: object, *, label: str, maximum: int = _MAX_TEXT) -> str:
    if not isinstance(value, str):
        _fail(f"{label} is not a string")
    if not value or len(value.encode("utf-8")) > maximum or _CONTROL.search(value):
        _fail(f"{label} is empty, contains controls, or exceeds its bound")
    return value


def _hex(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _HEX64.fullmatch(value) is None:
        _fail(f"{label} is not a lowercase SHA-256 digest")
    return value


def _safe_relative(value: str, *, label: str) -> str:
    value = _text(value, label=label, maximum=512).replace("\\", "/")
    try:
        assert_lexically_bounded_relative_path(
            value, label=label, max_path_bytes=512
        )
    except ValueError:
        _fail(f"{label} is not a safe relative path")
    if (
        value.startswith("/")
        or re.match(r"^[A-Za-z]:", value)
        or any(part in {"", ".", ".."} for part in value.split("/"))
        or value.endswith("/")
    ):
        _fail(f"{label} is not a safe relative path")
    return value


def _artifact_identity(value: object, *, label: str) -> str:
    text = _text(value, label=label, maximum=640)
    if not text.startswith("scratchpad:"):
        _fail(f"{label} is not scratchpad-rooted")
    _safe_relative(text.split(":", 1)[1], label=label)
    return text


def _source_locus(value: object, *, label: str) -> str:
    text = _text(value, label=label, maximum=1_024)
    # Provider descriptors may use ``function (path:L12)``.  We reject only
    # path escape/absolute spellings while preserving the provider's identity.
    pathish = text
    if " (" in text and text.endswith(")"):
        pathish = text.rsplit(" (", 1)[1][:-1]
    pathish = re.sub(r":L?[0-9]+(?:-L?[0-9]+)?$", "", pathish)
    if "/" in pathish or "\\" in pathish or re.match(r"^[A-Za-z]:", pathish):
        _safe_relative(pathish, label=label)
    return text


def _strict_string_list(value: object, *, label: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        _fail(f"{label} is not an array")
    if len(value) > _MAX_ELEMENTS:
        _fail(f"{label} denominator exceeds bound")
    result = tuple(_text(item, label=f"{label}[]", maximum=1_024) for item in value)
    if len(result) != len(set(result)):
        _fail(f"{label} contains duplicate entries")
    return result


def _element(prefix: str, unsigned: Mapping[str, Any]) -> dict[str, Any]:
    row = dict(unsigned)
    return {"element_id": f"G{prefix}-{_digest(row)[:24]}", **row}


def _descriptor_identity(value: str) -> str:
    return value.rsplit(" (", 1)[0].strip()


def _parse_graph(raw: bytes) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    graph = _strict_json(raw, label="mechanical graph", limit=_MAX_SOURCE_BYTES)
    functions = graph.get("functions")
    states = graph.get("state_symbols")
    if (
        not isinstance(graph.get("schema_version"), str)
        or not isinstance(graph.get("source"), str)
        or not isinstance(functions, dict)
        or not isinstance(states, list)
    ):
        _fail("mechanical graph schema is incomplete")
    if len(functions) + len(states) > _MAX_ELEMENTS:
        _fail("mechanical graph node denominator exceeds bound")

    nodes_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    function_nodes: dict[str, str] = {}
    bare_functions: dict[str, list[str]] = {}

    def add_node(node_kind: str, identity: str, locus: str = "") -> str:
        identity = _text(identity, label="graph node identity", maximum=1_024)
        if locus:
            locus = _source_locus(locus, label="graph node locus")
        key = (node_kind, identity)
        unsigned = {
            "kind": "NODE",
            "node_kind": node_kind,
            "identity": identity,
            "locus": locus,
        }
        row = _element("N", unsigned)
        prior = nodes_by_key.get(key)
        if prior is not None and prior != row:
            _fail(f"conflicting graph node: {node_kind}:{identity}")
        if prior is None and len(nodes_by_key) >= _MAX_ELEMENTS:
            _fail("mechanical graph node denominator exceeds bound")
        nodes_by_key[key] = row
        return row["element_id"]

    for identity, raw_row in functions.items():
        identity = _text(identity, label="function identity", maximum=1_024)
        if not isinstance(raw_row, Mapping):
            _fail(f"function row is not an object: {identity}")
        locus = str(raw_row.get("loc") or "")
        node_id = add_node("FUNCTION", identity, locus)
        function_nodes[identity] = node_id
        bare = str(raw_row.get("bare") or identity.rsplit(".", 1)[-1]).strip()
        if bare:
            bare_functions.setdefault(bare, []).append(identity)

    state_nodes: dict[str, str] = {}
    normalized_states: list[tuple[str, Mapping[str, Any]]] = []
    for raw_row in states:
        if not isinstance(raw_row, Mapping):
            _fail("state-symbol row is not an object")
        identity = str(raw_row.get("symbol_id") or raw_row.get("qualified_name") or "")
        identity = _text(identity, label="state identity", maximum=1_024)
        if identity in state_nodes:
            _fail(f"duplicate state identity: {identity}")
        locus = str(raw_row.get("declaration_locus") or "")
        state_nodes[identity] = add_node("STATE", identity, locus)
        normalized_states.append((identity, raw_row))

    def endpoint(descriptor: str) -> str:
        descriptor = _source_locus(descriptor, label="graph endpoint descriptor")
        identity = _descriptor_identity(descriptor)
        if identity in function_nodes:
            return function_nodes[identity]
        matches = bare_functions.get(identity, [])
        if len(matches) == 1:
            return function_nodes[matches[0]]
        # An unresolved/ambiguous descriptor is itself the reference identity.
        # Reusing only its bare name would incorrectly conflict when two
        # contracts expose the same function at different loci.
        return add_node("REFERENCE", descriptor, "")

    edge_sources: dict[tuple[str, str, str], set[str]] = {}

    def add_edge(
        edge_kind: str, source: str, target: str, evidence_side: str
    ) -> None:
        key = (edge_kind, source, target)
        if key not in edge_sources:
            if len(nodes_by_key) + len(edge_sources) >= _MAX_ELEMENTS:
                _fail("mechanical graph element denominator exceeds bound")
            edge_sources[key] = set()
        edge_sources[key].add(evidence_side)
    for identity, raw_row in functions.items():
        callers = _strict_string_list(raw_row.get("callers", []), label=f"{identity}.callers")
        callees = _strict_string_list(raw_row.get("callees", []), label=f"{identity}.callees")
        source_id = function_nodes[identity]
        for descriptor in callees:
            add_edge("CALL", source_id, endpoint(descriptor), "CALLEE_LIST")
        for descriptor in callers:
            add_edge("CALL", endpoint(descriptor), source_id, "CALLER_LIST")

    for state_identity, raw_row in normalized_states:
        state_id = state_nodes[state_identity]
        for descriptor in _strict_string_list(raw_row.get("read_sites", []), label=f"{state_identity}.read_sites"):
            add_edge("STATE_READ", state_id, endpoint(descriptor), "STATE_SYMBOL")
        for descriptor in _strict_string_list(raw_row.get("write_sites", []), label=f"{state_identity}.write_sites"):
            add_edge("STATE_WRITE", endpoint(descriptor), state_id, "STATE_SYMBOL")

    edges = [
        _element("E", {
            "kind": "EDGE",
            "edge_kind": edge_kind,
            "source_element_id": source,
            "target_element_id": target,
            "evidence_sides": sorted(sides),
        })
        for (edge_kind, source, target), sides in edge_sources.items()
    ]
    elements = [*nodes_by_key.values(), *edges]
    if len(elements) > _MAX_ELEMENTS:
        _fail("mechanical graph element denominator exceeds bound")
    return graph, elements


def _split_markdown_row(line: str) -> list[str]:
    if not line.startswith("|") or not line.rstrip().endswith("|"):
        return []
    cells: list[str] = []
    current: list[str] = []
    escaped = False
    for character in line.strip()[1:-1]:
        if escaped:
            current.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == "|":
            cells.append("".join(current).strip())
            current = []
        else:
            current.append(character)
    if escaped:
        current.append("\\")
    cells.append("".join(current).strip())
    return cells


def _parse_leads(raw: bytes, *, expected_count: int) -> list[dict[str, Any]]:
    raw = _bounded_bytes(raw, label="depth candidates", limit=_MAX_CONTROL_BYTES)
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeError as exc:
        _fail("depth candidates is not UTF-8", exc)
    route = ""
    leads: dict[str, dict[str, Any]] = {}
    for line in text.splitlines():
        if line.startswith("## "):
            heading = line[3:].strip()
            route = heading if heading in _ROUTE_SECTIONS else ""
            continue
        if not route:
            continue
        cells = _split_markdown_row(line)
        if len(cells) != 5 or _FINDING_ID.fullmatch(cells[0]) is None:
            continue
        finding_id, severity, verdict, locus, title = cells
        unsigned = {
            "kind": "LEAD",
            "finding_id": finding_id,
            "route": route,
            "severity": _text(severity, label="lead severity", maximum=64),
            "verdict": _text(verdict, label="lead verdict", maximum=64),
            "locus": _source_locus(locus, label="lead locus"),
            "title": _text(title, label="lead title", maximum=1_024),
        }
        row = _element("L", unsigned)
        if finding_id in leads:
            _fail(f"duplicate/conflicting routed lead: {finding_id}")
        leads[finding_id] = row
    if len(leads) != expected_count:
        _fail(
            "routed lead denominator differs from handoff finding_count: "
            f"{len(leads)} != {expected_count}"
        )
    return list(leads.values())


def _validate_handoff(
    raw: bytes,
    *,
    graph_raw: bytes,
    candidates_raw: bytes,
    function_count: int,
    state_count: int,
) -> dict[str, Any]:
    value = _strict_json(raw, label="depth handoff receipt", limit=_MAX_CONTROL_BYTES)
    # depth_handoff.py owns a stable pretty/sorted canonical representation.
    expected_bytes = (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    if raw != expected_bytes:
        _fail("depth handoff receipt is not producer-canonical JSON")
    sources = value.get("source_sha256")
    outputs = value.get("output_sha256")
    if (
        set(value) != {
            "schema_version", "source_sha256", "finding_count",
            "function_count", "state_symbol_count", "uncovered_files",
            "output_sha256",
        }
        or
        value.get("schema_version") != "plamen.depth_handoff_receipt.v1"
        or not isinstance(sources, Mapping)
        or not isinstance(outputs, Mapping)
        or value.get("function_count") != function_count
        or value.get("state_symbol_count") != state_count
        or isinstance(value.get("finding_count"), bool)
        or not isinstance(value.get("finding_count"), int)
        or not 0 <= value["finding_count"] <= _MAX_ELEMENTS
    ):
        _fail("depth handoff receipt schema/count authority is malformed")
    uncovered = value.get("uncovered_files")
    if (
        not isinstance(uncovered, list)
        or len(uncovered) > _MAX_ELEMENTS
        or len(uncovered) != len(set(uncovered))
    ):
        _fail("depth handoff uncovered-file denominator is malformed")
    for path in uncovered:
        _safe_relative(path, label="depth handoff uncovered file")
    if sources.get("_mechanical_graph.json") != _raw_digest(graph_raw):
        _fail("depth handoff receipt binds another mechanical graph")
    if outputs.get("depth_candidates.md") != _raw_digest(candidates_raw):
        _fail("depth handoff receipt binds another depth-candidate projection")
    required_outputs = {
        "depth_candidates.md", "file_coverage.md", "state_dependency_map.md",
        "phase4_gates.md", *_HANDOFF_GRAPH_VIEWS,
    }
    if set(outputs) != required_outputs:
        _fail("depth handoff receipt graph/depth projection roster differs")
    required_sources = {
        "_mechanical_graph.json", "findings_inventory.md",
        "contract_inventory.md", "spawn_manifest.md",
    }
    source_names = set(sources)
    if (
        not required_sources.issubset(source_names)
        or not any(re.fullmatch(r"analysis_[A-Za-z0-9_.-]+\.md", name) for name in source_names)
        or any(
            name not in required_sources
            and re.fullmatch(r"analysis_[A-Za-z0-9_.-]+\.md", name) is None
            for name in source_names
        )
    ):
        _fail("depth handoff source denominator differs")
    for roster_name, roster in (("source", sources), ("output", outputs)):
        seen: set[str] = set()
        for path, digest in roster.items():
            path = _safe_relative(path, label=f"handoff {roster_name} path")
            if path in seen:
                _fail(f"depth handoff {roster_name} roster contains duplicate path")
            seen.add(path)
            _hex(digest, label=f"handoff digest for {path}")
    return value


def _validate_generation_manifest(
    raw: bytes | None,
    *,
    graph_raw: bytes,
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    if raw is None:
        return ({
            "state": "ABSENT",
            "artifact_identity": _GRAPH_GENERATION_ARTIFACT,
            "artifact_sha256": None,
            "provider_generation_sha256": None,
        }, [{
            "code": "GRAPH_GENERATION_MANIFEST_ABSENT",
            "subject": _GRAPH_GENERATION_ARTIFACT,
            "reason": "the exact provider-generation manifest was not available",
        }])
    value = _strict_json(raw, label="graph generation manifest", limit=_MAX_CONTROL_BYTES)
    producer_canonical = (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    if raw != producer_canonical:
        _fail("graph generation manifest is not producer-canonical JSON")
    unsigned = dict(value)
    stored = unsigned.pop("generation_sha256", None)
    artifacts = value.get("artifacts")
    denominator = value.get("artifact_denominator")
    if (
        value.get("schema_version") != "plamen.mechanical_graph_generation.v1"
        or value.get("state") != "COMMITTED"
        or not isinstance(artifacts, list)
        or not isinstance(denominator, list)
        or len(artifacts) != len(denominator)
        or denominator != list(_PRECISE_GRAPH_DENOMINATOR)
        or _HEX64.fullmatch(str(stored or "")) is None
        or _raw_digest(canonical_file_bytes(unsigned)) != stored
    ):
        _fail("graph generation manifest integrity failure")
    paths: list[str] = []
    graph_matches = 0
    for row in artifacts:
        if not isinstance(row, Mapping) or set(row) != {"path", "sha256", "bytes"}:
            _fail("graph generation artifact row is malformed")
        path = _safe_relative(row["path"], label="graph generation path")
        _hex(row["sha256"], label=f"graph generation digest for {path}")
        size = row["bytes"]
        if isinstance(size, bool) or not isinstance(size, int) or not 0 < size <= _MAX_SOURCE_BYTES:
            _fail("graph generation artifact size is malformed")
        paths.append(path)
        if path == "_mechanical_graph.json":
            graph_matches += 1
            if row["sha256"] != _raw_digest(graph_raw) or size != len(graph_raw):
                _fail("graph generation manifest binds another mechanical graph")
    if (
        paths != denominator
        or paths != list(_PRECISE_GRAPH_DENOMINATOR)
        or len(paths) != len(set(paths))
        or graph_matches != 1
    ):
        _fail("graph generation denominator is not exact/unique")
    # The producer writes pretty JSON.  Integrity is semantic and its own
    # generation digest is authoritative, so retain the raw-byte digest too.
    return ({
        "state": "BOUND",
        "artifact_identity": _GRAPH_GENERATION_ARTIFACT,
        "artifact_sha256": _raw_digest(raw),
        "provider_generation_sha256": stored,
    }, [])


def _validate_workspace(
    raw: bytes,
    *,
    run_id: str,
    snapshot_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    value = _strict_json(raw, label="EVM workspace receipt", limit=_MAX_CONTROL_BYTES)
    if canonical_file_bytes(value) != raw:
        _fail("EVM workspace receipt is not canonical")
    try:
        validated = validate_evm_analysis_workspace_receipt(
            value,
            expected_run_id=run_id,
            expected_snapshot_sha256=snapshot_sha256,
        )
        reference = workspace_public_reference(validated)
    except EVMAnalysisWorkspaceAuthorityError as exc:
        _fail(f"EVM workspace receipt failed replay: {exc}", exc)
    if reference.get("artifact_identity") != _WORKSPACE_ARTIFACT:
        _fail("EVM workspace reference identity differs")
    return validated, reference


def _graph_provider_binding(
    workspace: Mapping[str, Any],
    graph_provider: str,
) -> dict[str, Any]:
    provider = str(graph_provider or "").strip().lower()
    if provider == "evm-source":
        return {
            "provider": provider,
            "authority_kind": "BUILTIN_SOURCE_PROVIDER",
            "tool_id": None,
            "admission_state": "SOURCE_BOUND",
            "tool_row_sha256": None,
        }
    tool_id = {"slither": "slither"}.get(provider)
    if tool_id is None:
        return {
            "provider": provider,
            "authority_kind": "UNDECLARED",
            "tool_id": None,
            "admission_state": "UNDECLARED",
            "tool_row_sha256": None,
        }
    rows = [
        row for row in workspace.get("tools", [])
        if isinstance(row, Mapping) and row.get("tool_id") == tool_id
    ]
    if len(rows) != 1:
        return {
            "provider": provider,
            "authority_kind": "WORKSPACE_TOOL",
            "tool_id": tool_id,
            "admission_state": "UNDECLARED",
            "tool_row_sha256": None,
        }
    row = rows[0]
    return {
        "provider": provider,
        "authority_kind": "WORKSPACE_TOOL",
        "tool_id": tool_id,
        "admission_state": row.get("admission_state"),
        "tool_row_sha256": row.get("tool_row_sha256"),
    }


def _derive_authority_debts(value: Mapping[str, Any]) -> list[dict[str, str]]:
    debts: list[dict[str, str]] = []
    workspace = value["workspace"]
    generation = value["graph_generation"]
    provider_manifest = generation["provider_manifest"]
    provider = generation["mechanical_graph"]["provider_authority"]
    if provider_manifest["state"] == "ABSENT":
        debts.append({
            "code": "GRAPH_GENERATION_MANIFEST_ABSENT",
            "subject": _GRAPH_GENERATION_ARTIFACT,
            "reason": "the exact provider-generation manifest was not available",
        })
    if workspace["state"] != "BOUND":
        debts.append({
            "code": "WORKSPACE_AUTHORITY_DEGRADED",
            "subject": _WORKSPACE_ARTIFACT,
            "reason": (
                f"workspace state is {workspace['state']}; all declared tool "
                "rows must be admitted before graph application can complete"
            ),
        })
    if provider["authority_kind"] == "UNDECLARED":
        debts.append({
            "code": "GRAPH_PROVIDER_UNDECLARED",
            "subject": str(provider["provider"] or "empty-provider"),
            "reason": "mechanical graph names no supported declared provider",
        })
    elif provider["admission_state"] not in {"ADMITTED", "SOURCE_BOUND"}:
        debts.append({
            "code": "GRAPH_PROVIDER_UNADMITTED",
            "subject": str(provider["tool_id"] or provider["provider"]),
            "reason": (
                f"declared graph provider admission state is "
                f"{provider['admission_state']}"
            ),
        })
    if not value["elements"]:
        debts.append({
            "code": "GRAPH_ELEMENT_DENOMINATOR_EMPTY",
            "subject": _GRAPH_ARTIFACT,
            "reason": "the mechanical graph and handoff contain no nodes, edges, or leads",
        })
    if not value["consumers"]:
        debts.append({
            "code": "REQUIRED_CONSUMER_ROSTER_EMPTY",
            "subject": "consumer-denominator",
            "reason": "the committed scheduler declared no downstream phase/agent",
        })
    for row in value["consumers"]:
        if not row["assigned_element_ids"]:
            debts.append({
                "code": "CONSUMER_ASSIGNMENT_EMPTY",
                "subject": row["consumer_id"],
                "reason": "the deterministic selector assigned no graph element",
            })
    unassigned = value["unassigned_element_ids"]
    if unassigned:
        debts.append({
            "code": "GRAPH_ELEMENTS_UNASSIGNED",
            "subject": _digest(unassigned),
            "reason": (
                f"{len(unassigned)} exact graph elements have no downstream "
                "consumer assignment; see unassigned_element_ids"
            ),
        })
    return sorted(debts, key=lambda row: (row["code"], row["subject"]))


def _assigned_ids_for_selector(
    elements: Sequence[Mapping[str, Any]],
    selector: Mapping[str, Any],
    *,
    pair_budget: int | None = None,
) -> list[str]:
    if set(selector) != {
        "graph_element_kinds", "graph_shard_index", "graph_shard_count",
        "lead_routes",
    }:
        _fail("graph assignment selector fields are malformed")
    raw_kinds = selector.get("graph_element_kinds")
    raw_routes = selector.get("lead_routes")
    shard_index = selector.get("graph_shard_index")
    shard_count = selector.get("graph_shard_count")
    if (
        not isinstance(raw_kinds, list)
        or raw_kinds != sorted(raw_kinds)
        or len(raw_kinds) != len(set(raw_kinds))
        or any(kind not in {"NODE", "EDGE"} for kind in raw_kinds)
        or not isinstance(raw_routes, list)
        or raw_routes != sorted(raw_routes)
        or len(raw_routes) != len(set(raw_routes))
        or any(route not in _ROUTE_SECTIONS for route in raw_routes)
        or isinstance(shard_index, bool)
        or not isinstance(shard_index, int)
        or isinstance(shard_count, bool)
        or not isinstance(shard_count, int)
        or not 1 <= shard_count <= _MAX_CONSUMERS
        or not 0 <= shard_index < shard_count
        or (not raw_kinds and (shard_index != 0 or shard_count != 1))
    ):
        _fail("graph assignment selector values are malformed")
    kinds = set(raw_kinds)
    lead_routes = set(raw_routes)
    result: list[str] = []
    for element in elements:
        selected = (
            element["kind"] in kinds
            and int(element["element_id"].rsplit("-", 1)[1], 16)
            % shard_count == shard_index
        ) or (
            element["kind"] == "LEAD"
            and element.get("route") in lead_routes
        )
        if not selected:
            continue
        # Enforce the product cap before appending, so a hostile selector can
        # never first materialize an over-limit Cartesian product.
        if pair_budget is not None and len(result) >= pair_budget:
            _fail(
                "graph application assignment product exceeds bounded pair "
                f"limit: more than {_MAX_ASSIGNMENT_PAIRS}"
            )
        result.append(element["element_id"])
    return sorted(result)


def _normalize_consumer_specs(
    raw: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    if isinstance(raw, (str, bytes)) or not isinstance(raw, Sequence):
        _fail("required consumers is not a sequence")
    if len(raw) > _MAX_CONSUMERS:
        _fail("required consumer denominator exceeds bound")
    allowed = {
        "consumer_id", "phase", "agent_id", "graph_element_kinds",
        "graph_shard_index", "graph_shard_count", "lead_routes",
        "minimum_disposition", "evidence_artifacts",
    }
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for candidate in raw:
        if not isinstance(candidate, Mapping) or set(candidate) != allowed:
            _fail("required-consumer row has unknown/missing fields")
        consumer_id = str(candidate.get("consumer_id") or "")
        phase = str(candidate.get("phase") or "")
        agent_id = str(candidate.get("agent_id") or "")
        if _CONSUMER_ID.fullmatch(consumer_id) is None or ".." in consumer_id.split("/"):
            _fail("consumer_id is malformed")
        if consumer_id in seen:
            _fail(f"duplicate consumer_id: {consumer_id}")
        seen.add(consumer_id)
        if _ROLE_TOKEN.fullmatch(phase) is None or _ROLE_TOKEN.fullmatch(agent_id) is None:
            _fail(f"consumer phase/agent is malformed: {consumer_id}")
        consumer_parts = consumer_id.split("/", 1)
        if (
            len(consumer_parts) != 2
            or consumer_parts[0] != phase
            or _ROLE_TOKEN.fullmatch(consumer_parts[1]) is None
        ):
            _fail(
                "consumer_id must bind its exact phase/work-unit identity: "
                + consumer_id
            )
        kinds = candidate.get("graph_element_kinds")
        routes = candidate.get("lead_routes")
        if (
            isinstance(kinds, list) and len(kinds) > len(ELEMENT_KINDS)
        ) or (
            isinstance(routes, list) and len(routes) > len(_ROUTE_SECTIONS)
        ):
            _fail("required-consumer selector denominator exceeds bound")
        shard_index = candidate.get("graph_shard_index")
        shard_count = candidate.get("graph_shard_count")
        selector = {
            "graph_element_kinds": sorted(kinds) if isinstance(kinds, list) else kinds,
            "graph_shard_index": shard_index,
            "graph_shard_count": shard_count,
            "lead_routes": sorted(routes) if isinstance(routes, list) else routes,
        }
        # Reuse the selector validator without needing any graph elements.
        _assigned_ids_for_selector((), selector)
        minimum = candidate.get("minimum_disposition")
        if minimum not in MINIMUM_DISPOSITIONS:
            _fail(f"consumer minimum disposition is malformed: {consumer_id}")
        evidence = candidate.get("evidence_artifacts")
        if (
            not isinstance(evidence, list)
            or not evidence
            or len(evidence) > _MAX_EVIDENCE_ARTIFACTS_PER_CONSUMER
        ):
            _fail(
                "consumer evidence-artifact roster is empty or exceeds bound: "
                + consumer_id
            )
        evidence = sorted(
            _artifact_identity(value, label=f"{consumer_id} evidence artifact")
            for value in evidence
        )
        if len(evidence) != len(set(evidence)):
            _fail(f"consumer evidence-artifact roster duplicates: {consumer_id}")
        rows.append({
            "consumer_id": consumer_id,
            "phase": phase,
            "agent_id": agent_id,
            **selector,
            "minimum_disposition": minimum,
            "evidence_artifacts": evidence,
        })
    rows.sort(key=lambda row: row["consumer_id"])
    return rows


def consumer_denominator_sha256_test_only(
    required_consumers: Sequence[Mapping[str, Any]],
) -> str:
    """TEST_ONLY helper; production expects this digest from scheduling authority."""

    return _digest(_normalize_consumer_specs(required_consumers))


def _consumer_requirements(
    raw: Sequence[Mapping[str, Any]],
    elements: Sequence[Mapping[str, Any]],
    *,
    full_availability_sha256: str,
) -> tuple[list[dict[str, Any]], list[dict[str, str]], list[str], int]:
    raw = _normalize_consumer_specs(raw)
    elements_by_id = {row["element_id"]: row for row in elements}
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    debts: list[dict[str, str]] = []
    pair_count = 0
    for candidate in raw:
        if not isinstance(candidate, Mapping):
            _fail("required-consumer row is not an object")
        allowed = {
            "consumer_id", "phase", "agent_id", "graph_element_kinds",
            "graph_shard_index", "graph_shard_count", "lead_routes",
            "minimum_disposition", "evidence_artifacts",
        }
        if set(candidate) != allowed:
            _fail("required-consumer row has unknown/missing fields")
        consumer_id = str(candidate.get("consumer_id") or "")
        phase = str(candidate.get("phase") or "")
        agent_id = str(candidate.get("agent_id") or "")
        if _CONSUMER_ID.fullmatch(consumer_id) is None or ".." in consumer_id.split("/"):
            _fail("consumer_id is malformed")
        if consumer_id in seen:
            _fail(f"duplicate consumer_id: {consumer_id}")
        seen.add(consumer_id)
        if _ROLE_TOKEN.fullmatch(phase) is None or _ROLE_TOKEN.fullmatch(agent_id) is None:
            _fail(f"consumer phase/agent is malformed: {consumer_id}")
        kinds = candidate.get("graph_element_kinds")
        if not isinstance(kinds, list) or len(kinds) != len(set(kinds)):
            _fail(f"consumer graph element kinds duplicate/malformed: {consumer_id}")
        if any(kind not in {"NODE", "EDGE"} for kind in kinds):
            _fail(f"consumer graph element kind is unsupported: {consumer_id}")
        kinds = sorted(kinds)
        shard_index = candidate.get("graph_shard_index")
        shard_count = candidate.get("graph_shard_count")
        if (
            isinstance(shard_index, bool)
            or not isinstance(shard_index, int)
            or isinstance(shard_count, bool)
            or not isinstance(shard_count, int)
            or not 1 <= shard_count <= _MAX_CONSUMERS
            or not 0 <= shard_index < shard_count
            or (not kinds and (shard_index != 0 or shard_count != 1))
        ):
            _fail(f"consumer graph shard selector is malformed: {consumer_id}")
        lead_routes = candidate.get("lead_routes")
        if (
            not isinstance(lead_routes, list)
            or len(lead_routes) != len(set(lead_routes))
            or any(route not in _ROUTE_SECTIONS for route in lead_routes)
        ):
            _fail(f"consumer lead-route selector is malformed: {consumer_id}")
        lead_routes = sorted(lead_routes)
        minimum = candidate.get("minimum_disposition")
        if minimum not in MINIMUM_DISPOSITIONS:
            _fail(f"consumer minimum disposition is malformed: {consumer_id}")
        evidence = candidate.get("evidence_artifacts")
        if (
            not isinstance(evidence, list)
            or not evidence
            or len(evidence) > _MAX_EVIDENCE_ARTIFACTS_PER_CONSUMER
        ):
            _fail(
                "consumer evidence-artifact roster is empty or exceeds bound: "
                + consumer_id
            )
        evidence = [
            _artifact_identity(value, label=f"{consumer_id} evidence artifact")
            for value in evidence
        ]
        if len(evidence) != len(set(evidence)):
            _fail(f"consumer evidence-artifact roster duplicates: {consumer_id}")
        selector = {
            "graph_element_kinds": kinds,
            "graph_shard_index": shard_index,
            "graph_shard_count": shard_count,
            "lead_routes": lead_routes,
        }
        assigned = _assigned_ids_for_selector(
            elements,
            selector,
            pair_budget=_MAX_ASSIGNMENT_PAIRS - pair_count,
        )
        pair_count += len(assigned)
        unsigned = {
            "consumer_id": consumer_id,
            "phase": phase,
            "agent_id": agent_id,
            "minimum_disposition": minimum,
            "evidence_artifacts": sorted(evidence),
            "full_availability_sha256": full_availability_sha256,
            "assignment_selector": selector,
            "assigned_element_ids": assigned,
        }
        row = {**unsigned, "assignment_sha256": _digest(unsigned)}
        rows.append(row)
        if not assigned:
            debts.append({
                "code": "CONSUMER_ASSIGNMENT_EMPTY",
                "subject": consumer_id,
                "reason": "the deterministic selector assigned no graph element",
            })
    if not rows:
        debts.append({
            "code": "REQUIRED_CONSUMER_ROSTER_EMPTY",
            "subject": "consumer-denominator",
            "reason": "no downstream phase/agent was declared",
        })
    rows.sort(key=lambda row: row["consumer_id"])
    assigned_ids = {
        element_id
        for row in rows
        for element_id in row["assigned_element_ids"]
    }
    unassigned = sorted(set(elements_by_id) - assigned_ids)
    if unassigned:
        debts.append({
            "code": "GRAPH_ELEMENTS_UNASSIGNED",
            "subject": _digest(unassigned),
            "reason": (
                f"{len(unassigned)} exact graph elements have no downstream "
                "consumer assignment; see unassigned_element_ids"
            ),
        })
    if pair_count != sum(len(row["assigned_element_ids"]) for row in rows):
        _fail("graph application assignment pair counter diverged")
    if pair_count > _MAX_ASSIGNMENT_PAIRS:
        _fail(
            "graph application assignment product exceeds bounded pair limit: "
            f"{pair_count} > {_MAX_ASSIGNMENT_PAIRS}"
        )
    return rows, debts, unassigned, pair_count


def _validate_driver_output_contract(
    contract: PhaseIOContract,
    launch: LaunchSpec,
    *,
    artifact_identity: str,
    schema_version: str,
    phase: str | None = None,
    work_unit_id: str | None = None,
) -> None:
    if type(contract) is not PhaseIOContract or type(launch) is not LaunchSpec:
        _fail("production artifact loader requires PhaseIOContract and LaunchSpec")
    try:
        replayed_contract, replayed_launch = replay_phase_io_authority_pair(
            contract, launch
        )
    except (TypeError, ValueError) as exc:
        _fail("production PhaseIO/launch object authority replay failed", exc)
    if (
        replayed_contract.to_dict() != contract.to_dict()
        or replayed_launch.to_dict() != launch.to_dict()
    ):
        _fail("production PhaseIO/launch authority replay changed")
    if launch.work_unit_key != contract.key:
        _fail("production artifact launch differs from its PhaseIO owner")
    if phase is not None and contract.phase != phase:
        _fail("production artifact PhaseIO phase differs")
    if work_unit_id is not None and contract.work_unit_id != work_unit_id:
        _fail("production artifact PhaseIO work unit differs")
    matches = [row for row in contract.outputs if row.identity == artifact_identity]
    if (
        len(matches) != 1
        or {row.identity for row in contract.outputs} != {artifact_identity}
        or matches[0].writer != "DRIVER"
        or matches[0].schema_version != schema_version
        or contract.required_commit_actor != "DRIVER"
        or contract.model_invoked is not False
        or contract.launch_profile != "DRIVER_PYTHON_NO_TOOLS"
        or launch.model != "driver"
        or launch.exec_mode != "python"
        or launch.tool_policy
    ):
        _fail("production artifact PhaseIO output authority differs")


def _producer_key(contract: PhaseIOContract, phase: str, work_unit: str) -> str:
    return "/".join((
        contract.pipeline,
        contract.mode,
        contract.ecosystem,
        contract.backend,
        phase,
        work_unit,
    ))


def _require_fixed_input_producers(
    contract: PhaseIOContract,
    expected: Mapping[str, tuple[str, str, str, str]],
    *,
    exact_denominator: bool = True,
) -> None:
    """Require exact committed producer tokens for every production input.

    Values are ``(phase, work_unit_id, writer, schema_version)``.  Digests are
    not accepted as top-level caller expectations: they live inside PhaseIO's
    exact producer requirement and are replayed against the committed ledger.
    """

    if exact_denominator:
        _require_exact_contract_inputs(contract, set(expected))
    requirements = {
        row.identity: row for row in contract.input_authority_requirements
    }
    if (
        (exact_denominator and set(requirements) != set(expected))
        or (not exact_denominator and not set(expected).issubset(requirements))
    ):
        _fail("production PhaseIO input producer-token denominator differs")
    for identity, row in requirements.items():
        if (
            type(row) is not InputAuthorityRequirement
            or row.allow_raw is not False
            or not row.expected_producer_work_unit_key
            or row.expected_writer not in {"DRIVER", "MODEL"}
            or row.require_same_run is not True
            or row.require_exact_contract is not True
            or row.require_exact_launch is not True
            or _HEX64.fullmatch(str(row.expected_contract_digest or "")) is None
            or _HEX64.fullmatch(str(row.expected_launch_digest or "")) is None
        ):
            _fail("production PhaseIO input lacks exact producer token: " + identity)
    for identity, (phase, work_unit, writer, _schema) in expected.items():
        row = requirements[identity]
        exact_key = _producer_key(contract, phase, work_unit)
        if (
            type(row) is not InputAuthorityRequirement
            or row.allow_raw is not False
            or row.expected_producer_work_unit_key != exact_key
            or row.expected_writer != writer
            or row.require_same_run is not True
            or row.require_exact_contract is not True
            or row.require_exact_launch is not True
            or _HEX64.fullmatch(str(row.expected_contract_digest or "")) is None
            or _HEX64.fullmatch(str(row.expected_launch_digest or "")) is None
        ):
            _fail(
                "production PhaseIO input producer token differs: " + identity
            )


def _validate_fixed_input_producers_in_ledger(
    ledger: Mapping[str, Any],
    contract: PhaseIOContract,
    *,
    run_id: str,
    expected: Mapping[str, tuple[str, str, str, str]],
) -> None:
    bindings = ledger.get("artifact_bindings")
    units = ledger.get("work_units")
    if not isinstance(bindings, Mapping) or not isinstance(units, Mapping):
        _fail("artifact ledger producer authority maps are absent")
    requirements = {
        row.identity: row for row in contract.input_authority_requirements
    }
    expected_outputs_by_key: dict[str, set[str]] = {}
    for identity, (phase, work_unit, _writer, _schema) in expected.items():
        expected_outputs_by_key.setdefault(
            _producer_key(contract, phase, work_unit), set()
        ).add(identity)
    for identity, (phase, work_unit, writer, schema) in expected.items():
        key = _producer_key(contract, phase, work_unit)
        binding = bindings.get(identity)
        unit = units.get(key)
        manifest = unit.get("contract_manifest") if isinstance(unit, Mapping) else None
        launch_manifest = (
            unit.get("launch_manifest") if isinstance(unit, Mapping) else None
        )
        outputs = manifest.get("outputs") if isinstance(manifest, Mapping) else None
        matches = [
            row for row in outputs or ()
            if isinstance(row, Mapping) and row.get("identity") == identity
        ]
        immutable_inputs = (
            manifest.get("immutable_inputs")
            if isinstance(manifest, Mapping)
            else None
        )
        bounded_inputs = (
            manifest.get("bounded_lookup_inputs")
            if isinstance(manifest, Mapping)
            else None
        )
        producer_requirements = (
            manifest.get("input_authority_requirements", [])
            if isinstance(manifest, Mapping)
            else None
        )
        semantic_inputs = (
            set(immutable_inputs) | set(bounded_inputs)
            if isinstance(immutable_inputs, list)
            and isinstance(bounded_inputs, list)
            and all(isinstance(item, str) for item in immutable_inputs)
            and all(isinstance(item, str) for item in bounded_inputs)
            else None
        )
        exact_requirement_inputs = (
            {
                row.get("identity")
                for row in producer_requirements
                if isinstance(row, Mapping)
                and row.get("allow_raw") is False
                and row.get("require_same_run") is True
                and row.get("require_exact_contract") is True
                and row.get("require_exact_launch") is True
                and row.get("expected_producer_work_unit_key")
                and row.get("expected_writer") in {"DRIVER", "MODEL"}
                and _HEX64.fullmatch(
                    str(row.get("expected_contract_digest") or "")
                )
                and _HEX64.fullmatch(
                    str(row.get("expected_launch_digest") or "")
                )
            }
            if isinstance(producer_requirements, list)
            else None
        )
        requirement = requirements[identity]
        if (
            not isinstance(binding, Mapping)
            or not isinstance(unit, Mapping)
            or unit.get("execution_state") != "OUTPUT_COMMITTED"
            or binding.get("status") != "ACTIVE"
            or unit.get("run_id") != run_id
            or binding.get("owner_key") != key
            or binding.get("run_id") != run_id
            or binding.get("writer") != writer
            or binding.get("contract_digest") != requirement.expected_contract_digest
            or binding.get("launch_digest") != requirement.expected_launch_digest
            or unit.get("contract_digest") != requirement.expected_contract_digest
            or unit.get("launch_digest") != requirement.expected_launch_digest
            or not isinstance(manifest, Mapping)
            or manifest.get("key") != key
            or manifest.get("model_invoked") is not False
            or manifest.get("launch_profile") != "DRIVER_PYTHON_NO_TOOLS"
            or manifest.get("required_commit_actor") != "DRIVER"
            or semantic_inputs is None
            or exact_requirement_inputs is None
            or exact_requirement_inputs != semantic_inputs
            or len(producer_requirements) != len(semantic_inputs)
            or not isinstance(outputs, list)
            or {
                row.get("identity")
                for row in outputs
                if isinstance(row, Mapping)
            } != expected_outputs_by_key[key]
            or len(outputs) != len(expected_outputs_by_key[key])
            or not isinstance(launch_manifest, Mapping)
            or launch_manifest.get("work_unit_key") != key
            or launch_manifest.get("model") != "driver"
            or launch_manifest.get("exec_mode") != "python"
            or launch_manifest.get("tool_policy") != []
            or len(matches) != 1
            or matches[0].get("writer") != writer
            or matches[0].get("schema_version") != schema
        ):
            _fail("committed fixed producer differs for " + identity)


def _load_committed_driver_output(
    *,
    scratchpad: Path,
    project_root: Path,
    contract: PhaseIOContract,
    launch: LaunchSpec,
    run_id: str,
    artifact_identity: str,
    schema_version: str,
    phase: str | None = None,
    work_unit_id: str | None = None,
    limit: int = _MAX_CONTROL_BYTES,
    fixed_input_producers: Mapping[
        str, tuple[str, str, str, str]
    ] | None = None,
    fixed_inputs_exact: bool = True,
) -> bytes:
    _validate_driver_output_contract(
        contract,
        launch,
        artifact_identity=artifact_identity,
        schema_version=schema_version,
        phase=phase,
        work_unit_id=work_unit_id,
    )
    if fixed_input_producers is not None:
        _require_fixed_input_producers(
            contract,
            fixed_input_producers,
            exact_denominator=fixed_inputs_exact,
        )
    root = Path(scratchpad)
    project = Path(project_root)
    try:
        issues = list(validate_work_unit_inputs(
            root, project, contract, launch, run_id=run_id
        ))
        issues.extend(validate_work_unit_artifacts(
            root,
            project,
            contract,
            launch,
            run_id=run_id,
            actor="DRIVER",
        ))
        ledger = read_artifact_ledger(root)
    except (ArtifactLedgerError, OSError, TypeError, ValueError) as exc:
        _fail("committed PhaseIO replay failed", exc)
    if issues:
        _fail("committed PhaseIO replay differs: " + "; ".join(issues))
    row = (ledger.get("work_units") or {}).get(contract.key)
    if (
        not isinstance(row, Mapping)
        or row.get("semantic_status") != "ACTIVE"
        or row.get("run_id") != run_id
        or row.get("contract_digest") != contract.digest
        or row.get("launch_digest") != launch.digest
    ):
        _fail("committed PhaseIO ledger row is absent, inactive, or stale")
    if fixed_input_producers is not None:
        _validate_fixed_input_producers_in_ledger(
            ledger,
            contract,
            run_id=run_id,
            expected=fixed_input_producers,
        )
    root_name, relative = artifact_identity.split(":", 1)
    base = root if root_name == "scratchpad" else project
    target = base / relative
    try:
        raw = rooted_path_io.read_bytes(
            target,
            label=artifact_identity,
            require_single_link=True,
        )
    except (OSError, rooted_path_io.RootedPathIOError) as exc:
        _fail("committed artifact physical replay failed", exc)
    return _bounded_bytes(raw, label=artifact_identity, limit=limit)


def _commit_replay_context(
    *,
    scratchpad: Path,
    project_root: Path,
    contract: PhaseIOContract,
    launch: LaunchSpec,
    run_id: str,
    artifact_identity: str,
    schema_version: str,
    phase: str,
    work_unit_id: str,
    limit: int,
    fixed_input_producers: Mapping[
        str, tuple[str, str, str, str]
    ] | None = None,
    fixed_inputs_exact: bool = True,
) -> _CommittedReplayContext:
    return _CommittedReplayContext(
        scratchpad=Path(os.path.abspath(os.fspath(scratchpad))),
        project_root=Path(os.path.abspath(os.fspath(project_root))),
        contract=contract,
        launch=launch,
        run_id=run_id,
        artifact_identity=artifact_identity,
        schema_version=schema_version,
        phase=phase,
        work_unit_id=work_unit_id,
        limit=limit,
        fixed_input_producers=tuple(sorted((fixed_input_producers or {}).items())),
        fixed_inputs_exact=fixed_inputs_exact,
    )


def _revalidate_token_commit(
    token: object,
    *,
    artifact_identity: str,
    schema_version: str,
    phase: str,
    work_unit_id: str,
) -> None:
    """Re-read the exact PhaseIO commit behind a process-local token."""

    context = getattr(token, "_commit_context", None)
    if type(context) is not _CommittedReplayContext:
        _fail("committed token has no exact PhaseIO replay context")
    expected_fixed_by_identity = {
        _CONSUMER_ROSTER_IDENTITY: {
            _SCHEDULE_IDENTITY: (
                "recon", "graph_application.scheduler", "DRIVER",
                SCHEDULE_SCHEMA,
            ),
        },
        f"scratchpad:{AUTHORITY_ARTIFACT}": {
            _CONSUMER_ROSTER_IDENTITY: (
                "inventory", "graph_application.consumer_roster", "DRIVER",
                CONSUMER_ROSTER_SCHEMA,
            ),
            _WORKSPACE_ARTIFACT: (
                "recon", "evm_analysis_workspace_capture", "DRIVER",
                WORKSPACE_SCHEMA,
            ),
            _GRAPH_ARTIFACT: (
                "recon", "mechanical_graph", "DRIVER",
                "plamen.mechanical_graph.v2",
            ),
            _HANDOFF_ARTIFACT: (
                "inventory", "depth_handoff", "DRIVER",
                "plamen.depth_handoff_receipt.v1",
            ),
            _DEPTH_CANDIDATES_ARTIFACT: (
                "inventory", "depth_handoff", "DRIVER",
                "plamen.depth_candidates_projection.v1",
            ),
            _GRAPH_GENERATION_ARTIFACT: (
                "inventory", "graph_generation", "DRIVER",
                "plamen.mechanical_graph_generation.v1",
            ),
        },
        f"scratchpad:{OBSERVATIONS_ARTIFACT}": {
            f"scratchpad:{AUTHORITY_ARTIFACT}": (
                "inventory", "graph_application.authority", "DRIVER",
                AUTHORITY_SCHEMA,
            ),
        },
        f"scratchpad:{RECONCILIATION_ARTIFACT}": {
            f"scratchpad:{AUTHORITY_ARTIFACT}": (
                "inventory", "graph_application.authority", "DRIVER",
                AUTHORITY_SCHEMA,
            ),
            f"scratchpad:{OBSERVATIONS_ARTIFACT}": (
                "chain", "graph_application.observations", "DRIVER",
                OBSERVATIONS_SCHEMA,
            ),
        },
    }
    expected_fixed = expected_fixed_by_identity.get(artifact_identity)
    expected_fixed_exact = artifact_identity != f"scratchpad:{OBSERVATIONS_ARTIFACT}"
    if (
        expected_fixed is None
        or getattr(token, "contract_digest", None) != context.contract.digest
        or getattr(token, "launch_digest", None) != context.launch.digest
        or context.artifact_identity != artifact_identity
        or context.schema_version != schema_version
        or context.phase != phase
        or context.work_unit_id != work_unit_id
        or dict(context.fixed_input_producers) != expected_fixed
        or context.fixed_inputs_exact is not expected_fixed_exact
    ):
        _fail("committed token PhaseIO replay context differs")
    raw = _load_committed_driver_output(
        scratchpad=context.scratchpad,
        project_root=context.project_root,
        contract=context.contract,
        launch=context.launch,
        run_id=context.run_id,
        artifact_identity=context.artifact_identity,
        schema_version=context.schema_version,
        phase=context.phase,
        work_unit_id=context.work_unit_id,
        limit=context.limit,
        fixed_input_producers=dict(context.fixed_input_producers),
        fixed_inputs_exact=context.fixed_inputs_exact,
    )
    if (
        raw != getattr(token, "canonical_bytes", None)
        or _raw_digest(raw) != getattr(token, "artifact_sha256", None)
    ):
        _fail("committed token bytes differ from live PhaseIO commit")


def build_graph_schedule_payload(
    *,
    run_id: str,
    snapshot_sha256: str,
    required_consumers: Sequence[Mapping[str, Any]],
    contract: PhaseIOContract,
    launch: LaunchSpec,
) -> dict[str, Any]:
    """Build the canonical scheduler artifact; authority begins at commit."""

    if _RUN_ID.fullmatch(str(run_id or "")) is None:
        _fail("graph schedule run_id is malformed")
    snapshot_sha256 = _hex(snapshot_sha256, label="graph schedule snapshot")
    consumers = _normalize_consumer_specs(required_consumers)
    _validate_driver_output_contract(
        contract,
        launch,
        artifact_identity=_SCHEDULE_IDENTITY,
        schema_version=SCHEDULE_SCHEMA,
        phase="recon",
        work_unit_id="graph_application.scheduler",
    )
    if contract.immutable_inputs or contract.bounded_lookup_inputs:
        _fail("graph scheduler producer must have an empty input denominator")
    denominator = _digest(consumers)
    unsigned = {
        "schema_version": SCHEDULE_SCHEMA,
        "state": "COMMITTED",
        "run_id": run_id,
        "snapshot_sha256": snapshot_sha256,
        "required_consumers": consumers,
        "consumer_count": len(consumers),
        "consumer_denominator_sha256": denominator,
        "owner": {
            "work_unit_key": contract.key,
            "contract_digest": contract.digest,
            "launch_digest": launch.digest,
        },
    }
    result = {**unsigned, "schedule_sha256": _digest(unsigned)}
    if len(canonical_file_bytes(result)) > _MAX_CONTROL_BYTES:
        _fail("graph schedule exceeds serialized byte bound")
    return result


def _validate_graph_schedule(
    value: object,
    *,
    expected_run_id: str,
    expected_snapshot_sha256: str,
    expected_owner_work_unit_key: str,
    expected_contract_digest: str,
    expected_launch_digest: str,
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "schema_version", "state", "run_id", "snapshot_sha256",
        "required_consumers", "consumer_count",
        "consumer_denominator_sha256", "owner", "schedule_sha256",
    }:
        _fail("graph schedule fields differ from v1 schema")
    unsigned = dict(value)
    stored = unsigned.pop("schedule_sha256", None)
    consumers = _normalize_consumer_specs(value.get("required_consumers"))
    owner = value.get("owner")
    if (
        value.get("schema_version") != SCHEDULE_SCHEMA
        or value.get("state") != "COMMITTED"
        or stored != _digest(unsigned)
        or value.get("run_id") != expected_run_id
        or value.get("snapshot_sha256") != expected_snapshot_sha256
        or value.get("required_consumers") != consumers
        or value.get("consumer_count") != len(consumers)
        or value.get("consumer_denominator_sha256") != _digest(consumers)
        or not isinstance(owner, Mapping)
        or set(owner) != {"work_unit_key", "contract_digest", "launch_digest"}
        or owner.get("work_unit_key") != expected_owner_work_unit_key
        or owner.get("contract_digest") != expected_contract_digest
        or owner.get("launch_digest") != expected_launch_digest
    ):
        _fail("graph schedule committed producer replay failed")
    _hex(owner.get("contract_digest"), label="graph schedule owner contract")
    _hex(owner.get("launch_digest"), label="graph schedule owner launch")
    return dict(value)


def decode_graph_schedule_test_only(raw: bytes, **expected: str) -> dict[str, Any]:
    """TEST_ONLY structural decoder; never grants scheduler authority."""

    return _validate_graph_schedule(
        _canonical_artifact(raw, label=SCHEDULE_ARTIFACT), **expected
    )


def _validate_scheduler_authority(
    value: object,
    *,
    schedule: Mapping[str, Any],
    schedule_artifact_sha256: str,
) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != {
        "artifact_identity", "artifact_sha256", "schedule_sha256",
        "consumer_denominator_sha256", "producer_work_unit_key",
        "producer_contract_digest", "producer_launch_digest",
    }:
        _fail("consumer scheduler authority is malformed")
    result = {
        "artifact_identity": _artifact_identity(
            value.get("artifact_identity"), label="consumer scheduler artifact"
        ),
        "artifact_sha256": _hex(
            value.get("artifact_sha256"), label="consumer scheduler artifact digest"
        ),
        "consumer_denominator_sha256": _hex(
            value.get("consumer_denominator_sha256"),
            label="scheduled consumer denominator",
        ),
        "schedule_sha256": _hex(
            value.get("schedule_sha256"), label="graph schedule digest"
        ),
        "producer_work_unit_key": _text(
            value.get("producer_work_unit_key"), label="graph schedule producer key"
        ),
        "producer_contract_digest": _hex(
            value.get("producer_contract_digest"), label="graph schedule contract"
        ),
        "producer_launch_digest": _hex(
            value.get("producer_launch_digest"), label="graph schedule launch"
        ),
    }
    if (
        result["artifact_identity"] != _SCHEDULE_IDENTITY
        or result["artifact_sha256"] != schedule_artifact_sha256
        or result["schedule_sha256"] != schedule["schedule_sha256"]
        or result["consumer_denominator_sha256"]
        != schedule["consumer_denominator_sha256"]
        or result["producer_work_unit_key"] != schedule["owner"]["work_unit_key"]
        or result["producer_contract_digest"] != schedule["owner"]["contract_digest"]
        or result["producer_launch_digest"] != schedule["owner"]["launch_digest"]
    ):
        _fail("consumer scheduler authority differs from committed schedule")
    return result


def build_graph_consumer_roster_payload(
    *,
    run_id: str,
    snapshot_sha256: str,
    committed_schedule_raw: bytes,
    contract: PhaseIOContract,
    launch: LaunchSpec,
) -> dict[str, Any]:
    """Build a roster payload which grants no authority until ledger-committed."""
    if _RUN_ID.fullmatch(str(run_id or "")) is None:
        _fail("consumer roster run_id is malformed")
    snapshot_sha256 = _hex(snapshot_sha256, label="consumer roster snapshot")
    _validate_driver_output_contract(
        contract,
        launch,
        artifact_identity=_CONSUMER_ROSTER_IDENTITY,
        schema_version=CONSUMER_ROSTER_SCHEMA,
        phase="inventory",
        work_unit_id="graph_application.consumer_roster",
    )
    fixed = {
        _SCHEDULE_IDENTITY: (
            "recon", "graph_application.scheduler", "DRIVER", SCHEDULE_SCHEMA
        )
    }
    _require_fixed_input_producers(contract, fixed)
    requirement = contract.input_authority_requirements[0]
    schedule_raw = _bounded_bytes(
        committed_schedule_raw,
        label=SCHEDULE_ARTIFACT,
        limit=_MAX_CONTROL_BYTES,
    )
    schedule = decode_graph_schedule_test_only(
        schedule_raw,
        expected_run_id=run_id,
        expected_snapshot_sha256=snapshot_sha256,
        expected_owner_work_unit_key=requirement.expected_producer_work_unit_key,
        expected_contract_digest=requirement.expected_contract_digest,
        expected_launch_digest=requirement.expected_launch_digest,
    )
    consumers = schedule["required_consumers"]
    expected = schedule["consumer_denominator_sha256"]
    scheduler = {
        "artifact_identity": _SCHEDULE_IDENTITY,
        "artifact_sha256": _raw_digest(schedule_raw),
        "schedule_sha256": schedule["schedule_sha256"],
        "consumer_denominator_sha256": expected,
        "producer_work_unit_key": schedule["owner"]["work_unit_key"],
        "producer_contract_digest": schedule["owner"]["contract_digest"],
        "producer_launch_digest": schedule["owner"]["launch_digest"],
    }
    unsigned = {
        "schema_version": CONSUMER_ROSTER_SCHEMA,
        "state": "COMMITTED",
        "run_id": run_id,
        "snapshot_sha256": snapshot_sha256,
        "scheduler_authority": scheduler,
        "required_consumers": consumers,
        "consumer_count": len(consumers),
        "consumer_denominator_sha256": expected,
        "owner": {
            "work_unit_key": contract.key,
            "contract_digest": contract.digest,
            "launch_digest": launch.digest,
        },
    }
    result = {**unsigned, "roster_sha256": _digest(unsigned)}
    if len(canonical_file_bytes(result)) > _MAX_CONTROL_BYTES:
        _fail("consumer roster exceeds serialized byte bound")
    return result


def _validate_consumer_roster(
    value: object,
    *,
    expected_run_id: str,
    expected_snapshot_sha256: str,
    committed_schedule: Mapping[str, Any],
    schedule_artifact_sha256: str,
    expected_owner_work_unit_key: str | None = None,
    expected_contract_digest: str | None = None,
    expected_launch_digest: str | None = None,
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "schema_version", "state", "run_id", "snapshot_sha256",
        "scheduler_authority", "required_consumers", "consumer_count",
        "consumer_denominator_sha256", "owner", "roster_sha256",
    }:
        _fail("consumer roster fields differ from v1 schema")
    unsigned = dict(value)
    stored = unsigned.pop("roster_sha256", None)
    if (
        value.get("schema_version") != CONSUMER_ROSTER_SCHEMA
        or value.get("state") != "COMMITTED"
        or _digest(unsigned) != stored
        or value.get("run_id") != expected_run_id
        or value.get("snapshot_sha256") != expected_snapshot_sha256
    ):
        _fail("consumer roster integrity/run/snapshot replay failed")
    expected_denominator = committed_schedule["consumer_denominator_sha256"]
    scheduler = _validate_scheduler_authority(
        value.get("scheduler_authority"),
        schedule=committed_schedule,
        schedule_artifact_sha256=schedule_artifact_sha256,
    )
    consumers = _normalize_consumer_specs(value.get("required_consumers"))
    if (
        value.get("required_consumers") != consumers
        or consumers != committed_schedule["required_consumers"]
        or value.get("consumer_count") != len(consumers)
        or value.get("consumer_denominator_sha256") != expected_denominator
        or _digest(consumers) != expected_denominator
    ):
        _fail("consumer roster denominator differs")
    owner = value.get("owner")
    if not isinstance(owner, Mapping) or set(owner) != {
        "work_unit_key", "contract_digest", "launch_digest"
    }:
        _fail("consumer roster owner is malformed")
    for field in ("contract_digest", "launch_digest"):
        _hex(owner.get(field), label=f"consumer roster owner {field}")
    if expected_owner_work_unit_key is not None and owner.get("work_unit_key") != expected_owner_work_unit_key:
        _fail("consumer roster owner work unit differs")
    if expected_contract_digest is not None and owner.get("contract_digest") != expected_contract_digest:
        _fail("consumer roster owner contract differs")
    if expected_launch_digest is not None and owner.get("launch_digest") != expected_launch_digest:
        _fail("consumer roster owner launch differs")
    return dict(value)


def decode_graph_consumer_roster_test_only(
    raw: bytes,
    **expected: str,
) -> dict[str, Any]:
    """TEST_ONLY structural decoder; never returns a committed token."""
    value = _canonical_artifact(raw, label=CONSUMER_ROSTER_ARTIFACT)
    return _validate_consumer_roster(value, **expected)


def _load_committed_graph_consumer_roster_impl(
    *,
    scratchpad: Path,
    project_root: Path,
    contract: PhaseIOContract,
    launch: LaunchSpec,
    run_id: str,
    expected_snapshot_sha256: str,
    __issuer: Any,
) -> CommittedGraphConsumerRoster:
    fixed = {
        _SCHEDULE_IDENTITY: (
            "recon", "graph_application.scheduler", "DRIVER", SCHEDULE_SCHEMA
        )
    }
    raw = _load_committed_driver_output(
        scratchpad=scratchpad,
        project_root=project_root,
        contract=contract,
        launch=launch,
        run_id=run_id,
        artifact_identity=_CONSUMER_ROSTER_IDENTITY,
        schema_version=CONSUMER_ROSTER_SCHEMA,
        phase="inventory",
        work_unit_id="graph_application.consumer_roster",
        fixed_input_producers=fixed,
    )
    requirement = {
        row.identity: row for row in contract.input_authority_requirements
    }[_SCHEDULE_IDENTITY]
    scheduler_raw = _read_bound_identity(
        Path(scratchpad), Path(project_root), _SCHEDULE_IDENTITY,
        limit=_MAX_CONTROL_BYTES,
    )
    schedule = decode_graph_schedule_test_only(
        scheduler_raw,
        expected_run_id=run_id,
        expected_snapshot_sha256=expected_snapshot_sha256,
        expected_owner_work_unit_key=requirement.expected_producer_work_unit_key,
        expected_contract_digest=requirement.expected_contract_digest,
        expected_launch_digest=requirement.expected_launch_digest,
    )
    value = _canonical_artifact(raw, label=CONSUMER_ROSTER_ARTIFACT)
    value = _validate_consumer_roster(
        value,
        expected_run_id=run_id,
        expected_snapshot_sha256=expected_snapshot_sha256,
        committed_schedule=schedule,
        schedule_artifact_sha256=_raw_digest(scheduler_raw),
        expected_owner_work_unit_key=contract.key,
        expected_contract_digest=contract.digest,
        expected_launch_digest=launch.digest,
    )
    return __issuer(
        CommittedGraphConsumerRoster,
        kind="committed graph consumer roster",
        payload=value,
        canonical_bytes=raw,
        artifact_sha256=_raw_digest(raw),
        contract_digest=contract.digest,
        launch_digest=launch.digest,
        _commit_context=_commit_replay_context(
            scratchpad=scratchpad,
            project_root=project_root,
            contract=contract,
            launch=launch,
            run_id=run_id,
            artifact_identity=_CONSUMER_ROSTER_IDENTITY,
            schema_version=CONSUMER_ROSTER_SCHEMA,
            phase="inventory",
            work_unit_id="graph_application.consumer_roster",
            limit=_MAX_CONTROL_BYTES,
            fixed_input_producers=fixed,
        ),
    )


def _replay_committed_roster_token(
    token: CommittedGraphConsumerRoster,
    *,
    run_id: str,
    snapshot_sha256: str,
    __verifier: Any = _require_committed_token,
) -> dict[str, Any]:
    if type(token) is not CommittedGraphConsumerRoster:
        _fail("graph authority requires a committed consumer-roster token")
    __verifier(
        token,
        cls=CommittedGraphConsumerRoster,
        kind="committed graph consumer roster",
    )
    _revalidate_token_commit(
        token,
        artifact_identity=_CONSUMER_ROSTER_IDENTITY,
        schema_version=CONSUMER_ROSTER_SCHEMA,
        phase="inventory",
        work_unit_id="graph_application.consumer_roster",
    )
    if _raw_digest(token.canonical_bytes) != token.artifact_sha256:
        _fail("committed consumer-roster token bytes were mutated")
    decoded = _canonical_artifact(
        token.canonical_bytes, label=CONSUMER_ROSTER_ARTIFACT
    )
    scheduler = decoded.get("scheduler_authority")
    if not isinstance(scheduler, Mapping):
        _fail("committed consumer roster scheduler binding is absent")
    schedule = {
        "required_consumers": decoded.get("required_consumers"),
        "consumer_denominator_sha256": decoded.get(
            "consumer_denominator_sha256"
        ),
        "schedule_sha256": scheduler.get("schedule_sha256"),
        "owner": {
            "work_unit_key": scheduler.get("producer_work_unit_key"),
            "contract_digest": scheduler.get("producer_contract_digest"),
            "launch_digest": scheduler.get("producer_launch_digest"),
        },
    }
    validated = _validate_consumer_roster(
        decoded,
        expected_run_id=run_id,
        expected_snapshot_sha256=snapshot_sha256,
        committed_schedule=schedule,
        schedule_artifact_sha256=scheduler.get("artifact_sha256"),
        expected_owner_work_unit_key=str(token.payload["owner"]["work_unit_key"]),
        expected_contract_digest=token.contract_digest,
        expected_launch_digest=token.launch_digest,
    )
    if dict(token.payload) != validated:
        _fail("committed consumer-roster token payload differs from its bytes")
    return validated


def build_graph_application_authority(
    *,
    run_id: str,
    snapshot_sha256: str,
    workspace_receipt_raw: bytes,
    mechanical_graph_raw: bytes,
    depth_handoff_receipt_raw: bytes,
    depth_candidates_raw: bytes,
    committed_consumer_roster: CommittedGraphConsumerRoster,
    graph_generation_manifest_raw: bytes | None = None,
) -> dict[str, Any]:
    """Build an exact denominator from a ledger-authenticated scheduler roster."""

    if _RUN_ID.fullmatch(str(run_id or "")) is None:
        _fail("run_id is malformed")
    snapshot_sha256 = _hex(snapshot_sha256, label="snapshot_sha256")
    if type(committed_consumer_roster) is not CommittedGraphConsumerRoster:
        _fail("graph authority requires a committed consumer-roster token")
    roster_payload = committed_consumer_roster.payload
    roster = _replay_committed_roster_token(
        committed_consumer_roster,
        run_id=run_id,
        snapshot_sha256=snapshot_sha256,
    )
    expected_consumer_denominator_sha256 = roster[
        "consumer_denominator_sha256"
    ]
    expected_scheduler_artifact_sha256 = roster[
        "scheduler_authority"
    ]["artifact_sha256"]
    workspace, workspace_ref = _validate_workspace(
        workspace_receipt_raw, run_id=run_id, snapshot_sha256=snapshot_sha256
    )
    graph, graph_elements = _parse_graph(mechanical_graph_raw)
    handoff = _validate_handoff(
        depth_handoff_receipt_raw,
        graph_raw=mechanical_graph_raw,
        candidates_raw=depth_candidates_raw,
        function_count=len(graph["functions"]),
        state_count=len(graph["state_symbols"]),
    )
    leads = _parse_leads(
        depth_candidates_raw, expected_count=int(handoff["finding_count"])
    )
    elements = sorted([*graph_elements, *leads], key=lambda row: row["element_id"])
    if len(elements) != len({row["element_id"] for row in elements}):
        _fail("graph element ID collision/conflict")
    generation_manifest, _ = _validate_generation_manifest(
        graph_generation_manifest_raw, graph_raw=mechanical_graph_raw
    )
    element_denominator_sha256 = _digest(elements)
    generation_unsigned = {
        "workspace_reference_sha256": workspace_ref["reference_sha256"],
        "snapshot_sha256": snapshot_sha256,
        "mechanical_graph_sha256": _raw_digest(mechanical_graph_raw),
        "depth_handoff_receipt_sha256": _raw_digest(depth_handoff_receipt_raw),
        "depth_candidates_sha256": _raw_digest(depth_candidates_raw),
        "provider_generation_sha256": generation_manifest["provider_generation_sha256"],
        "element_denominator_sha256": element_denominator_sha256,
    }
    generation_sha256 = _digest(generation_unsigned)
    full_availability = {
        "workspace_reference_sha256": workspace_ref["reference_sha256"],
        "snapshot_sha256": snapshot_sha256,
        "generation_sha256": generation_sha256,
        "mechanical_graph_sha256": _raw_digest(mechanical_graph_raw),
        "depth_handoff_receipt_sha256": _raw_digest(depth_handoff_receipt_raw),
        "depth_candidates_sha256": _raw_digest(depth_candidates_raw),
        "element_denominator_sha256": element_denominator_sha256,
    }
    full_availability_sha256 = _digest(full_availability)
    consumers, _, unassigned, assignment_pair_count = _consumer_requirements(
        roster["required_consumers"],
        elements,
        full_availability_sha256=full_availability_sha256,
    )
    roster_owner = roster["owner"]
    scheduler = roster["scheduler_authority"]
    unsigned: dict[str, Any] = {
        "schema_version": AUTHORITY_SCHEMA,
        "state": "DEGRADED",
        "run_id": run_id,
        "snapshot_sha256": snapshot_sha256,
        "consumer_roster": {
            "artifact_identity": _CONSUMER_ROSTER_IDENTITY,
            "artifact_sha256": committed_consumer_roster.artifact_sha256,
            "roster_sha256": roster["roster_sha256"],
            "owner_work_unit_key": roster_owner["work_unit_key"],
            "contract_digest": roster_owner["contract_digest"],
            "launch_digest": roster_owner["launch_digest"],
            "scheduler_artifact_identity": scheduler["artifact_identity"],
            "scheduler_artifact_sha256": scheduler["artifact_sha256"],
        },
        "consumer_denominator_sha256": expected_consumer_denominator_sha256,
        "workspace": {
            "artifact_identity": _WORKSPACE_ARTIFACT,
            "artifact_sha256": _raw_digest(workspace_receipt_raw),
            "receipt_sha256": workspace["receipt_sha256"],
            "reference_sha256": workspace_ref["reference_sha256"],
            "owner_work_unit_key": workspace["owner"]["work_unit_key"],
            "state": workspace["state"],
            "tool_rows_sha256": _digest(workspace["tools"]),
        },
        "graph_generation": {
            "generation_sha256": generation_sha256,
            "provider_manifest": generation_manifest,
            "mechanical_graph": {
                "artifact_identity": _GRAPH_ARTIFACT,
                "artifact_sha256": _raw_digest(mechanical_graph_raw),
                "bytes": len(mechanical_graph_raw),
                "schema_version": graph["schema_version"],
                "provider": graph["source"],
                "provider_authority": _graph_provider_binding(
                    workspace, graph["source"]
                ),
            },
            "depth_handoff": {
                "artifact_identity": _HANDOFF_ARTIFACT,
                "artifact_sha256": _raw_digest(depth_handoff_receipt_raw),
                "schema_version": handoff["schema_version"],
                "depth_candidates_artifact_identity": _DEPTH_CANDIDATES_ARTIFACT,
                "depth_candidates_sha256": _raw_digest(depth_candidates_raw),
            },
        },
        "elements": elements,
        "element_count": len(elements),
        "element_denominator_sha256": element_denominator_sha256,
        "full_availability": full_availability,
        "full_availability_sha256": full_availability_sha256,
        "consumers": consumers,
        "consumer_count": len(consumers),
        "consumer_assignment_denominator_sha256": _digest(consumers),
        "assignment_pair_count": assignment_pair_count,
        "unassigned_element_ids": unassigned,
        "debts": [],
    }
    unsigned["debts"] = _derive_authority_debts(unsigned)
    unsigned["state"] = "READY" if not unsigned["debts"] else "DEGRADED"
    result = {**unsigned, "authority_sha256": _digest(unsigned)}
    if len(canonical_file_bytes(result)) > _MAX_ARTIFACT_BYTES:
        _fail("graph application authority exceeds serialized byte bound")
    return result


def _validate_terminal_digest(
    value: object,
    *,
    schema: str,
    digest_field: str,
    states: frozenset[str],
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _fail(f"{schema} is not an object")
    collection_limits = {
        AUTHORITY_SCHEMA: {
            "elements": _MAX_ELEMENTS,
            "consumers": _MAX_CONSUMERS,
            "unassigned_element_ids": _MAX_ELEMENTS,
            "debts": _MAX_CONSUMERS + 8,
        },
        OBSERVATIONS_SCHEMA: {
            "evidence_artifacts": _MAX_EVIDENCE_BINDINGS,
            "consumers": _MAX_CONSUMERS,
        },
        RECONCILIATION_SCHEMA: {
            "consumers": _MAX_CONSUMERS,
            "debts": _MAX_ASSIGNMENT_PAIRS + (2 * _MAX_CONSUMERS) + 8,
        },
    }.get(schema, {})
    for field, limit in collection_limits.items():
        candidate = value.get(field)
        if not isinstance(candidate, list) or len(candidate) > limit:
            _fail(f"{schema} {field} denominator exceeds bound")
    if schema == AUTHORITY_SCHEMA:
        pair_count = 0
        for row in value.get("consumers", []):
            if not isinstance(row, Mapping):
                _fail("graph authority consumer row is malformed")
            assigned = row.get("assigned_element_ids")
            evidence = row.get("evidence_artifacts")
            if (
                not isinstance(assigned, list)
                or len(assigned) > _MAX_ASSIGNMENT_PAIRS - pair_count
                or not isinstance(evidence, list)
                or len(evidence) > _MAX_EVIDENCE_ARTIFACTS_PER_CONSUMER
            ):
                _fail("graph authority nested denominator exceeds bound")
            pair_count += len(assigned)
        for row in value.get("elements", []):
            if (
                isinstance(row, Mapping)
                and row.get("kind") == "EDGE"
                and (
                    not isinstance(row.get("evidence_sides"), list)
                    or len(row["evidence_sides"]) > 2
                )
            ):
                _fail("graph authority edge evidence denominator exceeds bound")
    elif schema == OBSERVATIONS_SCHEMA:
        outcome_count = 0
        evidence_row_count = 0
        evidence_locus_count = 0
        for consumer in value.get("consumers", []):
            if not isinstance(consumer, Mapping):
                _fail("graph observation consumer row is malformed")
            outcomes = consumer.get("outcomes")
            if (
                not isinstance(outcomes, list)
                or len(outcomes) > _MAX_ASSIGNMENT_PAIRS - outcome_count
            ):
                _fail("graph observation outcome denominator exceeds bound")
            outcome_count += len(outcomes)
            for outcome in outcomes:
                if not isinstance(outcome, Mapping):
                    _fail("graph observation outcome row is malformed")
                evidence = outcome.get("evidence")
                if (
                    not isinstance(evidence, list)
                    or len(evidence) > _MAX_EVIDENCE_ROWS_PER_OUTCOME
                    or len(evidence)
                    > _MAX_OBSERVATION_EVIDENCE_ROWS - evidence_row_count
                ):
                    _fail("graph observation evidence denominator exceeds bound")
                evidence_row_count += len(evidence)
                for evidence_row in evidence:
                    loci = (
                        evidence_row.get("loci")
                        if isinstance(evidence_row, Mapping)
                        else None
                    )
                    if (
                        not isinstance(loci, list)
                        or len(loci) > _MAX_EVIDENCE_LOCI_PER_ROW
                        or len(loci)
                        > _MAX_OBSERVATION_EVIDENCE_LOCI - evidence_locus_count
                    ):
                        _fail("graph observation evidence-locus denominator exceeds bound")
                    evidence_locus_count += len(loci)
    elif schema == RECONCILIATION_SCHEMA:
        nested_debt_count = 0
        nested_limit = _MAX_ASSIGNMENT_PAIRS + (2 * _MAX_CONSUMERS) + 8
        for consumer in value.get("consumers", []):
            debts = consumer.get("debts") if isinstance(consumer, Mapping) else None
            if (
                not isinstance(debts, list)
                or len(debts) > nested_limit - nested_debt_count
            ):
                _fail("graph reconciliation nested debt denominator exceeds bound")
            nested_debt_count += len(debts)
    result = dict(value)
    stored = result.pop(digest_field, None)
    if (
        value.get("schema_version") != schema
        or value.get("state") not in states
        or _HEX64.fullmatch(str(stored or "")) is None
        or _digest(result) != stored
    ):
        _fail(f"{schema} terminal digest/state integrity failure")
    return dict(value)


def validate_graph_application_authority(
    value: object,
    *,
    expected_consumer_denominator_sha256: str | None = None,
    expected_scheduler_artifact_sha256: str | None = None,
    expected_run_id: str | None = None,
    expected_snapshot_sha256: str | None = None,
    expected_generation_sha256: str | None = None,
) -> dict[str, Any]:
    """Replay structural and denominator integrity of an authority mapping."""

    result = _validate_terminal_digest(
        value,
        schema=AUTHORITY_SCHEMA,
        digest_field="authority_sha256",
        states=AUTHORITY_STATES,
    )
    if set(result) != {
        "schema_version", "state", "run_id", "snapshot_sha256",
        "consumer_roster", "workspace",
        "graph_generation", "elements", "element_count",
        "element_denominator_sha256", "full_availability",
        "full_availability_sha256", "consumers", "consumer_count",
        "consumer_denominator_sha256",
        "consumer_assignment_denominator_sha256", "assignment_pair_count",
        "unassigned_element_ids", "debts", "authority_sha256",
    }:
        _fail("graph application authority fields differ from the v1 schema")
    if _RUN_ID.fullmatch(str(result.get("run_id") or "")) is None:
        _fail("graph application authority run_id is malformed")
    if expected_run_id is not None and result.get("run_id") != expected_run_id:
        _fail("graph application authority run_id differs")
    if expected_snapshot_sha256 is not None and result.get("snapshot_sha256") != expected_snapshot_sha256:
        _fail("graph application authority snapshot differs")
    _hex(result.get("snapshot_sha256"), label="authority snapshot")
    expected_consumer_denominator_sha256 = _hex(
        (
            result.get("consumer_denominator_sha256")
            if expected_consumer_denominator_sha256 is None
            else expected_consumer_denominator_sha256
        ),
        label="expected consumer denominator",
    )
    if (
        result.get("consumer_denominator_sha256")
        != expected_consumer_denominator_sha256
    ):
        _fail("graph authority consumer denominator differs from scheduler")
    elements = result.get("elements")
    consumers = result.get("consumers")
    debts = result.get("debts")
    graph_generation = result.get("graph_generation")
    workspace = result.get("workspace")
    full_availability = result.get("full_availability")
    unassigned = result.get("unassigned_element_ids")
    if (
        not isinstance(elements, list)
        or len(elements) > _MAX_ELEMENTS
        or result.get("element_count") != len(elements)
        or result.get("element_denominator_sha256") != _digest(elements)
        or not isinstance(consumers, list)
        or len(consumers) > _MAX_CONSUMERS
        or result.get("consumer_count") != len(consumers)
        or result.get("consumer_assignment_denominator_sha256")
        != _digest(consumers)
        or not isinstance(debts, list)
        or not isinstance(graph_generation, Mapping)
        or not isinstance(workspace, Mapping)
        or not isinstance(full_availability, Mapping)
        or result.get("full_availability_sha256") != _digest(full_availability)
        or not isinstance(unassigned, list)
        or unassigned != sorted(unassigned)
        or len(unassigned) != len(set(unassigned))
    ):
        _fail("graph application authority denominator fields are malformed")
    ids: list[str] = []
    for row in elements:
        if not isinstance(row, Mapping) or row.get("kind") not in ELEMENT_KINDS:
            _fail("graph element row is malformed")
        expected_fields = {
            "NODE": {"element_id", "kind", "node_kind", "identity", "locus"},
            "EDGE": {
                "element_id", "kind", "edge_kind", "source_element_id",
                "target_element_id", "evidence_sides",
            },
            "LEAD": {
                "element_id", "kind", "finding_id", "route", "severity",
                "verdict", "locus", "title",
            },
        }[row["kind"]]
        if set(row) != expected_fields:
            _fail("graph element row fields differ from its kind schema")
        element_id = row.get("element_id")
        if not isinstance(element_id, str) or _ELEMENT_ID.fullmatch(element_id) is None:
            _fail("graph element ID is malformed")
        unsigned = dict(row)
        unsigned.pop("element_id", None)
        prefix = {"NODE": "N", "EDGE": "E", "LEAD": "L"}[row["kind"]]
        if element_id != f"G{prefix}-{_digest(unsigned)[:24]}":
            _fail("graph element ID does not bind its row")
        ids.append(element_id)
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        _fail("graph element denominator is unsorted or duplicate")
    consumer_ids: list[str] = []
    reconstructed_consumer_specs: list[dict[str, Any]] = []
    valid_ids = set(ids)
    for row in elements:
        if row["kind"] == "NODE":
            if row.get("node_kind") not in {"FUNCTION", "STATE", "REFERENCE"}:
                _fail("graph node kind is malformed")
            _text(row.get("identity"), label="graph node identity", maximum=1_024)
            if row.get("locus"):
                _source_locus(row["locus"], label="graph node locus")
        elif row["kind"] == "EDGE":
            if (
                row.get("edge_kind") not in {"CALL", "STATE_READ", "STATE_WRITE"}
                or row.get("source_element_id") not in valid_ids
                or row.get("target_element_id") not in valid_ids
                or not isinstance(row.get("evidence_sides"), list)
                or row["evidence_sides"] != sorted(row["evidence_sides"])
                or len(row["evidence_sides"]) != len(set(row["evidence_sides"]))
            ):
                _fail("graph edge endpoints/evidence are malformed")
        else:
            if (
                _FINDING_ID.fullmatch(str(row.get("finding_id") or "")) is None
                or row.get("route") not in _ROUTE_SECTIONS
            ):
                _fail("graph lead identity/route is malformed")
            _source_locus(row.get("locus"), label="graph lead locus")
    assigned_union: set[str] = set()
    assignment_pair_count = 0
    for row in consumers:
        if not isinstance(row, Mapping):
            _fail("consumer row is malformed")
        if set(row) != {
            "consumer_id", "phase", "agent_id", "minimum_disposition",
            "evidence_artifacts", "full_availability_sha256",
            "assignment_selector", "assigned_element_ids", "assignment_sha256",
        }:
            _fail("consumer assignment row fields differ from v1 schema")
        unsigned = dict(row)
        assignment_sha256 = unsigned.pop("assignment_sha256", None)
        if _digest(unsigned) != assignment_sha256:
            _fail("consumer assignment digest differs")
        consumer_id = row.get("consumer_id")
        assigned = row.get("assigned_element_ids")
        selector = row.get("assignment_selector")
        remaining_pair_budget = _MAX_ASSIGNMENT_PAIRS - assignment_pair_count
        if (
            not isinstance(consumer_id, str)
            or _CONSUMER_ID.fullmatch(consumer_id) is None
            or not isinstance(assigned, list)
            or len(assigned) > remaining_pair_budget
            or assigned != sorted(assigned)
            or len(assigned) != len(set(assigned))
            or not set(assigned).issubset(valid_ids)
            or not isinstance(selector, Mapping)
            or set(selector) != {
                "graph_element_kinds", "graph_shard_index",
                "graph_shard_count", "lead_routes",
            }
            or row.get("minimum_disposition") not in MINIMUM_DISPOSITIONS
            or row.get("full_availability_sha256")
            != result.get("full_availability_sha256")
        ):
            _fail("consumer assignment row is malformed")
        if _assigned_ids_for_selector(
            elements,
            selector,
            pair_budget=remaining_pair_budget,
        ) != assigned:
            _fail("consumer assignment row is malformed")
        for identity in row.get("evidence_artifacts", []):
            _artifact_identity(identity, label="consumer evidence artifact")
        consumer_ids.append(consumer_id)
        reconstructed_consumer_specs.append({
            "consumer_id": consumer_id,
            "phase": row.get("phase"),
            "agent_id": row.get("agent_id"),
            **dict(selector),
            "minimum_disposition": row.get("minimum_disposition"),
            "evidence_artifacts": list(row.get("evidence_artifacts", [])),
        })
        assigned_union.update(assigned)
        assignment_pair_count += len(assigned)
    if consumer_ids != sorted(consumer_ids) or len(consumer_ids) != len(set(consumer_ids)):
        _fail("consumer denominator is unsorted or duplicate")
    if _digest(_normalize_consumer_specs(reconstructed_consumer_specs)) != (
        expected_consumer_denominator_sha256
    ):
        _fail("consumer assignments differ from externally committed roster")
    generation = graph_generation.get("generation_sha256")
    _hex(generation, label="graph generation")
    if expected_generation_sha256 is not None and generation != expected_generation_sha256:
        _fail("graph application authority generation differs")
    if set(workspace) != {
        "artifact_identity", "artifact_sha256", "receipt_sha256",
        "reference_sha256", "owner_work_unit_key", "state",
        "tool_rows_sha256",
    }:
        _fail("workspace graph binding fields differ")
    _artifact_identity(workspace.get("artifact_identity"), label="workspace artifact")
    for field in ("artifact_sha256", "receipt_sha256", "reference_sha256"):
        _hex(workspace.get(field), label=f"workspace {field}")
    if workspace.get("state") not in {"BOUND", "BOUND_WITH_DEBT"}:
        _fail("workspace graph binding state is malformed")
    _hex(workspace.get("tool_rows_sha256"), label="workspace tool rows")
    roster = result.get("consumer_roster")
    if not isinstance(roster, Mapping) or set(roster) != {
        "artifact_identity", "artifact_sha256", "roster_sha256",
        "owner_work_unit_key", "contract_digest", "launch_digest",
        "scheduler_artifact_identity", "scheduler_artifact_sha256",
    }:
        _fail("committed consumer roster binding is malformed")
    if roster.get("artifact_identity") != _CONSUMER_ROSTER_IDENTITY:
        _fail("committed consumer roster identity differs")
    for field in (
        "artifact_sha256", "roster_sha256", "contract_digest", "launch_digest",
        "scheduler_artifact_sha256",
    ):
        _hex(roster.get(field), label=f"consumer roster {field}")
    _artifact_identity(
        roster.get("scheduler_artifact_identity"),
        label="consumer roster scheduler artifact",
    )
    expected_scheduler_artifact_sha256 = _hex(
        (
            roster.get("scheduler_artifact_sha256")
            if expected_scheduler_artifact_sha256 is None
            else expected_scheduler_artifact_sha256
        ),
        label="expected scheduler artifact digest",
    )
    if roster["scheduler_artifact_sha256"] != expected_scheduler_artifact_sha256:
        _fail("consumer roster scheduler bytes differ")
    if set(graph_generation) != {
        "generation_sha256", "provider_manifest", "mechanical_graph",
        "depth_handoff",
    }:
        _fail("graph generation binding fields differ")
    provider_manifest = graph_generation.get("provider_manifest")
    mechanical = graph_generation.get("mechanical_graph")
    handoff = graph_generation.get("depth_handoff")
    if (
        not isinstance(provider_manifest, Mapping)
        or set(provider_manifest) != {
            "state", "artifact_identity", "artifact_sha256",
            "provider_generation_sha256",
        }
        or provider_manifest.get("state") not in {"BOUND", "ABSENT"}
        or not isinstance(mechanical, Mapping)
        or set(mechanical) != {
            "artifact_identity", "artifact_sha256", "bytes", "schema_version",
            "provider", "provider_authority",
        }
        or not isinstance(handoff, Mapping)
        or set(handoff) != {
            "artifact_identity", "artifact_sha256", "schema_version",
            "depth_candidates_artifact_identity", "depth_candidates_sha256",
        }
    ):
        _fail("graph generation source binding is malformed")
    for identity in (
        provider_manifest.get("artifact_identity"),
        mechanical.get("artifact_identity"), handoff.get("artifact_identity"),
        handoff.get("depth_candidates_artifact_identity"),
    ):
        _artifact_identity(identity, label="graph generation artifact")
    for value, label in (
        (mechanical.get("artifact_sha256"), "mechanical graph digest"),
        (handoff.get("artifact_sha256"), "depth handoff digest"),
        (handoff.get("depth_candidates_sha256"), "depth candidates digest"),
    ):
        _hex(value, label=label)
    provider_authority = mechanical.get("provider_authority")
    if not isinstance(provider_authority, Mapping) or set(provider_authority) != {
        "provider", "authority_kind", "tool_id", "admission_state",
        "tool_row_sha256",
    }:
        _fail("mechanical graph provider authority is malformed")
    if provider_authority.get("provider") != mechanical.get("provider"):
        _fail("mechanical graph provider authority differs")
    if provider_authority.get("authority_kind") not in {
        "BUILTIN_SOURCE_PROVIDER", "WORKSPACE_TOOL", "UNDECLARED"
    }:
        _fail("mechanical graph provider authority kind is malformed")
    if provider_authority.get("tool_row_sha256") is not None:
        _hex(provider_authority["tool_row_sha256"], label="provider tool row")
    if provider_manifest["state"] == "BOUND":
        _hex(provider_manifest.get("artifact_sha256"), label="provider manifest digest")
        _hex(provider_manifest.get("provider_generation_sha256"), label="provider generation digest")
    elif (
        provider_manifest.get("artifact_sha256") is not None
        or provider_manifest.get("provider_generation_sha256") is not None
    ):
        _fail("absent provider-generation manifest carries digests")
    generation_unsigned = {
        "workspace_reference_sha256": workspace["reference_sha256"],
        "snapshot_sha256": result["snapshot_sha256"],
        "mechanical_graph_sha256": mechanical["artifact_sha256"],
        "depth_handoff_receipt_sha256": handoff["artifact_sha256"],
        "depth_candidates_sha256": handoff["depth_candidates_sha256"],
        "provider_generation_sha256": provider_manifest["provider_generation_sha256"],
        "element_denominator_sha256": result["element_denominator_sha256"],
    }
    if generation != _digest(generation_unsigned):
        _fail("graph generation digest does not bind its sources")
    expected_full_availability = {
        "workspace_reference_sha256": workspace.get("reference_sha256"),
        "snapshot_sha256": result.get("snapshot_sha256"),
        "generation_sha256": generation,
        "mechanical_graph_sha256": (
            graph_generation.get("mechanical_graph", {}).get("artifact_sha256")
            if isinstance(graph_generation.get("mechanical_graph"), Mapping)
            else None
        ),
        "depth_handoff_receipt_sha256": (
            graph_generation.get("depth_handoff", {}).get("artifact_sha256")
            if isinstance(graph_generation.get("depth_handoff"), Mapping)
            else None
        ),
        "depth_candidates_sha256": (
            graph_generation.get("depth_handoff", {}).get("depth_candidates_sha256")
            if isinstance(graph_generation.get("depth_handoff"), Mapping)
            else None
        ),
        "element_denominator_sha256": result.get("element_denominator_sha256"),
    }
    if dict(full_availability) != expected_full_availability:
        _fail("full graph availability binding differs from source authorities")
    expected_unassigned = sorted(valid_ids - assigned_union)
    if (
        unassigned != expected_unassigned
        or result.get("assignment_pair_count") != assignment_pair_count
        or assignment_pair_count > _MAX_ASSIGNMENT_PAIRS
        or len(canonical_file_bytes(result)) > _MAX_ARTIFACT_BYTES
    ):
        _fail("graph assignment coverage/count/size authority differs")
    debt_keys: list[tuple[str, str]] = []
    for debt in debts:
        if not isinstance(debt, Mapping) or set(debt) != {"code", "subject", "reason"}:
            _fail("graph authority debt row is malformed")
        key = (
            _text(debt.get("code"), label="graph debt code", maximum=128),
            _text(debt.get("subject"), label="graph debt subject", maximum=1_024),
        )
        _text(debt.get("reason"), label="graph debt reason")
        debt_keys.append(key)
    if debt_keys != sorted(debt_keys) or len(debt_keys) != len(set(debt_keys)):
        _fail("graph authority debt denominator is unsorted or duplicate")
    derived_debts = _derive_authority_debts(result)
    if debts != derived_debts:
        _fail("graph authority typed debt denominator differs from exact replay")
    expected_state = "READY" if not derived_debts else "DEGRADED"
    if result["state"] != expected_state:
        _fail("graph authority state differs from exact debt replay")
    return result


def decode_graph_application_authority_test_only(
    raw: bytes,
    **expected: str,
) -> dict[str, Any]:
    """TEST_ONLY structural decoder; never returns committed authority."""
    value = _canonical_artifact(raw, label=AUTHORITY_ARTIFACT)
    return validate_graph_application_authority(value, **expected)


def _evidence_bindings(value: Mapping[str, str]) -> list[dict[str, str]]:
    if not isinstance(value, Mapping):
        _fail("evidence binding denominator is not a mapping")
    if len(value) > _MAX_EVIDENCE_BINDINGS:
        _fail("evidence binding denominator exceeds bound")
    rows: list[dict[str, str]] = []
    for identity, digest in value.items():
        rows.append({
            "artifact_identity": _artifact_identity(identity, label="evidence binding"),
            "artifact_sha256": _hex(digest, label="evidence binding digest"),
        })
    rows.sort(key=lambda row: row["artifact_identity"])
    if len(rows) != len({row["artifact_identity"] for row in rows}):
        _fail("evidence binding roster contains duplicates")
    return rows


def _require_evidence_producer_topology(
    contract: PhaseIOContract,
    authority: Mapping[str, Any],
    evidence: Sequence[Mapping[str, str]],
) -> None:
    """Bind every evidence artifact to its scheduled consumer work unit.

    PhaseIO proves that an input came from *a* committed producer.  Graph
    application additionally proves that it came from the exact downstream
    consumer scheduled to emit that evidence, preventing an unrelated
    committed work unit from laundering bytes into a clean observation.
    """

    requirements = {
        row.identity: row for row in contract.input_authority_requirements
    }
    consumers = authority.get("consumers")
    if not isinstance(consumers, list):
        _fail("graph authority consumer topology is malformed")
    for binding in evidence:
        identity = binding["artifact_identity"]
        producer_keys: set[str] = set()
        for consumer in consumers:
            if identity not in consumer.get("evidence_artifacts", ()):
                continue
            consumer_id = str(consumer.get("consumer_id") or "")
            phase = str(consumer.get("phase") or "")
            parts = consumer_id.split("/", 1)
            if len(parts) != 2 or parts[0] != phase:
                _fail("scheduled evidence consumer identity is malformed")
            producer_keys.add(_producer_key(contract, phase, parts[1]))
        requirement = requirements.get(identity)
        if (
            len(producer_keys) != 1
            or type(requirement) is not InputAuthorityRequirement
            or requirement.expected_producer_work_unit_key
            != next(iter(producer_keys), None)
        ):
            _fail(
                "observation evidence producer differs from scheduled "
                "consumer: " + identity
            )


def _build_graph_application_observations_payload(
    *,
    authority: Mapping[str, Any],
    expected_consumer_denominator_sha256: str,
    expected_scheduler_artifact_sha256: str,
    evidence_artifact_sha256: Mapping[str, str],
    consumer_observations: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Build exact structured consumer observations.

    The consumer roster may be incomplete: reconciliation converts every
    absent consumer/element into explicit debt.  Rows that are present must be
    exact, unique, and authorized by the availability record.
    """

    authority = validate_graph_application_authority(
        authority,
        expected_consumer_denominator_sha256=(
            expected_consumer_denominator_sha256
        ),
        expected_scheduler_artifact_sha256=expected_scheduler_artifact_sha256,
    )
    bindings = _evidence_bindings(evidence_artifact_sha256)
    bound = {row["artifact_identity"]: row["artifact_sha256"] for row in bindings}
    requirements = {row["consumer_id"]: row for row in authority["consumers"]}
    if isinstance(consumer_observations, (str, bytes)) or not isinstance(consumer_observations, Sequence):
        _fail("consumer observations is not a sequence")
    if len(consumer_observations) > _MAX_CONSUMERS:
        _fail("consumer observation roster exceeds bound")
    rows: list[dict[str, Any]] = []
    seen_consumers: set[str] = set()
    outcome_count = 0
    evidence_row_count = 0
    evidence_locus_count = 0
    used_evidence_artifacts: set[str] = set()
    for raw_row in consumer_observations:
        if not isinstance(raw_row, Mapping) or set(raw_row) != {
            "consumer_id", "full_availability_acknowledgement", "outcomes"
        }:
            _fail("consumer observation row has unknown/missing fields")
        consumer_id = str(raw_row.get("consumer_id") or "")
        if consumer_id in seen_consumers:
            _fail(f"duplicate consumer observation: {consumer_id}")
        seen_consumers.add(consumer_id)
        requirement = requirements.get(consumer_id)
        if requirement is None:
            _fail(f"observation names undeclared consumer: {consumer_id}")
        outcomes = raw_row.get("outcomes")
        if not isinstance(outcomes, list):
            _fail(f"consumer outcomes is not an array: {consumer_id}")
        outcome_count += len(outcomes)
        if outcome_count > _MAX_ASSIGNMENT_PAIRS:
            _fail("consumer outcome denominator exceeds bound")
        assigned = set(requirement["assigned_element_ids"])
        accepted_artifacts = set(requirement["evidence_artifacts"])
        acknowledgement = raw_row.get("full_availability_acknowledgement")
        if acknowledgement is not None:
            if not isinstance(acknowledgement, Mapping):
                _fail("full availability acknowledgement is malformed")
            if dict(acknowledgement) != dict(authority["full_availability"]):
                _fail("full availability acknowledgement is stale/different")
            normalized_acknowledgement: dict[str, Any] | None = dict(acknowledgement)
        else:
            normalized_acknowledgement = None
        outcome_rows: list[dict[str, Any]] = []
        seen_elements: set[str] = set()
        for outcome in outcomes:
            if not isinstance(outcome, Mapping):
                _fail("element outcome is not an object")
            allowed = {"element_id", "disposition", "evidence", "conclusion", "debt"}
            if set(outcome) != allowed:
                _fail("element outcome has unknown/missing fields")
            element_id = str(outcome.get("element_id") or "")
            if element_id not in assigned:
                _fail(f"outcome element is outside consumer assignment: {consumer_id}:{element_id}")
            if element_id in seen_elements:
                _fail(f"duplicate/conflicting element outcome: {consumer_id}:{element_id}")
            seen_elements.add(element_id)
            disposition = outcome.get("disposition")
            if disposition not in DISPOSITIONS:
                _fail("element outcome disposition is malformed")
            conclusion = _text(outcome.get("conclusion"), label="outcome conclusion")
            evidence = outcome.get("evidence")
            if (
                not isinstance(evidence, list)
                or len(evidence) > _MAX_EVIDENCE_ROWS_PER_OUTCOME
            ):
                _fail("element outcome evidence is not an array")
            evidence_row_count += len(evidence)
            if evidence_row_count > _MAX_OBSERVATION_EVIDENCE_ROWS:
                _fail("observation evidence-row denominator exceeds bound")
            evidence_rows: list[dict[str, Any]] = []
            evidence_keys: set[tuple[str, tuple[str, ...]]] = set()
            for evidence_row in evidence:
                if not isinstance(evidence_row, Mapping) or set(evidence_row) != {"artifact_identity", "artifact_sha256", "loci"}:
                    _fail("outcome evidence row is malformed")
                artifact = _artifact_identity(evidence_row.get("artifact_identity"), label="outcome evidence artifact")
                artifact_sha256 = _hex(evidence_row.get("artifact_sha256"), label="outcome evidence digest")
                loci = evidence_row.get("loci")
                if (
                    artifact not in accepted_artifacts
                    or bound.get(artifact) != artifact_sha256
                    or not isinstance(loci, list)
                    or not loci
                    or len(loci) > _MAX_EVIDENCE_LOCI_PER_ROW
                    or any(not isinstance(locus, str) or _LOCUS.fullmatch(locus) is None for locus in loci)
                    or loci != sorted(loci)
                    or len(loci) != len(set(loci))
                ):
                    _fail("outcome evidence is unauthorized, stale, or malformed")
                key = (artifact, tuple(loci))
                if key in evidence_keys:
                    _fail("duplicate outcome evidence row")
                evidence_keys.add(key)
                evidence_locus_count += len(loci)
                if evidence_locus_count > _MAX_OBSERVATION_EVIDENCE_LOCI:
                    _fail("observation evidence-locus denominator exceeds bound")
                used_evidence_artifacts.add(artifact)
                evidence_rows.append({
                    "artifact_identity": artifact,
                    "artifact_sha256": artifact_sha256,
                    "loci": loci,
                })
            evidence_rows.sort(key=lambda row: (row["artifact_identity"], row["loci"]))
            debt = outcome.get("debt")
            if disposition == "NOT_APPLIED":
                if evidence_rows or not isinstance(debt, Mapping) or set(debt) != {"code", "reason"}:
                    _fail("NOT_APPLIED requires zero evidence and one typed debt")
                code = debt.get("code")
                if code not in _ALLOWED_DEBT_CODES:
                    _fail("NOT_APPLIED debt code is unsupported")
                normalized_debt: dict[str, str] | None = {
                    "code": str(code),
                    "reason": _text(debt.get("reason"), label="outcome debt reason"),
                }
            else:
                if not evidence_rows or debt is not None:
                    _fail("REFERENCED/APPLIED requires evidence and no debt")
                normalized_debt = None
            outcome_rows.append({
                "element_id": element_id,
                "disposition": disposition,
                "evidence": evidence_rows,
                "conclusion": conclusion,
                "debt": normalized_debt,
            })
        outcome_rows.sort(key=lambda row: row["element_id"])
        unsigned = {
            "consumer_id": consumer_id,
            "assignment_sha256": requirement["assignment_sha256"],
            "full_availability_acknowledgement": normalized_acknowledgement,
            "outcomes": outcome_rows,
        }
        rows.append({**unsigned, "observation_sha256": _digest(unsigned)})
    rows.sort(key=lambda row: row["consumer_id"])
    if set(bound) != used_evidence_artifacts:
        _fail("evidence binding denominator differs from referenced evidence")
    unsigned = {
        "schema_version": OBSERVATIONS_SCHEMA,
        "state": "RECORDED",
        "run_id": authority["run_id"],
        "snapshot_sha256": authority["snapshot_sha256"],
        "generation_sha256": authority["graph_generation"]["generation_sha256"],
        "authority_sha256": authority["authority_sha256"],
        "evidence_artifacts": bindings,
        "consumers": rows,
        "consumer_observation_count": len(rows),
        "element_outcome_count": outcome_count,
    }
    result = {**unsigned, "observations_sha256": _digest(unsigned)}
    if len(canonical_file_bytes(result)) > _MAX_ARTIFACT_BYTES:
        _fail("graph application observations exceeds serialized byte bound")
    return result


def _replay_committed_authority_token(
    token: CommittedGraphApplicationAuthority,
    __verifier: Any = _require_committed_token,
) -> dict[str, Any]:
    if type(token) is not CommittedGraphApplicationAuthority:
        _fail("production graph operation requires committed authority token")
    __verifier(
        token,
        cls=CommittedGraphApplicationAuthority,
        kind="committed graph application authority",
    )
    _revalidate_token_commit(
        token,
        artifact_identity=f"scratchpad:{AUTHORITY_ARTIFACT}",
        schema_version=AUTHORITY_SCHEMA,
        phase="inventory",
        work_unit_id="graph_application.authority",
    )
    if _raw_digest(token.canonical_bytes) != token.artifact_sha256:
        _fail("committed graph-authority token bytes were mutated")
    value = decode_graph_application_authority_test_only(
        token.canonical_bytes,
    )
    if dict(token.payload) != value:
        _fail("committed graph-authority token payload differs from bytes")
    return value


def build_graph_application_observations(
    *,
    committed_authority: CommittedGraphApplicationAuthority,
    evidence_artifact_sha256: Mapping[str, str],
    consumer_observations: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Build observations only from a ledger-authenticated authority token."""
    authority = _replay_committed_authority_token(
        committed_authority,
    )
    expected_consumer_denominator_sha256 = authority[
        "consumer_denominator_sha256"
    ]
    expected_scheduler_artifact_sha256 = authority[
        "consumer_roster"
    ]["scheduler_artifact_sha256"]
    return _build_graph_application_observations_payload(
        authority=authority,
        expected_consumer_denominator_sha256=(
            expected_consumer_denominator_sha256
        ),
        expected_scheduler_artifact_sha256=expected_scheduler_artifact_sha256,
        evidence_artifact_sha256=evidence_artifact_sha256,
        consumer_observations=consumer_observations,
    )


def validate_graph_application_observations(
    value: object,
    *,
    authority: Mapping[str, Any],
    expected_consumer_denominator_sha256: str,
    expected_scheduler_artifact_sha256: str,
    expected_evidence_artifact_sha256: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    authority = validate_graph_application_authority(
        authority,
        expected_consumer_denominator_sha256=(
            expected_consumer_denominator_sha256
        ),
        expected_scheduler_artifact_sha256=expected_scheduler_artifact_sha256,
    )
    result = _validate_terminal_digest(
        value,
        schema=OBSERVATIONS_SCHEMA,
        digest_field="observations_sha256",
        states=frozenset({"RECORDED"}),
    )
    if (
        result.get("run_id") != authority["run_id"]
        or result.get("snapshot_sha256") != authority["snapshot_sha256"]
        or result.get("generation_sha256") != authority["graph_generation"]["generation_sha256"]
        or result.get("authority_sha256") != authority["authority_sha256"]
    ):
        _fail("graph observations lineage differs from authority")
    evidence_rows = result.get("evidence_artifacts")
    consumer_rows = result.get("consumers")
    if not isinstance(evidence_rows, list) or not isinstance(consumer_rows, list):
        _fail("graph observations rosters are malformed")
    observed_evidence: dict[str, str] = {}
    for row in evidence_rows:
        if not isinstance(row, Mapping) or set(row) != {"artifact_identity", "artifact_sha256"}:
            _fail("graph observations evidence binding is malformed")
        identity = _artifact_identity(row["artifact_identity"], label="observations evidence")
        digest = _hex(row["artifact_sha256"], label="observations evidence digest")
        if identity in observed_evidence:
            _fail("graph observations evidence roster duplicates")
        observed_evidence[identity] = digest
    if list(observed_evidence) != sorted(observed_evidence):
        _fail("graph observations evidence roster is unsorted")
    if expected_evidence_artifact_sha256 is not None:
        if observed_evidence != dict(expected_evidence_artifact_sha256):
            _fail("graph observations evidence bytes are stale/different")
    requirements = {row["consumer_id"]: row for row in authority["consumers"]}
    consumer_ids: list[str] = []
    outcome_count = 0
    for row in consumer_rows:
        if not isinstance(row, Mapping):
            _fail("graph consumer observation is malformed")
        unsigned = dict(row)
        stored = unsigned.pop("observation_sha256", None)
        if _digest(unsigned) != stored:
            _fail("graph consumer observation digest differs")
        consumer_id = row.get("consumer_id")
        requirement = requirements.get(consumer_id)
        outcomes = row.get("outcomes")
        if (
            requirement is None
            or row.get("assignment_sha256") != requirement["assignment_sha256"]
            or not isinstance(outcomes, list)
        ):
            _fail("graph consumer observation authority differs")
        outcome_count += len(outcomes)
        assigned = set(requirement["assigned_element_ids"])
        acknowledgement = row.get("full_availability_acknowledgement")
        if acknowledgement is not None and acknowledgement != authority["full_availability"]:
            _fail("graph consumer full availability acknowledgement differs")
        element_ids: list[str] = []
        for outcome in outcomes:
            if not isinstance(outcome, Mapping) or outcome.get("element_id") not in assigned:
                _fail("graph element observation is outside assignment")
            element_ids.append(outcome["element_id"])
            for evidence in outcome.get("evidence", []):
                if observed_evidence.get(evidence.get("artifact_identity")) != evidence.get("artifact_sha256"):
                    _fail("graph element evidence is stale/different")
        if element_ids != sorted(element_ids) or len(element_ids) != len(set(element_ids)):
            _fail("graph element observations are unsorted or duplicate")
        consumer_ids.append(consumer_id)
    if consumer_ids != sorted(consumer_ids) or len(consumer_ids) != len(set(consumer_ids)):
        _fail("graph consumer observations are unsorted or duplicate")
    if (
        result.get("consumer_observation_count") != len(consumer_rows)
        or result.get("element_outcome_count") != outcome_count
        or outcome_count > _MAX_ASSIGNMENT_PAIRS
        or len(canonical_file_bytes(result)) > _MAX_ARTIFACT_BYTES
    ):
        _fail("graph observation counts differ")
    rebuilt = _build_graph_application_observations_payload(
        authority=authority,
        expected_consumer_denominator_sha256=(
            expected_consumer_denominator_sha256
        ),
        expected_scheduler_artifact_sha256=expected_scheduler_artifact_sha256,
        evidence_artifact_sha256=observed_evidence,
        consumer_observations=[
            {
                "consumer_id": row["consumer_id"],
                "full_availability_acknowledgement": row.get(
                    "full_availability_acknowledgement"
                ),
                "outcomes": row["outcomes"],
            }
            for row in consumer_rows
        ],
    )
    if rebuilt != result:
        _fail("graph observations differ from exact normalized replay")
    return result


def decode_graph_application_observations_test_only(
    raw: bytes,
    *,
    authority: Mapping[str, Any],
    expected_consumer_denominator_sha256: str,
    expected_scheduler_artifact_sha256: str,
    expected_evidence_artifact_sha256: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    value = _canonical_artifact(raw, label=OBSERVATIONS_ARTIFACT)
    return validate_graph_application_observations(
        value,
        authority=authority,
        expected_consumer_denominator_sha256=(
            expected_consumer_denominator_sha256
        ),
        expected_scheduler_artifact_sha256=expected_scheduler_artifact_sha256,
        expected_evidence_artifact_sha256=expected_evidence_artifact_sha256,
    )


def _reconcile_graph_application_payload(
    *,
    authority: Mapping[str, Any],
    observations: Mapping[str, Any],
    expected_consumer_denominator_sha256: str,
    expected_scheduler_artifact_sha256: str,
) -> dict[str, Any]:
    """Reconcile every required consumer/element pair without vacuous pass."""

    authority = validate_graph_application_authority(
        authority,
        expected_consumer_denominator_sha256=(
            expected_consumer_denominator_sha256
        ),
        expected_scheduler_artifact_sha256=expected_scheduler_artifact_sha256,
    )
    observations = validate_graph_application_observations(
        observations,
        authority=authority,
        expected_consumer_denominator_sha256=(
            expected_consumer_denominator_sha256
        ),
        expected_scheduler_artifact_sha256=expected_scheduler_artifact_sha256,
    )
    observed = {row["consumer_id"]: row for row in observations["consumers"]}
    result_rows: list[dict[str, Any]] = []
    debts: list[dict[str, str]] = [dict(row) for row in authority["debts"]]
    rank = {"NOT_APPLIED": 0, "REFERENCED": 1, "APPLIED": 2}
    reconciled_pairs = 0
    required_pairs = 0
    for requirement in authority["consumers"]:
        consumer_id = requirement["consumer_id"]
        observation = observed.get(consumer_id)
        outcomes = {
            row["element_id"]: row
            for row in (observation.get("outcomes", []) if observation else [])
        }
        required = requirement["assigned_element_ids"]
        required_pairs += len(required)
        counts = {"APPLIED": 0, "REFERENCED": 0, "NOT_APPLIED": 0, "OMITTED": 0}
        consumer_debts: list[dict[str, str]] = []
        if observation is None:
            consumer_debts.append({
                "code": "CONSUMER_OBSERVATION_ABSENT",
                "subject": consumer_id,
                "reason": "required downstream phase/agent emitted no structured observation",
            })
        elif observation.get("full_availability_acknowledgement") != authority["full_availability"]:
            consumer_debts.append({
                "code": "FULL_AVAILABILITY_ACKNOWLEDGEMENT_ABSENT",
                "subject": consumer_id,
                "reason": (
                    "consumer did not acknowledge the exact complete workspace/"
                    "graph/generation/handoff availability binding"
                ),
            })
        for element_id in required:
            outcome = outcomes.get(element_id)
            if outcome is None:
                counts["OMITTED"] += 1
                consumer_debts.append({
                    "code": "ELEMENT_OUTCOME_OMITTED",
                    "subject": f"{consumer_id}:{element_id}",
                    "reason": "available graph element has no consumer disposition",
                })
                continue
            disposition = outcome["disposition"]
            counts[disposition] += 1
            reconciled_pairs += 1
            if disposition == "NOT_APPLIED":
                consumer_debts.append({
                    "code": f"NOT_APPLIED:{outcome['debt']['code']}",
                    "subject": f"{consumer_id}:{element_id}",
                    "reason": outcome["debt"]["reason"],
                })
            elif rank[disposition] < rank[requirement["minimum_disposition"]]:
                consumer_debts.append({
                    "code": "MINIMUM_DISPOSITION_UNMET",
                    "subject": f"{consumer_id}:{element_id}",
                    "reason": (
                        f"{disposition} is below required "
                        f"{requirement['minimum_disposition']}"
                    ),
                })
        consumer_status = "COMPLETE" if not consumer_debts and required else "DEGRADED"
        row_unsigned = {
            "consumer_id": consumer_id,
            "assignment_sha256": requirement["assignment_sha256"],
            "full_availability_acknowledged": bool(
                observation is not None
                and observation.get("full_availability_acknowledgement")
                == authority["full_availability"]
            ),
            "observation_sha256": (
                observation["observation_sha256"] if observation else None
            ),
            "status": consumer_status,
            "required_element_count": len(required),
            "outcome_counts": counts,
            "debts": consumer_debts,
        }
        result_rows.append({**row_unsigned, "consumer_result_sha256": _digest(row_unsigned)})
        debts.extend(consumer_debts)
    all_consumers_complete = all(
        row["status"] == "COMPLETE" for row in result_rows
    )
    state = (
        "COMPLETE"
        if (
            authority["state"] == "READY"
            and not debts
            and required_pairs > 0
            and all_consumers_complete
            and len(result_rows) == authority["consumer_count"]
        )
        else "DEGRADED"
    )
    unsigned = {
        "schema_version": RECONCILIATION_SCHEMA,
        "state": state,
        "run_id": authority["run_id"],
        "snapshot_sha256": authority["snapshot_sha256"],
        "workspace_reference_sha256": authority["workspace"]["reference_sha256"],
        "generation_sha256": authority["graph_generation"]["generation_sha256"],
        "depth_handoff_receipt_sha256": authority["graph_generation"]["depth_handoff"]["artifact_sha256"],
        "authority_sha256": authority["authority_sha256"],
        "observations_sha256": observations["observations_sha256"],
        "element_denominator_sha256": authority["element_denominator_sha256"],
        "consumer_denominator_sha256": authority["consumer_denominator_sha256"],
        "required_pair_count": required_pairs,
        "reconciled_pair_count": reconciled_pairs,
        "consumers": result_rows,
        "debts": debts,
    }
    result = {**unsigned, "reconciliation_sha256": _digest(unsigned)}
    if len(canonical_file_bytes(result)) > _MAX_ARTIFACT_BYTES:
        _fail("graph application reconciliation exceeds serialized byte bound")
    return result


def _replay_committed_observations_token(
    token: CommittedGraphApplicationObservations,
    *,
    authority: Mapping[str, Any],
    expected_consumer_denominator_sha256: str,
    expected_scheduler_artifact_sha256: str,
    __verifier: Any = _require_committed_token,
) -> dict[str, Any]:
    if type(token) is not CommittedGraphApplicationObservations:
        _fail("production reconciliation requires committed observations token")
    __verifier(
        token,
        cls=CommittedGraphApplicationObservations,
        kind="committed graph application observations",
    )
    _revalidate_token_commit(
        token,
        artifact_identity=f"scratchpad:{OBSERVATIONS_ARTIFACT}",
        schema_version=OBSERVATIONS_SCHEMA,
        phase="chain",
        work_unit_id="graph_application.observations",
    )
    if _raw_digest(token.canonical_bytes) != token.artifact_sha256:
        _fail("committed graph-observations token bytes were mutated")
    value = decode_graph_application_observations_test_only(
        token.canonical_bytes,
        authority=authority,
        expected_consumer_denominator_sha256=(
            expected_consumer_denominator_sha256
        ),
        expected_scheduler_artifact_sha256=expected_scheduler_artifact_sha256,
    )
    if dict(token.payload) != value:
        _fail("committed graph-observations token payload differs from bytes")
    return value


def reconcile_graph_application(
    *,
    committed_authority: CommittedGraphApplicationAuthority,
    committed_observations: CommittedGraphApplicationObservations,
) -> dict[str, Any]:
    """Reconcile only ledger-authenticated parent artifacts."""
    authority = _replay_committed_authority_token(
        committed_authority,
    )
    expected_consumer_denominator_sha256 = authority[
        "consumer_denominator_sha256"
    ]
    expected_scheduler_artifact_sha256 = authority[
        "consumer_roster"
    ]["scheduler_artifact_sha256"]
    observations = _replay_committed_observations_token(
        committed_observations,
        authority=authority,
        expected_consumer_denominator_sha256=(
            expected_consumer_denominator_sha256
        ),
        expected_scheduler_artifact_sha256=expected_scheduler_artifact_sha256,
    )
    return _reconcile_graph_application_payload(
        authority=authority,
        observations=observations,
        expected_consumer_denominator_sha256=(
            expected_consumer_denominator_sha256
        ),
        expected_scheduler_artifact_sha256=expected_scheduler_artifact_sha256,
    )


def validate_graph_application_reconciliation(
    value: object,
    *,
    authority: Mapping[str, Any],
    observations: Mapping[str, Any],
    expected_consumer_denominator_sha256: str,
    expected_scheduler_artifact_sha256: str,
) -> dict[str, Any]:
    """Replay reconciliation byte-for-byte from its two immutable parents."""

    result = _validate_terminal_digest(
        value,
        schema=RECONCILIATION_SCHEMA,
        digest_field="reconciliation_sha256",
        states=RECONCILIATION_STATES,
    )
    expected = _reconcile_graph_application_payload(
        authority=authority,
        observations=observations,
        expected_consumer_denominator_sha256=(
            expected_consumer_denominator_sha256
        ),
        expected_scheduler_artifact_sha256=expected_scheduler_artifact_sha256,
    )
    if result != expected:
        _fail("graph application reconciliation differs from exact replay")
    if result["state"] == "COMPLETE" and (
        result["debts"]
        or result["required_pair_count"] <= 0
        or result["reconciled_pair_count"] != result["required_pair_count"]
        or any(row.get("status") != "COMPLETE" for row in result["consumers"])
    ):
        _fail("COMPLETE graph reconciliation is vacuous or contains debt")
    return result


def decode_graph_application_reconciliation_test_only(
    raw: bytes,
    *,
    authority: Mapping[str, Any],
    observations: Mapping[str, Any],
    expected_consumer_denominator_sha256: str,
    expected_scheduler_artifact_sha256: str,
) -> dict[str, Any]:
    value = _canonical_artifact(raw, label=RECONCILIATION_ARTIFACT)
    return validate_graph_application_reconciliation(
        value,
        authority=authority,
        observations=observations,
        expected_consumer_denominator_sha256=(
            expected_consumer_denominator_sha256
        ),
        expected_scheduler_artifact_sha256=expected_scheduler_artifact_sha256,
    )


def _read_bound_identity(
    scratchpad: Path,
    project_root: Path,
    identity: str,
    *,
    limit: int,
) -> bytes:
    identity = _artifact_identity(identity, label="bound artifact")
    root_name, relative = identity.split(":", 1)
    target = (Path(scratchpad) if root_name == "scratchpad" else Path(project_root)) / relative
    try:
        raw = rooted_path_io.read_bytes(
            target, label=identity, require_single_link=True
        )
    except (OSError, rooted_path_io.RootedPathIOError) as exc:
        _fail(f"bound artifact cannot be replayed: {identity}", exc)
    return _bounded_bytes(raw, label=identity, limit=limit)


def _require_exact_contract_inputs(
    contract: PhaseIOContract,
    expected: set[str],
) -> None:
    actual = set(contract.immutable_inputs) | set(contract.bounded_lookup_inputs)
    if actual != expected:
        _fail(
            "production PhaseIO input denominator differs; expected "
            f"{sorted(expected)}, got {sorted(actual)}"
        )


def _assert_token_on_disk(
    token: object,
    *,
    scratchpad: Path,
    project_root: Path,
    identity: str,
) -> None:
    raw = _read_bound_identity(
        scratchpad, project_root, identity, limit=_MAX_ARTIFACT_BYTES
    )
    token_raw = getattr(token, "canonical_bytes", None)
    token_digest = getattr(token, "artifact_sha256", None)
    if raw != token_raw or _raw_digest(raw) != token_digest:
        _fail(f"committed parent bytes differ on disk: {identity}")


def _load_committed_graph_application_authority_impl(
    *,
    scratchpad: Path,
    project_root: Path,
    contract: PhaseIOContract,
    launch: LaunchSpec,
    committed_consumer_roster: CommittedGraphConsumerRoster,
    run_id: str,
    expected_snapshot_sha256: str,
    __issuer: Any,
) -> CommittedGraphApplicationAuthority:
    """Load and replay the committed authority and every exact source byte."""
    fixed = {
        _CONSUMER_ROSTER_IDENTITY: (
            "inventory", "graph_application.consumer_roster", "DRIVER",
            CONSUMER_ROSTER_SCHEMA,
        ),
        _WORKSPACE_ARTIFACT: (
            "recon", "evm_analysis_workspace_capture", "DRIVER", WORKSPACE_SCHEMA,
        ),
        _GRAPH_ARTIFACT: (
            "recon", "mechanical_graph", "DRIVER", "plamen.mechanical_graph.v2",
        ),
        _HANDOFF_ARTIFACT: (
            "inventory", "depth_handoff", "DRIVER",
            "plamen.depth_handoff_receipt.v1",
        ),
        _DEPTH_CANDIDATES_ARTIFACT: (
            "inventory", "depth_handoff", "DRIVER",
            "plamen.depth_candidates_projection.v1",
        ),
        _GRAPH_GENERATION_ARTIFACT: (
            "inventory", "graph_generation", "DRIVER",
            "plamen.mechanical_graph_generation.v1",
        ),
    }
    raw = _load_committed_driver_output(
        scratchpad=scratchpad,
        project_root=project_root,
        contract=contract,
        launch=launch,
        run_id=run_id,
        artifact_identity=f"scratchpad:{AUTHORITY_ARTIFACT}",
        schema_version=AUTHORITY_SCHEMA,
        phase="inventory",
        work_unit_id="graph_application.authority",
        limit=_MAX_ARTIFACT_BYTES,
        fixed_input_producers=fixed,
    )
    _assert_token_on_disk(
        committed_consumer_roster,
        scratchpad=scratchpad,
        project_root=project_root,
        identity=_CONSUMER_ROSTER_IDENTITY,
    )
    workspace_raw = _read_bound_identity(
        scratchpad, project_root, _WORKSPACE_ARTIFACT, limit=_MAX_CONTROL_BYTES
    )
    graph_raw = _read_bound_identity(
        scratchpad, project_root, _GRAPH_ARTIFACT, limit=_MAX_SOURCE_BYTES
    )
    handoff_raw = _read_bound_identity(
        scratchpad, project_root, _HANDOFF_ARTIFACT, limit=_MAX_CONTROL_BYTES
    )
    candidates_raw = _read_bound_identity(
        scratchpad,
        project_root,
        _DEPTH_CANDIDATES_ARTIFACT,
        limit=_MAX_SOURCE_BYTES,
    )
    generation_raw = _read_bound_identity(
        scratchpad,
        project_root,
        _GRAPH_GENERATION_ARTIFACT,
        limit=_MAX_CONTROL_BYTES,
    )
    expected = build_graph_application_authority(
        run_id=run_id,
        snapshot_sha256=expected_snapshot_sha256,
        workspace_receipt_raw=workspace_raw,
        mechanical_graph_raw=graph_raw,
        depth_handoff_receipt_raw=handoff_raw,
        depth_candidates_raw=candidates_raw,
        graph_generation_manifest_raw=generation_raw,
        committed_consumer_roster=committed_consumer_roster,
    )
    if raw != canonical_file_bytes(expected):
        _fail("committed graph authority differs from exact source replay")
    return __issuer(
        CommittedGraphApplicationAuthority,
        kind="committed graph application authority",
        payload=expected,
        canonical_bytes=raw,
        artifact_sha256=_raw_digest(raw),
        contract_digest=contract.digest,
        launch_digest=launch.digest,
        _commit_context=_commit_replay_context(
            scratchpad=scratchpad,
            project_root=project_root,
            contract=contract,
            launch=launch,
            run_id=run_id,
            artifact_identity=f"scratchpad:{AUTHORITY_ARTIFACT}",
            schema_version=AUTHORITY_SCHEMA,
            phase="inventory",
            work_unit_id="graph_application.authority",
            limit=_MAX_ARTIFACT_BYTES,
            fixed_input_producers=fixed,
        ),
    )


def _load_committed_graph_application_observations_impl(
    *,
    scratchpad: Path,
    project_root: Path,
    contract: PhaseIOContract,
    launch: LaunchSpec,
    committed_authority: CommittedGraphApplicationAuthority,
    run_id: str,
    expected_evidence_artifact_sha256: Mapping[str, str],
    __issuer: Any,
) -> CommittedGraphApplicationObservations:
    authority = _replay_committed_authority_token(
        committed_authority,
    )
    expected_consumer_denominator_sha256 = authority[
        "consumer_denominator_sha256"
    ]
    expected_scheduler_artifact_sha256 = authority[
        "consumer_roster"
    ]["scheduler_artifact_sha256"]
    evidence = _evidence_bindings(expected_evidence_artifact_sha256)
    expected_inputs = {f"scratchpad:{AUTHORITY_ARTIFACT}"} | {
        row["artifact_identity"] for row in evidence
    }
    _require_exact_contract_inputs(contract, expected_inputs)
    _require_evidence_producer_topology(contract, authority, evidence)
    fixed = {
        f"scratchpad:{AUTHORITY_ARTIFACT}": (
            "inventory", "graph_application.authority", "DRIVER",
            AUTHORITY_SCHEMA,
        )
    }
    raw = _load_committed_driver_output(
        scratchpad=scratchpad,
        project_root=project_root,
        contract=contract,
        launch=launch,
        run_id=run_id,
        artifact_identity=f"scratchpad:{OBSERVATIONS_ARTIFACT}",
        schema_version=OBSERVATIONS_SCHEMA,
        phase="chain",
        work_unit_id="graph_application.observations",
        limit=_MAX_ARTIFACT_BYTES,
        fixed_input_producers=fixed,
        fixed_inputs_exact=False,
    )
    _assert_token_on_disk(
        committed_authority,
        scratchpad=scratchpad,
        project_root=project_root,
        identity=f"scratchpad:{AUTHORITY_ARTIFACT}",
    )
    for row in evidence:
        evidence_raw = _read_bound_identity(
            scratchpad,
            project_root,
            row["artifact_identity"],
            limit=_MAX_SOURCE_BYTES,
        )
        if _raw_digest(evidence_raw) != row["artifact_sha256"]:
            _fail("committed observation evidence bytes differ")
    value = decode_graph_application_observations_test_only(
        raw,
        authority=authority,
        expected_consumer_denominator_sha256=(
            expected_consumer_denominator_sha256
        ),
        expected_scheduler_artifact_sha256=expected_scheduler_artifact_sha256,
        expected_evidence_artifact_sha256=expected_evidence_artifact_sha256,
    )
    return __issuer(
        CommittedGraphApplicationObservations,
        kind="committed graph application observations",
        payload=value,
        canonical_bytes=raw,
        artifact_sha256=_raw_digest(raw),
        contract_digest=contract.digest,
        launch_digest=launch.digest,
        _commit_context=_commit_replay_context(
            scratchpad=scratchpad,
            project_root=project_root,
            contract=contract,
            launch=launch,
            run_id=run_id,
            artifact_identity=f"scratchpad:{OBSERVATIONS_ARTIFACT}",
            schema_version=OBSERVATIONS_SCHEMA,
            phase="chain",
            work_unit_id="graph_application.observations",
            limit=_MAX_ARTIFACT_BYTES,
            fixed_input_producers=fixed,
            fixed_inputs_exact=False,
        ),
    )


def _load_committed_graph_application_reconciliation_impl(
    *,
    scratchpad: Path,
    project_root: Path,
    contract: PhaseIOContract,
    launch: LaunchSpec,
    committed_authority: CommittedGraphApplicationAuthority,
    committed_observations: CommittedGraphApplicationObservations,
    run_id: str,
    __issuer: Any,
) -> CommittedGraphApplicationReconciliation:
    authority = _replay_committed_authority_token(
        committed_authority,
    )
    expected_consumer_denominator_sha256 = authority[
        "consumer_denominator_sha256"
    ]
    expected_scheduler_artifact_sha256 = authority[
        "consumer_roster"
    ]["scheduler_artifact_sha256"]
    observations = _replay_committed_observations_token(
        committed_observations,
        authority=authority,
        expected_consumer_denominator_sha256=(
            expected_consumer_denominator_sha256
        ),
        expected_scheduler_artifact_sha256=expected_scheduler_artifact_sha256,
    )
    _require_exact_contract_inputs(contract, {
        f"scratchpad:{AUTHORITY_ARTIFACT}",
        f"scratchpad:{OBSERVATIONS_ARTIFACT}",
    })
    fixed = {
        f"scratchpad:{AUTHORITY_ARTIFACT}": (
            "inventory", "graph_application.authority", "DRIVER",
            AUTHORITY_SCHEMA,
        ),
        f"scratchpad:{OBSERVATIONS_ARTIFACT}": (
            "chain", "graph_application.observations", "DRIVER",
            OBSERVATIONS_SCHEMA,
        ),
    }
    raw = _load_committed_driver_output(
        scratchpad=scratchpad,
        project_root=project_root,
        contract=contract,
        launch=launch,
        run_id=run_id,
        artifact_identity=f"scratchpad:{RECONCILIATION_ARTIFACT}",
        schema_version=RECONCILIATION_SCHEMA,
        phase="chain",
        work_unit_id="graph_application.reconciliation",
        limit=_MAX_ARTIFACT_BYTES,
        fixed_input_producers=fixed,
    )
    _assert_token_on_disk(
        committed_authority,
        scratchpad=scratchpad,
        project_root=project_root,
        identity=f"scratchpad:{AUTHORITY_ARTIFACT}",
    )
    _assert_token_on_disk(
        committed_observations,
        scratchpad=scratchpad,
        project_root=project_root,
        identity=f"scratchpad:{OBSERVATIONS_ARTIFACT}",
    )
    expected = _reconcile_graph_application_payload(
        authority=authority,
        observations=observations,
        expected_consumer_denominator_sha256=(
            expected_consumer_denominator_sha256
        ),
        expected_scheduler_artifact_sha256=expected_scheduler_artifact_sha256,
    )
    if raw != canonical_file_bytes(expected):
        _fail("committed graph reconciliation differs from exact parent replay")
    return __issuer(
        CommittedGraphApplicationReconciliation,
        kind="committed graph application reconciliation",
        payload=expected,
        canonical_bytes=raw,
        artifact_sha256=_raw_digest(raw),
        contract_digest=contract.digest,
        launch_digest=launch.digest,
        _commit_context=_commit_replay_context(
            scratchpad=scratchpad,
            project_root=project_root,
            contract=contract,
            launch=launch,
            run_id=run_id,
            artifact_identity=f"scratchpad:{RECONCILIATION_ARTIFACT}",
            schema_version=RECONCILIATION_SCHEMA,
            phase="chain",
            work_unit_id="graph_application.reconciliation",
            limit=_MAX_ARTIFACT_BYTES,
            fixed_input_producers=fixed,
        ),
    )


def _replay_committed_reconciliation_token(
    token: CommittedGraphApplicationReconciliation,
    *,
    authority: Mapping[str, Any],
    observations: Mapping[str, Any],
    __verifier: Any = _require_committed_token,
) -> dict[str, Any]:
    __verifier(
        token,
        cls=CommittedGraphApplicationReconciliation,
        kind="committed graph application reconciliation",
    )
    _revalidate_token_commit(
        token,
        artifact_identity=f"scratchpad:{RECONCILIATION_ARTIFACT}",
        schema_version=RECONCILIATION_SCHEMA,
        phase="chain",
        work_unit_id="graph_application.reconciliation",
    )
    if _raw_digest(token.canonical_bytes) != token.artifact_sha256:
        _fail("committed reconciliation token bytes were mutated")
    value = decode_graph_application_reconciliation_test_only(
        token.canonical_bytes,
        authority=authority,
        observations=observations,
        expected_consumer_denominator_sha256=authority[
            "consumer_denominator_sha256"
        ],
        expected_scheduler_artifact_sha256=authority[
            "consumer_roster"
        ]["scheduler_artifact_sha256"],
    )
    if dict(token.payload) != value:
        _fail("committed reconciliation token payload differs from bytes")
    return value


def _install_committed_loaders(
    issuer: Any,
    roster_impl: Any,
    authority_impl: Any,
    observations_impl: Any,
    reconciliation_impl: Any,
) -> tuple[Any, Any, Any, Any]:
    """Close the mint capability inside fixed-signature production loaders."""

    def load_committed_graph_consumer_roster(
        *,
        scratchpad: Path,
        project_root: Path,
        contract: PhaseIOContract,
        launch: LaunchSpec,
        run_id: str,
        expected_snapshot_sha256: str,
    ) -> CommittedGraphConsumerRoster:
        return roster_impl(
            scratchpad=scratchpad,
            project_root=project_root,
            contract=contract,
            launch=launch,
            run_id=run_id,
            expected_snapshot_sha256=expected_snapshot_sha256,
            __issuer=issuer,
        )

    def load_committed_graph_application_authority(
        *,
        scratchpad: Path,
        project_root: Path,
        contract: PhaseIOContract,
        launch: LaunchSpec,
        committed_consumer_roster: CommittedGraphConsumerRoster,
        run_id: str,
        expected_snapshot_sha256: str,
    ) -> CommittedGraphApplicationAuthority:
        return authority_impl(
            scratchpad=scratchpad,
            project_root=project_root,
            contract=contract,
            launch=launch,
            committed_consumer_roster=committed_consumer_roster,
            run_id=run_id,
            expected_snapshot_sha256=expected_snapshot_sha256,
            __issuer=issuer,
        )

    def load_committed_graph_application_observations(
        *,
        scratchpad: Path,
        project_root: Path,
        contract: PhaseIOContract,
        launch: LaunchSpec,
        committed_authority: CommittedGraphApplicationAuthority,
        run_id: str,
        expected_evidence_artifact_sha256: Mapping[str, str],
    ) -> CommittedGraphApplicationObservations:
        return observations_impl(
            scratchpad=scratchpad,
            project_root=project_root,
            contract=contract,
            launch=launch,
            committed_authority=committed_authority,
            run_id=run_id,
            expected_evidence_artifact_sha256=(
                expected_evidence_artifact_sha256
            ),
            __issuer=issuer,
        )

    def load_committed_graph_application_reconciliation(
        *,
        scratchpad: Path,
        project_root: Path,
        contract: PhaseIOContract,
        launch: LaunchSpec,
        committed_authority: CommittedGraphApplicationAuthority,
        committed_observations: CommittedGraphApplicationObservations,
        run_id: str,
    ) -> CommittedGraphApplicationReconciliation:
        return reconciliation_impl(
            scratchpad=scratchpad,
            project_root=project_root,
            contract=contract,
            launch=launch,
            committed_authority=committed_authority,
            committed_observations=committed_observations,
            run_id=run_id,
            __issuer=issuer,
        )

    return (
        load_committed_graph_consumer_roster,
        load_committed_graph_application_authority,
        load_committed_graph_application_observations,
        load_committed_graph_application_reconciliation,
    )


(
    load_committed_graph_consumer_roster,
    load_committed_graph_application_authority,
    load_committed_graph_application_observations,
    load_committed_graph_application_reconciliation,
) = _install_committed_loaders(
    _issue_committed_token,
    _load_committed_graph_consumer_roster_impl,
    _load_committed_graph_application_authority_impl,
    _load_committed_graph_application_observations_impl,
    _load_committed_graph_application_reconciliation_impl,
)


# Production signatures expose neither mint nor verifier injection.  The
# implementation callables and process-local capabilities are absent from
# module scope after import; raw structural decoders remain TEST_ONLY.
del _install_committed_loaders
del _load_committed_graph_consumer_roster_impl
del _load_committed_graph_application_authority_impl
del _load_committed_graph_application_observations_impl
del _load_committed_graph_application_reconciliation_impl
del _issue_committed_token
del _require_committed_token


def integration_contract() -> dict[str, Any]:
    """Return stable artifact/ownership metadata for driver and assurance."""

    return {
        "schemas": {
            SCHEDULE_ARTIFACT: SCHEDULE_SCHEMA,
            CONSUMER_ROSTER_ARTIFACT: CONSUMER_ROSTER_SCHEMA,
            AUTHORITY_ARTIFACT: AUTHORITY_SCHEMA,
            OBSERVATIONS_ARTIFACT: OBSERVATIONS_SCHEMA,
            RECONCILIATION_ARTIFACT: RECONCILIATION_SCHEMA,
        },
        "producer_sequence": [
            {"artifact": SCHEDULE_ARTIFACT, "writer": "DRIVER", "phase": "recon"},
            {"artifact": CONSUMER_ROSTER_ARTIFACT, "writer": "DRIVER", "phase": "inventory"},
            {"artifact": AUTHORITY_ARTIFACT, "writer": "DRIVER", "phase": "inventory"},
            {"artifact": OBSERVATIONS_ARTIFACT, "writer": "DRIVER", "phase": "chain"},
            {"artifact": RECONCILIATION_ARTIFACT, "writer": "DRIVER", "phase": "chain"},
        ],
        "required_parent_artifacts": [
            _SCHEDULE_IDENTITY,
            _CONSUMER_ROSTER_IDENTITY,
            _WORKSPACE_ARTIFACT,
            _GRAPH_ARTIFACT,
            _HANDOFF_ARTIFACT,
            _DEPTH_CANDIDATES_ARTIFACT,
            _GRAPH_GENERATION_ARTIFACT,
        ],
        "optional_parent_artifacts": [],
        "consumer_activation": GRAPH_APPLICATION_CONSUMER_ACTIVATION,
        "terminal_complete_state": "COMPLETE",
    }


def validate_graph_application_assurance_phaseio(
    ledger: Mapping[str, Any],
    *,
    run_id: str,
    authority: Mapping[str, Any],
    observations: Mapping[str, Any],
    control_artifact_sha256: Mapping[str, str],
) -> None:
    """Prove the public control trio came from the closed PhaseIO chain.

    Structural decoding is intentionally available to final-report assurance,
    but it must never turn self-consistent, uncommitted JSON into a clean
    claim.  This replay checks the five driver-owned control producers, their
    exact input/output denominators, active commit receipts, and one shared
    pipeline/mode/ecosystem/backend namespace.
    """

    if not isinstance(ledger, Mapping):
        _fail("graph assurance artifact ledger is malformed")
    authority = validate_graph_application_authority(
        authority,
        expected_run_id=run_id,
    )
    observations = validate_graph_application_observations(
        observations,
        authority=authority,
        expected_consumer_denominator_sha256=authority[
            "consumer_denominator_sha256"
        ],
        expected_scheduler_artifact_sha256=authority[
            "consumer_roster"
        ]["scheduler_artifact_sha256"],
    )
    controls = {
        _artifact_identity(identity, label="graph assurance control"): _hex(
            digest, label="graph assurance control digest"
        )
        for identity, digest in control_artifact_sha256.items()
    }
    expected_control_identities = {
        f"scratchpad:{AUTHORITY_ARTIFACT}",
        f"scratchpad:{OBSERVATIONS_ARTIFACT}",
        f"scratchpad:{RECONCILIATION_ARTIFACT}",
    }
    if set(controls) != expected_control_identities:
        _fail("graph assurance control denominator differs")

    roster_owner = authority["consumer_roster"]["owner_work_unit_key"]
    roster_suffix = "/inventory/graph_application.consumer_roster"
    if not isinstance(roster_owner, str) or not roster_owner.endswith(roster_suffix):
        _fail("graph assurance roster owner namespace is malformed")
    namespace = roster_owner[: -len(roster_suffix)]
    if len(namespace.split("/")) != 4:
        _fail("graph assurance PhaseIO namespace is malformed")

    identities = {
        "schedule": _SCHEDULE_IDENTITY,
        "roster": _CONSUMER_ROSTER_IDENTITY,
        "authority": f"scratchpad:{AUTHORITY_ARTIFACT}",
        "observations": f"scratchpad:{OBSERVATIONS_ARTIFACT}",
        "reconciliation": f"scratchpad:{RECONCILIATION_ARTIFACT}",
    }
    keys = {
        "schedule": f"{namespace}/recon/graph_application.scheduler",
        "roster": roster_owner,
        "authority": f"{namespace}/inventory/graph_application.authority",
        "observations": f"{namespace}/chain/graph_application.observations",
        "reconciliation": f"{namespace}/chain/graph_application.reconciliation",
    }
    evidence_identities = {
        row["artifact_identity"] for row in observations["evidence_artifacts"]
    }
    expected_inputs = {
        "schedule": set(),
        "roster": {_SCHEDULE_IDENTITY},
        "authority": {
            _CONSUMER_ROSTER_IDENTITY,
            _WORKSPACE_ARTIFACT,
            _GRAPH_ARTIFACT,
            _HANDOFF_ARTIFACT,
            _DEPTH_CANDIDATES_ARTIFACT,
            _GRAPH_GENERATION_ARTIFACT,
        },
        "observations": {
            f"scratchpad:{AUTHORITY_ARTIFACT}", *evidence_identities,
        },
        "reconciliation": {
            f"scratchpad:{AUTHORITY_ARTIFACT}",
            f"scratchpad:{OBSERVATIONS_ARTIFACT}",
        },
    }
    fixed_producer_keys = {
        _SCHEDULE_IDENTITY: keys["schedule"],
        _CONSUMER_ROSTER_IDENTITY: keys["roster"],
        _WORKSPACE_ARTIFACT: (
            f"{namespace}/recon/evm_analysis_workspace_capture"
        ),
        _GRAPH_ARTIFACT: f"{namespace}/recon/mechanical_graph",
        _HANDOFF_ARTIFACT: f"{namespace}/inventory/depth_handoff",
        _DEPTH_CANDIDATES_ARTIFACT: f"{namespace}/inventory/depth_handoff",
        _GRAPH_GENERATION_ARTIFACT: f"{namespace}/inventory/graph_generation",
        f"scratchpad:{AUTHORITY_ARTIFACT}": keys["authority"],
        f"scratchpad:{OBSERVATIONS_ARTIFACT}": keys["observations"],
    }
    evidence_producer_keys: dict[str, str] = {}
    for identity in evidence_identities:
        candidates = {
            f"{namespace}/{consumer['phase']}/"
            f"{consumer['consumer_id'].split('/', 1)[1]}"
            for consumer in authority["consumers"]
            if identity in consumer["evidence_artifacts"]
        }
        if len(candidates) != 1:
            _fail(
                "graph assurance evidence producer topology is ambiguous: "
                + identity
            )
        evidence_producer_keys[identity] = next(iter(candidates))
    expected_producer_keys = {
        "schedule": {},
        "roster": {_SCHEDULE_IDENTITY: keys["schedule"]},
        "authority": {
            identity: fixed_producer_keys[identity]
            for identity in expected_inputs["authority"]
        },
        "observations": {
            f"scratchpad:{AUTHORITY_ARTIFACT}": keys["authority"],
            **evidence_producer_keys,
        },
        "reconciliation": {
            f"scratchpad:{AUTHORITY_ARTIFACT}": keys["authority"],
            f"scratchpad:{OBSERVATIONS_ARTIFACT}": keys["observations"],
        },
    }
    schemas = {
        "schedule": SCHEDULE_SCHEMA,
        "roster": CONSUMER_ROSTER_SCHEMA,
        "authority": AUTHORITY_SCHEMA,
        "observations": OBSERVATIONS_SCHEMA,
        "reconciliation": RECONCILIATION_SCHEMA,
    }
    work_units = ledger.get("work_units")
    bindings = ledger.get("artifact_bindings")
    if not isinstance(work_units, Mapping) or not isinstance(bindings, Mapping):
        _fail("graph assurance ledger authority maps are absent")
    for name in ("schedule", "roster", "authority", "observations", "reconciliation"):
        key = keys[name]
        identity = identities[name]
        issues = active_committed_work_unit_authority_issues(
            ledger,
            work_unit_key=key,
            run_id=run_id,
            expected_artifact_identities=(identity,),
        )
        unit = work_units.get(key)
        manifest = unit.get("contract_manifest") if isinstance(unit, Mapping) else None
        launch = unit.get("launch_manifest") if isinstance(unit, Mapping) else None
        outputs = manifest.get("outputs") if isinstance(manifest, Mapping) else None
        immutable = manifest.get("immutable_inputs") if isinstance(manifest, Mapping) else None
        bounded = manifest.get("bounded_lookup_inputs") if isinstance(manifest, Mapping) else None
        semantic_inputs = (
            set(immutable) | set(bounded)
            if isinstance(immutable, list)
            and isinstance(bounded, list)
            and all(isinstance(item, str) for item in immutable + bounded)
            else None
        )
        requirement_rows = (
            manifest.get("input_authority_requirements", [])
            if isinstance(manifest, Mapping)
            else None
        )
        requirement_map = (
            {
                row.get("identity"): row
                for row in requirement_rows
                if isinstance(row, Mapping)
            }
            if isinstance(requirement_rows, list)
            else None
        )
        exact_requirement_topology = bool(
            isinstance(requirement_rows, list)
            and isinstance(requirement_map, dict)
            and len(requirement_map) == len(requirement_rows)
            and set(requirement_map) == expected_inputs[name]
            and all(
                row.get("allow_raw") is False
                and row.get("require_same_run") is True
                and row.get("require_exact_contract") is True
                and row.get("require_exact_launch") is True
                and row.get("expected_producer_work_unit_key")
                == expected_producer_keys[name][identity]
                and (
                    row.get("expected_writer") in {"DRIVER", "MODEL"}
                    if identity in evidence_identities
                    else row.get("expected_writer") == "DRIVER"
                )
                and _HEX64.fullmatch(
                    str(row.get("expected_contract_digest") or "")
                )
                and _HEX64.fullmatch(
                    str(row.get("expected_launch_digest") or "")
                )
                for identity, row in requirement_map.items()
            )
        )
        binding = bindings.get(identity)
        expected_digest = controls.get(identity)
        if name == "schedule":
            expected_digest = authority["consumer_roster"][
                "scheduler_artifact_sha256"
            ]
        elif name == "roster":
            expected_digest = authority["consumer_roster"]["artifact_sha256"]
        if (
            issues
            or not isinstance(unit, Mapping)
            or not isinstance(manifest, Mapping)
            or manifest.get("key") != key
            or manifest.get("model_invoked") is not False
            or manifest.get("launch_profile") != "DRIVER_PYTHON_NO_TOOLS"
            or manifest.get("required_commit_actor") != "DRIVER"
            or semantic_inputs != expected_inputs[name]
            or not exact_requirement_topology
            or not isinstance(outputs, list)
            or len(outputs) != 1
            or not isinstance(outputs[0], Mapping)
            or outputs[0].get("identity") != identity
            or outputs[0].get("writer") != "DRIVER"
            or outputs[0].get("schema_version") != schemas[name]
            or not isinstance(launch, Mapping)
            or launch.get("work_unit_key") != key
            or launch.get("model") != "driver"
            or launch.get("exec_mode") != "python"
            or launch.get("tool_policy") != []
            or not isinstance(binding, Mapping)
            or binding.get("owner_key") != key
            or binding.get("run_id") != run_id
            or binding.get("status") != "ACTIVE"
            or binding.get("sha256") != expected_digest
        ):
            detail = "; ".join(issues) if issues else "closed topology differs"
            _fail(f"graph assurance PhaseIO replay failed for {identity}: {detail}")
    roster_unit = work_units[keys["roster"]]
    if (
        roster_unit.get("contract_digest")
        != authority["consumer_roster"]["contract_digest"]
        or roster_unit.get("launch_digest")
        != authority["consumer_roster"]["launch_digest"]
    ):
        _fail("graph assurance roster owner digests differ")


def load_graph_application_authority_bytes(
    value: object,
    **expected: Any,
) -> dict[str, Any]:
    """Replay a committed token or decode bytes for assurance projection.

    The bytes branch is deliberately non-authoritative: it returns a plain
    mapping and therefore cannot be passed to any production builder or
    committed loader.  Final-report assurance uses it to independently replay
    already-published control bytes without acquiring a mint capability.
    """

    if type(value) is CommittedGraphApplicationAuthority:
        if expected:
            replayed = _replay_committed_authority_token(value)
            return validate_graph_application_authority(replayed, **expected)
        return _replay_committed_authority_token(value)
    if not isinstance(value, bytes):
        _fail("graph authority projection requires canonical bytes or a committed token")
    return decode_graph_application_authority_test_only(value, **expected)


def load_graph_application_observations_bytes(
    value: object,
    *,
    authority: object,
    **_expected: Any,
) -> dict[str, Any]:
    """Load committed observations or perform non-authoritative byte projection."""

    if (
        type(value) is CommittedGraphApplicationObservations
        and type(authority) is CommittedGraphApplicationAuthority
    ):
        authority_value = _replay_committed_authority_token(authority)
        return _replay_committed_observations_token(
            value,
            authority=authority_value,
            expected_consumer_denominator_sha256=authority_value[
                "consumer_denominator_sha256"
            ],
            expected_scheduler_artifact_sha256=authority_value[
                "consumer_roster"
            ]["scheduler_artifact_sha256"],
        )
    if not isinstance(value, bytes) or not isinstance(authority, Mapping):
        _fail("graph observation projection requires canonical bytes/mapping parents")
    expected_consumer = _expected.pop(
        "expected_consumer_denominator_sha256",
        authority.get("consumer_denominator_sha256"),
    )
    expected_scheduler = _expected.pop(
        "expected_scheduler_artifact_sha256",
        (
            authority.get("consumer_roster", {}).get(
                "scheduler_artifact_sha256"
            )
            if isinstance(authority.get("consumer_roster"), Mapping)
            else None
        ),
    )
    expected_evidence = _expected.pop(
        "expected_evidence_artifact_sha256", None
    )
    if _expected:
        _fail("graph observation projection received unsupported expectations")
    return decode_graph_application_observations_test_only(
        value,
        authority=authority,
        expected_consumer_denominator_sha256=expected_consumer,
        expected_scheduler_artifact_sha256=expected_scheduler,
        expected_evidence_artifact_sha256=expected_evidence,
    )


def load_graph_application_reconciliation_bytes(
    value: object,
    *,
    authority: object,
    observations: object,
    **_expected: Any,
) -> dict[str, Any]:
    """Load committed reconciliation or perform non-authoritative byte projection."""

    if (
        type(value) is CommittedGraphApplicationReconciliation
        and type(authority) is CommittedGraphApplicationAuthority
        and type(observations) is CommittedGraphApplicationObservations
    ):
        authority_value = _replay_committed_authority_token(authority)
        observations_value = load_graph_application_observations_bytes(
            observations, authority=authority
        )
        return _replay_committed_reconciliation_token(
            value,
            authority=authority_value,
            observations=observations_value,
        )
    if (
        not isinstance(value, bytes)
        or not isinstance(authority, Mapping)
        or not isinstance(observations, Mapping)
    ):
        _fail(
            "graph reconciliation projection requires canonical bytes/mapping parents"
        )
    expected_consumer = _expected.pop(
        "expected_consumer_denominator_sha256",
        authority.get("consumer_denominator_sha256"),
    )
    expected_scheduler = _expected.pop(
        "expected_scheduler_artifact_sha256",
        (
            authority.get("consumer_roster", {}).get(
                "scheduler_artifact_sha256"
            )
            if isinstance(authority.get("consumer_roster"), Mapping)
            else None
        ),
    )
    if _expected:
        _fail("graph reconciliation projection received unsupported expectations")
    return decode_graph_application_reconciliation_test_only(
        value,
        authority=authority,
        observations=observations,
        expected_consumer_denominator_sha256=expected_consumer,
        expected_scheduler_artifact_sha256=expected_scheduler,
    )


__all__ = [
    "AUTHORITY_ARTIFACT",
    "AUTHORITY_SCHEMA",
    "AUTHORITY_STATES",
    "CONSUMER_ROSTER_ARTIFACT",
    "CONSUMER_ROSTER_SCHEMA",
    "CommittedGraphApplicationAuthority",
    "CommittedGraphApplicationObservations",
    "CommittedGraphApplicationReconciliation",
    "CommittedGraphConsumerRoster",
    "DISPOSITIONS",
    "GraphApplicationAuthorityError",
    "GRAPH_APPLICATION_CONSUMER_ACTIVATION",
    "MINIMUM_DISPOSITIONS",
    "OBSERVATIONS_ARTIFACT",
    "OBSERVATIONS_SCHEMA",
    "RECONCILIATION_ARTIFACT",
    "RECONCILIATION_SCHEMA",
    "RECONCILIATION_STATES",
    "SCHEDULE_ARTIFACT",
    "SCHEDULE_SCHEMA",
    "build_graph_application_authority",
    "build_graph_application_observations",
    "build_graph_consumer_roster_payload",
    "build_graph_schedule_payload",
    "canonical_file_bytes",
    "integration_contract",
    "load_committed_graph_application_authority",
    "load_committed_graph_application_observations",
    "load_committed_graph_application_reconciliation",
    "load_committed_graph_consumer_roster",
    "load_graph_application_authority_bytes",
    "load_graph_application_observations_bytes",
    "load_graph_application_reconciliation_bytes",
    "reconcile_graph_application",
    "validate_graph_application_assurance_phaseio",
]
