"""G1 + G2 — mechanical enumeration-coverage gate (ecosystem-agnostic).

The pipeline's dominant recall failure is under-enumeration: an agent analyzes a
function that writes/transfers a state symbol, reasons about ONE consumer, and
writes "SAFE" without addressing the OTHER functions that reference the same
symbol. The deep-research pass showed the only proven fix is grounding the
required set in an EXTERNAL static-analysis graph (LLMxCPG) and gating the
verdict on covering it — not self-critique or debate.

This module reads the unified `_mechanical_graph.json` (emitted by the Slither /
SCIP / Move / DAML graph providers) and:

  G1 `compute_enumeration_obligations` — for each inventory finding, derives the
     set of CO-REFERENCING functions of the symbols its function touches (the
     functions the finding's analysis ought to address). Bounded (per the
     chain_prep precedent) so it never floods.

  G2 `validate_enumeration_coverage` — mechanically diffs each obligation's
     required co-referencers against the finding's own prose. An un-addressed
     co-referencer is a COVERAGE GAP: it is appended to findings_inventory as a
     low-confidence `ENUMGAP` candidate (append-only, idempotent) so the existing
     verify-the-positives filter adjudicates it. Recall-safe: never drops, never
     halts; missing, degenerate, or materially under-resolved graph coverage is
     emitted to the shared human-review control plane instead of reading as a
     clean zero.

No-overfit: pure graph mechanics, names no protocol.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import posixpath
import re
import threading
import time
import uuid

from enumgap_markdown import (
    ENUMGAP_ACTION_ID_RE as _ENUMGAP_ACTION_ID_RE,
    exploration_field as _exploration_field,
    parse_enumgap_exploration_findings,
    parse_exploration_finding_blocks,
    sha256_text as _sha256_text,
)
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from coverage_shortfalls import (
    CoverageShortfallError,
    _validate_row as _validate_coverage_shortfall_row,
    replace_producer_shortfalls,
    shortfall,
    unknown_shortfall,
)
from enumeration_anchor_facts import (
    canonical_digest as _anchor_digest,
    derive_symbol_anchors,
    unknown_anchor_obligation,
)
from enumeration_type_ir import (
    boundary_is_addressed,
    boundary_specs_for_parameter,
    collect_type_facts,
    select_function_parameter_ir,
)
from plamen_parsers import COMMITTED_INVARIANT_ID_PATTERN
from plamen_markdown import mapped_headings
from plamen_types import FINDING_BLOCK_HEADING_RE
from late_committed_invariant_authority import (
    LATE_CI_AUTHORITY,
    LATE_CI_STATUS,
    LateCommittedInvariantAuthority,
    LateCommittedInvariantError,
    LateCommittedInvariantRecoveryResult,
    persist_late_committed_invariant_authorities,
)
from production_source_scope import (
    is_production_source_path as _graph_producer_is_production_source_path,
    walker_accepts_relative_path,
)

try:
    from plamen_mechanical import _inventory_blocks  # type: ignore
except Exception:  # pragma: no cover
    _inventory_blocks = None  # type: ignore

try:
    from plamen_mechanical import _field_from_markdown  # type: ignore
except Exception:  # pragma: no cover
    _field_from_markdown = None  # type: ignore

# Keep walker exclusions explicit here: graph producer and consumer both run
# from this checkout, while the shared semantic predicate lives in an
# import-safe module that cannot be replaced by a recon-phase test shim.
_GRAPH_PRODUCER_SKIP_DIR_NAMES = frozenset({
    "node_modules", ".git", "target", "build", "out", "artifacts", "cache",
    "dist", ".venv", "venv", "__pycache__", ".next", ".idea", ".vscode",
    "forge-cache", ".foundry", ".anchor", ".aptos", ".sui",
})
_GRAPH_PRODUCER_ROOT_ONLY_SKIP_DIR_NAMES = frozenset({"lib"})

__all__ = [
    # Axis 1 (co-reference) — G1/G2, unchanged.
    "compute_enumeration_obligations",
    "compute_coverage_gaps",
    "validate_enumeration_coverage",
    # Additional mechanical obligation-derivers (L-04/L-08/L-10, M1).
    "compute_critical_asset_mover_candidates",
    "compute_array_uniqueness_candidates",
    "compute_unbounded_input_candidates",
    "compute_invariant_assertion_candidates",
    "recover_invariant_assertion_candidates",
    "LateCommittedInvariantAuthority",
    "LateCommittedInvariantError",
    "LateCommittedInvariantRecoveryResult",
    "compute_hot_function_set",
    "compute_axis_population",
    "compute_axis_coverage_gaps",
    "promote_axis_findings_to_inventory",
    "parse_enumgap_exploration_findings",
    "promote_enumgap_exploration_to_inventory",
    "validated_enumgap_promotion_deliveries",
    # Driver entry point (all axes + derivers).
    "run_enumeration_gate",
    # Gate V (Fix A) — boundary + symmetric Variant-Family Coverage.
    "compute_boundary_input_candidates",
    "compute_symmetric_operation_candidates",
    "compute_variant_gaps",
    "validate_variant_coverage",
]

# Bounds (mirror chain_prep's recall-safe bounding so the gate can't flood).
_MAX_VARS_PER_FINDING = 5      # only the few symbols a finding most directly touches
_MAX_COREFS_PER_VAR = 6       # cap co-referencers enumerated per symbol
_SKIP_VAR_REF_THRESHOLD = 25  # a symbol referenced by >25 fns is too common to gate on
_MAX_ENUMGAP_PER_RUN = 40     # global cap on emitted candidates
_CANDIDATE_TRANSACTION_LOCK = threading.RLock()

# R0-6 graph-health contract.  The ratio is deliberately explicit and
# operator-configurable, but invalid values fail back to the conservative
# default instead of silently disabling the check.  This is a join-health
# threshold, not a claim that the underlying graph is semantically complete.
_GRAPH_HEALTH_PRODUCER = "enumeration.axis1.graph_health"
_GRAPH_LOCATION_RESOLUTION_MIN_RATIO_DEFAULT = 0.80
_GRAPH_LOCATION_RESOLUTION_MIN_RATIO_ENV = (
    "PLAMEN_GRAPH_LOCATION_RESOLUTION_MIN_RATIO"
)
_GRAPH_HEALTH_FALLBACK_NAME = "report_semantic_enumeration_graph_health.md"
_SC_PRODUCTION_SOURCE_SUFFIXES = frozenset({
    ".sol", ".vy", ".rs", ".go", ".move", ".daml",
})
_SOURCE_LOCATION_RE = re.compile(
    r"(?P<path>(?:[A-Za-z]:)?[A-Za-z0-9_./\\-]+\.(?:sol|vy|rs|go|move|daml))"
    r"(?:(?::[A-Za-z_]\w*)?:L?(?P<line>\d+))?",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class _SourceLocation:
    display_path: str
    normalized_path: str
    line: int | None

    @property
    def rendered(self) -> str:
        if self.line is None:
            return self.display_path
        return f"{self.display_path}:L{self.line}"


@contextmanager
def _candidate_transaction(scratchpad: Path):
    """Serialize the complete inventory/key-receipt emission transaction."""
    scratchpad = Path(scratchpad)
    scratchpad.mkdir(parents=True, exist_ok=True)
    lock_path = scratchpad / ".enumeration_candidates.lock"
    with _CANDIDATE_TRANSACTION_LOCK:
        with lock_path.open("a+b") as handle:
            if os.name == "nt":
                import msvcrt
                handle.seek(0, os.SEEK_END)
                if handle.tell() == 0:
                    handle.write(b"0")
                    handle.flush()
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
                try:
                    yield
                finally:
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

# The six generic committed-invariant SHAPES (M1). Each is a relational form
# (HOW to interrogate a locus), never a protocol constant; symbols resolve at the
# locus at runtime. Kept as a frozenset so an unknown/garbled Shape degrades to
# an un-shaped (still-emitted) candidate rather than being dropped.
_CI_SHAPES: frozenset = frozenset({
    "CONSERVATION", "REQUESTED_EQ_DELIVERED", "APPROVE_EQ_SPEND",
    "NO_REVERT_AT_BOUNDARY", "ROUNDTRIP", "FRESHNESS",
})

# Falsify Class → generic postcondition/precondition class tags for chain
# metadata. Generic (relational), no protocol names. A boundary/conservation
# assertion CREATES/needs a STATE/BALANCE relation; freshness is EXTERNAL/TIMING.
_CI_SHAPE_CHAIN: dict = {
    "CONSERVATION": ("BALANCE: value-conservation relation asserted at the locus", "BALANCE"),
    "REQUESTED_EQ_DELIVERED": ("BALANCE: requested==delivered relation asserted at the locus", "BALANCE"),
    "APPROVE_EQ_SPEND": ("ACCESS: approve==spend relation asserted at the locus", "ACCESS"),
    "NO_REVERT_AT_BOUNDARY": ("STATE: no-revert-at-boundary relation asserted at the locus", "STATE"),
    "ROUNDTRIP": ("STATE: decode∘encode==id roundtrip relation asserted at the locus", "STATE"),
    "FRESHNESS": ("EXTERNAL: input-freshness/source relation asserted at the locus", "EXTERNAL"),
}

# Generic conversion/boundary cues. A `CONSERVATION` invariant emitted at a
# value-conversion boundary is frequently *true by construction* (a 1:1 unwrap
# trivially conserves), so the emitted candidate's Falsify Class is enriched with
# the two shapes that CAN break there — NO_REVERT_AT_BOUNDARY + REQUESTED_EQ_
# DELIVERED. These are HOW-shaped substrings (wrap/convert/bridge boundaries),
# NEVER a protocol/token/function signature; native↔wrapped is only illustrative.
_CI_CONVERSION_CUE = re.compile(
    r"(?i)\b(?:wrap|unwrap|wrapped|native|convert|conversion|redeem|"
    r"deposit\s*/?\s*withdraw|withdraw\s*/?\s*deposit|bridge|mint\s*/?\s*burn|"
    r"burn\s*/?\s*mint|swap|exchange|peg|1\s*[:=]\s*1)\b"
)
# The breakable shapes appended to a true-by-construction CONSERVATION candidate.
_CI_BREAKABLE_SHAPES: tuple = ("NO_REVERT_AT_BOUNDARY", "REQUESTED_EQ_DELIVERED")


def _chain_metadata_lines(postcondition: str = "", postcondition_type: str = "",
                          missing_precondition: str = "", precondition_type: str = "") -> list[str]:
    """Render generic, chain-matchable pre/post metadata in finding-output-format
    field names so the chain phase can use an ENUMGAP candidate as an enabler.

    These are the SAME optional fields the inventory parser ingests
    (`Postconditions Created` / `Postcondition Types` / `Missing Precondition` /
    `Precondition Type`) and that chain_prep / Chain Agent match on. A deriver
    candidate is individually weak (NEEDS_VERIFICATION), but stamping the state/
    access it CREATES (postcondition) or NEEDS (missing precondition) lets it
    pair with another finding into a compound CHAIN hypothesis — which is then
    itself sent to verification. Empty fields are omitted. Recall-safe; generic
    (type tags only, no protocol names)."""
    out: list[str] = []
    if postcondition:
        out.append(f"**Postconditions Created**: {postcondition}")
        if postcondition_type:
            out.append(f"**Postcondition Types**: {postcondition_type}")
    if missing_precondition:
        out.append(f"**Missing Precondition**: {missing_precondition}")
        if precondition_type:
            out.append(f"**Precondition Type**: {precondition_type}")
    return out


def _append_inventory_blocks(inv_text: str, hdr: str, appended: list[str]) -> str:
    """Append ENUMGAP/exploration blocks to inventory text, separator-safe.

    `inv_text.rstrip()` strips the trailing newline of the prior block. When a
    sibling deriver already created the shared section, `hdr` is "" — without a
    separator the first appended '### Finding' header glues onto the previous
    block's last line and becomes invisible to `^### Finding` parsers. Inserting
    a blank-line separator when `hdr` is empty guarantees the header is always
    line-anchored. Recall-safe: never drops blocks.
    """
    # Preserve the exact prior prefix; separator-only growth is append-safe.
    return inv_text + (hdr if hdr else "\n\n") + "\n".join(appended) + "\n"


def _load_graph(scratchpad: Path) -> dict | None:
    p = scratchpad / "_mechanical_graph.json"
    if not p.exists():
        return None
    try:
        g = json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None
    if not isinstance(g, dict):
        return None
    raw_var_refs = g.get("var_refs")
    raw_functions = g.get("functions")
    if not isinstance(raw_var_refs, dict) or not isinstance(raw_functions, dict):
        return None

    # One malformed provider row must not poison every valid row. Salvage the
    # mechanically usable subset and carry exact diagnostics into graph-health
    # UNKNOWN. This preserves recall while refusing to self-certify the partial
    # graph as complete.
    diagnostics: list[str] = []
    functions: dict[str, dict] = {}
    for key, raw in raw_functions.items():
        if not isinstance(raw, dict):
            diagnostics.append(f"functions:{key}:not-object")
            continue
        clean = dict(raw)
        if "bare" in clean and not isinstance(clean.get("bare"), str):
            diagnostics.append(f"functions:{key}:invalid-bare")
            clean.pop("bare", None)
        if "loc" in clean and not isinstance(clean.get("loc"), str):
            diagnostics.append(f"functions:{key}:invalid-loc")
            clean.pop("loc", None)
        functions[str(key)] = clean

    var_refs: dict[str, dict] = {}
    for key, raw in raw_var_refs.items():
        if not isinstance(raw, dict):
            diagnostics.append(f"var_refs:{key}:not-object")
            continue
        refs = raw.get("refs", [])
        if not isinstance(refs, list):
            diagnostics.append(f"var_refs:{key}:refs-not-array")
            continue
        valid_refs = [ref for ref in refs if isinstance(ref, str)]
        if len(valid_refs) != len(refs):
            diagnostics.append(
                f"var_refs:{key}:discarded-{len(refs) - len(valid_refs)}-invalid-ref"
            )
        clean = dict(raw)
        clean["refs"] = valid_refs
        if "bare" in clean and not isinstance(clean.get("bare"), str):
            diagnostics.append(f"var_refs:{key}:invalid-bare")
            clean.pop("bare", None)
        var_refs[str(key)] = clean

    source = g.get("source", "")
    if not isinstance(source, str):
        diagnostics.append("source:invalid-type")
        source = ""
    return {
        "source": source,
        "var_refs": var_refs,
        "functions": functions,
        "_graph_health_diagnostics": tuple(sorted(diagnostics)),
    }


def _graph_location_resolution_threshold() -> float:
    """Return the configured SC inventory-location join-health floor.

    A bad environment value must not turn the health check off.  Keeping the
    parser here makes the threshold independently fixtureable on every OS and
    avoids adding a driver/config-schema dependency for an advisory gate.
    """
    raw = os.environ.get(_GRAPH_LOCATION_RESOLUTION_MIN_RATIO_ENV, "").strip()
    if not raw:
        return _GRAPH_LOCATION_RESOLUTION_MIN_RATIO_DEFAULT
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return _GRAPH_LOCATION_RESOLUTION_MIN_RATIO_DEFAULT
    if not math.isfinite(value) or not (0.0 < value <= 1.0):
        return _GRAPH_LOCATION_RESOLUTION_MIN_RATIO_DEFAULT
    return value


def _normalized_source_path(raw_path: str) -> str:
    path = str(raw_path or "").replace("\\", "/").strip()
    normalized = posixpath.normpath(path)
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized.casefold()


@lru_cache(maxsize=65536)
def _producer_accepts_source_path(raw_path: str) -> bool:
    """Apply the graph producer's canonical production-source predicate.

    ``_is_production_source_path`` is content-independent, so a synthetic root
    is sufficient. Directory pruning performed by its walker is mirrored from
    the producer's exported ``SKIP_DIR_NAMES``. If those imports are unavailable
    the caller cannot establish parity and treats the location as unmeasurable.
    """
    normalized = _normalized_source_path(raw_path)
    if not normalized or normalized in {".", ".."}:
        return False
    try:
        return walker_accepts_relative_path(
            normalized,
            skip_dir_names=_GRAPH_PRODUCER_SKIP_DIR_NAMES,
            root_only_skip_dir_names=_GRAPH_PRODUCER_ROOT_ONLY_SKIP_DIR_NAMES,
        )
    except Exception:
        return False


def _production_source_locations(location: str) -> list[_SourceLocation]:
    """Return every eligible source reference, preserving citation order.

    Lines are optional so path-only inventory entries remain observable as
    unmeasurable input rather than disappearing into a false clean zero.
    """
    out: list[_SourceLocation] = []
    seen: set[tuple[str, int | None]] = set()
    for match in _SOURCE_LOCATION_RE.finditer(str(location or "")):
        raw_path = match.group("path").replace("\\", "/")
        if Path(raw_path).suffix.lower() not in _SC_PRODUCTION_SOURCE_SUFFIXES:
            continue
        if not _producer_accepts_source_path(raw_path):
            continue
        raw_line = match.group("line")
        line = int(raw_line) if raw_line is not None else None
        normalized = _normalized_source_path(raw_path)
        identity = (normalized, line)
        if identity in seen:
            continue
        seen.add(identity)
        out.append(_SourceLocation(raw_path, normalized, line))
    return out


def _production_source_location(location: str) -> str | None:
    """Backward-compatible first line-bearing production location."""
    for ref in _production_source_locations(location):
        if ref.line is not None:
            return ref.rendered
    return None


def _graph_function_location_rows(
    graph: dict,
) -> list[tuple[str, _SourceLocation]]:
    return list(_graph_location_index(graph)["rows"])


def _graph_location_index(graph: dict) -> dict:
    """Build one immutable lookup index per loaded graph.

    Real graphs carry thousands of function rows and var-reference descriptors.
    Re-scanning every function for every inventory row/descriptor is quadratic;
    the index makes exact joins O(functions-in-file) and basename fallback
    O(paths-with-basename) without changing selection semantics.
    """
    cached = graph.get("_graph_location_index")
    if isinstance(cached, dict):
        return cached
    rows: list[tuple[str, _SourceLocation]] = []
    exact: dict[str, list[tuple[str, _SourceLocation]]] = {}
    basename: dict[str, dict[str, list[tuple[str, _SourceLocation]]]] = {}
    bare: dict[str, list[str]] = {}
    for function_key, info in sorted(graph.get("functions", {}).items()):
        if not isinstance(info, dict):
            continue
        for ref in _production_source_locations(str(info.get("loc", ""))):
            if ref.line is not None:
                row = (str(function_key), ref)
                rows.append(row)
                exact.setdefault(ref.normalized_path, []).append(row)
                base = posixpath.basename(ref.normalized_path)
                basename.setdefault(base, {}).setdefault(
                    ref.normalized_path, []
                ).append(row)
                normalized_bare = str(
                    info.get("bare", str(function_key).split(".")[-1])
                ).casefold()
                if normalized_bare:
                    bare.setdefault(normalized_bare, []).append(str(function_key))
                break
    index = {
        "rows": tuple(rows),
        "exact": {
            path: tuple(path_rows) for path, path_rows in exact.items()
        },
        "basename": {
            base: {
                path: tuple(path_rows) for path, path_rows in paths.items()
            }
            for base, paths in basename.items()
        },
        "bare": {
            name: tuple(sorted(keys)) for name, keys in bare.items()
        },
    }
    graph["_graph_location_index"] = index
    return index


def _nearest_enclosing_function(
    candidates: list[tuple[str, _SourceLocation]], cited_line: int,
) -> str | None:
    eligible = [
        (key, ref) for key, ref in candidates
        if ref.line is not None and ref.line <= cited_line
    ]
    if not eligible:
        return None
    best_line = max(int(ref.line) for _key, ref in eligible if ref.line is not None)
    best = sorted({
        key for key, ref in eligible if int(ref.line or -1) == best_line
    })
    return best[0] if len(best) == 1 else None


def _resolve_inventory_function(
    graph: dict, location: str,
) -> tuple[str | None, _SourceLocation | None, str]:
    """Resolve one canonical inventory locus into a graph function.

    All exact project-relative matches are attempted in citation order before
    any basename fallback. Basename fallback is legal only when that basename
    maps to one distinct graph path. Health accounting and obligation derivation
    both call this function, eliminating selection drift.
    """
    refs = _production_source_locations(location)
    line_refs = [ref for ref in refs if ref.line is not None]
    if not refs:
        return None, None, "NO_PRODUCTION_LOCATION"
    if not line_refs:
        return None, refs[0], "MISSING_LINE"
    index = _graph_location_index(graph)

    for ref in line_refs:
        exact_rows = list(index["exact"].get(ref.normalized_path, ()))
        function_key = _nearest_enclosing_function(exact_rows, int(ref.line))
        if function_key:
            return function_key, ref, "EXACT_PATH"

    for ref in line_refs:
        basename = posixpath.basename(ref.normalized_path)
        paths = index["basename"].get(basename, {})
        if len(paths) != 1:
            continue
        basename_rows = list(next(iter(paths.values())))
        function_key = _nearest_enclosing_function(basename_rows, int(ref.line))
        if function_key:
            return function_key, ref, "UNIQUE_BASENAME"
    return None, line_refs[0], "UNRESOLVED_OR_AMBIGUOUS"


def _graph_health_shortfalls(
    scratchpad: Path,
    graph: dict | None,
    blocks: list[dict] | None,
) -> list[dict]:
    """Measure inventory-location -> graph-function join health.

    UNKNOWN is used when graph health cannot be measured.  A numerical EXACT
    shortfall is used only when there is a real denominator of inventory
    findings with parseable production source locations.  Resolved rows are
    never withheld merely because the aggregate ratio is low.
    """
    graph_path = Path(scratchpad) / "_mechanical_graph.json"
    if graph is None:
        return [unknown_shortfall(
            producer=_GRAPH_HEALTH_PRODUCER,
            scope="location-function-resolution",
            kind="PROVIDER_FAILED" if graph_path.exists() else "PROVIDER_UNAVAILABLE",
            detail=(
                "mechanical graph is malformed or has an invalid unified schema"
                if graph_path.exists()
                else "mechanical graph provider artifact is missing"
            ),
        )]

    rows: list[dict] = []
    diagnostics = list(graph.get("_graph_health_diagnostics", ()))
    if diagnostics:
        rows.append(unknown_shortfall(
            producer=_GRAPH_HEALTH_PRODUCER,
            scope="provider-schema",
            kind="PARTIAL_GRAPH_SCHEMA",
            detail=(
                "malformed graph entries were discarded while valid entries "
                "remained eligible for enumeration"
            ),
            samples=diagnostics,
        ))
    if (
        _graph_producer_is_production_source_path is None
        or _GRAPH_PRODUCER_SKIP_DIR_NAMES is None
    ):
        rows.append(unknown_shortfall(
            producer=_GRAPH_HEALTH_PRODUCER,
            scope="production-source-predicate",
            kind="PROVIDER_UNAVAILABLE",
            detail="graph producer production-source predicate could not be imported",
        ))
    if not str(graph.get("source", "") or "").strip():
        rows.append(unknown_shortfall(
            producer=_GRAPH_HEALTH_PRODUCER,
            scope="provider-identity",
            kind="PROVIDER_UNAVAILABLE",
            detail="mechanical graph has no provider/source identity",
        ))

    functions = graph.get("functions", {})
    usable_function_locations = _graph_function_location_rows(graph)
    if not functions or not usable_function_locations:
        rows.append(unknown_shortfall(
            producer=_GRAPH_HEALTH_PRODUCER,
            scope="location-function-resolution",
            kind="DEGENERATE_GRAPH",
            detail="mechanical graph contains no functions with parseable production locations",
        ))
        return rows

    if blocks and not graph.get("var_refs"):
        rows.append(unknown_shortfall(
            producer=_GRAPH_HEALTH_PRODUCER,
            scope="co-reference-capability",
            kind="COREFERENCE_CAPABILITY_EMPTY",
            detail=(
                "mechanical graph has functions but an empty var_refs map; "
                "zero co-reference obligations is not measurable as complete"
            ),
        ))

    measured: list[tuple[str, str, str | None]] = []
    unmeasurable: list[str] = []
    for block in blocks or []:
        finding_id = str(block.get("id", "") or "unknown-finding")
        raw_location = str(block.get("location", ""))
        function_key, canonical, status = _resolve_inventory_function(
            graph, raw_location
        )
        if canonical is not None and canonical.line is not None:
            measured.append((finding_id, canonical.rendered, function_key))
        else:
            sample_location = canonical.rendered if canonical is not None else raw_location
            unmeasurable.append(f"{finding_id}@{sample_location or '(missing location)'}")
    if unmeasurable:
        rows.append(unknown_shortfall(
            producer=_GRAPH_HEALTH_PRODUCER,
            scope="inventory-location-capability",
            kind="LOCATION_UNMEASURABLE",
            detail=(
                "nonempty inventory rows lacked a production path plus line and "
                "therefore could not participate in graph resolution"
            ),
            samples=unmeasurable,
        ))
    if not measured:
        # No denominator means no numerical health claim. UNKNOWN capability
        # rows above prevent nonempty unmeasurable input from reading as clean.
        return rows

    unresolved: list[tuple[str, str]] = []
    resolved = 0
    for finding_id, location, function_key in measured:
        if function_key:
            resolved += 1
        else:
            unresolved.append((finding_id, location))
    threshold = _graph_location_resolution_threshold()
    ratio = resolved / len(measured)
    if ratio < threshold:
        rows.append(shortfall(
            producer=_GRAPH_HEALTH_PRODUCER,
            scope="location-function-resolution",
            cap=f"MIN_RESOLUTION_RATIO_{threshold:.3f}",
            limit=len(measured),
            observed=len(measured),
            retained=resolved,
            exact=True,
            samples=[f"{fid}@{location}" for fid, location in unresolved],
            detail=(
                f"only {resolved}/{len(measured)} inventory findings with parseable "
                f"production locations resolved to a graph function; required ratio "
                f"is {threshold:.3f}; resolved rows were still enumerated"
            ),
            kind="GRAPH_RESOLUTION_SHORTFALL",
        ))
    return rows


def _record_graph_health(
    scratchpad: Path,
    graph: dict | None,
    blocks: list[dict] | None,
) -> None:
    """Best-effort replacement with a report-delivered durable fallback."""
    scratchpad = Path(scratchpad)
    fallback = scratchpad / _GRAPH_HEALTH_FALLBACK_NAME
    try:
        replace_producer_shortfalls(
            scratchpad,
            _GRAPH_HEALTH_PRODUCER,
            _graph_health_shortfalls(scratchpad, graph, blocks),
        )
        try:
            fallback.unlink(missing_ok=True)
        except Exception:
            pass
    except Exception as exc:
        # `report_semantic_*.md` is consumed by the report assembler's human-
        # review appendix. This independent fallback prevents a failed shared
        # ledger write from turning UNKNOWN into an invisible clean zero.
        detail = re.sub(r"\s+", " ", str(exc)).strip().replace("|", "/")
        text = (
            "# Enumeration Graph Health Control-Plane Failure\n\n"
            "- **Producer**: `enumeration.axis1.graph_health`\n"
            "- **Coverage State**: **UNKNOWN**\n"
            "- **Disposition**: FLAGGED_FOR_HUMAN_REVIEW\n"
            "- **Detail**: graph-health coverage receipt could not be persisted"
            f" ({type(exc).__name__}: {detail or 'no detail'}).\n"
        )
        tmp = fallback.with_name(
            f".{fallback.name}.{os.getpid()}.{threading.get_ident()}."
            f"{uuid.uuid4().hex}.tmp"
        )
        try:
            tmp.write_text(text, encoding="utf-8")
            tmp.replace(fallback)
        except Exception:
            pass
        finally:
            try:
                tmp.unlink(missing_ok=True)
            except Exception:
                pass


def _bare_from_descriptor(d: str) -> str:
    """A descriptor is 'BareName (file:line)' or 'file:line' — return the bare
    name (or the descriptor itself when it's a plain location)."""
    return (d.split("(", 1)[0].strip() or d).strip()


def _fn_at_location(graph: dict, location: str) -> str | None:
    """Map a cited locus using the shared exact-first canonical resolver."""
    function_key, _canonical, _status = _resolve_inventory_function(graph, location)
    return function_key


def _artifact_sha256(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return ""


def _axis1_input_digests(scratchpad: Path) -> dict[str, str]:
    return {
        "mechanical_graph_sha256": _artifact_sha256(
            Path(scratchpad) / "_mechanical_graph.json"
        ),
        "findings_inventory_sha256": _artifact_sha256(
            Path(scratchpad) / "findings_inventory.md"
        ),
    }


def _descriptor_function_key(graph: dict, descriptor: str) -> str | None:
    """Resolve provider descriptors, including SCIP's location-only form."""
    function_key, _canonical, _status = _resolve_inventory_function(graph, descriptor)
    if function_key:
        return function_key

    # Some providers retain only a bare name. Use it only when unique; qualified
    # duplicates without a resolving location are unmeasurable, never guessed.
    bare = _bare_from_descriptor(descriptor).casefold()
    # A syntactic source citation that was rejected by the producer predicate
    # (test/mock/vendor/etc.) must not re-enter through its leading bare name.
    if not bare or _SOURCE_LOCATION_RE.search(str(descriptor or "")):
        return None
    matches = list(_graph_location_index(graph)["bare"].get(bare, ()))
    return matches[0] if len(matches) == 1 else None


def compute_enumeration_obligations(scratchpad: Path) -> int:
    """G1. Derive per-finding co-reference obligations from the graph. Writes
    `enumeration_obligations.md` + `_enumeration_obligations.json`. Returns the
    obligation count. Never raises; missing/insufficient providers are exposed
    through graph-health coverage receipts rather than misreported as clean."""
    scratchpad = Path(scratchpad)
    graph = _load_graph(scratchpad)
    inv = scratchpad / "findings_inventory.md"
    if graph is None or _inventory_blocks is None or not inv.exists():
        _record_graph_health(scratchpad, graph, None)
        try:
            missing = (
                "mechanical graph" if graph is None else
                "inventory parser" if _inventory_blocks is None else
                "findings inventory"
            )
            replace_producer_shortfalls(
                scratchpad,
                "enumeration.axis1",
                [unknown_shortfall(
                    producer="enumeration.axis1",
                    scope="obligation-provider",
                    kind="PROVIDER_UNAVAILABLE",
                    detail=f"cannot enumerate co-references: missing {missing}",
                )],
            )
        except Exception:
            pass
        return 0
    try:
        blocks = _inventory_blocks(inv.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        _record_graph_health(scratchpad, graph, None)
        try:
            replace_producer_shortfalls(
                scratchpad,
                "enumeration.axis1",
                [unknown_shortfall(
                    producer="enumeration.axis1",
                    scope="obligation-provider",
                    kind="PROVIDER_FAILED",
                    detail="findings inventory could not be parsed for co-reference obligations",
                )],
            )
        except Exception:
            pass
        return 0

    _record_graph_health(scratchpad, graph, blocks)

    var_refs = graph["var_refs"]
    # Invert canonical graph function key -> referenced variable keys. Provider
    # descriptors are heterogeneous: Slither/source providers usually include
    # a name plus location; SCIP emits only reference locations. Resolve both
    # through the same exact-first function index used by graph health.
    fn_to_vars: dict[str, set] = {}
    for vk, vd in var_refs.items():
        for d in vd.get("refs", []):
            descriptor_key = _descriptor_function_key(graph, d)
            if descriptor_key:
                fn_to_vars.setdefault(descriptor_key, set()).add(vk)

    obligations: list[dict] = []
    anchors: list[dict] = []
    family_cards: list[dict] = []
    unresolved_anchor_obligations: list[dict] = []
    anchor_tail: list[dict] = []
    shortfalls: list[dict] = []
    for b in blocks:
        fid = b.get("id", "")
        loc = b.get("location", "")
        fk = _fn_at_location(graph, loc)
        if not fk:
            unresolved_anchor_obligations.append(unknown_anchor_obligation(
                finding_id=fid,
                function_key="UNRESOLVED",
                cited_location=loc,
                graph_source=str(graph.get("source", "unknown")),
            ))
            continue
        fbare = graph["functions"][fk].get("bare", fk.split(".")[-1]).lower()
        local_anchors = derive_symbol_anchors(
            graph=graph,
            finding_id=fid,
            function_key=fk,
            finding_block=str(b.get("block", "")),
            cited_location=loc,
            candidate_symbol_identities=fn_to_vars.get(fk, set()),
        )
        if not local_anchors:
            unknown = unknown_anchor_obligation(
                finding_id=fid,
                function_key=fk,
                cited_location=loc,
                graph_source=str(graph.get("source", "unknown")),
            )
            unresolved_anchor_obligations.append(unknown)
            shortfalls.append(unknown_shortfall(
                producer="enumeration.axis1",
                scope=f"finding:{fid}:local-anchor",
                kind="ANCHOR_FIDELITY_UNKNOWN",
                detail=(
                    "no exact finding-local symbol identity or statement-level "
                    "reference matched; function-scope variables were not expanded"
                ),
                samples=[loc],
            ))
            continue
        vars_touched = local_anchors[: _MAX_VARS_PER_FINDING]
        anchors.extend(vars_touched)
        if len(local_anchors) > _MAX_VARS_PER_FINDING:
            anchor_tail.extend(local_anchors[_MAX_VARS_PER_FINDING:])
            shortfalls.append(shortfall(
                producer="enumeration.axis1",
                scope=f"finding:{fid}:exact-anchors",
                cap="MAX_VARS_PER_FINDING",
                limit=_MAX_VARS_PER_FINDING,
                observed=len(local_anchors),
                retained=len(vars_touched),
                exact=True,
                samples=[row["symbol_identity"] for row in local_anchors[_MAX_VARS_PER_FINDING:]],
                detail=(
                    "exact finding-local anchors exceeded the scheduled work bound; "
                    "the complete tail remains in the typed obligation artifact"
                ),
            ))
        for anchor in vars_touched:
            vk = str(anchor["symbol_identity"])
            vd = var_refs.get(vk, {})
            refs = vd.get("refs", [])
            all_corefs: dict[str, dict] = {}
            for descriptor in refs:
                coref_key = _descriptor_function_key(graph, descriptor)
                if coref_key:
                    if coref_key == fk:
                        continue
                    coref_info = graph["functions"].get(coref_key, {})
                    all_corefs[str(coref_key)] = {
                        "function_identity": str(coref_key),
                        "function": str(coref_info.get("bare", coref_key.split(".")[-1])),
                        "location": str(coref_info.get("loc", "")),
                        "descriptor": str(descriptor),
                    }
                    continue
                # Preserve a provider's explicit non-location bare descriptor
                # when it cannot be joined, but never leak a path as a pseudo
                # function name into the verification obligation.
                fallback_bare = _bare_from_descriptor(descriptor)
                if (
                    not _SOURCE_LOCATION_RE.search(str(descriptor or ""))
                    and fallback_bare.casefold() != fbare.casefold()
                ):
                    identity = "UNRESOLVED:" + fallback_bare.casefold()
                    all_corefs[identity] = {
                        "function_identity": identity,
                        "function": fallback_bare,
                        "location": "",
                        "descriptor": str(descriptor),
                    }
            member_rows = [all_corefs[key] for key in sorted(all_corefs)]
            scheduled_rows = member_rows[: _MAX_COREFS_PER_VAR]
            tail_rows = member_rows[_MAX_COREFS_PER_VAR:]
            all_identities = [row["function_identity"] for row in member_rows]
            scheduled_identities = [row["function_identity"] for row in scheduled_rows]
            tail_identities = [row["function_identity"] for row in tail_rows]
            family = {
                "schema": "plamen.enumeration_coreference_family.v1",
                "family_id": "EAF-" + _anchor_digest({
                    "finding_id": fid,
                    "anchor_id": anchor["anchor_id"],
                    "members": all_identities,
                })[:24].upper(),
                "finding_id": fid,
                "anchor_id": anchor["anchor_id"],
                "symbol_identity": vk,
                "member_count": len(member_rows),
                "all_members": all_identities,
                "member_facts": member_rows,
                "scheduled_members": scheduled_identities,
                "tail_members": tail_identities,
                "tail_digest": _anchor_digest(tail_identities),
                "continuation_required": bool(tail_rows),
                "reference_fidelity": anchor["reference_fidelity"],
                "graph_source": str(graph.get("source") or "unknown"),
                "status": "CONTINUATION_REQUIRED" if tail_rows else "SCHEDULED",
                "action": "VERIFY_SCHEDULED_PREFIX_AND_DRAIN_TAIL",
            }
            family_cards.append(family)
            if tail_rows:
                shortfalls.append(shortfall(
                    producer="enumeration.axis1",
                    scope=f"finding:{fid}:symbol:{vd.get('bare', vk)}:corefs",
                    cap="MAX_COREFS_PER_VAR",
                    limit=_MAX_COREFS_PER_VAR,
                    observed=len(member_rows),
                    retained=len(scheduled_rows),
                    exact=True,
                    samples=tail_identities,
                    detail=(
                        "co-referencing family exceeded the scheduled work bound; "
                        f"full tail digest {family['tail_digest']} and identities are "
                        "retained in _enumeration_obligations.json"
                    ),
                    kind=(
                        "HIGH_FAN_IN_CONTINUATION_REQUIRED"
                        if len(member_rows) > _SKIP_VAR_REF_THRESHOLD
                        else "CAP_TRUNCATION"
                    ),
                ))
            if anchor["reference_fidelity"] != "EXACT_SITE":
                shortfalls.append(unknown_shortfall(
                    producer="enumeration.axis1",
                    scope=f"finding:{fid}:symbol:{vd.get('bare', vk)}:reference-family",
                    kind="APPROXIMATE_REFERENCE_FAMILY",
                    detail=(
                        "the finding-local symbol anchor is exact but co-reference "
                        "membership comes from a function-scope approximate provider"
                    ),
                    samples=all_identities,
                ))
            if scheduled_rows:
                obligations.append({
                    "schema": "plamen.enumeration_coreference_obligation.v1",
                    "finding_id": fid,
                    "function": graph["functions"][fk].get("bare", fk),
                    "function_identity": fk,
                    "symbol": vd.get("bare", vk),
                    "symbol_identity": vk,
                    "anchor_id": anchor["anchor_id"],
                    "anchor_kind": anchor["anchor_kind"],
                    "family_id": family["family_id"],
                    "required_corefs": [row["function"] for row in scheduled_rows],
                    "required_coref_identities": scheduled_identities,
                    "tail_coref_identities": tail_identities,
                    "continuation_required": bool(tail_rows),
                    "anchor_fidelity": str(anchor["fidelity"]),
                    "reference_fidelity": str(anchor["reference_fidelity"]),
                    "graph_source": str(graph.get("source") or "unknown"),
                    "status": "REQUIRED",
                    "action": "LOW_CONFIDENCE_VERIFICATION_CANDIDATE",
                    "confidence": "LOW_CONFIDENCE",
                })

    try:
        replace_producer_shortfalls(scratchpad, "enumeration.axis1", shortfalls)
    except Exception:
        # Haltless contract: receipt failure must not suppress candidates.
        pass

    payload = {
        "schema": "plamen.enumeration_obligation_set.v2",
        "source": graph.get("source", "?"),
        "input_digests": _axis1_input_digests(scratchpad),
        "anchors": sorted(anchors, key=lambda row: row["anchor_id"]),
        "anchor_tail": sorted(anchor_tail, key=lambda row: row["anchor_id"]),
        "family_cards": sorted(family_cards, key=lambda row: row["family_id"]),
        "unresolved_anchor_obligations": sorted(
            unresolved_anchor_obligations, key=lambda row: row["obligation_id"]
        ),
        "obligations": sorted(
            obligations,
            key=lambda row: (row["finding_id"], row["symbol_identity"], row["family_id"]),
        ),
    }
    (scratchpad / "_enumeration_obligations.json").write_text(
        json.dumps(payload, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    lines = ["# Enumeration Obligations",
             "",
             f"> Source graph: {graph.get('source', '?')}. {len(obligations)} scheduled obligation(s).",
             "> Each row starts from an exact finding-local symbol anchor. A finding "
             "analyzing `function` at that anchor must "
             "address every co-referencing function below, or the gap becomes an "
             "ENUMGAP candidate.", "",
             "| Finding | Function | Symbol | Anchor | Must also address | Tail |",
             "|---------|----------|--------|--------|-------------------|------|"]
    for o in obligations:
        lines.append(f"| {o['finding_id']} | `{o['function']}` | `{o['symbol']}` | "
                     f"{o['anchor_kind']} | "
                     f"{', '.join('`'+c+'`' for c in o['required_corefs'])} | "
                     f"{len(o['tail_coref_identities'])} |")
    if unresolved_anchor_obligations:
        lines.extend([
            "", "## Unknown Finding-Local Anchors", "",
            "These rows are actionable coverage debt and created no candidate family.", "",
            "| Finding | Function identity | Location | Reason |",
            "|---------|-------------------|----------|--------|",
        ])
        for row in sorted(unresolved_anchor_obligations, key=lambda item: item["obligation_id"]):
            lines.append(
                f"| {row['finding_id']} | `{row['function_identity']}` | "
                f"`{row['cited_location']}` | {row['reason']} |"
            )
    (scratchpad / "enumeration_obligations.md").write_text("\n".join(lines) + "\n",
                                                           encoding="utf-8")
    return len(obligations)


def compute_coverage_gaps(scratchpad: Path) -> list[dict]:
    """The diff half of G2 (pure, testable): for each obligation, the required
    co-referencers NOT mentioned anywhere in the finding's own block prose."""
    scratchpad = Path(scratchpad)
    op = scratchpad / "_enumeration_obligations.json"
    inv = scratchpad / "findings_inventory.md"
    if not op.exists() or _inventory_blocks is None or not inv.exists():
        return []
    try:
        obligation_payload = json.loads(
            op.read_text(encoding="utf-8", errors="replace")
        )
        if not isinstance(obligation_payload, dict):
            return []
        expected_digests = obligation_payload.get("input_digests")
        if isinstance(expected_digests, dict):
            current_digests = _axis1_input_digests(scratchpad)
            if expected_digests != current_digests:
                try:
                    replace_producer_shortfalls(
                        scratchpad,
                        "enumeration.axis1.source_binding",
                        [unknown_shortfall(
                            producer="enumeration.axis1.source_binding",
                            scope="obligation-inputs",
                            kind="SOURCE_DRIFT",
                            detail=(
                                "enumeration obligations do not bind the current graph "
                                "and inventory bytes; stale obligations were not consumed"
                            ),
                            samples=[
                                f"{side}:{key}:{values.get(key, '')}"
                                for key in sorted(
                                    set(expected_digests) | set(current_digests)
                                )
                                for side, values in (
                                    ("expected", expected_digests),
                                    ("current", current_digests),
                                )
                            ],
                        )],
                    )
                except Exception:
                    pass
                return []
            try:
                replace_producer_shortfalls(
                    scratchpad, "enumeration.axis1.source_binding", []
                )
            except Exception:
                pass
        obligations = obligation_payload.get("obligations", [])
        blocks = {b["id"]: b for b in _inventory_blocks(inv.read_text(encoding="utf-8", errors="replace"))}
    except Exception:
        return []
    gaps: list[dict] = []
    for o in obligations:
        b = blocks.get(o["finding_id"])
        if not b:
            continue
        text = b.get("block", "") or ""
        missing = [
            c for c in o["required_corefs"]
            if not re.search(
                rf"(?<![A-Za-z0-9_]){re.escape(c)}(?![A-Za-z0-9_])",
                text,
                re.IGNORECASE,
            )
        ]
        if missing:
            gaps.append({**o, "missing": missing})
    return gaps


def _validate_enumeration_coverage_unlocked(scratchpad: Path) -> dict:
    """G2. Compute coverage gaps and append each as a low-confidence ENUMGAP
    candidate to findings_inventory.md so the verify filter adjudicates it.
    Append-only, idempotent (receipt). Returns {gaps, emitted}. Never raises."""
    scratchpad = Path(scratchpad)
    if (_inventory_blocks is None
            or not (scratchpad / "_enumeration_obligations.json").exists()
            or not (scratchpad / "findings_inventory.md").exists()):
        try:
            replace_producer_shortfalls(
                scratchpad,
                "enumeration.axis1.emission",
                [unknown_shortfall(
                    producer="enumeration.axis1.emission",
                    scope="coverage-diff-provider",
                    kind="PROVIDER_UNAVAILABLE",
                    detail="coverage gaps cannot be diffed because a required obligation/inventory artifact is missing",
                )],
            )
        except Exception:
            pass
        return {"gaps": 0, "emitted": 0}
    try:
        gaps = compute_coverage_gaps(scratchpad)
    except Exception:
        try:
            replace_producer_shortfalls(
                scratchpad,
                "enumeration.axis1.emission",
                [unknown_shortfall(
                    producer="enumeration.axis1.emission",
                    scope="coverage-diff-provider",
                    kind="PROVIDER_FAILED",
                    detail="co-reference coverage diff failed",
                )],
            )
        except Exception:
            pass
        return {"gaps": 0, "emitted": 0}
    if not gaps:
        seen = _emitted_candidate_keys(scratchpad)
        if seen != _receipt_candidate_keys(scratchpad):
            try:
                _write_candidate_artifact(
                    scratchpad / "enumeration_gap_receipt.md",
                    _candidate_receipt_text(seen),
                )
            except Exception as exc:
                _record_persistence_failure(
                    scratchpad, "enumeration.axis1.emission", sorted(seen), exc
                )
                return {"gaps": 0, "emitted": 0}
        try:
            replace_producer_shortfalls(scratchpad, "enumeration.axis1.emission", [])
        except Exception:
            pass
        return {"gaps": 0, "emitted": 0}

    inv = scratchpad / "findings_inventory.md"
    try:
        inv_text = inv.read_text(encoding="utf-8", errors="replace")
    except Exception:
        try:
            replace_producer_shortfalls(
                scratchpad,
                "enumeration.axis1.emission",
                [unknown_shortfall(
                    producer="enumeration.axis1.emission",
                    scope="coverage-diff-provider",
                    kind="PROVIDER_FAILED",
                    detail="findings inventory could not be read for gap emission",
                )],
            )
        except Exception:
            pass
        return {"gaps": len(gaps), "emitted": 0}

    receipt = scratchpad / "enumeration_gap_receipt.md"
    seen = _emitted_candidate_keys(scratchpad)
    receipt_keys = _receipt_candidate_keys(scratchpad)

    max_inv = 0
    for m in re.finditer(r"\bINV-(\d+)\b", inv_text):
        try:
            max_inv = max(max_inv, int(m.group(1)))
        except ValueError:
            pass

    eligible: list[tuple[dict, str, str]] = []
    eligible_keys: set[str] = set()
    for g in gaps:
        for missing_fn in g["missing"]:
            key = f"{g['finding_id']}:{g['symbol']}:{missing_fn}"
            if key in seen or key in eligible_keys:
                continue
            eligible_keys.add(key)
            eligible.append((g, missing_fn, key))
    appended: list[str] = []
    keys: list[str] = []
    n = 0
    for g, missing_fn, key in eligible[:_MAX_ENUMGAP_PER_RUN]:
            n += 1
            inv_id = f"INV-{max_inv + n:03d}"
            title = (f"Unaddressed interaction: `{missing_fn}` also references "
                     f"`{g['symbol']}` (touched by `{g['function']}` in {g['finding_id']})")
            appended.extend([
                f"### Finding [{inv_id}]: {title}",
                "**Severity**: Low",
                f"**Location**: `{g['function']}` / `{missing_fn}` (shared symbol `{g['symbol']}`)",
                "**Preferred Tag**: [CODE-TRACE]",
                f"**Source IDs**: ENUMGAP (enumeration-coverage gap from {g['finding_id']}; "
                "mechanically derived from the reference graph — verifier to confirm or refute)",
                "**Verdict**: NEEDS_VERIFICATION",
                f"**Root Cause**: `{g['function']}` and `{missing_fn}` both reference "
                f"`{g['symbol']}`, but the analysis of `{g['function']}` did not address "
                f"`{missing_fn}`. Check whether their interaction over `{g['symbol']}` "
                "creates a stale-read, bricked-consumer, or accounting inconsistency.",
                f"**Description**: Enumeration-coverage gap. The reference graph shows "
                f"`{missing_fn}` also reads/writes `{g['symbol']}`; confirm the two "
                "functions are consistent or report the divergence.",
                 "**Impact**: Potential cross-function inconsistency over shared state "
                 "(verifier to confirm the concrete harm).",
                 _candidate_key_marker(key),
                 # Generic chain-matchable metadata: this gap both CREATES a
                # shared-state divergence (postcondition) and is a candidate
                # blocked-finding NEEDING that state to be consistent (missing
                # precondition). STATE-typed so the chain phase can pair it.
                *_chain_metadata_lines(
                    postcondition=(f"STATE: shared symbol `{g['symbol']}` may be left "
                                   f"inconsistent across `{g['function']}` / `{missing_fn}`"),
                    postcondition_type="STATE",
                    missing_precondition=(f"STATE: consistency of `{g['symbol']}` between "
                                          f"`{g['function']}` and `{missing_fn}`"),
                    precondition_type="STATE",
                ),
                "",
            ])
            keys.append(key)

    if not appended:
        # A prior inventory write may have succeeded while its key-receipt
        # write failed. Repair that second durable projection before clearing
        # the PERSISTENCE_FAILED debt.
        if seen != receipt_keys:
            try:
                _write_candidate_artifact(receipt, _candidate_receipt_text(seen))
            except Exception as exc:
                _record_persistence_failure(
                    scratchpad, "enumeration.axis1.emission", sorted(seen), exc
                )
                return {"gaps": len(gaps), "emitted": 0}
        try:
            replace_producer_shortfalls(
                scratchpad, "enumeration.axis1.emission", []
            )
        except Exception:
            pass
        return {"gaps": len(gaps), "emitted": 0}

    header = ("\n\n## Enumeration-Coverage Candidates (ENUMGAP)\n\n"
              "Mechanically-derived cross-function interactions over shared state that a "
              "finding's analysis did NOT address. Low-confidence by construction — the "
              "verify phase confirms or refutes each. Recall-safe: append-only.\n\n")
    hdr = "" if "Enumeration-Coverage Candidates (ENUMGAP)" in inv_text else header
    try:
        _write_candidate_artifact(
            inv, _append_inventory_blocks(inv_text, hdr, appended)
        )
        _write_candidate_artifact(
            receipt, _candidate_receipt_text(seen | set(keys))
        )
    except Exception as exc:
        _record_persistence_failure(
            scratchpad, "enumeration.axis1.emission", keys, exc
        )
        return {"gaps": len(gaps), "emitted": 0}

    # Only now are ``retained`` rows true: inventory and key receipt are both
    # durable. A failure above records UNKNOWN instead of a false exact count.
    cap_rows = []
    if len(eligible) > _MAX_ENUMGAP_PER_RUN:
        cap_rows.append(shortfall(
            producer="enumeration.axis1.emission",
            scope="coverage-gap-emission",
            cap="MAX_ENUMGAP_PER_RUN",
            limit=_MAX_ENUMGAP_PER_RUN,
            observed=len(eligible),
            retained=len(keys),
            exact=True,
            samples=[key for _g, _fn, key in eligible[_MAX_ENUMGAP_PER_RUN:]],
            detail="co-reference coverage gaps exceeded the per-run verify budget",
        ))
    try:
        replace_producer_shortfalls(
            scratchpad, "enumeration.axis1.emission", cap_rows
        )
    except Exception:
        pass
    try:
        from plamen_mechanical import _write_finding_records_from_inventory
        _write_finding_records_from_inventory(scratchpad)
    except Exception:
        pass
    required = set(keys)
    if not required.issubset(_inventory_candidate_keys(scratchpad)) or not required.issubset(
        _receipt_candidate_keys(scratchpad)
    ):
        _record_persistence_failure(
            scratchpad,
            "enumeration.axis1.emission",
            sorted(required),
            RuntimeError("post-write candidate/receipt subset check failed"),
        )
        return {"gaps": len(gaps), "emitted": 0}
    return {"gaps": len(gaps), "emitted": len(keys)}


def validate_enumeration_coverage(scratchpad: Path) -> dict:
    """Transaction-safe public G2 entry point."""
    with _candidate_transaction(Path(scratchpad)):
        return _validate_enumeration_coverage_unlocked(Path(scratchpad))


# ─────────────────────────────────────────────────────────────────────────────
# Additional mechanical obligation-derivers.
#
# The shared-state co-reference gate above is ONE obligation type. These add more
# bug-class SHAPES that are (a) mechanically identifiable from source and (b) a
# systematic agent blind spot ("enumerated then dismissed"). Each derives an
# obligation and emits a low-confidence ENUMGAP candidate the verify filter
# prunes — same recall-safe, append-only, idempotent framework. No-overfit: every
# deriver encodes a generic pattern (HOW), never a protocol's specific bug.
#
#   critical_asset_mover (L-04 class): a protocol-critical SINGLETON asset handle
#       (a state var ending in *Id/*TokenId, depended on by >=2 functions) can be
#       moved by a same-contract GENERIC asset-mover that does not exclude it.
#   array_uniqueness     (L-10 class): a function loops a caller-supplied array
#       with a per-element value effect and NO uniqueness guard.
#   unbounded_input      (L-08 class): a caller-controlled string/bytes is stored
#       or looped with NO length bound (storage-bloat / gas-bomb DoS).
# ─────────────────────────────────────────────────────────────────────────────

_MAX_PER_DERIVER = 15   # per-deriver, per-run cap (shared global budget on top)


def _write_candidate_artifact(path: Path, text: str) -> None:
    """Durably replace one candidate artifact via a unique same-dir temp."""
    path = Path(path)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    try:
        with tmp.open("w", encoding="utf-8", newline="") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        tmp.replace(path)
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except Exception:
            pass


def _candidate_key_marker(key: object) -> str:
    clean = re.sub(r"[\s>]+", "_", str(key or "").strip())
    return f"<!-- ENUMGAP-KEY: {clean} -->" if clean else ""


def _receipt_candidate_keys(scratchpad: Path) -> set[str]:
    receipt = Path(scratchpad) / "enumeration_gap_receipt.md"
    if not receipt.exists():
        return set()
    try:
        return set(re.findall(
            r"\bENUMGAP-KEY:\s*([^\s>`]+)",
            receipt.read_text(encoding="utf-8", errors="replace"),
        ))
    except Exception:
        return set()


def _inventory_candidate_keys(scratchpad: Path) -> set[str]:
    """Recover keys only from typed markers in actual finding blocks."""
    inventory = Path(scratchpad) / "findings_inventory.md"
    if not inventory.exists():
        return set()
    try:
        text = inventory.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return set()
    keys: set[str] = set()
    headings = list(FINDING_BLOCK_HEADING_RE.finditer(text))
    for index, heading in enumerate(headings):
        end = headings[index + 1].start() if index + 1 < len(headings) else len(text)
        block = text[heading.start():end]
        source = _field_from_markdown(block, ("Source IDs", "Source ID"))
        if not re.search(r"\b(?:ENUMGAP|VARGAP|INVARIANT)\b", source, re.IGNORECASE):
            continue
        keys.update(re.findall(
            r"<!--\s*ENUMGAP-KEY:\s*([^\s>]+)\s*-->", block
        ))
    return keys


def _emitted_candidate_keys(scratchpad: Path) -> set[str]:
    """Recover durable keys from typed markers in actual inventory blocks.

    Inventory markers make a receipt-write failure resumable without emitting a
    duplicate finding. The reverse is not true: a receipt whose inventory row
    vanished is stale and must not suppress re-emission. A later successful
    call rebuilds the receipt from inventory before clearing PERSISTENCE_FAILED.
    """
    return _inventory_candidate_keys(scratchpad)


def _candidate_receipt_text(keys: set[str]) -> str:
    lines = ["# Enumeration Gap Receipt", ""]
    lines += [f"ENUMGAP-KEY: {key}" for key in sorted(keys)]
    return "\n".join(lines) + "\n"


def _record_persistence_failure(
    scratchpad: Path, producer: str, keys: list[str], exc: BaseException
) -> None:
    try:
        replace_producer_shortfalls(
            scratchpad,
            producer,
            [unknown_shortfall(
                producer=producer,
                scope="candidate-emission",
                kind="PERSISTENCE_FAILED",
                detail=(
                    "candidate inventory/key receipt did not both become durable; "
                    f"resume must reconcile before coverage is considered retained ({type(exc).__name__})"
                ),
                samples=keys,
            )],
        )
    except Exception:
        # The audit remains haltless even if the control-plane ledger itself is
        # unavailable; the caller reports zero durable emissions.
        pass


def _unseen_candidate_count(candidates: list, emitted: set[str]) -> int:
    return len({
        str(c.get("key", "")) for c in candidates
        if c.get("key") and c.get("key") not in emitted
    })


def _bounded_deriver_result(
    scratchpad: Path, producer: str, candidates: list
) -> list:
    """Return at most ``_MAX_PER_DERIVER`` rows and expose scan truncation.

    Source derivers stop after discovering the first overflow candidate to keep
    repository scans bounded. Consequently the total is a LOWER_BOUND, not an
    exact population. ``retained`` here means selected for return to the
    downstream emitter, not durably persisted; the emitter owns that separate
    persistence receipt.
    """
    emitted = _emitted_candidate_keys(scratchpad)
    unseen: list[dict] = []
    unseen_keys: set[str] = set()
    for candidate in candidates:
        key = str(candidate.get("key", ""))
        if not key or key in emitted or key in unseen_keys:
            continue
        unseen_keys.add(key)
        unseen.append(candidate)
    rows: list[dict] = []
    if len(unseen) > _MAX_PER_DERIVER:
        rows.append(shortfall(
            producer=producer,
            scope="source-candidate-scan",
            cap="MAX_PER_DERIVER",
            limit=_MAX_PER_DERIVER,
            observed=len(unseen),
            retained=_MAX_PER_DERIVER,
            exact=False,
            samples=[c.get("key", "") for c in unseen[_MAX_PER_DERIVER:]],
            detail=("source scan stopped after the first overflow candidate; "
                    "retained rows were selected for return, not yet durably "
                    "persisted, and additional candidates may exist"),
        ))
    try:
        replace_producer_shortfalls(scratchpad, producer, rows)
    except Exception:
        pass
    return unseen[:_MAX_PER_DERIVER]

# ── Per-language signal registry ──────────────────────────────────────────────
# The 3 obligation-derivers are bug-class SHAPES, not Solidity idioms. A language
# appears for a vector only where that vector's shape genuinely exists (honest
# applicability — not every vector maps to every ecosystem):
#   L-04 critical-asset-mover : sol, rust, move          (NOT go node-clients / daml)
#   L-10 array-uniqueness     : sol, rust, move, go      (NOT daml)
#   L-08 unbounded-input      : sol, rust, move, go      (NOT daml)
# A vector key absent from a language's spec => that deriver skips that language
# (`.get(...)` lookup — see compute_array_uniqueness_candidates /
# compute_unbounded_input_candidates / compute_critical_asset_mover_candidates).
# All param regexes use NAMED groups (?P<name>/?P<typ>) so the language-agnostic
# deriver code reads them uniformly regardless of declaration order.
#
# `daml` is intentionally a PARTIAL entry (fn_re + effect only). It exists
# ONLY to feed the M2 hot-function/axis-coverage matrix (_value_effect_res,
# compute_hot_function_set, compute_axis_coverage_gaps) — those consumers are
# language-agnostic and already `.get()`-degrade cleanly for an absent
# language, so a DAML choice was previously ALWAYS `value_effect=False`,
# forcing the theft/identity axes to a provable N/A even for a value-moving
# choice whose only state reference happens to be a uniquely-referenced field
# (dropped by `_finalize_source_graph`'s `1 < len(fns) <= 25` var_refs filter
# in recon_prepass.py). `effect` below closes that hole. L-04/L-08/L-10 need a
# `with`-block field-type grammar (`array_param`/`str_param`/`mover`/
# `id_param`/`asset_handle`) this entry does NOT parse — those keys are
# deliberately omitted so those 3 derivers stay a no-op for DAML rather than
# fabricate an unvalidated param-shape regex with no real DAML repo to
# validate it against (see plamen_repo research note, applicability verdict).
def _c(p):
    return re.compile(p, re.MULTILINE)


_LANG = {
    "sol": {
        "suffix": (".sol",),
        "fn_re": _c(r"\bfunction\s+(\w+)\s*\(([^)]*)\)"),
        "array_param": _c(r"\b[\w.]+\[\]\s+(?:memory|calldata|storage)\s+(?P<name>\w+)"),
        "loop": _c(r"\b(?:for|while)\s*\("),
        "effect": _c(r"(?:safeTransferFrom|safeTransfer|transferFrom|\btransfer\b"
                     r"|\bmint\b|\bburn\b|\+=|\.push\()"),
        "uniq_guard": _c(r"(?i)\b(?:seen|unique|dedup|duplicat|sorted?|_sort)\b"),
        "str_param": _c(r"\b(?P<typ>string|bytes)\s+(?:memory|calldata)\s+(?P<name>\w+)"),
        "stored_tpl": (r"[\w.]+\s*\[[^\]]*\]\s*=\s*[^;]*\b{p}\b|\.push\(\s*{p}\b"
                       r"|=\s*\w+\s*\(\s*\{{[^}}]*\b{p}\b"),
        "lenguard_tpl": (r"(?:require|if)\b[^;{{]*(?:bytes\(\s*)?{p}\s*\)?\s*"
                         r"\.length\s*(?:<=|<|>=|>)"),
        "mover": _c(r"(?:\bI?ERC(?:20|721|1155)\s*\([^)]*\)\s*)?\.\s*"
                    r"(?:safeTransferFrom|transferFrom)\s*\(|\b_(?:safeTransfer|transfer)\s*\("),
        "id_param": _c(r"\b(?:uint256|uint|address)\s+(?:memory\s+|calldata\s+)?"
                       r"(\w*[Ii]d\b|\w*[Tt]oken\w*|to|token|asset|recipient)"),
        "asset_handle": _c(r"(?i)(?:tokenId|nftId|positionId|lpId)$|(?:Token|Nft|Position|Lp)Id$"),
    },
    "rust": {
        "suffix": (".rs",),
        "fn_re": _c(r"\bfn\s+(\w+)\s*(?:<[^>]*>)?\s*\(([^)]*)\)"),
        "array_param": _c(r"\b(?P<name>\w+)\s*:\s*&?(?:mut\s+)?(?:Vec\s*<|\[(?![^\]\n]*;))"),
        "loop": _c(r"\bfor\b|\.iter(?:_mut)?\(\)|\.into_iter\(\)|\bwhile\b"),
        # Token-MOVEMENT only (Fix 3c): bare `+=`/`.push(`/`.set(`/deposit/
        # withdraw over-matched non-value Rust code and diluted the Soroban
        # hot-set, inflating false GAP cells. Keep only actual asset movement.
        "effect": _c(r"\btransfer_from\b|\btransfer\b|\bmint\b|\bburn\b"
                     r"|token::transfer|\bTokenClient\b"),
        "uniq_guard": _c(r"(?i)\b(?:seen|unique|dedup|duplicat|sort|hashset|btreeset)\b"),
        "str_param": _c(r"\b(?P<name>\w+)\s*:\s*&?(?:mut\s+)?"
                        r"(?P<typ>String|str|Vec\s*<\s*u8|\[\s*u8\s*\])"),
        "stored_tpl": (r"(?:\.set\(|\.push\(|=\s*\w+\s*\{{|extend|insert\()[^;]*\b{p}\b"),
        "lenguard_tpl": r"\b{p}\b(?:\.as_bytes\(\))?\.len\(\)\s*(?:<=|<|>=|>)",
        "mover": _c(r"\.transfer(?:_from)?\s*\(|token::transfer|TokenClient|::transfer\s*\("),
        "id_param": _c(r"\b(\w*_?id|token|asset|to|recipient)\s*:"),
        "asset_handle": _c(r"(?i)(?:token_?id|nft_?id|position_?id|lp_?id|object_?id)$"),
    },
    "move": {
        "suffix": (".move",),
        "fn_re": _c(r"\b(?:public\s*(?:\([^)]*\))?\s+|entry\s+)*fun\s+(\w+)"
                    r"\s*(?:<[^>]*>)?\s*\(([^)]*)\)"),
        "array_param": _c(r"\b(?P<name>\w+)\s*:\s*(?:&\s*(?:mut\s+)?)?vector\s*<"),
        "loop": _c(r"\bwhile\b|\bloop\b|for_each"),
        "effect": _c(r"\btransfer\b|coin::|\bmint\b|\bburn\b|\+=|vector::push"
                     r"|\bdeposit\b|\bwithdraw\b|public_transfer"),
        "uniq_guard": _c(r"(?i)\b(?:seen|unique|dedup|duplicat|sort|contains)\b"),
        "str_param": _c(r"\b(?P<name>\w+)\s*:\s*(?:&\s*)?(?P<typ>vector\s*<\s*u8|String|string)"),
        "stored_tpl": (r"(?:move_to|borrow_global_mut|vector::push|=)\s*[^;]*\b{p}\b"),
        "lenguard_tpl": (r"(?:assert!|if)\b[^;{{]*(?:vector::length|\.length)"
                         r"\([^)]*\b{p}\b[^;{{]*(?:<=|<|>=|>)"),
        "mover": _c(r"transfer::(?:public_)?transfer|coin::transfer|::transfer\s*\("),
        "id_param": _c(r"\b(\w*_?id|token|asset|to|recipient)\s*:"),
        "asset_handle": _c(r"(?i)(?:token_?id|nft_?id|object_?id|position_?id|lp_?id)$"),
    },
    "go": {
        "suffix": (".go",),
        "fn_re": _c(r"\bfunc\s+(?:\([^)]*\)\s*)?(\w+)\s*\(([^)]*)\)"),
        "array_param": _c(r"\b(?P<name>\w+)\s+\[\]\w"),
        "loop": _c(r"\bfor\b|\brange\b"),
        "effect": _c(r"\+=|append\(|\.Add\(|\btransfer\b"),
        "uniq_guard": _c(r"(?i)\b(?:seen|unique|dedup|duplicat|sort)\b|map\["),
        "str_param": _c(r"\b(?P<name>\w+)\s+(?P<typ>string|\[\]byte)\b"),
        "stored_tpl": (r"\b\w+\s*\[[^\]]*\]\s*=\s*[^;\n]*\b{p}\b|append\([^)]*\b{p}\b"
                       r"|=\s*[^;\n]*\b{p}\b"),
        "lenguard_tpl": r"len\(\s*{p}\s*\)\s*(?:<=|<|>=|>)",
        # no mover/id_param/asset_handle: L-04 N/A for Go node-clients.
    },
    "daml": {
        "suffix": (".daml",),
        # group(1)=choice name — SAME grammar as recon_prepass._DAML_CHOICE_RE
        # so the bare name here joins the choice-keyed graph `_bake_daml_graph`
        # emits (`functions`/`var_refs` are keyed by choice name, not a
        # `Contract.choice` qualified path). group(2) is a throwaway
        # rest-of-declaration-line capture — `_iter_functions` requires a 2nd
        # group (`m.group(2)`); DAML choice syntax has no parenthesized param
        # list to capture, unlike sol/rust/move/go.
        "fn_re": _c(r"\b(?:nonconsuming\s+)?choice\s+(\w+)\b([^\n]*)"),
        # DAML value/authority movement: creating or archiving a contract (or
        # exercising another choice, which recurses into more create/archive)
        # is the only way a choice moves the value/quantity a contract
        # represents between parties — the DAML analog of sol's transfer/mint
        # or rust's token::transfer. Sets `value_effect=True` for
        # compute_hot_function_set / the theft+identity axis N/A gate in
        # compute_axis_coverage_gaps (both consume `_value_effect_res`).
        "effect": _c(r"\b(?:create|createAndExercise|archive|exercise|exerciseByKey)\b"),
        # Deliberately NO array_param/str_param/loop/uniq_guard/stored_tpl/
        # lenguard_tpl/mover/id_param/asset_handle: L-04/L-08/L-10 need a
        # `with`-block field-type grammar this entry does not parse, so those
        # 3 derivers stay a no-op for DAML (see the block comment above).
    },
}
_SUPPORTED_SUFFIXES = tuple(s for spec in _LANG.values() for s in spec["suffix"])


def _locate_project_root(scratchpad: Path):
    """The SC/L1 audit scratchpad is `<project_root>/.scratchpad`; the gate is not
    handed the source tree, so derive it. Returns the dir holding any supported
    source file, or None."""
    try:
        cand = Path(scratchpad).parent
        for suf in _SUPPORTED_SUFFIXES:
            if any(cand.rglob("*" + suf)):
                return cand
    except Exception:
        pass
    return None


def _iter_functions(root: Path):
    """Yield (lang, rel_path, fn_name, params, body, line) for each PRODUCTION
    function across every supported language present (tests/mocks excluded).
    Approximate body slice (decl→next decl). Never raises; empty on any failure."""
    try:
        from recon_prepass import (_production_source_files, _read_text,
                                    _line_of, _rel)  # type: ignore
    except Exception:
        return
    for lang, spec in _LANG.items():
        try:
            files = _production_source_files(root, spec["suffix"])
        except Exception:
            continue
        fn_re = spec["fn_re"]
        for f in files:
            text = _read_text(f)
            if not text:
                continue
            decls = list(fn_re.finditer(text))
            for i, m in enumerate(decls):
                end = decls[i + 1].start() if i + 1 < len(decls) else len(text)
                try:
                    yield (lang, _rel(f, root), m.group(1), m.group(2) or "",
                           text[m.end():end], _line_of(text, m.start()))
                except Exception:
                    continue


def _emit_candidates_unlocked(scratchpad: Path, candidates: list, cap: int,
                              source_id: str = "ENUMGAP", producer: str = "") -> int:
    """Shared ENUMGAP emitter for every deriver. `candidates` are dicts with:
    key, title, location, source_note, root_cause, description, impact.
    Append-only to findings_inventory.md, idempotent via the SHARED receipt,
    honours `cap` new emissions (per-deriver run budget). Returns count emitted.

    `source_id` stamps the `**Source IDs**:` field (default `ENUMGAP` for the
    co-reference derivers). M1 passes `INVARIANT` so committed-invariant
    candidates stay traceable and distinct for dedup/coverage accounting; the
    stamped tag never changes the `INV-NNN` finding ID (always cataloged).
    A candidate may carry an optional per-candidate `source_tag` (e.g.
    `INVARIANT:CI-3`) — a clean, greppable generator class token that overrides
    `source_id` for that block, so attribution stays machine-recoverable even
    after a downstream provenance-preserving dedup merge."""
    scratchpad = Path(scratchpad)
    cap = max(0, int(cap))
    receipt_producer = producer or f"enumeration.emitter.{source_id.lower()}"
    if not candidates:
        seen = _emitted_candidate_keys(scratchpad)
        if seen != _receipt_candidate_keys(scratchpad):
            try:
                _write_candidate_artifact(
                    scratchpad / "enumeration_gap_receipt.md",
                    _candidate_receipt_text(seen),
                )
            except Exception as exc:
                _record_persistence_failure(
                    scratchpad, receipt_producer, sorted(seen), exc
                )
                return 0
        try:
            replace_producer_shortfalls(scratchpad, receipt_producer, [])
        except Exception:
            pass
        return 0
    inv = scratchpad / "findings_inventory.md"
    try:
        inv_text = inv.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        _record_persistence_failure(
            scratchpad, receipt_producer,
            [str(c.get("key", "")) for c in candidates], exc,
        )
        return 0
    receipt = scratchpad / "enumeration_gap_receipt.md"
    seen = _emitted_candidate_keys(scratchpad)
    receipt_keys = _receipt_candidate_keys(scratchpad)
    # Intra-run dedup baseline: `seen` is the persisted (cross-run) receipt set;
    # `emitted` ALSO tracks keys appended earlier in THIS call so two candidates
    # with an identical key are not double-emitted within one run (the observed
    # sibling-deriver double-emit). `seen` stays receipt-only so the receipt is
    # not double-written below.
    emitted: set = set(seen)
    max_inv = 0
    for m in re.finditer(r"\bINV-(\d+)\b", inv_text):
        try:
            max_inv = max(max_inv, int(m.group(1)))
        except ValueError:
            pass
    # Determine the exact unseen population before applying the budget.  This
    # makes the receipt an accounting fact rather than an inference from the
    # number emitted. Preserve source order while removing duplicate keys.
    eligible: list[dict] = []
    eligible_keys: set[str] = set()
    for c in candidates:
        key = c.get("key", "")
        if not key or key in emitted or key in eligible_keys:
            continue
        eligible_keys.add(key)
        eligible.append(c)
    appended: list[str] = []
    keys: list[str] = []
    n = 0
    for c in eligible[:cap]:
        n += 1
        inv_id = f"INV-{max_inv + n:03d}"
        appended.extend([
            f"### Finding [{inv_id}]: {c['title']}",
            "**Severity**: Low",
            f"**Location**: {c['location']}",
            "**Preferred Tag**: [CODE-TRACE]",
            f"**Source IDs**: {c.get('source_tag') or source_id} ({c['source_note']})",
            "**Verdict**: NEEDS_VERIFICATION",
            f"**Root Cause**: {c['root_cause']}",
            f"**Description**: {c['description']}",
            f"**Impact**: {c['impact']}",
            _candidate_key_marker(c["key"]),
            # Generic chain-matchable pre/post metadata (per-deriver class) so a
            # weak candidate can still serve as a chain enabler. Omitted when a
            # deriver supplies none.
            *_chain_metadata_lines(
                postcondition=c.get("postcondition", ""),
                postcondition_type=c.get("postcondition_type", ""),
                missing_precondition=c.get("missing_precondition", ""),
                precondition_type=c.get("precondition_type", ""),
            ),
            "",
        ])
        keys.append(c["key"])
        emitted.add(c["key"])
    if not appended:
        if seen != receipt_keys:
            try:
                _write_candidate_artifact(receipt, _candidate_receipt_text(seen))
            except Exception as exc:
                _record_persistence_failure(
                    scratchpad, receipt_producer, sorted(seen), exc
                )
                return 0
        rows = []
        if len(eligible) > cap:
            rows = [shortfall(
                producer=receipt_producer,
                scope="candidate-emission",
                cap="EMISSION_BUDGET",
                limit=cap,
                observed=len(eligible),
                retained=0,
                exact=True,
                samples=[c.get("key", "") for c in eligible],
                detail="derived candidates exceeded the per-deriver verify budget",
            )]
        try:
            replace_producer_shortfalls(scratchpad, receipt_producer, rows)
        except Exception:
            pass
        return 0
    header = ("\n\n## Enumeration-Coverage Candidates (ENUMGAP)\n\n"
              "Mechanically-derived obligations a finding's analysis did NOT "
              "address. Low-confidence by construction — the verify phase confirms "
              "or refutes each. Recall-safe: append-only.\n\n")
    hdr = "" if "Enumeration-Coverage Candidates (ENUMGAP)" in inv_text else header
    try:
        _write_candidate_artifact(
            inv, _append_inventory_blocks(inv_text, hdr, appended)
        )
        _write_candidate_artifact(
            receipt, _candidate_receipt_text(seen | set(keys))
        )
    except Exception as exc:
        _record_persistence_failure(
            scratchpad, receipt_producer, keys, exc
        )
        return 0

    rows = []
    if len(eligible) > cap:
        rows = [shortfall(
            producer=receipt_producer,
            scope="candidate-emission",
            cap="EMISSION_BUDGET",
            limit=cap,
            observed=len(eligible),
            retained=len(keys),
            exact=True,
            samples=[c.get("key", "") for c in eligible[cap:]],
            detail="derived candidates exceeded the per-deriver verify budget",
        )]
    try:
        replace_producer_shortfalls(scratchpad, receipt_producer, rows)
    except Exception:
        pass
    try:
        from plamen_mechanical import _write_finding_records_from_inventory
        _write_finding_records_from_inventory(scratchpad)
    except Exception:
        pass
    required = set(keys)
    if not required.issubset(_inventory_candidate_keys(scratchpad)) or not required.issubset(
        _receipt_candidate_keys(scratchpad)
    ):
        _record_persistence_failure(
            scratchpad,
            receipt_producer,
            sorted(required),
            RuntimeError("post-write candidate/receipt subset check failed"),
        )
        return 0
    return len(keys)


def _emit_candidates(scratchpad: Path, candidates: list, cap: int,
                     source_id: str = "ENUMGAP", producer: str = "") -> int:
    """Transaction-safe shared candidate emitter."""
    with _candidate_transaction(Path(scratchpad)):
        return _emit_candidates_unlocked(
            Path(scratchpad), candidates, cap,
            source_id=source_id, producer=producer,
        )


def compute_critical_asset_mover_candidates(scratchpad: Path) -> list:
    """L-04 class (sol/rust/move). A protocol-critical singleton asset handle (a
    state/storage var named like an asset id, depended on by >=2 functions) that a
    SAME-FILE generic asset-mover can move WITHOUT excluding it → the mover can
    strand every function that depends on that asset. Generic across ecosystems
    that hold movable assets; bounded to the declaring file. Go node-clients and
    DAML have no such shape and are skipped (no `mover` in their lang spec)."""
    producer = "enumeration.deriver.critical_asset_mover.scan"
    try:
        graph = _load_graph(scratchpad)
        root = _locate_project_root(scratchpad)
        if graph is None or root is None:
            replace_producer_shortfalls(
                scratchpad, producer, [unknown_shortfall(
                    producer=producer,
                    scope="candidate-provider",
                    kind="PROVIDER_UNAVAILABLE",
                    detail="critical-asset mover scan requires both project root and mechanical graph",
                )],
            )
            return []
        # asset-handle match = the asset_handle pattern(s) for the language(s)
        # ACTUALLY present in the project tree (one audit is one ecosystem).
        # Scoping to present languages stops e.g. the rust/move id-stem shape from
        # matching an EVM ALL-CAPS chain-id constant when the audited ecosystem is
        # EVM. Haltless fallback to the full union if detection finds nothing.
        langs_present = {
            lang for lang, spec in _LANG.items()
            if "asset_handle" in spec
            and any(next(root.rglob("*" + suf), None) for suf in spec["suffix"])
        }
        handle_res = [_LANG[l]["asset_handle"] for l in langs_present]
        if not handle_res:  # detection found nothing → preserve prior behavior
            handle_res = [spec["asset_handle"] for spec in _LANG.values()
                          if "asset_handle" in spec]
        var_refs = graph.get("var_refs", {})
        crit: dict = {}    # bare -> [dependent fns]
        for vk, vd in var_refs.items():
            bare = vd.get("bare", vk.split(".")[-1])
            refs = vd.get("refs", [])
            if (any(r.search(bare) for r in handle_res)
                    and 2 <= len(refs) <= _SKIP_VAR_REF_THRESHOLD):
                crit[bare] = sorted({_bare_from_descriptor(d) for d in refs})
        if not crit:
            return _bounded_deriver_result(scratchpad, producer, [])
        # Same-file bound: which production file declares/holds each critical var?
        # (The source-tier graph keys var_refs by BARE name with no contract.)
        # Lang-agnostic: the file where the bare name appears as a word.
        decl_files: dict = {b: set() for b in crit}
        try:
            from recon_prepass import (_production_source_files, _read_text,
                                        _rel)  # type: ignore
            for f in _production_source_files(root, _SUPPORTED_SUFFIXES):
                t = _read_text(f)
                if not t:
                    continue
                rel_f = _rel(f, root)
                for b in crit:
                    if re.search(r"\b" + re.escape(b) + r"\b", t):
                        decl_files[b].add(rel_f)
        except Exception:
            pass
        out: list = []
        seen_pairs: set = set()
        emitted_keys = _emitted_candidate_keys(scratchpad)
        for lang, rel, name, params, body, _line in _iter_functions(root):
            if _unseen_candidate_count(out, emitted_keys) > _MAX_PER_DERIVER:
                break
            spec = _LANG[lang]
            mover = spec.get("mover")
            id_param = spec.get("id_param")
            if mover is None or id_param is None:   # L-04 N/A for this language
                continue
            if not mover.search(body) or not id_param.search(params):
                continue
            for bare, fns in crit.items():
                if decl_files.get(bare) and rel not in decl_files[bare]:
                    continue
                if re.search(r"\b" + re.escape(bare) + r"\b", body) or name in fns:
                    continue   # mover already references/excludes the critical var
                pairkey = f"{rel}:{name}:{bare}"
                if pairkey in seen_pairs:
                    continue
                seen_pairs.add(pairkey)
                dep = ", ".join(f"`{x}`" for x in fns[:6])
                out.append({
                    "key": f"ASSETMOVE:{pairkey}",
                    "title": (f"Generic asset-mover `{name}` can move the critical "
                              f"singleton `{bare}` that other functions depend on"),
                    "location": f"`{rel}` :: `{name}` (critical asset `{bare}`)",
                    "source_note": "critical-asset-mover gap; mechanically derived — verifier to confirm or refute",
                    "root_cause": (f"`{name}` transfers an asset selected by a caller "
                                   f"parameter and does not exclude `{bare}`. `{bare}` "
                                   f"is a singleton the protocol depends on (referenced "
                                   f"by {dep}). Moving it out would strand those functions."),
                    "description": (f"`{name}` is a generic asset-mover; `{bare}` is a "
                                    f"protocol-critical singleton asset. Verify `{name}` "
                                    f"cannot move `{bare}` (or that doing so does not "
                                    f"break {dep})."),
                    "impact": ("Potential permanent breakage of the dependent functions "
                               "if the critical asset is moved (verifier to confirm)."),
                    # L-04 class → STATE postcondition: the mover relocates a
                    # protocol-critical singleton out of the contract.
                    "postcondition": (f"STATE: critical singleton asset `{bare}` relocated "
                                      f"out of the contract, stranding dependent functions"),
                    "postcondition_type": "STATE",
                })
                if _unseen_candidate_count(out, emitted_keys) > _MAX_PER_DERIVER:
                    break
        return _bounded_deriver_result(scratchpad, producer, out)
    except Exception as exc:
        try:
            replace_producer_shortfalls(
                scratchpad, producer, [unknown_shortfall(
                    producer=producer,
                    scope="candidate-provider",
                    kind="PROVIDER_FAILED",
                    detail=f"critical-asset mover scan failed: {exc!r}",
                )],
            )
        except Exception:
            pass
        return []


def compute_array_uniqueness_candidates(scratchpad: Path) -> list:
    """L-10 class (sol/rust/move/go). A function loops a caller-supplied array/
    vector/slice producing a per-element value effect with NO uniqueness guard →
    duplicate elements multiply the effect. Universal source-parse shape."""
    producer = "enumeration.deriver.array_uniqueness.scan"
    try:
        root = _locate_project_root(scratchpad)
        if root is None:
            replace_producer_shortfalls(
                scratchpad, producer, [unknown_shortfall(
                    producer=producer,
                    scope="candidate-provider",
                    kind="PROVIDER_UNAVAILABLE",
                    detail="array-uniqueness scan cannot locate the project root",
                )],
            )
            return []
        out: list = []
        emitted_keys = _emitted_candidate_keys(scratchpad)
        for lang, rel, name, params, body, _line in _iter_functions(root):
            if _unseen_candidate_count(out, emitted_keys) > _MAX_PER_DERIVER:
                break
            spec = _LANG[lang]
            arr_re = spec.get("array_param")
            if arr_re is None:   # L-10 N/A for this language (e.g. DAML: no
                continue         # `with`-block field-type grammar parsed yet)
            arr = arr_re.search(params)
            if not arr:
                continue
            arrname = arr.group("name")
            e = re.escape(arrname)
            # Bind the per-element premise: the array must be ELEMENT-ACCESSED
            # (indexed / iterated), not merely passed wholesale to a callee. This
            # is what distinguishes a per-element value-effect loop from framework
            # plumbing arrays handed off intact (e.g. CPI signer-seeds, account
            # slices, calldata blobs) which never apply a per-element effect.
            elem_access = re.search(
                r"\b" + e + r"\s*\["
                r"|\b(?:range|in)\s+&?(?:mut\s+)?" + e + r"\b"
                r"|\b" + e + r"\s*\.\s*(?:iter|into_iter)\b"
                r"|\b(?:borrow|borrow_mut|for_each)\s*\(\s*&?(?:mut\s+)?" + e + r"\b",
                body)
            if not elem_access:
                continue
            iterates = (re.search(r"\b" + e + r"\b", body)
                        and spec["loop"].search(body))
            if not iterates or not spec["effect"].search(body):
                continue
            if spec["uniq_guard"].search(body):
                continue
            out.append({
                "key": f"ARRUNIQ:{rel}:{name}:{arrname}",
                "title": (f"`{name}` applies a per-element effect over caller array "
                          f"`{arrname}` with no uniqueness guard"),
                "location": f"`{rel}` :: `{name}` (array `{arrname}`)",
                "source_note": "array-uniqueness gap; mechanically derived — verifier to confirm or refute",
                "root_cause": (f"`{name}` loops the caller-supplied array `{arrname}` and "
                               f"performs a per-element value effect (transfer/mint/burn/"
                               f"accumulate) without validating element uniqueness. A "
                               f"repeated element has its effect applied multiple times."),
                "description": (f"Verify that passing a duplicate element in `{arrname}` "
                                f"does not double-count a payout/mint/burn/accumulation in "
                                f"`{name}` (e.g. draining a pool via repeated pro-rata credit)."),
                "impact": ("Potential multiplied value effect (e.g. over-payout / pool "
                           "drain) from duplicate array elements (verifier to confirm)."),
                # L-10 class → BALANCE/accounting postcondition: a per-element
                # value effect is applied more times than the distinct set.
                "postcondition": (f"BALANCE: per-element value effect in `{name}` applied "
                                  f"multiple times via duplicate `{arrname}` elements "
                                  "(accounting inflation)"),
                "postcondition_type": "BALANCE",
            })
        return _bounded_deriver_result(scratchpad, producer, out)
    except Exception as exc:
        try:
            replace_producer_shortfalls(
                scratchpad, producer, [unknown_shortfall(
                    producer=producer,
                    scope="candidate-provider",
                    kind="PROVIDER_FAILED",
                    detail=f"array-uniqueness scan failed: {exc!r}",
                )],
            )
        except Exception:
            pass
        return []


def compute_unbounded_input_candidates(scratchpad: Path) -> list:
    """L-08 class (sol/rust/move/go). A caller-controlled string/bytes value is
    stored on-chain with NO length bound → storage-bloat / gas-bomb DoS. Universal
    source-parse shape (Rust String/Vec<u8>, Move vector<u8>, Go []byte)."""
    producer = "enumeration.deriver.unbounded_input.scan"
    try:
        root = _locate_project_root(scratchpad)
        if root is None:
            replace_producer_shortfalls(
                scratchpad, producer, [unknown_shortfall(
                    producer=producer,
                    scope="candidate-provider",
                    kind="PROVIDER_UNAVAILABLE",
                    detail="unbounded-input scan cannot locate the project root",
                )],
            )
            return []
        out: list = []
        emitted_keys = _emitted_candidate_keys(scratchpad)
        for lang, rel, name, params, body, _line in _iter_functions(root):
            if _unseen_candidate_count(out, emitted_keys) > _MAX_PER_DERIVER:
                break
            spec = _LANG[lang]
            # Sol pure/view functions cannot write storage — the stored-input
            # storage-bloat harm premise is impossible for them. The modifier
            # section (where pure/view appears) precedes the body's opening brace.
            # Recall-safe: any storage-writing function is non-pure/view.
            if lang == "sol":
                head = body[:body.find("{")] if "{" in body else body[:160]
                if re.search(r"\b(?:pure|view)\b", head):
                    continue
            str_param_re = spec.get("str_param")
            if str_param_re is None:   # L-08 N/A for this language (e.g. DAML:
                continue                # no `with`-block field-type grammar yet)
            for m in str_param_re.finditer(params):
                pname = m.group("name")
                typ = (m.groupdict().get("typ") or "input").strip()
                p = re.escape(pname)
                stored = bool(re.search(spec["stored_tpl"].format(p=p), body))
                if not stored:
                    continue
                # UPPER length bound? A non-empty (== 0) check is NOT an upper
                # bound — the templates require an inequality comparator.
                if re.search(spec["lenguard_tpl"].format(p=p), body):
                    continue
                out.append({
                    "key": f"UNBOUND:{rel}:{name}:{pname}",
                    "title": (f"`{name}` stores caller-controlled `{typ} {pname}` "
                              f"with no length bound"),
                    "location": f"`{rel}` :: `{name}` (param `{typ} {pname}`)",
                    "source_note": "unbounded-input gap; mechanically derived — verifier to confirm or refute",
                    "root_cause": (f"`{name}` accepts a caller-controlled `{typ} {pname}` and "
                                   f"stores it without a length bound. A very large value "
                                   f"bloats storage and can gas-bomb later execution that "
                                   f"reads/iterates it."),
                    "description": (f"Verify there is an upper bound on `{pname}` in `{name}`; "
                                    f"without one, an oversized `{typ}` enables storage-bloat "
                                    f"or a gas-bomb DoS on downstream execution."),
                    "impact": ("Potential storage-bloat or gas-bomb DoS bricking later "
                               "execution (verifier to confirm)."),
                    # L-08 class → liveness/EXTERNAL postcondition: an oversized
                    # stored value can brick downstream execution that reads it.
                    "postcondition": (f"EXTERNAL: oversized stored `{typ} {pname}` enables a "
                                      f"gas-bomb/liveness DoS on later execution that reads it"),
                    "postcondition_type": "EXTERNAL",
                })
                if _unseen_candidate_count(out, emitted_keys) > _MAX_PER_DERIVER:
                    break
        return _bounded_deriver_result(scratchpad, producer, out)
    except Exception as exc:
        try:
            replace_producer_shortfalls(
                scratchpad, producer, [unknown_shortfall(
                    producer=producer,
                    scope="candidate-provider",
                    kind="PROVIDER_FAILED",
                    detail=f"unbounded-input scan failed: {exc!r}",
                )],
            )
        except Exception:
            pass
        return []


# ── GATE V — Variant-Family Coverage (Fix A, sibling/variant miss) ───────────
# The co-reference gate above (G1/G2) is a separate expansion over functions
# that share a state symbol. The dominant recall-miss class is broader: an agent
# confirms a defect on one function and never checks structurally-parallel
# LEGS of the same operation family (a checked deposit(), an unchecked
# withdraw(); a checked setFoo(), four unchecked sibling setters). Gate V adds
# two more mechanical axes, reusing this module's bounds (`_MAX_PER_DERIVER`)
# and the append-only, idempotent, low-confidence `_emit_candidates` path —
# nothing here is new infrastructure, only two new obligation SHAPES:
#
#   Axis 2 (boundary-input): a CONFIRMED/PARTIAL finding whose enclosing
#     function takes a numeric/collection/address parameter must have
#     addressed the boundary set {0, 1, min, MAX, empty, self} in its own
#     prose. A boundary never named -> one VARGAP candidate per boundary.
#     Degrades to a no-op when the graph/source parse lacks param-type info
#     for that finding's language (recall-neutral, never a wrong-positive).
#   Axis 3 (symmetric-operation): chain_prep's already-computed
#     `chain_candidate_pairs.md` (STATE/TYPE pairs — READ-ONLY reuse, no
#     edits to chain_prep.py here) identifies structurally-paired operations
#     via shared state/type/discovery signal. A CONFIRMED/PARTIAL defect on
#     one leg whose paired leg is NOT itself CONFIRMED/PARTIAL is an
#     unaddressed sibling leg -> one VARGAP for that leg.
#
# Gate V's boundary and symmetric-operation outputs remain candidate-only.
# G1/G2's separate co-reference candidates and both Gate-V candidate families
# flow through the SAME `NEEDS_VERIFICATION` inventory path as ENUMGAP — the verify-the-positives
# filter adjudicates every candidate; nothing here is promoted to
# body-at-severity directly. Unconditional: not Thorough-only, not
# confidence-gated (the failure mode is a confidently-WRONG agent, not merely
# a low-confidence one). No-overfit: pure graph/shape mechanics — every
# provider facts below are HOW-shaped structural data (type families, exact
# source identities, and pair-table parsing), never a protocol, token, or
# function name.

_CONFIRMED_VERDICTS = ("confirmed", "partial")

def _block_verdict(block_text: str) -> str:
    """Best-effort `**Verdict**:` extraction from a finding block. Empty
    (never raises) when the shared field parser is unavailable — degrades
    every Gate-V axis to a no-op rather than mis-classifying a verdict."""
    if _field_from_markdown is None:
        return ""
    try:
        return (_field_from_markdown(block_text or "",
                                     ("Verdict", "Final Verdict", "Status")) or "").strip().lower()
    except Exception:
        return ""


def _is_confirmed_verdict(block_text: str) -> bool:
    v = _block_verdict(block_text)
    return any(v.startswith(c) for c in _CONFIRMED_VERDICTS)


def _source_function_record(
    graph: dict, function_key: str, records: list[dict]
) -> dict | None:
    """Join one graph function to one source declaration without bare-name guessing."""
    info = graph.get("functions", {}).get(function_key, {})
    if not isinstance(info, dict):
        return None
    bare = str(info.get("bare", function_key.split(".")[-1])).casefold()
    refs = [
        row for row in _production_source_locations(str(info.get("loc", "")))
        if row.line is not None
    ]
    candidates = [row for row in records if str(row["name"]).casefold() == bare]
    if refs:
        exact_path = [
            row for row in candidates
            if _normalized_source_path(str(row["rel_path"])) == refs[0].normalized_path
        ]
        exact_line = [
            row for row in exact_path if int(row["line"]) == int(refs[0].line)
        ]
        if len(exact_line) == 1:
            return exact_line[0]
        if exact_path:
            ranked = sorted(
                exact_path,
                key=lambda row: (
                    abs(int(row["line"]) - int(refs[0].line)), int(row["line"])
                ),
            )
            if len(ranked) == 1:
                return ranked[0]
            first_distance = abs(int(ranked[0]["line"]) - int(refs[0].line))
            second_distance = abs(int(ranked[1]["line"]) - int(refs[0].line))
            return ranked[0] if first_distance < second_distance else None
    return candidates[0] if len(candidates) == 1 else None


def _boundary_source_records(root: Path) -> list[dict]:
    rows: list[dict] = []
    for lang, rel_path, name, params, body, line in _iter_functions(root):
        source_text = ""
        try:
            source_text = (Path(root) / rel_path).read_text(
                encoding="utf-8", errors="replace"
            )
        except OSError:
            pass
        rows.append({
            "lang": lang,
            "rel_path": str(rel_path).replace("\\", "/"),
            "name": name,
            "params": params,
            "body": body,
            "line": int(line),
            "source_text": source_text,
            "source_sha256": hashlib.sha256(source_text.encode("utf-8")).hexdigest(),
        })
    return rows


def _write_boundary_obligation_set(
    scratchpad: Path, *, input_digests: dict[str, str], obligations: list[dict]
) -> None:
    payload = {
        "schema": "plamen.boundary_input_obligation_set.v1",
        "input_digests": dict(sorted(input_digests.items())),
        "obligations": sorted(
            obligations,
            key=lambda row: (
                row["finding_id"], row["function_identity"],
                row["parameter_index"], row["boundary"],
            ),
        ),
    }
    (Path(scratchpad) / "_boundary_input_obligations.json").write_text(
        json.dumps(payload, indent=1, sort_keys=True) + "\n", encoding="utf-8"
    )


def compute_boundary_input_candidates(scratchpad: Path) -> list:
    """Enumerate parameter-local, type-valid boundary obligations.

    This is a candidate provider, not a vulnerability classifier.  Exact
    declaration facts produce LOW_CONFIDENCE verification candidates for
    boundaries absent from the finding's own analysis.  Unsupported or
    unresolved facts produce typed UNKNOWN repair debt, never a guessed
    universal boundary set.
    """
    producer = "enumeration.variant.boundary.scan"
    unknown_producer = "enumeration.variant.boundary.unknown"
    try:
        scratchpad = Path(scratchpad)
        graph = _load_graph(scratchpad)
        inventory_path = scratchpad / "findings_inventory.md"
        if graph is None or _inventory_blocks is None or not inventory_path.exists():
            replace_producer_shortfalls(
                scratchpad,
                producer,
                [unknown_shortfall(
                    producer=producer,
                    scope="candidate-provider",
                    kind="PROVIDER_UNAVAILABLE",
                    detail=(
                        "boundary scan requires graph, inventory parser, and "
                        "findings inventory"
                    ),
                )],
            )
            replace_producer_shortfalls(scratchpad, unknown_producer, [])
            return []

        root = _locate_project_root(scratchpad)
        if root is None:
            replace_producer_shortfalls(
                scratchpad,
                producer,
                [unknown_shortfall(
                    producer=producer,
                    scope="candidate-provider",
                    kind="PROVIDER_UNAVAILABLE",
                    detail="boundary scan cannot locate the project root",
                )],
            )
            replace_producer_shortfalls(scratchpad, unknown_producer, [])
            return []

        try:
            blocks = _inventory_blocks(
                inventory_path.read_text(encoding="utf-8", errors="replace")
            )
        except Exception as exc:
            raise RuntimeError("boundary inventory parse failed") from exc

        source_records = _boundary_source_records(root)
        if not source_records:
            replace_producer_shortfalls(
                scratchpad,
                producer,
                [unknown_shortfall(
                    producer=producer,
                    scope="candidate-provider",
                    kind="PROVIDER_UNAVAILABLE",
                    detail="boundary scan found no parseable production functions",
                )],
            )
            replace_producer_shortfalls(scratchpad, unknown_producer, [])
            return []

        candidates: list[dict] = []
        obligations: list[dict] = []
        unknown_shortfalls: list[dict] = []
        emitted_keys = _emitted_candidate_keys(scratchpad)

        for block in blocks:
            if _unseen_candidate_count(candidates, emitted_keys) > _MAX_PER_DERIVER:
                break
            finding_text = str(block.get("block") or "")
            if not _is_confirmed_verdict(finding_text):
                continue
            finding_id = str(block.get("id") or "")
            function_key = _fn_at_location(graph, str(block.get("location") or ""))
            if not function_key:
                unknown_shortfalls.append(unknown_shortfall(
                    producer=unknown_producer,
                    scope=finding_id or "unknown-finding",
                    kind="FUNCTION_IDENTITY_UNKNOWN",
                    detail=(
                        "confirmed finding could not be joined to an exact graph "
                        "function identity; boundary obligations were not guessed"
                    ),
                ))
                continue

            source_record = _source_function_record(
                graph, function_key, source_records
            )
            if source_record is None:
                unknown_shortfalls.append(unknown_shortfall(
                    producer=unknown_producer,
                    scope=finding_id or function_key,
                    kind="DECLARATION_IDENTITY_UNKNOWN",
                    detail=(
                        f"{function_key} could not be joined unambiguously to an "
                        "exact source declaration; boundary obligations were not guessed"
                    ),
                ))
                continue

            type_facts = collect_type_facts(
                str(source_record["lang"]), str(source_record["source_text"])
            )
            graph_function = graph.get("functions", {}).get(function_key, {})
            provider_fact = (
                graph_function.get("signature_fact")
                if isinstance(graph_function, dict)
                else None
            )
            type_selection = select_function_parameter_ir(
                ecosystem=str(source_record["lang"]),
                provider_fact=(
                    provider_fact if isinstance(provider_fact, dict) else None
                ),
                fallback_raw_parameters=str(source_record["params"]),
                type_facts=type_facts,
                source_path=str(source_record["rel_path"]),
                source_line=int(source_record["line"]),
                source_sha256=str(source_record["source_sha256"]),
                function_identity=function_key,
            )
            parameters = list(type_selection["parameters"])
            for debt in type_selection["debts"]:
                unknown_shortfalls.append(unknown_shortfall(
                    producer=unknown_producer,
                    scope=(
                        f"{finding_id}:{function_key}:"
                        f"{str(debt.get('kind') or 'SIGNATURE_AUTHORITY_UNKNOWN')}"
                    ),
                    kind=str(debt.get("kind") or "SIGNATURE_AUTHORITY_UNKNOWN"),
                    detail=str(debt.get("detail") or "signature authority is unknown"),
                ))
            for parameter in parameters:
                specifications = boundary_specs_for_parameter(
                    parameter, source_body=str(source_record["body"])
                )
                for specification in specifications:
                    boundary = str(specification["boundary"])
                    status = str(specification["status"])
                    addressed = (
                        status == "REQUIRED"
                        and boundary_is_addressed(
                            finding_text, str(parameter["name"]), boundary
                        )
                    )
                    action = (
                        "UNKNOWN_REVIEW_DEBT"
                        if status == "UNKNOWN"
                        else "ALREADY_ADDRESSED"
                        if addressed
                        else "LOW_CONFIDENCE_CANDIDATE"
                    )
                    obligation = {
                        "schema": "plamen.boundary_input_obligation.v1",
                        "finding_id": finding_id,
                        "function_identity": function_key,
                        "function": str(source_record["name"]),
                        "source_location": (
                            f"{source_record['rel_path']}:L{source_record['line']}"
                        ),
                        "source_sha256": str(source_record["source_sha256"]),
                        "parameter_index": int(parameter["index"]),
                        "parameter": str(parameter["name"]),
                        "raw_type": str(parameter["raw_type"]),
                        "resolved_type": str(parameter["resolved_type"]),
                        "type_family": str(parameter["family"]),
                        "type_authority": str(type_selection["authority"]),
                        "type_fidelity": str(parameter["fidelity"]),
                        "signature_provider": str(type_selection.get("provider") or ""),
                        "provider_fact_sha256": str(
                            type_selection.get("provider_fact_sha256") or ""
                        ),
                        "boundary": boundary,
                        "boundary_class": str(specification["class"]),
                        "boundary_evidence": str(specification["evidence"]),
                        "status": status,
                        "addressed": addressed,
                        "action": action,
                        "confidence": (
                            "UNKNOWN" if status == "UNKNOWN"
                            else "NOT_APPLICABLE" if addressed
                            else "LOW_CONFIDENCE"
                        ),
                    }
                    obligation["obligation_id"] = (
                        "BIO-" + _anchor_digest(obligation)[:24].upper()
                    )
                    obligations.append(obligation)

                    if status == "UNKNOWN":
                        unknown_shortfalls.append(unknown_shortfall(
                            producer=unknown_producer,
                            scope=(
                                f"{finding_id}:{function_key}:"
                                f"param[{parameter['index']}]={parameter['name']}"
                            ),
                            kind="PARAMETER_TYPE_UNKNOWN",
                            detail=(
                                f"unsupported parameter type {parameter['raw_type']!r}; "
                                "one typed UNKNOWN obligation was retained instead of "
                                "inventing boundary values"
                            ),
                        ))
                        continue
                    if addressed:
                        continue

                    function_name = str(source_record["name"])
                    parameter_name = str(parameter["name"])
                    candidate = {
                        "key": (
                            f"VARGAP-B:{finding_id}:{function_key}:"
                            f"{parameter['index']}:{parameter_name}:{boundary}"
                        ),
                        "title": (
                            f"Boundary-input coverage gap: `{function_name}` parameter "
                            f"`{parameter_name}` not verified at `{boundary}` "
                            f"({finding_id})"
                        ),
                        "location": (
                            f"`{function_key}` parameter `{parameter_name}` "
                            f"({source_record['rel_path']}:L{source_record['line']})"
                        ),
                        "source_note": (
                            "typed boundary-input coverage gap; mechanically derived "
                            f"with {type_selection['authority']} facts; "
                            "verifier must confirm or refute"
                        ),
                        "root_cause": (
                            f"{finding_id} confirms a defect in `{function_key}`. "
                            f"{type_selection['authority']} parameter facts classify "
                            f"`{parameter_name}` as `{parameter['family']}`, and the "
                            f"finding does not address its `{boundary}` boundary."
                        ),
                        "description": (
                            f"Verify `{function_key}` with `{parameter_name}` at the "
                            f"type-valid `{boundary}` boundary; this is an analysis "
                            "obligation, not a vulnerability verdict."
                        ),
                        "impact": (
                            f"Potential unaddressed boundary-value variant of "
                            f"{finding_id}; verifier must establish concrete harm."
                        ),
                        "postcondition": (
                            f"STATE: `{function_key}` parameter `{parameter_name}` "
                            f"boundary `{boundary}` is not addressed by {finding_id}"
                        ),
                        "postcondition_type": "STATE",
                        "parameter_index": int(parameter["index"]),
                        "parameter": parameter_name,
                        "raw_type": str(parameter["raw_type"]),
                        "resolved_type": str(parameter["resolved_type"]),
                        "type_family": str(parameter["family"]),
                        "type_authority": str(type_selection["authority"]),
                        "type_fidelity": str(parameter["fidelity"]),
                        "boundary": boundary,
                        "boundary_class": str(specification["class"]),
                        "boundary_evidence": str(specification["evidence"]),
                        "obligation_id": str(obligation["obligation_id"]),
                        "confidence": "LOW_CONFIDENCE",
                    }
                    candidates.append(candidate)

        input_digests = _axis1_input_digests(scratchpad)
        input_digests["production_source_set_sha256"] = _anchor_digest([
            {
                "path": row["rel_path"],
                "line": row["line"],
                "sha256": row["source_sha256"],
            }
            for row in sorted(
                source_records,
                key=lambda value: (str(value["rel_path"]), int(value["line"])),
            )
        ])
        _write_boundary_obligation_set(
            scratchpad, input_digests=input_digests, obligations=obligations
        )
        replace_producer_shortfalls(scratchpad, unknown_producer, unknown_shortfalls)
        return _bounded_deriver_result(scratchpad, producer, candidates)
    except Exception as exc:
        try:
            replace_producer_shortfalls(
                Path(scratchpad),
                producer,
                [unknown_shortfall(
                    producer=producer,
                    scope="candidate-provider",
                    kind="PROVIDER_FAILED",
                    detail=f"boundary-input scan failed: {exc!r}",
                )],
            )
        except Exception:
            pass
        return []


# Bounded parser for chain_prep's already-computed pair tables (READ-ONLY
# reuse; `compute_chain_candidate_pairs` in chain_prep.py is NOT edited by
# this module). Table shape (see chain_prep.py `_fmt_table`):
#   | Finding A | A Severity | Finding B | B Severity | Shared Signal |
_PAIR_ROW_RE = _c(
    r"^\|\s*([^|]*?)\s*\|\s*([^|]*?)\s*\|\s*([^|]*?)\s*\|\s*([^|]*?)\s*\|\s*([^|]*)\|?\s*$"
)


def _parse_chain_candidate_pairs(text: str) -> list:
    """Parse `chain_candidate_pairs.md`'s STATE/TYPE Pairs tables into
    `[{a, b, a_sev, b_sev, signal}, ...]`. Skips header/separator/placeholder
    rows. Never raises; empty on any parse failure."""
    out: list = []
    try:
        for m in _PAIR_ROW_RE.finditer(text or ""):
            a, a_sev, b, b_sev, sig = (g.strip() for g in m.groups())
            if not a or a.lower() == "finding a" or set(a) <= {"-"}:
                continue
            if a == "(none)" or b == "(none)":
                continue
            out.append({"a": a, "b": b, "a_sev": a_sev, "b_sev": b_sev, "signal": sig})
    except Exception:
        return []
    return out


def compute_symmetric_operation_candidates(scratchpad: Path) -> list:
    """Gate V axis 3 (symmetric-operation coverage). Reads the already-
    computed `chain_candidate_pairs.md` STATE/TYPE pairs as operation-sibling
    pairs. A CONFIRMED/PARTIAL defect on one leg of a pair whose sibling
    leg's OWN finding is not itself CONFIRMED/PARTIAL is an unaddressed
    symmetric-operation gap -> one VARGAP for the unaddressed leg. Never
    raises; a no-op when the pairs file or inventory is absent, or when a
    pair's finding IDs are not both resolvable in the inventory."""
    producer = "enumeration.variant.symmetric.scan"
    try:
        scratchpad = Path(scratchpad)
        pairs_path = scratchpad / "chain_candidate_pairs.md"
        inv = scratchpad / "findings_inventory.md"
        if not pairs_path.exists() or _inventory_blocks is None or not inv.exists():
            replace_producer_shortfalls(
                scratchpad, producer, [unknown_shortfall(
                    producer=producer,
                    scope="candidate-provider",
                    kind="PROVIDER_UNAVAILABLE",
                    detail="symmetric-operation scan requires pair, parser, and inventory artifacts",
                )],
            )
            return []
        try:
            pairs_text = pairs_path.read_text(encoding="utf-8", errors="replace")
            inv_text = inv.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            raise RuntimeError("symmetric-operation inputs could not be read") from exc
        pairs = _parse_chain_candidate_pairs(pairs_text)
        if not pairs:
            return _bounded_deriver_result(scratchpad, producer, [])
        try:
            blocks = {bl["id"]: bl for bl in _inventory_blocks(inv_text)}
        except Exception as exc:
            raise RuntimeError("symmetric-operation inventory parse failed") from exc

        out: list = []
        seen_pairs: set = set()
        emitted_keys = _emitted_candidate_keys(scratchpad)
        for p in pairs:
            if _unseen_candidate_count(out, emitted_keys) > _MAX_PER_DERIVER:
                break
            a_id, b_id = p["a"], p["b"]
            ba, bb = blocks.get(a_id), blocks.get(b_id)
            if not ba or not bb:
                continue  # sibling leg not resolvable in the inventory -> no-op
            a_confirmed = _is_confirmed_verdict(ba.get("block", ""))
            b_confirmed = _is_confirmed_verdict(bb.get("block", ""))
            if a_confirmed == b_confirmed:
                continue  # both addressed, or neither -> nothing mechanically established
            confirmed_id, gap_id, gap_block = (
                (a_id, b_id, bb) if a_confirmed else (b_id, a_id, ba)
            )
            pairkey = f"{confirmed_id}:{gap_id}"
            if pairkey in seen_pairs:
                continue
            seen_pairs.add(pairkey)
            gap_loc = gap_block.get("location", "") or gap_id
            gap_title = gap_block.get("title", "") or gap_id
            out.append({
                "key": f"VARGAP-S:{confirmed_id}:{gap_id}",
                "title": (f"Symmetric-operation coverage gap: {gap_id} ({gap_title}) is "
                          f"the paired operation of confirmed defect {confirmed_id} and "
                          "is not itself confirmed/partial"),
                "location": f"{gap_loc} (symmetric-operation sibling of {confirmed_id})",
                "source_note": ("symmetric-operation coverage gap; mechanically derived "
                                "— verifier to confirm or refute"),
                "root_cause": (f"{confirmed_id} and {gap_id} share a state/type signal "
                               f"({p.get('signal', '')}) per chain_candidate_pairs.md, "
                               "identifying them as a structurally symmetric operation "
                               f"pair. {confirmed_id} is CONFIRMED/PARTIAL but {gap_id} "
                               "is not, so the paired leg's own defect status is "
                               "unaddressed."),
                "description": (f"Verify whether {gap_id} exhibits the same class of "
                                f"defect confirmed at {confirmed_id} on its symmetric "
                                "operation leg."),
                "impact": (f"Potential repeat instance of {confirmed_id}'s defect on the "
                           "paired operation (verifier to confirm the concrete harm)."),
                "postcondition": (f"STATE: paired operation leg {gap_id} may share "
                                  f"{confirmed_id}'s confirmed defect"),
                "postcondition_type": "STATE",
            })
        return _bounded_deriver_result(scratchpad, producer, out)
    except Exception as exc:
        try:
            replace_producer_shortfalls(
                scratchpad, producer, [unknown_shortfall(
                    producer=producer,
                    scope="candidate-provider",
                    kind="PROVIDER_FAILED",
                    detail=f"symmetric-operation scan failed: {exc!r}",
                )],
            )
        except Exception:
            pass
        return []


def compute_variant_gaps(scratchpad: Path) -> dict:
    """Gate V driver entry for variant-family axes 2 and 3 only.

    Axis 1 (co-reference) is owned exclusively by ``run_enumeration_gate`` at
    the accepted-depth boundary. Re-running it here used the inventory after
    mechanical candidates had already been appended, allowing candidates to
    become candidate origins and consuming the bounded verification budget.
    Compatibility keys for axis 1 remain present and are always zero.

    Boundary-input and symmetric-operation candidates emit through the shared
    append-only, idempotent, bounded, low-confidence inventory path.
    Unconditional (not Thorough-only, not confidence-gated).

    This function is intentionally NOT wired into `run_enumeration_gate`'s
    existing call sites — it is a separate, additive entry point the driver
    calls alongside it (mirroring the G1/G2 naming convention so the driver
    owner can wire the new call site without touching this module further).
    Never raises."""
    scratchpad = Path(scratchpad)
    result = {"axis1_emitted": 0, "axis2_emitted": 0, "axis3_emitted": 0,
              "obligations": 0, "gaps": 0, "emitted": 0}
    errors: list[str] = []

    def _pipeline_status(producer: str, exc: BaseException | None = None) -> None:
        rows = [] if exc is None else [unknown_shortfall(
            producer=producer,
            scope="variant-orchestration",
            kind="PIPELINE_FAILED",
            detail=f"variant scan/emission orchestration failed: {type(exc).__name__}",
        )]
        try:
            replace_producer_shortfalls(scratchpad, producer, rows)
        except Exception:
            pass

    try:
        b_cands = compute_boundary_input_candidates(scratchpad)
        _pipeline_status("enumeration.variant.boundary.orchestration")
    except Exception as exc:
        b_cands = []
        errors.append(f"boundary scan: {type(exc).__name__}: {exc}")
        _pipeline_status("enumeration.variant.boundary.orchestration", exc)
    try:
        result["axis2_emitted"] = _emit_candidates(
            scratchpad, b_cands, _MAX_PER_DERIVER, source_id="VARGAP",
            producer="enumeration.variant.boundary.emission",
        )
        _pipeline_status("enumeration.variant.boundary.pipeline")
    except Exception as exc:
        errors.append(f"boundary emission: {type(exc).__name__}: {exc}")
        _pipeline_status("enumeration.variant.boundary.pipeline", exc)
    try:
        s_cands = compute_symmetric_operation_candidates(scratchpad)
        _pipeline_status("enumeration.variant.symmetric.orchestration")
    except Exception as exc:
        s_cands = []
        errors.append(f"symmetric scan: {type(exc).__name__}: {exc}")
        _pipeline_status("enumeration.variant.symmetric.orchestration", exc)
    try:
        result["axis3_emitted"] = _emit_candidates(
            scratchpad, s_cands, _MAX_PER_DERIVER, source_id="VARGAP",
            producer="enumeration.variant.symmetric.emission",
        )
        _pipeline_status("enumeration.variant.symmetric.pipeline")
    except Exception as exc:
        errors.append(f"symmetric emission: {type(exc).__name__}: {exc}")
        _pipeline_status("enumeration.variant.symmetric.pipeline", exc)
    result["emitted"] = (result["axis1_emitted"] + result["axis2_emitted"]
                         + result["axis3_emitted"])
    if errors:
        result["status"] = "FAILED"
        result["error"] = "; ".join(errors)[:2000]
    return result


def validate_variant_coverage(scratchpad: Path) -> dict:
    """Alias for `compute_variant_gaps`, named to mirror the existing G2
    (`validate_enumeration_coverage`) convention for driver call-site parity.
    Never raises."""
    return compute_variant_gaps(Path(scratchpad))


# ── MECHANISM 1 — committed-invariant assertion deriver ──────────────────────
# The skeptic/depth phases, whenever they rule a value-bearing path SAFE or refute
# a value-bearing finding, commit the tacit LOCAL GUARD behind that verdict as an
# executable `committed-invariant [CI-n]` block (one of six generic SHAPES). This
# deriver harvests those blocks mechanically and turns each into a low-confidence
# falsifiable inventory candidate (Source IDs: INVARIANT, NEEDS_VERIFICATION) so
# the existing invariant-fuzz / verify / chain path FALSIFIES it. Generation is
# recall-biased (emit on doubt); the verify-the-positives filter is precision-
# preserving. Generic: names no protocol; symbols resolve at the locus.

# One `committed-invariant [CI-n]` block, tolerant of the emitters' formatting.
# Anchored on the `committed-invariant [CI-n]` header line; fields are matched
# case-insensitively anywhere in the block. Emitters live in
# phase4b6-exploration-skeptic.md, phase5-skeptic.md, phase4b-depth.md.
_CI_BLOCK_RE = re.compile(
    # ID accepts shard-namespaced forms (CI-A1, CI-B12) as well as the bare
    # CI-1 form. The skeptic shard-workers emit CI-<shard><n> (CI-A1..CI-D3);
    # a `CI-\d+`-only pattern silently dropped every namespaced block — the same
    # ID-format-too-narrow silent-drop class as the shared exploration parser (see
    # feedback_id_regex_catalog). Anchored on `committed-invariant [...]`.
    r"committed-invariant\s*\[\s*(?P<id>"
    + COMMITTED_INVARIANT_ID_PATTERN
    + r")\s*\]\s*\n(?P<body>.*?)"
    r"(?=\n\s*committed-invariant\s*\[|\n#{1,6}\s|\Z)",
    re.IGNORECASE | re.DOTALL,
)

# Artifacts that may carry [CI-n] blocks. Depth + verify are now the PRIMARY
# emitters (mandatory CI on any value-bearing CLEAR/REFUTED verdict — the richest
# reservoirs of concluded-safe judgments); the skeptic phases remain secondary.
_CI_SOURCE_GLOBS = (
    "exploration_skeptic_findings.md",
    "skeptic_findings.md",
    "depth_*_findings.md",
    "verify_*.md",
)


def _ci_field(body: str, name: str) -> str:
    m = re.search(r"(?im)^\s*" + re.escape(name) + r"\s*:\s*(.+?)\s*$", body)
    return m.group(1).strip() if m else ""


def compute_invariant_assertion_candidates(scratchpad: Path) -> list:
    """M1. Scan skeptic/depth artifacts for `committed-invariant [CI-n]` blocks
    and turn each into a falsifiable inventory candidate. Each candidate carries
    the assertion text, a Falsify Class, and generic chain pre/post metadata so it
    is a STEP-0a-LC enabler for free. Locus is resolved to its enclosing function
    via `_fn_at_location` over `_load_graph` when the graph is present; a missing
    graph or unresolved locus degrades to a file-scope candidate (still emitted,
    still verifiable). An empty result means no valid blocks were present;
    provider/read/derivation failures surface as typed errors."""
    try:
        scratchpad = Path(scratchpad)
        graph = _load_graph(scratchpad)   # may be None → degrade, never halt
        out: list = []
        seen_ids: set = set()
        globs: list[Path] = []
        for pat in _CI_SOURCE_GLOBS:
            globs.extend(sorted(scratchpad.glob(pat)))
        for art in globs:
            raw = art.read_bytes()
            text = raw.decode("utf-8", errors="strict")
            source_artifact = art.relative_to(scratchpad).as_posix()
            source_artifact_sha256 = hashlib.sha256(raw).hexdigest()
            for m in _CI_BLOCK_RE.finditer(text):
                cid = m.group("id").strip().upper()
                body = m.group("body")
                locus = _ci_field(body, "Locus")
                shape_raw = _ci_field(body, "Shape").strip()
                shape = shape_raw.split()[0].upper() if shape_raw else ""
                assertion = _ci_field(body, "Assertion")
                fclass = (_ci_field(body, "Falsify Class") or "property").split()[0].lower()
                provenance = _ci_field(body, "Provenance")
                if not (locus or assertion):
                    continue   # an empty stub carries nothing falsifiable
                # Dedup on CI id + source artifact so the same block in two files
                # (or a re-emitted block) yields one candidate. Key also embeds the
                # id so the shared receipt makes cross-run emission idempotent.
                dkey = f"{art.name}:{cid}"
                if dkey in seen_ids:
                    continue
                seen_ids.add(dkey)
                fn = _fn_at_location(graph, locus) if graph else None
                # A recognized shape gets a shape-typed chain relation; an
                # unknown/garbled shape still emits (recall-safe) with a generic
                # STATE relation so it remains a chain enabler.
                is_known = shape in _CI_SHAPES
                post, post_t = _CI_SHAPE_CHAIN.get(
                    shape, ("STATE: local guard asserted at the locus", "STATE"))
                shape_label = shape if is_known else (shape_raw or "UNSPECIFIED")
                loc_disp = locus or "file-scope (locus unresolved)"
                fn_disp = f" (fn: `{fn}`)" if fn else ""
                assert_disp = assertion or "assert the committed local guard holds at this locus"
                # DRIVER NUDGE (falsifiability-aware): a CONSERVATION invariant at
                # a value-conversion boundary is often true by construction, so its
                # conservation falsifier can never break. Append the breakable
                # shapes (NO_REVERT_AT_BOUNDARY + REQUESTED_EQ_DELIVERED) to the
                # emitted Falsify Class so the downstream falsifier ALSO tests the
                # relations that CAN diverge. Additive/recall-safe; generic HOW.
                falsify_extra = ""
                cue_src = f"{shape_raw} {assertion} {locus} {provenance}"
                if shape == "CONSERVATION" and _CI_CONVERSION_CUE.search(cue_src):
                    falsify_extra = (
                        "; conservation may be true by construction at this "
                        "conversion boundary — ALSO falsify "
                        + " + ".join(_CI_BREAKABLE_SHAPES)
                        + " (does the boundary case revert/mis-round, and does "
                        "requested==delivered across the conversion?)"
                    )
                out.append({
                    "key": f"INVARIANT:{dkey}",
                    # Clean, greppable generator class token stamped on the
                    # emitted `**Source IDs**:` line so the committed-invariant
                    # (M1) provenance survives dedup as `INVARIANT:CI-n`.
                    "source_tag": f"INVARIANT:{cid}",
                    "title": (f"Committed invariant {cid} ({shape_label}) at "
                              f"`{loc_disp}`{fn_disp} — falsify"),
                    "location": f"{loc_disp}{fn_disp}",
                    "source_note": (f"{cid}; committed-invariant assertion; Falsify Class: "
                                    f"{fclass}"
                                    + falsify_extra
                                    + (f"; {provenance}" if provenance else "")
                                    + "; mechanically harvested — falsifier to confirm or refute"),
                    "root_cause": (f"A prior verdict ruled this locus safe on the tacit local "
                                   f"guard committed as {shape_label}: {assert_disp}. The guard "
                                   f"is asserted but not falsified."),
                    "description": (f"Falsify the committed invariant {cid} ({shape_label}) at "
                                    f"{loc_disp}: {assert_disp}. Survived → sharpened spec; "
                                    f"triggered → real bug the SAFE/REFUTE verdict hid. "
                                    f"Falsify Class: {fclass}{falsify_extra}."),
                    "impact": ("If the committed local guard does not hold at a boundary or "
                               "reachable path, the value-bearing verdict that relied on it is "
                               "wrong (falsifier to confirm the concrete harm)."),
                    "postcondition": post,
                    "postcondition_type": post_t,
                    **(
                        {
                            "late_ci_authority": {
                                "authority": LATE_CI_AUTHORITY,
                                "status": LATE_CI_STATUS,
                                "source_artifact": source_artifact,
                                "source_artifact_sha256": (
                                    source_artifact_sha256
                                ),
                                "committed_invariant_id": cid,
                                "committed_invariant_sha256": hashlib.sha256(
                                    m.group(0).encode("utf-8")
                                ).hexdigest(),
                            }
                        }
                        if art.name.startswith("verify_")
                        and art.suffix == ".md"
                        else {}
                    ),
                })
        return out
    except LateCommittedInvariantError:
        raise
    except Exception as exc:
        raise LateCommittedInvariantError(
            stage="DERIVATION",
            code="CI_DERIVATION_FAILED",
            detail=(
                "committed-invariant candidate derivation failed "
                f"({type(exc).__name__})"
            ),
        ) from exc


def recover_invariant_assertion_candidates(
    scratchpad: Path,
) -> LateCommittedInvariantRecoveryResult:
    """Harvest and durably route every committed invariant immediately.

    The main enumeration gate runs before both skeptic producers. Validator-
    time recovery therefore closes the later-phase timing gap: an invariant
    emitted by exploration-skeptic enters the normal downstream verify funnel,
    while a post-verify skeptic invariant remains an explicit
    NEEDS_VERIFICATION inventory/human-review item instead of disappearing.
    Idempotence is provided by the shared candidate transaction and receipt.
    """
    root = Path(scratchpad)
    try:
        candidates = compute_invariant_assertion_candidates(root)
    except LateCommittedInvariantError:
        raise
    except Exception as exc:
        raise LateCommittedInvariantError(
            stage="DERIVATION",
            code="CI_DERIVATION_FAILED",
            detail=(
                "committed-invariant candidate derivation failed "
                f"({type(exc).__name__})"
            ),
        ) from exc

    authorities: list[LateCommittedInvariantAuthority] = []
    for candidate in candidates:
        late = candidate.get("late_ci_authority")
        if late is None:
            continue
        if not isinstance(late, dict):
            raise LateCommittedInvariantError(
                stage="DERIVATION",
                code="LATE_CI_AUTHORITY_INVALID",
                detail="late committed-invariant authority is malformed",
            )
        authorities.append(
            LateCommittedInvariantAuthority.create(
                source_artifact=late.get("source_artifact"),
                source_artifact_sha256=late.get("source_artifact_sha256"),
                committed_invariant_id=late.get("committed_invariant_id"),
                committed_invariant_sha256=late.get(
                    "committed_invariant_sha256"
                ),
                candidate_key=candidate.get("key"),
            )
        )
    try:
        ledger_path = persist_late_committed_invariant_authorities(
            root,
            authorities,
        )
    except LateCommittedInvariantError:
        raise
    except Exception as exc:
        raise LateCommittedInvariantError(
            stage="PERSISTENCE",
            code="LATE_CI_LEDGER_FAILED",
            detail=(
                "late committed-invariant authority persistence failed "
                f"({type(exc).__name__})"
            ),
        ) from exc

    seen_before = _emitted_candidate_keys(root)
    expected_new: list[str] = []
    expected_seen: set[str] = set()
    for candidate in candidates:
        key = str(candidate.get("key") or "")
        if (
            key
            and key not in seen_before
            and key not in expected_seen
            and len(expected_new) < _MAX_PER_DERIVER
        ):
            expected_new.append(key)
            expected_seen.add(key)
    try:
        emitted = _emit_candidates(
            root,
            candidates,
            _MAX_PER_DERIVER,
            source_id="INVARIANT",
            producer="enumeration.deriver.committed_invariant.emission",
        )
    except Exception as exc:
        raise LateCommittedInvariantError(
            stage="EMISSION",
            code="CANDIDATE_EMISSION_FAILED",
            detail=(
                "committed-invariant candidate emission raised "
                f"({type(exc).__name__})"
            ),
        ) from exc
    inventory_after = _inventory_candidate_keys(root)
    receipt_after = _receipt_candidate_keys(root)
    if (
        emitted != len(expected_new)
        or not set(expected_new).issubset(inventory_after)
        or not set(expected_new).issubset(receipt_after)
        or inventory_after != receipt_after
    ):
        raise LateCommittedInvariantError(
            stage="EMISSION",
            code="CANDIDATE_PERSISTENCE_UNPROVEN",
            detail=(
                "committed-invariant inventory/receipt persistence did not "
                "replay exactly"
            ),
        )
    return LateCommittedInvariantRecoveryResult(
        emitted,
        authorities=authorities,
        ledger_path=ledger_path,
    )


# ── MECHANISM 2 — multi-axis coverage meta-pass ──────────────────────────────
# M1 closes gaps WITHIN a verdict (commit-then-falsify the tacit local guard).
# M2 closes gaps ACROSS functions: it ranks the mechanically-hot functions, builds
# a `function × axis` completeness matrix, and — for orthogonal risk axes that were
# never examined at a hot function's locus — spawns a targeted deriver-worker.
# Axis-EXAMINED uses the CLOSED depth-evidence tag vocabulary as its PRIMARY
# signal, with narrowly bounded Description/Impact cues as a SECONDARY signal
# for tag-light findings. An AMBIGUOUS cell still defaults to GAP (recall-safe).
# The hot set is DRIVER-OWNED and DETERMINISTIC so the LLM cannot clobber the
# target set — the property that makes the gate load-bearing. Generic: axes +
# hotness predicate are question-shapes, never a protocol/token/function signature.

_MAX_HOT_FUNCTIONS = 40          # mirrors _MAX_ENUMGAP_PER_RUN; budget lands on core
_CALLER_THRESHOLD = 2            # "hot" caller count floor (a fn ≥2 callers is core)
_HOT_FUNCTION_CAP_RECEIPT_NAME = "_hot_function_cap_receipt.json"
_HOT_FUNCTION_CAP_RECEIPT_SCHEMA = "plamen.hot_function_cap_receipt.v1"
AXIS_POPULATION_SCHEMA = "plamen.axis_population.v2"
AXIS_POPULATION_PROVIDER_VERSION = "enumeration.axis_population/2"
AXIS_EXAMINED_AUTHORITY_SCHEMA = "plamen.axis_examined_authority.v1"
_AXIS_CAP_WRITE_CONTEXT: ContextVar[dict | None] = ContextVar(
    "plamen_axis_cap_write_context",
    default=None,
)


def _hot_function_identity(item: dict) -> str:
    """Return the exact matrix identity retained by the cap authority."""

    return f"{str(item.get('function') or '').strip()}@{str(item.get('loc') or '').strip()}"


def _hot_function_cap_digest(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _write_hot_function_cap_receipt(
    scratchpad: Path,
    *,
    source_scope: str,
    hot: list[dict],
    limit: int,
) -> None:
    """Persist the full pre-cap denominator while human output stays sampled.

    The generic shortfall ledger deliberately samples large populations. This
    typed sidecar is the machine authority used by the P0-I reconciler, so it
    retains every omitted function record and exact identity. It grants no
    finding or CLEAR authority by itself.
    """

    retained = [dict(item) for item in hot[:limit]]
    omitted = [dict(item) for item in hot[limit:]]
    observed = [dict(item) for item in hot]
    retained_ids = [_hot_function_identity(item) for item in retained]
    omitted_ids = [_hot_function_identity(item) for item in omitted]
    population_ids = [*retained_ids, *omitted_ids]
    unsigned = {
        "schema_version": _HOT_FUNCTION_CAP_RECEIPT_SCHEMA,
        "producer": "enumeration.hot_function_set",
        "source_scope": source_scope,
        "limit": limit,
        "observed_count": len(observed),
        "retained_count": len(retained),
        "omitted_count": len(omitted),
        "population_tail": population_ids[-1] if population_ids else "",
        "retained_tail": retained_ids[-1] if retained_ids else "",
        "omitted_tail": omitted_ids[-1] if omitted_ids else "",
        "retained_identities": retained_ids,
        "omitted_identities": omitted_ids,
        "observed_items": observed,
        "retained_items": retained,
        "omitted_items": omitted,
        "omitted_identities_sha256": _hot_function_cap_digest(omitted_ids),
        "population_sha256": _hot_function_cap_digest(population_ids),
        "raw_fallback_authority": "CANDIDATE_ONLY",
        "methodology_application_proven": False,
    }
    payload = {
        **unsigned,
        "receipt_sha256": _hot_function_cap_digest(unsigned),
    }
    _write_json_atomic(Path(scratchpad) / _HOT_FUNCTION_CAP_RECEIPT_NAME, payload)
    # ``compute_axis_population`` establishes this invocation-local context.
    # It proves that the cap consumed below was produced by the provider call
    # for the current run, rather than being a byte-valid receipt left by a
    # prior run.  The durable population authority then binds both run_id and
    # this receipt's digest.  Legacy direct callers deliberately get no stamp.
    context = _AXIS_CAP_WRITE_CONTEXT.get()
    if isinstance(context, dict):
        context["write_count"] = int(context.get("write_count", 0)) + 1
        context["receipt_sha256"] = payload["receipt_sha256"]


def _invalidate_hot_function_cap_receipt(scratchpad: Path) -> None:
    """Remove stale denominator authority when the provider did not run."""

    try:
        (Path(scratchpad) / _HOT_FUNCTION_CAP_RECEIPT_NAME).unlink(missing_ok=True)
    except OSError:
        # The shortfall ledger still records provider failure. A stale receipt
        # that cannot be removed will fail downstream source/hash replay.
        pass

# ── Hot-set scoring (Formula-2: log-dampened, distribution-robust blend) ──
# Fan-in is a POOR primary risk signal (popularity ≠ risk): a shared math util
# can rank above a value-mover purely on caller count. We log-dampen fan-in so it
# stays a BLENDED term (never dominant, never dropped — a util between entries and
# sinks is legitimately hot), keep the security terms (writes/elevate/value) at
# their prior linear weight, and add a MILD, FLAT entry-point bonus. A graded /
# strong entry bonus was rejected empirically: it produces a wide score tie
# (arbitrary alphabetical selection) AND evicts value-movers (burn/redeem) — the
# value-mover-eviction failure. These weights are conservative and validated by
# the fixtures in test_hotset_scoring.py against synthetic SCIP- and EVM-shaped
# caller distributions (no value-mover eviction, no tie collapse). Purely a
# topology/structure reweight — ZERO protocol/token/function vocabulary.
_W_FANIN = 1.0                   # coefficient on log2(n_callers + 1)
_W_WRITES = 2.0                  # touches security-relevant state
_W_ELEVATE = 2.0                 # recon [ELEVATE] tag
_W_VALUE = 2.0                   # value-effect regex match (can move value)
_W_ENTRY = 1.0                   # mild, FLAT entry-point bonus (not graded)
_ENTRY_THRESH = 1                # n_callers ≤ this ⇒ structural entry-point proxy

# Generic Rust/stdlib/EVM builtin METHOD names the graph's var_refs wrongly count
# as state symbols (`.mul()`, `.unwrap_or()`, `.assert()` etc.), giving math-util
# leaf functions false writes=True + inflated fan-in. This is a topology/vocabulary
# filter — it names ZERO protocol/token/function concepts, only generic language
# builtins, and benefits every Rust/Move/Sol codebase using checked-math idioms.
_BUILTIN_METHOD_DENYLIST = frozenset({
    "mul", "div", "add", "sub", "abs", "min", "max", "pow",
    "unwrap", "unwrap_or", "expect", "clone", "into", "from",
    "borrow", "deref", "assert", "ok", "ok_or",
    "is_some", "is_none", "len", "iter", "map",
})
# Builtin method FAMILIES matched by prefix (checked_add, saturating_sub,
# wrapping_mul, as_u128, ...). Generic language vocabulary only.
_BUILTIN_METHOD_PREFIXES = ("checked_", "saturating_", "wrapping_", "as_")


def _is_builtin_method(bare: str) -> bool:
    """True iff `bare` (lowercased bare symbol) is a generic language builtin
    method name that must NOT count as a contract state symbol. Exact match
    against the denylist OR a denylisted prefix family. Generic-only; no protocol
    vocabulary."""
    b = (bare or "").lower()
    if not b:
        return False
    if b in _BUILTIN_METHOD_DENYLIST:
        return True
    return b.startswith(_BUILTIN_METHOD_PREFIXES)

# The orthogonal risk axes (HOW-shaped question per function). Order is
# stable so the matrix columns are deterministic. `identity` = CWE-863/CWE-441/
# CWE-639-shaped authorization-subject coverage: was the caller<->subject
# binding examined at this locus (not merely "is the caller permitted" but "is
# the caller the SAME subject whose value/state/role is being mutated").
_AXES: tuple = ("theft", "liveness", "accounting", "provenance", "boundary", "identity")

# Per-language value-effect / mover regex reused to decide a function CAN move
# value (⇒ theft axis is IN-scope, not N/A). Built from the existing _LANG specs
# (effect ∪ mover) so no new vocabulary is invented.
def _value_effect_res(lang: str) -> list:
    spec = _LANG.get(lang, {})
    res = []
    for k in ("effect", "mover"):
        r = spec.get(k)
        if r is not None:
            res.append(r)
    return res


# CLOSED depth-evidence tag detectors (finding-output-format.md vocabulary only).
# A cell is EXAMINED iff one of these mechanically-detectable signals is present
# at the finding block whose locus maps to the function. Ambiguous ⇒ GAP.
_TAG_TRACE = re.compile(r"\[\s*TRACE\s*:", re.IGNORECASE)
_TAG_BOUNDARY = re.compile(r"\[\s*BOUNDARY\s*:", re.IGNORECASE)
_TAG_VARIATION = re.compile(r"\[\s*VARIATION\s*:", re.IGNORECASE)
_TAG_REGRESS = re.compile(r"\[\s*REGRESS\s*:", re.IGNORECASE)
_TAG_EXT_ASSUMPTION = re.compile(r"\[\s*EXTERNAL-ASSUMPTION\s*:", re.IGNORECASE)
_TAG_CROSS_DOMAIN_EXT = re.compile(r"\[\s*CROSS-DOMAIN-DEP\s*:\s*external", re.IGNORECASE)
# Terminal-mechanism / material-harm word cues (still mechanical substrings, NOT
# free-text attestation — they only STRENGTHEN an EXAMINED signal that a closed
# tag already anchors, or refine an axis N/A determination).
_TRACE_TO_MOVE = re.compile(r"\[\s*TRACE\s*:[^\]]*(?:transfer|mint|withdraw|burn|deposit|payout)", re.IGNORECASE)
_TRACE_TO_REVERT = re.compile(r"\[\s*TRACE\s*:[^\]]*(?:revert|lock|brick|freeze|abort)", re.IGNORECASE)
_BOUNDARY_ZERO_ETC = re.compile(r"\[\s*BOUNDARY\s*:[^\]]*(?:=\s*0\b|=\s*1\b|MAX|min|empty)", re.IGNORECASE)
_POST_TYPE_BAL_ACC = re.compile(r"(?im)^\s*\*{0,2}Postcondition\s*Types?\*{0,2}\s*:.*\b(?:BALANCE|ACCESS)\b")
# ACCESS-only postcondition cue (identity axis primary signal). Narrower than
# `_POST_TYPE_BAL_ACC` on purpose: a bare BALANCE postcondition next to an
# unrelated [TRACE:] (e.g. a theft trace to a transfer) must NOT also count as
# an examined identity axis -- ACCESS specifically denotes the "who can use
# these [postconditions]" authorization dimension (finding-output-format.md).
_POST_TYPE_ACCESS = re.compile(r"(?im)^\s*\*{0,2}Postcondition\s*Types?\*{0,2}\s*:.*\bACCESS\b")
_MH_LIVENESS = re.compile(r"(?i)\b(?:liveness|permanently\s+revert|permanently\s+lock|denial[- ]of[- ]service|halt|brick|freeze|stuck)\b")
_STALENESS_CUE = re.compile(r"(?i)\b(?:stale|staleness|freshness|oracle|price\s+feed|last\s*Updat|provenance|source\s+of)\b")
# Generic authorization-subject prose cue (CWE-863/CWE-441/CWE-639 shape): the
# finding's own words indicate the caller<->subject binding was interrogated —
# an actor authorized for ONE identity acting "on behalf of" / against a
# DIFFERENT owner/recipient without that subject's own authorization, or a
# confused-deputy / impersonation framing. Ecosystem-neutral wording only — no
# ecosystem source tokens (no `msg.sender`, `require_auth`, `&signer`, etc.)
# appear in this regex; it matches the generic English shape of the claim,
# regardless of which ecosystem's finding prose happens to use it.
_IDENTITY_CUE = re.compile(
    r"(?i)\bon\s+behalf\s+of\b"
    r"|\bcaller\b[^.\n]{0,80}\b(?:owner|recipient)\b"
    r"|\b(?:owner|recipient)\b[^.\n]{0,80}\bcaller\b"
    r"|\bwithout\s+the\s+(?:owner|recipient)(?:'s)?\s+(?:authorization|consent|approval)\b"
    r"|\bauthoriz\w*\b[^.\n]{0,80}\bacts?\s+on\s+(?:a\s+)?(?:different|another)\b"
    r"|\bconfused\s+deputy\b"
    r"|\bimperson\w*\b"
)


def _load_function_summary(scratchpad: Path) -> dict:
    """Parse `function_summary.md` into {bare_name_lower: {callers:int}}.
    Best-effort; empty dict on absence/parse-failure so the hot-set degrades to
    the graph + all-external fallback rather than halting. The summary's Function
    column may be a qualified path; we key on the BARE name (last dotted/`::`
    segment)."""
    out: dict = {}
    p = scratchpad / "function_summary.md"
    if not p.exists():
        return out
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return out
    # HEADER-DRIVEN callers column: the Callers column index differs across
    # schemas (SCIP places it at index 4; the EVM function_summary.md schema uses
    # a different column order). Parse the header row to find the column whose
    # label is "Callers" (case-insensitive) and use that index for data rows.
    # Fall back to the legacy cells[4]-if-int behavior when no labelled header is
    # found, so SCIP-shaped summaries still parse cleanly.
    callers_idx = None  # resolved from the table header when available
    for ln in text.splitlines():
        s = ln.strip()
        if not s.startswith("|") or "---" in s:
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        if not cells:
            continue
        # Header row: locate the "Callers" column by label, then skip the row.
        if "Function" in ln:
            for i, c in enumerate(cells):
                if c.strip("`# ").strip().lower() == "callers":
                    callers_idx = i
                    break
            continue
        fn_cell = cells[0].strip("` ").strip()
        if not fn_cell:
            continue
        # Typed provider identities retain overload/source discriminators, for
        # example ``Module.apply(uint256)`` or
        # ``apply@src/module.rs:L7#...``.  Hotness is still aggregated by bare
        # operation name; strip the discriminator before path punctuation can
        # be mistaken for qualification.
        identity_base = fn_cell.split("@", 1)[0]
        identity_base = re.sub(r"\([^)]*\)(?:#[A-Fa-f0-9]+)?$", "", identity_base)
        bare = re.split(r"[.:]{1,2}", identity_base)[-1].strip("` ").lower()
        if not bare:
            continue
        callers = 0
        if callers_idx is not None and callers_idx < len(cells) \
                and re.fullmatch(r"\d+", cells[callers_idx]):
            # Header-resolved column (works across SCIP/EVM/Move schemas).
            try:
                callers = int(cells[callers_idx])
            except ValueError:
                callers = 0
        elif len(cells) >= 5 and re.fullmatch(r"\d+", cells[4]):
            # Legacy fallback: SCIP layout | Function | File | Line | Kind | Callers | Callees |
            try:
                callers = int(cells[4])
            except ValueError:
                callers = 0
        prior = int(out.get(bare, {}).get("callers", 0))
        out[bare] = {"callers": max(prior, callers)}
    return out


def compute_hot_function_set(scratchpad: Path) -> list:
    """M2. Rank the mechanically-hot production functions deterministically off
    `_mechanical_graph.json` (+ `function_summary.md` when present). Writes
    nothing itself (the matrix builder writes the artifacts); returns a ranked,
    capped list of dicts: {function, loc, callers, writes, elevate, value_effect,
    score, lang}. Driver-owned + deterministic — the LLM cannot clobber the target
    set. Fallback: 'all external state-mutating functions' when the graph is
    absent. Never raises; empty on total failure."""
    producer = "enumeration.hot_function_set"
    try:
        scratchpad = Path(scratchpad)
        graph = _load_graph(scratchpad)
        root = _locate_project_root(scratchpad)
        summ = _load_function_summary(scratchpad)
        if graph is None and root is None:
            _invalidate_hot_function_cap_receipt(scratchpad)
            replace_producer_shortfalls(
                scratchpad, producer, [unknown_shortfall(
                    producer=producer,
                    scope="hotset-provider",
                    kind="PROVIDER_UNAVAILABLE",
                    detail="hot-function ranking has neither a mechanical graph nor a project root",
                )],
            )
            return []

        # ELEVATE tags (optional recon signal in attack_surface.md). A function
        # named on a line carrying [ELEVATE] is treated as hot. Best-effort.
        elevate_names: set = set()
        try:
            asf = scratchpad / "attack_surface.md"
            if asf.exists():
                atext = asf.read_text(encoding="utf-8", errors="replace")
                for ln in atext.splitlines():
                    if "[ELEVATE]" in ln.upper() or "ELEVATE" in ln.upper():
                        for nm in re.findall(r"`([A-Za-z_]\w*)`", ln):
                            elevate_names.add(nm.lower())
        except Exception:
            elevate_names = set()

        # writer set: bare fn names that reference (read/write) any state symbol.
        fn_writes: set = set()
        if graph is not None:
            for _vk, vd in graph.get("var_refs", {}).items():
                for d in vd.get("refs", []):
                    bare_ref = _bare_from_descriptor(d).lower()
                    # DENOISE: the graph's var_refs count generic builtin method
                    # calls (.mul()/.unwrap_or()/.assert()) as if they were state
                    # symbols, giving math-util leaves false writes=True. Drop
                    # descriptors whose bare symbol is a language builtin. Topology
                    # filter — no protocol vocabulary.
                    if _is_builtin_method(bare_ref):
                        continue
                    fn_writes.add(bare_ref)

        # value-effect scan over production function bodies (per language present).
        # Maps bare-name(lower) -> (lang, has_value_effect). Deterministic source
        # parse. `disp_by_fn` preserves the ORIGINAL-cased name so the fallback
        # hot set reports the source name, matching the graph path's `bare`.
        effect_by_fn: dict = {}
        loc_by_fn: dict = {}
        disp_by_fn: dict = {}
        if root is not None:
            for lang, rel, name, _params, body, line in _iter_functions(root):
                bare = name.lower()
                res = _value_effect_res(lang)
                has_eff = any(r.search(body) for r in res) if res else False
                # last write wins is fine; a bare name colliding across files still
                # yields a stable deterministic result (sorted iteration below).
                prev = effect_by_fn.get(bare)
                effect_by_fn[bare] = (lang, has_eff or (prev[1] if prev else False))
                loc_by_fn.setdefault(bare, f"{rel}:L{line}")
                disp_by_fn.setdefault(bare, name)

        # ── FALLBACK: no graph → 'all external state-mutating functions' ──
        # Without the graph we cannot count callers; use the source-parsed
        # value-effect set (a value effect ⇒ state-mutating) as the hot set.
        if graph is None:
            hot: list = []
            for bare, (lang, has_eff) in sorted(effect_by_fn.items()):
                if not has_eff:
                    continue
                hot.append({
                    "function": disp_by_fn.get(bare, bare),
                    "loc": loc_by_fn.get(bare, "?"),
                    "callers": 0,
                    "writes": False,
                    "elevate": bare in elevate_names,
                    "value_effect": True,
                    "lang": lang,
                    "score": 1 + (1 if bare in elevate_names else 0),
                })
            hot.sort(key=lambda h: (-h["score"], h["function"]))
            cap_rows = []
            if len(hot) > _MAX_HOT_FUNCTIONS:
                cap_rows.append(shortfall(
                    producer=producer,
                    scope="source-fallback-hotset",
                    cap="MAX_HOT_FUNCTIONS",
                    limit=_MAX_HOT_FUNCTIONS,
                    observed=len(hot),
                    retained=_MAX_HOT_FUNCTIONS,
                    exact=True,
                    samples=[h.get("function", "") for h in hot[_MAX_HOT_FUNCTIONS:]],
                    detail="source-derived hot functions were omitted from the axis matrix",
                ))
            try:
                replace_producer_shortfalls(
                    scratchpad, producer, cap_rows
                )
            except Exception:
                pass
            _write_hot_function_cap_receipt(
                scratchpad,
                source_scope="source-fallback-hotset",
                hot=hot,
                limit=_MAX_HOT_FUNCTIONS,
            )
            return hot[:_MAX_HOT_FUNCTIONS]

        # ── PRIMARY: rank off the graph ──
        hot = []
        graph_display_counts: dict[tuple[str, str], int] = {}
        for graph_identity, graph_info in graph.get("functions", {}).items():
            if not isinstance(graph_info, dict):
                continue
            display_key = (
                str(graph_info.get("bare", graph_identity)).casefold(),
                str(graph_info.get("loc", "?")).casefold(),
            )
            graph_display_counts[display_key] = graph_display_counts.get(display_key, 0) + 1
        for fk, info in graph.get("functions", {}).items():
            bare = info.get("bare", fk.split(".")[-1]).lower()
            callers = len(info.get("callers", []) or [])
            summ_callers = int(summ.get(bare, {}).get("callers", 0)) if summ else 0
            n_callers = max(callers, summ_callers)
            writes = bare in fn_writes
            elevate = bare in elevate_names
            lang, has_eff = effect_by_fn.get(bare, ("", False))
            # Hotness predicate: at least ONE hot signal (callers≥threshold, a
            # state write, an ELEVATE tag, or a value-effect regex match).
            is_hot = (n_callers >= _CALLER_THRESHOLD or writes or elevate or has_eff)
            if not is_hot:
                continue
            # Formula-2: log-dampened fan-in blended with the (unchanged) security
            # terms + a mild flat entry-point bonus. See _W_* rationale above.
            score = (_W_FANIN * math.log2(n_callers + 1)
                     + (_W_WRITES if writes else 0.0)
                     + (_W_ELEVATE if elevate else 0.0)
                     + (_W_VALUE if has_eff else 0.0)
                     + (_W_ENTRY if n_callers <= _ENTRY_THRESH else 0.0))
            location = info.get("loc", loc_by_fn.get(bare, "?"))
            bare_display = info.get("bare", fk)
            display = (
                fk
                if graph_display_counts.get(
                    (str(bare_display).casefold(), str(location).casefold()), 0
                ) > 1
                else bare_display
            )
            hot.append({
                "function": display,
                "loc": location,
                "callers": n_callers,
                "writes": writes,
                "elevate": elevate,
                "value_effect": has_eff,
                "lang": lang,
                "score": score,
            })
        # Deterministic ranking: score desc, then name asc (tie-break stable).
        hot.sort(key=lambda h: (
            -h["score"], str(h["function"]).lower(),
            str(h.get("loc") or "").lower(),
        ))
        cap_rows = []
        if len(hot) > _MAX_HOT_FUNCTIONS:
            cap_rows.append(shortfall(
                producer=producer,
                scope="mechanical-graph-hotset",
                cap="MAX_HOT_FUNCTIONS",
                limit=_MAX_HOT_FUNCTIONS,
                observed=len(hot),
                retained=_MAX_HOT_FUNCTIONS,
                exact=True,
                samples=[h.get("function", "") for h in hot[_MAX_HOT_FUNCTIONS:]],
                detail="graph-ranked hot functions were omitted from the axis matrix",
            ))
        try:
            replace_producer_shortfalls(
                scratchpad, producer, cap_rows
            )
        except Exception:
            pass
        _write_hot_function_cap_receipt(
            scratchpad,
            source_scope="mechanical-graph-hotset",
            hot=hot,
            limit=_MAX_HOT_FUNCTIONS,
        )
        return hot[:_MAX_HOT_FUNCTIONS]
    except Exception as exc:
        _invalidate_hot_function_cap_receipt(Path(scratchpad))
        try:
            replace_producer_shortfalls(
                scratchpad, producer, [unknown_shortfall(
                    producer=producer,
                    scope="hotset-provider",
                    kind="PROVIDER_FAILED",
                    detail=f"hot-function ranking failed: {exc!r}",
                )],
            )
        except Exception:
            pass
        return []


def _axis_examined_signals(block: str, axis: str) -> bool:
    """Return True iff the finding `block` carries a CLOSED depth-evidence signal
    that this `axis` was examined at the block's locus. Reads only the closed tag
    vocabulary + mechanical substring cues that STRENGTHEN a tag anchor. Ambiguous
    ⇒ False (caller defaults the cell to GAP — recall-safe)."""
    b = block or ""
    if axis == "theft":
        return bool(_TRACE_TO_MOVE.search(b) or _POST_TYPE_BAL_ACC.search(b))
    if axis == "liveness":
        return bool(_TRACE_TO_REVERT.search(b)
                    or (_TAG_BOUNDARY.search(b) and (_TRACE_TO_REVERT.search(b) or _MH_LIVENESS.search(b))))
    if axis == "accounting":
        return bool(_TAG_VARIATION.search(b) or _TAG_REGRESS.search(b)
                    or (_TAG_BOUNDARY.search(b) and _POST_TYPE_BAL_ACC.search(b)))
    if axis == "provenance":
        # A [CROSS-DOMAIN-DEP: external] tag is an ADMISSION the external domain
        # was NOT analyzed, not evidence it WAS — so it must NOT count as an
        # EXAMINED signal here (that would wrongly close the provenance gap). It
        # is instead harvested into a STEP-0a-LC enabler (see chain_prep). An
        # ambiguous provenance cell defaults to GAP (recall-safe).
        return bool(_TAG_EXT_ASSUMPTION.search(b)
                    or (_STALENESS_CUE.search(b) and _TAG_TRACE.search(b)))
    if axis == "boundary":
        return bool(_TAG_BOUNDARY.search(b) and _BOUNDARY_ZERO_ETC.search(b))
    if axis == "identity":
        # CWE-863/CWE-441/CWE-639: was the caller<->subject authorization
        # binding traced to a terminal outcome (a [TRACE:] locus anchored by a
        # stated ACCESS postcondition -- the "who can use these" dimension),
        # or does the finding's own prose concretely attest the
        # subject-authority relationship via the generic authorization-subject
        # cue anchored to a trace? Mirrors provenance's tag+cue shape; a bare
        # BALANCE postcondition next to an unrelated TRACE (theft/liveness)
        # must not also satisfy this axis.
        return bool((_TAG_TRACE.search(b) and _POST_TYPE_ACCESS.search(b))
                    or (_TAG_TRACE.search(b) and _IDENTITY_CUE.search(b)))
    return False


def _axis_field(block: str, name: str) -> str:
    """Extract a finding field's prose (`**Name**: ...` up to the next bold field
    / heading / end). Bold-marker- and case-tolerant; multi-line joined to one
    line for substring cue matching. Empty when the field is absent."""
    m = re.search(r"\*{0,2}" + re.escape(name) + r"\*{0,2}\s*:\s*(.+?)"
                  r"(?=\n\s*\*{2}\w|\n#{2,4}\s|\Z)",
                  block or "", re.IGNORECASE | re.DOTALL)
    return (m.group(1).strip() if m else "").replace("\n", " ")


def _axis_examined_secondary(block: str, axis: str) -> bool:
    """SECONDARY EXAMINED signal (Fix 3b — ecosystem-parity, prose-grounded).

    The primary signal reads ONLY the closed bracketed depth-evidence tags. On
    less tag-dense ecosystems (e.g. Soroban) a finding often addresses an axis
    CONCRETELY in its Description/Impact prose without stamping the exact tag,
    inflating false GAP cells. When the block resolves to the function AND its
    Description/Impact (or a stated BALANCE/ACCESS postcondition) concretely
    speaks to the axis via the already-defined mechanical cues, count the axis
    EXAMINED even without a bracketed tag. This is a SECONDARY signal only — the
    caller keeps `ambiguous ⇒ GAP` as the floor for every axis with no cue.
    Generic: reuses existing cue regexes; names no protocol."""
    b = block or ""
    prose = " ".join(_axis_field(b, f) for f in ("Description", "Impact"))
    if axis == "liveness":
        return bool(_MH_LIVENESS.search(prose))
    if axis == "provenance":
        return bool(_STALENESS_CUE.search(prose))
    if axis == "accounting":
        # A stated BALANCE/ACCESS postcondition type concretely addresses the
        # accounting axis (value/authorization relation examined at the locus).
        return bool(_POST_TYPE_BAL_ACC.search(b))
    if axis == "identity":
        # Tag-light ecosystems (Soroban/DAML) often attest the caller<->subject
        # binding concretely in Description/Impact prose without stamping a
        # bracketed [TRACE:] tag. The generic cue alone in prose is sufficient.
        return bool(_IDENTITY_CUE.search(prose))
    return False


def _axis_na(hf: dict, axis: str) -> bool:
    """Mechanically-provable N/A: a cell is N/A only when the function CANNOT be
    exposed to the axis. Conservative — returns True ONLY on a provable exclusion,
    else False (⇒ the cell falls through to EXAMINED-or-GAP). The only provable
    exclusion we assert: a function with NO value-effect (mechanically) cannot be
    a theft target."""
    if axis == "theft":
        # No value effect AND no state write ⇒ nothing to steal at this locus.
        return not (hf.get("value_effect") or hf.get("writes"))
    if axis == "identity":
        # No value effect, no state write, and no role-elevation signal ⇒ this
        # locus has no value/state/role effect that could be misdirected onto a
        # subject distinct from its authorizing caller — nothing for the
        # authorization-subject axis to bind. "Distinct subject" itself is not
        # cheaply derivable from abstract `hf` metadata without per-ecosystem
        # parameter-shape parsing, so we degrade conservatively onto the same
        # value/state/role-effect gate already proven safe for `theft`, rather
        # than fabricate a source-token detector here.
        return not (hf.get("value_effect") or hf.get("writes") or hf.get("elevate"))
    return False


def _axis_population_digest(value: object) -> str:
    """Canonical UTF-8 digest used by the typed P0-I population authority."""

    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _axis_cap_authority(
    scratchpad: Path,
    retained_hot: list[dict],
    *,
    current_run_stamp: dict | None,
    run_id: str,
) -> tuple[dict | None, list[str]]:
    """Validate the complete pre-cap hot population.

    ``compute_hot_function_set`` returns only the retained prefix.  The receipt
    is therefore the only exact authority for omitted identities; a missing or
    malformed receipt is UNKNOWN, never an empty population.
    """

    path = Path(scratchpad) / _HOT_FUNCTION_CAP_RECEIPT_NAME
    if (
        not isinstance(current_run_stamp, dict)
        or current_run_stamp.get("run_id") != run_id
        or current_run_stamp.get("write_count") != 1
    ):
        return None, [
            "hot-function cap receipt was not produced exactly once by the "
            "current run"
        ]
    try:
        payload = _axis_strict_json_bytes(
            path.read_bytes(), label="hot-function cap receipt"
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        return None, [
            "hot-function cap receipt is unavailable or unreadable: "
            f"{type(exc).__name__}: {exc}"
        ]
    required = {
        "schema_version",
        "producer",
        "source_scope",
        "limit",
        "observed_count",
        "retained_count",
        "omitted_count",
        "population_tail",
        "retained_tail",
        "omitted_tail",
        "retained_identities",
        "omitted_identities",
        "observed_items",
        "retained_items",
        "omitted_items",
        "omitted_identities_sha256",
        "population_sha256",
        "raw_fallback_authority",
        "methodology_application_proven",
        "receipt_sha256",
    }
    if not isinstance(payload, dict) or set(payload) != required:
        return None, ["hot-function cap receipt has an invalid exact shape"]
    unsigned = {
        key: value for key, value in payload.items() if key != "receipt_sha256"
    }
    if (
        payload.get("schema_version") != _HOT_FUNCTION_CAP_RECEIPT_SCHEMA
        or payload.get("producer") != "enumeration.hot_function_set"
        or not str(payload.get("source_scope") or "").strip()
        or payload.get("raw_fallback_authority") != "CANDIDATE_ONLY"
        or payload.get("methodology_application_proven") is not False
        or payload.get("receipt_sha256") != _hot_function_cap_digest(unsigned)
        or payload.get("receipt_sha256")
        != current_run_stamp.get("receipt_sha256")
    ):
        return None, ["hot-function cap receipt authority or digest mismatch"]
    limit = payload.get("limit")
    observed = payload.get("observed_items")
    retained = payload.get("retained_items")
    omitted = payload.get("omitted_items")
    if (
        type(limit) is not int
        or limit < 0
        or not isinstance(observed, list)
        or not isinstance(retained, list)
        or not isinstance(omitted, list)
        or any(not isinstance(item, dict) for item in observed)
    ):
        return None, ["hot-function cap receipt population is malformed"]
    retained_ids = [_hot_function_identity(item) for item in retained]
    omitted_ids = [_hot_function_identity(item) for item in omitted]
    population_ids = [*retained_ids, *omitted_ids]
    if (
        observed != [*retained, *omitted]
        or retained != observed[:limit]
        or omitted != observed[limit:]
        or retained != retained_hot
        or payload.get("retained_identities") != retained_ids
        or payload.get("omitted_identities") != omitted_ids
        or len(population_ids) != len(set(population_ids))
        or any(not identity or identity == "@" for identity in population_ids)
        or type(payload.get("observed_count")) is not int
        or type(payload.get("retained_count")) is not int
        or type(payload.get("omitted_count")) is not int
        or payload.get("observed_count") != len(observed)
        or payload.get("retained_count") != len(retained)
        or payload.get("omitted_count") != len(omitted)
        or payload.get("population_tail")
        != (population_ids[-1] if population_ids else "")
        or payload.get("retained_tail")
        != (retained_ids[-1] if retained_ids else "")
        or payload.get("omitted_tail")
        != (omitted_ids[-1] if omitted_ids else "")
        or payload.get("omitted_identities_sha256")
        != _hot_function_cap_digest(omitted_ids)
        or payload.get("population_sha256")
        != _hot_function_cap_digest(population_ids)
    ):
        return None, [
            "hot-function cap receipt does not bind the returned/full population"
        ]
    return payload, []


def _axis_graph_identity_index(graph: dict | None) -> dict[tuple[str, str], str]:
    if graph is None:
        return {}
    counts: dict[tuple[str, str], int] = {}
    rows: list[tuple[str, str, str]] = []
    for identity, raw in graph.get("functions", {}).items():
        if not isinstance(raw, dict):
            continue
        bare = str(raw.get("bare", identity))
        locus = str(raw.get("loc", "?"))
        key = (bare.casefold(), locus.casefold())
        counts[key] = counts.get(key, 0) + 1
        rows.append((str(identity), bare, locus))
    result: dict[tuple[str, str], str] = {}
    for identity, bare, locus in rows:
        display = identity if counts[(bare.casefold(), locus.casefold())] > 1 else bare
        result[(display.casefold(), locus.casefold())] = identity
    return result


def _axis_source_binding(
    project_root: Path | None,
    locus: object,
) -> tuple[dict, str]:
    """Bind a provider locus to current production bytes without escaping root."""

    locus_text = str(locus or "").strip().strip("`")
    empty = {
        "source_relpath": "",
        "source_locus": locus_text,
        "source_sha256": "",
    }
    if project_root is None:
        return empty, "axis source root is unavailable"
    match = re.fullmatch(
        r"(?P<path>.+\.(?:sol|vy|rs|go|move|daml))"
        r"(?:(?::[A-Za-z_]\w*)?:[Ll]?(?P<line>[1-9][0-9]*))",
        locus_text,
        re.IGNORECASE,
    )
    if match is None:
        return empty, f"axis locus has no production source identity: {locus!s}"
    display_path = match.group("path").replace("\\", "/")
    relative = Path(display_path)
    if (
        relative.is_absolute()
        or re.match(r"^[A-Za-z]:/", display_path)
        or ".." in relative.parts
    ):
        return empty, f"axis source path escapes the project root: {display_path}"
    try:
        root = Path(project_root).resolve(strict=True)
        resolved = (root / relative).resolve(strict=True)
        resolved.relative_to(root)
        # Match the graph provider's cross-checkout binding: universal newline
        # normalization makes LF and CRLF checkouts semantically identical.
        text = resolved.read_text(encoding="utf-8", errors="strict")
    except (OSError, ValueError, UnicodeError) as exc:
        return empty, (
            f"axis source binding failed for {display_path}: "
            f"{type(exc).__name__}: {exc}"
        )
    line = int(match.group("line"))
    line_count = len(text.splitlines())
    if line > line_count:
        return empty, (
            f"axis source line {line} is outside {display_path} "
            f"(current line count {line_count})"
        )
    return {
        "source_relpath": relative.as_posix(),
        "source_locus": f"{relative.as_posix()}:L{line}",
        "source_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
    }, ""


def _axis_strict_json_bytes(raw: bytes, *, label: str) -> dict:
    def object_hook(pairs: list[tuple[str, object]]) -> dict:
        result: dict = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"{label} duplicates JSON key {key!r}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ValueError(f"{label} contains non-finite constant {value}")

    payload = json.loads(
        raw.decode("utf-8", errors="strict"),
        object_pairs_hook=object_hook,
        parse_constant=reject_constant,
    )
    if not isinstance(payload, dict):
        raise ValueError(f"{label} is not an object")
    return payload


def _axis_graph_provider_debt(
    scratchpad: Path,
    project_root: Path | None,
) -> tuple[dict | None, list[str]]:
    """Validate the typed compiler graph before it may authorize EXACT/N/A."""

    path = Path(scratchpad) / "_mechanical_graph.json"
    try:
        payload = _axis_strict_json_bytes(
            path.read_bytes(), label="mechanical graph"
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        return None, [
            "mechanical graph authority is unavailable or invalid: "
            f"{type(exc).__name__}: {exc}"
        ]
    required = {
        "schema_version",
        "function_signature_schema",
        "source",
        "state_symbols",
        "var_refs",
        "functions",
        "function_signatures",
    }
    if set(payload) != required:
        return payload, ["mechanical graph typed authority shape mismatch"]
    try:
        from state_symbol_authority import GRAPH_SCHEMA
        from enumeration_type_ir import (
            FUNCTION_SIGNATURE_SCHEMA,
            validate_function_signature_fact,
        )
    except Exception as exc:
        return payload, [
            "mechanical graph validators are unavailable: "
            f"{type(exc).__name__}: {exc}"
        ]
    functions = payload.get("functions")
    signatures = payload.get("function_signatures")
    if (
        payload.get("schema_version") != GRAPH_SCHEMA
        or payload.get("function_signature_schema") != FUNCTION_SIGNATURE_SCHEMA
        or not str(payload.get("source") or "").strip()
        or not isinstance(payload.get("state_symbols"), list)
        or not isinstance(payload.get("var_refs"), dict)
        or not isinstance(functions, dict)
        or not isinstance(signatures, dict)
        or set(functions) != set(signatures)
    ):
        return payload, ["mechanical graph typed authority schema mismatch"]
    if not functions:
        return payload, [
            "mechanical graph has no typed function population; exact zero is "
            "not proven"
        ]
    if project_root is None:
        return payload, ["mechanical graph project root is unavailable"]

    debt: list[str] = []
    for identity in sorted(functions):
        row = functions.get(identity)
        fact = signatures.get(identity)
        if (
            not isinstance(row, dict)
            or not isinstance(fact, dict)
            or row.get("signature_fact") != fact
        ):
            debt.append(f"{identity}: graph/signature row binding mismatch")
            continue
        issues = validate_function_signature_fact(fact)
        if issues:
            debt.append(f"{identity}: " + "; ".join(issues))
            continue
        if (
            str(fact.get("function_identity") or "") != str(identity)
            or str(fact.get("authority") or "").upper() != "COMPILER_PROVIDER"
        ):
            debt.append(
                f"{identity}: function identity lacks compiler-provider authority"
            )
            continue
        binding = (
            fact.get("source_binding")
            if isinstance(fact.get("source_binding"), dict)
            else {}
        )
        locus = (
            f"{binding.get('path', '')}:L{int(binding.get('line') or 0)}"
        )
        observed, issue = _axis_source_binding(project_root, locus)
        if issue:
            debt.append(f"{identity}: {issue}")
            continue
        if (
            binding.get("status") != "EXACT"
            or str(binding.get("source_sha256") or "").lower()
            != observed["source_sha256"]
        ):
            debt.append(
                f"{identity}: graph source binding is unknown or stale"
            )
    return payload, debt


def _axis_provider_input_snapshot(
    scratchpad: Path,
    project_root: Path | None,
) -> tuple[dict[str, str], list[str]]:
    """Bind every deterministic input used to derive the hot denominator.

    The before/after comparison closes the graph/source TOCTOU window: a cap
    produced from one graph cannot be combined with source bindings read from a
    later graph and still authorize ``EXACT``.
    """

    bindings: dict[str, str] = {}
    debt: list[str] = []
    root = Path(scratchpad)
    for name in (
        "_mechanical_graph.json",
        "function_summary.md",
        "attack_surface.md",
    ):
        path = root / name
        if not path.is_file():
            bindings[name] = ""
            continue
        try:
            bindings[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as exc:
            bindings[name] = ""
            debt.append(
                f"axis provider input {name} is unreadable: "
                f"{type(exc).__name__}: {exc}"
            )
    if project_root is None:
        bindings["production_source_manifest"] = ""
        debt.append("axis production-source manifest root is unavailable")
        return bindings, debt
    try:
        from recon_prepass import _production_source_files, _rel  # type: ignore

        rows: list[dict[str, str]] = []
        suffixes = tuple(sorted(_SC_PRODUCTION_SOURCE_SUFFIXES))
        for path in _production_source_files(project_root, suffixes):
            rows.append(
                {
                    "path": str(_rel(path, project_root)).replace("\\", "/"),
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
            )
        rows.sort(key=lambda row: row["path"])
        bindings["production_source_manifest"] = _axis_population_digest(rows)
    except (OSError, ValueError, UnicodeError) as exc:
        bindings["production_source_manifest"] = ""
        debt.append(
            "axis production-source manifest is unavailable: "
            f"{type(exc).__name__}: {exc}"
        )
    return bindings, debt


def _axis_source_function_universe_debt(
    graph: dict | None,
    project_root: Path | None,
) -> list[str]:
    """Require every source-visible supported function in the typed graph.

    Per-row compiler facts prove that included graph rows are current; they do
    not prove that the provider omitted no rows.  This independent source
    enumeration supplies the missing subset check.  Unsupported production
    grammars degrade instead of silently certifying a graph-local zero.
    """

    if graph is None or project_root is None:
        return ["axis graph/source function universe cannot be compared"]
    try:
        from recon_prepass import _production_source_files, _rel  # type: ignore

        production_files = list(
            _production_source_files(
                project_root,
                tuple(sorted(_SC_PRODUCTION_SOURCE_SUFFIXES)),
            )
        )
    except Exception as exc:
        return [
            "axis production function universe is unavailable: "
            f"{type(exc).__name__}: {exc}"
        ]
    parsed_suffixes = set(_SUPPORTED_SUFFIXES)
    unsupported = sorted(
        {
            str(_rel(path, project_root)).replace("\\", "/")
            for path in production_files
            if path.suffix.lower() not in parsed_suffixes
        }
    )
    debt = [
        f"axis source function universe has no exact parser for {path}"
        for path in unsupported
    ]
    source_rows = {
        (
            str(name).casefold(),
            str(relative).replace("\\", "/").casefold(),
            int(line),
        )
        for _lang, relative, name, _params, _body, line
        in _iter_functions(project_root)
    }
    graph_rows: set[tuple[str, str, int]] = set()
    for identity, raw in graph.get("functions", {}).items():
        if not isinstance(raw, dict):
            continue
        binding, issue = _axis_source_binding(
            project_root,
            raw.get("loc", ""),
        )
        if issue:
            continue
        match = re.fullmatch(
            r"(?P<path>.+):L(?P<line>[1-9][0-9]*)",
            str(binding["source_locus"]),
            re.ASCII,
        )
        if match is None:
            continue
        graph_rows.add(
            (
                str(raw.get("bare", identity)).casefold(),
                match.group("path").casefold(),
                int(match.group("line")),
            )
        )
    missing = sorted(source_rows - graph_rows)
    debt.extend(
        "axis typed graph omits production-source function "
        f"{name}@{path}:L{line}"
        for name, path, line in missing
    )
    return debt


def _axis_coverage_shortfall_debt(scratchpad: Path) -> list[str]:
    """Return population-relevant UNKNOWN/lower-bound control-plane debt."""

    path = Path(scratchpad) / "_coverage_shortfalls.json"
    if not path.is_file():
        return []
    try:
        payload = _axis_strict_json_bytes(
            path.read_bytes(), label="coverage-shortfall authority"
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        return [
            "coverage-shortfall authority is unreadable: "
            f"{type(exc).__name__}: {exc}"
        ]
    if (
        not isinstance(payload, dict)
        or set(payload) != {"schema_version", "shortfalls"}
        or type(payload.get("schema_version")) is not int
        or payload.get("schema_version") != 1
        or not isinstance(payload.get("shortfalls"), list)
    ):
        return ["coverage-shortfall authority has an invalid schema"]
    relevant = {
        "enumeration.hot_function_set",
        _GRAPH_HEALTH_PRODUCER,
    }
    debt: list[str] = []
    for index, row in enumerate(payload["shortfalls"]):
        if not isinstance(row, dict):
            debt.append(f"coverage-shortfall row {index} is malformed")
            continue
        producer = str(row.get("producer") or "")
        try:
            row = _validate_coverage_shortfall_row(row)
        except CoverageShortfallError:
            debt.append(
                f"{producer or f'row {index}'}: coverage-shortfall row is invalid"
            )
            continue
        if row["producer"] not in relevant:
            continue
        semantics = row["count_semantics"]
        if semantics == "UNKNOWN":
            debt.append(
                f"{row.get('producer')}:{row.get('kind')}: "
                f"{row.get('detail') or 'population coverage is unknown'}"
            )
        elif semantics == "LOWER_BOUND":
            debt.append(
                f"{row.get('producer')}:{row.get('kind')}: "
                "population is only a lower bound"
            )
        elif semantics != "EXACT":
            debt.append(
                f"{row.get('producer')}: coverage-shortfall row is invalid"
            )
    return debt


def _validated_axis_examined_authority(
    authority: dict | None,
    *,
    scratchpad: Path,
    run_id: str,
) -> tuple[set[tuple[str, str]], dict, list[str]]:
    """Validate optional typed prior-application evidence.

    Markdown, closed-tag regexes, and arbitrary scratchpad files are
    intentionally absent from this function.  Without this side authority,
    prior prose is only a cost hint and cannot suppress an axis obligation.
    """

    absent = {
        "status": "ABSENT",
        "schema_version": AXIS_EXAMINED_AUTHORITY_SCHEMA,
        "row_count": 0,
        "authority_digest": "",
        "hint_artifacts_consumed": [],
    }
    if authority is None:
        return set(), absent, []
    required = {
        "schema_version",
        "run_id",
        "row_count",
        "rows",
        "hint_artifacts_consumed",
        "authority_digest",
    }
    if not isinstance(authority, dict) or set(authority) != required:
        return set(), absent, ["typed axis-examined authority shape mismatch"]
    unsigned = {
        key: value for key, value in authority.items()
        if key != "authority_digest"
    }
    rows = authority.get("rows")
    hints = authority.get("hint_artifacts_consumed")
    if (
        authority.get("schema_version") != AXIS_EXAMINED_AUTHORITY_SCHEMA
        or authority.get("run_id") != run_id
        or not isinstance(rows, list)
        or type(authority.get("row_count")) is not int
        or authority.get("row_count") < 0
        or authority.get("row_count") != len(rows)
        or not isinstance(hints, list)
        or hints != []
        or authority.get("authority_digest") != _axis_population_digest(unsigned)
    ):
        return set(), absent, [
            "typed axis-examined authority run, denominator, or digest mismatch"
        ]
    identities: set[tuple[str, str]] = set()
    replayed_receipts: dict[str, dict] = {}
    for row in rows:
        if (
            not isinstance(row, dict)
            or set(row)
            != {
                "function_identity",
                "axis",
                "application_receipt",
                "application_row_id",
                "application_row_digest",
            }
            or not str(row.get("function_identity") or "").strip()
            or row.get("axis") not in _AXES
            or not str(row.get("application_receipt") or "").strip()
            or not str(row.get("application_row_id") or "").strip()
            or not re.fullmatch(
                r"[0-9a-f]{64}",
                str(row.get("application_row_digest") or ""),
            )
        ):
            return set(), absent, ["typed axis-examined authority row is malformed"]
        key = (str(row["function_identity"]), str(row["axis"]))
        if key in identities:
            return set(), absent, [
                "typed axis-examined authority duplicates a function/axis identity"
            ]
        receipt_name = str(row["application_receipt"])
        relative = Path(receipt_name)
        if (
            relative.is_absolute()
            or len(relative.parts) != 1
            or relative.name != receipt_name
        ):
            return set(), absent, [
                "typed axis-examined authority application receipt is outside "
                "the registered scratchpad namespace"
            ]
        try:
            receipt_path = (Path(scratchpad) / relative).resolve(strict=True)
            receipt_path.relative_to(Path(scratchpad).resolve(strict=True))
            if receipt_name not in replayed_receipts:
                receipt_payload = _axis_strict_json_bytes(
                    receipt_path.read_bytes(),
                    label="axis application receipt",
                )
                worklist_payload = _axis_strict_json_bytes(
                    (Path(scratchpad) / "axis_disposition_worklist.json").read_bytes(),
                    label="axis disposition worklist",
                )
                from axis_disposition import load_axis_disposition_v2_receipt

                replayed_receipts[receipt_name] = (
                    load_axis_disposition_v2_receipt(
                        receipt_path,
                        worklist=worklist_payload,
                    )
                )
            receipt = replayed_receipts[receipt_name]
        except Exception as exc:
            return set(), absent, [
                "typed axis-examined authority application receipt could not "
                f"be replayed: {type(exc).__name__}: {exc}"
            ]
        matching = [
            candidate
            for candidate in receipt.get("dispositions", [])
            if isinstance(candidate, dict)
            and candidate.get("work_item_id") == row["application_row_id"]
        ]
        if len(matching) != 1:
            return set(), absent, [
                "typed axis-examined authority application row is absent or "
                "ambiguous in the replayed receipt"
            ]
        application_row = matching[0]
        source_item = (
            application_row.get("source_item")
            if isinstance(application_row.get("source_item"), dict)
            else {}
        )
        if (
            application_row.get("application_record_complete") is not True
            or source_item.get("function_identity") != row["function_identity"]
            or source_item.get("axis") != row["axis"]
            or _axis_population_digest(application_row)
            != row["application_row_digest"]
        ):
            return set(), absent, [
                "typed axis-examined authority application row evidence, locus, "
                "or digest mismatch"
            ]
        identities.add(key)
    projection = {
        "status": "CURRENT",
        "schema_version": AXIS_EXAMINED_AUTHORITY_SCHEMA,
        "row_count": len(rows),
        "authority_digest": authority["authority_digest"],
        "hint_artifacts_consumed": [],
    }
    return identities, projection, []


def _render_axis_population_projection(population: dict) -> str:
    lines = [
        "# Hot-Function × Axis Coverage Matrix",
        "",
        (
            f"> Population authority: **{population['denominator_status']}**; "
            f"{population['observed_hot_function_count']} hot function(s); "
            f"{population['gap_count']} executable GAP cell(s)."
        ),
        (
            "> Markdown is a human projection only. Exact authority is "
            "`_hot_function_axes.json`; unregistered prose cannot close a cell."
        ),
        "",
        "| Function Identity | Function | Location | "
        + " | ".join(_AXES)
        + " |",
        "|---|---|---|" + "|".join("---" for _ in _AXES) + "|",
    ]
    for row in population["matrix"]:
        lines.append(
            f"| `{row['function_identity']}` | `{row['function']}` | "
            f"{row['loc']} | "
            + " | ".join(row["cells"][axis] for axis in _AXES)
            + " |"
        )
    if population["debt"]:
        lines.extend(["", "## Provider debt", ""])
        lines.extend(f"- {item}" for item in population["debt"])
    return "\n".join(lines) + "\n"


def compute_axis_population(
    scratchpad: Path,
    *,
    run_id: str,
    examined_authority: dict | None = None,
) -> dict:
    """Build the schema-v2 P0-I axis population without false-clean collapse.

    This is the production authority API.  Provider exceptions, stale/missing
    cap receipts, graph degradation, and source-binding failures are explicit
    ``UNKNOWN``/``DEGRADED`` states.  The legacy list-returning API remains
    available for compatibility but is not safe as a no-work predicate.
    """

    root = Path(scratchpad)
    current_run_id = str(run_id)
    debt: list[str] = []
    retained_hot: list[dict] = []
    provider_exception = False
    if not current_run_id.strip():
        debt.append("axis population requires a non-empty current run identity")
    pre_project_root = _locate_project_root(root)
    pre_inputs, pre_input_debt = _axis_provider_input_snapshot(
        root,
        pre_project_root,
    )
    debt.extend(pre_input_debt)
    cap_write_stamp: dict = {
        "run_id": current_run_id,
        "write_count": 0,
        "receipt_sha256": "",
    }
    context_token = _AXIS_CAP_WRITE_CONTEXT.set(cap_write_stamp)
    try:
        try:
            retained_hot = [
                dict(item) for item in compute_hot_function_set(root)
                if isinstance(item, dict)
            ]
        except Exception as exc:
            provider_exception = True
            debt.append(
                "hot-function provider failed: "
                f"{type(exc).__name__}: {exc}"
            )
    finally:
        _AXIS_CAP_WRITE_CONTEXT.reset(context_token)

    project_root = _locate_project_root(root)
    post_inputs, post_input_debt = _axis_provider_input_snapshot(
        root,
        project_root,
    )
    debt.extend(post_input_debt)
    input_drifted = pre_inputs != post_inputs
    if input_drifted:
        debt.append(
            "axis provider graph/source inputs changed between cap derivation "
            "and population binding"
        )
        # One bounded deterministic repair pass refreshes the denominator over
        # the now-current inputs.  The original drift remains assurance debt,
        # so this cannot restore EXACT, but it prevents the degraded projection
        # from hiding newly-hot rows behind the stale pre-drift count.
        retry_stamp: dict = {
            "run_id": current_run_id,
            "write_count": 0,
            "receipt_sha256": "",
        }
        retry_token = _AXIS_CAP_WRITE_CONTEXT.set(retry_stamp)
        try:
            try:
                retained_hot = [
                    dict(item) for item in compute_hot_function_set(root)
                    if isinstance(item, dict)
                ]
                cap_write_stamp = retry_stamp
            except Exception as exc:
                provider_exception = True
                debt.append(
                    "hot-function provider stabilization failed: "
                    f"{type(exc).__name__}: {exc}"
                )
        finally:
            _AXIS_CAP_WRITE_CONTEXT.reset(retry_token)
        retry_project_root = _locate_project_root(root)
        retry_inputs, retry_input_debt = _axis_provider_input_snapshot(
            root,
            retry_project_root,
        )
        debt.extend(retry_input_debt)
        if retry_inputs != post_inputs:
            debt.append(
                "axis provider inputs changed again during the bounded "
                "stabilization pass"
            )
            cap_write_stamp["write_count"] = 0
        project_root = retry_project_root
        post_inputs = retry_inputs
    cap, cap_debt = _axis_cap_authority(
        root,
        retained_hot,
        current_run_stamp=cap_write_stamp,
        run_id=current_run_id,
    )
    debt.extend(cap_debt)
    hot = [
        dict(item) for item in (cap.get("observed_items") if cap else retained_hot)
        if isinstance(item, dict)
    ]
    graph, graph_debt = _axis_graph_provider_debt(root, project_root)
    debt.extend(graph_debt)
    graph_universe_debt = _axis_source_function_universe_debt(
        graph,
        project_root,
    )
    debt.extend(graph_universe_debt)
    shortfall_debt = _axis_coverage_shortfall_debt(root)
    debt.extend(shortfall_debt)

    examined, examined_projection, examined_debt = (
        _validated_axis_examined_authority(
            examined_authority,
            scratchpad=root,
            run_id=current_run_id,
        )
    )
    debt.extend(examined_debt)

    identity_index = _axis_graph_identity_index(graph)
    matrix: list[dict] = []
    gaps: list[dict] = []
    source_debt: list[str] = []
    graph_exact = (
        graph is not None
        and not graph_debt
        and not graph_universe_debt
        and not input_drifted
    )
    for raw in hot:
        display = str(raw.get("function") or "").strip()
        locus = str(raw.get("loc") or "?").strip()
        function_identity = identity_index.get(
            (display.casefold(), locus.casefold()),
            _hot_function_identity(raw),
        )
        binding, binding_issue = _axis_source_binding(project_root, locus)
        if binding_issue:
            source_debt.append(
                f"{function_identity}: {binding_issue}"
            )
        cells: dict[str, str] = {}
        cell_authority: dict[str, str] = {}
        for axis in _AXES:
            key = (function_identity, axis)
            if key in examined:
                cells[axis] = "EXAMINED"
                cell_authority[axis] = "TYPED_APPLICATION_AUTHORITY"
            elif graph_exact and not binding_issue and _axis_na(raw, axis):
                cells[axis] = "N/A"
                cell_authority[axis] = "COMPLETE_GRAPH_EXCLUSION"
            else:
                cells[axis] = "GAP"
                cell_authority[axis] = "RECALL_SAFE_DEFAULT"
                gaps.append(
                    {
                        "function_identity": function_identity,
                        "function": display,
                        "loc": locus,
                        "axis": axis,
                        "lang": str(raw.get("lang") or ""),
                        **binding,
                    }
                )
        matrix.append(
            {
                "function_identity": function_identity,
                "function": display,
                "loc": locus,
                "lang": str(raw.get("lang") or ""),
                "score": raw.get("score", 0),
                **binding,
                "cells": cells,
                "cell_authority": cell_authority,
            }
        )
    debt.extend(source_debt)
    matrix.sort(
        key=lambda row: (
            str(row["function_identity"]).casefold(),
            str(row["loc"]).casefold(),
        )
    )
    gaps.sort(
        key=lambda row: (
            str(row["function_identity"]).casefold(),
            str(row["axis"]),
        )
    )

    if provider_exception or cap is None:
        status = "UNKNOWN"
    elif (
        graph_debt
        or graph_universe_debt
        or source_debt
        or examined_debt
        or shortfall_debt
        or pre_input_debt
        or post_input_debt
        or input_drifted
        or not current_run_id.strip()
    ):
        status = "DEGRADED"
    else:
        status = "EXACT"
    source_bindings = {}
    for name in (
        "_mechanical_graph.json",
        _HOT_FUNCTION_CAP_RECEIPT_NAME,
        "_coverage_shortfalls.json",
    ):
        path = root / name
        if path.is_file():
            try:
                source_bindings[name] = hashlib.sha256(path.read_bytes()).hexdigest()
            except OSError:
                source_bindings[name] = ""
                debt.append(f"axis provider input became unreadable: {name}")
                if status == "EXACT":
                    status = "DEGRADED"
    observed_count = int(cap.get("observed_count", len(hot))) if cap else len(hot)
    exact_zero = bool(
        status == "EXACT"
        and observed_count == 0
        and not gaps
        and not debt
    )
    unsigned = {
        "schema_version": AXIS_POPULATION_SCHEMA,
        "provider_version": AXIS_POPULATION_PROVIDER_VERSION,
        "run_id": current_run_id,
        "denominator_status": status,
        "observed_hot_function_count": observed_count,
        "gap_count": len(gaps),
        "exact_zero_proven": exact_zero,
        "requires_execution": bool(gaps or debt or status != "EXACT"),
        "source_bindings": dict(sorted(source_bindings.items())),
        "cap_receipt_sha256": (
            str(cap.get("receipt_sha256") or "") if cap is not None else ""
        ),
        "examined_authority": examined_projection,
        "hot": hot,
        "matrix": matrix,
        "gaps": gaps,
        "debt": sorted(set(item for item in debt if item)),
        "raw_fallback_authority": "CANDIDATE_ONLY",
        "methodology_application_proven_by_raw_prose": False,
    }
    population = {
        **unsigned,
        "population_digest": _axis_population_digest(unsigned),
    }
    try:
        _write_json_atomic(root / "_hot_function_axes.json", population)
        projection = _render_axis_population_projection(population)
        projection_path = root / "hot_function_axes.md"
        temporary = projection_path.with_name(
            f".{projection_path.name}.{uuid.uuid4().hex}.tmp"
        )
        temporary.write_text(projection, encoding="utf-8", newline="\n")
        os.replace(temporary, projection_path)
    except OSError as exc:
        # Return an explicit UNKNOWN object even if the control-plane write
        # itself failed; the caller must route this as planning debt.
        failed_unsigned = {
            **unsigned,
            "denominator_status": "UNKNOWN",
            "exact_zero_proven": False,
            "requires_execution": True,
            "debt": sorted(set([
                *unsigned["debt"],
                "axis population authority could not be persisted: "
                f"{type(exc).__name__}: {exc}",
            ])),
        }
        return {
            **failed_unsigned,
            "population_digest": _axis_population_digest(failed_unsigned),
        }
    return population


def compute_axis_coverage_gaps(scratchpad: Path) -> list:
    """M2. Build the `function × axis` matrix over the hot set. For each hot
    function, map every value-bearing finding block whose locus resolves to that
    function, and mark each axis EXAMINED / N/A / GAP using CLOSED structured
    evidence as the primary signal plus bounded Description/Impact cues as a
    secondary signal (ambiguous ⇒ GAP). Writes `hot_function_axes.md` +
    `_hot_function_axes.json`. Returns the GAP rows: list of
    {function, loc, axis, lang}. Never raises; empty on failure."""
    try:
        scratchpad = Path(scratchpad)
        hot = compute_hot_function_set(scratchpad)
        if not hot:
            # Still write empty artifacts so the phase/validator sees authentic
            # empty state (no hot functions => no gaps => skip-when-clean).
            try:
                (scratchpad / "_hot_function_axes.json").write_text(
                    json.dumps({"hot": [], "matrix": [], "gaps": []}, indent=1),
                    encoding="utf-8")
                (scratchpad / "hot_function_axes.md").write_text(
                    "# Hot-Function × Axis Coverage Matrix\n\n"
                    "> No mechanically-hot functions were ranked (absent graph and "
                    "no value-effect functions). Nothing to gate.\n", encoding="utf-8")
            except Exception:
                pass
            return []

        graph = _load_graph(scratchpad)
        hot_identity_by_key: dict[tuple[str, str], str] = {}
        hot_bare_by_identity: dict[str, str] = {}
        if graph:
            display_counts: dict[tuple[str, str], int] = {}
            for graph_identity, graph_info in graph.get("functions", {}).items():
                if not isinstance(graph_info, dict):
                    continue
                key = (
                    str(graph_info.get("bare", graph_identity)).casefold(),
                    str(graph_info.get("loc", "?")).casefold(),
                )
                display_counts[key] = display_counts.get(key, 0) + 1
            for graph_identity, graph_info in graph.get("functions", {}).items():
                if not isinstance(graph_info, dict):
                    continue
                bare = str(graph_info.get("bare", graph_identity))
                locus = str(graph_info.get("loc", "?"))
                display = (
                    str(graph_identity)
                    if display_counts.get((bare.casefold(), locus.casefold()), 0) > 1
                    else bare
                )
                hot_identity_by_key[(display.casefold(), locus.casefold())] = str(
                    graph_identity
                )
                hot_bare_by_identity[str(graph_identity)] = bare

        def _matrix_function_identity(row: dict) -> str:
            return hot_identity_by_key.get(
                (
                    str(row.get("function") or "").casefold(),
                    str(row.get("loc") or "?").casefold(),
                ),
                _hot_function_identity(row),
            )

        # Collect finding blocks by exact provider function identity.  A bare
        # name bucket lets evidence from one overload/receiver falsely clear
        # every sibling with the same operation name.
        # Sources: the aggregated inventory + per-agent depth outputs (the closed
        # depth-evidence tags live in the depth findings).
        block_by_fn: dict = {}
        art_names = ["findings_inventory.md"]
        try:
            art_names += [p.name for p in sorted(scratchpad.glob("depth_*_findings.md"))]
        except Exception:
            pass
        try:
            art_names += [p.name for p in sorted(scratchpad.glob("*_findings.md"))]
        except Exception:
            pass
        seen_art: set = set()
        for an in art_names:
            if an in seen_art:
                continue
            seen_art.add(an)
            ap = scratchpad / an
            if not ap.exists():
                continue
            try:
                text = ap.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            # Split into finding blocks on '### Finding' / '## Finding' headers.
            headers = list(re.finditer(r"(?m)^#{2,4}\s*Finding\b.*$", text))
            spans = []
            if headers:
                for i, m in enumerate(headers):
                    end = headers[i + 1].start() if i + 1 < len(headers) else len(text)
                    spans.append(text[m.start():end])
            else:
                spans = [text]
            for block in spans:
                loc_m = re.search(r"(?im)^\s*\*{0,2}Location\*{0,2}\s*:\s*(.+)$", block)
                loc = loc_m.group(1).strip() if loc_m else ""
                fn = _fn_at_location(graph, loc) if (graph and loc) else None
                if fn and graph:
                    block_by_fn.setdefault(str(fn), []).append(block)
                    continue
                # Bare-name prose is usable only if it resolves to one hot
                # identity.  Ambiguity remains GAP instead of granting clear
                # authority to an arbitrary or cartesian set of overloads.
                matched_identities: set[str] = set()
                for hf in hot:
                    hf_identity = _matrix_function_identity(hf)
                    hn = str(
                        hot_bare_by_identity.get(hf_identity) or hf["function"]
                    ).lower()
                    if hn and re.search(r"\b" + re.escape(hn) + r"\b", loc.lower()):
                        matched_identities.add(hf_identity)
                if len(matched_identities) == 1:
                    block_by_fn.setdefault(matched_identities.pop(), []).append(block)

        matrix: list = []
        gaps: list = []
        for hf in hot:
            function_identity = _matrix_function_identity(hf)
            blocks = block_by_fn.get(function_identity, [])
            joined = "\n".join(blocks)
            cells: dict = {}
            for axis in _AXES:
                if _axis_na(hf, axis):
                    cells[axis] = "N/A"
                elif blocks and (_axis_examined_signals(joined, axis)
                                 or _axis_examined_secondary(joined, axis)):
                    # Primary = closed bracketed depth-evidence tag; secondary =
                    # concrete axis prose in Description/Impact (Fix 3b parity).
                    cells[axis] = "EXAMINED"
                else:
                    # No block, or a block with neither a closed-tag signal nor a
                    # concrete prose cue for this axis ⇒ ambiguous ⇒ GAP
                    # (recall-safe default / floor).
                    cells[axis] = "GAP"
                    gaps.append({
                        "function": hf["function"],
                        "loc": hf.get("loc", "?"),
                        "axis": axis,
                        "lang": hf.get("lang", ""),
                    })
            matrix.append({"function": hf["function"], "loc": hf.get("loc", "?"),
                           "score": hf.get("score", 0), "cells": cells})

        try:
            (scratchpad / "_hot_function_axes.json").write_text(
                json.dumps({"hot": hot, "matrix": matrix, "gaps": gaps}, indent=1),
                encoding="utf-8")
        except Exception:
            pass
        try:
            lines = ["# Hot-Function × Axis Coverage Matrix", "",
                     f"> {len(hot)} hot function(s) ranked mechanically; {len(gaps)} "
                     "GAP cell(s). Axis-EXAMINED uses CLOSED structured evidence "
                     "as the primary signal and bounded Description/Impact cues "
                     "as a secondary signal; an ambiguous cell defaults to GAP "
                     "(recall-safe). N/A is a mechanically-provable exclusion.", "",
                     "| Function | Location | " + " | ".join(a for a in _AXES) + " |",
                     "|----------|----------|" + "|".join("---" for _ in _AXES) + "|"]
            for row in matrix:
                cells = row["cells"]
                lines.append(f"| `{row['function']}` | {row['loc']} | "
                             + " | ".join(cells[a] for a in _AXES) + " |")
            (scratchpad / "hot_function_axes.md").write_text("\n".join(lines) + "\n",
                                                             encoding="utf-8")
        except Exception:
            pass
        return gaps
    except Exception:
        return []


def promote_axis_findings_to_inventory(scratchpad: Path) -> dict:
    """M2. Append the axis-deriver worker's findings to findings_inventory.md as
    fresh INV-* blocks, `Source IDs: AXISGAP`, `Verdict: NEEDS_VERIFICATION`.
    Idempotent via a dedicated receipt keyed on the source finding id. Chain
    metadata is inferred generically from the finding's own type cues. Clone of
    `promote_enumgap_exploration_to_inventory`. Returns {parsed, emitted}. Never
    raises, never halts."""
    scratchpad = Path(scratchpad)
    try:
        art = scratchpad / "axis_coverage_findings.md"
        inv = scratchpad / "findings_inventory.md"
        if not art.exists() or not inv.exists():
            return {"parsed": 0, "emitted": 0}
        text = art.read_text(encoding="utf-8", errors="replace")
        inv_text = inv.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return {"parsed": 0, "emitted": 0}

    # Axis and enumgap promotions share one fresh CommonMark heading map and
    # exact equal-or-higher section boundaries.  Axis IDs remain generic
    # (AXIS-1 and AXIS-A-1 are both valid) while strict required fields are
    # enforced by the shared parser.
    parsed = list(parse_exploration_finding_blocks(text))
    if not parsed:
        return {"parsed": 0, "emitted": 0}

    receipt = scratchpad / "axis_coverage_promotion_receipt.md"
    promoted: set = set()
    if receipt.exists():
        try:
            promoted = set(_PROMOTION_RECEIPT_ID_RE.findall(
                receipt.read_text(encoding="utf-8", errors="replace")))
        except Exception:
            promoted = set()

    new = [p for p in parsed if p["id"] not in promoted]
    if not new:
        return {"parsed": len(parsed), "emitted": 0}

    max_inv = 0
    for mm in re.finditer(r"\bINV-(\d+)\b", inv_text):
        try:
            max_inv = max(max_inv, int(mm.group(1)))
        except ValueError:
            pass

    def _field(block: str, name: str) -> str:
        return _exploration_field(block, name)

    appended: list[str] = []
    rec_lines: list[str] = []
    for n, p in enumerate(new, 1):
        inv_id = f"INV-{max_inv + n:03d}"
        sev = _field(p["block"], "Severity") or "Low"
        loc = _field(p["block"], "Location") or "UNKNOWN"
        desc = _field(p["block"], "Description") or p["title"]
        impact = _field(p["block"], "Impact") or "Verifier to confirm the concrete harm."
        rc = _field(p["block"], "Root Cause")
        tag = _field(p["block"], "Preferred Tag") or "[CODE-TRACE]"
        # Generic chain metadata from the finding's own Postcondition type cue when
        # present; a freshness/provenance axis finding is naturally EXTERNAL/TIMING.
        post = _field(p["block"], "Postconditions Created")
        post_t = _field(p["block"], "Postcondition Types")
        appended.extend([
            f"### Finding [{inv_id}]: {p['title']}",
            f"**Severity**: {sev.split()[0] if sev else 'Low'}",
            f"**Location**: {loc}",
            f"**Preferred Tag**: {tag}",
            f"**Source IDs**: AXISGAP:{p['id']} (multi-axis coverage meta-pass; a "
            "mechanically-hot function was interrogated on a previously-unexamined "
            "risk axis — verifier to confirm or refute)",
            "**Verdict**: NEEDS_VERIFICATION",
        ])
        if rc:
            appended.append(f"**Root Cause**: {rc}")
        appended.extend([
            f"**Description**: {desc}",
            f"**Impact**: {impact}",
        ])
        appended.extend(_chain_metadata_lines(
            postcondition=post, postcondition_type=(post_t.split()[0] if post_t else ""),
        ))
        appended.append("")
        rec_lines.append(f"{p['id']} -> {inv_id}")

    header = ("\n\n## Multi-Axis Coverage Findings (AXISGAP)\n\n"
              "Findings produced by the Phase 4b.8 multi-axis coverage meta-pass: "
              "a mechanically-hot function interrogated on a risk axis its owning "
              "domain lens never examined. Low-confidence by construction — the "
              "verify phase confirms or refutes each. Recall-safe: append-only.\n\n")
    hdr = "" if "Multi-Axis Coverage Findings (AXISGAP)" in inv_text else header
    try:
        inv.write_text(_append_inventory_blocks(inv_text, hdr, appended), encoding="utf-8")
    except Exception:
        return {"parsed": len(parsed), "emitted": 0}

    try:
        prior = []
        if receipt.exists():
            prior = [ln for ln in receipt.read_text(encoding="utf-8", errors="replace").splitlines()
                     if "->" in ln]
        out = ["# Multi-Axis Coverage Promotion Receipt", ""]
        out += [ln.strip() for ln in prior] + rec_lines
        receipt.write_text("\n".join(out) + "\n", encoding="utf-8")
    except Exception:
        pass

    try:
        from plamen_mechanical import _write_finding_records_from_inventory
        _write_finding_records_from_inventory(scratchpad)
    except Exception:
        pass
    return {"parsed": len(parsed), "emitted": len(rec_lines)}


# ─────────────────────────────────────────────────────────────────────────────
# Phase 4b.7 handoff: promote the depth-exploration agent's findings into the
# inventory so they flow through the SAME inventory -> chain -> verify path as
# every other finding. The exploration agent TRACES each enumeration obligation
# (boundary/variation/trace) and writes a real finding OR a reasoned clear to
# `enumgap_exploration_findings.md`; only the emitted findings (NEXP-n blocks)
# are promoted — reasoned clears live in its Coverage Record and are not
# candidates. Append-only + idempotent via a dedicated receipt. Never raises.
#
# This is the recall fix's load-bearing seam: the obligation is now EXPLORED
# (by the depth agent) before it reaches verify, instead of being handed to
# verify as a raw low-confidence candidate. If the exploration phase did not run
# (no obligations, spawn failure, degrade), this function simply finds no
# `enumgap_exploration_findings.md` and is a no-op — the pre-existing ENUMGAP
# candidates the gate already appended remain as the haltless fallback.
# ─────────────────────────────────────────────────────────────────────────────

# Receipt idempotency re-read for the promote_*_to_inventory promoters. MUST use
# the SAME multi-segment ID shape as the shared exploration parser: the receipt is written as
# `<finding-id> -> INV-nnn`, and a narrower `[A-Za-z]{2,6}-\d+` re-read captured
# only the `A-1` substring of a 3-part `AXIS-A-1`, so `id not in promoted` was
# always True → duplicate promotion on every haltless resume/retry. Pairs with
# the heading regex; widen both together or idempotency silently breaks.
_PROMOTION_RECEIPT_ID_RE = re.compile(
    r"\b([A-Za-z]{2,6}(?:-[A-Za-z0-9]+)+)\s*->\s*INV-\d+"
)
_ENUMGAP_PROMOTION_RECEIPT_NAME = "enumgap_exploration_promotion_receipt.json"
_ENUMGAP_PROMOTION_RECEIPT_SCHEMA = (
    "plamen.enumgap_exploration_promotion_receipt.v1"
)
_INVENTORY_FINDING_CONTENT_RE = re.compile(
    r"^Finding\s*\[\s*(?P<id>INV-\d+)\s*\]\s*:\s*"
    r"(?P<title>.+?)\s*$",
    re.IGNORECASE,
)
_INVENTORY_APPEND_LOCK_NAME = "_inventory_append.lock"
_ENUMGAP_APPEND_PLAN_NAME = "enumgap_inventory_append_plan.json"
_ENUMGAP_APPEND_COMMIT_NAME = "enumgap_inventory_append_commit.json"
_INVENTORY_APPEND_LOCK = threading.RLock()
_INVENTORY_APPEND_PROCESS_STATE = threading.local()


@contextmanager
def _inventory_append_lock(
    scratchpad: Path, *, timeout_s: float = 30.0,
):
    """Serialize the enumgap inventory read/plan/CAS/commit transaction."""

    root = Path(scratchpad)
    path = root / _INVENTORY_APPEND_LOCK_NAME
    key = os.path.normcase(str(path.resolve(strict=False)))
    held = getattr(_INVENTORY_APPEND_PROCESS_STATE, "held", {})
    with _INVENTORY_APPEND_LOCK:
        if held.get(key, 0):
            held[key] += 1
            _INVENTORY_APPEND_PROCESS_STATE.held = held
            try:
                yield
            finally:
                held[key] -= 1
            return
        stream = path.open("a+b")
        try:
            if path.stat().st_size == 0:
                stream.write(b"\0")
                stream.flush()
            deadline = time.monotonic() + max(0.1, timeout_s)
            while True:
                try:
                    stream.seek(0)
                    if os.name == "nt":
                        import msvcrt

                        msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                    else:
                        import fcntl

                        fcntl.flock(
                            stream.fileno(),
                            fcntl.LOCK_EX | fcntl.LOCK_NB,
                        )
                    break
                except (BlockingIOError, OSError):
                    if time.monotonic() >= deadline:
                        raise OSError(
                            "inventory append lock contention timed out"
                        )
                    time.sleep(0.05)
            held[key] = 1
            _INVENTORY_APPEND_PROCESS_STATE.held = held
            try:
                yield
            finally:
                held.pop(key, None)
                try:
                    stream.seek(0)
                    if os.name == "nt":
                        import msvcrt

                        msvcrt.locking(
                            stream.fileno(), msvcrt.LK_UNLCK, 1
                        )
                    else:
                        import fcntl

                        fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
                except OSError:
                    pass
        finally:
            stream.close()


def _atomic_inventory_replace(path: Path, payload: bytes) -> None:
    temporary = path.with_name(
        f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    )
    temporary.write_bytes(payload)
    os.replace(temporary, path)


def _promotion_phaseio_issues(scratchpad: Path) -> list[str]:
    """Require exact enumgap MODEL -> reconcile lineage before delivery."""

    try:
        state = json.loads(
            (Path(scratchpad) / "_artifact_state.json").read_text(
                encoding="utf-8"
            )
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return [f"enumgap promotion PhaseIO ledger unavailable: {exc}"]
    bindings = state.get("artifact_bindings")
    units = state.get("work_units")
    if not isinstance(bindings, dict) or not isinstance(units, dict):
        return ["enumgap promotion PhaseIO ledger malformed"]
    requirements = {
        "scratchpad:enumgap_exploration_findings.md": (
            "/enumgap_exploration/model",
        ),
        "scratchpad:enumgap_disposition_receipt.json": (
            "/enumgap_disposition/reconcile",
        ),
    }
    issues: list[str] = []
    for identity, suffixes in requirements.items():
        binding = bindings.get(identity)
        owner = (
            str(binding.get("owner_key") or "")
            if isinstance(binding, dict) else ""
        )
        unit = units.get(owner)
        if (
            not isinstance(binding, dict)
            or not owner.endswith(suffixes)
            or binding.get("status") != "ACTIVE"
            or not isinstance(unit, dict)
            or unit.get("semantic_status") != "ACTIVE"
            or unit.get("execution_state") != "OUTPUT_COMMITTED"
            or unit.get("run_id") != binding.get("run_id")
            or unit.get("contract_digest")
            != binding.get("contract_digest")
        ):
            issues.append(
                f"{identity}: exact ACTIVE producer lineage is absent"
            )
            continue
        relative = identity.split(":", 1)[1]
        try:
            raw = (Path(scratchpad) / relative).read_bytes()
        except OSError:
            issues.append(f"{identity}: producer bytes are absent")
            continue
        if (
            type(binding.get("size")) is not int
            or binding.get("size") < 0
            or binding.get("size") != len(raw)
            or binding.get("sha256")
            != hashlib.sha256(raw).hexdigest()
        ):
            issues.append(f"{identity}: producer bytes drifted")
    return issues


def _inventory_finding_block_records(text: str) -> tuple[dict, ...]:
    """Return the one shared mapped record set for inventory delivery.

    Max-ID allocation, duplicate census, torn-write recovery, and receipt
    validation all consume this exact tuple.  A record is an actual CommonMark
    H2-H4 heading with the legacy ``INV-<digits>`` content grammar; its source
    block ends at the next mapped heading of equal or higher level.
    """

    source = str(text or "")
    headings = mapped_headings(source)
    records: list[dict] = []
    for heading_index, heading in enumerate(headings):
        if int(heading["level"]) not in {2, 3, 4}:
            continue
        match = _INVENTORY_FINDING_CONTENT_RE.fullmatch(
            str(heading["content"]).strip()
        )
        if match is None:
            continue
        inventory_id = match.group("id").strip().upper()
        start = int(heading["start"])
        end = len(source)
        for later in headings[heading_index + 1 :]:
            if int(later["level"]) <= int(heading["level"]):
                end = int(later["start"])
                break
        block = source[start:end].strip()
        records.append({
            "id": inventory_id,
            "title": match.group("title").strip(),
            "block": block,
            "block_sha256": _sha256_text(block),
            "source_ids": _exploration_field(block, "Source IDs"),
        })
    return tuple(records)


def _inventory_finding_blocks(text: str) -> dict[str, dict]:
    """Return only inventory identities with exactly one defining block."""

    records = _inventory_finding_block_records(text)
    counts: dict[str, int] = {}
    for record in records:
        inventory_id = str(record["id"])
        counts[inventory_id] = counts.get(inventory_id, 0) + 1
    return {
        str(record["id"]): record
        for record in records
        if counts.get(str(record["id"])) == 1
    }


def _contains_exact_source_id(source_ids: str, action_id: str) -> bool:
    return bool(re.search(
        rf"(?<![A-Za-z0-9_-]){re.escape(action_id)}(?![A-Za-z0-9_-])",
        source_ids or "",
        re.IGNORECASE,
    ))


def _promotion_receipt_digest(payload: dict) -> str:
    unsigned = {
        key: value for key, value in payload.items()
        if key != "receipt_sha256"
    }
    encoded = json.dumps(
        unsigned,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _write_json_atomic(path: Path, payload: dict) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(tmp, path)


def _render_enumgap_inventory_block(finding: dict, inventory_id: str) -> str:
    """Render the one deterministic inventory projection for an NEXP action."""

    fields = finding.get("fields") or {}
    severity = str(fields.get("Severity") or "")
    location = str(fields.get("Location") or "")
    description = str(fields.get("Description") or "")
    impact = (
        _exploration_field(str(finding.get("block") or ""), "Impact")
        or "Verifier to confirm the concrete harm."
    )
    root_cause = _exploration_field(
        str(finding.get("block") or ""), "Root Cause"
    )
    preferred_tag = (
        _exploration_field(str(finding.get("block") or ""), "Preferred Tag")
        or "[CODE-TRACE]"
    )
    lines = [
        f"### Finding [{inventory_id}]: {finding['title']}",
        f"**Severity**: {severity.split()[0] if severity else 'Low'}",
        f"**Location**: {location}",
        f"**Preferred Tag**: {preferred_tag}",
        f"**Source IDs**: {finding['id']} (enumeration-obligation exploration; "
        "depth-traced from a mechanically-flagged obligation — verifier to "
        "confirm or refute)",
        "**Verdict**: NEEDS_VERIFICATION",
    ]
    if root_cause:
        lines.append(f"**Root Cause**: {root_cause}")
    lines.extend([
        f"**Description**: {description}",
        f"**Impact**: {impact}",
    ])
    return "\n".join(lines).strip()


def _promotion_delivery_entry(
    finding: dict,
    inventory_id: str,
    inventory_blocks: dict[str, dict],
) -> dict | None:
    inventory_id = str(inventory_id or "").upper()
    block = inventory_blocks.get(inventory_id)
    if (
        block is None
        or not _contains_exact_source_id(
            str(block.get("source_ids") or ""), str(finding.get("id") or "")
        )
        or str(block.get("block") or "").strip()
        != _render_enumgap_inventory_block(finding, inventory_id)
    ):
        return None
    return {
        "source_action_id": str(finding["id"]),
        "inventory_id": inventory_id,
        "source_block_sha256": str(finding["block_sha256"]),
        "inventory_block_sha256": str(block["block_sha256"]),
    }


def _recover_existing_enumgap_deliveries(
    parsed: list[dict],
    inventory_text: str,
) -> tuple[dict[str, dict], set[str]]:
    """Re-derive unique exact deliveries after a torn receipt write.

    Inventory presence alone never grants delivery authority.  Recovery
    succeeds only when exactly one uniquely-defined inventory block claims an
    action and that block byte-matches this promoter's deterministic
    projection.  Any claim, duplicate identity, or competing provenance that
    cannot meet that condition blocks a second append and remains debt.
    """

    records = _inventory_finding_block_records(inventory_text)
    inventory_id_counts: dict[str, int] = {}
    for record in records:
        inventory_id = str(record["id"])
        inventory_id_counts[inventory_id] = (
            inventory_id_counts.get(inventory_id, 0) + 1
        )

    recovered: dict[str, dict] = {}
    claimed_actions: set[str] = set()
    for finding in parsed:
        action_id = str(finding["id"])
        claims = [
            record
            for record in records
            if _contains_exact_source_id(
                str(record.get("source_ids") or ""), action_id
            )
        ]
        if claims:
            claimed_actions.add(action_id)
        if len(claims) != 1:
            continue
        record = claims[0]
        inventory_id = str(record["id"])
        if inventory_id_counts.get(inventory_id) != 1:
            continue
        entry = _promotion_delivery_entry(
            finding,
            inventory_id,
            {inventory_id: record},
        )
        if entry is not None:
            recovered[action_id] = entry
    return recovered, claimed_actions


def _enumgap_promotion_receipt_payload(
    source_text: str,
    deliveries: list[dict],
) -> dict:
    payload = {
        "schema_version": _ENUMGAP_PROMOTION_RECEIPT_SCHEMA,
        "source_artifact": "enumgap_exploration_findings.md",
        "source_sha256": _sha256_text(source_text),
        "delivery_count": len(deliveries),
        "deliveries": deliveries,
    }
    payload["receipt_sha256"] = _promotion_receipt_digest(payload)
    return payload


def validated_enumgap_promotion_deliveries(scratchpad: Path) -> dict[str, dict]:
    """Return exact NEXP -> inventory deliveries from current bound artifacts.

    A receipt is authority only when its own digest, current source digest,
    shared-parser source block identity, and current inventory block/provenance
    all agree.  Missing authority is normal and returns an empty mapping;
    malformed or stale authority raises so callers cannot mistake debt for a
    clean zero.
    """

    root = Path(scratchpad)
    receipt_path = root / _ENUMGAP_PROMOTION_RECEIPT_NAME
    if not receipt_path.is_file():
        return {}
    commit_path = root / _ENUMGAP_APPEND_COMMIT_NAME
    if not commit_path.is_file():
        raise ValueError(
            "enumgap promotion receipt lacks inventory append commit authority"
        )
    try:
        payload = json.loads(receipt_path.read_text(encoding="utf-8"))
        commit = json.loads(commit_path.read_text(encoding="utf-8"))
        source_text = (
            root / "enumgap_exploration_findings.md"
        ).read_bytes().decode("utf-8", errors="strict")
        inventory_text = (
            root / "findings_inventory.md"
        ).read_bytes().decode("utf-8", errors="strict")
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load enumgap promotion authority: {exc}") from exc
    if (
        not isinstance(commit, dict)
        or commit.get("schema_version")
        != "plamen.enumgap_inventory_append_commit.v1"
        or commit.get("source_sha256")
        != hashlib.sha256(
            (root / "enumgap_exploration_findings.md").read_bytes()
        ).hexdigest()
        or commit.get("inventory_sha256")
        != hashlib.sha256(
            (root / "findings_inventory.md").read_bytes()
        ).hexdigest()
        or commit.get("promotion_receipt_sha256")
        != hashlib.sha256(receipt_path.read_bytes()).hexdigest()
    ):
        raise ValueError("enumgap inventory append commit binding mismatch")
    if not isinstance(payload, dict) or set(payload) != {
        "schema_version",
        "source_artifact",
        "source_sha256",
        "delivery_count",
        "deliveries",
        "receipt_sha256",
    }:
        raise ValueError("enumgap promotion receipt shape mismatch")
    if (
        payload.get("schema_version") != _ENUMGAP_PROMOTION_RECEIPT_SCHEMA
        or payload.get("source_artifact") != "enumgap_exploration_findings.md"
        or payload.get("source_sha256") != _sha256_text(source_text)
        or payload.get("receipt_sha256") != _promotion_receipt_digest(payload)
    ):
        raise ValueError("enumgap promotion receipt binding mismatch")
    deliveries = payload.get("deliveries")
    if (
        not isinstance(deliveries, list)
        or type(payload.get("delivery_count")) is not int
        or payload.get("delivery_count") < 0
        or payload.get("delivery_count") != len(deliveries)
    ):
        raise ValueError("enumgap promotion delivery denominator mismatch")
    findings = {
        finding["id"]: finding
        for finding in parse_enumgap_exploration_findings(source_text)
    }
    recoverable_deliveries, _ = _recover_existing_enumgap_deliveries(
        list(findings.values()), inventory_text
    )
    resolved: dict[str, dict] = {}
    inventory_ids: set[str] = set()
    for row in deliveries:
        if not isinstance(row, dict) or set(row) != {
            "source_action_id",
            "inventory_id",
            "source_block_sha256",
            "inventory_block_sha256",
        }:
            raise ValueError("enumgap promotion delivery row shape mismatch")
        action_id = str(row.get("source_action_id") or "").upper()
        inventory_id = str(row.get("inventory_id") or "").upper()
        expected = recoverable_deliveries.get(action_id)
        if expected is None or row != expected:
            raise ValueError(
                f"enumgap promotion delivery identity mismatch for {action_id}"
            )
        if action_id in resolved or inventory_id in inventory_ids:
            raise ValueError("duplicate enumgap promotion delivery identity")
        resolved[action_id] = dict(row)
        inventory_ids.add(inventory_id)
    return resolved


def _write_enumgap_promotion_receipts(
    scratchpad: Path,
    source_text: str,
    parsed: list[dict],
    deliveries: dict[str, dict],
) -> bool:
    ordered = [
        deliveries[finding["id"]]
        for finding in parsed
        if finding["id"] in deliveries
    ]
    try:
        markdown = ["# Enumeration-Obligation Exploration Promotion Receipt", ""]
        markdown.extend(
            f"{row['source_action_id']} -> {row['inventory_id']}"
            for row in ordered
        )
        (scratchpad / "enumgap_exploration_promotion_receipt.md").write_text(
            "\n".join(markdown) + "\n",
            encoding="utf-8",
        )
        _write_json_atomic(
            scratchpad / _ENUMGAP_PROMOTION_RECEIPT_NAME,
            _enumgap_promotion_receipt_payload(source_text, ordered),
        )
        return True
    except (OSError, UnicodeError, TypeError, ValueError):
        return False


def promote_enumgap_exploration_to_inventory(scratchpad: Path) -> dict:
    """Append the depth-exploration agent's findings to findings_inventory.md as
    INV-* entries so they reach chain/verify. The live append is a locked,
    raw-byte CAS transaction; failures return visible debt and never overwrite
    a concurrent inventory writer."""

    root = Path(scratchpad)
    art = root / "enumgap_exploration_findings.md"
    inv = root / "findings_inventory.md"
    if not art.is_file() or not inv.is_file():
        return {"parsed": 0, "emitted": 0}
    try:
        with _inventory_append_lock(root):
            try:
                source_raw = art.read_bytes()
                inventory_before = inv.read_bytes()
                text = source_raw.decode("utf-8", errors="strict")
                inv_text = inventory_before.decode(
                    "utf-8", errors="strict"
                )
            except (OSError, UnicodeError) as exc:
                return {
                    "parsed": 0,
                    "emitted": 0,
                    "debt": [
                        "enumgap promotion raw-byte input is invalid: "
                        f"{type(exc).__name__}: {exc}"
                    ],
                }

            parsed = list(parse_enumgap_exploration_findings(text))
            if not parsed:
                return {"parsed": 0, "emitted": 0}
            lineage_issues = _promotion_phaseio_issues(root)
            if lineage_issues:
                return {
                    "parsed": len(parsed),
                    "emitted": 0,
                    "debt": lineage_issues,
                }
            parsed_by_id = {
                finding["id"]: finding for finding in parsed
            }
            deliveries: dict[str, dict] = {}
            try:
                deliveries = validated_enumgap_promotion_deliveries(root)
            except ValueError:
                deliveries = {}
            recovered, claimed_actions = (
                _recover_existing_enumgap_deliveries(parsed, inv_text)
            )
            for action_id, entry in recovered.items():
                deliveries.setdefault(action_id, entry)
            new = [
                finding
                for finding in parsed
                if finding["id"] not in deliveries
                and finding["id"] not in claimed_actions
            ]

            new_inventory_ids: dict[str, str] = {}
            inventory_after = inventory_before
            plan_path = root / _ENUMGAP_APPEND_PLAN_NAME
            if new:
                structural_ids = [
                    int(str(row["id"]).split("-", 1)[1])
                    for row in _inventory_finding_block_records(inv_text)
                ]
                max_inv = max(structural_ids, default=0)
                appended: list[str] = []
                for ordinal, finding in enumerate(new, 1):
                    inventory_id = f"INV-{max_inv + ordinal:03d}"
                    appended.extend(
                        _render_enumgap_inventory_block(
                            finding, inventory_id
                        ).splitlines()
                    )
                    appended.append("")
                    new_inventory_ids[finding["id"]] = inventory_id
                header = (
                    "\n\n## Enumeration-Obligation Exploration Findings\n\n"
                    "Depth-traced findings produced by the Phase 4b.7 "
                    "exploration of mechanically-flagged enumeration "
                    "obligations. Each was investigated "
                    "(boundary/variation/trace) before reaching verification. "
                    "Recall-safe: append-only.\n\n"
                )
                hdr = (
                    ""
                    if "Enumeration-Obligation Exploration Findings"
                    in inv_text
                    else header
                )
                delivered = _append_inventory_blocks(
                    inv_text, hdr, appended
                )
                inventory_after = delivered.encode("utf-8")
                if not inventory_after.startswith(inventory_before):
                    return {
                        "parsed": len(parsed),
                        "emitted": 0,
                        "debt": [
                            "enumgap inventory append-prefix proof failed"
                        ],
                    }
                ledger_owner: dict[str, str] = {}
                try:
                    ledger = json.loads(
                        (root / "_artifact_state.json").read_text(
                            encoding="utf-8"
                        )
                    )
                    binding = (
                        ledger.get("artifact_bindings", {}).get(
                            "scratchpad:findings_inventory.md"
                        )
                    )
                    if isinstance(binding, dict):
                        ledger_owner = {
                            "owner_key": str(
                                binding.get("owner_key") or ""
                            ),
                            "contract_digest": str(
                                binding.get("contract_digest") or ""
                            ),
                        }
                except (OSError, UnicodeError, json.JSONDecodeError):
                    ledger_owner = {}
                plan = {
                    "schema_version": (
                        "plamen.enumgap_inventory_append_plan.v1"
                    ),
                    "source_sha256": hashlib.sha256(
                        source_raw
                    ).hexdigest(),
                    "inventory_before_sha256": hashlib.sha256(
                        inventory_before
                    ).hexdigest(),
                    "inventory_before_size": len(inventory_before),
                    "inventory_after_sha256": hashlib.sha256(
                        inventory_after
                    ).hexdigest(),
                    "inventory_after_size": len(inventory_after),
                    "inventory_owner": ledger_owner,
                    "planned_deliveries": dict(
                        sorted(new_inventory_ids.items())
                    ),
                }
                plan["plan_sha256"] = hashlib.sha256(
                    json.dumps(
                        plan,
                        ensure_ascii=True,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8")
                ).hexdigest()
                _write_json_atomic(plan_path, plan)
                try:
                    live_before = inv.read_bytes()
                except OSError as exc:
                    return {
                        "parsed": len(parsed),
                        "emitted": 0,
                        "debt": [
                            f"enumgap inventory CAS read failed: {exc}"
                        ],
                    }
                if live_before != inventory_before:
                    return {
                        "parsed": len(parsed),
                        "emitted": 0,
                        "debt": [
                            "enumgap inventory changed after append prebind"
                        ],
                    }
                try:
                    _atomic_inventory_replace(inv, inventory_after)
                except OSError as exc:
                    return {
                        "parsed": len(parsed),
                        "emitted": 0,
                        "debt": [
                            f"enumgap inventory atomic append failed: {exc}"
                        ],
                    }
                try:
                    if inv.read_bytes() != inventory_after:
                        raise OSError(
                            "post-replace inventory digest mismatch"
                        )
                except OSError as exc:
                    return {
                        "parsed": len(parsed),
                        "emitted": 0,
                        "debt": [
                            f"enumgap inventory append commit failed: {exc}"
                        ],
                    }
                inv_text = inventory_after.decode("utf-8")

            inventory_blocks = _inventory_finding_blocks(inv_text)
            for action_id, inventory_id in new_inventory_ids.items():
                entry = _promotion_delivery_entry(
                    parsed_by_id[action_id],
                    inventory_id,
                    inventory_blocks,
                )
                if entry is not None:
                    deliveries[action_id] = entry
            receipts_written = _write_enumgap_promotion_receipts(
                root, text, parsed, deliveries
            )
            emitted = len(new_inventory_ids)
            if not receipts_written:
                return {
                    "parsed": len(parsed),
                    "emitted": emitted,
                    "debt": [
                        "enumgap inventory append committed but delivery "
                        "receipt publication failed"
                    ],
                }
            commit = {
                "schema_version": (
                    "plamen.enumgap_inventory_append_commit.v1"
                ),
                "source_sha256": hashlib.sha256(
                    source_raw
                ).hexdigest(),
                "inventory_sha256": hashlib.sha256(
                    inv.read_bytes()
                ).hexdigest(),
                "promotion_receipt_sha256": hashlib.sha256(
                    (
                        root / _ENUMGAP_PROMOTION_RECEIPT_NAME
                    ).read_bytes()
                ).hexdigest(),
                "plan_sha256": "",
            }
            if plan_path.is_file():
                try:
                    plan_payload = json.loads(
                        plan_path.read_text(encoding="utf-8")
                    )
                    commit["plan_sha256"] = str(
                        plan_payload.get("plan_sha256") or ""
                    )
                except (OSError, UnicodeError, json.JSONDecodeError):
                    pass
            _write_json_atomic(
                root / _ENUMGAP_APPEND_COMMIT_NAME, commit
            )
            try:
                from plamen_mechanical import (
                    _write_finding_records_from_inventory,
                )

                _write_finding_records_from_inventory(root)
            except Exception as exc:
                return {
                    "parsed": len(parsed),
                    "emitted": emitted,
                    "debt": [
                        "enumgap inventory append committed but finding-record "
                        f"refresh failed: {type(exc).__name__}: {exc}"
                    ],
                }
            return {"parsed": len(parsed), "emitted": emitted}
    except OSError as exc:
        return {
            "parsed": 0,
            "emitted": 0,
            "debt": [f"enumgap inventory transaction lock failed: {exc}"],
        }


def run_enumeration_gate(scratchpad: Path) -> dict:
    """Driver entry: the co-reference gate (G1+G2) then the additional mechanical
    obligation-derivers. Best-effort, never raises, never halts.

    Budget: each deriver gets its OWN `_MAX_PER_DERIVER` slots, INDEPENDENT of the
    co-reference gate's `_MAX_ENUMGAP_PER_RUN` pool. (Sharing one pool let the
    co-ref gate, which routinely hits its 40-cap, starve every new deriver to
    zero — the exact bug that silenced L-04/L-08/L-10 in a real run.) Each pool
    is bounded and the verify-the-positives filter prunes the candidates, so the
    bounded sum (co-ref 40 + 4×15 = 100) is recall-safe. The separately
    invoked two Gate-V pools add 30, making the accepted-depth maximum 130
    before axis work."""
    scratchpad = Path(scratchpad)
    errors: list[str] = []
    try:
        n_obl = compute_enumeration_obligations(scratchpad)
    except Exception as exc:
        n_obl = 0
        errors.append(f"obligations: {type(exc).__name__}: {exc}")
    try:
        res = validate_enumeration_coverage(scratchpad)
    except Exception as exc:
        res = {"gaps": 0, "emitted": 0}
        errors.append(f"coverage: {type(exc).__name__}: {exc}")
    emitted = int(res.get("emitted", 0))
    # Each deriver gets its own dedicated budget — never the co-ref gate's leftover.
    for fn, producer in (
        (compute_critical_asset_mover_candidates,
         "enumeration.deriver.critical_asset_mover.emission"),
        (compute_array_uniqueness_candidates,
         "enumeration.deriver.array_uniqueness.emission"),
        (compute_unbounded_input_candidates,
         "enumeration.deriver.unbounded_input.emission"),
    ):
        try:
            cands = fn(scratchpad)
            emitted += _emit_candidates(
                scratchpad, cands, _MAX_PER_DERIVER, producer=producer
            )
        except Exception as exc:
            errors.append(f"{producer}: {type(exc).__name__}: {exc}")
            continue
    # M1 committed-invariant deriver: its OWN `_MAX_PER_DERIVER` (15) pool,
    # INDEPENDENT of the co-ref `_MAX_ENUMGAP_PER_RUN` (40) pool and of the three
    # derivers above (each gets its own cap in its own `_emit_candidates` call).
    # Stamps `Source IDs: INVARIANT` so candidates stay distinct for dedup/
    # coverage while still flowing the standard ENUMGAP inventory->verify path.
    ci_emitted = 0
    try:
        ci_emitted = recover_invariant_assertion_candidates(scratchpad)
        emitted += ci_emitted
    except Exception as exc:
        ci_emitted = 0
        errors.append(f"invariant recovery: {type(exc).__name__}: {exc}")
    # Base return contract (obligations/gaps/emitted) is unchanged for backward
    # compat; the M1 count is folded into `emitted` AND surfaced as an additive
    # `invariant_emitted` key only when nonzero, so a clean no-graph/no-CI run
    # still returns the exact 3-key dict prior callers assert on.
    result = {"obligations": n_obl, "gaps": res.get("gaps", 0), "emitted": emitted}
    if ci_emitted:
        result["invariant_emitted"] = ci_emitted
    if errors:
        result["status"] = "FAILED"
        result["error"] = "; ".join(errors)[:2000]
    return result
