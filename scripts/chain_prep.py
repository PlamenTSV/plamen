"""Phase 4c chain prep — mechanical producers that BOUND the chain agents' work.

The chain phase hung 50 min on a live audit because Chain Agent 1's PHASE 1
grouping and Chain Agent 2's PHASE 2 matching are *unbounded* tasks — the
prompts say "exhaustively enumerate" with no finite candidate set. The chain
prompts ALREADY reference `chain_candidate_pairs.md` and `variable_finding_map.md`
("if present, evaluate ONLY these pairs") but no code ever produced them, so the
agents always ran the unbounded fallback.

This module builds the missing producers. Each is a pure mechanical pre-pass
(no LLM) that turns an open-ended "find everything" task into a finite,
completable candidate set:

  compute_chain_candidate_pairs  -> chain_candidate_pairs.md (+ _full.md)
      Bounds Agent 2 PHASE 2: pairs of findings sharing a state variable or a
      discriminative code identifier. The agent evaluates ONLY these.
  compute_variable_finding_map   -> variable_finding_map.md
      Supports Agent 2 variable-level matching: state var -> findings touching it.
  compute_enabler_baseline       -> enabler_results.md (STEP 0a pre-filled)
      Bounds Agent 1 PHASE 0: pre-extracts the dangerous-state candidate list
      from CONFIRMED/PARTIAL findings so the agent does not re-scan the inventory.

Design rules (match the plan's constraints):
  - Best-effort. Every public function catches its own exceptions and returns
    a summary dict. NEVER raises — a producer failure must degrade to the
    chain prompt's existing fallback path, not halt the pipeline.
  - Coverage-safe. The bounded `chain_candidate_pairs.md` is the top-N
    highest-signal pairs; a second bounded packet receives the highest-signal
    eligible tail, and every remaining real-signal pair is written to a
    durable coverage-gap ledger. Nothing is silently called covered.
  - Additive. No existing artifact is renamed or removed. `enabler_results.md`
    is overwritten, but only AFTER `_write_chain_passthrough_outputs` has
    written its stub safety-net, and the format stays compatible.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Optional

from chain_tail_authority import (
    MANIFEST_SCHEMA as _CHAIN_TAIL_MANIFEST_SCHEMA,
    initialize_chain_tail as _initialize_chain_tail,
    initialize_failed_chain_tail as _initialize_failed_chain_tail,
    reconcile_chain_tail_output as _reconcile_chain_tail_output,
)
from state_symbol_authority import (
    resolve_chain_state as _resolve_chain_state,
    update_signal_family_pair_counts as _update_state_pair_counts,
)


# The bounded file the chain agent evaluates directly. The full set goes to
# `chain_candidate_pairs_full.md`. The bound is split to guarantee STATE pairs
# (shared mutable state — the classic chain signal) get half the budget rather
# than being crowded out by multi-identifier TYPE pairs. 70 total is generous
# vs the chain prompt's own 50-pair fallback cap and completable inside Agent
# 2's 40-min budget; the tail is preserved in the full file + chain_iter2.
_BOUNDED_PAIR_CAP = 70
_BOUNDED_PER_TABLE = 35
_ITER2_TAIL_CAP = 15

_SEVERITY_RANK = {
    "critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0, "info": 0,
}

# Identifier tokens too common to be discriminative — appear in most findings
# of any Solidity audit, so a shared occurrence carries no pairing signal.
_STOPWORD_IDENTIFIERS = frozenset({
    "function", "functions", "address", "addresses", "contract", "contracts",
    "transfer", "transfers", "amount", "amounts", "balance", "balances",
    "require", "return", "returns", "external", "internal", "public", "private",
    "msgsender", "msgvalue", "uint256", "bytes32", "memory", "storage",
    "should", "would", "could", "value", "values", "result", "results",
    "caller", "callers", "called", "revert", "reverts", "reverted",
})

_DISCOVERY_FIELDS = (
    "discovery_steer",
    "missing_precondition",
    "precondition_type",
    "postconditions_created",
    "postcondition_types",
    "semantic_invariant",
    "branch_preconditions",
    "terminal_mechanism",
    "composition_candidates",
)

_DISCOVERY_GENERIC_TERMS = _STOPWORD_IDENTIFIERS | frozenset({
    "access", "accounting", "arithmetic", "authorization", "balance",
    "blocked", "branch", "branches", "callback", "candidate", "candidates",
    "category", "condition", "conditions", "configuration", "created",
    "creates", "effect", "effects", "enabled", "enables", "external",
    "flow", "flows", "guard", "guards", "impact", "invariant", "issue",
    "lifecycle", "match", "mechanism", "missing", "mode", "path", "paths",
    "permission", "precondition", "preconditions", "postcondition",
    "postconditions", "precision", "reachability", "rounding", "semantic",
    "state", "status", "terminal", "timing", "token", "tokens", "type",
    "types", "unit", "units", "value", "values", "write", "writes",
    "read", "reads",
})


# ---------------------------------------------------------------------------
# CROSS-DOMAIN-DEP → STEP-0a-LC enabler harvester
# ---------------------------------------------------------------------------
# A `[CROSS-DOMAIN-DEP: {domain}]` tag is a depth agent's ADMISSION that an
# assumption lives OUTSIDE its own domain — a potential compound-exploit path
# invisible to single-domain analysis. Rather than silently closing that
# provenance gap, we convert each SUBSTANTIVE tag into a low-confidence
# STEP-0a-LC enabler that verify must adjudicate. Generic, additive, recall-safe.

# Any tag, captured so we can split domain vs. detail.
_CROSS_DOMAIN_TAG_RE = re.compile(
    r"\[\s*CROSS-DOMAIN-DEP\s*:\s*(?P<body>[^\]]*?)\s*\]", re.IGNORECASE
)
# A tag is SUBSTANTIVE iff, after the domain label, there is elaboration prose
# introduced by an em-dash / en-dash / spaced hyphen / colon. A bare
# `[CROSS-DOMAIN-DEP: external]` (domain word only) carries no described
# dependency → skipped. A `none` domain is an explicit admission there is NO
# cross-domain dependency → also skipped.
_CROSS_DOMAIN_ELAB_RE = re.compile(r"(?:—|–|:|\s-\s)")
# Cap on emitted CROSS-DOMAIN-DEP enablers (mirrors _MAX_ENUMGAP_PER_RUN=40).
_MAX_CROSS_DOMAIN_ENABLERS = 40
# Raw finding artifacts the tags live in. Depth/exploration/analysis/niche/axis
# outputs — NOT prompt/stdio/log scaffolding. Bounded, best-effort globs.
_CROSS_DOMAIN_SOURCE_GLOBS = (
    "depth_*_findings.md",
    "enumgap_*_findings.md",
    "enumgap_exploration_findings.md",
    "_exploration_shard_*.md",
    "axis_coverage_findings.md",
    "niche_*_findings.md",
    "blind_spot_*_findings.md",
    "validation_sweep_findings.md",
    "sibling_propagation_findings.md",
    "design_stress_findings.md",
    "analysis_*.md",
)
# Anchors used to attribute a tag to a nearby finding id / location.
_FINDING_ID_ANCHOR_RE = re.compile(r"^#{2,4}\s*(?:Finding\s*)?\[?([A-Za-z][A-Za-z0-9]*-\d+)\]?", re.MULTILINE)
_LOCATION_ANCHOR_RE = re.compile(r"^\s*\*{0,2}Location\*{0,2}\s*:\s*(.+?)\s*$", re.IGNORECASE | re.MULTILINE)


# ---------------------------------------------------------------------------
# Shared parsing
# ---------------------------------------------------------------------------


def _load_inventory(scratchpad: Path) -> list[dict]:
    """Parse findings_inventory.md into entry dicts. [] on any failure."""
    inv = scratchpad / "findings_inventory.md"
    if not inv.exists():
        return []
    try:
        import importlib
        import sys
        sys.path.insert(0, str(Path(__file__).parent))
        parsers = importlib.import_module("plamen_parsers")
        return parsers._parse_inventory_chunk(inv) or []
    except Exception:
        return []


def _parse_state_write_map(scratchpad: Path) -> dict[str, set[str]]:
    """Parse state_write_map.md → {state_variable_name: {contract, ...}}.

    The file groups rows under `## Contract.sol` headers with a table
    `| State Variable | Writer Function | Write Site | Access Guard |`.
    Returns a map of bare variable name → set of contracts that declare it.
    Empty dict on any failure.
    """
    path = scratchpad / "state_write_map.md"
    if not path.exists():
        return {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return {}
    out: dict[str, set[str]] = {}
    current_contract = ""
    for line in text.splitlines():
        m = re.match(r"^##\s+(\S+?)(?:\.sol|\.rs|\.move|\.go)?\s*$", line)
        if m:
            current_contract = m.group(1)
            continue
        if not line.startswith("|"):
            continue
        cells = [c.strip().strip("`") for c in line.split("|")[1:-1]]
        if not cells:
            continue
        var = cells[0]
        # skip header / separator rows
        if not var or var.lower() in ("state variable", "variable") or set(var) <= {"-", ":"}:
            continue
        # Strip mapping/index decoration: `pendingClaims[externalId]` → `pendingClaims`
        bare = re.sub(r"[\[\(].*$", "", var).strip()
        bare = re.sub(r"\s*\(.*$", "", bare).strip()
        if bare:
            out.setdefault(bare, set()).add(current_contract)
    return out


def _parse_state_variable_inventory(scratchpad: Path) -> dict[str, set[str]]:
    """Parse the always-produced recon state inventory as a degraded fallback.

    Graph bakes can legitimately be unavailable when a repository cannot be
    compiled.  ``state_variables.md`` is then weaker than a write map (the
    regex pre-pass may include local-looking declarations), but it remains a
    finite, mechanically enumerated candidate set.  It only proposes chain
    relationships for later model/verification judgment.
    """
    path = scratchpad / "state_variables.md"
    if not path.exists():
        return {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return {}
    out: dict[str, set[str]] = {}
    in_canonical_table = False
    saw_table_row = False
    for line in text.splitlines():
        lowered = line.casefold()
        if line.startswith("|") and "| file |" in lowered and "| variable |" in lowered:
            in_canonical_table = True
            continue
        if in_canonical_table and saw_table_row and not line.startswith("|"):
            break
        if not in_canonical_table:
            continue
        if not line.startswith("|"):
            continue
        saw_table_row = True
        cells = [cell.strip().strip("`") for cell in line.split("|")[1:-1]]
        if len(cells) < 2:
            continue
        locus, var = cells[0], cells[1]
        variable_type = cells[2] if len(cells) >= 3 else ""
        if (
            not var
            or var.casefold() in {"variable", "state variable"}
            or set(var) <= {"-", ":"}
        ):
            continue
        bare = re.sub(r"[\[\(].*$", "", var).strip()
        if bare and _is_discriminative_fallback_state(bare, variable_type):
            out.setdefault(bare, set()).add(locus or "unknown")
    return out


_FALLBACK_STATE_GENERIC_NAMES = frozenset({
    "admin", "amount", "asset", "assets", "data", "factory", "from",
    "manager", "owner", "receiver", "router", "sender", "share", "shares",
    "state", "to", "token", "value", "values",
})
_FALLBACK_STATE_CONTAINER_RE = re.compile(
    r"\b(?:mapping|table|map|vector|vec|dictionary|dict|set|array|list)\b",
    re.IGNORECASE,
)


def _is_discriminative_fallback_state(variable: str, variable_type: str) -> bool:
    """Reject local-looking/generic regex hits from the degraded inventory.

    The canonical state inventory is regex-derived and can contain local
    declarations.  Structured names, constants, and container-typed entries
    retain useful state identity across supported ecosystems; generic scalar
    names would otherwise create near-complete pair graphs and crowd the
    bounded chain packet.
    """
    # Scalar names such as `fee`, `rate`, `owner`, and `balance` are often the
    # exact state seam that composes two findings. Do not delete them at the
    # recall generator. Fallback-only state evidence is scored below graph
    # evidence and bounded downstream, which is the correct place to control
    # noise/cost.
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", variable or ""))


def _load_state_candidates(scratchpad: Path) -> tuple[dict[str, set[str]], str]:
    """Union graph-backed writes with recon's lower-confidence inventory."""
    writes = _parse_state_write_map(scratchpad)
    inventory = _parse_state_variable_inventory(scratchpad)
    if writes and inventory:
        state_vars = {name: set(loci) for name, loci in writes.items()}
        for name, loci in inventory.items():
            state_vars.setdefault(name, set()).update(loci)
        return state_vars, "state_write_map.md+state_variables.md"
    if writes:
        return writes, "state_write_map.md"
    if inventory:
        return inventory, "state_variables.md"
    return {}, "none"


def _resolve_typed_state_application(
    scratchpad: Path,
    entries: list[dict],
    *,
    preserve_signal_counts: bool = True,
) -> tuple[
    dict,
    dict[str, dict],
    dict[str, set[str]],
    dict[str, set[str]],
    dict[str, set[str]],
]:
    """Return receipt/symbols and exact per-finding state identities.

    Graph-cited edges are kept separate from every lower-confidence route so
    prose volume cannot displace mechanically bound state relationships.
    """
    receipt = _resolve_chain_state(
        scratchpad,
        entries,
        preserve_signal_counts=preserve_signal_counts,
    )
    symbols = {
        str(row.get("symbol_id") or ""): row
        for row in (receipt.get("symbols") or [])
        if isinstance(row, dict) and str(row.get("symbol_id") or "")
    }
    all_edges: dict[str, set[str]] = {}
    graph_edges: dict[str, set[str]] = {}
    compatibility_map_edges: dict[str, set[str]] = {}
    for edge in receipt.get("resolution_edges") or []:
        if not isinstance(edge, dict):
            continue
        fid = str(edge.get("finding_id") or "")
        sid = str(edge.get("symbol_id") or "")
        if not fid or sid not in symbols:
            continue
        all_edges.setdefault(fid, set()).add(sid)
        if str(edge.get("basis") or "") == "GRAPH_CITED_LOCATION":
            graph_edges.setdefault(fid, set()).add(sid)
        elif str(symbols[sid].get("provider_source") or "") == "state_write_map.md":
            compatibility_map_edges.setdefault(fid, set()).add(sid)
    return receipt, symbols, all_edges, graph_edges, compatibility_map_edges


_IDENT_RE = re.compile(r"\b([a-z][A-Za-z0-9]{3,}|_[a-zA-Z0-9_]{3,})\b")


def _extract_identifiers(text: str) -> set[str]:
    """Extract candidate code identifiers (camelCase / _prefixed) from text.

    Drops common non-discriminative stopwords. Used to pair findings that
    discuss the same function / variable even when locations differ.
    """
    out: set[str] = set()
    for m in _IDENT_RE.finditer(text or ""):
        tok = m.group(1)
        norm = tok.lstrip("_").lower()
        if norm in _STOPWORD_IDENTIFIERS:
            continue
        # require some camelCase or underscore structure — discriminative
        if "_" in tok or re.search(r"[a-z][A-Z]", tok):
            out.add(tok)
    return out


def _entry_text(entry: dict, field: str) -> str:
    """Return a bounded string value from an inventory entry field."""
    try:
        val = entry.get(field, "")
    except Exception:
        return ""
    if val is None:
        return ""
    if isinstance(val, (list, tuple, set)):
        val = " ".join(str(x) for x in val)
    else:
        val = str(val)
    return re.sub(r"\s+", " ", val).strip()[:500]


def _discovery_text(entry: dict) -> str:
    return " ".join(_entry_text(entry, f) for f in _DISCOVERY_FIELDS).strip()


_MUTUAL_ZERO_ANCHOR_ROLE_RE = re.compile(
    r"\b(?:auth(?:entication|orization)?\s+)?(?:anchor|authority)|"
    r"\btrust\s+(?:root|anchor|material)|"
    r"\b(?:verifying|signer|guardian|committee|admin)\s+(?:key|set|root)|"
    r"\bauth_anchor_role\b",
    re.IGNORECASE,
)
_MUTUAL_ZERO_UNARMED_RE = re.compile(
    r"\b(?:default(?:s|ed)?(?:\s+(?:to|at|is|as))?\s+(?:zero|empty|null)|"
    r"zero\s+(?:element|value|anchor|authority|key|root)|"
    r"unset|uninitialized|uninitialised|unarmed|empty\s+(?:anchor|authority|key|set|root))\b",
    re.IGNORECASE,
)
_MUTUAL_ZERO_OPERATIONAL_RE = re.compile(
    r"\b(?:remain(?:s|ed)?\s+(?:operational|reachable)|"
    r"(?:operation|verification|verifier|call|system|functionality)s?\s+"
    r"(?:can|may|could|will)?\s*(?:still\s+)?(?:run|succeed|operate|proceed|execute)|"
    r"(?:privileged\s+)?operations?\s+remain(?:s)?\s+reachable|"
    r"no\s+(?:arming|initiali[sz]ation)\s+(?:check|gate)|"
    r"without\s+(?:an?\s+)?(?:arming|initiali[sz]ation)\s+(?:check|gate))\b",
    re.IGNORECASE,
)
_MUTUAL_ZERO_ANCHOR_SAFE_RE = re.compile(
    r"\b(?:atomically\s+armed|armed\s+non[- ]?zero|"
    r"non[- ]?zero\s+(?:before|enforced|required)|requires?\s+non[- ]?zero|"
    r"cannot\s+(?:operate|run|succeed|proceed)\s+until\s+armed|"
    r"(?:does\s+not|cannot|never)\s+(?:operate|run|succeed|proceed)\s+"
    r"(?:while|when)\s+(?:zero|unset|unarmed|empty)|"
    r"not\s+operational\s+(?:while|when)\s+(?:zero|unset|unarmed|empty)|"
    r"inert\s+until\s+armed|no\s+unarmed\s+operational\s+state)\b",
    re.IGNORECASE,
)

_MUTUAL_ZERO_INPUT_ROLE_RE = re.compile(
    r"\b(?:proof|signature|witness|input|identity|signer|derivation|derived_identity_role)\b",
    re.IGNORECASE,
)
_MUTUAL_ZERO_DEGENERATE_RE = re.compile(
    r"\b(?:degenerate|empty|zero[- ](?:length|bytes?)|zero(?:ed)?|all[- ]zero|null)\s+"
    r"(?:proof|signature|witness|input|identity|signer|derivation)|"
    r"\b(?:proof|signature|witness|input)\s+(?:is\s+)?(?:degenerate|empty|zero|null)\b",
    re.IGNORECASE,
)
_MUTUAL_ZERO_DERIVATION_RE = re.compile(
    r"\b(?:derive[sd]?|derivation|recover(?:s|ed)?|recovered)\b.{0,45}"
    r"\b(?:zero|null|empty)\b|"
    r"\b(?:zero|null|empty)\s+(?:derived\s+)?(?:identity|signer|derivation)\b",
    re.IGNORECASE,
)
_MUTUAL_ZERO_ACCEPT_RE = re.compile(
    r"\b(?:accept(?:s|ed)?|succeed(?:s|ed)?|authori[sz](?:e|es|ed|ation)|"
    r"passes?|not\s+reject(?:ed|s)?|without\s+reject(?:ion|ing))\b",
    re.IGNORECASE,
)
_MUTUAL_ZERO_FAIL_CLOSED_RE = re.compile(
    r"\b(?:reject(?:s|ed|ing)?\s+(?:the\s+)?(?:zero|null|empty|degenerate)|"
    r"(?:zero|null|empty)\s+(?:identity|signer|derivation|proof|input)\s+is\s+rejected|"
    r"unconditionally\s+reject(?:s|ed)?|fails?\s+closed|"
    r"(?:does\s+not|cannot|never)\s+(?:accept|pass|authori[sz]e)|"
    r"not\s+(?:accepted|authori[sz]ed)|"
    r"cannot\s+authori[sz]e|reverts?\s+(?:on|for|when))\b",
    re.IGNORECASE,
)


def _mutual_zero_roles(entry: dict) -> set[str]:
    """Classify the two independently necessary halves of a mutual-zero seam.

    This is a recall-only nomination predicate, never a vulnerability verdict.
    It deliberately requires positive evidence for reachability/acceptance and
    suppresses explicit armed/fail-closed evidence so ordinary mentions of a
    zero key or empty proof do not produce a quadratic pairing signal.
    """
    text = " ".join(
        _entry_text(entry, field)
        for field in ("title", "root_cause", "description", *_DISCOVERY_FIELDS)
    )
    roles: set[str] = set()
    if (
        _MUTUAL_ZERO_ANCHOR_ROLE_RE.search(text)
        and _MUTUAL_ZERO_UNARMED_RE.search(text)
        and _MUTUAL_ZERO_OPERATIONAL_RE.search(text)
        and not _MUTUAL_ZERO_ANCHOR_SAFE_RE.search(text)
    ):
        roles.add("unarmed-auth-anchor")
    if (
        _MUTUAL_ZERO_INPUT_ROLE_RE.search(text)
        and _MUTUAL_ZERO_DEGENERATE_RE.search(text)
        and _MUTUAL_ZERO_DERIVATION_RE.search(text)
        and _MUTUAL_ZERO_ACCEPT_RE.search(text)
        and not _MUTUAL_ZERO_FAIL_CLOSED_RE.search(text)
    ):
        roles.add("accepted-zero-derivation")
    return roles


def _extract_discovery_terms(text: str) -> set[str]:
    """Concrete terms from optional discovery metadata.

    Mechanism/category words alone are intentionally ignored so fields like
    `Discovery Steer: arithmetic rounding` do not pair unrelated findings.
    """
    terms = {tok.lower() for tok in _extract_identifiers(text)}
    for m in re.finditer(r"`([A-Za-z_][A-Za-z0-9_]{3,})`", text or ""):
        terms.add(m.group(1).lower())
    for m in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]{4,})\b", text or ""):
        tok = m.group(1)
        norm = tok.lower()
        if "_" in tok or re.search(r"[a-z][A-Z]", tok) or re.search(r"\d", tok):
            terms.add(norm)
    return {
        t for t in terms
        if len(t) >= 4 and t not in _DISCOVERY_GENERIC_TERMS
    }


def _extract_finding_refs(text: str) -> set[str]:
    return {
        m.group(0).upper()
        for m in re.finditer(r"\b[A-Z][A-Z0-9]{0,10}-\d+\b", text or "", re.IGNORECASE)
    }


def _entry_aliases(entry: dict, final_id: str) -> set[str]:
    """All finding IDs that may identify this entry across pipeline stages."""
    aliases: set[str] = set()
    for val in (final_id, entry.get("local_id", "")):
        if val:
            aliases |= _extract_finding_refs(str(val))
    for sid in entry.get("source_ids", []) or []:
        aliases |= _extract_finding_refs(str(sid))
    return aliases or {str(final_id).upper()}


_LOC_RE = re.compile(
    r"([A-Za-z0-9_]+\.(?:sol|rs|move|go|vy|daml))\s*:?\s*L?(\d+)\s*(?:-\s*L?(\d+))?"
)
# Two findings co-located within this many lines are treated as a proximity
# pair (likely the same or an adjacent function). Bare same-file with no line
# proximity and no shared identifier is NOT a candidate — in a 3-contract
# codebase that would pair nearly everything with everything.
_PROXIMITY_LINES = 60


def _extract_contracts(location: str) -> set[str]:
    """Pull the set of source-file basenames a finding's Location touches."""
    return {m.group(1) for m in _LOC_RE.finditer(location or "")}


def _extract_locations(location: str) -> dict[str, list[tuple[int, int]]]:
    """Parse a Location field into {file: [(start_line, end_line), ...]}."""
    out: dict[str, list[tuple[int, int]]] = {}
    for m in _LOC_RE.finditer(location or ""):
        f = m.group(1)
        start = int(m.group(2))
        end = int(m.group(3)) if m.group(3) else start
        if end < start:
            start, end = end, start
        out.setdefault(f, []).append((start, end))
    return out


def _line_proximity(a_locs: dict[str, list[tuple[int, int]]],
                    b_locs: dict[str, list[tuple[int, int]]]) -> bool:
    """True if A and B touch the same file within _PROXIMITY_LINES lines."""
    for f, a_ranges in a_locs.items():
        b_ranges = b_locs.get(f)
        if not b_ranges:
            continue
        for (a0, a1) in a_ranges:
            for (b0, b1) in b_ranges:
                # gap between the two line ranges (0 if they overlap)
                gap = max(0, max(a0, b0) - min(a1, b1))
                if gap <= _PROXIMITY_LINES:
                    return True
    return False


def _finding_state_vars(entry: dict, state_vars: dict[str, set[str]]) -> set[str]:
    """State variables a finding touches — var names appearing word-bounded
    in its root cause or description."""
    blob = f"{entry.get('root_cause', '')} {entry.get('description', '')}"
    touched: set[str] = set()
    for var in state_vars:
        if re.search(rf"\b{re.escape(var)}\b", blob):
            touched.add(var)
    return touched


def _entry_id(entry: dict, idx: int) -> str:
    return str(entry.get("local_id") or f"INV-{idx:03d}").strip()


def _chain_pair_key(row: dict) -> str:
    return "::".join(sorted((str(row.get("a", "")), str(row.get("b", "")))))


def _chain_pair_signal(row: dict) -> str:
    parts: list[str] = []
    if row.get("shared_graph_state"):
        parts.append("state-graph: " + ", ".join(row["shared_graph_state"][:3]))
    if row.get("shared_map_state"):
        parts.append(
            "state-compat-map: " + ", ".join(row["shared_map_state"][:3])
        )
    if row.get("shared_fallback_state"):
        parts.append(
            "state-fallback: " + ", ".join(row["shared_fallback_state"][:3])
        )
    if row.get("shared_ident"):
        parts.append("ident: " + ", ".join(row["shared_ident"][:3]))
    if row.get("shared_discovery"):
        parts.append("discovery: " + ", ".join(row["shared_discovery"][:3]))
    if row.get("discovery_ref"):
        parts.append("discovery: explicit finding reference")
    if row.get("mutual_zero_role"):
        parts.append(
            "role: mutual-zero (unarmed authentication anchor + accepted "
            "zero derivation)"
        )
    return "; ".join(parts) if parts else "co-located (same file)"


def _tail_row(row: dict) -> dict:
    return {
        "a": str(row.get("a", "")),
        "b": str(row.get("b", "")),
        "a_sev": str(row.get("a_sev", "")),
        "b_sev": str(row.get("b_sev", "")),
        "signal": _chain_pair_signal(row),
        "score": float(row.get("score", 0.0) or 0.0),
        "graph_backed": bool(row.get("shared_graph_state")),
        "signal_family": "STATE" if row.get("shared_state") else "TYPE",
    }


def _atomic_json(path: Path, payload: dict) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(path)


def _write_chain_tail_gap_ledger(
    scratchpad: Path,
    *,
    packet: list[dict],
    overflow: list[dict],
    consumed: set[str] | None = None,
    after_iter2: bool = False,
) -> None:
    consumed = consumed or set()
    rows: list[tuple[dict, str]] = []
    for row in packet:
        if _chain_pair_key(row) not in consumed:
            rows.append((row, "ITER2_UNRESOLVED" if after_iter2 else "PENDING_ITER2"))
    rows.extend((row, "UNEXAMINED_BOUNDED_LIMIT") for row in overflow)
    lines = [
        "# Chain Composition Coverage Gaps",
        "",
        "**Status**: " + ("GAPS_REMAIN" if rows else "COMPLETE"),
        "",
        "Every row below has a real mechanical composition signal but is not "
        "yet evidenced as semantically evaluated. These are coverage gaps, not "
        "EXCLUDED/no-signal pairs.",
        "",
        "| Finding A | Finding B | Coverage State | Real Signal |",
        "|---|---|---|---|",
    ]
    for row, state in rows:
        signal = str(row.get("signal", "")).replace("|", "/")
        lines.append(f"| {row['a']} | {row['b']} | {state} | {signal} |")
    if not rows:
        lines.append("| (none) | - | COMPLETE | - |")
    (scratchpad / "chain_composition_coverage_gaps.md").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )


def reconcile_chain_iter2_tail(scratchpad: Path) -> dict:
    """Reconcile the bounded tail packet against structured iter2 output.

    This cannot prove the model reasoned correctly, but it prevents a missing
    or partial tail from being called covered: only an exact pair row with a
    terminal disposition and non-empty evidence is marked consumed. Every
    other real-signal pair remains in the durable gap ledger.
    """
    scratchpad = Path(scratchpad)
    payload_path = scratchpad / "chain_candidate_pairs_iter2.json"
    try:
        payload = json.loads(payload_path.read_text(encoding="utf-8"))
        if (
            isinstance(payload, dict)
            and payload.get("schema_version") == _CHAIN_TAIL_MANIFEST_SCHEMA
        ):
            if payload.get("status") == "FAILED_GENERATOR":
                return json.loads(
                    (scratchpad / "chain_tail_coverage_receipt.json").read_text(
                        encoding="utf-8"
                    )
                )
            return _reconcile_chain_tail_output(scratchpad)
        if isinstance(payload, dict) and payload.get("status") == "FAILED":
            raise ValueError(
                str(payload.get("error") or "chain pair generation failed")
            )
        packet = payload.get("packet", []) if isinstance(payload, dict) else []
        overflow = payload.get("overflow", []) if isinstance(payload, dict) else []
        if not isinstance(packet, list) or not isinstance(overflow, list):
            raise ValueError("tail payload rows are not lists")
    except Exception as exc:
        receipt = {
            "schema_version": "plamen.chain_tail_receipt.v1",
            "status": "FAILED",
            "error": f"{type(exc).__name__}: {exc}",
            "consumed_pairs": 0,
            "unresolved_packet_pairs": 0,
        }
        _atomic_json(scratchpad / "chain_tail_coverage_receipt.json", receipt)
        (scratchpad / "chain_composition_coverage_gaps.md").write_text(
            "# Chain Composition Coverage Gaps\n\n"
            "**Status**: UNKNOWN\n\n"
            "The authoritative tail packet could not be parsed, so pair-level "
            "composition coverage is unknown and requires human review.\n\n"
            f"**Error**: {type(exc).__name__}: {exc}\n",
            encoding="utf-8",
        )
        return receipt

    output = scratchpad / "chain_iteration2.md"
    try:
        text = output.read_text(encoding="utf-8", errors="replace")
    except OSError:
        text = ""
    section_match = re.search(
        r"(?is)^##\s+Tail Pair Dispositions\s*$\n(.*?)(?=^##\s+|\Z)",
        text,
        re.MULTILINE,
    )
    section = section_match.group(1) if section_match else ""
    dispositions: dict[str, dict[str, str]] = {}
    for line in section.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        cells = [cell.strip().strip("`*") for cell in stripped.strip("|").split("|")]
        if len(cells) < 4 or cells[0].casefold().startswith("finding"):
            continue
        if all(set(cell) <= {"-", ":", " "} for cell in cells):
            continue
        disposition = re.sub(r"[^A-Z_]", "", cells[2].upper().replace(" ", "_"))
        evidence = cells[3].strip()
        if disposition not in {"EXPLORED", "COMPOSED", "REJECTED"}:
            continue
        if not evidence or evidence in {"-", "—", "n/a", "N/A"}:
            continue
        row = {"a": cells[0].upper(), "b": cells[1].upper()}
        dispositions[_chain_pair_key(row)] = {
            "disposition": disposition,
            "evidence": evidence[:500],
        }

    expected = {_chain_pair_key(row): row for row in packet}
    consumed = set(expected) & set(dispositions)
    unresolved = sorted(set(expected) - consumed)
    receipt = {
        "schema_version": "plamen.chain_tail_receipt.v1",
        "status": "COMPLETE" if not unresolved and not overflow else "DEGRADED_COVERAGE_GAPS",
        "packet_pairs": len(packet),
        "consumed_pairs": len(consumed),
        "unresolved_packet_pairs": len(unresolved),
        "overflow_pairs": len(overflow),
        "pair_dispositions": {
            key: dispositions[key] for key in sorted(consumed)
        },
    }
    _atomic_json(scratchpad / "chain_tail_coverage_receipt.json", receipt)
    _write_chain_tail_gap_ledger(
        scratchpad,
        packet=packet,
        overflow=overflow,
        consumed=consumed,
        after_iter2=True,
    )
    return receipt


def _write_empty_chain_pair_artifacts(scratchpad: Path, reason: str) -> None:
    """Replace every pair/tail artifact with one coherent empty generation.

    A resumed run can shrink below two inventory findings after an upstream
    repair. Materializing the empty generation prevents stale pairs and tail
    work from the prior generation from being scheduled as current evidence.
    """
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S")
    tables = [
        "### STATE Pairs", "",
        "| Finding A | A Severity | Finding B | B Severity | Shared Signal |",
        "|-----------|-----------|-----------|-----------|---------------|",
        "| (none) | - | - | - | - |", "",
        "### TYPE Pairs", "",
        "| Finding A | A Severity | Finding B | B Severity | Shared Signal |",
        "|-----------|-----------|-----------|-----------|---------------|",
        "| (none) | - | - | - | - |", "",
    ]
    for name, status in (
        ("chain_candidate_pairs.md", "MECHANICAL_PREFILTER"),
        ("chain_candidate_pairs_full.md", "MECHANICAL_PREFILTER_FULL"),
    ):
        title_suffix = " â€” Full Set" if name.endswith("_full.md") else ""
        (scratchpad / name).write_text(
            "\n".join([
                f"# Chain Candidate Pairs{title_suffix}", "",
                f"**Status**: {status}", f"**Generated At**: {stamp}",
                "**Total candidate pairs**: 0", f"**Reason**: {reason}", "",
                *tables,
            ]),
            encoding="utf-8",
        )
    (scratchpad / "chain_candidate_pairs_iter2.md").write_text(
        "# Chain Candidate Pairs â€” Iteration 2 Tail Packet\n\n"
        "**Status**: MECHANICAL_TAIL_PACKET\n"
        "**Packet pairs**: 0\n"
        "**Additional real-signal gaps**: 0\n\n"
        f"**Reason**: {reason}\n\n"
        "| Finding A | A Severity | Finding B | B Severity | Real Signal |\n"
        "|---|---|---|---|---|\n"
        "| (none) | - | - | - | - |\n",
        encoding="utf-8",
    )
    _atomic_json(
        scratchpad / "chain_candidate_pairs_iter2.json",
        {"schema_version": "plamen.chain_tail.v1", "packet": [], "overflow": []},
    )
    _atomic_json(
        scratchpad / "chain_tail_coverage_receipt.json",
        {
            "schema_version": "plamen.chain_tail_receipt.v1",
            "status": "COMPLETE", "packet_pairs": 0, "consumed_pairs": 0,
            "unresolved_packet_pairs": 0, "overflow_pairs": 0,
            "pair_dispositions": {},
        },
    )
    _write_chain_tail_gap_ledger(scratchpad, packet=[], overflow=[])
    _initialize_chain_tail(scratchpad, [], shard_size=_ITER2_TAIL_CAP)


def _write_failed_chain_pair_artifacts(scratchpad: Path, error: str) -> None:
    """Invalidate older pair generations and persist UNKNOWN tail coverage."""
    clean_error = re.sub(r"\s+", " ", str(error)).strip()[:1000] or "unknown error"
    for name in ("chain_candidate_pairs.md", "chain_candidate_pairs_full.md"):
        (scratchpad / name).write_text(
            "# Chain Candidate Pairs â€” Generation Failed\n\n"
            "**Status**: FAILED\n"
            "**Total candidate pairs**: UNKNOWN\n\n"
            f"**Error**: {clean_error}\n",
            encoding="utf-8",
        )
    (scratchpad / "chain_candidate_pairs_iter2.md").write_text(
        "# Chain Candidate Pairs â€” Iteration 2 Tail Packet\n\n"
        "**Status**: FAILED\n\n"
        "Pair-level tail coverage is UNKNOWN because mechanical pair "
        "generation failed.\n\n"
        f"**Error**: {clean_error}\n",
        encoding="utf-8",
    )
    _atomic_json(
        scratchpad / "chain_candidate_pairs_iter2.json",
        {
            "schema_version": "plamen.chain_tail.v1",
            "status": "FAILED", "error": clean_error,
        },
    )
    _atomic_json(
        scratchpad / "chain_tail_coverage_receipt.json",
        {
            "schema_version": "plamen.chain_tail_receipt.v1",
            "status": "FAILED", "error": clean_error,
            "consumed_pairs": 0, "unresolved_packet_pairs": 0,
        },
    )
    (scratchpad / "chain_composition_coverage_gaps.md").write_text(
        "# Chain Composition Coverage Gaps\n\n"
        "**Status**: UNKNOWN\n\n"
        "Mechanical pair generation failed, so composition coverage requires "
        "human review. No prior pair generation is authoritative.\n\n"
        f"**Error**: {clean_error}\n",
        encoding="utf-8",
    )
    _initialize_failed_chain_tail(scratchpad, clean_error)


# ---------------------------------------------------------------------------
# Producer 1 — chain_candidate_pairs.md
# ---------------------------------------------------------------------------


def compute_chain_candidate_pairs(scratchpad: Path) -> dict:
    """Write chain_candidate_pairs.md (bounded) + chain_candidate_pairs_full.md.

    A pair (A, B) is a candidate when A and B share at least one signal:
      - a state variable (STATE Pairs table) — strongest signal
      - a discriminative code identifier (TYPE Pairs table)
      - the same source file with line ranges within 60 lines (TYPE Pairs)
      - optional discovery metadata with a concrete shared term or explicit
        finding reference; generic mechanism-only overlap is not a signal
      - complementary mutual-zero roles: an operational unarmed authentication
        anchor and an accepted degenerate input that derives to zero/null

    The bounded file holds the top _BOUNDED_PAIR_CAP pairs ranked by signal
    strength + combined severity (cross-class pairs prioritized). The full
    file holds every candidate. The chain agent evaluates ONLY the bounded
    file; chain_iter2 + composition_coverage cover the tail.
    """
    try:
        scratchpad = Path(scratchpad)
        entries = _load_inventory(scratchpad)
        (
            state_receipt,
            state_symbols,
            finding_state_ids,
            finding_graph_state_ids,
            finding_map_state_ids,
        ) = _resolve_typed_state_application(
            scratchpad,
            entries,
            preserve_signal_counts=False,
        )
        # Keep the compatibility-source summary and its established failure
        # boundary, but use the typed receipt as the sole binding authority.
        _legacy_state_vars, state_source = _load_state_candidates(scratchpad)
        if int((state_receipt.get("schema_counts") or {}).get("mechanical_graph_symbol_count") or 0):
            state_source = (
                "_mechanical_graph.json+legacy-projections"
                if _legacy_state_vars else "_mechanical_graph.json"
            )
        if len(entries) < 2:
            _update_state_pair_counts(scratchpad, state_pairs=0, type_pairs=0)
            _write_empty_chain_pair_artifacts(
                scratchpad, "fewer than 2 parsed inventory findings"
            )
            return {"status": "skipped", "reason": "fewer than 2 findings",
                    "pairs": 0,
                    "state_resolution": state_receipt.get("status")}

        # Pre-compute per-finding signal sets.
        meta: list[dict] = []
        for idx, e in enumerate(entries, start=1):
            blob = f"{e.get('root_cause', '')} {e.get('description', '')} {e.get('title', '')}"
            discovery = _discovery_text(e)
            fid = _entry_id(e, idx)
            meta.append({
                "id": fid,
                "aliases": _entry_aliases(e, fid),
                "severity": str(e.get("severity") or "Medium"),
                "sev_rank": _SEVERITY_RANK.get(str(e.get("severity") or "medium").strip().lower(), 2),
                "title": re.sub(r"\s+", " ", str(e.get("title") or "")).strip()[:90],
                "location": str(e.get("location") or ""),
                "locs": _extract_locations(str(e.get("location") or "")),
                "state": set(finding_state_ids.get(fid, set())),
                "graph_state": set(finding_graph_state_ids.get(fid, set())),
                "map_state": set(finding_map_state_ids.get(fid, set())),
                "idents": _extract_identifiers(blob),
                "discovery_terms": _extract_discovery_terms(discovery),
                "discovery_refs": _extract_finding_refs(discovery),
                "mutual_zero_roles": _mutual_zero_roles(e),
            })

        state_pairs: list[dict] = []
        type_pairs: list[dict] = []
        for i in range(len(meta)):
            for j in range(i + 1, len(meta)):
                a, b = meta[i], meta[j]
                if a["id"] == b["id"]:
                    continue
                shared_state = a["state"] & b["state"]
                shared_graph_state = (
                    shared_state & a["graph_state"] & b["graph_state"]
                )
                shared_map_state = (
                    (shared_state - shared_graph_state)
                    & a["map_state"] & b["map_state"]
                )
                shared_fallback_state = (
                    shared_state - shared_graph_state - shared_map_state
                )
                shared_ident = a["idents"] & b["idents"]
                proximate = _line_proximity(a["locs"], b["locs"])
                shared_discovery = a["discovery_terms"] & b["discovery_terms"]
                explicit_discovery_ref = (
                    bool(a["discovery_refs"] & b["aliases"])
                    or bool(b["discovery_refs"] & a["aliases"])
                )
                mutual_zero_role = (
                    (
                        "unarmed-auth-anchor" in a["mutual_zero_roles"]
                        and "accepted-zero-derivation" in b["mutual_zero_roles"]
                    )
                    or (
                        "unarmed-auth-anchor" in b["mutual_zero_roles"]
                        and "accepted-zero-derivation" in a["mutual_zero_roles"]
                    )
                )
                # A candidate needs a REAL signal: shared state variable,
                # shared discriminative identifier, line proximity, or a
                # concrete discovery term/reference. Bare
                # same-file (no proximity) is NOT a signal — in a 3-contract
                # codebase that pairs everything. Generic mechanism-only
                # discovery overlap is also not a signal.
                if not (
                    shared_state or shared_ident or proximate
                    or shared_discovery or explicit_discovery_ref
                    or mutual_zero_role
                ):
                    continue
                cross_class = a["sev_rank"] != b["sev_rank"]
                score = (
                    5 * len(shared_graph_state)
                    + 3 * len(shared_map_state)
                    + 1 * len(shared_fallback_state)
                    + 2 * len(shared_ident)
                    + 2 * len(shared_discovery)
                    + (2 if explicit_discovery_ref else 0)
                    + (4 if mutual_zero_role else 0)
                    + (1 if proximate else 0)
                    + (1 if cross_class else 0)
                    + (a["sev_rank"] + b["sev_rank"]) / 10.0
                )
                def _state_names(ids: set[str]) -> list[str]:
                    return sorted(
                        str(state_symbols.get(sid, {}).get("qualified_name") or sid)
                        for sid in ids
                    )

                row = {
                    "a": a["id"], "b": b["id"], "score": score,
                    "shared_state": _state_names(shared_state),
                    "shared_state_ids": sorted(shared_state),
                    "shared_graph_state": _state_names(shared_graph_state),
                    "shared_graph_state_ids": sorted(shared_graph_state),
                    "shared_map_state": _state_names(shared_map_state),
                    "shared_map_state_ids": sorted(shared_map_state),
                    "shared_fallback_state": _state_names(shared_fallback_state),
                    "shared_fallback_state_ids": sorted(shared_fallback_state),
                    "shared_ident": sorted(shared_ident)[:4],
                    "shared_discovery": sorted(shared_discovery)[:4],
                    "discovery_ref": explicit_discovery_ref,
                    "mutual_zero_role": mutual_zero_role,
                    "a_sev": a["severity"], "b_sev": b["severity"],
                    "a_title": a["title"], "b_title": b["title"],
                }
                if shared_state:
                    state_pairs.append(row)
                else:
                    type_pairs.append(row)

        # Confidence partition first, score second: every graph-backed pair is
        # considered for the STATE quota before any fallback-only pair. This
        # retains useful partial-map recall without letting regex inventory
        # displace stronger evidence.
        state_pairs.sort(
            key=lambda r: (
                bool(r["shared_graph_state"]),
                bool(r["shared_map_state"]),
                r["score"],
                _chain_pair_key(r),
            ),
            reverse=True,
        )
        type_pairs.sort(
            key=lambda r: (r["score"], _chain_pair_key(r)), reverse=True
        )
        all_pairs = state_pairs + type_pairs

        def _fmt_table(title: str, rows: list[dict]) -> list[str]:
            out = [
                f"### {title}",
                "",
                "| Finding A | A Severity | Finding B | B Severity | Shared Signal |",
                "|-----------|-----------|-----------|-----------|---------------|",
            ]
            for r in rows:
                sig = _chain_pair_signal(r)
                out.append(
                    f"| {r['a']} | {r['a_sev']} | {r['b']} | {r['b_sev']} | {sig} |"
                )
            if not rows:
                out.append("| (none) | - | - | - | - |")
            out.append("")
            return out

        # Bounded file: guarantee each table up to _BOUNDED_PER_TABLE of its
        # own top-scored pairs, then top up from the larger pool to the total
        # cap so a thin table doesn't waste budget.
        bounded_state = state_pairs[:_BOUNDED_PER_TABLE]
        bounded_type = type_pairs[:_BOUNDED_PER_TABLE]
        remaining = _BOUNDED_PAIR_CAP - len(bounded_state) - len(bounded_type)
        if remaining > 0:
            leftovers = sorted(
                state_pairs[len(bounded_state):] + type_pairs[len(bounded_type):],
                # Preserve the graph-first confidence partition during top-up
                # too; a high-severity regex fallback must not displace an
                # AST/compiler-backed pair when the TYPE quota is thin.
                key=lambda r: (
                    bool(r["shared_graph_state"]),
                    bool(r.get("shared_map_state")),
                    r["score"],
                    _chain_pair_key(r),
                ),
                reverse=True,
            )[:remaining]
            bounded_state += [r for r in leftovers if r["shared_state"]]
            bounded_type += [r for r in leftovers if not r["shared_state"]]
        bounded = bounded_state + bounded_type
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S")

        header = [
            "# Chain Candidate Pairs",
            "",
            "**Status**: MECHANICAL_PREFILTER",
            f"**Generated At**: {stamp}",
            f"**Total candidate pairs**: {len(all_pairs)} "
            f"(STATE: {len(state_pairs)}, TYPE: {len(type_pairs)})",
            f"**Bounded set below**: top {len(bounded)} by signal strength. "
            "Chain Agent 2 evaluates the pairs in this file. Real-signal pairs "
            "outside this bound are not EXCLUDED: a bounded subset is routed "
            "to chain_candidate_pairs_iter2.md and every remainder is recorded "
            "in chain_composition_coverage_gaps.md.",
            "",
        ]
        body = (
            _fmt_table("STATE Pairs", bounded_state)
            + _fmt_table("TYPE Pairs", bounded_type)
        )
        (scratchpad / "chain_candidate_pairs.md").write_text(
            "\n".join(header + body), encoding="utf-8"
        )

        full_header = [
            "# Chain Candidate Pairs — Full Set",
            "",
            "**Status**: MECHANICAL_PREFILTER_FULL",
            f"**Generated At**: {stamp}",
            f"**Total candidate pairs**: {len(all_pairs)}",
            "",
        ]
        full_body = (
            _fmt_table("STATE Pairs", state_pairs)
            + _fmt_table("TYPE Pairs", type_pairs)
        )
        (scratchpad / "chain_candidate_pairs_full.md").write_text(
            "\n".join(full_header + full_body), encoding="utf-8"
        )

        bounded_keys = {_chain_pair_key(row) for row in bounded}
        tail = [row for row in all_pairs if _chain_pair_key(row) not in bounded_keys]
        tail.sort(
            key=lambda row: (
                bool(row["shared_state"]),
                bool(row["shared_graph_state"]),
                bool(row.get("shared_map_state")),
                row["score"],
                _chain_pair_key(row),
            ),
            reverse=True,
        )
        # P0-T: every real-signal tail pair is part of the exact denominator.
        # The authority exposes one bounded shard at a time and retains every
        # remaining identity as explicit unresolved work until it is processed
        # or a real run budget stops continuation.
        primary_rows = [
            {**_tail_row(row), "initial_route": "CHAIN_AGENT2"}
            for row in bounded
        ]
        tail_rows = [
            {**_tail_row(row), "initial_route": "CHAIN_ITER2"}
            for row in tail
        ]
        _initialize_chain_tail(
            scratchpad,
            [*primary_rows, *tail_rows],
            shard_size=_ITER2_TAIL_CAP,
            activate_first_shard=False,
        )
        # Commit pair denominators only after the exact P0-T ledger exists.
        # A later generator failure therefore cannot leave stale success counts.
        _update_state_pair_counts(
            scratchpad,
            state_pairs=len(state_pairs),
            type_pairs=len(type_pairs),
        )
        initial_packet = min(len(tail_rows), _ITER2_TAIL_CAP)
        return {
            "status": "ok",
            "state_source": state_source,
            "state_resolution": state_receipt.get("status"),
            "pairs": len(all_pairs),
            "bounded": len(bounded),
            "state_pairs": len(state_pairs),
            "type_pairs": len(type_pairs),
            "iter2_tail": initial_packet,
            "coverage_gaps": max(0, len(tail_rows) - initial_packet),
        }
    except Exception as exc:  # never raise — best-effort
        try:
            _write_failed_chain_pair_artifacts(
                Path(scratchpad), f"{type(exc).__name__}: {exc}"
            )
        except Exception:
            # A disk failure while stamping degradation must not turn a recall
            # generator into a pipeline halt; the returned error remains loud.
            pass
        return {"status": "error", "error": str(exc), "pairs": 0}


# ---------------------------------------------------------------------------
# Producer 2 — variable_finding_map.md
# ---------------------------------------------------------------------------


def compute_variable_finding_map(scratchpad: Path) -> dict:
    """Write variable_finding_map.md: state variable → findings touching it.

    Lets Chain Agent 2 do variable-level matching without the grep fallback.
    """
    try:
        scratchpad = Path(scratchpad)
        entries = _load_inventory(scratchpad)
        _legacy_state_vars, state_source = _load_state_candidates(scratchpad)
        (
            state_receipt,
            state_symbols,
            finding_state_ids,
            _graph_edges,
            _map_edges,
        ) = _resolve_typed_state_application(scratchpad, entries)
        if int((state_receipt.get("schema_counts") or {}).get("mechanical_graph_symbol_count") or 0):
            state_source = (
                "_mechanical_graph.json+legacy-projections"
                if _legacy_state_vars else "_mechanical_graph.json"
            )
        if not entries or not state_symbols:
            # Still write a header so the prompt sees a real (if empty) file.
            (scratchpad / "variable_finding_map.md").write_text(
                "# Variable → Finding Map\n\n"
                "**Status**: MECHANICAL_PREFILTER\n\n"
                "No state variables or no findings parsed — Chain Agent 2 "
                "should fall back to grep-based variable matching.\n",
                encoding="utf-8",
            )
            return {"status": "skipped", "reason": "no vars or no findings",
                    "variables": 0}

        var_to_findings: dict[str, list[str]] = {}
        for idx, e in enumerate(entries, start=1):
            fid = _entry_id(e, idx)
            for symbol_id in finding_state_ids.get(fid, set()):
                var_to_findings.setdefault(symbol_id, []).append(fid)

        lines = [
            "# Variable → Finding Map",
            "",
            "**Status**: MECHANICAL_PREFILTER",
            f"**Generated At**: {time.strftime('%Y-%m-%dT%H:%M:%S')}",
            "",
            "| Qualified State Symbol | Authority | Findings Touching It |",
            "|----------------|-------------|----------------------|",
        ]
        rows = 0
        alias_counts: dict[str, int] = {}
        for symbol in state_symbols.values():
            for alias in symbol.get("bare_aliases") or []:
                alias_counts[str(alias)] = alias_counts.get(str(alias), 0) + 1
        for symbol_id in sorted(
            var_to_findings,
            key=lambda sid: str(state_symbols.get(sid, {}).get("qualified_name") or sid),
        ):
            fids = sorted(set(var_to_findings[symbol_id]))
            if not fids:
                continue
            symbol = state_symbols.get(symbol_id, {})
            qualified = str(symbol.get("qualified_name") or symbol_id)
            unique_aliases = [
                str(alias)
                for alias in (symbol.get("bare_aliases") or [])
                if alias_counts.get(str(alias), 0) == 1
            ]
            display_symbol = unique_aliases[0] if unique_aliases else qualified
            authority = str(symbol.get("authority") or "UNKNOWN")
            lines.append(
                f"| {display_symbol} | {authority} | {', '.join(fids)} |"
            )
            rows += 1
        if rows == 0:
            lines.append("| (no variable touched by 2+ findings) | - | - |")
        (scratchpad / "variable_finding_map.md").write_text(
            "\n".join(lines) + "\n", encoding="utf-8"
        )
        return {
            "status": "ok",
            "state_source": state_source,
            "state_resolution": state_receipt.get("status"),
            "variables": rows,
        }
    except Exception as exc:
        return {"status": "error", "error": str(exc), "variables": 0}


# ---------------------------------------------------------------------------
# Producer 3 — enabler_results.md STEP 0a baseline
# ---------------------------------------------------------------------------


_UNVERIFIED_VERDICTS = frozenset({
    "NEEDS_VERIFICATION", "NEEDSVERIFICATION", "NEEDS VERIFICATION",
    "LOW_CONFIDENCE", "LOW CONFIDENCE", "UNVERIFIED", "UNCONFIRMED",
})


def _is_unverified_enabler(entry: dict) -> bool:
    """A mechanically-derived, individually-weak candidate (ENUMGAP / deriver /
    enumeration-obligation exploration) usable as a LOW-CONFIDENCE chain enabler.

    Identified by an unverified verdict OR an ENUMGAP/NEXP source-id tag. These
    never enter the CONFIRMED/PARTIAL/CONTESTED dangerous-state baseline (they
    are unproven at chain time), but a postcondition they CREATE can still enable
    another finding into a compound chain. Any such chain is itself sent to
    verification, so precision is preserved by the existing verify filter."""
    verdict = str(entry.get("verdict") or "").strip().upper()
    if verdict in _UNVERIFIED_VERDICTS:
        return True
    blob = " ".join(str(s) for s in (entry.get("source_ids") or []))
    return bool(re.search(r"\bENUMGAP\b|\bNEXP-\d+", blob, re.IGNORECASE))


def _cross_domain_locus_key(loc: str) -> str:
    """Normalize a location string to a coarse locus key for dedup: bare file
    name + first line number if present. Empty string when no location."""
    if not loc:
        return ""
    s = re.sub(r"[`*]", "", str(loc)).strip()
    # bare file name (drop any directory path), first path-like token
    fm = re.search(r"([A-Za-z0-9_./\\-]+\.(?:sol|rs|move|go|vy|daml))", s)
    fname = ""
    if fm:
        fname = re.split(r"[\\/]", fm.group(1))[-1].lower()
    lm = re.search(r"[Ll]?\s*(\d{1,7})", s)
    line = lm.group(1) if lm else ""
    key = f"{fname}:{line}".strip(":")
    return key or s[:60].lower()


def _axisgap_provenance_loci(entries: list[dict]) -> set[str]:
    """Loci already covered by an M2 AXISGAP provenance-gap candidate, so the
    CROSS-DOMAIN-DEP harvester does not emit a redundant enabler for the same
    locus. An AXISGAP finding whose text names the provenance axis (or the
    provenance cue vocabulary) is treated as covering that locus's provenance
    gap. Best-effort; empty set on any miss (harvester then keeps all rows)."""
    loci: set[str] = set()
    for e in entries:
        blob = " ".join(str(s) for s in (e.get("source_ids") or []))
        # The inventory parser may retain the full `AXISGAP:AXIS-n` tag OR strip
        # the prefix to a bare `AXIS-n` source id — accept either form.
        if not re.search(r"\bAXISGAP\b|\bAXIS-\d+\b", blob, re.IGNORECASE):
            continue
        text = f"{blob} {e.get('title','')} {e.get('root_cause','')} {e.get('description','')}".lower()
        if re.search(r"\bprovenance\b|freshness|staleness|source[- ]of|external[- ]assumption", text):
            k = _cross_domain_locus_key(str(e.get("location") or ""))
            if k:
                loci.add(k)
    return loci


def _harvest_cross_domain_enablers(scratchpad: Path, entries: list[dict]) -> list[dict]:
    """Convert each SUBSTANTIVE `[CROSS-DOMAIN-DEP: {domain}]` tag in the raw
    depth/enumgap finding artifacts into a LOW-CONFIDENCE STEP-0a-LC enabler.

    A CROSS-DOMAIN-DEP tag is an admission the domain was NOT analyzed in-domain
    — exactly the "individually-invalid observation that enables another finding"
    class chain analysis exists to catch. Each becomes a candidate ENABLER that
    verify must adjudicate (a spurious one yields a chain verify refutes).

    Rules (match the plan):
      - SUBSTANTIVE only: the tag body must carry elaboration prose after the
        domain label (an em/en-dash, colon, or spaced hyphen). Bare
        `[CROSS-DOMAIN-DEP: external]` and the `none` admission are SKIPPED.
      - Append-only / bounded / deduped: cap _MAX_CROSS_DOMAIN_ENABLERS (40),
        dedup on (locus, normalized detail), and dedup vs any M2 AXISGAP
        provenance-gap candidate at the SAME locus.
    Best-effort; returns [] on any failure. Generic — names no protocol."""
    out: list[dict] = []
    try:
        scratchpad = Path(scratchpad)
        files: list[Path] = []
        seen_files: set[str] = set()
        for pat in _CROSS_DOMAIN_SOURCE_GLOBS:
            try:
                for p in sorted(scratchpad.glob(pat)):
                    if p.name not in seen_files:
                        seen_files.add(p.name)
                        files.append(p)
            except Exception:
                continue
        prov_loci = _axisgap_provenance_loci(entries)
        seen_keys: set[str] = set()
        for art in files:
            try:
                text = art.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            # Pre-index finding-id / location anchors by character offset so a
            # tag can be attributed to the nearest PRECEDING finding + location.
            id_anchors = [(m.start(), m.group(1)) for m in _FINDING_ID_ANCHOR_RE.finditer(text)]
            loc_anchors = [(m.start(), m.group(1).strip()) for m in _LOCATION_ANCHOR_RE.finditer(text)]
            for m in _CROSS_DOMAIN_TAG_RE.finditer(text):
                body = (m.group("body") or "").strip()
                if not body:
                    continue
                # domain label = leading token(s) up to the first elaboration sep.
                sep = _CROSS_DOMAIN_ELAB_RE.search(body)
                if not sep:
                    continue   # bare domain-only tag → skip
                domain = body[:sep.start()].strip().lower()
                detail = body[sep.end():].strip()
                if not detail:
                    continue   # separator but no prose → skip
                if domain in ("none", "n/a", "na", ""):
                    continue   # explicit "no cross-domain dependency" → skip
                pos = m.start()
                fid = ""
                for off, val in id_anchors:
                    if off <= pos:
                        fid = val
                    else:
                        break
                loc = ""
                for off, val in loc_anchors:
                    if off <= pos:
                        loc = val
                    else:
                        break
                lkey = _cross_domain_locus_key(loc)
                # Dedup vs M2 provenance-gap at the same locus (append-only).
                if lkey and lkey in prov_loci:
                    continue
                detail_norm = re.sub(r"\s+", " ", detail.lower())[:80]
                dkey = f"{lkey}|{detail_norm}"
                if dkey in seen_keys:
                    continue
                seen_keys.add(dkey)
                loc_disp = (re.sub(r"[`*]", "", loc).strip() if loc
                            else (fid or art.name))
                out.append({
                    "finding_id": fid or "CROSS-DOMAIN",
                    "domain": domain,
                    "detail": detail,
                    "location": loc_disp,
                    "source_file": art.name,
                })
                if len(out) >= _MAX_CROSS_DOMAIN_ENABLERS:
                    return out
        return out
    except Exception:
        return []


def harvest_cross_domain_candidates(scratchpad: Path) -> list[dict]:
    """Public, read-only wrapper around `_harvest_cross_domain_enablers`.

    WP-D (L1-3): loads the current findings inventory and returns every
    SUBSTANTIVE `[CROSS-DOMAIN-DEP: {domain} — {detail}]` candidate harvested
    from the depth/scanner/sibling finding artifacts (`_CROSS_DOMAIN_SOURCE_GLOBS`
    already covers `blind_spot_*_findings.md`, `validation_sweep_findings.md`,
    and `sibling_propagation_findings.md`, so WP-B/WP-C scanner and sibling
    output is picked up automatically). Each dict carries
    `finding_id` / `domain` / `detail` / `location` / `source_file`.

    Callable independently of the chain phase (chain_prep's own
    `compute_enabler_baseline` also calls the same private harvester to build
    `enabler_results.md`); this wrapper lets other phases -- e.g. the L1
    verify_queue pre-hook -- consume the same candidates without depending on
    chain having run first. Best-effort: never raises, returns [] on any
    failure (missing/absent findings_inventory.md, malformed artifacts, etc).
    """
    try:
        scratchpad = Path(scratchpad)
        entries = _load_inventory(scratchpad)
        return _harvest_cross_domain_enablers(scratchpad, entries)
    except Exception:
        return []


def compute_enabler_baseline(scratchpad: Path) -> dict:
    """Overwrite enabler_results.md with a STEP 0a dangerous-state baseline.

    Pre-extracts every CONFIRMED/PARTIAL/CONTESTED finding into the STEP 0a
    table so Chain Agent 1 does NOT re-scan the inventory — it takes this
    finite list as given and fills the STEP 0b 5-actor reachability table.

    ALSO surfaces mechanically-derived ENUMGAP/deriver candidates (unverified)
    as a separate LOW-CONFIDENCE potential-enabler table, carrying any pre/post
    metadata they stamped. This lets a weak candidate act as a chain enabler at
    chain time (which runs BEFORE verify); the resulting chain is a HYPOTHESIS
    that goes to verification like every chain, so a spurious enabler yields a
    spurious chain that verify refutes — precision-bounded, recall-positive.

    Runs AFTER `_write_chain_passthrough_outputs` (which writes a stub
    enabler_results.md). If this producer fails, the stub remains and the
    chain phase still gate-passes — degradation, not halt.
    """
    try:
        scratchpad = Path(scratchpad)
        entries = _load_inventory(scratchpad)
        dangerous = [
            e for e in entries
            if str(e.get("verdict") or "").strip().upper()
            in ("CONFIRMED", "PARTIAL", "CONTESTED")
        ]
        unverified = [e for e in entries if _is_unverified_enabler(e)][:40]
        # Harvest SUBSTANTIVE CROSS-DOMAIN-DEP tags into low-confidence enablers.
        cross_domain = _harvest_cross_domain_enablers(scratchpad, entries)
        if not dangerous and not unverified and not cross_domain:
            return {"status": "skipped", "reason": "no CONFIRMED/PARTIAL findings",
                    "states": 0}

        lines = [
            "# Enabler Results",
            "",
            "**Status**: MECHANICAL_BASELINE_STEP0A",
            f"**Generated At**: {time.strftime('%Y-%m-%dT%H:%M:%S')}",
            "",
            "Chain Agent 1: STEP 0a (dangerous-state extraction) is PRE-FILLED "
            "below from CONFIRMED/PARTIAL/CONTESTED findings. Do NOT re-scan the "
            "inventory for dangerous states — take this list as the complete "
            "STEP 0a set. Your job is STEP 0b: for each row, fill the 5-actor "
            "reachability table, and STEP 0c cross-state interactions.",
            "",
            "## STEP 0a: Dangerous States (mechanical baseline)",
            "",
            "| Finding ID | Severity | Location | Dangerous State (root cause) |",
            "|------------|----------|----------|------------------------------|",
        ]
        if dangerous:
            for idx, e in enumerate(dangerous, start=1):
                fid = _entry_id(e, idx)
                sev = str(e.get("severity") or "Medium")
                loc = re.sub(r"\s+", " ", str(e.get("location") or "UNKNOWN")).replace("|", "/")
                rc = re.sub(r"\s+", " ", str(e.get("root_cause") or e.get("title") or "")).replace("|", "/")
                lines.append(f"| {fid} | {sev} | {loc[:120]} | {rc[:200]} |")
        else:
            lines.append("| (none CONFIRMED/PARTIAL/CONTESTED at chain time) | - | - | - |")

        # Low-confidence potential enablers: mechanically-derived ENUMGAP/deriver
        # candidates. Unverified at chain time, so NOT in the dangerous-state
        # baseline, but a postcondition they CREATE can enable another finding.
        # Chain Agent 1/2 MAY use these as candidate enablers (postcondition
        # providers) — any resulting chain is itself sent to verification, which
        # refutes spurious enabler chains. Recall-safe, precision-bounded.
        lines += [
            "",
            "## STEP 0a-LC: Low-Confidence Potential Enablers (unverified — ENUMGAP/derivers)",
            "",
            "These are mechanically-derived, individually-WEAK candidates "
            "(verdict NEEDS_VERIFICATION). They are NOT proven dangerous states. "
            "Use them ONLY as candidate ENABLERS: if a postcondition below "
            "creates the precondition another finding needs, build a "
            "LOW-CONFIDENCE chain hypothesis. Every such chain MUST go to "
            "verification — a spurious enabler yields a chain that verify "
            "refutes, so precision is preserved. Do NOT promote these to the "
            "dangerous-state baseline.",
            "",
            "| Finding ID | Severity | Location | Postcondition Created (type) | Missing Precondition (type) |",
            "|------------|----------|----------|------------------------------|-----------------------------|",
        ]
        if unverified:
            for idx, e in enumerate(unverified, start=1):
                fid = _entry_id(e, idx)
                sev = str(e.get("severity") or "Low")
                loc = re.sub(r"\s+", " ", str(e.get("location") or "UNKNOWN")).replace("|", "/")
                post = re.sub(r"\s+", " ", str(e.get("postconditions_created") or "")).replace("|", "/")
                post_t = re.sub(r"\s+", " ", str(e.get("postcondition_types") or "")).replace("|", "/")
                pre = re.sub(r"\s+", " ", str(e.get("missing_precondition") or "")).replace("|", "/")
                pre_t = re.sub(r"\s+", " ", str(e.get("precondition_type") or "")).replace("|", "/")
                if not post and not pre:
                    # No stamped metadata — fall back to the root cause so the
                    # candidate is still visible/matchable by prose.
                    post = re.sub(r"\s+", " ", str(e.get("root_cause") or e.get("title") or "")).replace("|", "/")
                post_cell = (f"{post[:160]}" + (f" ({post_t[:24]})" if post_t else "")) or "-"
                pre_cell = (f"{pre[:120]}" + (f" ({pre_t[:24]})" if pre_t else "")) if pre else "-"
                lines.append(f"| {fid} | {sev} | {loc[:120]} | {post_cell or '-'} | {pre_cell} |")
        else:
            lines.append("| (none) | - | - | - | - |")

        # CROSS-DOMAIN-DEP enablers: each substantive tag is a depth agent's
        # admission that a value-bearing assumption lives OUTSIDE its own domain.
        # These are low-confidence candidate enablers (verify adjudicates each),
        # appended below the ENUMGAP/deriver rows. Cap 40; deduped by locus +
        # detail and vs M2 provenance-gap at the same locus.
        lines += [
            "",
            "### STEP 0a-LC (cont.): Cross-Domain Dependency Enablers (unverified)",
            "",
            "Each row is a `[CROSS-DOMAIN-DEP: {domain}]` admission harvested from "
            "depth/exploration findings — an assumption a depth agent flagged as "
            "OUTSIDE its own domain. Treat ONLY as a candidate ENABLER: if the "
            "named external/other-domain dependency, once broken, creates the "
            "precondition another finding needs, build a LOW-CONFIDENCE chain "
            "hypothesis that MUST go to verification. Do NOT promote to the "
            "dangerous-state baseline.",
            "",
            "| Source Finding | Domain | Location | Cross-Domain Dependency (verify to adjudicate) |",
            "|----------------|--------|----------|------------------------------------------------|",
        ]
        if cross_domain:
            for c in cross_domain:
                fid = re.sub(r"\s+", " ", str(c.get("finding_id") or "CROSS-DOMAIN")).replace("|", "/")
                dom = re.sub(r"\s+", " ", str(c.get("domain") or "")).replace("|", "/")
                loc = re.sub(r"\s+", " ", str(c.get("location") or "UNKNOWN")).replace("|", "/")
                det = re.sub(r"\s+", " ", str(c.get("detail") or "")).replace("|", "/")
                lines.append(f"| {fid[:40]} | {dom[:24]} | {loc[:120]} | {det[:240]} |")
        else:
            lines.append("| (none substantive) | - | - | - |")

        lines += [
            "",
            "## STEP 0b: 5-Actor Reachability (Chain Agent 1 fills this)",
            "",
            "For each dangerous state above, enumerate which of the 5 actor "
            "categories can reach it: external attacker (permissionless), "
            "semi-trusted role, natural operation, external event, user action "
            "sequence. Create [EN-N] findings for reachable-but-uncovered paths.",
            "",
            "## STEP 0c: Cross-State Interactions (Chain Agent 1 fills this)",
            "",
        ]
        (scratchpad / "enabler_results.md").write_text(
            "\n".join(lines) + "\n", encoding="utf-8"
        )
        return {"status": "ok", "states": len(dangerous),
                "low_confidence_enablers": len(unverified),
                "cross_domain_enablers": len(cross_domain)}
    except Exception as exc:
        return {"status": "error", "error": str(exc), "states": 0}


# ---------------------------------------------------------------------------
# Driver entry point — runs all three, best-effort
# ---------------------------------------------------------------------------


def run_chain_prep(scratchpad: Path) -> dict:
    """Run all three producers. Never raises. Returns a per-producer summary."""
    scratchpad = Path(scratchpad)
    summary = {
        "candidate_pairs": compute_chain_candidate_pairs(scratchpad),
        "variable_map": compute_variable_finding_map(scratchpad),
        "enabler_baseline": compute_enabler_baseline(scratchpad),
    }
    try:
        source = scratchpad / "enabler_results.md"
        baseline = scratchpad / "chain_enabler_baseline.md"
        if source.is_file() and not source.is_symlink():
            baseline.write_bytes(source.read_bytes())
        else:
            baseline.write_text(
                "# Chain Enabler Baseline\n\n"
                "**Status**: DEGRADED_MISSING_BASELINE\n\n"
                "The deterministic enabler baseline was unavailable. Chain "
                "Agent 1 must enumerate STEP 0a without treating this as a "
                "clean empty denominator.\n",
                encoding="utf-8",
            )
    except Exception as exc:
        summary["enabler_baseline_snapshot"] = {
            "status": "error",
            "error": str(exc),
        }
    else:
        summary["enabler_baseline_snapshot"] = {"status": "ok"}
    return summary


__all__ = [
    "compute_chain_candidate_pairs",
    "compute_variable_finding_map",
    "compute_enabler_baseline",
    "_harvest_cross_domain_enablers",
    "run_chain_prep",
]
