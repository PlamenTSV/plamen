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
     halts; if the mechanical graph is absent the gate is a no-op (advisory).

No-overfit: pure graph mechanics, names no protocol.
"""
from __future__ import annotations

import json
import math
import os
import re
import threading
import uuid
from contextlib import contextmanager
from pathlib import Path

from coverage_shortfalls import (
    replace_producer_shortfalls,
    shortfall,
    unknown_shortfall,
)

try:
    from plamen_mechanical import _inventory_blocks  # type: ignore
except Exception:  # pragma: no cover
    _inventory_blocks = None  # type: ignore

try:
    from plamen_mechanical import _field_from_markdown  # type: ignore
except Exception:  # pragma: no cover
    _field_from_markdown = None  # type: ignore

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
    "compute_hot_function_set",
    "compute_axis_coverage_gaps",
    "promote_axis_findings_to_inventory",
    "promote_enumgap_exploration_to_inventory",
    # Driver entry point (all axes + derivers).
    "run_enumeration_gate",
    # Gate V (Fix A) — 3-axis Variant-Family Coverage.
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
    return inv_text.rstrip() + (hdr if hdr else "\n\n") + "\n".join(appended) + "\n"


def _load_graph(scratchpad: Path) -> dict | None:
    p = scratchpad / "_mechanical_graph.json"
    if not p.exists():
        return None
    try:
        g = json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None
    if not isinstance(g, dict) or "var_refs" not in g or "functions" not in g:
        return None
    return g


def _bare_from_descriptor(d: str) -> str:
    """A descriptor is 'BareName (file:line)' or 'file:line' — return the bare
    name (or the descriptor itself when it's a plain location)."""
    return (d.split("(", 1)[0].strip() or d).strip()


def _fn_at_location(graph: dict, location: str) -> str | None:
    """Map a finding location (e.g. 'core/QOrg.sol:L330') to the enclosing
    function: same file basename, nearest function whose line <= the cited line."""
    m = re.search(r"([A-Za-z0-9_./\\-]+)\D*:?L?(\d+)", location or "")
    if not m:
        return None
    fbase = Path(m.group(1).replace("\\", "/")).name.lower()
    fline = int(m.group(2))
    best, best_line = None, -1
    for fk, info in graph["functions"].items():
        loc = str(info.get("loc", ""))
        lm = re.search(r"([A-Za-z0-9_./\\-]+)\D*:?L?(\d+)", loc)
        if not lm:
            continue
        if Path(lm.group(1).replace("\\", "/")).name.lower() != fbase:
            continue
        fnl = int(lm.group(2))
        # the ENCLOSING function = highest declaration line at-or-before the
        # cited line. (A forward slack would wrongly grab the NEXT function when
        # two are adjacent.)
        if fnl <= fline and fnl > best_line:
            best, best_line = fk, fnl
    return best


def compute_enumeration_obligations(scratchpad: Path) -> int:
    """G1. Derive per-finding co-reference obligations from the graph. Writes
    `enumeration_obligations.md` + `_enumeration_obligations.json`. Returns the
    obligation count. Never raises; a no-op when the graph or inventory is absent."""
    scratchpad = Path(scratchpad)
    graph = _load_graph(scratchpad)
    inv = scratchpad / "findings_inventory.md"
    if graph is None or _inventory_blocks is None or not inv.exists():
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

    var_refs = graph["var_refs"]
    # invert: bare fn name -> set(var keys it references)
    fn_to_vars: dict[str, set] = {}
    for vk, vd in var_refs.items():
        for d in vd.get("refs", []):
            fn_to_vars.setdefault(_bare_from_descriptor(d).lower(), set()).add(vk)

    obligations: list[dict] = []
    shortfalls: list[dict] = []
    for b in blocks:
        fid = b.get("id", "")
        loc = b.get("location", "")
        fk = _fn_at_location(graph, loc)
        if not fk:
            continue
        fbare = graph["functions"][fk].get("bare", fk.split(".")[-1]).lower()
        all_vars = sorted(fn_to_vars.get(fbare, set()))
        vars_touched = all_vars[: _MAX_VARS_PER_FINDING]
        if len(all_vars) > _MAX_VARS_PER_FINDING:
            shortfalls.append(shortfall(
                producer="enumeration.axis1",
                scope=f"finding:{fid}:variables",
                cap="MAX_VARS_PER_FINDING",
                limit=_MAX_VARS_PER_FINDING,
                observed=len(all_vars),
                retained=len(vars_touched),
                exact=True,
                samples=all_vars[_MAX_VARS_PER_FINDING:],
                detail="state symbols touched by the finding were not all expanded",
            ))
        # Popularity is a distinct skip path. Inspect it across the complete
        # symbol set, including variables beyond MAX_VARS_PER_FINDING, so one
        # cap cannot hide another cap's highest-fan-in accounting target.
        high_fan_vars = {
            vk for vk in all_vars
            if len(var_refs.get(vk, {}).get("refs", [])) > _SKIP_VAR_REF_THRESHOLD
        }
        for vk in sorted(high_fan_vars):
            vd = var_refs.get(vk, {})
            refs = vd.get("refs", [])
            shortfalls.append(shortfall(
                producer="enumeration.axis1",
                scope=f"finding:{fid}:symbol:{vd.get('bare', vk)}",
                cap="SKIP_VAR_REF_THRESHOLD",
                limit=_SKIP_VAR_REF_THRESHOLD,
                observed=len(refs),
                retained=0,
                exact=True,
                samples=sorted(_bare_from_descriptor(d) for d in refs),
                detail=("high-fan-in accounting/state symbol was intentionally "
                        "not expanded by the co-reference gate"),
                kind="HIGH_FAN_IN_UNENUMERATED",
            ))
        for vk in vars_touched:
            vd = var_refs.get(vk, {})
            refs = vd.get("refs", [])
            if vk in high_fan_vars:
                # Choosing an arbitrary six-of-N subset would create noisy,
                # order-dependent obligations. The control-plane receipt above
                # is intentionally the only output for this symbol.
                continue
            all_corefs = sorted({
                _bare_from_descriptor(d) for d in refs
                if _bare_from_descriptor(d).lower() != fbare
            })
            corefs = all_corefs[: _MAX_COREFS_PER_VAR]
            if len(all_corefs) > _MAX_COREFS_PER_VAR:
                shortfalls.append(shortfall(
                    producer="enumeration.axis1",
                    scope=f"finding:{fid}:symbol:{vd.get('bare', vk)}:corefs",
                    cap="MAX_COREFS_PER_VAR",
                    limit=_MAX_COREFS_PER_VAR,
                    observed=len(all_corefs),
                    retained=len(corefs),
                    exact=True,
                    samples=all_corefs[_MAX_COREFS_PER_VAR:],
                    detail="co-referencing functions were not all enumerated",
                ))
            if corefs:
                obligations.append({
                    "finding_id": fid,
                    "function": graph["functions"][fk].get("bare", fk),
                    "symbol": vd.get("bare", vk),
                    "required_corefs": corefs,
                })

    try:
        replace_producer_shortfalls(scratchpad, "enumeration.axis1", shortfalls)
    except Exception:
        # Haltless contract: receipt failure must not suppress candidates.
        pass

    (scratchpad / "_enumeration_obligations.json").write_text(
        json.dumps({"source": graph.get("source", "?"), "obligations": obligations},
                   indent=1), encoding="utf-8")
    lines = ["# Enumeration Obligations",
             "",
             f"> Source graph: {graph.get('source', '?')}. {len(obligations)} obligation(s).",
             "> Each row: a finding analyzing `function` (which touches `symbol`) must "
             "address every co-referencing function below, or the gap becomes an "
             "ENUMGAP candidate.", "",
             "| Finding | Function | Symbol | Must also address |",
             "|---------|----------|--------|-------------------|"]
    for o in obligations:
        lines.append(f"| {o['finding_id']} | `{o['function']}` | `{o['symbol']}` | "
                     f"{', '.join('`'+c+'`' for c in o['required_corefs'])} |")
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
        obligations = json.loads(op.read_text(encoding="utf-8", errors="replace")).get("obligations", [])
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
    """Recover durable candidate keys from inventory markers only."""
    inventory = Path(scratchpad) / "findings_inventory.md"
    if not inventory.exists():
        return set()
    try:
        return set(re.findall(
            r"<!--\s*ENUMGAP-KEY:\s*([^\s>]+)\s*-->",
            inventory.read_text(encoding="utf-8", errors="replace"),
        ))
    except Exception:
        return set()


def _emitted_candidate_keys(scratchpad: Path) -> set[str]:
    """Recover durable keys from both the receipt and inventory markers.

    Inventory markers make a receipt-write failure resumable without emitting a
    duplicate finding. A later successful call repairs the key receipt from the
    union before clearing PERSISTENCE_FAILED.
    """
    keys = _receipt_candidate_keys(scratchpad)
    keys.update(_inventory_candidate_keys(scratchpad))
    return keys


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


# ── GATE V — 3-axis Variant-Family Coverage (Fix A, sibling/variant miss) ────
# The co-reference gate above (G1/G2) enumerates ONE axis: functions that
# share a state symbol. The dominant recall-miss class is broader: an agent
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
# Axis 1 (co-reference, G1/G2 above) is UNCHANGED — same functions, same
# bounds, same behavior. All three axes flow through the SAME
# `NEEDS_VERIFICATION` inventory path as ENUMGAP — the verify-the-positives
# filter adjudicates every candidate; nothing here is promoted to
# body-at-severity directly. Unconditional: not Thorough-only, not
# confidence-gated (the failure mode is a confidently-WRONG agent, not merely
# a low-confidence one). No-overfit: pure graph/shape mechanics — every
# regex below is a HOW-shaped structural cue (param-type vocabulary, generic
# boundary-value vocabulary, pair-table parsing), never a protocol, token, or
# function name.

_CONFIRMED_VERDICTS = ("confirmed", "partial")

# Per-language TYPE cues for Axis 2. Deliberately independent of `_LANG`'s
# `array_param`/`str_param`/etc. keys so this addition cannot perturb any
# existing deriver's behavior. A language absent from this map (or DAML,
# which has no `_LANG` entry at all) degrades Axis 2 to a no-op for that
# finding — recall-neutral, never a wrong-positive.
_PARAM_TYPE_CUES = {
    "sol": {
        "numeric": _c(r"\bu?int\d*\b"),
        "address": _c(r"\baddress\b"),
        "collection": _c(r"\[\]|\bmapping\s*\("),
    },
    "rust": {
        "numeric": _c(r"\b[iu](?:8|16|32|64|128|size)\b"),
        "address": _c(r"\bPubkey\b|\bAddress\b|\bAccountId\b"),
        "collection": _c(r"\bVec\s*<|\[\s*\w[^;\]]*;|\bHashMap\b|\bBTreeMap\b|\bHashSet\b"),
    },
    "move": {
        "numeric": _c(r"\bu(?:8|16|32|64|128|256)\b"),
        "address": _c(r"\baddress\b"),
        "collection": _c(r"\bvector\s*<"),
    },
    "go": {
        "numeric": _c(r"\b(?:u?int(?:8|16|32|64)?|float(?:32|64))\b"),
        "address": _c(r"\bcommon\.Address\b|\bAddress\b"),
        "collection": _c(r"\[\]\w|\bmap\s*\["),
    },
}

# The required-addressed boundary set (generic, HOW-shaped — no protocol
# constant). One VARGAP candidate per member NOT named anywhere in the
# finding's own prose.
_BOUNDARY_MEMBERS = ("0", "1", "min", "MAX", "empty", "self")
_BOUNDARY_CUES = {
    "0": _c(r"(?i)\b(?:zero|0)\b"),
    "1": _c(r"(?i)\b(?:one|1)\b"),
    "min": _c(r"(?i)\bmin(?:imum)?\b"),
    "MAX": _c(r"(?i)\bmax(?:imum)?\b"),
    "empty": _c(r"(?i)\bempty\b"),
    "self": _c(r"(?i)\bself\b|\bthis\s+contract\b|\bown(?:\s+address)?\b"),
}


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


def compute_boundary_input_candidates(scratchpad: Path) -> list:
    """Gate V axis 2 (boundary-input coverage). For each CONFIRMED/PARTIAL
    finding whose enclosing function takes a numeric/collection/address
    parameter, the required-addressed boundary set is
    {0, 1, min, MAX, empty, self}. A boundary never named in the finding's
    own prose is a coverage gap -> one VARGAP candidate per missing boundary.
    Never raises; a no-op when the graph, inventory, or source-parsed
    param-type info is absent for the finding's language (recall-neutral)."""
    producer = "enumeration.variant.boundary.scan"
    try:
        scratchpad = Path(scratchpad)
        graph = _load_graph(scratchpad)
        inv = scratchpad / "findings_inventory.md"
        if graph is None or _inventory_blocks is None or not inv.exists():
            replace_producer_shortfalls(
                scratchpad, producer, [unknown_shortfall(
                    producer=producer,
                    scope="candidate-provider",
                    kind="PROVIDER_UNAVAILABLE",
                    detail="boundary scan requires graph, inventory parser, and findings inventory",
                )],
            )
            return []
        root = _locate_project_root(scratchpad)
        if root is None:
            replace_producer_shortfalls(
                scratchpad, producer, [unknown_shortfall(
                    producer=producer,
                    scope="candidate-provider",
                    kind="PROVIDER_UNAVAILABLE",
                    detail="boundary scan cannot locate the project root",
                )],
            )
            return []
        try:
            blocks = _inventory_blocks(inv.read_text(encoding="utf-8", errors="replace"))
        except Exception as exc:
            raise RuntimeError("boundary inventory parse failed") from exc
        # bare function name (lowercased, first occurrence wins) -> (lang, params)
        fn_index: dict = {}
        for lang, _rel_path, name, params, _body, _line in _iter_functions(root):
            fn_index.setdefault(name.lower(), (lang, params))
        if not fn_index:
            replace_producer_shortfalls(
                scratchpad, producer, [unknown_shortfall(
                    producer=producer,
                    scope="candidate-provider",
                    kind="PROVIDER_UNAVAILABLE",
                    detail="boundary scan found no parseable production functions",
                )],
            )
            return []

        out: list = []
        emitted_keys = _emitted_candidate_keys(scratchpad)
        for b in blocks:
            if _unseen_candidate_count(out, emitted_keys) > _MAX_PER_DERIVER:
                break
            if not _is_confirmed_verdict(b.get("block", "")):
                continue
            fid = b.get("id", "")
            fk = _fn_at_location(graph, b.get("location", ""))
            if not fk:
                continue
            fbare = graph["functions"][fk].get("bare", fk.split(".")[-1])
            entry = fn_index.get(fbare.lower())
            if not entry:
                continue  # graph lacks param-type info for this function -> no-op
            lang, params = entry
            cues = _PARAM_TYPE_CUES.get(lang)
            if not cues or not (params or "").strip():
                continue  # graph lacks param-type info for this language -> no-op
            if not any(rx.search(params) for rx in cues.values()):
                continue  # no qualifying numeric/collection/address param
            text_l = (b.get("block", "") or "").lower()
            for member in _BOUNDARY_MEMBERS:
                if _unseen_candidate_count(out, emitted_keys) > _MAX_PER_DERIVER:
                    break
                if _BOUNDARY_CUES[member].search(text_l):
                    continue
                out.append({
                    "key": f"VARGAP-B:{fid}:{fbare}:{member}",
                    "title": (f"Boundary-input coverage gap: `{fbare}` not verified at "
                              f"the `{member}` boundary ({fid})"),
                    "location": f"`{fbare}` (boundary-input sibling of {fid})",
                    "source_note": ("boundary-input coverage gap; mechanically derived "
                                    "— verifier to confirm or refute"),
                    "root_cause": (f"{fid} confirmed a defect in `{fbare}`, which takes a "
                                   f"numeric/collection/address parameter. The finding's "
                                   f"own prose does not address the `{member}` boundary "
                                   "value for that parameter."),
                    "description": (f"Verify whether `{fbare}` behaves correctly (or "
                                    f"shares {fid}'s defect) when the relevant parameter "
                                    f"is at the `{member}` boundary."),
                    "impact": (f"Potential unaddressed boundary-value variant of {fid}'s "
                               "defect (verifier to confirm the concrete harm)."),
                    "postcondition": (f"STATE: `{fbare}` boundary `{member}` not addressed "
                                      f"by {fid}'s analysis"),
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
    """Gate V driver entry (Fix A — 3-axis Variant-Family Coverage). Axis 1
    (co-reference) reuses the existing G1/G2 gate UNCHANGED
    (`compute_enumeration_obligations` / `validate_enumeration_coverage`);
    axes 2 (boundary-input) and 3 (symmetric-operation) are the new derivers
    above. All three emit through the SAME append-only, idempotent, bounded,
    low-confidence inventory path (`_emit_candidates`, shared receipt).
    Unconditional (not Thorough-only, not confidence-gated).

    This function is intentionally NOT wired into `run_enumeration_gate`'s
    existing call sites — it is a separate, additive entry point the driver
    calls alongside it (mirroring the G1/G2 naming convention so the driver
    owner can wire the new call site without touching this module further).
    Never raises."""
    scratchpad = Path(scratchpad)
    result = {"axis1_emitted": 0, "axis2_emitted": 0, "axis3_emitted": 0,
              "obligations": 0, "gaps": 0, "emitted": 0}

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
        result["obligations"] = compute_enumeration_obligations(scratchpad)
        axis1_res = validate_enumeration_coverage(scratchpad)
        result["gaps"] = axis1_res.get("gaps", 0)
        result["axis1_emitted"] = int(axis1_res.get("emitted", 0))
        _pipeline_status("enumeration.variant.axis1.orchestration")
    except Exception as exc:
        _pipeline_status("enumeration.variant.axis1.orchestration", exc)
    try:
        b_cands = compute_boundary_input_candidates(scratchpad)
        _pipeline_status("enumeration.variant.boundary.orchestration")
    except Exception as exc:
        b_cands = []
        _pipeline_status("enumeration.variant.boundary.orchestration", exc)
    try:
        result["axis2_emitted"] = _emit_candidates(
            scratchpad, b_cands, _MAX_PER_DERIVER, source_id="VARGAP",
            producer="enumeration.variant.boundary.emission",
        )
        _pipeline_status("enumeration.variant.boundary.pipeline")
    except Exception as exc:
        _pipeline_status("enumeration.variant.boundary.pipeline", exc)
    try:
        s_cands = compute_symmetric_operation_candidates(scratchpad)
        _pipeline_status("enumeration.variant.symmetric.orchestration")
    except Exception as exc:
        s_cands = []
        _pipeline_status("enumeration.variant.symmetric.orchestration", exc)
    try:
        result["axis3_emitted"] = _emit_candidates(
            scratchpad, s_cands, _MAX_PER_DERIVER, source_id="VARGAP",
            producer="enumeration.variant.symmetric.emission",
        )
        _pipeline_status("enumeration.variant.symmetric.pipeline")
    except Exception as exc:
        _pipeline_status("enumeration.variant.symmetric.pipeline", exc)
    result["emitted"] = (result["axis1_emitted"] + result["axis2_emitted"]
                         + result["axis3_emitted"])
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
    # ID-format-too-narrow silent-drop class as _EXPL_HEADING_RE (see
    # feedback_id_regex_catalog). Anchored on `committed-invariant [...]`.
    r"committed-invariant\s*\[\s*(?P<id>CI(?:-[A-Za-z0-9]+)+)\s*\]\s*\n(?P<body>.*?)"
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
    still verifiable). Never raises; empty on any failure."""
    try:
        scratchpad = Path(scratchpad)
        graph = _load_graph(scratchpad)   # may be None → degrade, never halt
        out: list = []
        seen_ids: set = set()
        globs: list[Path] = []
        for pat in _CI_SOURCE_GLOBS:
            try:
                globs.extend(sorted(scratchpad.glob(pat)))
            except Exception:
                continue
        for art in globs:
            try:
                text = art.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
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
                })
        return out
    except Exception:
        return []


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
        bare = re.split(r"[.:]{1,2}", fn_cell)[-1].strip("` ").lower()
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
        out[bare] = {"callers": callers}
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
            return hot[:_MAX_HOT_FUNCTIONS]

        # ── PRIMARY: rank off the graph ──
        hot = []
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
            hot.append({
                "function": info.get("bare", fk),
                "loc": info.get("loc", loc_by_fn.get(bare, "?")),
                "callers": n_callers,
                "writes": writes,
                "elevate": elevate,
                "value_effect": has_eff,
                "lang": lang,
                "score": score,
            })
        # Deterministic ranking: score desc, then name asc (tie-break stable).
        hot.sort(key=lambda h: (-h["score"], str(h["function"]).lower()))
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
        return hot[:_MAX_HOT_FUNCTIONS]
    except Exception as exc:
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

        # Collect value-bearing finding blocks keyed by enclosing bare-fn name.
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
                bare = None
                if fn and graph:
                    bare = graph["functions"][fn].get("bare", fn.split(".")[-1]).lower()
                if not bare:
                    # Fallback: any hot-fn bare name mentioned in the Location line.
                    for hf in hot:
                        hn = str(hf["function"]).lower()
                        if hn and re.search(r"\b" + re.escape(hn) + r"\b", loc.lower()):
                            bare = hn
                            break
                if not bare:
                    continue
                block_by_fn.setdefault(bare, []).append(block)

        matrix: list = []
        gaps: list = []
        for hf in hot:
            bare = str(hf["function"]).lower()
            blocks = block_by_fn.get(bare, [])
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

    matches = list(_EXPL_HEADING_RE.finditer(text))
    parsed: list[dict] = []
    for i, m in enumerate(matches):
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        block = text[start:end]
        if not all(f"**{f}**" in block for f in _EXPL_REQUIRED_FIELDS):
            continue
        parsed.append({"id": m.group("id").strip(),
                       "title": m.group("title").strip(),
                       "block": block})
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
        mo = re.search(r"\*\*" + name + r"\*\*\s*:\s*(.+?)(?=\n\*\*|\n##|\n#{2,4}\s|\Z)",
                       block, re.IGNORECASE | re.DOTALL)
        return (mo.group(1).strip() if mo else "").replace("\n", " ").strip()

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

_EXPL_HEADING_RE = re.compile(
    # ID accepts multi-segment forms (AXIS-A-1, AXIS-F-4) as well as the bare
    # two-part form (NEXP-1, INV-001). The M2 axis-worker emits AXIS-<shard>-<n>;
    # a `[A-Za-z]{2,6}-\d+`-only pattern silently dropped every 3-part AXIS
    # heading (14 findings incl. a High), the same silent-drop class fixed for
    # _CI_BLOCK_RE (see feedback_id_regex_catalog). Anchored on `Finding [...]`.
    r"^#{2,4}\s*Finding\s*\[\s*(?P<id>[A-Za-z]{2,6}(?:-[A-Za-z0-9]+)+)\s*\]\s*:\s*(?P<title>.+?)\s*$",
    re.MULTILINE,
)
_EXPL_REQUIRED_FIELDS = ("Severity", "Location", "Description")
# Receipt idempotency re-read for the promote_*_to_inventory promoters. MUST use
# the SAME multi-segment ID shape as _EXPL_HEADING_RE: the receipt is written as
# `<finding-id> -> INV-nnn`, and a narrower `[A-Za-z]{2,6}-\d+` re-read captured
# only the `A-1` substring of a 3-part `AXIS-A-1`, so `id not in promoted` was
# always True → duplicate promotion on every haltless resume/retry. Pairs with
# the heading regex; widen both together or idempotency silently breaks.
_PROMOTION_RECEIPT_ID_RE = re.compile(
    r"\b([A-Za-z]{2,6}(?:-[A-Za-z0-9]+)+)\s*->\s*INV-\d+"
)


def promote_enumgap_exploration_to_inventory(scratchpad: Path) -> dict:
    """Append the depth-exploration agent's findings to findings_inventory.md as
    INV-* entries so they reach chain/verify. Idempotent via a receipt keyed on
    the source NEXP-* id. Returns {parsed, emitted}. Never raises, never halts."""
    scratchpad = Path(scratchpad)
    try:
        art = scratchpad / "enumgap_exploration_findings.md"
        inv = scratchpad / "findings_inventory.md"
        if not art.exists() or not inv.exists():
            return {"parsed": 0, "emitted": 0}
        text = art.read_text(encoding="utf-8", errors="replace")
        inv_text = inv.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return {"parsed": 0, "emitted": 0}

    matches = list(_EXPL_HEADING_RE.finditer(text))
    parsed: list[dict] = []
    for i, m in enumerate(matches):
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        block = text[start:end]
        if not all(f"**{f}**" in block for f in _EXPL_REQUIRED_FIELDS):
            continue
        parsed.append({"id": m.group("id").strip(),
                       "title": m.group("title").strip(),
                       "block": block})
    if not parsed:
        return {"parsed": 0, "emitted": 0}

    receipt = scratchpad / "enumgap_exploration_promotion_receipt.md"
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

    appended: list[str] = []
    rec_lines: list[str] = []

    def _field(block: str, name: str) -> str:
        mo = re.search(r"\*\*" + name + r"\*\*\s*:\s*(.+?)(?=\n\*\*|\n##|\n#{2,4}\s|\Z)",
                       block, re.IGNORECASE | re.DOTALL)
        return (mo.group(1).strip() if mo else "").replace("\n", " ").strip()

    for n, p in enumerate(new, 1):
        inv_id = f"INV-{max_inv + n:03d}"
        sev = _field(p["block"], "Severity") or "Low"
        loc = _field(p["block"], "Location") or "UNKNOWN"
        desc = _field(p["block"], "Description") or p["title"]
        impact = _field(p["block"], "Impact") or "Verifier to confirm the concrete harm."
        rc = _field(p["block"], "Root Cause")
        tag = _field(p["block"], "Preferred Tag") or "[CODE-TRACE]"
        appended.extend([
            f"### Finding [{inv_id}]: {p['title']}",
            f"**Severity**: {sev.split()[0] if sev else 'Low'}",
            f"**Location**: {loc}",
            f"**Preferred Tag**: {tag}",
            f"**Source IDs**: {p['id']} (enumeration-obligation exploration; depth-traced "
            "from a mechanically-flagged obligation — verifier to confirm or refute)",
            "**Verdict**: NEEDS_VERIFICATION",
        ])
        if rc:
            appended.append(f"**Root Cause**: {rc}")
        appended.extend([
            f"**Description**: {desc}",
            f"**Impact**: {impact}",
            "",
        ])
        rec_lines.append(f"{p['id']} -> {inv_id}")

    header = ("\n\n## Enumeration-Obligation Exploration Findings\n\n"
              "Depth-traced findings produced by the Phase 4b.7 exploration of "
              "mechanically-flagged enumeration obligations. Each was investigated "
              "(boundary/variation/trace) before reaching verification. Recall-safe: "
              "append-only.\n\n")
    hdr = "" if "Enumeration-Obligation Exploration Findings" in inv_text else header
    try:
        inv.write_text(_append_inventory_blocks(inv_text, hdr, appended), encoding="utf-8")
    except Exception:
        return {"parsed": len(parsed), "emitted": 0}

    try:
        prior = []
        if receipt.exists():
            prior = [ln for ln in receipt.read_text(encoding="utf-8", errors="replace").splitlines()
                     if "->" in ln]
        out = ["# Enumeration-Obligation Exploration Promotion Receipt", ""]
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


def run_enumeration_gate(scratchpad: Path) -> dict:
    """Driver entry: the co-reference gate (G1+G2) then the additional mechanical
    obligation-derivers. Best-effort, never raises, never halts.

    Budget: each deriver gets its OWN `_MAX_PER_DERIVER` slots, INDEPENDENT of the
    co-reference gate's `_MAX_ENUMGAP_PER_RUN` pool. (Sharing one pool let the
    co-ref gate, which routinely hits its 40-cap, starve every new deriver to
    zero — the exact bug that silenced L-04/L-08/L-10 in a real run.) Each pool
    is bounded and the verify-the-positives filter prunes the candidates, so the
    bounded sum (co-ref 40 + 3×15) is recall-safe."""
    scratchpad = Path(scratchpad)
    try:
        n_obl = compute_enumeration_obligations(scratchpad)
    except Exception:
        n_obl = 0
    try:
        res = validate_enumeration_coverage(scratchpad)
    except Exception:
        res = {"gaps": 0, "emitted": 0}
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
        except Exception:
            continue
    # M1 committed-invariant deriver: its OWN `_MAX_PER_DERIVER` (15) pool,
    # INDEPENDENT of the co-ref `_MAX_ENUMGAP_PER_RUN` (40) pool and of the three
    # derivers above (each gets its own cap in its own `_emit_candidates` call).
    # Stamps `Source IDs: INVARIANT` so candidates stay distinct for dedup/
    # coverage while still flowing the standard ENUMGAP inventory->verify path.
    ci_emitted = 0
    try:
        ci_cands = compute_invariant_assertion_candidates(scratchpad)
        ci_emitted = _emit_candidates(
            scratchpad, ci_cands, _MAX_PER_DERIVER, source_id="INVARIANT",
            producer="enumeration.deriver.committed_invariant.emission",
        )
        emitted += ci_emitted
    except Exception:
        ci_emitted = 0
    # Base return contract (obligations/gaps/emitted) is unchanged for backward
    # compat; the M1 count is folded into `emitted` AND surfaced as an additive
    # `invariant_emitted` key only when nonzero, so a clean no-graph/no-CI run
    # still returns the exact 3-key dict prior callers assert on.
    result = {"obligations": n_obl, "gaps": res.get("gaps", 0), "emitted": emitted}
    if ci_emitted:
        result["invariant_emitted"] = ci_emitted
    return result
