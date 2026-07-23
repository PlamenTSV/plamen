#!/usr/bin/env python3
"""
Reproduction spike: regenerate three CPG enrichment facts an external
proprietary oracle exposes, using ONLY the open, already-installed Slither.

Facts reproduced (per function):
  1. validationDominates  -- does a require/assert/revert node DOMINATE a
                             state-write node in the function CFG?
  2. taint source->sink   -- is the value reaching an external call dependent
                             on a user-controlled source (param / msg.sender /
                             msg.data)?  (slither.analyses.data_dependency)
  3. typed sinks          -- classify SlithIR ops into a sinkType set mirroring
                             EXTERNAL_CALL / STATE_WRITE / REVERT / EMIT_EVENT.

Run from the directory containing Sample.sol:
    python3 extract_cpg.py
"""
import json
import sys

from slither import Slither
from slither.core.cfg.node import NodeType
from slither.analyses.data_dependency.data_dependency import is_dependent
from slither.core.declarations.solidity_variables import SolidityVariableComposed
from slither.slithir.operations import (
    HighLevelCall, LowLevelCall, Send, Transfer, LibraryCall,
    SolidityCall, EventCall, Assignment, Binary,
)

TARGET = "Sample.sol"
CONTRACT = "Sample"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def is_validation_node(node):
    """A node that enforces a condition: require/assert, revert(), or throw."""
    if node.type == NodeType.THROW:
        return True
    if node.contains_require_or_assert():
        return True
    for ir in node.irs:
        if isinstance(ir, SolidityCall) and "revert" in ir.function.name.lower():
            return True
    return False


def is_external_call_op(ir):
    """SlithIR ops that leave the contract (EXTERNAL_CALL sink)."""
    return isinstance(ir, (HighLevelCall, LowLevelCall, Send, Transfer, LibraryCall))


def sink_types_of_node(node):
    """Classify a CFG node into the oracle's sinkType set."""
    sinks = set()
    if node.state_variables_written:
        sinks.add("STATE_WRITE")
    if is_validation_node(node):
        sinks.add("REVERT")
    for ir in node.irs:
        if is_external_call_op(ir):
            sinks.add("EXTERNAL_CALL")
        if isinstance(ir, EventCall):
            sinks.add("EMIT_EVENT")
    return sinks


def user_controlled_sources(func):
    """User-controlled taint sources: parameters + msg.sender + msg.data."""
    srcs = list(func.parameters)
    for name in ("msg.sender", "msg.data", "msg.value", "tx.origin"):
        try:
            srcs.append(SolidityVariableComposed(name))
        except Exception:
            pass
    return srcs


def source_label(func, var):
    """Human-readable label for a matched taint source."""
    if var in func.parameters:
        return "param:%s" % var.name
    return str(var)


# ---------------------------------------------------------------------------
# Fact extraction
# ---------------------------------------------------------------------------
def analyze_function(func, contract):
    result = {
        "function": func.full_name,
        "visibility": func.visibility,
        "stateWriteNodes": [],
        "validationDominates": None,   # aggregated: TRUE iff every state write is guarded
        "taintEdges": [],
        "sinks": {},                   # sinkType -> [node exprs]
    }

    # --- Fact 1: validationDominates (CFG dominance) ---------------------
    write_flags = []
    for node in func.nodes:
        if not node.state_variables_written:
            continue
        # a state-write node is "guarded" iff some validation node DOMINATES it
        dominators = node.dominators  # includes node itself
        guarded = any(
            d is not node and is_validation_node(d) for d in dominators
        )
        write_flags.append(guarded)
        result["stateWriteNodes"].append({
            "expr": str(node.expression),
            "vars": [str(v) for v in node.state_variables_written],
            "dominatedByValidation": guarded,
            "dominatorIds": sorted(d.node_id for d in dominators),
        })
    if write_flags:
        result["validationDominates"] = all(write_flags)

    # --- Fact 2: taint source -> external-call sink ---------------------
    sources = user_controlled_sources(func)
    for node in func.nodes:
        for ir in node.irs:
            if not is_external_call_op(ir):
                continue
            # candidate tainted values reaching the call: destination + args + reads
            reaching = set()
            if getattr(ir, "destination", None) is not None:
                reaching.add(ir.destination)
            for a in getattr(ir, "arguments", []) or []:
                reaching.add(a)
            for r in ir.read:
                reaching.add(r)
            for val in reaching:
                for src in sources:
                    try:
                        dep = is_dependent(val, src, func)
                    except Exception:
                        dep = False
                    # is_dependent is reflexive-ish; a param IS its own source
                    if dep or (val is src):
                        result["taintEdges"].append({
                            "source": source_label(func, src),
                            "via": str(val),
                            "sink": "EXTERNAL_CALL",
                            "op": type(ir).__name__,
                            "at": str(node.expression),
                        })

    # --- Fact 3: typed sinks -------------------------------------------
    for node in func.nodes:
        for st in sink_types_of_node(node):
            result["sinks"].setdefault(st, []).append(str(node.expression))

    return result


def main():
    sl = Slither(TARGET)
    contract = sl.get_contract_from_name(CONTRACT)[0]

    out = []
    for func in contract.functions_declared:
        if func.is_constructor:
            continue
        out.append(analyze_function(func, contract))

    print("=" * 78)
    print("CPG ENRICHMENT FACTS  (regenerated from open Slither %s)" % _slither_version())
    print("contract=%s  file=%s" % (CONTRACT, TARGET))
    print("=" * 78)

    # Compact human table
    hdr = "%-26s %-18s %-28s" % ("function", "validationDominates", "sinkTypes")
    print(hdr)
    print("-" * 78)
    for r in out:
        vd = "TRUE" if r["validationDominates"] else (
            "FALSE" if r["validationDominates"] is False else "n/a(no write)")
        print("%-26s %-18s %-28s" % (
            r["function"], vd, ",".join(sorted(r["sinks"].keys())) or "-"))
    print("-" * 78)
    print("\nTAINT EDGES (user source -> typed sink):")
    any_edge = False
    for r in out:
        for e in r["taintEdges"]:
            any_edge = True
            print("  [%s]  %s  --(%s)-->  %s   @ %s"
                  % (r["function"], e["source"], e["via"], e["sink"], e["at"]))
    if not any_edge:
        print("  (none)")

    print("\n" + "=" * 78)
    print("FULL JSON")
    print("=" * 78)
    print(json.dumps(out, indent=2))


def _slither_version():
    try:
        from importlib.metadata import version
        return version("slither-analyzer")
    except Exception:
        return "?"


if __name__ == "__main__":
    sys.exit(main())
