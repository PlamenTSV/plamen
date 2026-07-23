# Reproduction Spike — Regenerating Oracle CPG Enrichment Facts from Open Slither

**Goal.** Prove that the three CPG enrichment facts an external proprietary oracle
exposes — `validationDominates`, taint `source -> typed sink`, and typed-sink
classification — can be regenerated from the open, already-installed Slither, with
running code and **real captured output** (not a mock).

**Environment (captured).**

| Component | Value |
|-----------|-------|
| Slither | `0.11.5` (`slither --version`; `import slither` OK) |
| solc | `0.8.20+commit.a1b79de6` via `solc-select install 0.8.20 && solc-select use 0.8.20` (succeeded) |
| Host | macOS (Darwin, arm64) |
| Compile | `slither Sample.sol` → `1 contracts ... analyzed`, no compile errors |

solc install/select **succeeded** — no fallback/limitation was needed.

---

## Verdict

All three oracle facts are **reproduced from open Slither** on a purpose-built
fixture, with the fixture's designed ground truth matching the tool output
exactly:

| Fixture case (design intent) | Extractor output | Match |
|------------------------------|------------------|-------|
| (a) guarded state write → `validationDominates` TRUE | `setConfigGuarded` → **TRUE** | ✅ |
| (b) unguarded state write → `validationDominates` FALSE | `bumpCounter` → **FALSE** | ✅ |
| (c) user param → low-level `.call` → taint→EXTERNAL_CALL | `forward`: `param:target`, `param:payload` → **EXTERNAL_CALL** | ✅ |
| (d) normal transfer typed sink | `withdraw`: `Transfer` → **EXTERNAL_CALL** (+ `STATE_WRITE`) | ✅ |

---

## File 1 — `spike/Sample.sol` (fixture, pragma 0.8.20)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/// @notice Spike fixture exercising the three CPG enrichment facts.
contract Sample {
    address public owner;
    uint256 public config;
    uint256 public counter;
    mapping(address => uint256) public balances;

    event Configured(uint256 value);

    constructor() {
        owner = msg.sender;
    }

    // (a) state write GUARDED by require(msg.sender==owner)
    //     -> validationDominates should be TRUE
    function setConfigGuarded(uint256 value) external {
        require(msg.sender == owner, "not owner");
        config = value;
        emit Configured(value);
    }

    // (b) state write with NO guard
    //     -> validationDominates should be FALSE
    function bumpCounter(uint256 delta) external {
        counter += delta;
    }

    // (c) user-supplied address/param forwarded into a low-level .call
    //     -> taint source (parameter) -> EXTERNAL_CALL sink
    function forward(address target, bytes calldata payload) external {
        (bool ok, ) = target.call(payload);
        require(ok, "call failed");
    }

    // (d) a normal transfer
    function withdraw(uint256 amount) external {
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
}
```

## File 2 — `spike/extract_cpg.py` (extractor, Slither Python API)

```python
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
```

---

## Real Captured Output

Command (run from `spike/`):

```
$ python3 extract_cpg.py
```

Stdout (verbatim; warnings on stderr suppressed):

```
==============================================================================
CPG ENRICHMENT FACTS  (regenerated from open Slither 0.11.5)
contract=Sample  file=Sample.sol
==============================================================================
function                   validationDominates sinkTypes
------------------------------------------------------------------------------
setConfigGuarded(uint256)  TRUE               EMIT_EVENT,REVERT,STATE_WRITE
bumpCounter(uint256)       FALSE              STATE_WRITE
forward(address,bytes)     n/a(no write)      EXTERNAL_CALL,REVERT
withdraw(uint256)          FALSE              EXTERNAL_CALL,STATE_WRITE
------------------------------------------------------------------------------

TAINT EDGES (user source -> typed sink):
  [forward(address,bytes)]  param:payload  --(payload)-->  EXTERNAL_CALL   @ (ok,None) = target.call(payload)
  [forward(address,bytes)]  param:target  --(target)-->  EXTERNAL_CALL   @ (ok,None) = target.call(payload)
  [withdraw(uint256)]  param:amount  --(amount)-->  EXTERNAL_CALL   @ address(msg.sender).transfer(amount)
  [withdraw(uint256)]  msg.sender  --(TMP_4)-->  EXTERNAL_CALL   @ address(msg.sender).transfer(amount)
```

Selected JSON (dominance proof for the two guarded/unguarded writes):

```json
{ "function": "setConfigGuarded(uint256)", "validationDominates": true,
  "stateWriteNodes": [ { "expr": "config = value", "dominatedByValidation": true,
                         "dominatorIds": [0, 1, 2] } ] }
{ "function": "bumpCounter(uint256)", "validationDominates": false,
  "stateWriteNodes": [ { "expr": "counter += delta", "dominatedByValidation": false,
                         "dominatorIds": [0, 1] } ] }
```

The dominator sets are the mechanism: node `1` in `setConfigGuarded` is the
`require(msg.sender == owner)` node, and it appears in the dominator set
`[0,1,2]` of the `config = value` write (node `2`) → guarded. In `bumpCounter`
the write node's dominator set is `[0,1]` (entrypoint + itself), containing no
validation node → unguarded.

---

## Oracle-Schema → Slither-API Mapping

| Oracle schema field | Slither API used | Reproduction | Notes / precision gap |
|---------------------|------------------|--------------|-----------------------|
| **validationDominates** | `slither/core/cfg/node.py` → `node.dominators` (also `immediate_dominator`, `dominance_frontier`), `node.state_variables_written`, `node.contains_require_or_assert()`, `NodeType.THROW`, `SolidityCall` name `revert` | **FULL** (intra-procedural) | Exact CFG dominance from the tool's own dominator sets. Correctly TRUE for the `require`-guarded write, FALSE for the unguarded one. Gap: a guard living in a *modifier* or a *called internal function* would need the modifier CFG to be inlined / inter-procedural climb — modifiers ARE inlined by Slither into the function CFG so most on-function guards are covered; a guard delegated to a separate `internal` validator function is **needs-inter-procedural-work**. |
| **taintSource** (user source → sink) | `slither.analyses.data_dependency.data_dependency` → `is_dependent(value, source, func)` (+ `is_tainted`, `get_dependencies`); sources = `function.parameters` + `SolidityVariableComposed('msg.sender'/'msg.data'/'tx.origin')` | **FULL** for intra-contract; **PARTIAL** for cross-contract | Correctly links `param:target`/`param:payload` → the low-level `.call`, and `param:amount`/`msg.sender` → the `.transfer`. Documented gap: **Slither `data_dependency` is intra-contract-biased** — dependencies flowing *through an external call return value* or *across a contract boundary* are not tracked; those edges are **needs-inter-procedural-work**. `is_dependent` context is the enclosing function/contract, so a source laundered through a storage var written in a *different* function is captured only via the contract-level dependency map (coarser). |
| **sinkType** (EXTERNAL_CALL / STATE_WRITE / REVERT / EMIT_EVENT) | `slither.slithir.operations` classes: `HighLevelCall`, `LowLevelCall`, `Send`, `Transfer`, `LibraryCall` → EXTERNAL_CALL; `node.state_variables_written` → STATE_WRITE; `SolidityCall` require/assert + `NodeType.THROW`/`revert` → REVERT; `EventCall` → EMIT_EVENT | **FULL** | Every sink in the fixture typed correctly, incl. `.transfer` lowered to a `Transfer` SlithIR op and `.call` to `LowLevelCall`. Delegatecall is a `LowLevelCall` sub-case (distinguishable via `ir.function_name == 'delegatecall'`) — trivially separable if the oracle splits DELEGATECALL from EXTERNAL_CALL. |
| **STORAGE_FLOW** (oracle field, not directly in fixture) | `node.state_variables_written` / `node.state_variables_read` per SlithIR `Assignment`/`Binary`/`Index`, joined to `is_dependent` over storage vars, and the contract-level dependency map in `data_dependency` | **PARTIAL / needs-inter-procedural-work** | A single-function store→load flow (e.g. `withdraw` reads `balances[msg.sender]` and writes it) is recoverable node-locally. A *cross-function* storage flow (function A writes `config`, function B's external-call arg depends on `config`) requires the contract-level `data_dependency` map, which exists but is coarser and **intra-contract-biased**; cross-contract storage flow is not modeled. This field is the least complete of the four and is where genuine inter-procedural def-use work would be needed to match an oracle that claims precise storage flows. |

### Honest precision summary

- **validationDominates** and **sinkType**: reproduced **FULL** on the fixture with the tool's native dominator sets and SlithIR op classes — no heuristic guessing.
- **taintSource → sink**: reproduced **FULL intra-contract**; the known limitation is that `is_dependent` does not follow value across external-call boundaries or contract boundaries (**PARTIAL** in the general case).
- **STORAGE_FLOW**: **PARTIAL** — node-local and contract-level flows are available, but precise inter-procedural / cross-contract storage flow is **needs-inter-procedural-work** and is the main precision gap versus a proprietary oracle.

**Bottom line:** three of the oracle's enrichment facts (`validationDominates`,
`taintSource`, `sinkType`) are directly regenerable from open Slither at
parity on realistic single-contract code; the fourth (`STORAGE_FLOW`) is
partially regenerable and marks the boundary where additional inter-procedural
def-use plumbing would be required to close the gap.
