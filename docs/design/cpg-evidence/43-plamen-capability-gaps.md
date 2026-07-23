# Plamen Capability Gaps a Code-Property-Graph Would Address

**Scope:** Which analytical tasks Plamen currently performs with error-prone LLM reasoning that a mechanical graph backend (taint/data-flow paths, guard/dominance, typed sinks, access-control reachability, precise inter-procedural call graph) would do deterministically — and, critically, which gaps a CPG does **not** fix.
**Method:** Read of `/Users/ptsanev/.plamen` rules, EVM prompts, `docs/architecture.md`, `docs/internals.md`. No guessing.
**Date:** 2026-07-23

---

## 0. Baseline: Plamen ALREADY has a (coarse) mechanical graph — this is the key framing

Plamen is **not** a pure-LLM pipeline. `recon_prepass.py` bakes a per-ecosystem **reference graph** (`_mechanical_graph.json`) read by a deterministic deriver/gate layer (`enumeration_gate.py`, `plamen_mechanical.py`, `mechanical_verify.py`). Documented in `docs/architecture.md` §"Mechanical Recall Gates" and `docs/internals.md` §"Mechanical Derivers".

**What the existing graph is (its schema — `_write_mechanical_graph_json`, `recon_prepass.py:2134`):**
- Nodes: functions / Move-choices.
- Edges: `function → referenced state symbols` (`var_refs`) and `function → callees`; callees inverted to callers.
- Derived artifacts: `state_read_map.md`, `state_write_map.md`, `caller_map.md`, `callee_map.md`.
- **Granularity is FUNCTION × SYMBOL.** Even the precise Slither tier (`_bake_evm_slither_graph`, `recon_prepass.py:2167`, "type-resolved data-flow analysis") is *downcast* into this function→symbol-reference schema.

**What the existing graph is NOT (the actual CPG gap):**
- **No CFG / basic blocks / statement-level nodes** — the graph cannot say "statement A executes before statement B on this path."
- **No dominance relation** — cannot prove "guard `require(msg.sender==owner)` dominates the state write on ALL paths."
- **No path conditions / branch predicates.**
- **No true taint paths** — "function references symbol `feeBps`" is not "this untrusted parameter flows into this external-call arg through these ops." It is co-occurrence, not data-flow.
- **No typed sinks** — no classification of a statement as external-call / delegatecall / selfdestruct / privileged-storage-write / division sink.
- **No precise tier at all for Move (Aptos/Sui) and DAML** — `_bake_move_graph`/`_bake_daml_graph` are regex source parses (`recon_prepass.py:2441`, `:2479`); EVM precise tier requires the project to build under Slither; Rust/Soroban/Go get SCIP.

So the correct question is not "graph vs. no graph" but **"function-symbol reference graph vs. a statement-level Code Property Graph (CFG + data-flow + guard predicates + typed sinks)."** Every gap below is where the coarse graph runs out and the LLM is left to reason manually.

---

## Tier 1 — Gaps a CPG genuinely and strongly fixes (mechanical reachability/taint/guard tasks done by LLM today)

### G1. Enabler enumeration = manual backward reachability (Rule 12 / Phase 4c Agent 1 PHASE 0)
- **Where:** `generic-security-rules.md` Rule 12 "Exhaustive Enabler Enumeration"; `rules/phase4c-chain-prompt.md` Agent 1 STEP 0a/0b — the 5-actor-category table ("External attacker / Semi-trusted role / Natural operation / External event / User action sequence — Path to State S? Reachable? Y/N").
- **What the LLM does manually:** For each dangerous state S (a state write), enumerate every entry point that can reach the writer of S and decide reachability per actor class. This is textbook **backward inter-procedural reachability from a sink**, plus a guard check on each path.
- **Why error-prone:** The LLM guesses "No path — because…" freely; a missed permissionless writer is a silent false negative, and Rule 12 admits "Missing paths are coverage gaps." The existing `caller_map` gives *direct* callers only, not transitive guarded reachability.
- **CPG fix:** Backward slice from the sink over the precise call graph, intersect with entry points, annotate each path with the dominating guards → the 5-actor table becomes mechanical, not narrative.

### G2. Postcondition→precondition chain matching = manual def-use matching (Phase 4c Agent 2)
- **Where:** `rules/phase4c-chain-prompt.md` Agent 2 Step 2.1 — match Finding B's "Postcondition Created" (a state write) to Finding A's "Missing Precondition" (a state-read guard). Current mechanism is **string matching**: `variable_finding_map.md`, and the prompt's own fallback "grep-based variable name matching in findings_inventory.md."
- **What the LLM does manually:** Decide whether B's write actually feeds A's guarded read.
- **Why error-prone:** Name-string matching misses struct fields, mapping keys, aliased locals, and getter-wrapped reads; it also over-matches on same-named-but-unrelated variables. This is precisely a **def-use / data-dependency** edge.
- **CPG fix:** A real def-use graph makes "B's def reaches A's use" a graph edge query, not a grep — removing both the FN (missed alias) and FP (name collision) classes.

### G3. Access-control reachability — "does an unguarded path reach a privileged sink?" (Blind Spot Scanner C CHECK 8; Validation Sweep CHECK 2 & 3)
- **Where:** `phase4b-scanner-templates.md` — Blind Spot Scanner C "Role Lifecycle, Capability Exposure & **Reachability**" CHECK 8 "Function Reachability Audit" (LLM fills a Reachable-in-Production?/Dead-Code? table by hand); Validation Sweep **CHECK 2 "Validation Reachability"** and **CHECK 3 "Guard Coverage Completeness"** ("for EVERY modifier/guard: … NOT Applied To (same state writes) … Missing?").
- **What the LLM does manually:** Determine whether a function is reachable, and whether every function writing a given state carries the guard that some sibling writer has.
- **Why error-prone:** CHECK 3 is literally "which functions write the same state but lack the guard other writers have" — a set operation over `state_write_map` × guard-predicate. The LLM does it as a hand-built table; missing one writer = missed access-control bug. `docs/orchestrator-rules.md` Rule 13a even names "Scanner C CHECK 5 … guard parameter injection" as a NEVER-CUT recall-critical check.
- **CPG fix:** Typed-sink classification (privileged storage write / external call) + guard-dominance gives "sink S is reachable from entry E without a dominating access-control guard" as a deterministic query. The `state_write_map` already lists writers; the CPG adds the missing *guard-dominance* half.

### G4. Guard / stored-precondition tracing across calls (Rule 2, Rule 8)
- **Where:** Rule 2 "Function Preconditions Are Griefable"; Rule 8 "Cached Parameters / External state validated at one entry point, stored, and relied upon at a later entry point **without re-verification**."
- **What the LLM does manually:** Trace whether a value validated/checked at write-time is re-checked before each later consuming read.
- **Why error-prone:** Requires following a stored value from its guarded def to every later use and proving no re-guard exists between — a cross-function def-use walk with guard interposition. LLM attention drops consumers.
- **CPG fix:** "def at guarded site X → use at site Y with no dominating re-check between" is a data-flow + dominance query. This is the exact shape of Rule 8's "External state staleness."

### G5. Cross-variable / aggregate-invariant write-site enumeration (Rule 14, Rule R17, semantic-invariant "write completeness")
- **Where:** Rule 14 "trace ALL modification paths for both the aggregate AND its components; if any path modifies one without the other → FINDING"; Rule R17 "State Transition Completeness" field-by-field symmetric-branch diff; `phase4b-depth-templates.md:159` "Write completeness … for each variable flagged with POTENTIAL GAP … are there value-changing functions the pre-computation agent missed?"
- **What the LLM does manually:** Enumerate every writer of `total` and every writer of its components and check they co-update.
- **Why error-prone:** "value-changing functions the agent missed" is the admitted FN mode. The existing `state_write_map` mechanizes the *enumeration* of writers (and `compute_symmetric_operation_candidates` heuristically pairs deposit/withdraw), but the **co-update proof** ("in this function, is `total` written whenever a component is written?") needs intra-procedural data-flow the current graph lacks.
- **CPG fix:** Per-function def sets over the CFG make "component written but aggregate not written on this path" a mechanical intra-procedural check; pairing symmetric legs and diffing their write-sets becomes exact rather than name-heuristic.

### G6. Tainted-source consumption enumeration (depth-templates step 6)
- **Where:** `phase4b-depth-templates.md:172` "When a tainted or weak input source is identified (weak RNG, manipulable oracle, user-controllable parameter), enumerate ALL functions that consume it … Use `get_function_callers` or **grep** to find all call sites. Rate severity by the WORST consumption point."
- **What the LLM does manually:** Forward-taint a source to every sink and pick the worst.
- **Why error-prone:** The prompt itself falls back to grep — a lexical proxy for forward taint. Grep misses indirection (source stored then read elsewhere, passed through a helper).
- **CPG fix:** Forward taint slice from the source enumerates all reachable consumers precisely; "worst consumption point" is then a max over a real sink set.

### G7. Reachability of inherited / dead capability (Scanner B CHECK 5/5b, Scanner C CHECK 6/7)
- **Where:** `phase4b-scanner-templates.md` Scanner B "Inherited Capability Completeness"/"Override Safety" and Scanner C "inherited capability is unreachable post-deployment."
- **What the LLM does manually:** Resolve inheritance/override dispatch and decide if a base function is externally reachable.
- **Why error-prone:** Virtual dispatch, modifier inheritance, and `super` chains are exactly where the **regex source-parse graph tier is weakest** (and Move/DAML have only that tier). LLM re-derives dispatch by reading.
- **CPG fix:** A precise call graph with resolved dispatch answers "is `_setPeriod` reachable from any external entry?" mechanically.

---

## Tier 2 — Gaps a CPG partially fixes (mechanical half + irreducible semantic half)

### P1. Flash-loan precondition manipulation (Rule 15)
- CPG fixes the **structural** half: "is state var V (a precondition) writable within a single tx by a permissionless path?" (reachability + write-site query). CPG does **not** decide **profitability** ("profit = extracted − fee − gas > 0") — that is economic simulation, not a graph query.

### P2. Donation / threshold / counter-gate manipulation (Rule 7)
- CPG can flag "threshold read compares against `balanceOf(this)` which is externally increment-able" (a typed-source → guard query). It cannot decide whether crossing the threshold produces a *harmful* protocol outcome — semantic.

### P3. Root-cause consolidation & dedup (Phase 6 report-index STEP 1.5; `plamen_mechanical.py` dedup)
- CPG improves the **location/def-use overlap** signal ("same fix touches same statement/def"). The "same root cause / same fix?" judgment retains a semantic core. Plamen already mechanizes part of this (`build_dedup_cluster_map`) on file+function; CPG sharpens the mechanical input, not the decision.

### P4. Reentrancy / callback exit-path analysis (depth-templates step 3 "Callback exit path"; Rule 3 side effects)
- CPG mechanically finds the **state-write-after-external-call** ordering (classic reentrancy shape) via CFG ordering + typed external-call sink — a real win over LLM ordering-by-reading. It does **not** determine whether the reentrant re-entry is *economically* exploitable, or whether a token's transfer hook actually fires (needs external-contract behavior, Rule 1/Rule 3 "Verified in Production").

---

## Tier 3 — Gaps a CPG does NOT fix (semantic / economic / external-world reasoning)

A CPG is a **structural** engine. These Plamen tasks are irreducibly semantic and must stay LLM/verification work — building a CPG must not be sold as fixing them:

- **Material-harm / mechanism-vs-consequence judgment** (`finding-output-format.md` Material Harm floor; `report-template.md` body-vs-appendix). "State is corrupted" → "who loses what" is semantic.
- **Economic profitability & severity calibration** — Rule 5 (combinatorial $ impact), Rule 10 (worst-realistic-state severity), Rule 15 profit math. A graph shows *reachability*, not *value*.
- **"By design" / user-harm normalization** — Rule 13 5-question test, Passive Attack Modeling. Whether a reachable behavior *harms a user class* is a design-intent judgment.
- **Oracle-semantics adequacy** — Rule 16: a graph can detect "value is oracle-derived and used in a division" (typed source→sink), but "is a 1-hour heartbeat too stale," "are decimals mismatched," "is the confidence band mishandled" are semantic/numeric.
- **External-contract actual behavior** — Rule 1 (does the external call really return the wrong token?), Rule 3 (does transfer trigger a rebase?), the whole `[PROD-*]`/`EXTERNAL-ASSUMPTION` evidence regime in `finding-output-format.md`. Out-of-scope code is not in the graph.
- **Cross-VM serialization correctness** — `CROSS_VM_SERIALIZATION_CONFORMANCE`: byte-layout/decoder semantics, not reachability.
- **Novel economic/game-theoretic invariants** — anything requiring "what SHOULD the protocol's accounting model be" (Operational Implications gate, orchestrator Rule 14). A CPG has no notion of intended invariants.
- **PoC harm assertion** (`phase5-poc-execution.md` Impact-Premise gate) — proving the *harm* (not the mechanism) requires execution, not graph queries.

---

## Documented recall failure modes this bears on (evidence)

- `docs/architecture.md:99` — Re-scan phase exists specifically to "Counter LLM **attention saturation**." Attention saturation is the FN driver the mechanical layer targets.
- `docs/architecture.md:217-236` — the "Where the recall increase comes from" table enumerates the exact miss classes the coarse graph already recovers (co-referencer gap G1/G2, symmetric-op gap, boundary gap, etc.) — evidence that Plamen's own design treats reachability/co-reference gaps as mechanically recoverable. **Every row there is a function-symbol-level recovery; none is a statement-level taint/guard-dominance recovery — that is the un-served frontier a CPG opens.**
- `docs/architecture.md:238-241` — the integrity gate (`_classify_integrity`) is the *precision* counterpart; note there is no *taint-path* generator, confirming the CPG-shaped gap.
- `orchestrator-rules.md` Rule 13a — names Scanner C reachability/guard checks as recall-critical NEVER-CUT, i.e. exactly the access-control-reachability class where the LLM is known to miss.

---

## Prioritized recommendation (highest recall-leverage first)

1. **Access-control reachability + guard-dominance (typed sinks)** → directly mechanizes Scanner C CHECK 8, Validation Sweep CHECK 2/3, Rule 2 (G3). Highest ROI: privileged-sink-reachable-without-guard is the single most common high-severity FN class and is a clean graph query.
2. **Backward reachability for enabler enumeration (Rule 12 / Phase 4c Agent 1)** → replaces the hand-built 5-actor path table with mechanical entry→sink slices (G1).
3. **Def-use edges for chain matching (Phase 4c Agent 2)** → replaces grep/name-string variable matching, killing both alias-FN and name-collision-FP (G2).
4. **Forward taint for source-consumption enumeration (depth step 6)** → replaces the grep fallback (G6).
5. **Intra-procedural write-set diff for Rule 14 / R17 co-update proofs** (G5).
6. **Precise call graph / dispatch resolution for Move & DAML**, which today have *no* precise tier at all (regex only) — the largest structural blind spot by ecosystem (G7).

**One-line summary:** Plamen already has a function→symbol *reference* graph and a deriver layer that harvests co-reference/symmetry/boundary gaps from it; the un-served frontier a true CPG opens is **statement-level CFG + data-flow + guard-dominance + typed sinks**, which would mechanize enabler enumeration (Rule 12), chain def-use matching (Phase 4c), access-control reachability (Scanner C / Validation Sweep), and taint-source consumption — while economic, "by-design," oracle-adequacy, and external-behavior reasoning remain irreducibly LLM/verification work.
