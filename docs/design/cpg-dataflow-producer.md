# RFC / PR: Add a CPG dataflow producer to Plamen's mechanical-deriver layer

> **Status:** Proposed
> **Type:** Producer addition (additive graph enrichment) — no new consumer scaffold
> **Author:** Plamen lead architect
> **Date:** 2026-07-23
> **Scope of this PR:** EVM (Slither) producer only. Go/Rust/Move staged; DAML out.

---

## 1. TL;DR

Plamen already ships a deterministic mechanical-deriver layer (M1/M2, the
sibling/variant gates, ~50 derivers) that all read **one** artifact —
`_mechanical_graph.json`. Today that artifact carries only a coarse
**function × symbol reference graph** (which var is touched where, which function
calls which). This PR adds a **statement-level CPG enrichment producer** that
bakes four additive keys — `taint_edges`, `guards`, `typed_sinks`,
`reachability` — into that same file, computed from **Slither's own SlithIR
data-dependency and dominator-tree analyses that Plamen already runs but does not
surface**. No consumer needs a schema change: the derivers read the new keys via
`graph.get(...)` and light up additively. This is the *next fidelity tier* of the
v2.2.2–2.2.4 mechanical-deriver program — it grounds the LLMxCPG citation that
`enumeration_gate.py` already makes, replacing error-prone LLM+grep taint/guard
reasoning with graph ground-truth on the mechanical false-negative classes. It is
**not** a bug-finder, and the semantic/economic core stays LLM + PoC.

---

## 2. Motivation

Plamen's two documented recall failure modes are both *enumeration* failures, not
reasoning failures:

- **FM-1 — attention saturation / early returns.** An LLM reading long contracts
  silently drops a writer, a consumer, or a path and returns "no path." The
  Phase 3b/3c re-scan phase exists *specifically* to counter this
  (`docs/architecture.md:99`). A mechanical enumeration cannot get bored.
- **FM-2 — wasted verify budget.** Unguided depth/verify agents spend budget on
  candidates a structural query would have pre-filtered or pre-grounded.

The v2.2.2–2.2.4 program was built to attack exactly these: the enumeration gate
(G1/G2), the M1 invariant-assertion deriver, the M2 hot-function-set + axis-coverage
matrix, and the sibling/variant Gate V are all **deterministic derivers over a
shared graph** — roughly 50 of them — designed to mechanize what the LLM was doing
by hand. That program already names its own next step: the docstring in
`enumeration_gate.py` cites **LLMxCPG (USENIX Security '25, arXiv:2507.16585)** and
states that the proven fix for its dominant under-enumeration recall failure is
**grounding the required-set in an external static-analysis graph**. LLMxCPG's
result is that CPG-derived slices reduce code size 67.84–90.93% while preserving
vuln-relevant context and raise F1 by 15–40%, robust to syntactic mutation — i.e.
spend the model's budget only on the relevant dataflow slice.

The gap is precise: **Plamen ships the consumer scaffold but not the
statement-level graph that would feed it.** The current graph has no CFG, no
dominance, no taint, no typed sinks. So the four analyses that would most directly
close FM-1/FM-2 —

- enabler enumeration / backward reachability (Rule 12, phase4c Agent 1 STEP 0b 5-actor table),
- postcondition→precondition chain matching (phase4c Agent 2, currently name-string matching),
- access-control reachability + guard-coverage (Scanner C CHECK 8, Validation Sweep CHECK 2/3, flagged NEVER-CUT recall-critical),
- tainted-source consumption enumeration (depth step 6, currently grep),

— are all still performed by **error-prone LLM reasoning that falls back to grep.**
This PR is not a new direction. It is the fidelity tier the existing trajectory was
already pointing at.

---

## 3. The insight: reject the product, adopt the capability

An external vendor pitched a hosted "CPG oracle" (marketed as "an improved
Slither"). We probed it live and separately reproduced its core facts from open
tooling. The two evidence streams, side by side, make the decision:

**The product is unusable for Plamen.** The hosted oracle at
`https://solq.dev/api/v1/cpg/dodo/mcp` is real and, contrary to a prior degraded
observation, currently operational — the handshake succeeded (HTTP/2 200,
`serverInfo cpg-oracle v1.0.0`, session `ada4fd76-…`), `tools/list` returned all 7
tools, and all three probe `cypher` queries executed against a real Neo4j-backed
graph in under 800 ms with concrete, citeable rows
(`evidence_live_oracle.md`). But that graph is **one frozen, redacted demo
codebase** — a ZetaChain gateway + DODO route-proxy, 59 contracts, 12,694 nodes —
and the endpoint path hardcodes `/cpg/dodo/`. **There is no ingestion path: you
cannot point it at a client target.** Since Plamen audits arbitrary client code,
the oracle can never sit in the real pipeline. Add the eval-only license (no
production, no benchmarking, **no competing-tool build** — the exact uses Plamen
needs), the single-anonymous-author ~1-day-old repo, and the invite-only key, and
it is disqualified as a production dependency (`ASSESSMENT.md` §1–§4).

**The capability is standard CPG tech, reproducible from open tooling.** We took
the three enrichment facts the oracle exposes — `validationDominates`, taint
`source → typed sink`, and typed-sink classification — and **regenerated all three
from the already-installed open Slither 0.11.5**, with running code and real
captured output, no mocks (`evidence_slither_spike.md`). On a purpose-built
fixture the extractor output matched the designed ground truth exactly:

| Oracle fact | Open-Slither reproduction | Slither API | Precision |
|---|---|---|---|
| `validationDominates` TRUE (guarded write) | `setConfigGuarded` → **TRUE** (`require` node 1 in dominator set `[0,1,2]` of `config = value`) | `node.dominators` + `contains_require_or_assert()` | **FULL** intra-procedural |
| `validationDominates` FALSE (unguarded write) | `bumpCounter` → **FALSE** (dominator set `[0,1]`, no validation node) | same | **FULL** intra-procedural |
| taint source → typed sink | `forward`: `param:target`,`param:payload` → **EXTERNAL_CALL**; `withdraw`: `param:amount` → **EXTERNAL_CALL** | `slither.analyses.data_dependency.is_dependent` | **FULL** intra-contract, PARTIAL cross-contract |
| typed sink classification | `.transfer` → `Transfer` → EXTERNAL_CALL; `.call` → `LowLevelCall` → EXTERNAL_CALL; state write → STATE_WRITE; require → REVERT | SlithIR op classes + `state_variables_written` | **FULL** |

Deterministic (`md5 108e607249eb8af6c6d6f1b57b38c8e5` twice), exit 0, solc 0.8.20
via solc-select, no fallback needed.

**Conclusion:** the oracle's *power* is real but frozen to DODO and cannot touch a
target; Slither delivers the same statement-level facts locally on **every** EVM
target — and Plamen already runs Slither. The right move is not to rent a demo
graph. It is to **surface Slither's own unused SSA/dominator analyses into the
mechanical graph.**

---

## 4. Exact recommendation

Add an **EVM CPG-enrichment step** to `recon_prepass.py` that computes, from
SlithIR:

1. **`taint_edges`** — `slither.analyses.data_dependency.is_dependent(value, source, func)` from user-controlled sources (parameters + `msg.sender`/`msg.data`/`tx.origin`) to sinks;
2. **`guards`** (a.k.a. `validationDominates`) — per state-write node, whether a `require`/`assert`/`revert`/modifier-predicate node **dominates** it on all CFG paths, via `node.dominators`;
3. **`typed_sinks`** — SlithIR op-class classification into an EXTERNAL_CALL / DELEGATECALL / STATE_WRITE / REVERT / EMIT_EVENT set;
4. **`reachability`** — bounded backward/forward slice over the resolved call graph intersected with entry points (the Rule 12 5-actor table substrate).

Emit these as **additive top-level keys** in `_mechanical_graph.json` — the four
legacy fields (`source`, `var_refs`, `functions`) stay byte-for-byte unchanged.
Then **rewire the highest-ROI consumers to prefer graph ground-truth over agent
tags where the graph is authoritative**: M1's committed-invariant falsifier
(guard-dominance), M2's axis-coverage matrix (a mechanical taint/reachability
axis), chain_prep's Access-Guard column and 5-actor table (def-use reachability
instead of name-string matching), and the G1/G2 co-reference obligations
(taint-reachable sink instead of bare co-occurrence).

**What this is NOT:**

- **NOT** the hosted MCP oracle. We do not `claude mcp add` the `solq.dev`
  endpoint. It is DODO-only, licensed against our use, and single-vendor risk.
- **NOT** the proprietary product or its schema. We design the enrichment schema
  from the **open Joern CPG spec (`cpg.joern.io`) and the LLMxCPG paper**, never by
  copying the oracle's labels/enums (license guardrail, §7).
- **NOT** a bug-finder. It raises recall on mechanical FN classes. Material-harm
  judgment, severity (Rule 10), by-design normalization (Rule 13), oracle adequacy
  (Rule 16), external-contract behavior (Rule 1/3), and PoC harm assertion stay
  LLM + verification.

---

## 5. Where it fits (file:line seams)

**Producer sink (one function, additive).** Every provider funnels through
`_write_mechanical_graph_json` (`recon_prepass.py:2134`), which today serializes
`{source, var_refs, functions}` at the `recon_prepass.py:2150` dict literal. The
CPG producer adds the four keys at that literal and documents their shapes in the
schema-contract docstring (`recon_prepass.py:2136-2146`). Every current caller
passes only the four legacy args, so the new keys are opt-in per producer.

**EVM producer call.** `_bake_evm_slither_graph` (`recon_prepass.py:2167`) already
walks `sl.contracts → functions_declared`, harvesting reads/writes/callees, and
calls `_write_mechanical_graph_json(scratch, "slither", var_refs, functions)` at
`recon_prepass.py:2286`. SlithIR/dataflow is already in-process here — this is the
natural EVM insertion point (no new CLI tool). Compute the four dicts and pass them
at the `:2286` call.

**Access-guard heuristic replaced.** The current permissionless-setter detector is
a regex "body guard near top of function" proxy
(`recon_prepass.py:465-484`, `_SOL_BODY_GUARD_RE`), whose own comment admits
false-negatives on guards not near the top. Its downstream consumer is the
LLM-enriched `state_write_map.md` **"Access Guard" column**, parsed at
`chain_prep.py:159` (`_parse_state_write_map`, L155-191). The dominator-based
`guards` key fills that column mechanically and retires the regex proxy.

**Consumer reader (single, additive).** All derivers load the graph through one
reader, `_load_graph` (`enumeration_gate.py:147`), which validates **only**
`var_refs` + `functions` (`:155`). Additive keys pass through untouched; a consumer
opts in with `graph.get("taint_edges", {})`. Consumers that light up:

| Deriver | Anchor | What the CPG sharpens |
|---|---|---|
| **G1** enumeration obligations | `enumeration_gate.py:191` (`compute_enumeration_obligations`) | co-reference "both touch var X" → "value from A **flows to** a sink in B" via `taint_edges` |
| **G2** coverage-gap emission | `enumeration_gate.py:282` (`validate_enumeration_coverage`) | `typed_sinks` classifies an ENUMGAP (stale-read vs bricked-consumer vs fund-sink) instead of generic prose |
| **M1** invariant-assertion falsifier | `enumeration_gate.py:1266` | `guards` tells the falsifier whether the committed local guard actually dominates the locus |
| **M2** hot-set + axis coverage | `enumeration_gate.py:1550` / `:1772` | new mechanical "untrusted-input-reaches-sink" axis marked EXAMINED/GAP from `reachability`+`taint_edges`, not only agent tags |
| **Gate V** variant/sibling | `enumeration_gate.py:1177` (driver `plamen_driver.py:3982`) | typed-sink confirmation that symmetric (deposit/withdraw) and boundary pairs move the same tainted value |
| **chain_prep** candidate pairs / 5-actor | `chain_prep.py:921` / `:159` | def-use reachability replaces name-string matching; `guards` fills the Access-Guard column |

The gate orchestrator `run_enumeration_gate` (`enumeration_gate.py:2181`, driver
`plamen_driver.py:16444`/`:16675`) needs no change — it already sequences G1 → G2 →
shape derivers → M1.

**Why it's ecosystem-agnostic.** The consumer layer is tag/prose-based, confirmed
in-code: `_write_mechanical_graph_json` docstring calls the artifact "ecosystem-agnostic,
LLM-unclobberable" (`recon_prepass.py:2136-2137`); axis detectors carry "zero
ecosystem-specific tokens" (`enumeration_gate.py:417-419`, `CHANGELOG.md:17`); the
single reader has no ecosystem branch (`enumeration_gate.py:155`); one deriver body
runs across sol/rust/move/go via a `.get()`-degrading `_LANG` registry
(`enumeration_gate.py:433`). New producer keys light up every ecosystem uniformly
with zero per-consumer coupling.

---

## 6. Rough structure of the change

**New producer code (`recon_prepass.py`)** — mirrors the existing bake contracts:

- A new in-process EVM helper, `_compute_evm_cpg_enrichment(sl) -> tuple[dict, dict, dict, dict]`, returning `(taint_edges, guards, typed_sinks, reachability)`, called inside `_bake_evm_slither_graph` and passed at the `:2286` write. Reuses the spike's proven APIs: `node.dominators`, `is_dependent`, SlithIR op classes.
- For the L1/SCIP path, a future CLI bake `_bake_go_ssa_cpg(scratch, proj) -> str` mirrors `_bake_go_scip` (`recon_prepass.py:2063`): `shutil.which` guard + `go.mod` guard + `_run_hardened` subprocess + `WRITTEN|REUSED|SKIPPED|FAILED` status string, registered at the driver pre-breadth hook (`plamen_driver.py:13020`). **Deferred to Phase 2** (§8); the seam is documented now so the schema is designed for it.

**Additive `_mechanical_graph.json` schema** (new keys only; legacy keys unchanged):

```jsonc
{
  "source": "slither",
  "var_refs":  { /* unchanged */ },
  "functions": { /* unchanged */ },

  // --- NEW (all optional; consumers read via graph.get(...)) ---
  "cpg_meta": {
    "producer": "slither-cpg",
    "slither_version": "0.11.5",
    "precision": { "taint": "intra_contract", "guards": "intra_procedural",
                   "typed_sinks": "full", "storage_flow": "partial" }
  },

  "typed_sinks": {
    // "<qualified fn>": [ { "site": "file:Ln", "expr": str,
    //                       "sinkTypes": ["EXTERNAL_CALL","STATE_WRITE",...] } ]
  },

  "guards": {
    // "<qualified fn>": {
    //   "writes": [ { "var": "<bare>", "site": "file:Ln",
    //                 "validationDominates": true|false,
    //                 "dominatingGuards": ["require(msg.sender==owner)"] } ]
    // }
  },

  "taint_edges": [
    // { "fn": "<qualified fn>", "source": "param:target"|"msg.sender"|...,
    //   "via": str, "sink": "EXTERNAL_CALL"|..., "site": "file:Ln",
    //   "confidence": "full"|"partial" }
  ],

  "reachability": {
    // "<sink site file:Ln>": {
    //   "entryPoints": ["<qualified fn>", ...],   // backward slice ∩ entry points
    //   "actorCategories": ["external","semi_trusted","natural","event","user_seq"]
    // }
  }
}
```

Descriptors keep the existing `"BareName (file:line)"` / bare `file:line` form so
old prose-diff consumers are untouched.

**Consumer edits (`enumeration_gate.py`)** — small, additive, `.get()`-guarded:

- G1 `compute_enumeration_obligations` (`:191`): when `taint_edges` present, upgrade a co-reference obligation to a taint-reachability obligation; else keep today's var-ref co-occurrence.
- G2 `validate_enumeration_coverage` (`:282`): when `typed_sinks` present, tag the emitted `ENUMGAP` block with the sink class; else keep generic prose.
- M1 `compute_invariant_assertion_candidates` (`:1266`): when `guards` present, gate the "asserted but not falsified" branch on the dominance flag.
- M2 `compute_axis_coverage_gaps` (`:1772`): add one `_AXES` entry reading `graph.get("taint_edges")` for an "untrusted-input-reaches-sink" axis.
- `chain_prep._parse_state_write_map` (`chain_prep.py:155`): prefer the mechanical `guards` value for the Access-Guard column when present, over the LLM-enriched column.

**Gate conventions (mandatory).** Every edit is **additive** (new keys only),
**idempotent** (re-running the bake overwrites deterministically; freshness reuse
like `_scip_bake_is_fresh`), and **no-op-on-absent-input** (missing keys → today's
behavior exactly; the producer never halts the pipeline — `WRITTEN|REUSED|SKIPPED|FAILED`,
best-effort, haltless-by-design).

**Tests to add:**

1. **Producer unit** — the spike fixture `Sample.sol` becomes a committed test:
   assert `setConfigGuarded.validationDominates == true`, `bumpCounter == false`,
   `forward` taint edges to EXTERNAL_CALL, `withdraw` typed sinks
   `{EXTERNAL_CALL, STATE_WRITE}`. Deterministic-hash assertion.
2. **Schema back-compat** — a graph with the four new keys still passes
   `_load_graph` (`:155`); a graph *without* them still passes (no-op path).
3. **Consumer no-op** — G1/G2/M1/M2 produce byte-identical output on a legacy
   graph (no new keys) vs. today.
4. **Consumer light-up** — on an enriched graph, G1 emits a taint-reachability
   obligation and M1 flips an "asserted-not-falsified" row to a dominance check.
5. **Idempotency** — two bakes → identical `_mechanical_graph.json`.

---

## 7. Pros / Cons & Risks

### Pros
1. **Deterministic recall on mechanical FN classes.** Reachability, taint→sink, guard-dominance, and def-use matching are exactly today's LLM+grep tasks; a graph query cannot suffer attention saturation → closes FM-1 on its highest-value class (access-control-reachable-without-guard).
2. **Reuses the existing bake + deriver architecture.** Additive keys in one file that every consumer already `json.load`s; old prose-diff consumers keep working. No new consumer scaffold.
3. **Per-language producers behind one consumer.** EVM ships first with zero new heavyweight engine; the consumer wiring is written once and reused for Go/Rust later.
4. **Grounds a citation the pipeline already makes.** Supplies the CPG slice LLMxCPG proves works (15–40% F1, robust to mutation) — the fix `enumeration_gate.py` already names.
5. **EVM path is near-free.** Slither already computes SSA data-dependency and dominators; we just aren't surfacing them.

### Cons
1. **EVM-first only.** Real coverage at launch is one ecosystem. Go is mature but L1-only; Rust is medium; Move/DAML have no frontend — the largest structural blind spots by ecosystem stay open.
2. **Slither is intra-contract-biased.** `data_dependency` is field/alias-imperfect; **cross-contract `STORAGE_FLOW` is precisely where Slither is weakest** (`evidence_slither_spike.md`: PARTIAL, needs inter-procedural work) — so the flagship cross-contract class is the least precise on the first frontend. We ship it labeled `precision: partial`, not as ground truth.
3. **Maintenance & latency.** Each frontend is an external engine to track (Slither versions). The bake adds recon wall-clock and must stay off the depth/verify hot path (frozen artifact).

### Risks & guardrails
1. **Schema-license entanglement (design-time, avoidable).** Do **not** copy the cpg-oracle proprietary schema; its eval license forbids building/benchmarking a competing tool and redistributing schema/enrichment values. **Design from the open Joern CPG spec + LLMxCPG.** The *concepts* (typed sinks, `validationDominates`, cross-contract storage flow, field-sensitive taint) are standard CPG art and free to reimplement; the specific proprietary artifact is not. Our key names (`taint_edges`/`guards`/`typed_sinks`/`reachability`) are chosen independently.
2. **Overselling internally — the hard boundary.** A CPG is a **structural** engine. It raises recall on reachability/taint/guard/def-use and does **nothing** for material-harm, severity (Rule 10), by-design (Rule 13), oracle adequacy (Rule 16), external behavior (Rule 1/3), or PoC harm assertion. The semantic core stays LLM + PoC. If framed as "finding bugs," it will be blamed for semantic misses it never claimed. Document it as a **recall producer for mechanical FN classes — never a bug-finder.**
3. **Frontend build failures.** Same class as the existing Slither fail-fast — an unbuildable target yields no CPG tier and degrades to today's behavior; never blocks the audit.
4. **Precision honesty in-band.** Every emitted fact carries a `precision` marker; consumers must treat `partial` taint/storage-flow as a *lead to ground an obligation*, not a verified edge — consistent with the oracle's own honest "a lead for a human, never a confirmed exploit."

---

## 8. Generalization & phased rollout

Architecture: **per-language producers behind one consumer.** Each ecosystem needs
its own frontend to emit the four keys; all downcast into the same additive schema,
so the consumer wiring (§5, §6) is written once. Per-ecosystem substrate readiness
(`evidence_generalization.md`):

| Phase | Ecosystem | Substrate | Verdict |
|---|---|---|---|
| **1 (this PR)** | **EVM / Solidity** | Slither SlithIR-SSA + `data_dependency` + `node.dominators` | **READY — ship first.** Local, already running; surface unused analyses. |
| **2** | **Go / L1 node-clients** | `go/ssa` + `go/callgraph` (CHA/RTA/VTA) + `go/pointer`; Joern `gosrc2cpg` | **MOST MATURE.** Production-grade SSA/callgraph/pointer *and* a maintained CPG frontend. Slots into the `_bake_go_scip` seam (`recon_prepass.py:2063`, driver `:13020`); SCIP today gives **reference graphs only — no dataflow** (`scip_reader.py` has only `find_definition`/`find_references`/`workspace_symbol`; Opengrep taint is intra-file, "inter-file taint gap documented openly", `docs/l1-mode/design.md:307`). CPG replaces the file-co-occurrence callee **heuristic** at `recon_prepass.py:2738-2772`. |
| **3** | **Rust / Solana · Soroban · L1** | rustc MIR + rust-analyzer/SCIP + CodeQL-Rust (GA 2.23.3, Oct-2025) | **MEDIUM — assemble-it-yourself.** No Joern Rust frontend; MIRAI orphaned. Prefer rust-analyzer/SCIP + CodeQL-Rust. Phase-3. |
| **4** | **Move / Aptos · Sui** | MoveScan / MoveScanner (research: bytecode → stackless IR + CFG + dataflow) | **EMERGING.** Substrate demonstrated in papers, no stable embeddable frontend. Today Move is regex-only (`_bake_move_graph`) — biggest structural blind spot, but research-dependent. |
| **—** | **DAML** | None | **NO PATH.** Stays on the tag/prose regex tier indefinitely. Explicitly out of scope. |

Rollout gate: **land EVM, prove the consumer wiring against recall benchmarks**
(model-routing/recall changes require validation per orchestrator rules), then stage
Go and Rust against the same schema. Move and DAML are scoped out until a stable
frontend exists.

---

## 9. Open questions (for reviewers)

1. **Prefer-graph vs. reconcile.** Where the mechanical `guards` value and the
   LLM-enriched Access-Guard column disagree, do we (a) prefer the graph
   unconditionally, (b) prefer graph only when `precision: full`, or (c) surface
   both and let chain_prep flag the disagreement as an obligation? (Proposed: c —
   disagreement is signal.)
2. **Reachability actor-category mapping.** The Rule 12 5-actor table needs
   entry-point → actor-category classification (external/semi-trusted/natural/event/user-seq).
   How much of that is mechanical (visibility + modifier) vs. still LLM?
3. **Cross-contract `STORAGE_FLOW`.** Ship it PARTIAL now as a grounding lead, or
   withhold until inter-procedural def-use plumbing closes the gap? (Proposed: ship
   PARTIAL, labeled, as a lead only.)
4. **Bake cost budget.** Acceptable added recon wall-clock for the enrichment on a
   large (59-contract-class) target? Freshness-reuse threshold?
5. **Taint source set.** Is params + `msg.sender`/`msg.data`/`tx.origin`/`msg.value`
   the right default source set, or do we add storage-var laundering sources
   (coarser contract-level dependency map)?
6. **Axis-coverage interaction.** Does a new mechanical taint axis risk
   double-counting against existing agent-tag axes in M2, and how do we dedup?

---

## 10. Out of scope

This PR does **NOT**:

- add or connect the hosted `solq.dev` CPG MCP oracle, or any hosted CPG service;
- copy, vendor, or benchmark against the proprietary cpg-oracle schema/enums/labels (design is from open Joern spec + LLMxCPG only);
- ship Go, Rust, Move, or DAML producers (Phase 2+; seams documented, code deferred);
- claim to find bugs, assess severity, judge material harm, adjudicate by-design behavior, evaluate oracle adequacy, or model external-contract behavior — the semantic/economic core stays LLM + PoC;
- change any consumer's output on a legacy (un-enriched) graph — every edit is no-op-on-absent-input;
- introduce a new heavyweight engine (Joern/JVM) into recon — EVM enrichment is in-process Slither, which Plamen already runs;
- alter the gate orchestrator sequencing, model routing, or any phase schedule.
