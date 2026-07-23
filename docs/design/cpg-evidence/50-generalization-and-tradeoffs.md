# Evidence: Cross-Ecosystem Generalization & Tradeoffs — CPG Dataflow Producer

**Purpose:** Grounding for the PR proposing a CPG (Code Property Graph) dataflow
producer for Plamen. This file answers three questions the PR must not hand-wave:
(1) *is there a real, per-language tool substrate to build a CPG frontend on?*,
(2) *what concrete security-research payoff does each CPG fact buy?*, and
(3) *what are the honest pros / cons / risks / rejected alternatives?*

**Scope discipline:** The proposal is a **producer behind one consumer** — it
bakes deterministic `taint_edges` / `guards` / `typed_sinks` / `reachability`
into the existing `_mechanical_graph.json` contract (integration point IP-1 from
`ASSESSMENT.md`). It is **not** a bug-finder and must never be sold as one (§3).

**Method:** Web-grounded 2026-07-23 against primary sources (Joern docs, Slither
wiki, golang.org/x/tools, GitHub CodeQL changelogs, USENIX '25 + ISSTA '24
papers). Builds on the three prior scratchpad assessments:
`ASSESSMENT.md`, `cpg_oracle_profile.md`, `plamen_capability_gaps.md`.

---

## 1. Per-ecosystem CPG frontend readiness

The proposal's architecture is **per-language producers behind one consumer**:
each ecosystem needs its own frontend to emit the four CPG fact-keys, but they
all downcast into the same additive `_mechanical_graph.json` schema, so one
consumer (enum-gate G1/G2, chain_prep, Scanner-C/Validation-Sweep worklists)
lights up for whichever frontends exist. Readiness therefore varies **per
ecosystem**, and the PR should ship EVM first and stage the rest.

### Readiness table

| Ecosystem (Plamen targets) | Concrete tool substrate for a CPG frontend | What it natively provides | Missing / gap | Maturity verdict |
|---|---|---|---|---|
| **EVM / Solidity** | **Slither** `SlithIR` (SSA form, <40 instrs) + `slither.analyses.data_dependency` (`is_dependent`/`get_dependencies`) + per-node **dominator tree** (`node.dominators`) | SSA def-use, data-dependency, CFG dominance, call graph, inheritance/override, storage layout — everything the four fact-keys need, **already run locally** by Plamen's `slither-mcp` | Slither precision is intra-contract-biased; `data_dependency` is field/alias-imperfect; cross-contract taint is weaker | **READY (ship first).** No new engine — surface analyses Slither already computes but Plamen doesn't emit. |
| **Go / L1 node-clients** | Std `golang.org/x/tools`: **`go/ssa`** (SSA IR), **`go/callgraph`** (static/CHA/**RTA**/**VTA**), **`go/pointer`** (points-to) + **Joern `gosrc2cpg`** (first-party Go CPG frontend) | Compiler-grade SSA, interprocedural call graph with points-to, AND a turnkey CPG frontend — two independent paths to the same facts | Go is not a smart-contract target per se; L1-only. Joern adds a JVM footprint if used | **MOST MATURE.** Best-supported ecosystem: production-grade first-party SSA/callgraph/pointer *plus* a maintained Joern frontend. Plamen already bakes SCIP for Go/Rust. |
| **Rust / Solana · Soroban · L1** | **rustc MIR** (analyzer-friendly IR); **MIRAI** (MIR abstract interpreter — interprocedural taint/value flow); **Rudra** (HIR+MIR hybrid, memory-safety); **MirChecker** (MIR static analysis); **rust-analyzer** (already used by Plamen for SCIP); **CodeQL Rust** (public preview 2.22.1 Jun/Jul-2025 → **GA 2.23.3 Oct-2025**) | MIR-level dataflow/taint (MIRAI), SSA-ish IR, symbol/xref (rust-analyzer/SCIP), and a now-GA CodeQL dataflow library | **No Joern Rust frontend.** MIRAI is **orphaned** (sponsor disbanded). No single turnkey Rust→CPG path; must compose MIR + a dataflow layer | **MEDIUM.** Substrate exists and CodeQL Rust just reached GA, but it's assemble-it-yourself: no maintained turnkey frontend, MIRAI unmaintained. Viable Phase-2. |
| **Move / Aptos · Sui** | **MoveScan** (ISSTA '24: bytecode → stackless IR + **CFG + dataflow**, 8 defect types, 98.85% precision); **MoveScanner** (arXiv 2508.17964, CFG+dataflow); **Move Prover** (formal verification, but 6.02% recall) | Bytecode-level CFG + dataflow IR exists in research tools; Prover gives spec-level proofs | Research-grade, not productized libraries with stable APIs; Prover is verification-not-CPG and low-recall for discovery | **EMERGING.** CFG+dataflow substrate demonstrated in papers but no stable, embeddable frontend. Today Plamen's Move tier is regex-only (`_bake_move_graph`) — the largest *structural* blind spot. |
| **DAML** | **None.** No CPG/dataflow frontend, no SSA IR toolchain, no equivalent research substrate | — | Everything | **NONE.** DAML stays on the regex tier indefinitely; no CPG path exists to propose. |

### Row-level citations

- **EVM/Slither:** SlithIR uses SSA form with a reduced (<40) instruction set;
  "SSA is a key component for building an efficient data-dependency analysis …
  explicit def-use chains enable precise propagation of value and control
  dependencies." (crytic/slither wiki: *SlithIR-SSA*, *data-dependency*;
  Slither paper arXiv:1908.09878). Dominator info per node (`node.dominators`)
  is standard SlithIR — the guard-dominance substrate.
- **Go:** `go/ssa` provides an SSA IR "for use by analysis tools"; `go/callgraph`
  ships static/CHA/RTA/VTA algorithms; `go/pointer` provides points-to for
  callgraph construction (pkg.go.dev, golang.org/x/tools). Joern lists
  `gosrc2cpg` (Golang) as a first-party frontend (docs.joern.io/frontends).
- **Rust:** MIRAI = "Rust mid-level IR Abstract Interpreter … interprocedural
  analysis that tracks how values flow through function calls … taint
  propagation," but "became orphaned when the sponsoring organization was
  disbanded" (facebookexperimental/MIRAI). Rudra = HIR+MIR hybrid, 43k crates,
  264 bugs (RUDRA paper). CodeQL Rust: public preview in **2.22.1 (2025-07-02)**,
  generally available in **2.23.3 (2025-10)** (github.blog changelogs). Joern
  frontend list contains **no Rust** (docs.joern.io/frontends).
- **Move:** MoveScan "translates Move bytecode into stackless intermediate
  representation and generates Control Flow Graph … shares the underlying
  control flow and data flow analysis infrastructure," 98.85% precision vs Move
  Prover's 6.02% recall (ISSTA 2024; arXiv:2508.17964 MoveScanner).
- **DAML:** no source found; consistent with `plamen_capability_gaps.md` (DAML
  has only the regex `_bake_daml_graph` tier).
- **LLMxCPG:** CPG-guided slice construction "reduces code size by 67.84 to
  90.93% while preserving vulnerability-relevant context … 15–40% improvements
  in F1-score … robust detection efficacy under various syntactic code
  modifications" (arXiv:2507.16585, USENIX Security '25) — the paper
  `enumeration_gate.py` already cites.

**Readiness ordering for the PR roadmap:** Go (most mature) and **EVM (ship
first, because it's local and already running)** → Rust (medium, Phase-2) →
Move (emerging, research-dependent) → DAML (no path). The PR should land EVM,
prove the consumer wiring, then stage Go/Rust; explicitly scope Move/DAML *out*.

---

## 2. Security-research payoff: which vuln classes each CPG fact mechanizes

Each CPG fact-key replaces an **error-prone LLM/grep task** with a deterministic
graph query, and each directly attacks one of Plamen's two documented recall
failure modes:

- **FM-1 — attention saturation / early returns:** the LLM, reading long
  contracts, drops a writer/consumer/path and silently returns "no path"
  (`docs/architecture.md:99` — the re-scan phase exists *specifically* to counter
  attention saturation). A mechanical enumeration cannot get bored.
- **FM-2 — wasted verify budget:** unguided depth/verify agents burn budget on
  findings that a structural query would have pre-filtered or pre-grounded.
  LLMxCPG's core result — 67.84–90.93% slice reduction while preserving
  vuln-relevant context — is exactly "spend the model's budget only on the
  relevant slice."

| CPG fact | Vuln classes it mechanizes | Plamen task replaced | Failure mode hit |
|---|---|---|---|
| **`validationDominates`** (a require/assert/revert dominates the write on all CFG paths) | Missing/bypassable access control on privileged state writes; guard-coverage asymmetry (writer A gated, sibling writer B not) | Scanner C CHECK 8, Validation Sweep CHECK 2/3 (LLM hand-builds guard tables — NEVER-CUT per orchestrator Rule 13a); Rule 2 / Rule 8 | **FM-1**: guaranteed enumeration of *every* writer + its dominating guard set; no dropped sibling writer |
| **taint → typed-sink** (source→sink dataflow with an 8-value sink class: EXTERNAL_CALL, DELEGATECALL, STATE_WRITE, REVERT, …) | Arbitrary external call / tainted delegatecall; unchecked user input into value/target; oracle/`msg.value` into division | depth-templates step 6 (grep fallback for source-consumption); tainted-arg reasoning | **FM-1 + FM-2**: forward slice enumerates *all* consumers and ranks worst sink → depth agent gets a grounded worklist, not a grep guess |
| **cross-contract `STORAGE_FLOW`** (state var written in contract A, read in contract B) | Cross-contract state-desync; write-in-one/read-in-another trust gaps; the class single-contract analysis (incl. Slither's intra-contract bias) misses entirely | phase4c Agent 2 def-use matching (currently name-string/grep — misses struct fields, aliases, getters) | **FM-1**: makes B's def→A's use a graph edge, killing both alias-FN and name-collision-FP |
| **`SINK_CHAIN` / CEI** (two sinks sharing taint sources; state-write-after-external-call ordering) | Reentrancy (state write after external call); cross-function CEI violations; sequential-external / oracle-trust chains | depth step 3 callback-exit ordering; Rule 3 side-effects (LLM orders statements by reading) | **FM-2**: CEI-violation candidates are pre-flagged, so verify budget targets the reentrancy-shaped set, not every external call |
| **`CALLS*` reachability** (bounded backward/forward slice over the resolved call graph, intersected with entry points) | Unreachable-guard / dead-capability; permissionless path to a privileged sink; the Rule 12 5-actor enabler table | phase4c Agent 1 STEP 0b (LLM freely writes "No path — because…", an admitted FN source); Scanner B/C inheritance-dispatch reachability | **FM-1**: the 5-actor reachability table becomes a mechanical entry→sink slice instead of a narrative guess |

**Tie to LLMxCPG (arXiv:2507.16585), which `enumeration_gate.py` already cites:**
LLMxCPG's thesis is that grounding an LLM in CPG-derived slices (a) *raises* F1
by 15–40% and (b) makes detection robust to syntactic mutation — i.e. the model
reasons over a **precise dataflow slice**, not the whole file. Plamen's own
`enumeration_gate.py` docstring names this paper and states the proven fix for
its dominant under-enumeration recall failure is grounding the required-set in an
external static-analysis graph. This producer *is* that grounding step:
`validationDominates` + typed-sink taint + `CALLS*` reachability construct the
required-set (the slice) that the enum-gate then hands to the model — attacking
FM-1 (nothing dropped) and FM-2 (budget spent only on the relevant slice) at
once. **The payoff is deterministic recall on mechanical FN classes, not a new
bug-finder** (see §3).

---

## 3. Honest PROS / CONS / RISKS / ALTERNATIVES

### PROS

1. **Deterministic recall on mechanical FN classes.** Reachability, taint→sink,
   guard-dominance, and def-use chain matching are exactly the tasks Plamen does
   today by LLM+grep (per `plamen_capability_gaps.md` Tier-1 G1–G7). A graph
   query cannot suffer attention saturation → closes FM-1 on its highest-value
   classes (access-control-reachable-without-guard is the most common
   high-severity FN).
2. **Reuses the existing bake + deriver architecture.** Lands as additive keys
   in `_mechanical_graph.json` (IP-1) behind the same fail-fast + frozen-artifact
   contract as Slither/SCIP. Every mechanical consumer already `json.load`s that
   one file, so old prose-diff consumers keep working (descriptors keep `bare` /
   `file:Ln` form). No new consumer scaffold needed — the pipeline already ships
   G1/G2, chain_prep, axis_coverage.
3. **Per-language producers behind one consumer.** EVM (Slither) ships first with
   zero new heavyweight engine; Go/Rust stage in later against the *same* schema;
   the consumer wiring is written once. Graceful degradation: an ecosystem with
   no frontend simply keeps today's regex/reference-graph behavior — the pipeline
   never blocks.
4. **Grounds a citation the pipeline already makes.** `enumeration_gate.py`
   already cites LLMxCPG as the fix; this producer supplies the slice that paper
   proves works (15–40% F1, robust to mutation).
5. **EVM path is near-free.** Slither *already computes* SSA data-dependency and
   dominators; Plamen just isn't surfacing them. Highest ROI, lowest new-code.

### CONS

1. **EVM-first only.** Real coverage at launch is one ecosystem. Go is mature but
   L1-only; Rust is medium and assemble-it-yourself; **Move and DAML have no
   frontend** — the largest *structural* blind spots by ecosystem stay open.
2. **Slither precision is intra-contract-biased.** `data_dependency` is
   field/alias-imperfect; cross-contract taint (the `STORAGE_FLOW` win) is
   precisely where Slither is weakest, so the flagship cross-contract class is
   the least precise on the first-shipped frontend.
3. **Maintenance & latency.** Each frontend is an external engine to track
   (Slither versions, rustc MIR churn, orphaned MIRAI). The bake adds
   wall-clock to recon; must stay off the depth/verify hot path (frozen
   artifact).
4. **Not a bug-finder — and must not be sold as one.** A CPG is a *structural*
   engine. It raises recall on mechanical FN classes and does **nothing** for
   material-harm judgment, severity calibration (Rule 10), by-design
   normalization (Rule 13), oracle adequacy (Rule 16), external-contract behavior
   (Rule 1/3), or PoC harm assertion (`plamen_capability_gaps.md` Tier-3). Even
   the cpg-oracle vendor is honest that a structural path "is a lead for a human,
   never a confirmed exploit."

### RISKS

1. **Schema-license entanglement (design-time, avoidable).** Do **not** copy the
   cpg-oracle proprietary schema. Its eval-only LICENSE §forbids "building/
   benchmarking a competing tool" and "redistributing the schema/enrichment
   values." **Design the Plamen schema from OPEN specs** — the Joern CPG spec
   (`cpg.joern.io`) and the LLMxCPG paper — not from the oracle's labels/enums.
   The *concepts* (typed sinks, `validationDominates`, cross-contract storage
   flow, field-sensitive struct taint) are standard CPG art and free to
   reimplement; the specific proprietary artifact is not.
2. **Overselling internally.** If the CPG layer is framed as "finding bugs," it
   will be blamed for semantic misses it never claimed. Guardrail: document that
   it raises recall on reachability/taint/guard/def-use and nothing else.
3. **Frontend build failures.** Same class as the existing Slither fail-fast — an
   unbuildable target yields no CPG tier. Must degrade to today's behavior, never
   block the audit (haltless-by-design).
4. **Rust substrate decay.** MIRAI is orphaned; leaning on it is a bet on
   unmaintained code. Prefer rust-analyzer/SCIP + CodeQL-Rust (now GA) if Rust
   is staged.

### ALTERNATIVES REJECTED

1. **Adopt the hosted cpg-oracle product.** *Rejected.* It is **DODO-only** (one
   frozen redacted demo graph, no ingestion path — cannot analyze a client
   target), currently **degraded** (0 query workers), **invite-only**, ~1-day-old
   single-anonymous-author repo, and **licensed against the exact production +
   benchmarking use Plamen needs.** It delivers none of its (real) power to a
   live audit; its only value is its schema as a *read-only design reference*
   (already public, no key needed) — see `cpg_oracle_profile.md` §1, §6–§8.
2. **Stand up full Joern as the CPG engine.** *Rejected for now (Phase-2
   stretch).* Joern has a first-party Go frontend but **no Rust, no Solidity, no
   Move frontend** (docs.joern.io/frontends — 12 frontends, none of them
   Solidity/Rust/Move). It is JVM-heavy with an uneven Solidity story, and would
   *not* close the biggest ecosystem blind spots. Reassess only if CFG-level or
   cross-language depth becomes the bottleneck after the Slither path ships.
3. **Stay LLM+grep (status quo).** *Rejected.* This is the documented FN source
   (Rule 12 "missing paths are coverage gaps"; depth-step-6 grep taint;
   phase4c name-string matching). The whole point is to mechanize it.

---

## Bottom line

The **idea** — a per-language CPG producer feeding the existing mechanical
consumer — is sound, wanted (the pipeline already cites LLMxCPG and ships the
consumer scaffold), and grounded in real per-ecosystem substrate. **Ship EVM
first on Slither's own unused SSA/dominator analyses; stage Go (most mature) and
Rust (medium) against the same schema; scope Move (emerging) and DAML (no path)
out.** Design the schema from open specs, keep it behind the fail-fast/frozen
contract, and frame it honestly as a **recall producer for mechanical FN
classes — never a bug-finder.**
