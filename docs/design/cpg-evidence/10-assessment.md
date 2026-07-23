# cpg-oracle vs. Plamen: Decision-Grade Assessment

**Date:** 2026-07-23
**Author:** Lead security-tooling architect (Plamen)
**Question:** Should Plamen adopt "cpg-oracle" (pitched as "an improved Slither") to expand its static/graph analysis capability?

---

## TL;DR

- **The pitch is wrong.** cpg-oracle is **not** "an improved Slither." Slither is a local analyzer you point at *any* codebase. cpg-oracle is a **hosted, proprietary, read-only Cypher query service** over **one pre-baked, redacted demo graph — the "dodo" cross-chain DEX**. It has **no ingestion path**: you cannot point it at a new audit target. That single fact disqualifies it as a production audit tool for Plamen, whose entire job is analyzing arbitrary client codebases.
- **The product is not adoptable.** Beyond the no-your-code blocker: the service is **currently degraded** (health check shows 0 query workers), access is **invite-only** (out-of-band `X-API-Key`, no public request/buy path), the repo is **~1 day old, single anonymous author (alias email), 0 stars/forks**, and the **eval-only license explicitly forbids production use, benchmarking, and building a competing tool** — the exact things Plamen would need to do.
- **But the IDEA is genuinely valuable and already wanted.** A true statement-level Code Property Graph (CFG + data-flow/taint + guard-dominance + typed sinks) maps *precisely* onto Plamen's documented un-served frontier. Plamen's own `enumeration_gate.py` docstring cites **LLMxCPG (USENIX '25, arXiv:2507.16585)** and states the only proven fix for its dominant under-enumeration recall failure is grounding the required-set in an external static-analysis graph. Plamen already ships the *consumer scaffold* (`_mechanical_graph.json`, G1/G2, chain_prep) — it is missing the *statement-level graph* that would feed it.
- **Recommendation: reject the product; adopt the idea locally.** Do **not** wire in the hosted oracle (except, optionally, a zero-key afternoon reading its already-public schema for design ideas). Instead, **build the CPG capability into the existing `slither-mcp` using Slither's own SlithIR data-dependency + dominator-tree analyses**, baking `taint_edges` / `guards` / `typed_sinks` / `reachability` into `_mechanical_graph.json` (integration point **IP-1**). This is the lowest-risk, highest-ROI path, works on every EVM target, reuses the fail-fast + frozen-artifact contract Plamen already has, and directly fills the LLMxCPG grounding the pipeline already asks for. Evaluate a local **Joern**-class general CPG as a Phase-2 stretch for cross-language depth.

---

## 1. What cpg-oracle actually is (vs. the pitch)

| Dimension | The pitch ("improved Slither") | The reality (from cloning + probing) |
|---|---|---|
| Deployment | Implied: a better local analyzer | **Hosted-only** remote MCP endpoint `https://solq.dev/api/v1/cpg/dodo/mcp`, `X-API-Key`-gated |
| What ships | Implied: a tool | A **~90 KB access kit**: 1 agent skill + 4 reference docs + a proprietary license. **No server code, no graph-builder, no CPG file.** |
| Analyzes your code? | Implied: yes | **NO.** One frozen, redacted graph (**dodo**, 59 contracts, 12,694 nodes / 39,811 edges). Endpoint path hardcodes `/cpg/dodo/`. No upload/load/build path in the kit or the 7 tools. |
| Bug finder? | Implied: finds bugs better | **Vendor-disclaimed.** README/SKILL/LICENSE §6 all state it answers *structural* questions, returns "a lead for a human," and "never asserts exploitability." Its own `dodo-findings.md` concedes formula/fee/economic bugs "a structural graph cannot prove." |
| Availability | — | **Degraded now**: `/health` shows `worker: down, 0 workers`. Access invite-only; no public key path; price undisclosed. |
| Maturity | — | Repo created 2026-07-22 (~1 day old), 2 commits, single author `mishoko` on alias email `cc.bankroll320@8alias.com`, 0 stars/forks/issues, zero web footprint, zero independent adoption. |
| License | — | Proprietary **Evaluation-only**, 30-day revocable, no production, no reverse-engineering, **no competing-tool build/benchmark**, no redistribution of schema/results, $100 liability cap. |

**Crux for adoption:** it **cannot analyze a new audit target — only the DODO demo graph.** Since Plamen audits arbitrary client code, the hosted oracle can never sit in the real pipeline. The only thing it can do is let you *experience the query surface* against a canned example — and even that is ~90% readable statically from the public repo (the kit ships 30 cookbook queries, 7 demo questions **with their live result rows already captured**, and 2 finding walk-throughs), so you can study it **without a key and without connecting.**

---

## 2. Capability comparison: CPG-oracle vs. slither-mcp vs. SCIP

The comparison worth having is **CPG-as-a-capability vs. Plamen's current structural stack** — not the hosted product, which delivers zero of its power to Plamen's targets.

| Capability | cpg-oracle (CPG + Cypher) | Plamen `slither-mcp` (Slither AST/IR) | SCIP (L1 Go/Rust only) |
|---|---|---|---|
| Runs on **your** target | **No** — DODO only | **Yes** — any Slither-parseable EVM project | Yes — Go/Rust node clients |
| Local / offline | No (hosted, key-gated) | **Yes** (local, cached to `project_facts.json`) | Yes (local index bake) |
| Call graph (callers/callees, reachability) | Yes (`CALLS`, bounded `*1..N`) | **Yes** (`get_function_callees/callers`, `export_call_graph`, `find_dead_code`) | Yes (2-hop call graphs, xref map) |
| Inheritance / type / override resolution | Yes (`INHERITS`, `IMPLEMENTS`) | **Yes** (`get_inherited/derived_contracts`, `list_function_implementations`) | Yes (`type_hierarchy.md`) |
| Storage layout / state-var inventory | Partial (VARIABLE nodes) | **Yes** (computed slot/offset/packing, `analyze_state_variables`) | No |
| Access-control / modifier map | Yes + enriched (`isAccessControl`, `isContractGated`, `isReentrancyGuard`) | Partial (`analyze_modifiers` = modifier→function; no dominance) | No |
| **CFG / basic blocks / statement order** | **Yes** (`CFG_BLOCK`, `CONTROL_FLOW`) | **No** | No |
| **Dominance / guard-dominance proof** | **Yes** (`DOMINATES`, `POST_DOMINATES`, `validationDominates`) | **No** | No |
| **Taint / data-flow paths (source→sink)** | **Yes** (`TAINT` w/ confidence, `DATA_FLOW`, field-sensitive `struct_field:*`, SSA) | **No** (co-occurrence only; taint done by LLM+grep) | No |
| **Typed sinks** (ext-call / delegatecall / state-write / revert…) | **Yes** (8-value `sinkType` enum) | Partial (`analyze_low_level_calls` inventories sites; not classified sinks) | No |
| Cross-contract storage/taint flow | **Yes** (`STORAGE_FLOW` with source/target contract) | Partial (call graph only) | Partial (xrefs) |
| Detector suite (reentrancy, CEI, etc.) | **No** (explicitly not a bug-finder) | **Yes** (`run_detectors`, ~90 Slither checks; + Aderyn, Opengrep 2107 rules, fender) | No (ast-grep panic/concurrency inventories only) |
| Ecosystem coverage | EVM (dodo only) | EVM | Go/Rust |
| Semantic / economic / exploitability | **No** (structural only) | No (LLM does this) | No |

**Where a true CPG is genuinely more powerful:** the four bolded rows — **CFG, dominance, taint paths, typed sinks**. These are exactly the analyses Plamen currently performs by **error-prone LLM reasoning (often falling back to grep)**: enabler enumeration (Rule 12 / phase4c Agent 1 backward reachability), postcondition→precondition chain matching (phase4c Agent 2 def-use, currently name-string matching), access-control reachability + guard-coverage (Scanner C CHECK 8, Validation Sweep CHECK 2/3 — flagged NEVER-CUT recall-critical), and tainted-source consumption enumeration (depth step 6, currently grep). A CPG mechanizes all four.

**Does the HOSTED oracle deliver that power to Plamen?** **No.** All of that power is real *in the schema/engine*, but it is frozen to the DODO graph and cannot touch a client codebase. Slither, by contrast, delivers its (lesser) power on every target. So on the axis that matters for a production auditor — **works on the code in front of you** — Plamen's local slither-mcp already beats the hosted oracle, despite the oracle's richer graph. **The oracle's value to Plamen is its schema design as a blueprint, nothing more.**

**Where slither-mcp/SCIP already match a CPG:** call graph, inheritance/type hierarchy, storage layout, override resolution, dead-code reachability. Plamen is *not* starting from zero — it has a coarse **function×symbol** reference graph (`_mechanical_graph.json`) plus a deterministic deriver/gate layer. The gap is strictly the **statement-level** tier (CFG + data-flow + dominance + typed sinks).

---

## 3. Separating the IDEA from the PRODUCT

| | **The IDEA** — a CPG backend for mechanical taint / reachability / guard-dominance | **The PRODUCT** — this specific hosted DODO oracle |
|---|---|---|
| Value to Plamen | **High.** Fills the documented un-served frontier; the pipeline already cites LLMxCPG and ships the consumer scaffold. | **~Zero for production.** Cannot analyze targets; degraded; invite-only; eval-license blocks the use Plamen needs. |
| Adoptable? | **Yes**, via local implementation (options b/c below). | **No.** At most a one-afternoon schema study (already public — no key needed). |
| Risk | Engineering effort + maintenance; must not oversell (see below). | License entanglement (competing-tool clause), vendor/service risk, single anonymous author, no continuity guarantee. |

**Do not oversell the idea, either.** A CPG is a **structural** engine. It fixes Tier-1 mechanical tasks (reachability, taint, guard-dominance, def-use chain matching) and **partially** helps Tier-2 (reentrancy ordering yes; flash-loan/donation profitability no). It does **not** touch Plamen's semantic/economic core: material-harm judgment, severity calibration (Rule 10), by-design/user-harm normalization (Rule 13), oracle adequacy (Rule 16), actual external-contract behavior (Rule 1/3), and PoC harm assertion. Those stay LLM + verification work. A CPG raises **recall on mechanical FN classes**; it is not a bug-finder and must never be sold internally as one — which, ironically, is the one thing the oracle vendor is honest about.

**License caution on the schema:** cpg-oracle's schema is published publicly but sits under an eval license forbidding "building/benchmarking a competing tool" and "redistributing the schema/enrichment values." If Plamen builds its own CPG, design the schema from **first principles / the open Joern CPG spec (`cpg.joern.io`) and the LLMxCPG paper**, not by copying cpg-oracle's labels/enums, to avoid any entanglement. The *concepts* (typed sinks, `validationDominates`, cross-contract storage flow, field-sensitive struct taint) are standard CPG art and free to reimplement; the *specific proprietary schema artifact* is not something to vendor.

---

## 4. Integration options (effort / risk), mapped to Phase-1 insertion points

All three options converge on the same anchor: **IP-1 — enrich `_mechanical_graph.json`** (`recon_prepass.py::_write_mechanical_graph_json`, L2134) with additive keys `taint_edges` / `guards` / `typed_sinks` / `reachability`. Every mechanical consumer (G1/G2 `enumgap_exploration`, M2 `axis_coverage`, `chain_prep`, function_summary obligation gate) already `json.load`s this one file, so enriching it lights up all of them at once, and old prose-diff consumers keep working because descriptors keep the same `bare` / `file:Ln` form.

### Option (a) — Wire the hosted oracle in as an MCP, eval-only
- **What:** `claude mcp add --transport http cpg-query-oracle …` with an issued key; query the DODO graph.
- **Maps to:** nothing in the real pipeline — it can only answer about DODO, so it never reaches a client target. At most a sandbox to study query ergonomics.
- **Effort:** Very low (config only) **but** requires obtaining an invite key (no public path) and the service is degraded (0 workers).
- **Risk:** License forbids benchmarking/competing-tool use — i.e. forbids exactly the comparative eval you'd run; single-vendor/anonymous continuity risk; results only about DODO.
- **Verdict:** **Reject** for production. Even the "study the query experience" goal is better served for free by reading the already-public cookbook/demo rows in the repo — no key, no license exposure.

### Option (b) — Build/adopt a LOCAL general-purpose CPG (Joern-class) as a new slither-mcp-peer server
- **What:** Stand up Joern (has a Solidity/EVM frontend) or a Fraunhofer-CPG-class engine as a new provider that bakes CPG artifacts to disk, joining Slither/SCIP/Move/DAML under the same fail-fast + `_mechanical_graph.json` contract in `recon_prepass`.
- **Maps to:** IP-1 (schema enrichment), IP-3 (a new `cpg/` prebake dir alongside `slither/` and `scip/`), then consumers IP-4/IP-5/IP-6/IP-11.
- **Effort:** **High.** Joern's Solidity frontend maturity is uneven; you own the CPG→`_mechanical_graph.json` mapping, the frozen-artifact bake (depth/verify run MCP-disabled), and a new fail-fast/fallback path. **Move (Aptos/Sui) and DAML have no CPG frontend at all** — so this does not close the biggest *ecosystem* blind spot without additional frontends.
- **Risk:** Medium-high — frontend coverage gaps, build failures (same class as Slither fail-fast), ongoing maintenance of a heavyweight external engine, JVM/tooling footprint.
- **Verdict:** **Phase-2 stretch.** Worth a scoped evaluation *after* option (c) proves the consumer wiring, especially if cross-language depth or CFG-level analysis becomes the bottleneck.

### Option (c) — Port the QUERY PATTERNS into the existing slither-mcp using SlithIR + dominators  ★ recommended
- **What:** Extend `slither-mcp` with a handful of new tools/bake-steps built on Slither's **own** semantic analyses that already exist but Plamen doesn't surface:
  - **Taint / def-use:** `slither.analyses.data_dependency` (`is_dependent`, `get_dependencies`) → `taint_edges` and def-use chain edges (fixes phase4c Agent 2 name-string matching, depth-step-6 grep taint).
  - **Guard-dominance:** SlithIR node **dominator tree** (`node.dominators`) + `require/assert/revert` and modifier predicates → per-write-site "dominated by access-control guard?" = `validationDominates`-equivalent (fixes Scanner C CHECK 8, Validation Sweep CHECK 3, Rule 2/8).
  - **Typed sinks:** classify existing external/low-level/delegatecall/state-write sites into a `sinkType` set (you already inventory them via `analyze_low_level_calls`).
  - **Backward reachability:** you already have the call graph — add a backward slice from a sink intersected with entry points → the Rule 12 / phase4c Agent 1 5-actor table.
- **Maps to:** **IP-1** (bake the four new keys) → **IP-4** enum-gate G1/G2 gains taint-reachable-sink + guard-dominance axes (the docstring's LLMxCPG grounding) → **IP-6** chain_prep replaces shared-state heuristic with def-use reachability and fills the STEP 0b 5-actor table → **IP-11** pre-fills Scanner C / Validation-Sweep worklists (discovery→confirmation) → IP-2/IP-3 add `Sink`/`Guard` columns to the frozen `state_write_map.md` / `function_summary.md`.
- **Effort:** **Medium.** Reuses Slither's cached `ProjectFacts`, the existing MCP server, the fail-fast probe, and the frozen-artifact bake. No new heavyweight engine, no JVM, no new fallback path.
- **Risk:** **Low-medium.** Bounded by Slither's own precision (intra/limited-inter-procedural; data_dependency is field/alias-imperfect) and EVM-only. But it degrades gracefully to today's behavior and never blocks the pipeline.
- **Verdict:** **Adopt first.** Highest ROI, lowest risk, works on every EVM target, and it delivers ~80% of the CPG value (taint + guard-dominance + typed sinks + backward reachability) using infrastructure Plamen already runs.

**Priority of consumers once IP-1 is enriched** (from Phase-1 ranking): (1) enum-gate G1/G2 taint/guard axes, (2) chain_prep taint pairs + 5-actor table (biggest chain-precision win), (3) axis-coverage CPG columns, (4) Scanner C / Validation-Sweep worklists, (5) depth-step-6 taint replacement.

---

## 5. Recommendation

**Reject cpg-oracle as a product. Adopt the CPG idea locally via Option (c): extend `slither-mcp` with SlithIR data-dependency + dominator-based taint/guard-dominance/typed-sink/backward-reachability, baked into `_mechanical_graph.json`.**

Rationale in one paragraph: the hosted oracle cannot analyze Plamen's targets (DODO-only, no ingestion), is degraded, invite-gated, one day old from an anonymous author, and licensed against the exact production/benchmarking use Plamen needs — so it delivers none of its (real) power to a live audit. Meanwhile the *capability* it demonstrates is precisely the statement-level frontier Plamen's own code already asks for (LLMxCPG grounding in `enumeration_gate.py`) and already has a consumer scaffold for. Slither can supply that frontier locally — its data-dependency and dominator analyses are unused by Plamen today — so the fastest, safest way to "expand Plamen" is to surface Slither's own semantics into the mechanical graph, not to rent a frozen demo graph.

---

## Next steps (ordered)

1. **Study the schema for free (0.5 day).** Read the already-public `schema-key.md` / `query-cookbook.md` / `demo-queries.md` in the cloned repo as a design reference for what enrichment keys to emit (`sinkType`, `validationDominates`, `STORAGE_FLOW` cross-contract, field-sensitive taint). Do **not** copy the proprietary schema verbatim; design from the open Joern spec + LLMxCPG. Do **not** obtain a key or connect the hosted MCP.
2. **Spike Slither's semantic analyses (2-3 days).** Prove out `slither.analyses.data_dependency` (`is_dependent`/`get_dependencies`) for taint/def-use and `node.dominators` + require/modifier predicates for guard-dominance on a couple of real EVM audit targets. Confirm precision is good enough to ground obligations.
3. **Design the additive `_mechanical_graph.json` enrichment (IP-1).** Specify `taint_edges`, `guards`, `typed_sinks`, `reachability` keeping `bare` / `file:Ln` descriptors so existing consumers are untouched. Land the producer in `recon_prepass.py` behind the same fail-fast contract as Slither/SCIP.
4. **Wire the two highest-ROI consumers first.** IP-4 (enum-gate G1/G2 taint-reachable-sink + guard-dominance axes — the LLMxCPG grounding the docstring already names) and IP-6 (chain_prep def-use pairs + STEP 0b 5-actor reachability table). Gate on recall benchmarks (model-routing changes require recall validation per orchestrator rules).
5. **Convert Scanner C / Validation-Sweep to confirmation (IP-11) + add Sink/Guard columns to frozen maps (IP-2/IP-3).** Pre-fill the reachability/guard-coverage worklists deterministically.
6. **Scope a Phase-2 Joern evaluation (Option b) only if needed.** Reassess after (c) ships: if CFG-level analysis or cross-language (Move/DAML/non-EVM) CPG coverage becomes the bottleneck, evaluate a local general-purpose CPG then — not before.
7. **Guardrail the framing.** Document internally that the CPG layer raises recall on mechanical FN classes (reachability/taint/guard/def-use) and does **not** address material-harm, severity, by-design, oracle-adequacy, or external-behavior reasoning — those remain LLM + verification work.
