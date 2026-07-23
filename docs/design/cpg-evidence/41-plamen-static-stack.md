# Plamen Static / Structural Analysis Stack — Inventory (as of 2026-07-23)

Scope: every static/structural analysis capability Plamen has **today**, read from
`/Users/ptsanev/.plamen`. Sources are cited inline. RAG (`unified-vuln-db`) and
dynamic tools (Foundry, fuzzers) are noted only where relevant to distinguish
"static" from "not static".

---

## 0. TL;DR

- Plamen's structural analysis is **Slither-AST-derived** for EVM, exposed through a
  vendored **trailofbits `slither-mcp`** server with **23 MCP tools** (structural
  queries + a detector wrapper).
- Pattern/regex scanning is provided by **Opengrep** (Semgrep-fork, SARIF) using a
  vendored rule corpus of **2107 YAML rules** (Solidity: 50 core + 67 Decurity +
  9 Aptos-Move + rust/go/etc.), run in a Python "recon prepass" → `opengrep_findings.md`.
- **farofino-mcp** adds **Aderyn** (Rust-based Solidity static analyzer) and a small
  regex `pattern_analysis` — its Slither wrapper is explicitly **banned** in favor of
  `slither-analyzer`.
- **solana-fender** wraps the Sec3 X-Ray ("fender") Solana detector.
- Cross-file **SCIP** indexing (`scip-go`, `rust-analyzer scip`) exists **only in L1
  mode** (Go/Rust node clients) — it gives real call graphs + xrefs + type hierarchy,
  surfaced as flat Markdown files and an `[LSP-TRACE]` evidence tag.
- **There is NO taint analysis, NO data-flow/def-use, NO dominance, NO code-property-graph,
  NO Joern anywhere.** Joern/CPG is an **explicit documented non-goal** (deferred to
  "Phase 2"): `docs/l1-mode/design.md:33, :324, :440`.

---

## 1. Each Static Tool + What It Does

### 1a. `slither-mcp` (vendored trailofbits) — PRIMARY EVM structural engine
Path: `custom-mcp/slither-mcp/`. MCP namespace used by agents: `mcp__slither-analyzer__*`.
Wraps Slither once, caches a `ProjectFacts` object to `<project>/artifacts/project_facts.json`,
and answers all queries from that cache (lazy load; if Slither fails once →
`SLITHER_AVAILABLE=false` for the whole audit, agents fall back to Read/Grep).
Registered tools are enumerated in `slither_mcp/tool_registry.py` (`TOOL_CONFIGS`,
23 entries). Everything is derived from Slither's AST/IR — the **only** detector-driven
tools are `list_detectors` / `run_detectors`.

**The 23 registered MCP tools** (`tool_registry.py:122-436`):

| # | Tool | Category | What it answers | Structural vs Detector |
|---|------|----------|-----------------|------------------------|
| 1 | `list_contracts` | Query | Contracts + type flags (abstract/interface/library), direct inheritance | Structural (AST) |
| 2 | `get_contract` | Query | Full contract metadata: functions, inheritance, state vars, events | Structural |
| 3 | `get_contract_source` | Query | Source of a contract (line range) | Structural |
| 4 | `get_function_source` | Query | Source of one function w/ line numbers | Structural |
| 5 | `list_functions` | Query | Function inventory filtered by contract/visibility/modifier | Structural |
| 6 | `get_function_callees` | **Graph** | Outgoing call edges: internal / external(high-level) / library, + low-level flag | Structural call graph (AST) |
| 7 | `get_function_callers` | **Graph** | Incoming call edges (inverse of callees), by call type | Structural call graph |
| 8 | `get_inherited_contracts` | **Graph** | Recursive parent/ancestor inheritance tree (upward), `max_depth` | Structural (inheritance DAG) |
| 9 | `get_derived_contracts` | **Graph** | Recursive child/descendant tree (downward) | Structural |
| 10 | `list_function_implementations` | Query | All contracts implementing a signature (override/polymorphism) | Structural |
| 11 | `list_detectors` | Security | Lists Slither detectors + impact/confidence metadata | **Detector meta** |
| 12 | `run_detectors` | Security | Cached Slither detector findings, filter by name/impact/confidence/path | **Detector-based** |
| 13 | `search_contracts` | Search | Regex over contract names | Structural |
| 14 | `search_functions` | Search | Regex over function names/signatures | Structural |
| 15 | `get_project_overview` | Query | Aggregate stats: counts by type/visibility, findings by impact | Structural + detector counts |
| 16 | `find_dead_code` | **Graph** | Functions with **no callers** (call-graph reachability); excludes entry points/test/inherited | Structural (call-graph, NOT the Slither dead-code detector) |
| 17 | `export_call_graph` | **Graph** | Whole-project call graph as **Mermaid or DOT**; filter by contract/entry-points-only, include external/library edges, `max_nodes` | Structural call-graph export |
| 18 | `get_contract_dependencies` | **Graph** | Per-contract deps: inheritance + external calls + library usage, **circular-dependency detection** | Structural dependency graph |
| 19 | `analyze_state_variables` | Query | State-var inventory (type/visibility/location), filter constants/immutables | Structural |
| 20 | `get_storage_layout` | Structural | **Computed storage slot layout**: slot#, byte offset, size, packing; incl./excl. inherited storage | Structural (tool computes slots from a Solidity type-size table, not a detector) |
| 21 | `analyze_events` | Query | Event defs, indexed params, locations (defs only, not emissions) | Structural |
| 22 | `analyze_modifiers` | **Access-control map** | Modifier definitions + **which functions use each modifier** | Structural |
| 23 | `analyze_low_level_calls` | **Security-structural** | All functions using `call`/`delegatecall`/`staticcall`/assembly, grouped by type + location | Structural (AST scan for reentrancy/proxy analysis) |

Notes:
- Call graph is built from Slither IR call sets: `internal_calls`, `library_calls`,
  `high_level_calls` (external), `low_level_calls` (`callees.py:21-45`). It is a
  **static call graph**, resolved per-signature; it does **not** resolve dynamic dispatch
  targets beyond signature match and does not recurse (call repeatedly to go deeper).
- `find_dead_code` is *reachability over the call graph* (no callers), distinct from the
  Slither `dead-code` detector.
- `get_storage_layout` is computed inside the MCP tool from a hardcoded type-size table
  (`get_storage_layout.py`), giving upgrade/collision analysis without needing solc's
  `--storage-layout`.
- Tool-name drift: some agent tool-allowlists and the README/CLIENT_USAGE reference
  `list_function_callees` / `list_function_callers`; the live registry names are
  `get_function_callees` / `get_function_callers`. Both implementation files exist
  (`tools/list_function_callees.py`, `tools/list_function_callers.py`).

### 1b. Opengrep (vendored rule corpus) — pattern/regex-AST scanner
Path: `opengrep-rules/` (3 rule sets, **2107 YAML rules** total).
- `opengrep-rules/opengrep-rules/` — upstream multi-language corpus (solidity: 50 rules
  under best-practice/performance/security; plus go, rust, python, js/ts, java, etc.).
- `decurity-rules/` — Decurity smart-contract rules (solidity: 67, plus cairo, rust).
- `aptos-move-rules/` — Aptos Move rules (9).
Opengrep is a Semgrep-fork producing SARIF. It is run by the **Python recon prepass**
(not by an LLM) and results land in `{SCRATCHPAD}/opengrep_findings.md` /
`opengrep_hits.json`. Recon/depth agents read those and append under `## OpenGrep Findings`,
and there is a whole **obligation-receipt** system (`_check_opengrep_obligation_coverage`,
per-row `[OBLIG:opengrep_findings.md:<row#>]` receipts) to guarantee every Opengrep hit is
triaged. Purely syntactic/AST-pattern matching — **no taint, no dataflow**.

### 1c. `farofino-mcp` — Aderyn + regex patterns (COMPLEMENT only)
Path: `custom-mcp/farofino-mcp/`. Tools: `slither_audit`, `aderyn_audit`, `pattern_analysis`,
`read_contract`, `check_tools`.
- `aderyn_audit` → **Aderyn** (Cyfrin's Rust-based Solidity/Vyper static analyzer) — an
  independent detector engine, approved as a complement.
- `pattern_analysis` → tiny regex checker (selfdestruct, delegatecall, tx.origin, missing
  SafeMath, block.timestamp, naive reentrancy).
- `mcp__farofino__slither_audit` is **explicitly PROHIBITED** as a Slither substitute
  (`prompts/evm/mcp-tools-reference.md:9, :109`) — only `mcp__slither-analyzer__*` is
  approved for Slither; only farofino's `aderyn_audit` + `pattern_analysis` are allowed.

### 1d. `solana-fender` — Sec3 X-Ray Solana detector
Path: `custom-mcp/solana-fender/`. Tools: `security_check_program` (whole program dir),
`security_check_file` (single file). Shells out to the `fender` binary (Sec3 X-Ray). Wired
into Solana depth agents (`agents/depth-state-trace.md`, `depth-token-flow.md` tool lists).
Detector/pattern-based; not a graph/taint engine.

### 1e. SCIP indexing — L1 mode ONLY (Go/Rust node clients)
Path/spec: `prompts/l1/phase05-bake.md`. Runs **before** recon in L1 mode:
- `scip-go` → `scip_go.index`; `rust-analyzer scip` → `scip_rust.index` (reused if large &
  <24h old; failure → degrade to Grep). Status in `primitive_status.md`.
- A Python `plamen_l1.scip_reader` bakes the SCIP index into agent-readable flat Markdown
  (agents can't call MCP in subagent context):
  - `repo_map.md` / `repo_map_full.md` — per-file symbol listing
  - `xref_map.md` — **cross-file references** for top-50 exported symbols
  - `call_graph_consensus.md` / `call_graph_p2p.md` / `call_graph_execution.md` —
    **2-hop call graphs** from subsystem entry points (BeginBlocker, HandleMsg, SetValidator…)
  - `type_hierarchy.md` — **interface → implementations**
  - `concurrency_inventory.md` (goroutine spawns + `sync.Mutex`, via **ast-grep**),
    `panic_sites.md` (all `panic()` sites, via ast-grep)
  - `all_symbols.txt`
- Evidence tag `[LSP-TRACE]` = a SCIP citation proving a call-graph / cross-reference path;
  ranked **stronger than `[CODE-TRACE]`, weaker than mechanical proof** (`[DIFF-PASS]`,
  `[FUZZ-PASS]`, `[NON-DET-PASS]`). SCIP here is symbol/xref/call-graph resolution — **not**
  taint or dominance.

### 1f. Supporting / adjacent (not structural analysis, listed for boundary clarity)
- `unified-vuln-db` (`mcp__unified-vuln-db__*`) — **RAG**, not static: Solodit / known-bug
  DB (`analyze_code_pattern`, `validate_hypothesis`, `get_root_cause_analysis`,
  `get_attack_vectors`, `search_solodit_live`). Pattern *library*, not code analysis.
- Foundry-suite / Heimdall (bytecode CFG/decompile), Anvil, fuzzers — dynamic, out of scope.
- Move/Sui/Soroban ecosystems: **no dedicated structural MCP** — they rely on Opengrep
  rules (where available) + grep-based recon derivation. Recon prompts note "Sui Move rules
  are not yet available in public rule repos."

---

## 2. Structural / Graph Queries Available TODAY (the actual menu)

**Call graph (EVM, Slither):**
- Outgoing edges per function — `get_function_callees` (internal/external/library + low-level flag)
- Incoming edges per function — `get_function_callers`
- Whole-graph export (Mermaid/DOT, entry-points-only, node cap) — `export_call_graph`
- Reachability: uncalled functions — `find_dead_code`
- Per-contract dependency graph + **circular-dependency detection** — `get_contract_dependencies`

**Inheritance / type graph (EVM):**
- Upward parents tree — `get_inherited_contracts`
- Downward children tree — `get_derived_contracts`
- Signature → all implementations (override resolution) — `list_function_implementations`

**Storage / state (EVM):**
- Computed **storage slot layout** (slot/offset/size/packing, incl. inherited) — `get_storage_layout`
- State-variable inventory + lifecycle metadata — `analyze_state_variables`

**Access control / call safety (EVM):**
- Modifier → using-functions map — `analyze_modifiers`
- Low-level call sites (`call`/`delegatecall`/`staticcall`/assembly) — `analyze_low_level_calls`

**Inventory / search (EVM):** `list_contracts`, `list_functions`, `search_contracts`,
`search_functions`, `analyze_events`, `get_project_overview`, `get_*_source`.

**Cross-file symbol graph (L1 Go/Rust only, SCIP):** per-file symbol map, cross-file xrefs
(`xref_map.md`), 2-hop call graphs from entry points, interface→impl `type_hierarchy.md`,
ast-grep concurrency + panic inventories.

**NOT available (confirmed absent):**
- Taint / source→sink data-flow tracking (no `taint`/`dataflow`/`def_use`/`reaching` anywhere
  in `slither_mcp`; grep returned empty)
- Dominator / dominance-frontier analysis
- Code-property-graph / program-dependence-graph / slicing
- Joern (any language) — **explicit non-goal**, deferred: `docs/l1-mode/design.md:33` ("Joern /
  CPG for Go/Rust: second-class tooling support. Deferred"), `:324` ("no … Joern …"), `:440`
  ("Joern / CPG — Go/Rust second-class. Phase 2 candidate"). CPG "slicing" is referenced only
  as a *known blind spot* the pipeline works around (`scripts/plamen_prompt.py:3533-3539`).
- CodeQL (license), Semgrep Pro (replaced by Opengrep) — Week-1 non-goals.

---

## 3. Detector-based vs Graph/Structural vs Pattern — classification

| Capability | Engine | Type |
|-----------|--------|------|
| `run_detectors` / `list_detectors` (slither-mcp) | Slither detectors | **Detector-based** (Slither's ~90 built-in checks: reentrancy, CEI, etc.) |
| `aderyn_audit` (farofino) | Aderyn | **Detector-based** (independent Rust analyzer) |
| `pattern_analysis` (farofino) | regex | **Pattern-based** |
| `solana-fender` `security_check_*` | Sec3 X-Ray | **Detector-based** (Solana) |
| Opengrep corpus (2107 rules) | Opengrep/Semgrep-fork | **Pattern-based** (syntactic/AST patterns, SARIF) |
| callees/callers/export_call_graph/find_dead_code/get_contract_dependencies | Slither IR call sets | **Graph (structural), NOT taint** |
| inherited/derived/implementations | Slither AST | **Graph (inheritance/type)** |
| get_storage_layout / analyze_state_variables / analyze_modifiers / analyze_low_level_calls / analyze_events / list_* / search_* | Slither AST (tool-computed) | **Structural query (AST), not detector, not taint** |
| SCIP xref_map / call_graph_* / type_hierarchy (L1) | scip-go, rust-analyzer scip | **Graph (symbol/xref/call, semantic-index-based)** — still not taint/dominance |
| concurrency_inventory / panic_sites (L1) | ast-grep | **Pattern-based (AST-grep)** |

**Bottom line:** Plamen's "graph" capability today = Slither's **static call graph +
inheritance/type graph + storage layout** (EVM), plus **SCIP symbol/xref/call graphs**
(L1 Go/Rust only). All genuine *semantic* dataflow reasoning — taint propagation,
def-use, dominance, slicing, CPG — is done by the **LLM agents by hand** (grep + Read +
manual trace), not by any installed tool. That is the gap a CPG/taint engine would fill.
