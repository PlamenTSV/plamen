# Plamen ↔ CPG Oracle Integration Points

> Where a Code-Property-Graph query oracle (taint-flow, guard/dominance, typed-sink,
> access-control-reachability) plugs into the Plamen V2 audit pipeline.
> All findings are read from source at `/Users/ptsanev/.plamen` (not guessed).

---

## 0. Executive picture

Plamen ALREADY has a hand-rolled, poor-man's CPG and a mechanical consumer scaffold:

1. **Recon bakes structural graph artifacts to disk** (frozen files, because depth/verify
   run with MCP disabled): `caller_map.md`, `callee_map.md`, `state_write_map.md`,
   `function_summary.md`, `call_graph.md`, plus an EVM "Slither prebake" (`slither/`)
   and an L1 "SCIP prebake" (`scip/`).
2. **A unified machine graph `_mechanical_graph.json`** is emitted by every provider
   (Slither / SCIP / Move / DAML / regex source-parse) with `{var_refs, functions{callers,callees}}`.
3. **`enumeration_gate.py` is an EXPLICIT CPG consumer** — its module docstring cites
   LLMxCPG (USENIX '25, arXiv:2507.16585) and says the "only proven fix" for the
   under-enumeration recall failure is "grounding the required set in an EXTERNAL
   static-analysis graph (LLMxCPG) and gating the verdict on covering it."

A CPG oracle does not need a greenfield slot. The highest-leverage move is to **enrich
`_mechanical_graph.json`** (add taint/guard/dominance/sink edges) and **add CPG-backed
gate axes** alongside the existing G1/G2 co-reference axis and M2 axis-coverage matrix.
Everything downstream (obligations, hot-set, chain pairs, coverage receipts) already
reads that graph.

---

## 1. Pipeline phase order (driver phase-name literals)

From `scripts/plamen_driver.py` `PHASE` list + phase-name literals:

```
bake → recon → breadth → rescan → (percontract) → inventory[_prepare/_surface/_templates/_chunk_a..c]
 → invariants/invariant → semantic_gap_investigator → enumgap_exploration → axis_coverage
 → depth (iter1-3) → chain_prep → chain → chain_agent2 → chain_iter2 → invariant_fuzz
 → verify_queue → verify → verify_aggregate → skeptic → semantic_dedup
 → report_index → report_dedup → report_body_writer_* → report_assemble → report_floor
```

Static/graph analysis is produced in `bake`+`recon`, consumed mechanically in
`enumgap_exploration`, `axis_coverage`, `chain_prep`, and via prompt injection in
`breadth`/`depth`/`verify`.

---

## 2. Concrete insertion points

### IP-1 — PRODUCER: `_mechanical_graph.json` schema enrichment ★ highest leverage
- **Phase**: `recon` (SC) / `bake` (L1). **File/slot**:
  `scripts/recon_prepass.py::_write_mechanical_graph_json` (L2134) and
  `_finalize_source_graph` (L2513); provider bakes `_bake_evm_source_graph` (L2322),
  Slither path (L2286), SCIP path (L2857), `_bake_rust/go/move/daml_source_graph`.
- **Current schema** (ecosystem-agnostic, LLM-unclobberable):
  ```json
  {"source": "slither|scip|evm-source|rust-source|go-source|move|daml",
   "var_refs": {"<qualVar>": {"bare": str, "refs": ["<fn> (file:Ln)", ...]}},
   "functions": {"<qualFn>": {"bare": str, "loc": "file:Ln",
                              "callers": ["<descriptor>"], "callees": ["<descriptor>"]}}}
  ```
- **What a CPG oracle adds** (new top-level keys, additive — old consumers ignore them):
  `taint_edges` (source→sink descriptors), `guards` (per fn/write-site: dominating
  require/modifier predicate + dominance flag), `typed_sinks` (call/transfer/sstore
  sink nodes with arg provenance), `reachability` (entry-actor → fn reachability under
  guard set). Descriptors keep the same `bare` / `file:Ln` matchable form so ALL
  existing prose-diff consumers work unchanged.
- **Why here**: every mechanical gate + `chain_prep` already `json.load`s this one file.
  Enrich once, and G1/G2/M2/chain all gain CPG signal for free.

### IP-2 — PRODUCER: recon derived graph artifacts (TASK 2.1)
- **Phase**: `recon`, Agent 2. **File**: `prompts/evm/phase1-recon-prompt.md` TASK 2.1 (L233+).
- **Artifacts baked** (frozen because depth/verify run MCP-disabled): `caller_map.md`,
  `callee_map.md`, `state_write_map.md` (schema `| State Variable | Writer Function |
  Write Site | Access Guard |`), `function_summary.md` (`| Function | Visibility |
  Modifiers | #Callers | #Callees | State Reads | State Writes |`).
- **CPG slot**: replace the Slither-or-grep generation of these tables with CPG queries.
  The `Access Guard` column of `state_write_map.md` and the `Modifiers` column of
  `function_summary.md` are exactly guard/dominance output; a typed-sink query fills a
  new `Sink` column. This upgrades the frozen map every later phase reads.

### IP-3 — PRODUCER: EVM "Slither prebake" + L1 "SCIP prebake"
- **EVM prebake** (`slither/` dir): `call_graph.md`, `state_write_map.md`,
  `function_summary.md`, `inheritance_tree.md`, `access_control_map.md` (which modifiers
  guard which functions — a guard/dominance product), `detector_findings.md`,
  `project_facts.json`. Gated by `SLITHER_PREBAKE_COMPLETE: true` in
  `slither/primitive_status.md`. Verified by `prompts/shared/v2-full-assessment.md` §B.
- **L1 SCIP prebake** (`scip/` dir, `commands/plamen-l1.md` §SCIP-PREBAKE L206+, 1.5b L26+):
  `repo_map.md`, `call_graph_{consensus,p2p,execution}.md`, `xref_map.md`,
  `panic_sites.md`, `concurrency_inventory.md`, `type_hierarchy.md`.
- **CPG slot**: `access_control_map.md` → access-control-reachability query output;
  `type_hierarchy.md`/`typed_sinks` → typed-sink query; `xref_map.md` → taint-source
  enumeration. A CPG oracle emits these directly, deterministically, replacing the
  Slither/scip-reader bake.

### IP-4 — CONSUMER: enumeration gate G1/G2 (`enumgap_exploration` phase) ★
- **File**: `scripts/enumeration_gate.py`; driver validator `_validate_enumgap_exploration`
  (driver L2380); `run_enumeration_gate` / `compute_enumeration_obligations` (G1) /
  `validate_enumeration_coverage` (G2).
- **Current axis**: G1 derives, per finding, the set of CO-REFERENCING functions of the
  symbols its function touches (from `var_refs`); G2 diffs required co-referencers vs the
  finding's prose; un-addressed → append `ENUMGAP` low-confidence candidate to
  `findings_inventory.md` (recall-safe, append-only). Caps: `_MAX_COREFS_PER_VAR=6`,
  `_MAX_ENUMGAP_PER_RUN`.
- **CPG slot**: add **Axis-2 = taint-reachable sinks** and **Axis-3 =
  guard-dominance**. For a finding at fn F: obligation set becomes "every typed sink
  reachable from F's tainted source" and "every write-site of F's symbol NOT dominated
  by the same guard." Same `ENUMGAP`-style emit path; the docstring already frames this
  as the intended LLMxCPG grounding.

### IP-5 — CONSUMER: axis-coverage meta-pass M2 (`axis_coverage` phase)
- **File**: `enumeration_gate.py` MECHANISM 2 (L~1372+); `compute_axis_coverage_gaps`;
  driver `_validate_axis_coverage` (L2384), `_axis_coverage_has_no_gaps` (L12882).
- **Current**: driver-owned DETERMINISTIC "hot function" set (`_MAX_HOT_FUNCTIONS=40`,
  `_CALLER_THRESHOLD=2`, Formula-2 log-dampened hot-set scoring blending fan-in +
  state-writes + `[ELEVATE]` + value-effect + entry-point) × a `function × risk-axis`
  completeness matrix; orthogonal never-examined axes at a hot locus spawn a deriver
  worker. Axis-EXAMINED read ONLY from the closed depth-evidence tag vocabulary.
- **CPG slot**: (a) hot-set scoring gains real fan-in/taint-centrality from CPG instead
  of regex `var_refs` counting; (b) add CPG risk axes to the matrix columns —
  taint-flow-to-sink, guard-dominance, typed-sink-arg-provenance, actor-reachability —
  so an un-examined CPG axis at a hot function forces a targeted deriver.

### IP-6 — CONSUMER: chain pre-filter (`chain_prep` phase) ★
- **File**: `scripts/chain_prep.py`; `_parse_state_write_map` (L155, parses
  `state_write_map.md` incl. `Access Guard` col), pair builder (L340+),
  `_finding_state_vars`, writes `chain_candidate_pairs.md` (STATE Pairs / TYPE Pairs,
  top `_BOUNDED_PAIR_CAP`); also fills STEP 0b 5-actor reachability table (L768, L896).
- **Current**: postcondition→precondition matching is grounded on shared state-variable
  writers (grep/Slither-derived) + shared code identifiers + line proximity.
- **CPG slot**: replace shared-state heuristic with **taint-flow reachability** (does
  finding A's write actually flow to finding B's read?) and fill the **5-actor
  reachability table** (STEP 0b) with an access-control-reachability query instead of
  the LLM enumerating it. This is the single biggest precision win for chain analysis.

### IP-7 — CONSUMER: `function_summary` obligation gate
- **File**: `scripts/plamen_validators.py::_check_function_summary_obligation` (L10048),
  `_parse_function_summary_rows` (L9999); driver call L16714.
- **Current**: every `function_summary.md` row with non-empty State Writes must have a
  depth-state-trace receipt; non-empty External Calls must have a depth-token-flow
  receipt; misses → `function_summary_obligation_gap.md` (WARNING-class).
- **CPG slot**: obligation partitioning becomes CPG-typed — a row with a taint edge to a
  value sink escalates to a hard obligation; a write dominated by a verified guard can be
  discharged automatically (reduces false obligations). Feeds `function_summary.md`
  Sink/Guard columns from IP-2.

### IP-8 — CONSUMER: graph-artifact consumption gate (depth phase)
- **File**: `plamen_validators.py` L9439-9475 (`_GRAPH_ARTIFACT_NAMES`,
  `_GRAPH_UNAVAILABLE_TAG_RE`, `[GRAPH-ARTIFACT: UNAVAILABLE:...]` tags).
- **Current**: mechanically checks each depth agent output referenced/consumed
  `caller_map / callee_map / state_write_map / function_summary` (or acknowledged
  unavailability). Confidence scoring uses graph-artifact status as a signal.
- **CPG slot**: extend the artifact-name set + status signal to CPG query artifacts
  (taint slices, guard maps), so "did the agent consult the CPG slice for this locus"
  becomes a scored coverage signal.

### IP-9 — PROMPT-INJECTION: depth agent tool slots (per-role MCP)
- **Files**: `agents/depth-*.md` frontmatter `tools:` + `prompts/evm/phase4b-depth-driver.md`
  Slither-Prebake role table (L86-110) + `phase4b-depth-templates.md` MANDATORY
  graph-artifact reads (L35-41) + tainted-source consumption enumeration (L172).
- **Current per-role slither MCP tools** (the exact slots a CPG tool would join/replace):

  | Depth agent | slither MCP tools held | Purpose |
  |---|---|---|
  | depth-token-flow | `get_function_source`, `analyze_state_variables` | trace value flow, var lifecycle |
  | depth-state-trace | `get_function_source`, `analyze_state_variables` | state write ordering, R14 cross-var |
  | depth-edge-case | `get_function_source` | boundary reads |
  | depth-external | `get_function_source`, `get_function_callees` | external call-target tracing |

  Prebake role files: token-flow←`call_graph,state_write_map,function_summary`;
  state-trace←`state_write_map,access_control_map,function_summary`;
  edge-case←`function_summary,detector_findings,call_graph`;
  external←`call_graph(external),inheritance_tree`.
- **Notable hand-rolled taint query**: `phase4b-depth-templates.md` L172 "Tainted source
  consumption enumeration" tells the agent to enumerate ALL functions consuming a tainted
  source (weak RNG / manipulable oracle / user param) via `get_function_callers` or grep,
  and rate severity by WORST consumption point — a **manual taint-flow + typed-sink
  query**. Direct CPG replacement target.
- **CPG slot**: add a CPG-query MCP tool (or `scip_reader`-style Bash query) to each
  role's tool list; swap the "MANDATORY graph-artifact reads" block to point at CPG
  slice files; replace the L172 manual taint enumeration with a `taint_edges` query.

### IP-10 — PROMPT-INJECTION: breadth structural orientation
- **File**: `prompts/evm/phase3-breadth-driver.md` L13-30. Injects `slither/`
  `function_summary.md`, `call_graph.md`, `inheritance_tree.md`, `access_control_map.md`
  as "Structural Orientation" when `SLITHER_PREBAKE_COMPLETE: true`.
- **CPG slot**: replace the four orientation files with CPG-derived equivalents
  (access-control-reachability map, typed-sink inventory) as navigation input; low risk,
  orientation-only (agents told: map, not evidence).

### IP-11 — CONSUMER: blind-spot scanners (reachability/guard) — Phase 4b iter1
- **File**: `prompts/evm/phase4b-scanner-templates.md`. Scanner B "Guards, Visibility &
  Inheritance" (L146, CHECK 5 inherited-capability), Scanner C "Role Lifecycle,
  Capability Exposure & Reachability" (L230; CHECK 7 capability exposure, CHECK 8
  Function Reachability Audit — externally-reachable / dead-code table); Validation Sweep
  CHECK 2 Validation Reachability (L357), CHECK 3 Guard Coverage Completeness (L372 —
  "same state writes without the guard = gap").
- **CPG slot**: CHECK 8 reachability table and CHECK 3 guard-coverage table are literally
  access-control-reachability + guard-dominance queries done by hand. A CPG oracle can
  pre-fill both tables deterministically and hand the scanner a verified worklist,
  converting a discovery task into a confirmation task.

### IP-12 — CONSUMER: verify phase variant/reachability
- **File**: `prompts/evm/phase5-verification-prompt.md` L83 (before FALSE_POSITIVE:
  check same-location same-class reachable variants), L221 (true-by-construction
  unreachable-input reasoning). Verifier tools: `agents/security-verifier.md` +
  `verification-protocol` skill hold `get_function_source`.
- **CPG slot**: a reachability query substantiates "is this input actually reachable"
  mechanically, hardening the FALSE_POSITIVE / true-by-construction decisions the
  verifier currently reasons about in prose.

---

## 3. Ranked recommendation

| Rank | Insertion point | Query type | Effort | Why |
|------|-----------------|-----------|--------|-----|
| 1 | IP-1 enrich `_mechanical_graph.json` | all four | Med | one file, every gate reads it |
| 2 | IP-4 enum-gate G1/G2 taint/guard axes | taint, guard | Med | docstring already asks for LLMxCPG grounding |
| 3 | IP-6 chain_prep taint pairs + 5-actor table | taint, AC-reach | Med | biggest chain precision win |
| 4 | IP-5 axis-coverage matrix CPG columns | typed-sink, taint | Med | forces derivers on un-examined CPG axes |
| 5 | IP-2/IP-3 baked map/prebake columns | guard, typed-sink | Low | upgrades frozen artifacts read everywhere |
| 6 | IP-11 scanner C/validation-sweep worklists | AC-reach, guard | Low | prompt-level, converts discovery→confirm |
| 7 | IP-9 depth tool slot + L172 taint replace | taint, typed-sink | Low | swaps a hand-rolled taint query |

---

## 4. Key facts (evidence)

- `_mechanical_graph.json` is the unified graph; producers in `recon_prepass.py`
  (`_write_mechanical_graph_json` L2134, providers slither/scip/evm-source/rust/go/move/daml).
- `enumeration_gate.py` docstring explicitly names LLMxCPG (arXiv:2507.16585) as the
  proven grounding fix and reads `_mechanical_graph.json` (`var_refs`+`functions`).
- Recon TASK 2.1 bakes `caller_map/callee_map/state_write_map/function_summary` to disk
  because "depth/verify phases run under the V2 driver with MCP disabled" — CPG output
  must likewise be **frozen to files at recon/bake time**.
- Depth/verify agents' ONLY structural MCP tools are `mcp__slither-analyzer__{get_function_source,
  analyze_state_variables, get_function_callees}` (per-role, see IP-9 table); full slither
  catalog (list_functions, export_call_graph, analyze_modifiers/events, list_function_callers/callees,
  find_dead_code, run_detectors) is used at RECON only (`prompts/evm/mcp-tools-reference.md`).
- Slither availability is fail-fast: one `list_contracts` probe in recon sets
  `SLITHER_AVAILABLE`; if false, depth/verify MUST NOT call slither and fall to Read/grep.
  A CPG provider slots in as a peer of Slither/SCIP in `recon_prepass` with the same
  fail-fast + `_mechanical_graph.json` contract, so grep fallback still holds.
- Guard/dominance data ALREADY partially exists: `state_write_map.md` `Access Guard`
  column, `function_summary.md` `Modifiers` column, `access_control_map.md`
  (modifier→function). A CPG guard/dominance query is an upgrade, not a new artifact.
