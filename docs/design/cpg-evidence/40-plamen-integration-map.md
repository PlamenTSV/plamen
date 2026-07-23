# CPG Dataflow Producer — Integration-Point Map (file:line anchored)

> Goal: identify the EXACT seams where a Code-Property-Graph (CPG) dataflow producer
> (taint edges, guard/validation dominators, typed sinks, reachability) would be
> **added** (producer) and **consumed** (derivers/gates), for EVM and L1.
> Design finding: the producer emits into the SAME `_mechanical_graph.json` seam
> that Slither/SCIP already fill; consumers are prose/tag-based and light up
> **additively** off new top-level keys with no per-consumer schema coupling.

All paths absolute. Line anchors are declaration/first-line of the cited construct.

---

## 1. PRODUCER SIDE — the bake pattern a CPG producer mirrors

### 1a. The unified sink every provider writes — `_mechanical_graph.json`
`/Users/ptsanev/.plamen/scripts/recon_prepass.py:2134`
```
def _write_mechanical_graph_json(scratch: Path, source: str,
                                 var_refs: dict, functions: dict) -> None:
```
- Emits exactly (L2149-2152): `json.dumps({"source": source, "var_refs": var_refs, "functions": functions}, indent=1)`.
- Docstring (L2136-2146) declares the schema contract:
  - `var_refs: { "<qualified var>": {"bare": str, "refs": ["<descriptor>", ...]} }`
  - `functions: { "<qualified fn>": {"bare": str, "loc": str, "callers": [...], "callees": [...] (optional)} }`
  - A "descriptor" = `"BareName (file:line)"` or a bare `file:line` — matched against agent finding prose.
- **CPG SEAM**: a producer adds top-level keys (`taint_edges`, `guards`, `typed_sinks`, `reachability`) via the SAME function — extend the dict literal at L2150, keep `source`/`var_refs`/`functions` unchanged for backward compat. Every current caller passes only the 4 legacy args, so the additive keys are opt-in per producer.

### 1b. CLI-subprocess bake template (what a go/ssa or slither-CPG bake follows)
- Rust SCIP bake: `/Users/ptsanev/.plamen/scripts/recon_prepass.py:2014` `def _bake_rust_scip(scratch, proj) -> str:` — `shutil.which` guard (L2022), manifest guard (L2025), freshness reuse `_scip_bake_is_fresh` (L2033), hardened subprocess `_run_hardened([...], proj, TIMEOUT)` (L2040-2043), rc 124/127/!=0 → `FAILED/SKIPPED` string, then delegates to `_scip_to_graph_artifacts` (L2060).
- Go SCIP bake: `/Users/ptsanev/.plamen/scripts/recon_prepass.py:2063` `def _bake_go_scip(scratch, proj) -> str:` — identical shape (`scip-go`/`go` on PATH L2073-2076, `go.mod` guard L2078, `_run_hardened` L2097, delegates to `_scip_to_graph_artifacts` L2121).
- Status-string contract: `WRITTEN | REUSED | SKIPPED:{r} | FAILED:{r}` (L2020) — best-effort, never halts; on non-WRITTEN the LLM/legacy maps remain.
- **CPG bake mirrors this**: `def _bake_go_ssa_cpg(scratch, proj) -> str:` — `shutil.which("<cpg-tool>")` + `go.mod` guard → `_run_hardened` → convert to graph artifacts → `_write_mechanical_graph_json(..., taint_edges=..., guards=...)`.

### 1c. EVM in-process producer (Slither) — the richest current producer
`/Users/ptsanev/.plamen/scripts/recon_prepass.py:2167` `def _bake_evm_slither_graph(scratch, proj) -> str:`
- Walks `sl.contracts` → `functions_declared` (L2222), harvests `state_variables_read`/`state_variables_written` (L2229/L2233), `internal_calls` (L2237) + `high_level_calls` (L2243) → `fn_callees`; inverts to `fn_callers` (L2257).
- Builds `var_refs`/`functions` (L2276-2285) and calls `_write_mechanical_graph_json(scratch, "slither", var_refs, functions)` at **L2286**.
- **CPG SEAM (EVM)**: Slither already exposes IR (SlithIR/dataflow) — a CPG producer computes taint/guard-dominance HERE and passes the extra dicts at the L2286 call. This is the natural EVM insertion point (in-process, no new CLI tool).

### 1d. SCIP → graph converter (the L1/Rust/Go reference-graph builder)
`/Users/ptsanev/.plamen/scripts/recon_prepass.py:2669` `def _scip_to_graph_artifacts(scratch, index_path, proj) -> str:`
- Builds `callers` from `reader._references` (L2717-2725), `state_writers` from Field/Variable refs (L2727-2736), `callees` by **file-level co-occurrence HEURISTIC** (L2738-2772, status `HEURISTIC`/`PARTIAL`, NOT verified call edges — L2747/L2790-2793).
- Emits `_mechanical_graph.json` at **L2857** via `_write_mechanical_graph_json(scratch, "scip", var_refs, functions)`; `var_refs`/`functions` built L2848-2856 (descriptors are reference LOCATIONS; SCIP does not resolve callee names → callee_map is co-occurrence only).
- **CPG SEAM (L1)**: SCIP gives reference/xref graph only — NO dataflow, NO verified call edges, NO taint. A go/ssa CPG producer replaces the L2738-2772 heuristic with real call edges AND adds `taint_edges`/`guards` before the L2857 write.

### 1e. Current ACCESS-GUARD heuristic — what `validationDominates` replaces/augments
`/Users/ptsanev/.plamen/scripts/recon_prepass.py:465-484` (permissionless-setter detector):
```
_SOL_ACCESS_MODIFIER_RE = re.compile(r"\b(onlyOwner|onlyRole|onlyAdmin|onlyGovernance|auth|restricted)\b")   # L472
# Body guard checked only near the top of the function body ("first statements")  # L475-476
_SOL_BODY_GUARD_RE = re.compile(r"require\s*\(\s*msg\.sender\s*==|_checkOwner\s*\(|...")                       # L477
```
- This is a **regex "body guard near top of function"** proxy for "is this write access-gated" — explicitly precision-favoring, admits false-negatives on guards not near the top (L475-476 comment).
- Downstream consumer of the guard concept: the LLM-enriched `state_write_map.md` **"Access Guard" column**, parsed at
  `/Users/ptsanev/.plamen/scripts/chain_prep.py:159` (`| State Variable | Writer Function | Write Site | Access Guard |`, parser `_parse_state_write_map` L155-191).
  NOTE: the mechanical bakes (slither L2293, SCIP L2816) do NOT emit an "Access Guard" column — it is an LLM-enrichment expectation today.
- **CPG SEAM**: a `guards`/`validationDominates` producer key gives a **dominator-based** answer ("does a require/role-check dominate this state write on all paths") that mechanically fills the Access-Guard column and replaces the top-of-body regex proxy — same append seam at `_write_mechanical_graph_json`.

---

## 2. CONSUMER SIDE — what lights up off the enriched graph

All consumers load the graph through ONE reader:
`/Users/ptsanev/.plamen/scripts/enumeration_gate.py:147` `def _load_graph(scratchpad)` — validates only `"var_refs" in g and "functions" in g` (L155). **Additive keys pass through untouched**; a consumer that wants `taint_edges` just reads `graph.get("taint_edges", {})`.

### G1 — enumeration obligations (co-reference)
`/Users/ptsanev/.plamen/scripts/enumeration_gate.py:191` `def compute_enumeration_obligations(scratchpad) -> int:`
- Reads `graph["var_refs"]` (L205), inverts descriptor→`fn_to_vars` (L207-210), resolves finding locus→fn via `_fn_at_location` (L216, def L166), emits `required_corefs` obligations (L226-236) → `_enumeration_obligations.json` + `enumeration_obligations.md`.
- **CPG lights up**: co-reference obligations today are "both functions touch var X". With `taint_edges` the obligation sharpens to "a value from fn A **flows to** a sink in fn B" — a `reachability`/`taint_edges` read slots beside the L207-210 var-ref inversion.

### G2 — coverage-gap emission
`/Users/ptsanev/.plamen/scripts/enumeration_gate.py:257` `compute_coverage_gaps` + `:282` `validate_enumeration_coverage` → appends low-confidence `ENUMGAP` INV-* blocks to `findings_inventory.md` (L318-358), STATE-typed chain metadata (L348-355), idempotent via `enumeration_gap_receipt.md` (L300-306).
- **CPG lights up**: `typed_sinks` lets an ENUMGAP be classified (stale-read vs bricked-consumer vs fund-sink) instead of the generic L342-343 "Potential cross-function inconsistency".

### Gate orchestrator (single wiring point for all derivers)
`/Users/ptsanev/.plamen/scripts/enumeration_gate.py:2181` `def run_enumeration_gate(scratchpad) -> dict:` — runs G1 (L2193) → G2 (L2197) → the 3 shape derivers (L2202-2207) → M1 invariant deriver (L2217). Driver call sites:
- `/Users/ptsanev/.plamen/scripts/plamen_driver.py:16444` and `:16675` `_eg.run_enumeration_gate(scratchpad)` (SC + L1 depth-phase post-processing).

### M1 — invariant-assertion deriver
`/Users/ptsanev/.plamen/scripts/enumeration_gate.py:1266` `def compute_invariant_assertion_candidates(scratchpad) -> list:`
- Loads graph (L1276), resolves committed-invariant `[CI-n]` locus→fn via `_fn_at_location` (L1308), emits falsifiable candidates with chain pre/post metadata (L1335-1361). Promoted via driver L15530 `promote_axis_findings_to_inventory` sibling path.
- **CPG lights up**: `guards`/`validationDominates` tells the falsifier whether the committed local guard actually dominates the locus — turns "asserted but not falsified" (L1350-1351) into a dominance check.

### M2 — hot-function set + axis coverage (`axis_coverage` / chain_prep feed)
- Hot set: `/Users/ptsanev/.plamen/scripts/enumeration_gate.py:1550` `def compute_hot_function_set(scratchpad) -> list:` — ranks off `_load_graph` (L1560): `var_refs`→`fn_writes` (L1580-1591, with `_is_builtin_method` denoise L1589), `functions.callers` fan-in scoring (`_W_FANIN*log2(n_callers+1)` L1393/L1650), `value_effect` source-scan (L1600-1610). Fallback to "all state-mutating fns" when graph absent (L1615).
- Axis matrix: `/Users/ptsanev/.plamen/scripts/enumeration_gate.py:1772` `def compute_axis_coverage_gaps(scratchpad) -> list:` — builds `function × axis` matrix over the hot set (L1853-1878), axis-EXAMINED read ONLY from CLOSED depth-evidence tags `_axis_examined_signals`/`_axis_examined_secondary` (L1861-1862), ambiguous ⇒ GAP (L1870). Writes `hot_function_axes.md` + `_hot_function_axes.json`; returns GAP rows. Promoted by `promote_axis_findings_to_inventory` (L1907).
- Driver wiring: skip-when-clean `_axis_coverage_has_no_gaps` `/Users/ptsanev/.plamen/scripts/plamen_driver.py:12882` (calls `_eg.compute_axis_coverage_gaps` L12899); phase validator `_validate_axis_coverage` L2384/L15527; phase def `plamen_types.py:1304` (`axis_coverage` → `axis_coverage_findings.md`); prompt `plamen_prompt.py:919` → `phase4b8-axis-coverage.md`.
- **CPG lights up**: axes are prose/tag question-shapes today. `reachability` + `taint_edges` let a new axis (e.g. "untrusted-input-reaches-sink") be marked EXAMINED/GAP mechanically instead of only from agent tags — a new `_AXES` entry reading `graph.get("taint_edges")`.

### Variant / sibling gate (Gate V, axes 2+3)
- Driver entry: `/Users/ptsanev/.plamen/scripts/plamen_driver.py:3982` `def _run_gate_v_for_phase(phase_name, scratchpad) -> dict:` → `enumeration_gate.compute_variant_gaps` (L4002). Docstring L3985-3998: "additive derivers over the SAME `_mechanical_graph.json` + `chain_candidate_pairs.md` data", wired immediately after `run_enumeration_gate` in SC+L1 depth post-processing.
- Deriver: `/Users/ptsanev/.plamen/scripts/enumeration_gate.py:1177` `def compute_variant_gaps(scratchpad) -> dict:` (co-referencer / boundary-input / symmetric-operation axes).
- **CPG lights up**: symmetric-operation pairing (deposit/withdraw) and boundary-input axes both benefit from `taint_edges`/`typed_sinks` to confirm the paired paths actually move the same tainted value.

### chain_prep — cross-domain / candidate-pair feed
`/Users/ptsanev/.plamen/scripts/chain_prep.py:921` `def run_chain_prep(scratchpad) -> dict:` (driver L18863). Consumes `state_write_map.md` "Access Guard" column via `_parse_state_write_map` (L155). Produces `chain_candidate_pairs.md` (read by variant gate + Chain Agent 2). CPG `guards` mechanically fills the Access-Guard column chain_prep reads.

---

## 3. Consumer layer is ecosystem-agnostic (tag/prose-based) — citations

- `_write_mechanical_graph_json` docstring: "the UNIFIED `_mechanical_graph.json` every provider emits ... **ecosystem-agnostic, LLM-unclobberable**" — `/Users/ptsanev/.plamen/scripts/recon_prepass.py:2136-2137`.
- Axis machinery is language-uniform: comment "those consumers are language-agnostic and already `.get()`-degrade cleanly for an absent language" — `/Users/ptsanev/.plamen/scripts/enumeration_gate.py:417-419`.
- Axis-EXAMINED is read from the CLOSED depth-evidence tag vocabulary + one generic prose cue, "carries zero ecosystem-specific tokens" — `compute_axis_coverage_gaps` L1775/L1861-1862; CHANGELOG line 17: *"the underlying graph-bake and axis detectors are tag/prose-based, not ecosystem-specific"* — `/Users/ptsanev/.plamen/CHANGELOG.md:17`.
- Single reader gate `_load_graph` validates only `var_refs`+`functions` (no ecosystem branch) — `/Users/ptsanev/.plamen/scripts/enumeration_gate.py:147-157`.
- One deriver body runs across sol/rust/move/go via a per-language SIGNAL REGISTRY `_LANG` (`.get()`-degrades) — `/Users/ptsanev/.plamen/scripts/enumeration_gate.py:433` — the derivers are shapes, not idioms (L402-413).

**Conclusion**: consumers key off (a) the 2 required graph keys, (b) closed depth-evidence tags, (c) `.get()`-degrading language registries. New producer keys are read via `graph.get(...)` and light up every ecosystem uniformly with zero per-consumer schema coupling.

---

## 4. L1 generalization anchor — SCIP has NO dataflow; go/ssa CPG slots in the same seam

- SCIP bakes → `_scip_to_graph_artifacts` (recon_prepass L2669) produce ONLY reference graphs: caller_map (L2774), callee_map = **file co-occurrence HEURISTIC, not verified edges** (L2738-2772/L2790-2793), state_write_map (L2809), function_summary (L2824), plus xref/type via the SCIP reader.
- Backing reader has ZERO dataflow: `/Users/ptsanev/.plamen/plamen_l1/scip_reader.py` exposes only `find_definition` (L241), `find_references` (L266), `list_symbols_in_file` (L296), `workspace_symbol` (L306), `stats` (L350) — no taint/ssa/def_use/reaching methods.
- L1 static layer is intra-file only: ast-grep + Opengrep panic/concurrency inventories (`go-concurrency-safety`: goroutine leaks, mutex ordering, **panic boundaries** — docs/l1-mode/design.md:188; `rust-unsafe-audit`:189), and Opengrep provides only **intra-file** taint — "**Inter-file taint gap documented openly**" (`/Users/ptsanev/.plamen/docs/l1-mode/design.md:307`).
- L1 bake dispatch seam (where a CPG bake registers): driver pre-breadth hook `/Users/ptsanev/.plamen/scripts/plamen_driver.py:13007` (`_bake_rust_graph`), `:13020` (`_bake_go_graph`), guarded by `not (scratchpad/"caller_map.md").exists()` + `PLAMEN_DISABLE_SCIP`. `run_recon_prepass` L1 branch does NOT bake a graph (`recon_prepass.py:4107-4111`); it is deferred here.
- Graph-bake top-level dispatch (SC): `recon_prepass.py:4162-4164` (`lang=="evm"` → `_bake_evm_graph`), `:4198-4201` (solana/soroban → `_bake_rust_graph`), `:4204-4205` (aptos/sui → `_bake_move_graph`), `:4118` (daml → `_bake_daml_graph`).

**Conclusion**: a `go/ssa`-based CPG producer registers at the SAME bake seam as `_bake_go_graph`/`_bake_go_scip` (driver L13020 / recon_prepass L2063), computes real call edges + taint + guard-dominance that SCIP/Opengrep cannot, and emits them through the additive `_write_mechanical_graph_json` keys — no consumer change required; every gate above lights up.

---

## Insertion-point summary (one-line each)

| Seam | File:line | Action |
|------|-----------|--------|
| Additive schema | `recon_prepass.py:2150` | add `taint_edges`/`guards`/`typed_sinks`/`reachability` to the json dict |
| Schema contract doc | `recon_prepass.py:2136-2146` | document the 4 new keys' shapes |
| EVM producer call | `recon_prepass.py:2286` | pass CPG dicts from SlithIR at the `_write_mechanical_graph_json` call |
| L1/SCIP producer call | `recon_prepass.py:2857` | pass CPG dicts (replaces L2738-2772 co-occurrence heuristic) |
| New CLI CPG bake | mirror `recon_prepass.py:2063` `_bake_go_scip` | `_run_hardened` + delegate; register at driver `plamen_driver.py:13020` |
| Access-guard replace | `recon_prepass.py:465-484` heuristic + `chain_prep.py:159` column | `validationDominates`/`guards` fills Access-Guard mechanically |
| Consumer reader | `enumeration_gate.py:155` | `graph.get("taint_edges", {})` — additive, no gate rewrite |
| G1/G2 co-ref | `enumeration_gate.py:191/282` | sharpen obligations with taint reachability |
| M1 invariant | `enumeration_gate.py:1266` | guard-dominance for committed-invariant falsifier |
| M2 hot-set/axis | `enumeration_gate.py:1550/1772` | new taint/reachability axis; mechanical writes flag |
| Variant gate | `enumeration_gate.py:1177` (driver `plamen_driver.py:3982`) | typed-sink confirmation of symmetric/boundary pairs |
