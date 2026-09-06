---
description: "Launch the V2 deterministic L1 audit pipeline for Go/Rust node clients (same as /plamen-l1-wizard). Experimental."
---

# Plamen L1 Infrastructure Audit Pipeline

## Step -1: Route to V2 L1 Wizard (MANDATORY first check)

**Routing rule** (evaluate `$ARGUMENTS` exactly once, before any other step):

- If `$ARGUMENTS` is empty OR does NOT contain the literal token `wrapper-launch`:
  - **STOP processing this file.** Read and execute
    `~/.claude/commands/plamen-l1-wizard.md` from its Step 1 onward, passing
    `$ARGUMENTS` through unchanged. The wizard collects L1 audit parameters
    and launches `~/.claude/scripts/plamen_driver.py` with `pipeline=l1`.
  - Do NOT run any of the Step 0..Step 6 sections below in interactive mode.
    Those sections are section-extracted by the driver one phase at a time
    via `claude -p --resume` invocations with `wrapper-launch` set; they
    are not a complete interactive pipeline.

- If `$ARGUMENTS` contains `wrapper-launch`:
  - You are running INSIDE a driver subprocess. Proceed to Step 0 below.

> **Why this routing exists**: pre-v2.0.0 `/plamen-l1` was an LLM orchestrator
> with the same context-saturation failure modes as the SC V1 prompt
> (silent step-skipping on long audits, files claimed-written-but-missing
> on disk, compaction-induced data loss). v2.0.0 replaced it with the
> deterministic Python driver. The interactive surface now points at the
> wizard so users get the reliable path by default.

---



> **Experimental.** L1 mode is newer than the SC pipeline and being validated
> against benchmark targets (Geth, Reth, CometBFT, Cosmos SDK). Bug classes,
> phase ordering, and evidence tags are L1-specific (see below) and **do not
> apply to smart-contract codebases** — run `/plamen` (without `l1`) for
> Solidity / Move / Solana / Soroban. See `docs/l1-mode/design.md` for the
> full specification.

> **Scope**: Go and Rust L1 / L2 node clients — Geth, Erigon, Reth, Lighthouse, CometBFT, Cosmos SDK, Substrate, op-geth, op-reth, and their forks. Targets T0 (patch review) / T1 (subsystem audit) / T2 (whole-client via multi-scoped runs) / T3 (full client, shallower coverage).

> **Architecture**: Unlike smart-contract modes, L1 mode:
> - Runs **Phase 0.5 Bake** before recon (scip-go / rust-analyzer SCIP plus ast-grep inventories)
> - Decomposes breadth by **layer** (network / consensus / execution / crypto / storage / rpc / mempool), not by file cluster
> - Spawns **two new depth agent roles** (`depth-consensus-invariant`, `depth-network-surface`)
> - **Removes Phase 4c chain analysis** — L1 bugs are point vulnerabilities, not compound exploits
> - Uses **new evidence tags** in Phase 5: `[DIFF-PASS]`, `[CONFORMANCE-PASS]`, `[NON-DET-PASS]`, `[FUZZ-PASS]`, `[LSP-TRACE]` alongside `[POC-PASS]` and `[CODE-TRACE]`
> - Applies the **L1-specific severity matrix** at `docs/l1-mode/severity-matrix.md`, not the smart-contract matrix in `rules/report-template.md`

## Orchestration Protocol

**MANDATORY**: Before starting any audit work, read and apply `~/.claude/rules/orchestrator-rules.md`. It contains the AUDIT MODES table, CRITICAL RULES 1-16, and the orchestration architecture. You are the orchestrator — those rules govern how you spawn agents, manage phases, and enforce completeness.

## Step 0: L1 Audit Wizard

Parse `$ARGUMENTS` for pre-filled values (shortcut handling):

- First token is `l1` — already known, strip it.
- If the next token is an absolute path, set `PROJECT_PATH` to that path. Otherwise use cwd.
- `light` / `core` / `thorough` → set `L1_DEPTH` accordingly. Default `core`. This controls depth loop iterations, niche agent activation, and verification scope — same semantics as the smart-contract mode axis.
- `scope:<subdir>` → set `SUBSYSTEM_SCOPE=<subdir>`. Audit only that subsystem (T1) or mark as T2 multi-scoped-run component. Default: no scope restriction.
- `target-type:{patch|subsystem|feature|whole}` → set the tier explicitly. Default: inferred from `SCOPE` and diff detection.
- `docs:<path-or-url>` → protocol spec / whitepaper / audit docs to ingest in recon.
- `nodocs` → explicit no docs.
- `wrapper-launch` → same as smart-contract mode; skip cost estimate + confirmation, jump to Step 1.
- `proven-only: true` → cap unproven findings (no mechanical evidence tag) at Low severity.

### Step 0a: Banner + Toolchain Check

Output the banner (same as plamen.md Step 0a), then add the L1 header:

```
┌─ L1 Infrastructure Mode (experimental) ────────────────────┐
│  Scope: Go / Rust node clients (50k-500k LOC)              │
│  Tiers: T0 patch  |  T1 subsystem  |  T2 whole-client      │
│  Phase 4c: REMOVED (point vulnerabilities don't chain)     │
│  Evidence tags: [DIFF-PASS] [NON-DET-PASS] [LSP-TRACE] ... │
└────────────────────────────────────────────────────────────┘
```

**Toolchain probe** (L1-specific additions to the standard probe):

```bash
export PATH="$HOME/.cargo/bin:$HOME/go/bin:$HOME/.local/bin:$PATH" && \
echo "L1 Toolchain:" && \
echo -n "  Primitives: " && \
(command -v scip-go >/dev/null 2>&1 && echo -n "✓scip-go " || echo -n "✗scip-go ") && \
(command -v rust-analyzer >/dev/null 2>&1 && echo -n "✓rust-analyzer " || echo -n "✗rust-analyzer ") && \
(command -v ast-grep >/dev/null 2>&1 && echo -n "✓ast-grep " || echo -n "✗ast-grep ") && \
(command -v codeql >/dev/null 2>&1 && echo -n "✓codeql" || echo -n "○codeql") && echo "" && \
echo -n "  Targets: " && \
(command -v go >/dev/null 2>&1 && echo -n "✓go($(go version 2>/dev/null | awk '{print $3}')) " || echo -n "✗go ") && \
(command -v cargo >/dev/null 2>&1 && echo -n "✓cargo($(cargo --version 2>/dev/null | awk '{print $2}'))" || echo -n "✗cargo") && echo ""
```

Missing `scip-go`, `rust-analyzer`, or `ast-grep` is a **hard blocker** — L1 mode requires the primitive layer. Stop and instruct the user to install:

```
scip-go:       go install github.com/scip-code/scip-go/cmd/scip-go@latest
rust-analyzer: rustup component add rust-analyzer  (or platform binary)
ast-grep:      cargo install ast-grep --locked     (or brew install ast-grep)
codeql:        https://github.com/github/codeql-cli-binaries/releases  (public-OSS only)
```

Also check: `python -c "import plamen_l1.scip_reader; print('ok')"` should succeed. If not, direct the user to run `protoc --python_out=plamen_l1/ scip.proto` (see `plamen_l1/scip_reader.py` docstring).

### Step 0b: Codebase Scan + Tier Detection

Run this scan BEFORE asking the user anything:

```bash
# Auto-detect: language, LOC, crate/module structure, fork status
LANGUAGE=$([ -f go.mod ] && echo "go" || ([ -f Cargo.toml ] && echo "rust" || echo "unknown"))
LOC=$(find . -name "*.go" -o -name "*.rs" | grep -v vendor | grep -v target | xargs wc -l 2>/dev/null | tail -1 | awk '{print $1}')
MODULES=$(ls -d crates/*/ x/*/ internal/*/ pkg/*/ modules/*/ 2>/dev/null | head -20)
IS_FORK=$(grep -l 'replace\|patch\.\|fork' go.mod Cargo.toml 2>/dev/null | head -1)
```

Then compute the tier:
- `LOC ≤ 2000` OR `git diff` shows ≤2k changed → **T0** (patch)
- Scope argument provided → **T1** (subsystem)
- `LOC ≤ 60000` → **T2** (whole-client)
- `LOC > 60000` → **T3** (full client, shallow)

### Step 0c: Interactive Questioning (ALL questions mandatory, ALL use AskUserQuestion)

**Q1 — Target**: AskUserQuestion "Is this the L1 target?" with options `Yes, use {PROJECT_PATH}` / `No, let me specify`. Show detected language, LOC, module count, fork status in description.

**Q2 — Tier** (ALWAYS ask — never auto-select): AskUserQuestion "Select audit tier:" with options:
- `T0 — Patch (≤2k LOC diff)` — PR/commit review
- `T1 — Subsystem (5-30k LOC)` — one module cluster, I'll choose next
- `T2 — Whole-client (30-100k LOC)` — full codebase, all subsystems
- `T3 — Full client screen (>100k, shallow)` — first-pass, breadth over depth

Show detected tier in header: `"Tier (detected: {DETECTED_TIER} based on {LOC} LOC)"`.

**Q3 — Module selection (T1 ONLY)**: enumerate detected modules with LOC:

```bash
for dir in $MODULES; do
  LOC_MOD=$(find "$dir" -name "*.go" -o -name "*.rs" | grep -v test | xargs wc -l 2>/dev/null | tail -1 | awk '{print $1}')
  echo "  $(basename $dir): $LOC_MOD LOC — $dir"
done
```

AskUserQuestion (multiSelect=true) "Which modules to audit?" — one option per module with `{name} ({LOC} LOC)` label. Set `SUBSYSTEM_SCOPE` to selected paths. Warn if total >30k LOC.

**Q4 — Fork** (only if `IS_FORK` detected): AskUserQuestion "Fork detected. Upstream comparison?" with options: `Diff against upstream` / `Audit as standalone` / `Both`.

**Q5 — Docs**: AskUserQuestion "Project docs available?" — `No docs` / `Yes, local files` / `Yes, URL`. Store as `DOCS_PATH`.

**Q6 — Proven-only**: AskUserQuestion "Proven-only mode?" — `No (default)` / `Yes (cap unproven at Low)`.

**Q7 — Confirmation**: display summary table and AskUserQuestion `Launch` / `Change settings` / `Cancel`:

```
┌─ L1 Audit Configuration ─────────────────────────────┐
│  Target:   {PROJECT_PATH} ({LANGUAGE}, {LOC} LOC)     │
│  Tier:     {TIER}    Scope: {SCOPE or "full"}         │
│  Modules:  {MODULE_LIST or "all"}                     │
│  Depth:    {L1_DEPTH}   Fork: {FORK or "no"}          │
│  Docs:     {DOCS_PATH or "none"}                      │
│  Proven:   {PROVEN_ONLY}                              │
└───────────────────────────────────────────────────────┘
```

If `Change settings` → restart Q1. If `Cancel` → abort. If `Launch` → Step 1.

---

## §WRITE-THEN-VERIFY: Subagent Output Protocol

Subagents Write directly to the scratchpad. The orchestrator verifies file existence. Full-text return is the FALLBACK, not the default.

**Why this replaces §HYBRID-RETURN**: the old fence-return pattern required every agent to dump its full output (~10-30 KB each) into the orchestrator's conversation context. With 30-40 agents, this consumed 300-1200 KB — filling the orchestrator's 200K-token context window by Phase 4b and leaving no room for depth iteration 2, Skeptic-Judge, or later phases. The smart-contract pipeline (`commands/plamen.md`) uses direct-Write successfully across 100+ runs. Bug #9458 (subagent Write flush race) is intermittent (~20%), not universal.

**Protocol** (include in every agent spawn prompt):

```
Write your output directly to {SCRATCHPAD}/{expected_filename} using the Write tool.
Return ONLY a one-line summary: "DONE: {N} findings written to {filename}"
Do NOT return your full output as text — the orchestrator's context budget is limited.
```

**Orchestrator verification** (runs after each agent returns):

```bash
FILE="{SCRATCHPAD}/{expected_filename}"
if [ -f "$FILE" ] && [ "$(wc -c < "$FILE")" -gt 100 ]; then
  echo "[VERIFY OK] $FILE ($(wc -l < "$FILE") lines)"
else
  echo "[VERIFY FAIL] $FILE missing or empty — requesting text fallback" | tee -a "{SCRATCHPAD}/violations.md"
  # Re-prompt the agent: "Your Write to {FILE} failed. Return your full output as text now."
  # Extract content from the re-prompt response and Write from the main session.
fi
```

**Key difference from §HYBRID-RETURN**: the orchestrator's context holds only one-line summaries (~50 bytes each) instead of full agent output (~15 KB each). With 30 agents: ~1.5 KB total context vs ~450 KB previously. This frees ~95% of the orchestrator's context budget for later phases (depth iter 2, Skeptic-Judge, Perturbation, etc.).

---

## §SCIP-PREBAKE: Depth Agent SCIP Directive

Include this block verbatim in every depth agent prompt:

> Read `{SCRATCHPAD}/scip/repo_map.md` + your domain-specific `call_graph_*.md` + `xref_map.md` + `type_hierarchy.md` + `concurrency_inventory.md` + `panic_sites.md`.
> DO NOT call `mcp__scip-reader__*` or `mcp__ast-grep__*` tools. They are unavailable in subagent contexts.
> Cite `scip/*.md` files for `[LSP-TRACE]` evidence. Findings without SCIP file citations use `[CODE-TRACE]`.
> For targeted queries not in pre-baked files, use Bash: `python -m plamen_l1.scip_reader {SCIP_INDEX_PATH} find_references "SymbolName"`

---

## §STEP-TRACE: Depth Agent Step Execution Trace Directive (advisory)

> **Mode gate**: Thorough mode only. Light/Core depth agents do NOT need to emit a step trace.
>
> **Status**: Agent-emit is now ADVISORY. The Python driver auto-synthesizes
> `step_execution_trace_{role}.md` from your `depth_{role}_findings.md` evidence-tag density
> (`[BOUNDARY:*]`, `[VARIATION:*]`, `[TRACE:*]`, etc.) if you don't emit a richer one.
> Agents that DO follow the directive get per-skill granularity preserved; agents that
> don't no longer halt the pipeline. The driver's projection is deterministic and lives
> on the same artifact path the prior gate inspected.

Include this block verbatim in every Thorough-mode depth agent prompt:

> Before returning, you SHOULD write `{SCRATCHPAD}/step_execution_trace_{your_role}.md` (where `{your_role}` is the suffix of your output filename — e.g., `consensus_invariant`, `network_surface`, `state_trace`, `external`, `edge_case`). If you do not, the driver will synthesize this file from your findings' evidence-tag density.
>
> This file accounts for whether each numbered section in your inherited skills was executed. Format:
>
> ```markdown
> # Step Execution Trace — depth-{your_role}
>
> | Skill | Step | Executed | Evidence | Result |
> |-------|------|----------|----------|--------|
> | {SKILL_NAME_A} | 1 | yes | {your-codebase}/{file}.rs:L{line} | {finding-id} |
> | {SKILL_NAME_A} | 2 | yes | {your-codebase}/{file}.rs:L{line} | safe ({brief justification}) |
> | {SKILL_NAME_A} | 3 | partial | {your-codebase}/{file}.rs:L{line} | partial: {what's left} |
> | {SKILL_NAME_A} | 4 | no | - | - |
> | {SKILL_NAME_B} | 1 | yes | {your-codebase}/{file}.{ext}:L{line} | {finding-id} |
> ```
>
> The `{...}` tokens above are placeholders showing the schema — replace with REAL values from the codebase you are auditing. Do NOT copy the placeholder text verbatim. Cite real file paths from THIS audit's source tree, not from any example or prior audit.
>
> **One row per (skill, numbered-section) pair** for every skill listed in `template_recommendations.md` BINDING MANIFEST as `Required = YES` and routed to your role per `~/.claude/rules/skill-index.md` "Inject Into" column. Resolve the numbered sections by reading each skill's `SKILL.md` — sections start with `## N. Title`.
>
> **Allowed `Executed` values**:
> - `yes` — section executed; Evidence MUST contain a `file:line` token (e.g. `block.rs:L45`). The driver hard-rejects ceremonial `yes` rows without `file:line` evidence.
> - `partial` — partially executed; Evidence MUST cite what WAS analyzed and Result MUST state what's left.
> - `no` — not executed; Evidence may be `-`. The driver aggregates these for the next phase.
>
> **Result column**:
> - For `yes` rows: a finding ID (e.g. `DEPTH-CI-3`) OR `safe (justification)` if the analysis confirmed no bug.
> - For `partial`/`no` rows: empty or `-`. The driver consumes these via `step_execution_gaps_mechanical.md` to spawn iter2 / DA / skill-checklist coverage.
>
> If you skipped a skill entirely because its trigger conditions are not met in the codebase (e.g., `BLS_AGGREGATION_AUDIT` when no BLS imports exist), write ONE row per skill with `Step = N/A`, `Executed = no`, `Result = trigger condition absent: <reason>`. Do not silently omit skills.
>
> **Why this matters**: Iteration-1 depth agents that produce 7-15 findings while leaving 60% of inherited skill sections unexecuted is the documented root cause of Plamen's recall ceiling. The trace makes execution mechanically observable; the driver derives the iter2 directive from it deterministically.

---

## Step 1: Language Detection

L1 mode supports `go` and `rust` only:

```bash
find {PROJECT_PATH} -name 'go.mod' -not -path '*/vendor/*' | head -1
find {PROJECT_PATH} -name 'Cargo.toml' -not -path '*/target/*' | head -1
```

Set `LANGUAGE` to `go`, `rust`, or `mixed`. If neither found, STOP.

---

## Step 1.5: Phase 0.5 Bake

Initialize scratchpad in the project root:

```bash
SCRATCHPAD={PROJECT_ROOT}/.scratchpad
mkdir -p "$SCRATCHPAD"
export PLAMEN_SCRATCHPAD="$SCRATCHPAD"

# Arm the violations log — every workflow violation per CLAUDE.md Rule 12 MUST be logged here.
# An empty violations.md is a HEALTHY signal (no skips). A missing violations.md is a
# meta-violation (the gate that catches skips wasn't enforced).
echo "# Plamen L1 violations log — initialized $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$SCRATCHPAD/violations.md"
echo "# Mode: $L1_DEPTH | Target: $PROJECT_ROOT | Commit: $(git -C "$PROJECT_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)" >> "$SCRATCHPAD/violations.md"
```

The V2 driver (`plamen_driver.py`) handles artifact gate enforcement between phases automatically.

**Mandatory invariant**: `violations.md` MUST exist for the entire run. The Step 6.5 gates and the Thorough-only step gates write to it on failure. After the run, if `violations.md` contains only the two header lines and the run also skipped Thorough-mandatory steps, this is a meta-violation that triggers a Round-N+1 investigation.

### 1.5a: SCIP Indexing (with reuse check)

**Go targets** (`LANGUAGE` is `go` or `mixed`):

```bash
cd {PROJECT_PATH}
INDEX_PATH="{PROJECT_PATH}/index.scip"
REUSE=false
if [ -f "$INDEX_PATH" ]; then
  SIZE=$(stat -c %s "$INDEX_PATH" 2>/dev/null || wc -c < "$INDEX_PATH")
  AGE_SEC=$(( $(date +%s) - $(stat -c %Y "$INDEX_PATH" 2>/dev/null || date -r "$INDEX_PATH" +%s) ))
  if [ "$SIZE" -gt 1048576 ] && [ "$AGE_SEC" -lt 86400 ]; then
    REUSE=true
    echo "Reusing SCIP index: $INDEX_PATH ($((SIZE/1024/1024)) MB, aged $((AGE_SEC/60)) min)"
  fi
fi
if [ "$REUSE" = false ]; then
  scip-go --module-root=. --module-version=plamen-audit-$(date +%s) 2>&1 | tail -20
fi
cp index.scip "$SCRATCHPAD/scip_go.index"
echo "SCIP_GO_REUSED=$REUSE" >> "$SCRATCHPAD/primitive_status.md"
```

**Rust targets** (`LANGUAGE` is `rust` or `mixed`): same pattern with `rust-analyzer scip . --exclude-vendored-libraries`, 5 MB reuse threshold. Record `SCIP_RUST_REUSED` in `primitive_status.md`. If rust-analyzer OOMs, fall back to crate-level scoping.

### 1.5b: SCIP Flat-File Pre-Bake

The orchestrator runs `plamen_l1.scip_reader` from the main session to produce flat files that depth agents will Read:

```bash
SCIP_DIR="$SCRATCHPAD/scip"
mkdir -p "$SCIP_DIR"
INDEX="$SCRATCHPAD/scip_go.index"  # or scip_rust.index

# 1. Repo map: per-file symbol listing (CAPPED at 2000 lines to prevent agent context overflow)
# Run 8 produced a 17 MB / 835K-line repo_map.md that agents couldn't read. Cap at 2000 lines
# (~50 KB) — for larger codebases, the summary is function signatures + line ranges only.
for f in $(find {AUDIT_SCOPE} -name "*.go" -o -name "*.rs" | head -100); do
  REL=$(python -c "import os; print(os.path.relpath('$f', '{PROJECT_ROOT}'))")
  echo "## $REL" >> "$SCIP_DIR/repo_map_full.md"
  python -m plamen_l1.scip_reader "$INDEX" file "$REL" >> "$SCIP_DIR/repo_map_full.md" 2>/dev/null
  echo "" >> "$SCIP_DIR/repo_map_full.md"
done
# Cap the agent-readable version at 2000 lines; full version stays as repo_map_full.md for targeted reads
head -2000 "$SCIP_DIR/repo_map_full.md" > "$SCIP_DIR/repo_map.md"
REPO_MAP_LINES=$(wc -l < "$SCIP_DIR/repo_map_full.md")
[ "$REPO_MAP_LINES" -gt 2000 ] && echo "[SCIP-PREBAKE] repo_map.md capped at 2000/$REPO_MAP_LINES lines. Full version: repo_map_full.md" >> "$SCRATCHPAD/violations.md"

# 2. Cross-file reference map (top 50 exported symbols)
python -m plamen_l1.scip_reader "$INDEX" search "" --limit 2000 > "$SCIP_DIR/all_symbols.txt"
head -50 "$SCIP_DIR/all_symbols.txt" | while read -r sym; do
  echo "### $sym" >> "$SCIP_DIR/xref_map.md"
  python -m plamen_l1.scip_reader "$INDEX" references "$sym" --limit 30 >> "$SCIP_DIR/xref_map.md" 2>/dev/null
  echo "" >> "$SCIP_DIR/xref_map.md"
done

# 3. Subsystem call graphs (2-hop from entry points)
for entry in BeginBlocker EndBlocker Slash SlashRedelegation ApplyAndReturnValidatorSetUpdates; do
  echo "## $entry" >> "$SCIP_DIR/call_graph_consensus.md"
  python -m plamen_l1.scip_reader "$INDEX" references "$entry" --limit 50 >> "$SCIP_DIR/call_graph_consensus.md" 2>/dev/null
done
for entry in HandleMsg HandleMessage ServeHTTP RegisterRoutes NewQuerier; do
  echo "## $entry" >> "$SCIP_DIR/call_graph_p2p.md"
  python -m plamen_l1.scip_reader "$INDEX" references "$entry" --limit 50 >> "$SCIP_DIR/call_graph_p2p.md" 2>/dev/null
done
for entry in SetValidator GetValidator DeleteValidator UpdateValidator; do
  echo "## $entry" >> "$SCIP_DIR/call_graph_execution.md"
  python -m plamen_l1.scip_reader "$INDEX" references "$entry" --limit 50 >> "$SCIP_DIR/call_graph_execution.md" 2>/dev/null
done

# 4. Concurrency inventory + panic sites (Go)
ast-grep run --pattern 'go $FUNC($$$)' --lang go {AUDIT_SCOPE} > "$SCIP_DIR/concurrency_inventory.md" 2>/dev/null || true
ast-grep run --pattern 'sync.Mutex' --lang go {AUDIT_SCOPE} >> "$SCIP_DIR/concurrency_inventory.md" 2>/dev/null || true
ast-grep run --pattern 'panic($X)' --lang go {AUDIT_SCOPE} >> "$SCIP_DIR/panic_sites.md" 2>/dev/null || true

# 5. Type hierarchy (interface implementations)
python -m plamen_l1.scip_reader "$INDEX" search "interface" --limit 200 > "$SCIP_DIR/type_hierarchy.md" 2>/dev/null || true

echo "SCIP_PREBAKE_COMPLETE=true" >> "$SCRATCHPAD/primitive_status.md"
echo "SCIP_PREBAKE_FILES=$(ls $SCIP_DIR/*.md 2>/dev/null | wc -l)" >> "$SCRATCHPAD/primitive_status.md"
```

**Expected output**: 6-10 flat files in `{SCRATCHPAD}/scip/` (~80-200 KB total). If any `scip_reader` command fails, the file is created empty; agents fall back to Grep.

---

## Step 2: L1 Recon

Read `~/.claude/prompts/l1/phase1-recon-prompt.md`. Spawn 3 parallel recon agents (L1-1 threat model + fork ancestry, L1-2 subsystem map + attack surface + scope leftovers, L1-3 bake validation + primitive sweep). No RAG agent for L1.

After all three complete, write `$SCRATCHPAD/recon_summary.md` with:
- `L1_PATTERN = true`
- Subsystem flags: `CONSENSUS`, `P2P`, `MEMPOOL`, `LIGHT_CLIENT`, `RPC`, `BLS`, `STATE_SYNC`, `EXECUTION`, `XENV`, `VALIDATOR_LIFECYCLE`, `HARDFORK`
- `IS_FORK`, `LANGUAGE`, primitive flags from Phase 0.5

Recon must also write `$SCRATCHPAD/scope_leftover.md` listing in-scope files
that are not covered by any declared subsystem / layer scope:

```markdown
| File | LOC | Reason | Acknowledged |
|------|-----|--------|--------------|
| crates/c/foo.c | 406 | language-mismatch | ACKNOWLEDGED: LANGUAGE_LANE_NOT_DETECTED |
```

Files above 200 LOC without an `ACKNOWLEDGED:` marker are a recon gate failure.

---

## Step 3: Breadth (Layer Decomposition)

### 3a. Build the layer set from recon subsystem flags

Read `{SCRATCHPAD}/recon_summary.md`. For each flag that is `true`, activate the corresponding layer:

| Layer | Flag | Skills |
|---|---|---|
| **network** | `P2P` | `p2p-dos-and-eclipse`, `go-concurrency-safety` / `rust-unsafe-audit` |
| **mempool** | `MEMPOOL` | `mempool-asymmetric-dos`, `go-concurrency-safety` / `rust-unsafe-audit` |
| **consensus** | `CONSENSUS` | `consensus-safety-invariants`, `consensus-math-correctness` (if difficulty / reward / EMA math is in scope), `fork-choice-audit` (if detected), `validator-lifecycle-and-slashing` (if detected), `hardfork-activation-and-protocol-upgrade` (if detected) |
| **execution** | `EXECUTION` | `execution-client-hardening`, `cross-environment-semantic-drift` (if `XENV`) |
| **crypto** | `BLS` or crypto/ in scope | `bls-aggregation-audit`, `dependency-audit-nodeclient` |
| **storage** | `STATE_SYNC` | `state-sync-pruning`, `go-concurrency-safety` / `rust-unsafe-audit` |
| **rpc** | `RPC` | `rpc-surface-audit`. MUST include `grpc_query.go`, `autocli.go`, and query infrastructure in scope. |
| **cross-chain** | `LIGHT_CLIENT` | `light-client-proof-verification` |
| **difficulty** | `adjust_difficulty` or `difficulty_adjustment` or `DIFFICULTY` detected in scope | `consensus-safety-invariants` + `consensus-math-correctness`. If no dedicated difficulty agent, ensure the consensus breadth agent's scope includes the difficulty adjustment file. |

**Layer splitting**: when a layer's merged skills exceed the 300-line cap, split into sub-agents (e.g. `consensus-lifecycle` + `consensus-crypto-forkchoice`). Prefer splitting over dropping skills.

**Per-agent methodology load warning**: if a depth agent's total skill load exceeds 800 lines (sum of all assigned SKILL.md files), the agent may miss findings due to attention saturation across too many concurrent methodology sections. Consider splitting the agent's scope or dropping the lowest-priority skill. Current heaviest: `depth-consensus-invariant` at ~1060 lines across 6 skills — acceptable for Thorough mode but at the attention limit.

### 3b. Agent count

```
breadth_agents = min(N_layers, 7)
```

Soft cap: ≤3 for T1 scope. Log to `violations.md` if exceeded.

### 3c. Spawn

For each layer, spawn ONE `general-purpose` Opus 5 agent (`model="claude-opus-5"`). Include the layer's skill set, paths to primitive artifacts, and the §WRITE-THEN-VERIFY directive. End with SCOPE CONTAINMENT.

After each agent returns, verify the file exists per §WRITE-THEN-VERIFY (`ls -lh` + `wc -l`). If missing, re-prompt for text fallback.

---

## Step 4a.6: Graph-Sharded Audit Sweeps

Thorough-only. This phase converts the baked graph artifacts into explicit
work queues before inventory, so uncovered files and panic sites cannot remain
advisory-only.

Read:
- `{SCRATCHPAD}/subsystem_coverage_gap.md`
- `{SCRATCHPAD}/scip/panic_sites.md`
- `{SCRATCHPAD}/scip/repo_map.md`
- `{SCRATCHPAD}/scip/xref_map.md`
- `{SCRATCHPAD}/scip/call_graph_p2p.md`
- `{SCRATCHPAD}/scip/call_graph_consensus.md`
- `{SCRATCHPAD}/scip/call_graph_execution.md`

Write `graph_sweep_summary.md` in all cases. If a queue is empty, state that
explicitly in the summary and do not fabricate findings.

### Sweep A: Panic-Site Triage

If `scip/panic_sites.md` has entries, split it into bounded shards by file or
by roughly 150 entries. For every panic/unwrap/expect/assert entry, assign one
verdict line:

| Entry | Reachability | Input Control | Verdict | Evidence |
|-------|--------------|---------------|---------|----------|

Allowed verdicts:
- `SAFE`: not reachable from peer, network, RPC, consensus input, disk state,
  or other untrusted input.
- `EXPLOITABLE`: attacker-controlled input can reach the panic; emit a finding
  block in the shard output.
- `NEEDS_REVIEW`: reachability is uncertain; include the exact missing edge.

Outputs:
- `panic_audit_{N}.md` for shard details
- `panic_audit_summary.md` with counts and all `EXPLOITABLE` /
  `NEEDS_REVIEW` entries

### Sweep B: Coverage Fill

If `subsystem_coverage_gap.md` reports coverage below 60%, split the uncited
file table into bounded shards. For each assigned file, read the source file
and audit every function with these minimum checks:
- boundary/length validation
- panic safety
- signature/authentication-before-state
- peer/network amplification or unbounded loop
- serialization/deserialization mismatch

Every function must get a verdict line. Findings are allowed only when backed
by file:line evidence; `SAFE` verdicts are valid and expected.

Output: `coverage_fill_{N}.md`.

### Sweep C: Symmetric Pair Audit

Read `xref_map.md` and existing depth findings. Mechanically enumerate pair
names such as `validate/produce`, `encode/decode`, `increment/decrement`,
`accept/reject`, `lock/unlock`, `request/respond`, and `gossip/receive`.
Audit the counterpart for inverted preconditions, missing validation, or
asymmetric state updates.

Output: `symmetric_pair_findings.md` if any pair was audited. If no pairs are
identified, record that in `graph_sweep_summary.md`.

### Sweep D: Field-Validation Matrix

Use `repo_map.md`, `type_hierarchy.md`, and `xref_map.md` as the work queue.
Enumerate peer/RPC/consensus-supplied structs and messages whose names or
fields include `Block`, `Header`, `Tx`, `Transaction`, `Commitment`, `Proof`,
`Signature`, `Signed`, `Peer`, `Gossip`, `Chunk`, `Request`, or `Response`.
Also enumerate sidecar / extension / witness / blob / optional-consensus data
attached to a block or transaction, especially data that is not obviously part
of the canonical block or transaction hash.

For every externally supplied field, write one row:

| Object | Field | Source | Validator / Binding | Missing? | Evidence |
|--------|-------|--------|---------------------|----------|----------|

Mandatory checks:
- replay guard: nonce, sequence, chain/domain/fork ID, expiry, or equivalent
- ID binding: claimed hash/id equals recomputed bytes and is what the
  signature covers
- sidecar / extension-data binding: extension blocks, witnesses, blobs,
  MWEB-like payloads, DA sidecars, and non-hash-committed serialized data are
  either bound into the canonical block/tx identity OR independently
  revalidated at block connection before acceptance
- parent/height/time binding for block/header structures
- length/bounds validation for vectors, proof arrays, commitments, chunks
- persistence-key binding: stored key cannot disagree with signed/hash input

Write `field_validation_matrix.md` in all L1 graph-sweep runs when such
objects exist. If every row is safe, keep the table and write `No findings`.
Do not skip this as "covered by depth"; this sweep is exhaustive enumeration,
not attention-driven reasoning.

### Sweep E: Primitive Correctness Queue

Use `repo_map.md` to enumerate files/functions matching primitive surfaces:
`merkle`, `proof`, `validate_path`, `validate_chunk`, `from_compact`,
`to_compact`, `serialize`, `deserialize`, `codec`, `difficulty`, `ema`,
`log10`, `pow`, `round`, `nonce`, `signature`, `hash`, `commitment`.

For every candidate primitive, write a verdict row:

| Primitive | Expected invariant | Edge vectors tested | Verdict | Evidence |
|-----------|--------------------|---------------------|---------|----------|

Mandatory edge vectors:
- empty/singleton/multi-element trees and proof length exactness
- every verifier input affects the validation outcome; no proof parameter is
  parsed but ignored
- leaf binding, target offset binding, and root recomputation equality
- encode/decode cursor advancement and trailing-byte rejection
- encode/decode byte arithmetic: bytes consumed by every decode branch equals
  bytes emitted by the corresponding encode branch
- integer/fixed-point edges: exact boundary, one below, one above, max/min
- EMA/oracle direction: identify current-cycle vs previous-cycle inputs and
  verify the implementation uses the documented direction
- floating/platform-sensitive operations in consensus paths
- proof-of-computation determinism: VDF/PoW/recursive-hash seed inputs must be
  unpredictable before the commitment point and must include all consensus
  domain separators needed to prevent precomputation or cross-context reuse
- heavy verifier early rejection: impossible length, step-count, timestamp, and
  domain values must be rejected before expensive replay loops
- error-return hygiene: functions returning `Result` must have reachable error
  conditions or should not imply fallibility

Write `primitive_correctness_findings.md` whenever primitive candidates exist.
Safe rows are valid. Findings require file:line evidence.

### Sweep F: Network Amplification Flow Queue

Use `call_graph_p2p.md`, `concurrency_inventory.md`, and `xref_map.md` to
enumerate ingress-to-egress paths:

| Ingress | Dedup / seen-cache point | Validation point | Egress / loop | Verdict | Evidence |
|---------|--------------------------|------------------|---------------|---------|----------|

Mandatory checks:
- cache/dedup happens after validation, or poisoned entries are rolled back
- valid but repeated input cannot trigger unbounded re-gossip or echo
- peer list / handshake / outbound request fanout has concurrency and timeout
  bounds
- sequential `.await` or blocking loops over peers have bounded peer count and
  per-peer timeout
- score/reputation reward paths have symmetric penalties for timeout,
  non-response, parse error, invalid data, and failed delivery
- endpoint success responses reflect actual downstream delivery; do not return
  success when a queued send, gossip, or storage delivery failed
- valid-message echo is bounded: a peer cannot repeatedly trigger fan-out by
  changing non-identity fields while preserving payload validity

Write `network_amplification_findings.md` when P2P/network/mempool/RPC
surfaces exist. Safe rows are valid. Findings require file:line evidence.

### Sweep G: Lifecycle / Replay Set-Cover Queue

Use `repo_map.md`, `xref_map.md`, `call_graph_consensus.md`, `call_graph_p2p.md`,
and `concurrency_inventory.md` to enumerate all cache/pool/pending/seen-state
objects and all signed or identity-bearing message types.

For every cache-like object, write one row per lifecycle leg:

| Object | Insert | Consume | Evict on success | Evict on error | Evict on reorg/expiry | Verdict | Evidence |
|--------|--------|---------|------------------|----------------|-----------------------|---------|----------|

For every signed or identity-bearing message/transaction, write one row:

| Message | Identity hash | Replay guard | Sender binding | Domain/fork binding | Consumption marker | Verdict | Evidence |
|---------|---------------|--------------|----------------|---------------------|--------------------|---------|----------|

Mandatory checks:
- cache insert is bounded by size/TTL before the insert, not after
- failed validation, invalid block, delivery failure, and parse failure clear or
  penalize the same state as the success path
- mutated sidecar cache poisoning: malformed sidecar / extension / witness /
  blob data for a valid block or tx identity must be evicted or replaceable
  after failed validation, and must not block later valid sidecar, RPC, or
  mining submission for the same identity
- reorg/fork-choice rollback invalidates caches keyed by block, epoch, anchor,
  partition, chunk, nonce, peer, or score context
- every user transaction, system transaction, commitment, gossip message, and
  RPC-submitted object has a nonce/sequence/anchor/expiry/consumed marker or
  equivalent replay defense
- peer-score rewards cannot be farmed by repeated successful reads, health
  checks, `/get_data`, or delivery acknowledgements without rate/dedup caps

Write `lifecycle_replay_findings.md` when any cache/pool/seen/replay/scoring
surface exists. Safe rows are valid. Findings require file:line evidence.

Do not proceed to inventory, invariants, depth, verification, or report.

---

## Step 4a: Finding Inventory

Spawn ONE haiku agent. Reads all discovery artifacts assigned by the driver
manifest, including `{SCRATCHPAD}/analysis_*.md`,
`{SCRATCHPAD}/coverage_fill_*.md`, `{SCRATCHPAD}/panic_audit_*.md`,
`{SCRATCHPAD}/panic_audit_summary.md`, `{SCRATCHPAD}/symmetric_pair_findings.md`,
`{SCRATCHPAD}/field_validation_matrix.md`,
`{SCRATCHPAD}/primitive_correctness_findings.md`, and
`{SCRATCHPAD}/network_amplification_findings.md`,
`{SCRATCHPAD}/lifecycle_replay_findings.md`, and
`{SCRATCHPAD}/attention_repair_findings.md` when present. Merges by root cause
(dedup key: file, line range ±5, vulnerability class). Returns
`findings_inventory.md` with F-01..F-N IDs, evidence tags, cross-domain
dependency tags. per §WRITE-THEN-VERIFY.

### Step 3b: THOROUGH-ONLY: Breadth Re-Scan

Runs after first-pass breadth and before Step 4a inventory. Spawn 2 sonnet
agents in parallel. Both read first-pass `analysis_*.md` files as the
exclusion set and cover half the scope with contrastive framing per
`rules/phase3b-rescan-prompt.md`. Returns `analysis_rescan_1.md` +
`analysis_rescan_2.md` per §WRITE-THEN-VERIFY. If 0 new findings above Info,
skip iteration 2. Do not read or write `findings_inventory.md`.

### Step 3c: THOROUGH-ONLY: Per-Contract Analysis

Runs after Step 3b and before Step 4a inventory. Per
`rules/phase3b-rescan-prompt.md` §"Phase 3c". Spawn 1 sonnet agent per file
cluster (related subsystem files, max 5 clusters). Each agent focuses on its
cluster at max depth with zero distraction from other clusters. Returns
`analysis_percontract_{cluster}.md` per §WRITE-THEN-VERIFY. Do not read or
write `findings_inventory.md`.

### Step 4a Handoff

Step 4a inventory runs once after first-pass breadth, Step 3b re-scan, and
Step 3c per-contract analysis. It consumes `analysis_*.md`,
`analysis_rescan_*.md`, and `analysis_percontract_*.md` in a single inventory
build. No earlier phase may create, append, or re-merge `findings_inventory.md`.

---

## Step 4a.5: Semantic Invariants

Spawn ONE sonnet agent. Reads `threat_model.md`, `subsystem_map.md`, `findings_inventory.md`. Identifies L1 invariants: non-determinism, state completeness, safety (no double-vote, no finality reversal), liveness (no unbounded loops), validator lifecycle, hardfork activation. Returns `semantic_invariants.md` per §WRITE-THEN-VERIFY.

---

## Step 4b: Depth Loop

Spawn 5 depth agents in ONE message (all parallel), each as `general-purpose`:

| Agent | Model | Reads (from `scip/`) | Skills |
|---|---|---|---|
| `depth-consensus-invariant` | claude-opus-5 | `call_graph_consensus.md`, `repo_map.md`, `xref_map.md` | consensus-safety, consensus-math-correctness (if difficulty / reward / EMA math detected), fork-choice, light-client, BLS, validator-lifecycle, hardfork, data-availability-enforcement (if `DATA_AVAILABILITY=true`) |
| `depth-network-surface` | claude-opus-5 | `call_graph_p2p.md`, `concurrency_inventory.md`, `panic_sites.md` | p2p-dos, mempool, RPC |
| `depth-state-trace` | claude-opus-5 | `call_graph_execution.md`, `type_hierarchy.md` | state-sync-pruning, execution-client-hardening |
| `depth-external` | sonnet | `xref_map.md`, `type_hierarchy.md` | dependency-audit-nodeclient, cross-environment-semantic-drift |
| `depth-edge-case` | sonnet | `repo_map.md`, `xref_map.md` | zero-state, boundary checks |

Each agent prompt includes:
1. `Read ~/.claude/agents/depth-{role}.md` for full methodology
2. The §SCIP-PREBAKE directive (verbatim)
3. The §WRITE-THEN-VERIFY directive
4. SCOPE CONTAINMENT
5. (Thorough only) The §STEP-TRACE directive — produces `step_execution_trace_{role}.md`

If an agent has performed fewer than 2 pre-baked `scip/*.md` reads before
starting analysis, it MUST stop immediately: write
`[HALT] pre-baked reads insufficient` as the first line of its output file,
append `[GATE FAIL] {agent}: pre-baked reads` to `violations.md`, and return
no findings. The driver will retry the phase with explicit read guidance.

### Depth agent YAML header (mandatory)

Every `depth_*_findings.md` MUST begin with:

```yaml
---
agent: {role}
model: {model}
iteration: 1
prebaked_files_read:
  - file: scip/call_graph_consensus.md
    size_kb: 12
    symbols_cited: ["BeginBlocker", "Slash"]
  - file: scip/repo_map.md
    size_kb: 35
primitive_calls_bash: []
fallback_to_grep: false
---
```

### Telemetry gate (after all depth agents return)

Internal milestone — replaced the previous bash `grep -c '^\s*- file:.*scip/'` gate
with a Python YAML-aware check. The grep approach only matched the
multi-line block form (`  - file: scip/...`) and emitted false-alarm
[GATE FAIL]s on any agent that wrote the equivalent inline-array form
(`prebaked_files_read: [{file: scip/...}, ...]` or
`prebaked_files_read: ["scip/...", ...]`). The Python check accepts
both forms and is whitespace-tolerant.

```bash
python - <<'PYEOF'
import os, re, glob
sp = "{SCRATCHPAD}"
viol_path = os.path.join(sp, "violations.md")
fails = []
for f in sorted(glob.glob(os.path.join(sp, "depth_*_findings.md"))):
    name = os.path.basename(f).replace("depth_", "").replace("_findings.md", "")
    try:
        text = open(f, encoding="utf-8", errors="replace").read()
    except Exception:
        fails.append(f"{name}: unreadable")
        continue
    m = re.match(r"^---\s*\n(.*?)\n---\s*", text, re.DOTALL)
    if not m:
        fails.append(f"{name}: no YAML header")
        continue
    header = m.group(1)
    # Block form:   "  - file: scip/foo.md"   (or any path containing /scip/)
    block = len(re.findall(
        r"(?m)^\s*-\s+file\s*:\s*[\"']?[^\"'\s]*scip/", header))
    # Inline-array form: prebaked_files_read: [scip/a.md, scip/b.md]
    #                or  prebaked_files_read: [{file: scip/a.md}, {file: scip/b.md}]
    inline = 0
    im = re.search(r"prebaked_files_read\s*:\s*\[(.*?)\]", header, re.DOTALL)
    if im:
        inline = len(re.findall(r"scip/", im.group(1)))
    total = max(block, inline)
    if total < 2:
        fails.append(f"{name}: {total} pre-baked reads (need >=2)")
if fails:
    with open(viol_path, "a", encoding="utf-8") as v:
        for line in fails:
            v.write(f"[GATE FAIL] {line}\n")
    for line in fails:
        print(f"[GATE FAIL] {line}")
PYEOF
```

Core mode: iteration 1 + transient confidence routing (2-axis). See Step 4b.3 for Thorough-only iterations.

### Step 4b.1: Transient confidence routing (Core: 2-axis, Thorough: 3 code-evidence axes)

Ask ONE sonnet-class helper to return a compact routing table to the
coordinator per `rules/phase4-confidence-scoring.md`. It reads completed
depth evidence but has no scratchpad write authority. The driver independently
publishes `confidence_scores.md` after the depth wave. If the helper fails,
route every unresolved Medium+ candidate as UNCERTAIN.
- **Core mode**: 2-axis routing (Evidence × 0.5 + Analysis_Quality × 0.5). No iteration 2.
- **Thorough mode**: 3-axis routing (Evidence × 0.25 + Consensus × 0.25 + Analysis_Quality × 0.3). Findings with composite < 0.7 are UNCERTAIN and route to Step 4b.3.

### Step 4b.2: THOROUGH-ONLY: Design Stress Testing (1 reserved slot, UNCONDITIONAL)

Spawn ONE sonnet agent. Reads `design_context.md`, `semantic_invariants.md`, `findings_inventory.md`. Asks: under what operational parameters does the protocol's stated design break? Produce findings about design-level limits (e.g. maximum validators, minimum stake, timeout bounds, adjustment factors at extreme values). Returns `design_stress_findings.md` per §WRITE-THEN-VERIFY.

### Step 4b.3: THOROUGH-ONLY: Depth iteration 2 (Devil's Advocate)

Per `rules/phase4-confidence-scoring.md` §"Hard Devil's Advocate Role". For each UNCERTAIN finding in the transient routing table (or recall-safe fallback), spawn a DA agent with the contrastive prompt: "You are the Devil's Advocate. Your PRIMARY job is to find what the previous analysis MISSED. The prior agent explored {analysis path summary} — you MUST explore a DIFFERENT path." Each DA agent receives Max 5 findings via `extract_evidence_only()` card format (no verdicts, no reasoning contamination). Writes `depth_iter2_{type}_findings.md` per §WRITE-THEN-VERIFY. Re-routing is new-evidence-only per Rule AD-5.

If iter 2 produces progress on any finding → spawn iter 3 with the same DA role. Hard cap: 3 iterations total.

### Step 4b.4: THOROUGH-ONLY: Finding Perturbation + Skill Execution Checklist

Two parallel agents:
1. **Perturbation** (sonnet): reads `findings_inventory.md` + `depth_*_findings.md`. For each finding, apply structured mutations (DIRECTION_FLIP, TIMING_SHIFT, ACTOR_SWAP) to discover adjacent vulnerabilities. Writes `perturbation_findings.md` per §WRITE-THEN-VERIFY.
2. **Skill Execution Checklist** (haiku): reads all `depth_*_findings.md`. For each agent, verifies each skill step was executed. Writes `skill_execution_gaps.md` listing skipped steps. Gaps feed into iter 3 DA input.

### Step 4b.5: THOROUGH-ONLY: Iteration 2 depth gate

Before leaving Step 4b, write `{SCRATCHPAD}/never_cut_checkpoint.md` with one
line per mandatory category.

**REQUIRED LINE FORMAT** — `label: STATUS rest-of-line`. The driver parses
this with a regex anchored to `^{label}:\s*(SPAWNED|SKIPPED)`. Markdown
tables, YAML blocks, indented nested lists, and headings are ALSO accepted
by the relaxed parser, but the plain form below is the canonical shape.
Do NOT invent new labels or new statuses.

```text
depth-consensus-invariant: SPAWNED {SCRATCHPAD}/depth_consensus_invariant_findings.md
depth-network-surface: SPAWNED {SCRATCHPAD}/depth_network_surface_findings.md
depth-state-trace: SPAWNED {SCRATCHPAD}/depth_state_trace_findings.md
depth-external: SPAWNED {SCRATCHPAD}/depth_external_findings.md
depth-edge-case: SPAWNED {SCRATCHPAD}/depth_edge_case_findings.md
design-stress: SPAWNED {SCRATCHPAD}/design_stress_findings.md
perturbation: SPAWNED {SCRATCHPAD}/perturbation_findings.md
confidence-scoring: SPAWNED {SCRATCHPAD}/confidence_scores.md
skill-execution-checklist: SPAWNED {SCRATCHPAD}/skill_execution_gaps.md
```

If a category is intentionally skipped, write
`SKIPPED {NO_APPLICABLE_FLAG|LANGUAGE_LANE_NOT_DETECTED|EMPTY_SCOPE_AFTER_MANIFEST}`.
Any other skip reason is invalid.

**Worked skip example** — if the codebase has no BLS aggregation surface,
the `design-stress` spawn skips BLS-specific stressors; write:

```text
design-stress: SKIPPED NO_APPLICABLE_FLAG (no BLS/consensus-crypto surface detected)
```

The parenthesised tail is free-form; the parser only reads the status word
and the first `[A-Z_]+` reason token after it.

Mandatory: if ANY uncertain finding is Medium+ severity, iter 2 MUST run. Iter 2 skip is a WORKFLOW VIOLATION per CLAUDE.md Rule 12. Log to `violations.md` if iter 2 is skipped despite qualifying findings.

Before returning from Step 4b, write `{SCRATCHPAD}/depth_exit.md`.

**REQUIRED SHAPE** — `criterion: N` / `rationale: text` / a `- path` list.
The driver also accepts a markdown table with `| criterion | N |` and
`| rationale | text |` rows (the `_validate_depth_exit` regex matches both
shapes). Plain YAML is still the canonical form.

```yaml
criterion: 1
rationale: short plain-English explanation
explored_paths:
  - path one
  - path two
  - path three
```

`criterion` must be one of `1`, `2`, `3`, `4`. `rationale` must be non-empty.
If you return a "no new findings / exit criterion 4" result, `explored_paths`
must contain at least 3 distinct paths that were actually examined.

---

## Step 4b.5: Attention Repair

Run only when the driver writes `{SCRATCHPAD}/attention_repair_queue.md`.
This phase is a bounded repair pass for proven attention gaps; it is not a
second breadth or depth iteration.

Inputs:
- `{SCRATCHPAD}/attention_repair_queue.md`
- The exact source file or artifact named in each queue row
- `scip/repo_map.md`, `scip/xref_map.md`, or a call graph only when the row
  needs symbol resolution

Do not read all breadth outputs, all depth outputs, or the full scratchpad.
Do not re-open already verified findings unless a queue row names that finding.

For every queue row, write one row to `attention_repair_summary.md`:

| Queue # | Kind | Target | Verdict | Evidence | Notes |
|---------|------|--------|---------|----------|-------|

Receipt contract:
- `Queue #`, `Kind`, and `Target` must copy the queue row exactly.
- Path targets must use the full relative path, not only the basename.
- `Evidence` must cite the exact target path again with file:line evidence,
  or cite the exact target path and mark `NEEDS_HUMAN` if unavailable.

Allowed verdicts:
- `SAFE`: reviewed and no issue; include file:line evidence or a concrete
  reason why the row is unreachable.
- `CONFIRMED`: issue exists; write a finding block in
  `attention_repair_findings.md`.
- `NO_FINDING`: row was stale or already covered by a precise existing finding;
  cite the existing finding/source.
- `NEEDS_HUMAN`: only if source is unavailable or semantics depend on runtime
  data outside the repository.

Confirmed findings must use IDs `ATT-1`, `ATT-2`, ... and the standard fields:

```markdown
### Finding [ATT-1]: title
**Severity**: High
**Location**: crates/path/src/file.rs:L123
**Preferred Tag**: CODE-TRACE
**Evidence Tag**: CODE-TRACE
**Source IDs**: attention_repair_queue.md row N
**Description**: ...
```

Repair priorities:
- NOTREAD files: inspect every queued file and enumerate each externally
  reachable function for boundary, panic, authentication-before-state,
  replay, lifecycle, and amplification issues.
- Uncited security files: inspect only the named file and direct callers/callees
  needed to determine reachability.
- Graph rows: resolve the exact uncertain row and either confirm it with
  evidence or mark it SAFE with the missing edge explained.

SCOPE: Write ONLY to `attention_repair_summary.md` and, if needed,
`attention_repair_findings.md`. Do NOT proceed to RAG, verification, or report.

---

## Step 4b.6: RAG Validation Sweep

Spawn ONE sonnet-class precedent agent per
`rules/phase4-confidence-scoring.md` §"Phase 4b.5". Claude headless may use the
receipt-bound singleton `unified-vuln-db`; Claude PTY and Codex use governed Web
research. If neither route is available, record typed `UNAVAILABLE` context.
Never invent a numeric floor or use precedent to change confidence, verdict,
severity, proof, or remaining depth. Returns `rag_validation.md` per
§WRITE-THEN-VERIFY.

---

## Step 4d: Verification Queue Manifest (orchestrator inline)

Read `findings_inventory.md`. Extract findings by mode:
- **Thorough**: ALL severities (Critical, High, Medium, Low, Informational) + chain hypothesis IDs. Per CLAUDE.md Rule 12 ("Verification scope: ALL severities (with fuzz)") and `rules/phase5-poc-execution.md` Verification Completeness Assert.
- **Core**: Medium+ + chain hypothesis IDs.
- **Light**: Medium+.

Write `{SCRATCHPAD}/verification_queue.md`:

```markdown
# Verification Queue Manifest
| Queue # | Finding ID | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact |
|---------|-----------|----------|-------|-----------|--------------|----------|------------------|
| 1 | F-01 | High | ... | ... | [DIFF-PASS] | path/to/file.rs:123 | depth_network_surface_findings.md |
Total: {N} findings | Expected verify_*.md files: {N}
```

`Primary Artifact` must be the narrowest prior artifact that already contains
the finding body or strongest source citation (for example:
`depth_network_surface_findings.md`, `design_stress_findings.md`,
`analysis_rescan_1.md`). Do NOT list broad catch-all files unless no narrower
artifact exists.

Assert manifest is non-empty. If all findings are Low/Info, log to
violations.md and skip Step 5.

---

## Step 4e: Semantic Dedup (L1 only — replaces SC chain grouping)

Read `~/.claude/prompts/shared/v2/phase4e-semantic-dedup.md` for the full agent
prompt template.

L1 has no chain analysis phase (Phase 4c removed). In SC, chain Agent 1's
grouping step naturally deduplicates findings. Without an equivalent for L1,
the same bug reported by multiple depth agents enters verification N times,
wasting budget.

This phase runs a single sonnet agent that:
1. Reads the exact typed, bounded block/pair/focus packet derived from the
   current canonical `findings_inventory.md`
2. Makes semantic merge/keep decisions for each candidate pair
3. Identifies cross-file pattern groups (same bug at different locations)
4. Writes only the proposal artifact `dedup_decisions.md`

The model never mutates a verification queue. The driver applies accepted
proposals through the crash-safe pre-queue semantic-dedup transaction, which
atomically publishes the canonical post-dedup inventory, its exact typed
records projection, the applied receipt, the absorbed-ID alias map, and the
read-only deduped inventory projection. Missing or failed signal enumeration
degrades to a DRIVER-owned inventory passthrough with visible debt and no
negative conclusion. Verification queues and shards are derived later from
the committed canonical inventory.

---

## Step 5: Verification

Read `{SCRATCHPAD}/verification_queue.md` or the shard manifest assigned by the
driver (`verification_queue_crithigh.md`, `verification_queue_medium_a.md`,
`verification_queue_medium_b.md`, or `verification_queue_low.md`).

Process the assigned rows directly in the current phase agent. Do NOT spawn one
subagent per finding. Prior L1 runs showed that nested verifier swarms dominate
usage and do not improve promotion quality compared with bounded shard-local
verification.

The driver uses severity-aware bounded shards and runs every verify shard on
Sonnet: Critical/High target ~8 rows, Medium target ~12 rows, Low/Info target
~18 rows. Empty shard slots are skipped by the driver, so this does not add
cost on smaller audits.

**Bug-class routing table**:

| Bug class | Evidence tag |
|---|---|
| Fork-diff / cross-env | `[DIFF-PASS]` |
| Non-determinism | `[NON-DET-PASS]` |
| Consensus invariant | `[CONFORMANCE-PASS]` |
| Network DoS | `[FUZZ-PASS]` |
| Light-client proof | `[CONFORMANCE-PASS]` |
| RPC / execution | `[POC-PASS]` |
| BLS / crypto | `[CONFORMANCE-PASS]` |
| SCIP-backed trace | `[LSP-TRACE]` |
| Fallback (no mechanical path) | `[CODE-TRACE]` |

**Verifier row template** (repeat directly in the current phase for each assigned finding):

```
Phase 5 Verifier for {FINDING_ID}: {TITLE}
Location: {LOCATION} | Bug class: {CLASS} | Preferred tag: {TAG} | Primary Artifact: {PRIMARY_ARTIFACT}
PoC Class: {POC_CLASS} | Test infrastructure: {SCRATCHPAD}/test_infrastructure.md
Produce mechanical verification per preferred workflow. If it fails, try one variant before
falling back to [LSP-TRACE] (requires scip/ citation) or [CODE-TRACE] (caps at CONTESTED).
Read ONLY:
1. your row in `{SCRATCHPAD}/verification_queue.md`
2. the exact source file(s) at `{LOCATION}`
3. `{SCRATCHPAD}/{PRIMARY_ARTIFACT}`
4. one relevant `scip/*.md` helper or build artifact if the preferred workflow requires it
5. `{SCRATCHPAD}/test_infrastructure.md` (for poc_class: unit|property — use constructors and patterns)
Do NOT read unrelated `verify_*.md`, unrelated depth artifacts, or the full
`findings_inventory.md` unless `{PRIMARY_ARTIFACT}` is missing.
Write ONLY `{SCRATCHPAD}/verify_{FINDING_ID}.md`. Do NOT write
`skeptic_findings.md`, `skeptic_judge_decisions.md`,
`cross_batch_consistency.md` (or any `cross_batch_consistency*.md` /
`skeptic*.md` / `judge*.md` variant) — those are produced by Step 5.4
(crossbatch) and Step 5.5 (skeptic-judge) in dedicated subsequent phases
that the V2 driver runs separately. Inline writes from a verify shard are
quarantined to `_overflow/` automatically (internal milestone) but recurring
violations indicate methodology drift; respect the phase boundary.
Write your result to {SCRATCHPAD}/verify_{FINDING_ID}.md per §WRITE-THEN-VERIFY.
Return ONLY: "DONE: {FINDING_ID} verdict={VERDICT} tag={TAG}"
Include in the file:
- Preferred Tag: {TAG}
- Evidence Tag: {ACTUAL_TAG_USED}
- Verdict (CONFIRMED/REFUTED/CONTESTED/INFEASIBLE/FALSE_POSITIVE)
- Suggested Fix (if CONFIRMED)
- Execution Output
Missing `Preferred Tag:` is a schema failure.
SCOPE: Verify ONLY this finding for this row, write its file, then continue to
the next assigned row. After all assigned rows are written, return and stop.
```

### Step 5.3: Completeness Assert (runs after ALL verifier batches return)

```bash
EXPECTED=$(grep -c '^|' "{SCRATCHPAD}/verification_queue.md" | tail -1)
ACTUAL=$(ls "{SCRATCHPAD}"/verify_*.md 2>/dev/null | wc -l)
[ "$ACTUAL" -lt "$EXPECTED" ] && echo "[VERIFY GATE FAIL] $ACTUAL/$EXPECTED files" | tee -a "{SCRATCHPAD}/violations.md"
```

If missing, re-spawn verifiers for missing IDs. Do NOT proceed to 5.4/5.5 until this gate passes.

### Step 5.4: Cross-batch Consistency (Core + Thorough, runs after 5.3)

Spawn ONE haiku agent. Reads all `verify_*.md`. Asserts: (a) all Medium+ findings have evidence tags, (b) all verifier files preserve the queue manifest's `Preferred Tag`, (c) no two findings at the same location contradict each other, (d) severity in verifier matches severity in inventory. Returns `cross_batch_consistency.md`. Orchestrator logs inconsistencies to `violations.md`.

### Step 5.5: THOROUGH-ONLY: Skeptic-Judge for HIGH/CRIT (runs after 5.4)

Spawn ONE sonnet Skeptic agent with INVERSION MANDATE: "For each Critical and High finding in `verify_core.md`, argue the OPPOSITE. What assumption is wrong? What defense did the verifier miss? Produce a counter-case per finding." Skeptic reads all C+H `verify_*.md` files. Returns `skeptic_findings.md` per §WRITE-THEN-VERIFY.

Spawn ONE haiku Judge agent. Reads Skeptic output + original verifier outputs. For each C+H finding, resolves: ORIGINAL VERDICT / SKEPTIC CORRECT (downgrade or refute) / UNRESOLVED (flag for human review). Returns `skeptic_judge_decisions.md` per §WRITE-THEN-VERIFY. Orchestrator updates `verify_*.md` files to reflect Judge decisions.

> **UNRESOLVED disposition**: An UNRESOLVED ruling does NOT exclude the finding from the report body. The Index Agent (Phase 6) demotes the finding's severity by 1 tier (Critical→High, High→Medium, Medium→Low, floor: Low) and the tier writer formats it with the `[UNRESOLVED — needs human review]` flag per `rules/report-template.md` § UNRESOLVED finding format. Routing UNRESOLVED to Appendix A is a workflow violation — `_run_report_quality_gate` (driver) treats it as a promotion dropout via the promotion-receipt symmetry check.

### Step 5.6: Aggregate verify_core.md

After 5.3/5.4 (and 5.5 in Thorough), write `verify_core.md` as a summary index of all per-ID verifier results. This is consumed by the Phase 6 index agent.

---

## Step 6: Report

Read `~/.claude/rules/phase6-report-prompts.md` for full prompt templates.

### §L1-REPORT-OVERRIDES (MUST be appended verbatim to EVERY tier writer spawn prompt)

```
## L1 MODE OVERRIDES (MANDATORY — append to every finding section)

1. **Severity matrix**: use `~/.claude/docs/l1-mode/severity-matrix.md`, NOT `rules/report-template.md`.
2. **Mandatory `**Severity rationale**:` field on EVERY finding** (Critical / High / Medium / Low / Informational — no exceptions). Format:
   ```
   **Severity rationale**: Impact: {cell from matrix — e.g., "High — single-client consensus halt"} / Likelihood: {cell — e.g., "Medium — specific conditions"} / Modifiers: {list — e.g., "+1 for Byzantine stake ≥33%", or "none"} / Resulting tier: {final tier}
   ```
3. **L1 evidence tags only**: `[DIFF-PASS]`, `[CONFORMANCE-PASS]`, `[NON-DET-PASS]`, `[FUZZ-PASS]`, `[LSP-TRACE]`, `[POC-PASS]`, `[CODE-TRACE]`. `[LSP-TRACE]` REQUIRES a `{SCRATCHPAD}/scip/*.md` citation in the Evidence field.
4. **Source citation REQUIRED on every finding**: the Evidence field MUST contain a `file:line` reference that exists in the source tree. Extract these from `findings_inventory.md`, `depth_*_findings.md`, or `verify_*.md`. Do NOT extrapolate from summary text. If no source-line citation is available for a finding, the tier writer MUST:
   - Mark the finding `[EVIDENCE: UNVERIFIED EXTRAPOLATION]` in its header, AND
   - Downgrade its severity by 1 tier (floor: Informational), AND
   - Log `[MEDIUM-TIER EXTRAPOLATION] {report_id}: {reason}` to `{SCRATCHPAD}/violations.md`
5. **Latent dead-code calibration**: findings describing code that exists but is not currently reachable in production (dead branches, disabled features, `#[cfg]`-gated paths not in the build) are capped at **High** unless a PoC demonstrates a realistic activation path. They cannot be Critical.
```

### 6a. Index Agent (haiku)

Reads `skeptic_judge_decisions.md` (if present) first, then `findings_inventory.md`, `rag_validation.md`, `verify_core.md`. Open
individual `verify_*.md` files only when `verify_core.md` leaves a finding
ambiguous, contested, cross-referenced, or missing a source-line citation.
Assigns report IDs (C-01, H-01, M-01, L-01, I-01), tier assignments,
cross-references. Returns `report_index.md` per §WRITE-THEN-VERIFY.

Severity authority order:
1. `skeptic_judge_decisions.md`
2. `verify_core.md`
3. `findings_inventory.md`

If a judge decision downgrades or refutes a finding, the index agent MUST use
the judge outcome rather than the original inventory severity.

### 6a.1: Index Completeness Gate

Assert `report_index.md` exists, contains `## Tier Assignments` with all three tier sections. Extract per-tier counts. Re-spawn index agent if gate fails.

### 6b. Tier Writers (3 parallel in ONE message)

1. **Critical+High** — sonnet in the V2 driver, reads ONLY assigned C+H IDs from `report_index.md` + matching `verify_*.md` files + `findings_inventory.md` fallback → `report_critical_high.md`
2. **Medium** — sonnet, reads ONLY assigned M IDs + matching `verify_*.md` files + `findings_inventory.md` fallback → `report_medium.md`
3. **Low+Info** — sonnet, reads ONLY assigned L+I IDs + `findings_inventory.md`; open a matching `verify_*.md` file only if the assigned finding references one → `report_low_info.md`

**Orchestrator MUST append §L1-REPORT-OVERRIDES verbatim to EACH of the three tier writer spawn prompts** (not just a summary, not "see §L1-REPORT-OVERRIDES above" — the actual text must be in every spawn). This is the ONLY mechanism that propagates the L1 directives to the sub-agents, since they do not see this file.

All use §WRITE-THEN-VERIFY. All must produce `**Severity rationale**:` on every finding or the Step 6b.1 gate fails.

### 6b.1: Tier File Completeness Gate (HARD BLOCKER)

For EACH tier file (`report_critical_high.md`, `report_medium.md`, `report_low_info.md`) with >0 assigned findings:

```bash
TIER_FILE="{SCRATCHPAD}/report_{tier}.md"
EXPECTED=$(grep -c '| .-[0-9]' "{SCRATCHPAD}/report_index.md" | tail -1)  # tier count from index
FINDINGS=$(grep -c '^### \[' "$TIER_FILE")
RATIONALES=$(grep -c 'Severity rationale\|Severity Rationale' "$TIER_FILE")
CITATIONS=$(grep -cE '\*\*Location\*\*:\s*`?[^`\s]+\.(rs|go|ts|sol):[0-9]' "$TIER_FILE")
EXTRAPOLATIONS=$(grep -c '\[EVIDENCE: UNVERIFIED EXTRAPOLATION\]' "$TIER_FILE")

# HARD GATES
[ "$FINDINGS" -ne "$EXPECTED" ] && echo "[6b.1 FAIL] $TIER_FILE: $FINDINGS findings, expected $EXPECTED" | tee -a "{SCRATCHPAD}/violations.md"
[ "$RATIONALES" -lt "$FINDINGS" ] && echo "[6b.1 FAIL] $TIER_FILE: $RATIONALES/$FINDINGS severity rationales" | tee -a "{SCRATCHPAD}/violations.md"
[ "$CITATIONS" -lt "$FINDINGS" ] && [ "$EXTRAPOLATIONS" -lt $((FINDINGS - CITATIONS)) ] && \
  echo "[6b.1 FAIL] $TIER_FILE: $CITATIONS source-line citations for $FINDINGS findings ($EXTRAPOLATIONS marked extrapolated)" | tee -a "{SCRATCHPAD}/violations.md"
```

If ANY gate fails → re-spawn the tier writer with the specific violation in the prompt: `"Your previous output failed Gate 6b.1 because {reason}. Fix ALL findings per §L1-REPORT-OVERRIDES and return again."` Max 2 re-spawn attempts per tier. Do NOT proceed to Step 6c until all three tier files pass.

### 6c. Assembler

Model: haiku (≤25 findings) or sonnet (>25). Reads `report_index.md` + three
tier files only. Do NOT reopen `verify_*.md`, `findings_inventory.md`, or
source files unless a mechanical gate explicitly says a citation is missing.
Writes `AUDIT_REPORT.md` to `{PROJECT_ROOT}/AUDIT_REPORT.md` per
§WRITE-THEN-VERIFY. Orchestrator verifies with `ls -lh` + `wc -l`.

Report header includes: L1 mode label, Phase 0.5 Bake status, audit scope path, severity matrix reference.

---

## Step 6.5: Mechanical Report Gates

### Gate 1: Severity rationale (100% coverage) — HARD BLOCKER

```bash
REPORT="{PROJECT_ROOT}/AUDIT_REPORT.md"
FINDINGS=$(grep -c '^### \[' "$REPORT")
RATIONALES=$(grep -c -i 'severity rationale' "$REPORT")
if [ "$RATIONALES" -lt "$FINDINGS" ]; then
  MISSING=$((FINDINGS - RATIONALES))
  echo "[GATE 1 FAIL] $RATIONALES/$FINDINGS rationales ($MISSING missing)" | tee -a "{SCRATCHPAD}/violations.md"
  # Identify which findings lack the field, then re-spawn the assembler with:
  # "Your previous AUDIT_REPORT.md is missing Severity rationale fields on findings X-NN, Y-NN, ...
  #  Re-write EVERY finding section per §L1-REPORT-OVERRIDES point 2 — every finding MUST have
  #  **Severity rationale**: Impact: {cell} / Likelihood: {cell} / Modifiers: {list} / Resulting tier: {tier}
  #  Do NOT proceed until all $FINDINGS findings have the field."
  # Max 2 re-spawn attempts. If still failing, abort and require human intervention.
fi
```

Gate 1 is a BLOCKER — the report cannot be considered complete until 100% coverage.

### Gate 2: Scope leak

```bash
python3 -c "
import re, sys; from pathlib import Path
report = Path('{PROJECT_ROOT}/AUDIT_REPORT.md').read_text()
scope = Path('{SCRATCHPAD}/audit_scope.md').read_text()
prefixes = {l.strip()[2:].rsplit('/',1)[0]+'/' for l in scope.splitlines() if l.strip().startswith('- ')}
for m in re.finditer(r'^### \[([A-Z]-\d+)\]', report, re.M):
  body = report[m.end():report.find('### [', m.end()+1) if '### [' in report[m.end()+1:] else len(report)]
  loc = re.search(r'\*\*Location\*\*:\s*\`?([^\`\s,\n]+)', body)
  if loc and not any(loc.group(1).startswith(p) for p in prefixes):
    print(f'[GATE 2 FAIL] {m.group(1)}: {loc.group(1)} outside scope'); sys.exit(1)
print('[GATE 2 PASS]')
"
```

### Gate 3: Evidence-tag completeness (warn)

```bash
REPORT="{PROJECT_ROOT}/AUDIT_REPORT.md"
CODE_TRACE=$(grep -c '\[CODE-TRACE\]' "$REPORT")
MECHANICAL=$(grep -c '\[DIFF-PASS\]\|\[FUZZ-PASS\]\|\[POC-PASS\]\|\[CONFORMANCE-PASS\]\|\[NON-DET-PASS\]' "$REPORT")
[ "$CODE_TRACE" -gt "$MECHANICAL" ] && [ "$MECHANICAL" -lt 2 ] && \
  echo "[GATE 3 WARN] $CODE_TRACE CODE-TRACE vs $MECHANICAL mechanical" | tee -a "{SCRATCHPAD}/violations.md"
```

### Gate 4: LSP-TRACE honesty (blocker)

```bash
REPORT="{PROJECT_ROOT}/AUDIT_REPORT.md"
LSP_COUNT=$(grep -c '\[LSP-TRACE\]' "$REPORT")
if [ "$LSP_COUNT" -gt 0 ]; then
  CITATIONS=$(grep -B 30 '\[LSP-TRACE\]' "$REPORT" | grep -c 'scip/\|call_graph_\|repo_map\|xref_map')
  [ "$CITATIONS" -lt "$LSP_COUNT" ] && \
    echo "[GATE 4 FAIL] $((LSP_COUNT - CITATIONS)) [LSP-TRACE] tags lack scip/ citations" | tee -a "{SCRATCHPAD}/violations.md"
fi
```

**Gate failure handling**: Gates 1, 2, 4 are blockers. Re-prompt the report writer with the specific correction, re-run all gates. Gate 3 is a warning (logged, not blocking).

---

## Step 6.6: Report Preservation

```bash
TIMESTAMP=$(date -u +%Y-%m-%dT%H%M%SZ)
cp "{PROJECT_ROOT}/AUDIT_REPORT.md" "{SCRATCHPAD}/AUDIT_REPORT.${TIMESTAMP}.md"
echo "[Report preserved] {SCRATCHPAD}/AUDIT_REPORT.${TIMESTAMP}.md"
```

---

## Cross-references

| Purpose | Location |
|---------|----------|
| Design | `docs/l1-mode/design.md` |
| Severity matrix | `docs/l1-mode/severity-matrix.md` |
| Recon prompt | `prompts/l1/phase1-recon-prompt.md` |
| Verification prompt | `prompts/l1/phase5-verification-prompt.md` |
| L1 skills | `agents/skills/injectable/l1/` |
| Depth agents | `agents/depth-consensus-invariant.md`, `agents/depth-network-surface.md` |
| Primitive shim | `plamen_l1/scip_reader.py` |
| Benchmark corpus | `benchmarks/l1/README.md` |
