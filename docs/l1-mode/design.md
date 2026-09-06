# Plamen L1 Mode — Design Document

> **Status**: Design spec v0.5 — implementation delivered; T2/T3 in-scope (see Section 3 for tier expectations).
> **Owner**: PlamenTSV

## 1. Why this mode exists

Plamen today is a mature pipeline for **smart contract audits**. It handles 5k-30k LOC Solidity / Move / Rust-contract codebases via 6 language trees, 113 skills, and 4 depth agent roles. It does not handle **L1 node-client infrastructure**: 50k-500k LOC of Go or Rust implementing consensus, p2p networking, execution engines, mempools, RPC surfaces, cryptography, and state storage.

The gap matters because:

1. **Different bug classes.** L1 bugs are mostly *mechanism-level*: non-determinism, consensus liveness/safety violations, p2p DoS, fork-choice bugs, cross-environment semantic drift. Smart contract bug classes (reentrancy, access control, oracle manipulation) are secondary.
2. **Different audit rhythm.** Sigma Prime budgets 1-3 weeks on threat modeling alone for a Reth audit, and notes 80% of the work is manual. Smart contract audits are days, not weeks.
3. **Different navigation primitives.** OpenZeppelin's own methodology: *"line-by-line code review is not feasible"*. Professional auditors work from attack surfaces and integration points, which Plamen's current file-oriented breadth phase doesn't model.
4. **Chain analysis does not apply.** L1 bugs rarely compound through postcondition→precondition matching the way DeFi bugs do — they are point vulnerabilities in the mechanism itself. Plamen's Phase 4c can be **removed** for L1 mode, not just reworked. This is a real simplification.

## 2. Goals and non-goals

### Goals

- Add a Plamen mode `/plamen l1 [light|core|thorough]` that composes cleanly with existing mode axes.
- Target Go and Rust node clients (Geth, Erigon, Reth, Lighthouse, CometBFT, Cosmos SDK, Substrate).
- **Deliver value across all four tiers** — T0 (patch review) and T1 (subsystem) as Phase 1 smoke tests; T2 (whole-client feature audit) via multi-scoped run composition in Phase 2; T3 (full L1 client audit) with shallower per-subsystem coverage in Phase 3. This is a correction to v0.1-v0.3 which incorrectly treated T2/T3 as non-goals. See Section 3 for the tier-by-tier expectations.
- Ship primitives that also benefit existing modes (SCIP batch indexing, ast-grep, Opengrep are language-agnostic and cross-platform).
- Leave a paper trail: every design decision traces to a cited source or a documented experiment.

### Non-goals

- **Matching human audit depth per subsystem**. Sigma Prime budgets 1-3 weeks on threat modeling alone for a Reth audit; Plamen cannot match that per-module depth. L1 mode is LLM-augmented pattern-matching at scale, not a human-equivalent deep review. Output profile is "breadth + known-class recall," not "novel-exploit discovery."
- **Replacing human auditors**. L1 mode outputs a candidate findings list for human triage, not a shippable audit report.
- **Full formal verification integration**: Verus, Kani, TLA+/Apalache, Coq — deferred beyond Phase 1. Evidence tags reserved for future integration but not wired.
- **CodeQL on private targets**: license-blocked to public OSS. Paid GHAS is available but user preference is OSS-only. Opengrep fills the cross-function intraprocedural gap for free; inter-file taint on private targets falls back to agent reasoning via SCIP.
- **Joern / CPG for Go/Rust**: second-class tooling support. Deferred per research Spike Round 1.
- **Novel-class discovery**. LLM agents are good at recognizing variations of known bug classes (the 15-skill pack codifies these). Inventing a new attack category — "invent a successor to DETER" — is outside the scope of what Plamen claims to do.

## 3. Scope tiers

All four tiers are **in-scope** as of v0.4. The earlier framing that T2/T3 were "out of reach" assumed the naive grep-and-load-context architecture. Rounds 1-3 replaced that with batch SCIP indexing + Opengrep pre-filter + sliced context, which is the same primitive layer that CodeQL uses on the Linux kernel and Semgrep Pro uses on Netflix-scale monorepos. The architecture is already proven at T2/T3 scale in adjacent domains.

| Tier | Scope | Expected output profile | Phase |
|---|---|---|---|
| **T0 — Patch / diff review** | Bounded diff against known baseline (fork-choice tweak, slashing change, precompile addition). ≤2k LOC delta. | Near-complete coverage of the delta. Recall ≥ 50% on known-class bugs in the diff. | ✅ **Phase 1** (smoke test target) |
| **T1 — Subsystem audit** | One bounded subsystem (mempool, fork-choice, p2p, RPC, light client, BLS wrapper). 5k-30k LOC, one language. | Near-complete coverage of the subsystem. Recall ≥ 30% on the Phase 1 benchmark (see Section 11). | ✅ **Phase 1** (smoke test target) |
| **T2 — Whole-client feature audit** | Full node client scoped to one feature path or iterated across subsystems. 50k-150k LOC effective, 2-4 subsystems touched. | Broad coverage via **multi-scoped run composition** — audit each subsystem independently, merge deterministic reports. May produce duplicate findings at subsystem boundaries (deduped at merge time). | ✅ **Phase 2** (primary target) |
| **T3 — Full L1 client audit** | 500k+ LOC, multi-language, multi-subsystem. | **Shallower than human audit per subsystem** but broader sweep. Catches known-class patterns across the entire client. Misses novel-class and subtle cross-subsystem economic bugs. **Positioned as a "first-pass screen" before a human audit, not a replacement.** | ⚠️ **Phase 3** (deferred until Phase 2 is validated) |

### Why T2/T3 became in-scope in v0.4

The v0.1-v0.3 framing treated 500k LOC as a capacity problem. It isn't — it's an **output-profile** problem. CodeQL on the Linux kernel produces output; that output is a candidate list that maintainers triage. Plamen L1 mode in Thorough mode on reth would produce the same kind of candidate list.

What the architecture already delivers at T2/T3:

- **Context**: batch SCIP indexes a 500k LOC Rust workspace in 10-25 minutes once per audit, then queries at sub-millisecond latency. Agent context never holds more than a call-graph slice.
- **Pre-filter**: Opengrep baseline scan narrows the 500k LOC to 50-500 hotspots per rule. Agents analyze hotspots, not files.
- **Skill coverage**: 15 L1 skills codify the known bug classes. A whole-client audit exercises more of them than a subsystem audit, not fewer.
- **Differential diff**: for forks (the most common L1 audit target per OpenZeppelin), the effective scope shrinks to the delta, which is almost always T1-sized even on a T3 base client.

What the architecture does **not** deliver at T2/T3:

- **Per-subsystem depth matching human auditors**. Sigma Prime's 1-3 weeks of threat modeling = deeper than what Plamen does in an hour per subsystem. This is a real gap but does not make the tier "out of reach."
- **Novel-exploit discovery**. LLMs match known classes; they don't invent new ones. T3 bugs Plamen misses will be novel-class bugs that even a human might miss.
- **Cross-subsystem economic reasoning**. MEV-at-protocol-level, validator-cartel dynamics, multi-step coordinated attacks spanning consensus + execution + bridge — these are hard for LLMs. Plamen flags them as `[CROSS-DOMAIN-DEP]` tags but doesn't solve them.

The Phase 1 benchmark (5 T0/T1 targets) is the **smoke test**, not the ceiling. Once Phase 1 exit criteria are met (recall ≥ 30% on the benchmark corpus), Phase 2 launches the multi-scoped-run harness and attempts T2. Phase 3 tackles T3 with the explicit understanding that coverage is "first-pass screen, human triage required."

## 4. Architectural changes vs existing pipeline

### 4.1 Mode composition

`/plamen l1 [light|core|thorough] [path]` — `l1` is a new axis. Existing mode axes (Light/Core/Thorough) control depth loop iterations, verification scope, niche agent activation, and model diversity. L1 axis controls pipeline shape (see table below).

### 4.2 Phase-by-phase delta

| Phase | Smart contract mode | L1 mode | Rationale |
|---|---|---|---|
| **Phase 0 Wizard** | Mode + project + docs + scope + proven-only flag | **Extended**: target type (subsystem / fork-diff / whole-client), base client (reth / geth / cometbft / custom), subsystem selection | L1 audits have structurally different inputs |
| **Phase 0.5 Primitive warmup** | N/A | **NEW**: pre-index the target with gopls/rust-analyzer/ast-grep/Semgrep. Caches results in scratchpad. | rust-analyzer cold start on reth can exceed MCP 300s timeout; must happen before depth agents run |
| **Phase 1 Recon** | Contract/function enumeration, attack surface via AST patterns | **Rewritten**: threat-model-first. Actors/trust boundaries, subsystem map via LSP `workspace/symbol`, fork ancestry via `go.mod` replace / `Cargo.toml` patch, OpenZeppelin 10-point attack surface decomposition | Sigma Prime's threat-model-first approach, OpenZeppelin methodology |
| **Phase 2 Instantiation** | Based on findings count and protocol complexity | **Modified**: based on subsystems detected + diff size (for forks) | Resource allocation follows the real work shape |
| **Phase 3 Breadth** | By file/cluster | **Reorganized by layer**: network / consensus / execution / crypto / storage / rpc / mempool. Each layer gets one agent. | Matches OpenZeppelin decomposition; prevents attention bleed across layers |
| **Phase 3b Rescan** | Anti-saturation re-pass | **Kept**, scoped by layer | Model diversity still useful |
| **Phase 3c Per-contract** | Per inheritance cluster | **Replaced** with per-subsystem focused agent | No inheritance; subsystems are the natural unit |
| **Phase 4a Inventory** | Unchanged format | **Unchanged** | Finding format is format-agnostic |
| **Phase 4a.5 Semantic invariants** | DeFi invariants (vault accounting, token conservation) | **Reframed**: consensus safety/liveness, non-determinism, state machine invariants, protocol-spec invariants | Different invariant space |
| **Phase 4b Depth Loop** | 4 roles × 1-3 iters | **Extended**: +2 roles (`depth-consensus-invariant`, `depth-network-surface`), same iteration protocol, LSP-driven context instead of file-read | Subsystem coverage + primitive-driven context |
| **Phase 4c Chain Analysis** | Postcondition→precondition matching, enabler enumeration | **REMOVED** | L1 bugs are point vulnerabilities. Chain analysis is DeFi-shaped and does not apply. Frees ~400 lines of orchestration and 2 agent classes. |
| **Phase 5 Verification** | PoC via Foundry/Anchor/cargo test | **Rewritten**: differential testing (fork audits), conformance testing (Hive / spec-tests), non-determinism replay, LSP-driven trace. New evidence tags. | Foundry PoC model does not apply to consensus bugs |
| **Phase 6 Report** | Tier writers + assembler | **Unchanged** structure; L1-specific severity matrix | Report template is format-agnostic |

### 4.3 What gets removed

- **Phase 4c chain analysis** (2 agents: Enabler Enumeration + Chain Matching + Composition Coverage). Saves 2 agents per Thorough audit.
- **Per-contract cluster phase 3c** in its current form (replaced with per-subsystem).
- **All DeFi-specific injectable skills** (vault, lending, DEX, governance) do not load for L1 targets.
- **Foundry/Anchor test harness assumption** in Phase 5.

### 4.4 What gets added

- **Phase 0.5 Primitive warmup** (new phase).
- **L1 injectable skill pack** (24 skills, see Section 6).
- **Two new depth agent roles** (see Section 7).
- **New verification evidence tags** (see Section 8).
- **Layer-oriented breadth decomposition** (new recon output).

## 5. Primitives layer (prerequisite)

Before any L1 skill runs, Plamen needs tooling primitives beyond grep. Per research Spikes Round 1-3, the highest-ROI additions are listed below. **Three corrections vs v0.2 after Round 3:**

1. **WSL2 mandate is dropped.** Round 3 validated that the "batch index once, query static artifact forever" pattern (used by LocAgent, IRIS, LLMxCPG) eliminates per-call LSP latency regardless of host OS. `scip-go` and `rust-analyzer scip` both run at compiler speed on Windows, macOS, and Linux. Go issue [#75208](https://github.com/golang/go/issues/75208) remains open but only affects *interactive* gopls — Plamen's primitives do not touch gopls on the hot path.
2. **Opengrep replaces Semgrep OSS.** [Opengrep](https://github.com/opengrep/opengrep) is a January 2025 LGPL-2.1 fork of Semgrep that restored the cross-function (intra-file) taint analysis Semgrep moved to their paid Pro tier. It runs ~3× faster than Semgrep, supports Go and Rust, and is cross-platform including Windows. This closes the "Semgrep Pro gap" from v0.2 at $0. Limitation: cross-function is *intra-file*, not inter-file. For inter-file taint we fall back to agent reasoning via SCIP.
3. **CodeQL is Tier-2 opt-in, not the default.** Round 3 found the [CodeQL CLI license](https://github.com/github/codeql-cli-binaries/blob/main/LICENSE.md) hard-restricts free use to "Open Source Codebases hosted and maintained on GitHub.com". Analyzing a private fork, audit client, or pre-release branch **requires paid GitHub Advanced Security** ($19/committer/month). The user has stated a preference for OSS. CodeQL therefore loads only when the target is a public OSS repo (benchmark runs, upstream mainline audits). A startup prompt gates it.

### 5.1 Tool inventory (v0.3)

| Primitive | Tool | License | Runtime | Plamen integration | Build cost | Priority |
|---|---|---|---|---|---|---|
| **Go semantic index (batch)** | `scip-go` (scip-code/scip-go) | Apache-2.0 | All (Win/Mac/Linux) | Phase 0.5 bake step; output is a SCIP protobuf | ~2 days (integration) | **P0** |
| **Rust semantic index (batch)** | `rust-analyzer scip` | MIT/Apache | All | Phase 0.5 bake step; output is a SCIP protobuf | ~1 day | **P0** |
| **SCIP query shim** | Custom `plamen/scip_reader.py` (~150 LOC) over the sourcegraph/scip protobuf schema | (in-project) | All | MCP tool exposing `find_definition`, `find_references`, `list_symbols_in_file` over the baked artifact | ~1-2 days | **P0** |
| **Structural search** | ast-grep CLI + custom MCP wrapper | MIT | All | MCP exposing `ast_search(pattern, lang, path)`, `ast_diff(rev_a, rev_b, lang)` | ~1 day | **P0** |
| **Intra-file taint + pattern** | **Opengrep** + custom L1 rule pack | LGPL-2.1 | All | MCP wrapper exposing `opengrep_scan(ruleset, path, json)` | ~1 week (rule pack is the bulk) | **P1** |
| **Lexical / sparse retrieval** | ripgrep + `code-sage` or `qex-mcp` | MIT / Apache | All | Evaluate both on reth and geth, pick one | ~1 day (integration) | **P1** |
| **Semantic diff (fork audits)** | tree-sitter + custom tool | (in-project) | All | MCP wrapping `git diff` with symbol-level granularity | ~1 day | **P2** |
| **Interprocedural inter-file taint (opt-in)** | CodeQL CLI | **Free for public OSS only**; paid GHAS otherwise | All | Phase 0.5 opt-in bake step; query pack; SARIF parser | ~2 weeks one-off (custom query pack) | **P2** (conditional) |
| **Live LSP (fallback)** | gopls / rust-analyzer | MIT | All | Only when SCIP index cannot answer (rare: generated code, macro-expanded symbols) | ~1 day per language | **P3** |

### Architectural implication

Phase 0.5 becomes a **mandatory "Bake" phase** that runs ONCE per audit and caches all primitive outputs. Estimated bake time on 16 GB RAM (from Round 3):

| Repo | scip-go / rust-analyzer scip | codeql database create (opt-in) |
|---|---|---|
| go-ethereum (~800k LOC Go) | 3-8 min | 15-30 min |
| cometbft (~200k LOC Go) | 1-2 min | 5-10 min |
| reth (~500k LOC Rust, 500 crates) | 10-25 min | 20-60 min |
| lighthouse (~250k LOC Rust) | 5-15 min | 15-30 min |

These are one-time costs. Every subsequent primitive call is millisecond-latency regardless of host OS. This is the cross-platform win Round 2's WSL2 mandate was trying to achieve — but done by architecture instead of by runtime restriction.

### 5.2 Warmup sequence (Phase 0.5 — "Bake")

Runs once per audit on the host OS (no WSL2 requirement). All steps are shell invocations outside MCP, so 300s timeout does not apply.

1. Detect target language (Go / Rust / mixed) from file extensions and manifest files.
2. Detect target license / visibility (public OSS vs private fork) — sets the CodeQL eligibility flag.
3. For Rust: `rust-analyzer scip --exclude-vendored-libraries <path>` → cache SCIP file path in scratchpad.
4. For Go: `scip-go index <path>` → cache SCIP file path in scratchpad. (Falls back to `go list ./...` warming if scip-go fails.)
5. ast-grep: no warmup needed; runs per-query.
6. Opengrep: run baseline scan with L1 rule pack, cache the hit list at `scratchpad/opengrep_hits.json`.
7. BM25 / lexical index: `code-sage` or `qex-mcp` handles its own indexing; trigger build, wait for readiness file.
8. **CodeQL (opt-in, public OSS only)**: if target is public, `codeql database create --language=go|rust <target>` → cache database path. If private, skip with a log line.
9. Write `scratchpad/primitive_status.md` with availability + cache paths + any fallback flags.

Phase 1 Recon reads `primitive_status.md` and uses cached primitives throughout subsequent phases.

### 5.3 MCP timeout strategy

Existing Plamen MCP tool timeout is 300s per call. **Round 3's batch-indexing pivot resolves this concern for all languages**: the long-running indexing step is a shell command outside MCP, and every subsequent query against the static SCIP file (or CodeQL database, when opt-in) is sub-second. No per-phase timeout overrides needed.

The Round 2 concern about gopls cold start on Windows is moot — Plamen never touches live gopls on the hot path. Live LSP is a P3 fallback only for edge cases the static SCIP index cannot answer (rare).

## 6. L1 injectable skill pack

Skills live under `~/.claude/agents/skills/injectable/l1/` and load conditionally when `L1_PATTERN = true` is set by recon. Each skill is ≤100 lines per post-audit-improvement-protocol anti-bloat gates.

The pack is lifted from the OpenZeppelin infrastructure auditing checklist, cross-referenced with Sigma Prime's 8-layer attack surface model.

| # | Skill | Trigger subclass | Layer covered |
|---|---|---|---|
| 1 | `consensus-safety-invariants` | always (L1_PATTERN) | consensus |
| 1a | `consensus-math-correctness` | difficulty / reward / EMA math detected | consensus |
| 2 | `fork-choice-audit` | consensus detected | consensus |
| 3 | `p2p-dos-and-eclipse` | p2p/networking detected | network |
| 4 | `mempool-asymmetric-dos` | mempool detected | mempool |
| 5 | `light-client-proof-verification` | light-client/IBC detected | cross-chain |
| 6 | `rpc-surface-audit` | RPC handlers detected | rpc |
| 7 | `bls-aggregation-audit` | BLS/crypto-aggregation detected | crypto |
| 8 | `state-sync-pruning` | state-sync/snapshot detected | storage |
| 9 | `execution-client-hardening` | VM/execution-engine detected | execution |
| 10 | `cross-environment-semantic-drift` | L2 / EVM-on-non-EVM / precompile / inherited-base detected | cross-env |

The pack has grown to 24 skills under `agents/skills/injectable/l1/` (excluding the `_opengrep-rules/` local rule pack, which is rules not a skill) as of v0.5 — see the v0.5 change log entry for the full addition list, including `cosmos-sdk-module-safety` and `cosmos-ibc-security` for Cosmos-SDK/IBC targets. The full, current trigger table is maintained in `rules/skill-index.md` under "L1 Skills"; the 10 core rows above are the original set and are not re-numbered here to avoid churn.

### 6.1 Language-specific supplements

Short skill-lets (≤50 lines) that augment the above based on implementation language:

- `go-concurrency-safety` — map iteration non-determinism, goroutine leaks, mutex ordering, panic boundaries, context cancellation
- `rust-unsafe-audit` — unsafe blocks, uninitialized memory, Send/Sync violations, panic safety, drop order
- `dependency-audit-nodeclient` — extends existing `dependency-audit` with Go modules (go.mod, vendor) and Cargo (Cargo.lock, crates.io advisories)

### 6.2 Skill methodology pattern

Every L1 skill follows this structure, matching existing Plamen skills:

```
# SKILL: {name}

## Trigger
{pattern from recon phase}

## Objective
{1-sentence: what attack class this detects}

## Known bug exemplars
{3-5 real production bugs with URLs — validation targets}

## Methodology (for the assigned agent)
{step-by-step: what LSP queries to run, what ast-grep patterns to search,
 what invariants to check, what evidence to gather}

## Output schema
{finding format}

## Fallback if primitives unavailable
{degraded path using grep + manual reasoning}
```

Every skill MUST include fallback methodology because primitive availability is environment-dependent.

## 7. Depth agent roles (shipped in v0.5)

### 7.1 `depth-consensus-invariant`

- **Definition**: `agents/depth-consensus-invariant.md`
- **Input**: consensus code slice (call-graph-sliced via LSP from consensus entry points), extracted invariants from Phase 4a.5, known-bad patterns from skill library
- **Methodology**:
  1. For each documented invariant, enumerate all write sites via LSP `find-references`
  2. For each write site, check if the invariant is preserved under all input partitions
  3. For N-validator scenarios, reason about Byzantine fractions (1/3, 1/2, 2/3 boundaries)
  4. Cross-reference against known consensus bug exemplars (Cosmos Dragonberry, Solana fork-choice, Geth Aug 2021)
- **Evidence tags produced**: `[CONSENSUS-TRACE]`, `[INVARIANT-VIOLATION]`, `[BYZANTINE-CASE]`, `[LSP-TRACE]`

### 7.2 `depth-network-surface`

- **Definition**: `agents/depth-network-surface.md`
- **Input**: p2p/rpc code slice, trust boundaries from recon, known DoS patterns
- **Methodology**:
  1. Enumerate entry points via LSP `workspace/symbol` filtered by known interface names (`Handler`, `Service`, `Api`, `Listener`, message-type enums)
  2. For each entry point, trace forward via LSP call-hierarchy to state mutation
  3. Check: rate limits, message size limits, peer scoring, validation before state change
  4. Cross-reference DETER/MemPurge/eclipse exemplars
- **Evidence tags produced**: `[NETWORK-TRACE]`, `[ASYMMETRIC-COST]`, `[UNBOUNDED-RESOURCE]`, `[UNVALIDATED-INPUT]`, `[LSP-TRACE]`

### 7.3 Existing depth roles still apply

- `depth-state-trace` — still useful for storage/pruning analysis, reframed for node-client state
- `depth-external` — still useful for dependency audits, inter-process/inter-client interactions
- `depth-edge-case` — still useful for boundary conditions in consensus
- `depth-token-flow` — not useful for L1 mode; does not load when `L1_PATTERN = true`

## 8. Verification protocol rewrite

### 8.1 New evidence tags

The existing tag set (`[POC-PASS]`, `[CODE-TRACE]`, `[MEDUSA-PASS]`, etc.) assumes smart contract test harnesses. L1 mode adds:

| Tag | Meaning | Weight | Applies to |
|---|---|---|---|
| `[DIFF-PASS]` | Differential test between fork and upstream produced different output for same input → semantic drift confirmed | 1.0 (mechanical) | fork audits |
| `[DIFF-SAME]` | Differential test produced same output → finding refuted | 0.0 | fork audits |
| `[CONFORMANCE-PASS]` | Spec conformance test (Hive, execution-spec-tests, ICS-23) reports failure | 1.0 | spec-defined behavior |
| `[NON-DET-PASS]` | Ran implementation 2× with same input, got different output → non-determinism confirmed | 1.0 | consensus/state transitions |
| `[FUZZ-PASS]` | Fuzzer (libfuzzer, go-fuzz, Fluffy, D2PFuzz) produced counterexample | 1.0 | mechanically fuzzable surfaces |
| `[LSP-TRACE]` | Manual trace performed using LSP type info and call hierarchy | 0.7 | everything else |
| `[CODE-TRACE]` | Manual trace with concrete values, no LSP assistance (fallback) | 0.6 | fallback when primitives unavailable |

### 8.2 Verification flow (Phase 5)

Each hypothesis is routed by type:

- **Fork diff findings** → try `[DIFF-PASS]` via differential test harness
- **Non-determinism findings** → try `[NON-DET-PASS]` via repeated execution
- **Consensus invariant findings** → try `[CONFORMANCE-PASS]` against spec, fall back to `[LSP-TRACE]`
- **Network DoS findings** → try `[FUZZ-PASS]` via D2PFuzz/Fluffy if available, fall back to `[LSP-TRACE]` + resource analysis
- **Cross-environment drift findings** → try `[DIFF-PASS]` or `[CONFORMANCE-PASS]`
- **Everything else** → `[LSP-TRACE]` as best-effort, `[CODE-TRACE]` as fallback

### 8.3 Confidence model impact

The existing 4-axis confidence model in `rules/phase4-confidence-scoring.md` is reused as-is. New tags slot into the `Axis 1: Evidence` quality mapping. Axis 4 (RAG match) may score lower for L1 findings until a benchmark corpus of L1 vuln writeups is ingested.

## 9. Severity matrix for L1

| Impact | Likelihood: High (permissionless) | Medium (specific conditions) | Low (complex setup) |
|---|---|---|---|
| **Critical** (consensus halt, chain fork, fund loss via mechanism) | **Critical** | **High** | **Medium** |
| **High** (chain reorg enabler, light client bypass, network-wide DoS) | **High** | **High** | **Medium** |
| **Medium** (single-node DoS, privilege escalation, info disclosure) | **Medium** | **Medium** | **Low** |
| **Low** (resource inefficiency, minor inconsistencies) | **Low** | **Low** | **Low** |

**Modifiers** (applied after matrix lookup):
- Requires consensus-level access (>1/3 or >2/3 validator stake) → −1 tier
- Requires privileged position (validator, trusted RPC operator) → −1 tier
- Cross-chain / bridge surface → +1 tier if fund-loss path exists
- Requires fork of target client to exploit → +1 tier (attacker has source-level control)

## 10. Phase 1 milestone plan

Six weeks of fork work, organized by dependency order. **Week 1 rewritten from v0.2** following Round 3 to reflect batch-indexing architecture and Opengrep substitution. Each Week 1 day has a specific exit criterion.

### Week 1 — primitives smoke test (daily breakdown, Round 3 revision)

| Day | Focus | Exit criterion |
|---|---|---|
| **Day 1** | Primitive bake harness. Implement `plamen/scip_reader.py` (parse SCIP protobuf, expose `find_definition` / `find_references` / `list_symbols_in_file`). Wire `scip-go` and `rust-analyzer scip` as Phase 0.5 "Bake" steps. Verify cross-platform on a small Go repo and a small Rust repo (Win / Mac / Linux as available). | SCIP reader returns correct symbol data on both test repos on at least 2 platforms. |
| **Day 2** | Opengrep integration. Install on all available platforms. Write 3 proof-of-concept rules: (a) Go integer underflow in p2p handler (CVE-2024-32972 pattern), (b) Go panic in EndBlocker (Cosmos ASA-2025-003 pattern), (c) Rust missing input validation on deserialization. Verify intra-file cross-function taint works. | All 3 rules compile and produce findings on seeded vulnerable fixtures. Inter-file taint gap documented openly. |
| **Day 3** | CodeQL opt-in path. Install CLI. Add license-gate prompt at `/plamen l1` startup. Bake `codeql database create` as an opt-in Phase 0.5 step. Hello-world custom query for Go: "find all functions named `Handle*Request` that reach a `chain.Get*` call without bounds check." Parse SARIF output to Plamen finding format. | Gate prompt correctly skips CodeQL on private-target input; custom query returns results on a public target. |
| **Day 4** | Benchmark corpus fetch + build. Check out the 5 Phase 1 benchmark targets at their pre-fix commits (see Section 11). Verify each builds on 16 GB. Record build time + peak RAM. Document workarounds if reth OOMs (use `cargo check` + scoped builds). | All 5 targets build; reth build strategy confirmed (may need crate-scoped `cargo check`). |
| **Day 5** | Benchmark corpus baking + ground truth. Run Phase 0.5 Bake (scip + optional codeql) on each target. Record bake time. Download corresponding advisories + audit PDFs. Write ground-truth markdown per target in `benchmarks/l1/<target>/ground_truth.md`. Prepare run harness for Week 6 validation. | All 5 targets have baked indexes + ground truth files. |
| **Day 6** | Skill pack updates from Round 3 + Round 4 gap analysis. Apply methodology nuances from real bugs to every skill's Section 1-6. Add 2 new skills (`validator-lifecycle-and-slashing`, `hardfork-activation-and-protocol-upgrade`). Update `skill-index.md` with L1 entries. | All 13 (now 15) skills updated; skill-index.md registered. |
| **Day 7** | Documentation + smoke test. Bump design.md to v0.4 with Round 4 integration. Write `benchmarks/l1/README.md` with reproduction instructions. Quick smoke: run Opengrep + new rules against geth v1.13.14 and confirm it flags the `count-1` underflow in advance of Week 6 validation. | Smoke test flags the known bug OR produces a clear signal of why it missed. |

### Weeks 2–6

| Week | Focus | Deliverables | Validation |
|---|---|---|---|
| **Week 2** | Primitives hardening + fork-ancestry extension | All Week 1 primitives stable under repeated agent calls; fork-ancestry skill reads `go.mod` replace, `Cargo.toml` patch, and `.git` remotes; semantic diff MCP wraps `git diff` + tree-sitter | Depth agent on a reth fork can see "only the diff" as its context window |
| **Week 3** | Opengrep L1 rule pack (full) | 15-25 intraprocedural rules covering OZ checklist + Round 4 nuances — goroutine leak, missing size-limit on p2p decoder, panic in BeginBlock/EndBlock, RLPx handshake validation, integer truncation at env boundaries | Rule pack flags known bugs in benchmark targets during dry runs |
| **Week 4** | L1 injectable skill pack v0.3 | 15 skills (10 core + 3 language + 2 new from Round 4 gap) finalized, registered in `skill-index.md`, fallback methodologies documented | Each skill reviewable; exemplar sections populated with Round 4 data |
| **Week 5** | L1 mode scaffold | `/plamen l1` command parses mode axis, routes to `prompts/l1/` subtree, Phase 4c removed, Phase 5 stub with new evidence tags, depth agent roles (`depth-consensus-invariant`, `depth-network-surface`) registered | `/plamen l1 light <path>` runs end-to-end on a small Go target |
| **Week 6** | Benchmark run | Run L1 mode against the 5 validation targets in Section 11. Record recall, precision, FP rate. | Quantified recall ≥ 30% against known-bug ground truth (Phase 1 exit criterion) |

**Explicit non-goals for Week 1**: no Semgrep Pro (use Opengrep), no CodeQL for private targets (license), no Kani, no Verus, no Joern, no Hive integration, no Fluffy runtime, no dense embeddings, no hierarchical summarization. These are Phase 2 at earliest.

### Phase 1 exit criteria

1. **Recall ≥ 30%** on the 5-target benchmark (catching 2 of 5 root causes is the minimum signal that L1 mode is viable).
2. **Primitives layer stable on Windows**: no MCP timeouts, no crashes, reproducible on a fresh machine.
3. **No regression on existing modes**: existing Light/Core/Thorough modes on a known EVM target produce the same report as upstream.
4. **All 6 weekly deliverables complete** and merged to mainline.

If recall < 30%, stop before Phase 2 and investigate whether LLMs can meaningfully reason about this class. Option D evolution (full mode, new recon subtree, full Phase 5 rewrite) is wasted effort without evidence the core loop works.

## 11. Validation targets (Round 3 curated corpus)

Round 3 research curated the Phase 1 benchmark from 12 candidates against these constraints: publicly reproducible commit, documented root cause, ≤30k LOC relevant subsystem, 16 GB RAM build feasibility, plausible coverage by the L1 skill pack, class diversity, 2+ Go and 1+ Rust.

### Phase 1 benchmark (top 5)

| # | Target | Language | Class | Sources | Bake feasibility |
|---|---|---|---|---|---|
| **1** | **Geth CVE-2024-32972** `GetHeadersFrom` integer underflow | Go | p2p-dos (boundary substitution) | [GHSA-4xc9-8hmq-j652](https://github.com/ethereum/go-ethereum/security/advisories/GHSA-4xc9-8hmq-j652); vulnerable `v1.13.14`; fix in PR #29534 shipped `v1.13.15` | ~2 GB RAM build |
| **2** | **Geth CVE-2025-24883** RLPx zero pubkey handshake crash | Go | crypto + p2p-dos (missing curve-point validation) | [GHSA-q26p-9cq4-7fc2](https://github.com/ethereum/go-ethereum/security/advisories/GHSA-q26p-9cq4-7fc2); vulnerable `v1.14.12`; fix `159fb1a` shipped `v1.14.13` | ~2 GB build |
| **3** | **Geth CVE-2020-26241** RETURNDATACOPY / dataCopy shallow-copy consensus split | Go | execution-hardening + consensus-safety (cross-client divergence, found by Fluffy OSDI '21) | [NVD CVE-2020-26241](https://nvd.nist.gov/vuln/detail/CVE-2020-26241); vulnerable pre-`v1.9.17`; exploited on mainnet block 13107518 | ~2 GB build; older Go version (~1.15) required |
| **4** | **Cosmos-SDK ASA-2025-003** `x/group` div-by-zero chain halt | Go | consensus-safety (unrecovered panic in governance path) | [GHSA-x5vx-95h7-rv4p](https://github.com/cosmos/cosmos-sdk/security/advisories/GHSA-x5vx-95h7-rv4p); vulnerable `v0.50.11`; fix in `v0.50.12` | ~4 GB build |
| **5** | **Reth Sigma Prime audit** (June 2024, commit `66c9403`) | **Rust** | varies — pick 1-2 concrete findings from audit PDF | [sigp/public-audits](https://github.com/sigp/public-audits) | **Marginal** on 16 GB RAM — use `cargo check --workspace` with scoped crates; document workarounds |

Diversity: 3 bug classes (p2p-dos, crypto, consensus-safety), 4 Go + 1 Rust, all with public writeups + CVE/advisory IDs.

### Phase 2 stretch targets (6-12)

- **Geth CVE-2021-41173** snap/1 trie-node panic ([GHSA-59hh-656j-3p7v](https://github.com/ethereum/go-ethereum/security/advisories/GHSA-59hh-656j-3p7v)) — state-sync class
- **Geth CVE-2023-42319** GraphQL DoS ([GHSA-v9jh-j8px-98vq](https://github.com/advisories/GHSA-v9jh-j8px-98vq)) — rpc-surface class
- **Cosmos-SDK ISA-2025-002** `x/group` EndBlocker panic ([GHSA-47ww-ff84-4jrg](https://github.com/cosmos/cosmos-sdk/security/advisories/GHSA-47ww-ff84-4jrg)) — tests "any error in EndBlocker = chain halt" methodology
- **Cosmos-SDK ISA-2025-005** `x/distribution` integer overflow ([GHSA-p22h-3m2v-cmgh](https://github.com/cosmos/cosmos-sdk/security/advisories/GHSA-p22h-3m2v-cmgh))
- **CometBFT ASA-2025-002** block-part index validation ([GHSA-r3r4-g7hq-pq4f](https://github.com/cometbft/cometbft/security/advisories)) — promote to Phase 1 if reth proves too heavy
- **Forest (Filecoin) Sigma Prime 2021** — Rust alternative to reth
- **Aptos 10/18/23 incident** — deterministic→non-deterministic map refactor; excellent for consensus-safety map-iteration test
- **NEAR "Ping of Death"** ([Zellic](https://www.zellic.io/blog/near-protocol-bug/)) — pre-auth panic; Rust case; $150k Zellic bounty
- **Optimism OVM_ETH SELFDESTRUCT** (Saurik $2M) — cross-env class, historical but well-documented
- **Moonbeam precompile delegatecall** (pwning.eth $1M+) — cross-env class
- **Polkadot Frontier u128 truncation** (pwning.eth $1M) — cross-env class
- **Ghost in the Block** (Asymmetric Research, fastssz offset forging) — light-client + SSZ canonicality

**Corpus note**: Round 4 research surfaced real URLs/CVEs for every skill's exemplar dossier. Skill file v0.2 commits will link targets back to this benchmark table.

## 12. Open questions and risks

### Technical risks

1. **LLM consensus reasoning capability is unproven.** Byzantine multi-actor invariants are adversarial in a way contract logic rarely is. Phase 1 benchmark recall is the capability probe. **If recall < 30%, stop.**
2. **rust-analyzer cold-start on reth may exceed even 600s.** Mitigation: fall back to ast-grep + LSP call-hierarchy only for Rust Thorough mode.
3. **Semgrep Rust interprocedural taint is incomplete** (as of 2026). Rust audits get weaker taint than Go. Mitigation: lean harder on LSP + call-graph slicing for Rust.
4. **No open-source equivalent of CodeQL variant analysis** for scaling "one bug → find everywhere."
5. **Attack-surface enumeration is manual.** LSP `workspace/symbol` + curated interface names is the best available primitive; unverified whether it captures all 8 Sigma Prime attack surfaces automatically.

### Product questions still open

1. **Should verification be optional in Light mode?** Phase 5 rewrite is heavy; Light mode users may prefer findings + CODE-TRACE only.
2. **Does the Codex adapter need parallel L1 work?** Or does L1 mode land in Claude Code only for Phase 1 and backport later? (Likely the latter.)
3. **How do we handle proprietary/audit-time forks** where the base client is not public? (Defer: out of scope for Phase 1.)

### Research debts being answered

- **Validation spike Round 2 — COMPLETED 2026-04-10.** Findings integrated into this doc (v0.2). Full report at `docs/l1-research/tooling-validation.md`.
- **Benchmark writeups** — user will supply later. Until then, Section 11 stands.

### Unknowns only running it can answer (from Round 2)

These must be resolved empirically during Week 1 — they cannot be answered by more research:

1. **gopls `go_search` latency on geth specifically.** No published benchmarks. Day 4 data point.
2. **rust-analyzer SCIP output size on reth.** Does the SCIP index fit in memory for query-time use, or need a SQLite wrapper? Day 3 data point.
3. **Tree-sitter grammars on geth/reth corner cases.** Do Go generics and Rust async blocks match cleanly, or do procedural macros silently fall through?
4. **Semgrep OSS intraprocedural FP rate on geth's `p2p/` and `eth/protocols/`.** No published numbers. Day 5 data point.
5. **WSL2 I/O performance for large cargo builds.** Forces operational choice about where Plamen stores target repos (always `/home/...`, never `/mnt/c/...`).
6. **MCP timeout budget under chained tool calls.** A single "find callers of X" may need 3-5 LSP round trips. Close to 300s ceiling fast on cold workspaces.
7. **Can the LLM reliably stitch Semgrep OSS intraprocedural hits into cross-function chains**, or does lack of taint propagation produce too many dead ends? This is the deepest unknown and may force a Semgrep Pro budget decision.
8. **Does `rust-analyzer scip` handle reth's procedural macros** (alloy-rlp derives, cfg-gated code, build.rs outputs) correctly, or produce an incomplete index?

Questions 1, 2, and 7 are the highest-priority unknowns — they drive week 1 choices.

## 13. Runtime requirements (v0.3 cross-platform)

L1 mode is **cross-platform first class on Windows, macOS, and Linux**. No WSL2 requirement. The v0.2 WSL2 mandate was dropped in v0.3 after Round 3 validated the batch-indexing architecture.

### Why no WSL2

The Round 2 concern was that gopls on native Windows is 15-25× slower than on WSL2 due to `go list` metadata operations (Go issue [#75208](https://github.com/golang/go/issues/75208), still open as of Aug 2025). The v0.2 plan treated this as a blocker because it assumed interactive gopls calls in the audit hot path. Round 3 removed that assumption: Plamen uses **batch SCIP indexing** for all semantic navigation, and primitive queries hit a static file, not a live language server. Go issue #75208 no longer matters for Plamen's hot path.

### Runtime split

- **Plamen orchestrator** (Python/Node): runs on whatever OS Claude Code runs on. Unchanged.
- **Tool-execution layer** (scip-go, rust-analyzer, ast-grep, Opengrep, BM25 MCPs, optional CodeQL): all cross-platform binaries or interpreted. Installed natively on the host OS.
- **Target repos**: stored anywhere the user prefers. On Windows, native `C:\Users\...\targets\` is fine; no `/mnt/c` concern because we don't stream data through a VFS.

### Installation baseline (Day 1, any OS)

- Go 1.25+ (`go` CLI for scip-go + builds)
- Rust stable toolchain
- rust-analyzer (latest stable) — provides the `scip` subcommand
- scip-go (exact version governed by `verification_policy/toolchain_version_lock.v1.json`)
- ast-grep (via cargo or prebuilt binary)
- Opengrep (prebuilt binary from https://github.com/opengrep/opengrep/releases)
- Python 3.11+
- Optional: CodeQL CLI (only for public-OSS benchmark runs)
- Optional: ripgrep (for lexical fallback)

### Known platform nuances (non-blocking)

- **Windows**: `go list` metadata operations are slow (#75208) but Plamen's batch indexing bypasses this. Initial scip-go bake on a geth-class repo may run slower on Windows than Linux — order of minutes, not hours. Acceptable.
- **macOS**: Apple Silicon: verify scip-go / ast-grep / Opengrep have native arm64 binaries. All confirmed as of 2026-Q1.
- **Linux**: baseline; fastest but not required.

### Explicitly deferred for Phase 1 (platform-limited)

- **Kani** — install docs focus on Linux/macOS; Windows support unverified. WSL2 is an option for this specific tool if Phase 2 pursues it.
- **Verus** — requires Rust project refactoring to verify; not practical for existing reth/lighthouse. Phase 2 at earliest.
- **Joern / CPG** — Go/Rust second-class. Phase 2 candidate.
- **Hive** — requires Docker; cross-platform via Docker Desktop (Win/Mac) or native Docker (Linux). Phase 2 integration for Phase 5 verification.
- **Fluffy (snuspl)** — academic artifact, no 2024-2026 maintenance. Read the OSDI '21 paper for methodology, don't try to run it.
- **Semgrep Pro** — user-preference: no paid tools. Opengrep fills the gap for intra-file cross-function taint.
- **CodeQL on private targets** — license-blocked. Only loads for public OSS targets (benchmark runs, upstream audits).

## 14. Change log

- **v0.5 — 2026-05-26**: **Implementation delivered.** Items from Sections 4-7 that landed on the `experimental/pty-supervision` branch are now production. (1) **Skill pack expanded from 15 to 22 skills** under `agents/skills/injectable/l1/` — additions per `MEMORY.md` v2.1.0+: `gossip-cache-invariance`, `peer-scoring-correctness`, `consensus-tx-identity-invariants`, `config-correctness`, `write-error-divergence` on top of the original 15. (2) **Two new depth agent roles shipped**: `depth-consensus-invariant` and `depth-network-surface` (definitions at `agents/depth-consensus-invariant.md` and `agents/depth-network-surface.md`). (3) **Phase 0.5 Bake implemented** in `scripts/recon_prepass.py` — runs `scip-go` / `rust-analyzer scip` / Opengrep once before recon. (4) **OpenGrep pre-breadth wired** into the driver for Core/Thorough modes. (5) **Phase 4c (chain analysis) removal** reflected in the actual pipeline. (6) **L1 evidence tags** (`[DIFF-PASS]`, `[CONFORMANCE-PASS]`, `[NON-DET-PASS]`, `[FUZZ-PASS]`, `[LSP-TRACE]`) honored by Phase 5 verification. Orthogonal change (cross-platform unchanged): the orchestrator now uses a PTY supervision transport (`scripts/pty_exec.py` — POSIX `pty.openpty()` + `Popen` with `setsid`/`TIOCSCTTY`/SIGCHLD-reset; Windows `winpty` via `pywinpty>=2.0.14`) that lets `/plamen` launch from inside a Claude Code session without parent SIGCHLD disposition poisoning children. Preflight cache schema bumped to v3 to invalidate stale env-inheriting caches. Section 13 runtime-requirements addendum: orchestrator-side dependency on `pywinpty>=2.0.14` on Windows (auto-installed via `requirements.txt`); macOS/Linux unchanged.
- **v0.4 — 2026-04-11**: **Scope reframe**. The v0.1-v0.3 non-goal that treated T2/T3 (whole-client) as out of reach was based on a pre-primitive-layer architecture assumption that Rounds 1-3 had already invalidated. Commercial and academic tools (CodeQL on the Linux kernel, Semgrep Pro on monorepos, IRIS on whole-repo Java, Snyk CodeReduce, Sourcegraph Cody) demonstrate that the batch-index + pre-filter + sliced-context recipe Plamen already committed works at T2/T3 scale. Section 2 (Non-goals) rewritten to remove the T2/T3 exclusion and replace it with honest output-profile constraints (per-subsystem depth, novel-exploit discovery, cross-subsystem economic reasoning). Section 3 (Scope tiers) rewritten: T0/T1 are Phase 1 smoke tests, T2 is Phase 2 via multi-scoped-run composition, T3 is Phase 3 with "first-pass screen" positioning. Architecture unchanged.
- **v0.3 — 2026-04-10**: Integrated Round 3 research. Four architectural changes: (1) **dropped WSL2 mandate** — cross-platform first-class on Windows, macOS, Linux; batch-indexing architecture bypasses the Go issue #75208 concern that drove the v0.2 WSL2 rule. (2) **Opengrep replaces Semgrep OSS/Pro** as the intra-file cross-function taint engine — LGPL-2.1, cross-platform, restored the functionality Semgrep moved to paid Pro. (3) **CodeQL added as Tier-2 opt-in primitive** — license-gated to public OSS targets only; user-preference for OSS means CodeQL is not the default. (4) **Unified batch-indexing** for both Go (scip-go) and Rust (rust-analyzer scip) via a single `plamen/scip_reader.py` shim. Rewrote Section 5 (primitives layer), Section 10 Week 1 (7-day plan), Section 11 (curated 5-target benchmark corpus + 7 stretch targets with real CVEs), Section 13 (cross-platform runtime requirements). Added Round 3 Phase 0.5 "Bake" phase definition with estimated index times per target repo.
- **v0.2 — 2026-04-10**: Integrated Round 2 validation research. Three architectural corrections (later partially superseded by v0.3): (1) WSL2 mandate (DROPPED in v0.3); (2) rust-analyzer batch SCIP (KEPT, extended to Go via scip-go in v0.3); (3) Semgrep OSS scope caveat (REPLACED with Opengrep in v0.3).
- **v0.1 — 2026-04-10**: Initial draft. Based on planning conversation + research Spike Round 1. Validation research Round 2 pending.
