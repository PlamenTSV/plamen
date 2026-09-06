# Audit Modes

> Plamen v2.2.4. All modes run through the PTY-supervised V2 driver
> (`plamen_driver.py`) on Windows, macOS, and Linux, with either the Claude Code
> or OpenAI Codex CLI backend.

## Comparison

| Dimension | Light | Core | Thorough |
|-----------|-------|------|----------|
| **Target plan** | **Pro** | Max | Max |
| Orchestrator model | Session model (Sonnet default) | Opus | Opus |
| Agent models | All Sonnet/Haiku | Opus + Sonnet | Opus + Sonnet (Opus tier resolves to Opus-4.8) |
| Recon | 2 sonnet (no RAG, no fork) | 4 agents (RAG fire-and-forget) | 4 agents (full RAG) |
| Breadth | 3-4 sonnet | 5-9 opus | 5-9 opus |
| Re-scan (3b/3c) | Skip | Skip | Full (sonnet, 2 iters + per-contract) |
| Depth loop | 4 merged sonnet, iter 1 | 8+ agents, iter 1 | Iter 1-3 (Devil's Advocate) |
| Niche agents | Skip | Flag-triggered (up to 9) | Flag-triggered (up to 9) |
| Semantic invariants | Skip | Pass 1 only | Pass 1 + Pass 2 (recursive trace) |
| Confidence scoring | None (verdicts only) | 2-axis (Evidence + Quality) | 4-axis (Evidence, Consensus, Quality, RAG) |
| RAG Sweep | Skip | 1 sonnet | 1 sonnet |
| Invariant / Medusa fuzz | Skip | Skip | Yes (EVM, zero budget cost) |
| Design stress testing | Skip | Skip | 1 reserved slot, UNCONDITIONAL |
| Chain analysis | 1 sonnet (merged) | 2 agents | 2 agents + iteration 2 |
| Verification (PoC) | Chains + ALL Medium+ (sonnet) | Chains + ALL Medium+ | ALL severities (with fuzz) |
| Skeptic-Judge | Skip | Skip | HIGH/CRIT |
| Cross-batch consistency | Skip | 1 sonnet | 1 sonnet |
| Report | 2 agents (sonnet + haiku) | 5 agents (opus + sonnet + haiku) | 5 agents |
| Agent count | **~18-22** | **~30-50** | **~40-100** |

> The "agent" counts above are role counts. Agents in the **breadth**, **rescan**, and **depth** rows execute as a driver-owned PTY worker pool (one Claude PTY per agent artifact) rather than as `Task()` subagents under a Claude coordinator. The driver supervises each worker through a pseudo-terminal and infers turn completion from artifacts written to disk (`PLAMEN_STATUS` markers) rather than from a stdout/JSON envelope, eliminating the 0-byte-stdio / silent-hang class. See [pipeline-phases-presentation.md](pipeline-phases-presentation.md) for execution-shape details.

> **Cross-platform & ecosystem auto-detect**: All modes run on Windows, macOS, and Linux. The driver auto-detects (and auto-corrects, without a halt-to-rerun) the language ecosystem at startup, shows it on the startup banner, and resolves it via manifest-priority rules. POSIX runs use `Popen`-owned PTY execution with nested-session env isolation.

> **Haltless resilience**: A finished audit is never discarded at the finish line. The report_index, verify, inventory, and resume paths repair-then-degrade and surface any unfinished obligations as flagged Appendix-B items in `AUDIT_REPORT.md` instead of halting. Stale or corrupt checkpoints recover instead of stranding the run.

> **Deterministic plumbing**: Fragile LLM-prose-parsing phases have been replaced with deterministic Python — mechanical SC `report_index` recovery, mechanical verify backfill / queue manifests, and the data-loss-free `report_dedup` builder — so structure-assembly steps no longer depend on LLM output shape.

> **Mechanical recall gates** (all modes): graph-grounded, always-on gates catch recurring miss classes before report assembly. G1/G2 independently expand and reconcile co-referencing functions. Gate V checks a confirmed finding's boundary-value set and structurally-paired sibling operations; it does not rerun co-reference expansion. An external-dependency research gate has recon bake a citation ledger for every detected external dependency so depth/verify phases can ground worst-case assumptions instead of guessing (an uncited assumption caps at code-trace-level evidence). A promotion-completeness gate reconciles every intermediate finding artifact against the final inventory by location so a candidate can never silently vanish between phases. All candidates route through the existing verify-the-positives filter and material-harm floor — recall-safe (never drop) and precision-safe (never assert severity directly).

> **Force-by-default PoC gate** (Phase 5, all modes): a mechanical, label-independent check forces any finding with a concrete stated material harm into an executed PoC attempt unless it matches one of a small closed set of code-grounded blockers (fully-trusted-actor design, deploy/transaction-ordering dependency, an external dependency with no available fork, a required live external artifact, or no on-chain state delta to assert). A forced attempt that still cannot construct a harm assertion is recorded as traced-but-unexecuted with the named blocker — never as a failed or refuted PoC.

## When to Use Each

- **Light**: Pro plan, codebases under 3000 lines, quick first pass. Reports all severities but skips semantic invariants, fuzzing, and design stress testing.
- **Core**: Standard audit. Reports all severities, PoC-verifies Medium+, flag-triggered niche agents. Best balance of coverage and cost.
- **Thorough**: Maximum coverage. Iterative depth with Devil's Advocate, fuzz campaigns (invariant + Medusa), design stress testing, skeptic-judge for HIGH/CRIT, a Thorough-only Exploration-Completeness skeptic (Phase 4b.6), 4-axis confidence scoring, and a durable post-report `report_dedup` pass. Use for high-value or pre-deployment audits.

## Proven-Only Mode

Available in all modes via `--proven-only`. Caps findings with only `[CODE-TRACE]` evidence (no executed PoC or fuzzer counterexample) at Low severity. Useful for benchmark comparisons where only mechanically proven findings should drive severity.

---

## L1 Mode

L1 infrastructure audits use the same Light/Core/Thorough tiers with these differences:

| Dimension | L1 Difference |
|-----------|---------------|
| Languages | Go, Rust (instead of Solidity, Move, etc.) |
| Depth agents | + depth-consensus-invariant, depth-network-surface; no depth-token-flow |
| Phase 0.5 | Bake phase: deterministic SCIP batch indexing — `_bake_go_scip` (Go) and rust-analyzer SCIP (Rust) |
| Phase 4c | Removed (no chain analysis for L1 point vulnerabilities); a cross-domain-dependency-tag harvester feeds low-confidence candidates into the verification queue as the minimal generic replacement |
| Severity matrix | L1-specific, aligned with Immunefi v2.3 |
| Skills | 22+ L1 injectable skills (consensus, p2p, mempool, RPC, validator, etc.) |
| Evidence tags | + [DIFF-PASS], [CONFORMANCE-PASS], [NON-DET-PASS], [FUZZ-PASS], [LSP-TRACE] |
| Pre-breadth hook | Mechanical dependency-vulnerability scan (language-appropriate tooling), degrades gracefully if not installed |
| Race/concurrency findings | Mechanical verification re-runs with a race-detector instrumentation and an extended timeout instead of the default PoC-exempt structural bucket |

```bash
plamen l1 core /path/to/node-client    # terminal wrapper (both backends)
```

Inside Claude Code, use `/plamen-l1-wizard` for interactive L1 audit configuration.

See [l1-mode/design.md](l1-mode/design.md) for the full L1 architecture.

---

## Codex Backend (BETA)

All audit modes work with both Claude Code and OpenAI Codex CLI (`codex exec`) backends. The Codex backend is a cost-saving **beta**: it adds a research-backed model/tier/compact configuration, per-job depth fan-out (one `codex exec` per depth job, which fixes the never-cut-stub halt), and natural-language usage-cap detection that auto-waits instead of halting. Codex depth runs the full Devil's-Advocate iteration 2 and seeds the complete mandatory first-pass artifact set so recon/depth degrade losslessly, and a context-exceeded turn no longer perma-fails.

The V2 driver (`plamen_driver.py`) auto-detects the active backend via `plamen_home()` and handles tool translation and path rewriting (`~/.claude/` vs `~/.codex/plamen/`). Install the Codex backend with `plamen install --codex`. See the main [README](../README.md) for full Codex setup.
