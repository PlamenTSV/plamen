# Glossary

Quick reference for the Plamen-specific terms that show up in the README,
slash commands, and orchestrator rules. Read once; everything else is
explained inline where it's used.

## Pipeline structure

- **Pipeline** — the full audit. Two flavors: `sc` (smart contract) and `l1`
  (node-client infrastructure). Picked at wizard step 0.
- **Phase** — one stage of the pipeline. SC has 40+, L1 has more. Examples:
  `recon`, `breadth`, `inventory`, `depth_iter1`, `verify_critical`,
  `report_assemble`. Sequence is hard-coded in
  [`docs/architecture.md`](architecture.md).
- **V1 / V2** — V1 was the legacy single-conversation LLM orchestrator. V2 is
  the current pipeline: a Python driver (`scripts/plamen_driver.py`) that runs
  each phase. For the three parallel discovery phases (breadth, depth, rescan)
  V2 spawns one Claude PTY worker per output artifact and trusts only disk
  markers (`PLAMEN_STATUS: COMPLETE`) for completion. Other phases run as a
  single phase LLM with disk-gated artifacts. V2 is resumable on crash.
- **Execution shape** — every phase runs in one of three shapes: **LLM phase
  session** (single `claude -p` / `codex exec` subprocess), **Python
  mechanical** (no LLM), or **Direct PTY worker pool** (driver supervises one
  Claude PTY per worker artifact). See `docs/pipeline-phases-presentation.md`
  for the per-phase mapping.
- **Worker pool** — the parallel execution shape used for breadth, depth, and
  rescan. The Python driver schedules N concurrent Claude PTY workers via a
  `ThreadPoolExecutor`, one per `analysis_*.md` / `depth_*_findings.md`
  artifact, retries only missing or `IN_PROGRESS` rows, and treats Claude's
  "done" text as advisory.
- **PLAMEN_STATUS marker** — HTML comment markers written into worker output
  files (e.g. `<!-- PLAMEN_STATUS: IN_PROGRESS -->`, then `... COMPLETE -->`).
  The driver's disk gate uses these to distinguish complete artifacts from
  crash-safety reservation headers. Full marker envelope is documented in
  `docs/architecture.md`.
- **Disk gate** — completion check that reads `PLAMEN_STATUS` markers from
  disk, not LLM "DONE" prose. Source of truth for worker-pool phases.
- **Compaction (informational)** — Claude auto-compacts a long session
  mid-turn. For worker phases, the driver emits a single heartbeat line and
  continues — disk markers still decide completion. Not a warning, not a
  failure.

## Agent vocabulary

- **Breadth agent** — surveys the whole codebase quickly, flags candidate
  issues. Multiple run in parallel, each covering a subset.
- **Depth agent** — verifies a single candidate by tracing code paths.
  Types: `depth-token-flow`, `depth-state-trace`, `depth-edge-case`,
  `depth-external`, plus `depth-consensus-invariant` and
  `depth-network-surface` for L1.
- **Scanner** — focused single-purpose static check (e.g. `scanner-A`,
  `scanner-B`, `scanner-C` for blind-spots).
- **Niche agent** — flag-triggered specialist (e.g.
  `callback-receiver-safety`, `signature-verification-audit`). Loads only
  when its trigger pattern is detected.
- **Skill** — reusable methodology shipped as a markdown file
  (`SKILL.md`) under `agents/skills/`. Injected into an agent prompt
  when the relevant flag fires. Three tiers exist: standard (per-language),
  injectable, and niche — see [internals.md](internals.md).
- **Injectable skill** — a protocol-type-specific skill that is **appended to
  an existing agent's prompt** (it does not spawn a new agent) when recon
  classifies the protocol as a matching type (e.g. `VAULT_ACCOUNTING` for
  vaults, `LENDING_PROTOCOL_SECURITY` for lending). Increases the depth of an
  existing agent rather than adding a budget slot. Contrast with niche agents,
  which are standalone. Full list in [internals.md](internals.md).
- **Skeptic-Judge** (a.k.a. **Skeptic-judge**) — Thorough-mode quality gate and
  built-in false-positive filter. For each HIGH/CRITICAL verified finding a
  Skeptic agent independently argues the OPPOSITE case (without seeing the
  verifier's analysis); if it disagrees, a Judge agent reads both sides and
  decides. Unresolved disagreements are tagged `UNRESOLVED` — demoted one tier
  but kept in the report body for human review, not dropped.

## Evidence

- **PoC** — proof of concept. Executable test that demonstrates the bug.
  Evidence tag `[POC-PASS]` means the test ran and the assertion held.
- **CODE-TRACE** — manual trace through code, no executable test. Lower
  confidence than POC-PASS.
- **`[POC-FAIL]`** — PoC compiled and executed, but the harm assertion
  failed. Defaults to "the attack does not work as described" unless the
  failure is shown to be a test-setup error rather than a real defense.
- **`[MEDUSA-PASS]`** — the Medusa stateful fuzzer found a counterexample
  violating an invariant. Mechanical proof — same evidentiary weight as
  `[POC-PASS]`.
- **`[PROD-ONCHAIN]`** — claim verified directly against live production
  on-chain state (e.g. a mainnet RPC read), not a local mock.
- **`[PROD-SOURCE]`** — claim verified against production/verified source
  code on a block/chain explorer, not a mock or assumption.
- **`[PROD-FORK]`** — claim verified by executing a test against a forked
  copy of real production state (e.g. an Anvil/Foundry fork). Proof-grade;
  valid to support a REFUTED verdict too.
- **`[LSP-TRACE]`** — L1-only manual trace performed with SCIP/LSP
  static-index type info and call hierarchy when mechanical proof (diff /
  conformance / fuzz) isn't feasible. Supports CONFIRMED only at Medium
  severity or below — Critical/High still need a mechanical-evidence tag.
- **`[EXTERNAL-ASSUMPTION: condition]`** — severity assumes the worst
  realistic external condition (Rule R10) for a mechanism already confirmed
  in-scope whose safety hinges on an unresearched external factor. A
  verification obligation, not a license to discount severity to
  Informational — must be paired with `[EXT-CITED]` below or a
  `NEEDS_DEPENDENCY_RESEARCH` escalation line.
- **`[EXT-CITED: dependency, source=url, fetched=date]`** — grounds a paired
  `[EXTERNAL-ASSUMPTION]` tag in a matching row of the recon-baked
  `external_dependency_research.md` ledger (see **Fix B** in the gates
  section below). Missing this citation (or the escalation line) caps the
  pairing at `[CODE-TRACE]`-equivalent evidence quality.
- **`[UNPROVEN-EXTERNAL]`** — stamped when the fork-PoC mandate for an
  external-integration finding is inert because no fork RPC is reachable.
  The in-scope mechanism is proven; the external leg is unverified. Never
  upgrades evidence grade, and the finding stays at its proven-mechanism
  severity either way.
- **`[BOUNDARY:X=val]`** — a depth agent substituted a concrete boundary
  value (0, 1, MAX, etc.) into the vulnerable expression and observed the
  result.
- **`[VARIATION:param A→B]`** — a depth agent tested how behavior changes
  when a parameter is varied between two concrete values.
- **`[TRACE:path→outcome]`** — a depth agent traced execution to a genuine
  terminal state (revert, return value, or state change), not just an
  intermediate step.
- **`[REGRESS:symptom→cause]`** — a depth agent traced a symptom that varies
  under different inputs backward to its single architectural root cause.
- **`[PERTURBATION:operator]`** — Thorough-mode only: the Finding
  Perturbation agent found an adjacent vulnerability by applying a
  structured mutation (e.g. a direction-flip) to an existing confirmed
  finding.
- **`[CROSS-DOMAIN-DEP: domain]`** — a depth agent flagged an assumption
  outside its own analysis domain that could enable exploitation if broken.
  Chain analysis reads these to seed cross-domain enabler candidates.
- **CONTESTED** — verdict where verifier and skeptic disagree; held back
  from final report or human-review-only.
- **Provisional analysis ID** — finding IDs assigned by breadth/depth/chain
  agents (e.g. `[CS-1]`, `[TF-3]`, `CH-2`). Internal pipeline IDs only — the
  `report_index` phase later assigns the final client-facing IDs.
- **Report ID** — final client-facing finding ID assigned by `report_index`:
  `C-01` (Critical), `H-01` (High), `M-01`, `L-01`, `I-01`. These are the only
  IDs that appear in `AUDIT_REPORT.md`.
- **Canonical finding identity map** — refreshed after major discovery phases.
  Detects re-minted / collision IDs across phases. Owned by the driver
  (`_write_canonical_finding_identity_map`).
- **`.scratchpad/`** — per-audit workspace inside the target project. Holds
  all intermediate artifacts (findings, traces, manifests). Created by
  recon, deleted on `--fresh` restart, otherwise preserved for resume.
  Contains a per-scratchpad `.plamen_run.lock` that prevents concurrent
  driver invocations against the same audit.
- **`.plamen_archive_<ts>/`** — on a `--fresh` restart the driver MOVES prior-run
  answer-key artifacts out of the project root (prior `AUDIT_REPORT*.md`,
  `*_RCA.md`, hardening notes, and generated fuzz-harness dirs like
  `.medusa-tests/`) into this dot-prefixed sibling folder. Moved, never deleted —
  nothing is lost — and dot-prefixed so recon/build/Slither walks never
  re-ingest a prior report or harness and prime a supposedly-fresh run.

## Mechanical recall gates, mechanisms & axes

> Deterministic Python mechanisms (no LLM call) that either **generate** extra
> low-confidence candidates the LLM passes tend to miss (recall side) or
> **adjudicate** an existing claim against ground truth (precision side).
> None of them assert a body-severity finding directly — every generated
> candidate is a `NEEDS_VERIFICATION` block that still passes through the
> normal chain/verify/report pipeline and the material-harm body floor. Full
> per-function contracts (consumes/produces/source line) live in
> [internals.md § Mechanical Derivers](internals.md); this table is the
> canonical place to resolve a bare code like `G1` or `Gate P` to a name and
> a one-line purpose — link here instead of re-explaining the mnemonic at
> each call site.

| Canonical name | Aliases | What it does | Defined at |
|---|---|---|---|
| Enumeration-obligation deriver | `G1`, co-reference enumeration gate | For each inventory finding, derives every OTHER function that co-references the same state symbol(s) — the set the finding's own analysis "ought to address" but may not have. | `compute_enumeration_obligations`, [internals.md § Mechanical Derivers](internals.md) (`scripts/enumeration_gate.py:191`) |
| Enumeration-coverage validation gate | `G2`, co-reference coverage gate, `ENUMGAP` | Diffs G1's obligation set against a finding's own prose; any un-addressed co-referencer is appended as a low-confidence `ENUMGAP` candidate. | `validate_enumeration_coverage`, [internals.md](internals.md) (`scripts/enumeration_gate.py:282`) |
| Variant-Family Coverage gate | `Gate V`, `Fix A`, sibling/variant-coverage gate, `VARGAP` | Checks two "did the analysis try the sibling variant" axes: boundary-input values (`{0,1,min,MAX,empty,self}`) and symmetric-operation pairing. G1/G2 own co-reference expansion separately. Gate V runs unconditionally, not confidence-gated, because the failure mode is a *confidently-wrong* single-variant analysis. | `compute_variant_gaps` / `validate_variant_coverage`, [internals.md](internals.md) (`scripts/enumeration_gate.py:1177`) |
| Assumption-commitment falsifier | `M1`, Mechanism 1, committed-invariant deriver, `INVARIANT` | Harvests the `committed-invariant [CI-n]` blocks that depth/skeptic/verify phases must emit whenever they rule a value-bearing path SAFE or REFUTE a finding, and turns each tacit local guard into a falsifiable low-confidence candidate. | `compute_invariant_assertion_candidates`, [internals.md](internals.md) (`scripts/enumeration_gate.py:1266`) |
| Multi-axis coverage meta-pass | `M2`, Mechanism 2, axis-coverage meta-pass, `AXISGAP` | Ranks the mechanically-hottest production functions, then builds a function × risk-axis completeness matrix over the **6 risk axes** (below); an ambiguous or unexamined cell defaults to GAP and spawns a targeted deriver-worker. | `compute_hot_function_set` / `compute_axis_coverage_gaps`, [internals.md](internals.md) (`scripts/enumeration_gate.py:1550` / `:1772`) |
| External-Dependency Research ledger + citation gate | `Fix B`, `Hook 1`, `EXTERNAL-ASSUMPTION`, `EXT-CITED`, `EXTERNAL-ASSUMPTION-CAP` | Recon (the only phase with live web tools) bakes a per-dependency research ledger to disk; any `[EXTERNAL-ASSUMPTION: ...]` finding tag must cite a matching ledger row (`[EXT-CITED: ...]`) or a `NEEDS_DEPENDENCY_RESEARCH` escalation, else it is capped at `[CODE-TRACE]`-equivalent evidence quality. A paired report-severity brake floors an unproven external-harm High/Critical to Medium. | `scripts/recon_prepass.py:1838` (ledger); citation rule at `rules/finding-output-format.md` (R10); `EXTERNAL-ASSUMPTION-CAP` token at `rules/report-template.md` |
| Promotion-completeness gate | `Gate P`, `PROMOGAP`, Class C pipeline-loss | Content-shaped (not ID-pattern) harvest of every intermediate finding artifact, reconciled by location against the final consolidated inventory; anything not already tracked is reopened in the inventory as a `NEEDS_VERIFICATION` candidate. The current active disposition is always `BODY`; historic Appendix A/C routing is tombstoned. | `compute_promotion_orphans` / `route_promotion_orphans`, [internals.md](internals.md) (`scripts/plamen_mechanical.py:4834` / `:5052`) |
| Verdict-evidence integrity gate | `_classify_integrity`, integrity gate | Compares a verifier's prose evidence-tag claim against actual mechanical test-execution status and records the effective result in the typed verdict manifest. The legacy markdown-rewrite helper `flip_verdict_on_integrity_downgrade` has no production caller and is tombstoned, not live authority. | `_classify_integrity` / `_write_verdict_manifest`, [internals.md](internals.md) (`scripts/mechanical_verify.py:1546` / `:1648`) |
| Force-by-default PoC gate | closed skip-blocker taxonomy | Any finding with a stated concrete material harm is forced into an executable PoC attempt unless a named blocker from a small CLOSED taxonomy applies (fully-trusted-actor design, deploy/tx-ordering, external-dep-no-fork, live-artifact-required, no state-delta-to-assert, or REFUTED). Closes the loophole where a verifier's self-declared PoC-class label zeroed its own PoC obligation. | `_poc_contract_required` et al., `scripts/plamen_validators.py`; policy at `rules/phase5-poc-execution.md` (§ Force-by-Default Skip Justification) |
| Blind-first independent-severity min-cap | `M4`, `INDEPENDENT-MIN` | Every verifier assesses an Independent Severity from the code/evidence ALONE, before seeing the pre-assigned/claimed severity (anti-rubber-stamp). Final severity = `min(independent, claimed)`; cap-only, never raises. | `_apply_independent_severity_caps`, `scripts/plamen_validators.py:20895`; token at `rules/report-template.md` |
| Identifier-existence hallucination gate | `M5a`, `Gate 3`, `IDENTIFIER_UNVERIFIED` | Catches a finding that cites a concrete function/method identifier absent from the ENTIRE project source index (not just the resolved file). Low/Info findings citing a phantom identifier are appendix-routed; Medium+ findings are flagged for human review, never dropped. | `_identifier_exists_in_project` et al., `scripts/plamen_validators.py:16128-16234` |
| Location-existence anti-hallucination gate | `Gate 1` (location) | Catches a finding that cites a source file that doesn't exist, or a line number past EOF — independent of whether its Source ID is also bad. | `_resolve_inventory_location`, `scripts/plamen_parsers.py:8339`; invoked at `scripts/plamen_validators.py:16193` |
| Non-production scope filter | `Gate 2` (scope) | A finding that resolves to a real file in a test/fuzz/mock/harness tree (or whose location prose names one) is routed out of the report body — it describes unaudited harness code, not the production protocol. | `_is_nonproduction_location` et al., `scripts/plamen_validators.py:16196-16206` |
| Evidence-Only Carryover | `AD-1`, Rule AD-1 | Between depth-loop iterations, only evidence artifacts (ID, location, evidence tags, confidence score, investigation question, analysis-path summary) carry forward — prior verdicts and confidence assessments are explicitly excluded, so iteration 2 can't be contaminated by iteration 1's conclusion. | `rules/phase4-confidence-scoring.md` § Anti-Dilution Rules |
| Hard Devil's Advocate Role | `AD-2`, Rule AD-2, DA role | Iteration 2+ depth agents are structurally assigned a Devil's Advocate role (not just told to "think critically") whose job is to explore what iteration 1 did NOT explore — hard role framing produces far higher divergence than a soft instruction. | `rules/phase4-confidence-scoring.md` § Anti-Dilution Rules |
| Focused Input Cap | `AD-3`, Rule AD-3 | Each iteration 2+ depth agent receives at most 5 uncertain findings in its domain, prioritized by lowest confidence score. | `rules/phase4-confidence-scoring.md` § Anti-Dilution Rules |
| Fresh Tool Calls Mandatory | `AD-4`, Rule AD-4 | Iteration 2+ agents must make their own fresh MCP/static-analyzer/RAG calls rather than reusing iteration-1 summaries, to prevent stale-data regression. | `rules/phase4-confidence-scoring.md` § Anti-Dilution Rules |
| New-Evidence-Only Re-Scoring | `AD-5`, Rule AD-5 | A confidence score may only increase after an iteration if the agent produced genuinely NEW evidence (new code reference, tool output, or verification result) — restating prior analysis in different words moves nothing. | `rules/phase4-confidence-scoring.md` § Anti-Dilution Rules |
| Error Trace Injection | `AD-6`, Rule AD-6 | Error traces from failed Phase-5 PoCs become investigation questions for post-verification targeted depth agents. Bypasses AD-2's role-framing requirement because they're mechanical test-execution output, not agent reasoning. | `rules/phase4-confidence-scoring.md` § Anti-Dilution Rules |
| Post-audit root-cause classification taxonomy | `RC-SCOPE`, `RC-METHOD`, `RC-DEPTH`, `RC-CONTEXT`, `RC-NOVEL`, `RC-AGENT`, `RC-ANCHOR` | **Not a mechanical gate** — a manual 7-code rubric applied by a human/orchestrator only in the ephemeral, offline post-audit gap-analysis session, to classify why a ground-truth finding was missed. A mandatory "RC-AGENT Exclusion Test" must pass before any other code may be assigned. | `rules/post-audit-improvement-protocol.md` (Part 2 §§ Step 2 / Step 2.5) |

**Caution — `Gate 1` is an overloaded label, not one mechanism.** The bare
string "Gate 1" is independently reused for at least five unrelated things in
the codebase: the location-existence gate above, niche-manifest 3-way
reconciliation, a depth-agent "Spawn Verification" checklist item in the
per-language inventory prompts, a driver resume-safety check, and an MCP
tool's historical-evidence lookup. When you see "Gate 1" in the wild, check
which subsystem is talking before assuming it's the location gate.

### The 6 risk axes (Multi-axis coverage meta-pass)

| Axis | One-line meaning |
|---|---|
| `theft` | Can value be extracted or redirected to an unauthorized party? |
| `liveness` | Can a core action be permanently or indefinitely blocked/bricked? |
| `accounting` | Can internal bookkeeping (balances, shares, totals) drift from reality? |
| `provenance` | Can the origin/authenticity of an input, asset, or message be forged or misattributed? |
| `boundary` | Does behavior break at a limit value (0, 1, min, MAX, empty, overflow)? |
| `identity` | Can the wrong caller/subject/recipient be substituted (authorization-subject, consent, recipient identity)? |

Added last (v2.2.4); earlier versions of the same mechanism checked only the
first 5 axes — see [internals.md § Mechanical Derivers](internals.md) for the
current authoritative axis tuple.

> Dev-internal Source-ID candidate tags (`ENUMGAP`, `ASSETMOVE`, `ARRUNIQ`,
> `UNBOUND`, `VARGAP`, `INVARIANT:CI-n`, `AXISGAP:...`, `PROMOGAP`, `NEXP-n`,
> ...) are cataloged in [internals.md § Mechanical Derivers](internals.md) —
> not repeated here to keep this one legend as the single source of truth.

## Models & accounts

- **MCP** — Model Context Protocol. Anthropic's protocol for plugging tools
  (Slither, Solodit, ChromaDB, etc.) into Claude Code. Codex CLI supports a
  subset; see [`docs/mcp-servers.md`](mcp-servers.md).
- **RAG** — retrieval-augmented generation. Plamen's vulnerability
  knowledge base built from Solodit + DefiHackLabs + Immunefi writeups.
  Built via `plamen rag` (~6GB RAM, 3–5 min). Optional but improves recall.
- **Pro / Max** — Anthropic Claude subscription tiers in the audit-mode
  table. Pro = ~5x weekly cap; Max = ~20x. Light mode is Pro-friendly;
  Core/Thorough generally need Max.
- **Sonnet / Opus / Haiku** — Anthropic Claude model tiers. Cheaper /
  faster / less capable in that order. Plamen picks per agent role per
  audit mode automatically.

## Operations

- **Bake (Phase 0.5)** — L1-only. Runs `scip-go` / `rust-analyzer scip` /
  Opengrep once before recon to build a code-index baseline. SC mode does
  not have this phase.
- **Recon** — first phase of every audit. Builds the design context,
  attack surface, semantic invariants. Output drives every later phase.
- **Inventory** — phase that lists every entry point, state variable, and
  external interaction for downstream agents to consume.
- **Validation Sweep** — one of the depth iteration-1 workers. Produces
  `scanner_validation_findings.md` / `validation_sweep_findings.md`. Not a
  separate late-pipeline phase.
- **`plamen_home()`** — Python abstraction in `scripts/plamen_types.py` for the
  runtime package root. Installed entry points resolve it to the signed
  COMMITTED package at `~/.plamen/` (or to an exact explicit `PLAMEN_HOME`
  authority); source-tree execution resolves script-relative paths for
  pre-install validation. `~/.claude/` is a receipt-bound projection and
  `~/.codex/` contains transactionally copied/merged integration files. Neither
  backend trusts a symlink to a mutable source checkout.
- **PTY transport** — how the driver runs Claude PTY workers. On POSIX:
  `pty.openpty()` + `subprocess.Popen` with a `preexec_fn` that calls
  `os.setsid()`, claims the controlling TTY via `TIOCSCTTY`, and resets
  inherited SIGCHLD. On Windows: `winpty.PtyProcess.spawn` via `pywinpty`.
  Lets `/plamen` launch from inside a Claude Code session without parent
  process state poisoning the children.
- **Discovery aids** — feature-derived analysis prompt consumed by depth
  workers: `security_obligations.md` (obligation ledger from recon).
  Protocol-agnostic — generalizes across DEX, vault, lending, bridge, L1
  client, etc.

## Resilience & recovery

- **PTY-supervised execution** — the v2.1.0 way the driver runs workers: each
  worker (Claude, or one `codex exec` per depth job) is driven through a
  **pseudo-terminal (PTY)** and its turn completion is inferred from artifacts
  written to disk (the `PLAMEN_STATUS: COMPLETE` marker), not from a
  stdout/JSON envelope. This eliminates the 0-byte-stdio "silent hang"
  ambiguity from earlier versions. POSIX uses `pty.openpty()` + `Popen`;
  Windows uses `winpty` via `pywinpty`. See the **PTY transport** entry above
  and [architecture.md](architecture.md) for the implementation contract.
- **Haltless** — a design property of the v2.1.0 driver: a finished audit is
  never thrown away at the finish line. Late-stage phases (`report_index`,
  verify, inventory, resume) **repair-then-degrade** rather than stopping the
  run, and stale/corrupt checkpoints recover instead of stranding the audit.
- **Repair-then-degrade** — the haltless recovery policy: when a late phase
  cannot fully complete, the driver first **repairs** what it can
  deterministically (mechanical report-index recovery, verify backfill, queue
  manifests), and if work still remains it **degrades** — finishing the run and
  surfacing the unfinished obligation as a flagged item rather than halting.
- **Appendix-B flagged items** — the "human-review" obligations that
  repair-then-degrade could not fully resolve. They are folded into a delivered
  **Appendix B** of `AUDIT_REPORT.md` (`_build_human_review_appendix` in
  `scripts/plamen_mechanical.py`) so the flag actually reaches the reader,
  instead of being buried in an intermediate file the client never sees.
- **Degraded phase** — a phase that failed (or was skipped) and was marked
  `degraded` in the checkpoint so the pipeline could continue; downstream
  phases handle its missing optional artifacts gracefully. A degraded sentinel
  is cleared on a genuine resume.
