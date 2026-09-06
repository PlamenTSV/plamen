# Internals

> V3 platform boundary: Windows is currently production-qualified. POSIX code
> described here is useful implementation substrate, but Linux/macOS native
> install and E2E support remain gated by `continuation/GOAL.md`.

## Skill System

Skills are methodology files loaded into agents at instantiation time. Three tiers:

### Standard Skills (per-language)

Always-available, triggered by pattern flags from recon. Examples: `ORACLE_ANALYSIS`, `SEMI_TRUSTED_ROLES`, `TOKEN_FLOW_TRACING`, `FLASH_LOAN_INTERACTION`.

| Language | Skills |
|----------|--------|
| EVM | 18 |
| Solana | 20 |
| Aptos | 22 (21 + core directives) |
| Sui | 22 (21 + core directives) |
| Soroban | 19 (13 cross-language + 6 Soroban-specific) |
| DAML | 12 (7 DAML-specific + 5 cross-language) |

### Injectable Skills (protocol-type-specific)

Loaded only when recon classifies the protocol as a matching type. Appended to existing agents (9 total):

| Skill | Trigger |
|-------|---------|
| VAULT_ACCOUNTING | `vault` protocol type |
| ACCOUNT_ABSTRACTION_SECURITY | ERC-4337, EntryPoint, UserOperation |
| NFT_PROTOCOL_SECURITY | ERC721/1155 with marketplace/staking/collateral |
| GOVERNANCE_ATTACK_VECTORS | Governor, Timelock, voting, proposal |
| OUTCOME_DETERMINISM | Finite-pool selection with depletion fallback |
| LENDING_PROTOCOL_SECURITY | liquidate/borrow/repay/collateral/LTV/healthFactor |
| DEX_INTEGRATION_SECURITY | swap/addLiquidity/removeLiquidity (non-DEX protocols) |
| INTEGRATION_HAZARD_RESEARCH | NAMED_EXTERNAL_PROTOCOL flag (named external protocol imports) |
| CROSS_VM_SERIALIZATION_CONFORMANCE | NON_EVM_TARGET flag (EVM serializes for a non-EVM VM) |

### Niche Agents (flag-triggered standalone)

Spawn as independent agents (1 depth budget slot each, 9 total):

| Agent | Trigger |
|-------|---------|
| EVENT_COMPLETENESS | `MISSING_EVENT` flag |
| SEMANTIC_GAP_INVESTIGATOR | Semantic invariant flags |
| SPEC_COMPLIANCE_AUDIT | `HAS_DOCS` flag |
| SIGNATURE_VERIFICATION_AUDIT | `HAS_SIGNATURES` flag |
| SEMANTIC_CONSISTENCY_AUDIT | `HAS_MULTI_CONTRACT` flag |
| MULTI_STEP_OPERATION_SAFETY | `MULTI_STEP_OPS` flag (approve/delegate + on-behalf-of) |
| CALLBACK_RECEIVER_SAFETY | `OUTCOME_CALLBACK` flag (EVM only) |
| DIMENSIONAL_ANALYSIS | `MIXED_DECIMALS` flag (EVM only) |
| STABLESWAP_COMPLIANCE | `STABLESWAP_FORK` flag (Curve/StableSwap fork) |

### L1 Skills (infrastructure audits)

Loaded only in L1 mode (`/plamen-l1-wizard` in Claude Code, or `plamen l1` from terminal). Injected into `depth-consensus-invariant` or `depth-network-surface`:

| Skill | Trigger |
|-------|---------|
| CONSENSUS_SAFETY_INVARIANTS | `CONSENSUS` flag |
| CONSENSUS_MATH_CORRECTNESS | `CONSENSUS` + difficulty/EMA/reward patterns |
| FORK_CHOICE_AUDIT | `CONSENSUS` + fork_choice/ghost patterns |
| P2P_DOS_AND_ECLIPSE | `P2P` flag |
| MEMPOOL_ASYMMETRIC_DOS | `MEMPOOL` flag |
| LIGHT_CLIENT_PROOF_VERIFICATION | `LIGHT_CLIENT` flag |
| RPC_SURFACE_AUDIT | `RPC` flag |
| BLS_AGGREGATION_AUDIT | `BLS` flag |
| STATE_SYNC_PRUNING | `STATE_SYNC` flag |
| EXECUTION_CLIENT_HARDENING | `EXECUTION` flag |
| CROSS_ENVIRONMENT_SEMANTIC_DRIFT | `XENV` flag |
| VALIDATOR_LIFECYCLE_AND_SLASHING | `VALIDATOR_LIFECYCLE` flag |
| HARDFORK_ACTIVATION_AND_PROTOCOL_UPGRADE | `HARDFORK` flag |
| GO_CONCURRENCY_SAFETY | Always (Go code) |
| RUST_UNSAFE_AUDIT | Always (Rust code) |
| DEPENDENCY_AUDIT_NODECLIENT | Always (L1) |
| DATA_AVAILABILITY_ENFORCEMENT | `data_availability` flag |
| PEER_SCORING_CORRECTNESS | `P2P` + scoring patterns |
| GOSSIP_CACHE_INVARIANCE | `P2P` + cache patterns |
| CONSENSUS_TX_IDENTITY_INVARIANTS | `CONSENSUS` + txid/nonce patterns |
| CONFIG_CORRECTNESS | `L1_PATTERN` + config patterns |
| WRITE_ERROR_DIVERGENCE | `STORAGE`/`DATABASE_TX` flag |

Plus 2 new depth agents for L1 mode: **depth-consensus-invariant** and **depth-network-surface**.

---

## Security Rules (R1-R16)

| Rule | Name | Summary |
|------|------|---------|
| R1 | External Return Types | Verify all external call return values |
| R2 | Keeper/Admin Griefability | Check both directions of privileged action abuse |
| R3 | Transfer Side Effects | Document token type and side effects |
| R4 | Adversarial Assumption | CONTESTED/unknown -> assume adversarial |
| R5 | Combinatorial Impact | N-entity systems need combinatorial analysis |
| R6 | Bidirectional Role | Semi-trusted roles analyzed in both directions |
| R7 | Donation-based DoS | Check thresholds vulnerable to donations |
| R8 | Cached Parameters | Multi-step ops with stale external state |
| R9 | Stranded Assets | Check recovery paths for locked funds |
| R10 | Worst-State Severity | Use worst realistic state, not current snapshot |
| R11 | Unsolicited Token Transfer | Trace impact of uninitiated transfers |
| R12 | Exhaustive Enabler Enum | 5 actor categories per dangerous state |
| R13 | Anti-Normalization | "By design" is not a valid severity dismissal |
| R14 | Cross-Variable Invariant | Aggregate variables, constraint coherence |
| R15 | Flash Loan Precondition | Flash-loan-accessible state manipulation |
| R16 | Oracle Integrity | Staleness, decimals, zero, failure modes |

---

## Severity Matrix

Impact x Likelihood:

| | **High Likelihood** | **Medium Likelihood** | **Low Likelihood** |
|---|---|---|---|
| **High Impact** (direct fund loss) | **Critical** | **High** | **Medium** |
| **Medium Impact** (conditional fund loss) | **High** | **Medium** | **Medium** |
| **Low Impact** (non-fund) | **Medium** | **Low** | **Low** |
| **Info** (quality, style) | **Informational** | **Informational** | **Informational** |

Downgrade modifiers: on-chain-only exploit (-1), view-function-only (cap Medium), fully-trusted actor (-1, floor Info).

---

## Evidence Tags

| Tag | Weight | Meaning |
|-----|--------|---------|
| `[PROD-ONCHAIN]` | 1.0 | Verified against production on-chain state |
| `[PROD-SOURCE]` | 0.9 | Verified against production source code |
| `[PROD-FORK]` | 0.9 | Verified on Anvil fork |
| `[MEDUSA-PASS]` | 1.0 | Medusa fuzzer found counterexample |
| `[POC-PASS]` | 1.0 | PoC compiled, executed, assertions passed |
| `[POC-FAIL]` | -- | PoC executed but assertions failed |
| `[CODE]` | 0.8 | Code-level evidence with specific locations |
| `[CODE-TRACE]` | 0.6 | Manual trace, no execution (caps at CONTESTED) |
| `[DOC]` | 0.4 | Documentation-based evidence |
| `[MOCK]` | 0.2 | Mock-based (not production-representative) |

### L1 Evidence Tags

| Tag | Meaning |
|-----|---------|
| `[DIFF-PASS]` | Cross-client differential test passed |
| `[CONFORMANCE-PASS]` | Spec conformance test passed |
| `[NON-DET-PASS]` | Non-determinism detection test passed |
| `[FUZZ-PASS]` | Fuzzer found counterexample |
| `[LSP-TRACE]` | LSP-assisted code trace |

---

## Driver

One-liner: **Python driver → worker pool → one isolated backend invocation
(Claude PTY or headless `codex exec`) per artifact → disk artifact gate → retry
only missing/bad rows. The worker saying "done" is not trusted; disk markers
are.**

The pipeline driver (`plamen_driver.py`) executes model-owned phases as isolated
backend subprocesses and mechanical phases as deterministic Python. All public
invocations (`/plamen-wizard`, terminal `plamen`, `plamen core`, and their L1
forms) converge on this driver. The portable driver substrate is tested on
Windows, macOS, and Linux against Claude Code or Codex; the governed installed
runtime is currently release-qualified only on Windows.

### Driver layout

| Component | Purpose |
|-----------|---------|
| `plamen_driver.py` | Phase scheduling, checkpointing, retry, gate checking, worker-pool orchestration |
| `plamen_types.py` | Canonical definitions (evidence tags, severities, finding ID regex); installed `plamen_home()` resolves the signed `~/.plamen/` package, while backend integration state is separately projected/copied under `~/.claude/` and `~/.codex/` |
| `plamen_parsers.py` | LLM output parsing (report index, verification results) |
| `plamen_validators.py` | Artifact quality gates (mechanical, not LLM-dependent); per-row marker statuses (`_BREADTH_STATUS_*`, `scripts/plamen_validators.py:931-935`) |
| `plamen_prompt.py` | Phase prompt building with forward-ref sanitization |
| `plamen_mechanical.py` | Deterministic report assembly, dedup, tier dispatch |
| `plamen_display.py` | Rich terminal UI for driver progress |
| `plamen_markdown.py` | Markdown AST helpers shared between parsers and validators |
| `plamen_contracts.py` | Worker artifact / marker envelope contracts (manifest schema, expected-output shape) |
| `mechanical_verify.py` | Phase 5 mechanical verification helpers (severity caps, PoC demotions, integrity gates) |
| `chain_prep.py` | Chain-analysis pre-pass: extracts candidate finding pairs with shared state / type before the chain LLM phase |
| `report_index_machinery.py` | Report-index ID assignment and `report_coverage.md` ledger reconciliation |
| `pty_exec.py` | Claude PTY session: POSIX `pty.openpty()` + governed process ownership, Windows `winpty.PtyProcess.spawn`; Codex uses its separate headless `codex exec` transport |
| `preflight_pty_transports.py` | Per-host PTY transport probe; cache schema v3 (`scripts/preflight_pty_transports.py:62`) |
| `codex_adapter.py` | Codex CLI backend: tool translation, path rewriting (`~/.claude/` ↔ `~/.codex/plamen/`) |
| `recon_prepass.py` | Pre-recon static analysis (Slither, Opengrep, SCIP) |

Installed public entry points authenticate the COMMITTED receipt and execute the
runtime under `~/.plamen/`; the mutable source checkout is not a runtime
dependency. The installer creates a signed, receipt-bound Claude projection
under `~/.claude/` using governed link/copy representations and transactionally
copies/merges Codex roles, skills, commands, `AGENTS.md`, and `config.toml` under
`~/.codex/`. Managed backend launchers are bound to exact Claude Code 2.1.252 and
Codex 0.152.0 selections running on managed Node.js 24.20.0/npm 11.19.0.

### Execution model

Three execution shapes coexist behind the same `plamen_home()` and disk-gate primitives:

1. **Direct worker pool** — used for `breadth`, `rescan`, `per_contract`, and `depth`. The driver builds a manifest of expected output artifacts, launches a bounded worker pool, and invokes one Claude PTY or headless Codex process per row. Each worker's success is a disk artifact passing the row gate — the worker's prose `DONE` is **advisory only**.
2. **LLM phase session** — used for sequential analytical phases (recon, inventory, chain, report index, skeptic, judge, tier writers, etc.). The driver uses the selected backend's isolated transport and runs `gate_passes` against the scratchpad after the turn ends.
3. **Python mechanical** — used for `inventory_prepare`, `report_assemble`, `chain_prep`, `verify_aggregate`, semantic-dedup fallback, severity binding, and similar plumbing phases. No LLM is spawned; deterministic Python in `plamen_mechanical.py` / `mechanical_verify.py` / `chain_prep.py` / `report_index_machinery.py` reads and writes scratchpad artifacts in-process.

All three shapes share the same checkpoint (`_v2_checkpoint.json`), the same `gate_passes` validator, the same `plamen_home()`-derived paths, and the same artifact ownership rules. Phase ordering and retry policy live in `plamen_driver.py`; shape-specific behavior is dispatched by phase name.

### Model routing

Claude tiers resolve to fixed model IDs: **Opus 5** (`claude-opus-5`), **Sonnet 5** (`claude-sonnet-5`), and the dated Haiku 4.5 snapshot. **Core** uses the phase's pinned tier; **Thorough** promotes reasoning-critical roles (discovery, verification shards, skeptic-judge) to Opus 5; **Light** stays on Sonnet 5 to bound plan usage. `PLAMEN_OPUS_MODEL`, `PLAMEN_THOROUGH_OPUS_MODEL`, `PLAMEN_SONNET_MODEL`, and `PLAMEN_HAIKU_MODEL` are explicit overrides for benchmarking, gateways, or cost controls.

### Backends (Claude Code + Codex BETA)

The driver runs against two interchangeable CLI backends behind the same `plamen_home()` and disk-gate primitives:

- **Claude Code** (default) — config files `CLAUDE.md` + `settings.json` + `mcp.json`.
- **Codex CLI** (`codex exec`, **BETA / cost-saving**) — OpenAI's CLI as an alternative worker backend, with research-backed model/tier/compact configuration and per-job depth fan-out (one `codex exec` per depth job, which fixes the never-cut-stub halt). Codex model aliases map through `_CODEX_MODEL_MAP` (`scripts/plamen_types.py:128`), config files are `AGENTS.md` + `config.toml`, and `codex_adapter.py` regenerates them from the Claude-side manifests to prevent drift. Codex usage-cap messages are detected in natural language so the driver auto-waits instead of halting, Codex depth runs real Devil's-Advocate iter-2, and `context-exceeded` no longer perma-fails. The active backend is detected at startup (`backend == "codex"`, `scripts/plamen_driver.py:211`) and selected paths/tools are translated only when Codex is active.

### Cross-platform substrate (Windows + macOS + Linux)

The PTY worker-pool implementation has platform branches for all three hosts.
POSIX uses `pty.openpty()` + `Popen` ownership with a `SIGCHLD` reset on spawn;
Windows uses `winpty` (see the PTY transport section below). This source-level
portability is not a native POSIX production-support claim: the hardened POSIX
install dispatcher, crash keeper, and recovery transaction remain continuation
work. Nested-session environment isolation and backend path propagation are
tested independently of that release boundary.

### Ecosystem auto-detection

The configured language/ecosystem is mechanically auto-detected and auto-corrected at startup with no halt-to-rerun (`_detect_ecosystem`, `scripts/plamen_driver.py:16280`), shown on the startup banner, and resolved via manifest-priority rules (a suffix-only signal never clobbers an explicit config; native-SDK / Pinocchio Solana is detected at high confidence). The auto-corrector is recall-safe by design — a wrong auto-correct is treated as worse than the status quo (`_language_correction`, `scripts/plamen_driver.py:16238`), and L1 pipelines always keep their configured Rust/Go language.

### Haltless resilience

A finished audit is never discarded at the finish line. The `report_index`, `verify`, `inventory`, and resume paths **repair-then-degrade** instead of halting: unfinished obligations are surfaced as flagged Appendix-B items in `AUDIT_REPORT.md` rather than blocking the run. Retry/recovery is unified across backend × mode × pipeline (hinted 3rd retry for under-covering phases, rescan added to recovering phases, verify queue-completeness backfill that stops the resume-rewind loop), and stale/corrupt checkpoints recover rather than stranding the run. Degraded phases carry a sentinel that is cleared on a genuine resume (`checkpoint.degraded` / `clear_degraded_sentinel`, `scripts/plamen_driver.py:2187-2191`).

### Compaction as informational

When a Claude PTY session's transcript shows an auto-compaction event, the driver emits a one-shot `INFO` log line for the affected phase (`compaction_warned` guard, `scripts/plamen_driver.py:5658-5757`). Compaction never gates a phase and never alters control flow — the disk-gate verdict is the only authority. A coordinator that emits `DONE` after compaction but leaves the disk gate red is treated identically to any other premature-DONE: the missing-only / live / resume continuation handles recovery.

---

## Mechanical Derivers

> Deterministic Python functions — no LLM call — that generate, gate, promote, or reconcile findings directly against scratchpad artifacts and the mechanical reference graph. None of them assert a body-severity finding directly: every emitted candidate is a low-confidence `NEEDS_VERIFICATION` block that still passes through the normal chain/verify/report pipeline and the material-harm body floor. Source files: `scripts/enumeration_gate.py`, `scripts/plamen_mechanical.py`, `scripts/mechanical_verify.py`, `scripts/recon_prepass.py`, `scripts/plamen_contracts.py`, `scripts/plamen_markdown.py`.

### Source-ID candidate tags

The recall-generator functions below stamp a literal token into a candidate's `**Source IDs**:` line in `findings_inventory.md` (or, for two tags, into an internal receipt key only — never the markdown line itself). This table is the single place that tag is defined; see [glossary.md § Mechanical recall gates](glossary.md#mechanical-recall-gates-mechanisms--axes) for the plain-language description of the G1/G2/Gate V/Gate P/Mechanism-1/Mechanism-2 mechanisms these tags belong to.

| Tag | Meaning | Emitted by (function) | Code-parsed? |
|-----|---------|------------------------|---------------|
| `ENUMGAP` | G1/G2 co-reference coverage-gap candidate; also the default stamp actually written for the critical-asset-mover, array-uniqueness, and unbounded-input derivers below (they share the same emitter and never override the tag) | `validate_enumeration_coverage` (`enumeration_gate.py:282`) via the shared emitter `_emit_candidates` (`enumeration_gate.py:572`) | **Yes** |
| `ASSETMOVE` | Receipt/dedup key prefix only for the critical-asset-mover deriver — never written to a finding's `Source IDs` line (that line reads `ENUMGAP`, above) | `compute_critical_asset_mover_candidates` (`enumeration_gate.py:664`) | No |
| `ARRUNIQ` | Receipt/dedup key prefix only for the array-uniqueness deriver — same `ENUMGAP` caveat as `ASSETMOVE` | `compute_array_uniqueness_candidates` (`enumeration_gate.py:768`) | No |
| `UNBOUND` | Receipt/dedup key prefix only for the unbounded-input deriver — same `ENUMGAP` caveat | `compute_unbounded_input_candidates` (`enumeration_gate.py:835`) | No |
| `VARGAP-B` | Receipt-key prefix only for Gate V axis 2 (boundary-input coverage) — the text actually stamped into `Source IDs` is the plain `VARGAP` row below | `compute_boundary_input_candidates` (`enumeration_gate.py:994`) | No |
| `VARGAP-S` | Receipt-key prefix only for Gate V axis 3 (symmetric-operation coverage) — same `VARGAP` caveat | `compute_symmetric_operation_candidates` (`enumeration_gate.py:1100`) | No |
| `VARGAP` | The literal tag both Gate V axis derivers above actually stamp into a finding's `Source IDs` line | `compute_variant_gaps` (`enumeration_gate.py:1177`) | No — referenced only in a driver log line, not regex-matched |
| `PROMOGAP` | Gate P promotion-completeness candidate: harvested finding-shaped content reopened in the inventory as a fresh `NEEDS_VERIFICATION` block; current active dispositions are all `BODY` | `route_promotion_orphans` (`plamen_mechanical.py:5052`) | **Yes** |
| `INVARIANT:CI-n` | Mechanism 1 committed-invariant assertion candidate — always suffixed with the specific `CI-n` id, never bare `INVARIANT` | `compute_invariant_assertion_candidates` (`enumeration_gate.py:1266`) | **Yes** |
| `AXISGAP:<worker-finding-id>` | Mechanism 2 axis-coverage-gap candidate — always suffixed with the axis worker's own finding id | `compute_axis_coverage_gaps` / `promote_axis_findings_to_inventory` (`enumeration_gate.py:1772` / `:1907`) | **Yes** |
| `NEXP-n` | Raw finding-ID prefix from the Phase 4b.7 depth-exploration worker, promoted verbatim as the `Source IDs` value; matched by the same chain-enabler regex as `ENUMGAP` | `promote_enumgap_exploration_to_inventory` (`enumeration_gate.py:2068`) | **Yes** |

Every tag marked **Yes** above is matched by a downstream parser or gate (chain-enabler detection, the mechanism-attribution ledger, or the receipt/promotion machinery itself), so these literal strings are an internal contract — do not rename any of them without a coordinated code-and-test change (this file is documentation only).

### Recall-generators

Read the mechanical reference graph (bake output, below) plus the finding inventory and emit low-confidence candidates for gaps a purely LLM-driven pass tends to miss: unexamined co-referencing functions, unaddressed boundary values, unpaired symmetric operations, un-asserted local invariants, and (via the axis-coverage meta-pass) risk-axes never examined against the codebase's mechanically-ranked hot functions.

| Function | Location | Consumes | Produces | Purpose |
|----------|----------|----------|----------|---------|
| `compute_enumeration_obligations` | `scripts/enumeration_gate.py:191` | `_mechanical_graph.json`, `findings_inventory.md` | `enumeration_obligations.md`, `_enumeration_obligations.json` | G1: for each inventory finding, derives the co-referencing functions of the state symbols its enclosing function touches, from the unified reference graph |
| `compute_coverage_gaps` | `scripts/enumeration_gate.py:257` | `_enumeration_obligations.json`, `findings_inventory.md` | in-memory gap list (feeds `validate_enumeration_coverage`) | Pure diff half of G2: required co-referencers not mentioned anywhere in a finding's own block prose |
| `validate_enumeration_coverage` | `scripts/enumeration_gate.py:282` | `compute_coverage_gaps()` output, `findings_inventory.md`, `enumeration_gap_receipt.md` | `findings_inventory.md` (appended `ENUMGAP` blocks), `enumeration_gap_receipt.md` | G2: appends each unaddressed co-reference gap as a low-confidence `NEEDS_VERIFICATION` candidate, idempotent via a receipt |
| `_emit_candidates` | `scripts/enumeration_gate.py:572` | candidate list, `findings_inventory.md`, `enumeration_gap_receipt.md` | `findings_inventory.md` (appended blocks), `enumeration_gap_receipt.md` | Shared bounded, idempotent, append-only emitter substrate that every downstream obligation-deriver uses to turn candidate dicts into `NEEDS_VERIFICATION` inventory blocks |
| `compute_critical_asset_mover_candidates` | `scripts/enumeration_gate.py:664` | `_mechanical_graph.json`, production source tree | candidates via `_emit_candidates` (`ASSETMOVE`) | Detects a same-file generic asset-mover function that can move a protocol-critical singleton state handle without excluding it, stranding dependent functions |
| `compute_array_uniqueness_candidates` | `scripts/enumeration_gate.py:768` | production source tree (per-language regex specs) | candidates via `_emit_candidates` (`ARRUNIQ`) | Detects a function that loops a caller-supplied array with a per-element value effect and no uniqueness guard, so duplicate elements multiply the effect |
| `compute_unbounded_input_candidates` | `scripts/enumeration_gate.py:835` | production source tree | candidates via `_emit_candidates` (`UNBOUND`) | Detects a caller-controlled string/bytes value stored on-chain with no length bound (storage-bloat / gas-bomb DoS) |
| `compute_boundary_input_candidates` | `scripts/enumeration_gate.py:994` | `_mechanical_graph.json`, `findings_inventory.md`, production source tree | candidates via `_emit_candidates` (`VARGAP-B`) | Gate V axis 2: for each CONFIRMED/PARTIAL finding, checks whether its own prose addressed the required boundary set `{0,1,min,MAX,empty,self}` for the enclosing function's parameters |
| `compute_symmetric_operation_candidates` | `scripts/enumeration_gate.py:1100` | `chain_candidate_pairs.md`, `findings_inventory.md` | candidates via `_emit_candidates` (`VARGAP-S`) | Gate V axis 3: reads structurally-paired operation legs (shared state/type signal) and flags when one leg is CONFIRMED/PARTIAL but its sibling leg's own finding is not |
| `compute_variant_gaps` / `validate_variant_coverage` | `scripts/enumeration_gate.py:1177` | boundary-input and symmetric-operation candidate outputs | aggregate emitted-count dict | Gate V (Fix A) driver: runs boundary-input and symmetric-operation coverage only, unconditional and not confidence-gated. G1/G2 own co-reference expansion separately. Its two 15-candidate pools are additional to `run_enumeration_gate`'s 100-candidate bound, making the accepted-depth maximum 130 before axis work. |
| `compute_invariant_assertion_candidates` | `scripts/enumeration_gate.py:1266` | `exploration_skeptic_findings.md`, `skeptic_findings.md`, `depth_*_findings.md`, `verify_*.md`, `_mechanical_graph.json` | candidates via `_emit_candidates` (`INVARIANT`) | Mechanism 1: harvests committed-invariant blocks that skeptic/depth/verify phases stamp behind a SAFE/REFUTED verdict, turning each tacit local guard into a falsifiable low-confidence candidate |
| `compute_hot_function_set` | `scripts/enumeration_gate.py:1550` | `_mechanical_graph.json`, `function_summary.md`, `attack_surface.md`, production source tree | ranked, capped in-memory hot-function list (feeds `compute_axis_coverage_gaps`) | Mechanism 2: deterministically ranks the mechanically-hot production functions (log-dampened fan-in + state-write + elevate + value-effect + entry-point signals) so the LLM cannot clobber the target set |
| `compute_axis_coverage_gaps` | `scripts/enumeration_gate.py:1772` | `compute_hot_function_set()` output, `findings_inventory.md`, `depth_*_findings.md`, `*_findings.md` | `hot_function_axes.md`, `_hot_function_axes.json`, gap list | Thorough-only Mechanism 2 prepass: builds a function x risk-axis (theft/liveness/accounting/provenance/boundary/identity) matrix over the hot set. Closed structured evidence tags are primary; bounded Description/Impact cues are secondary for tag-light findings; ambiguous defaults to GAP. A Sonnet worker is spawned only when GAP rows exist. |
| `run_enumeration_gate` | `scripts/enumeration_gate.py:2181` | all deriver inputs above except Gate V | aggregate obligations/gaps/emitted counts | Driver entry point: runs G1+G2's 40-candidate pool plus four additional 15-candidate pools, each independent so one deriver cannot starve another; its maximum is 100 before the separately invoked Gate V pools |

### Gates

Adjudicate mechanical claims against ground truth (the coverage seed, or actual test execution) rather than generating new candidates.

| Function | Location | Consumes | Produces | Purpose |
|----------|----------|----------|----------|---------|
| `compute_promotion_orphans` | `scripts/plamen_mechanical.py:4834` | `report_index_coverage_seed.md`, feeder globs (`depth_*.md`, `blind_spot_*.md`, `analysis_*.md`, checklists) | `promotion_orphans.md` | Gate P harvest: scans feeder artifacts for content-shaped finding blocks (real file:line location + mechanism cue + descriptive text) and reconciles each against the coverage seed; anything not already tracked is an orphan |
| `_promo_disposition` | `scripts/plamen_mechanical.py:4763` | one harvested candidate dict | `("BODY", reason)` tuple | Reopens every active harvested promotion-orphan case for independent verification. Classifier and producer-negative results remain non-authoritative proposals and cannot route a candidate out of the inventory. |
| `route_promotion_orphans` | `scripts/plamen_mechanical.py:5052` | `compute_promotion_orphans()` output, `promotion_gate_receipt.md` | `findings_inventory.md` (appended `PROMOGAP` blocks), `promotion_routing.md`, compatibility staging snapshots, `promotion_gate_receipt.md` | Gate P router: appends every currently active harvested orphan as a `NEEDS_VERIFICATION` candidate, idempotent via a content-hash receipt. Historic Appendix A/C routing is tombstoned; its staging snapshots are compatibility artifacts, not live negative-disposition authority. |
| `_classify_integrity` | `scripts/mechanical_verify.py:1546` | verifier prose evidence-tag claim, mechanical execution status, `verify_<ID>.md` text | `(integrity_state, effective_tag)` tuple | Integrity gate: compares a verifier's prose evidence-tag claim against the actual mechanical test-execution status; classifies CONSISTENT / INFLATED_PROSE / POC_UNVERIFIED_HARNESS / MECHANICAL_UNAVAILABLE and computes an effective tag |
| `flip_verdict_on_integrity_downgrade` | `scripts/mechanical_verify.py:1628` | legacy test callers only | legacy rewritten verifier markdown | Tombstoned compatibility helper (`verdict.integrity_markdown_flip`): it has no production caller and is not live verdict authority. Current integrity handling is carried by the typed verdict manifest. |
| `_write_verdict_manifest` | `scripts/mechanical_verify.py:1648` | `ExecResult` list, `verify_<ID>.md` files | `verdict_manifest.json` | Writes the canonical per-finding effective evidence tag (post integrity-gate) that skeptic-judge and report-index phases read instead of the verifier's raw prose claim |
| `run_phase5b_mechanical_verify` | `scripts/mechanical_verify.py:1844` | `verify_<ID>.md` files, project build tree, language registry | `mechanical_verify_manifest.md`, `verdict_manifest.json`, annotated `verify_<ID>.md` files | Top-level driver entry: locates the build root, prewarms the build, runs each finding's PoC test mechanically, classifies pass/fail/harness-status, and writes the verdict manifest |

### Promotion

Move a worker- or exploration-phase finding into the inventory so it reaches chain analysis and verification instead of dead-ending in an intermediate artifact.

| Function | Location | Consumes | Produces | Purpose |
|----------|----------|----------|----------|---------|
| `promote_axis_findings_to_inventory` | `scripts/enumeration_gate.py:1907` | `axis_coverage_findings.md`, `findings_inventory.md`, `axis_coverage_promotion_receipt.md` | `findings_inventory.md` (appended `AXISGAP` blocks), `axis_coverage_promotion_receipt.md` | Promotes the multi-axis coverage worker's findings into the inventory as fresh `NEEDS_VERIFICATION` blocks, idempotent via a dedicated receipt |
| `promote_enumgap_exploration_to_inventory` | `scripts/enumeration_gate.py:2068` | `enumgap_exploration_findings.md`, `findings_inventory.md`, `enumgap_exploration_promotion_receipt.md` | `findings_inventory.md` (appended `INV-*` blocks), `enumgap_exploration_promotion_receipt.md` | Promotes a depth-exploration agent's traced (boundary/variation/trace) obligation findings into the inventory so they reach chain/verify instead of arriving as a raw low-confidence candidate |

### Bake

Build the per-ecosystem mechanical reference graph that every recall-generator above reads. Tiered: a precise indexer (Slither / rust-analyzer SCIP / scip-go) when the toolchain is present and the project builds, else a compile-free approximate source parse — never mocked to force a compile.

| Function | Location | Consumes | Produces | Purpose |
|----------|----------|----------|----------|---------|
| `_bake_evm_graph` | `scripts/recon_prepass.py:2407` | Solidity project source tree | `_mechanical_graph.json`, `state_read_map.md`, `state_write_map.md`, `caller_map.md` | Tiered EVM reference-graph provider: precise Slither data-flow graph when the project builds, else compile-free approximate source parse |
| `_bake_evm_slither_graph` | `scripts/recon_prepass.py:2167` | `.sol` production sources, foundry/hardhat build config | `_mechanical_graph.json` (Source: slither), state read/write/caller maps | Runs Slither against the resolved build root and emits the mechanical reference graph from its type-resolved data-flow analysis |
| `_bake_evm_source_graph` | `scripts/recon_prepass.py:2322` | `.sol` production sources | `_mechanical_graph.json` via `_finalize_source_graph` | Compilation-free approximate Solidity reference graph (function -> referenced state symbols + callees), the always-available fallback beneath the Slither precision tier |
| `_bake_move_graph` | `scripts/recon_prepass.py:2441` | `.move` production sources | `_mechanical_graph.json` via `_finalize_source_graph` | Approximate Move (Aptos/Sui) reference graph: function -> referenced field/resource symbols + callees, via regex source parse (no mechanical indexer wired for Move) |
| `_bake_daml_graph` | `scripts/recon_prepass.py:2479` | `.daml` production sources | `_mechanical_graph.json` via `_finalize_source_graph` | Approximate DAML reference graph: choice -> referenced field identifiers + exercised choices (DAML has no SAST/SCIP tooling, so this is the only mechanical graph tier) |
| `_bake_rust_graph` | `scripts/recon_prepass.py:2634` | Cargo project source tree | `_mechanical_graph.json`, `caller_map.md`, `callee_map.md`, `state_write_map.md`, `function_summary.md` | Tiered Rust reference-graph provider: precise rust-analyzer SCIP index when the toolchain is present and builds, else compile-free approximate source parse |
| `_bake_rust_scip` | `scripts/recon_prepass.py:2014` | `Cargo.toml` project, prior `scip_rust.index` (freshness check) | `scip_rust.index`, graph artifacts via `_scip_to_graph_artifacts` | Runs `rust-analyzer scip` and converts the resulting SCIP index into the standard graph artifacts, reusing a fresh prior bake instead of re-indexing when unchanged |
| `_bake_rust_source_graph` | `scripts/recon_prepass.py:2570` | `.rs` production sources | `_mechanical_graph.json` via `_finalize_source_graph` | Compile-free approximate Rust reference graph (Tier-2 SCIP fallback): function -> struct-field/symbol references + callees |
| `_bake_go_graph` | `scripts/recon_prepass.py:2652` | Go module source tree | `_mechanical_graph.json`, `caller_map.md`, `callee_map.md`, `state_write_map.md`, `function_summary.md` | Tiered Go reference-graph provider: precise scip-go index when available, else compile-free approximate source parse |
| `_bake_go_scip` | `scripts/recon_prepass.py:2063` | `go.mod` project, prior `scip_go.index` (freshness check) | `scip_go.index`, graph artifacts via `_scip_to_graph_artifacts` | Runs `scip-go` and converts the resulting SCIP index into the standard graph artifacts, with freshness-based reuse of a prior bake |
| `_bake_go_source_graph` | `scripts/recon_prepass.py:2602` | `.go` production sources | `_mechanical_graph.json` via `_finalize_source_graph` | Compile-free approximate Go reference graph (Tier-2 SCIP fallback): function/method -> struct-field/symbol references + callees |
| `_scip_to_graph_artifacts` | `scripts/recon_prepass.py:2669` | a `.index` SCIP file (Rust or Go origin) | `_mechanical_graph.json`, `caller_map.md`, `callee_map.md`, `state_write_map.md`, `function_summary.md` | Language-agnostic converter from a protobuf SCIP index into the 4 standard graph artifacts depth agents and the enumeration gate consume |
| `_finalize_source_graph` | `scripts/recon_prepass.py:2513` | per-provider `fn_loc`/`sym_refs`/`fn_callees` dicts | `_mechanical_graph.json` via `_write_mechanical_graph_json` | Shared tail for every approximate (non-SCIP, non-Slither) source-parse provider: inverts callees into callers, drops over-referenced noisy symbols, writes the unified graph schema |
| `_write_mechanical_graph_json` | `scripts/recon_prepass.py:2134` | `var_refs` dict, `functions` dict, source-provider label | `_mechanical_graph.json` | The single unified schema writer every graph provider (Slither/SCIP/source-parse, any ecosystem) calls — the ecosystem-agnostic, LLM-unclobberable source the enumeration gate reads |
| `_write_external_dependency_research_stub` | `scripts/recon_prepass.py:1838` | none (pure scaffold write) | `external_dependency_research.md` (stub) | Seeds a header-only ledger before recon runs, so depth-phase workers (no live web tools) can rely on the file existing even before recon enriches it with one researched row per flagged external dependency |
| `_detect_external_dependency_markers` | `scripts/recon_prepass.py:3875` | `.sol` production sources | list of `(interface_name, file:line)` markers | Structurally detects an imported/declared interface with no in-repo implementation whose return value is consumed, excluding recognized standard/utility interfaces — a mechanical proxy for an unresearched external dependency |
| `_seed_external_dependency_flag` | `scripts/recon_prepass.py:3913` | `_detect_external_dependency_markers()` output | `template_recommendations.md`, `detected_patterns.md`, `recon_summary.md` updates (via `_seed_mechanical_flag`) | When a generic external dependency is mechanically detected, flips the integration-hazard-research skill row to Required=YES and emits the dependency flag as a second channel independent of the LLM recon pass |
| `_seed_mechanical_flag` | `scripts/recon_prepass.py:3615` | rows-to-flip mapping, flag tokens, detection rationale text | `template_recommendations.md`, `detected_patterns.md`, `recon_summary.md` (pre-pass-owned files only) | Shared 3-step mechanical flag-dispatch substrate (flip a skill row to Required=YES, emit flag tokens, append a subsystem-flags summary line) reused by every mechanical marker-based flag seeder |
| `run_recon_prepass` | `scripts/recon_prepass.py:4070` | project source tree, scratchpad config | the full pre-pass artifact set (graphs, maps, stubs, seeded flags) | Top-level driver entry orchestrating every mechanical bake, seed-flag detector, and stub writer before the recon LLM phase runs |

### Dedup-recovery

Consolidate duplicate findings and preserve provenance across the pipeline's discovery-phase fragmentation, without an LLM call (or as a fallback/supplement when the LLM dedup pass under-merges).

| Function | Location | Consumes | Produces | Purpose |
|----------|----------|----------|----------|---------|
| `build_dedup_cluster_map` | `scripts/plamen_mechanical.py:3408` | `findings_inventory.md` | `dedup_cluster_map.md` | Writes the transitive-closure consolidation-hint map over post-pairwise-dedup survivors (same file+function+fix-pattern, same tier) that report-index STEP-1.5 reads to emit one finding per cluster |
| `_detect_dedup_report_clusters` | `scripts/plamen_mechanical.py:3208` | inventory finding records | in-memory cluster list (feeds `build_dedup_cluster_map`) | Pure clustering primitive: groups inventory records into consolidation clusters and computes each cluster's survivor, unioned locations, and rendered location table |
| `_apply_mechanical_dedup_from_pairs` | `scripts/plamen_mechanical.py:8474` | `dedup_candidate_pairs.md` or `dedup_candidate_pairs_full.md`, `verification_queue.md` or `findings_inventory.md` | `*_deduped.md` (fallback) or in-place merged artifact + `dedup_decisions.md` (supplemental) | Mechanical dedup fallback/supplement when LLM dedup fails or leaves deferred pairs: merges only source-ID-subset/PERT-lineage or location-overlap+title-match pairs of the same severity, gated by an aggregate guard and a survivor-superset check so no distinct attack path is dropped |
| `_dedup_report_python` | `scripts/plamen_mechanical.py:6504` | `AUDIT_REPORT.md`, report-dedup proposals, typed candidate denominator, current semantic applied-alias receipts | rewritten `AUDIT_REPORT.md`, `report_dedup_mapping.md`, `report_dedup_applied_alias_receipt.json`, preimage/candidate sidecars | Cross-tier report dedup: LLM/heuristic rows remain proposals; only exact current source identity may receive a transaction-bound applied alias, with complete candidate disposition, live-survivor/cycle checks, exact absorbed-section coupling, and the whole-report data-loss gate |
| `write_mechanism_attribution_ledger` | `scripts/plamen_mechanical.py:8233` | `findings_inventory.md` | `mechanism_attribution.md` | Post-dedup provenance bookkeeping: maps each surviving inventory finding to its upstream Source ID tokens, including the generator-class tokens (`AXISGAP:`/`INVARIANT:`) stamped by the recall-generators, so meta-pass contribution is a mechanical grep instead of an LLM guess |

### Identity

Assign stable, content-derived finding identity ahead of the driver's final sequential report-ID assignment (see *ID identity* below).

| Function | Location | Consumes | Produces | Purpose |
|----------|----------|----------|----------|---------|
| `_write_canonical_finding_identity_map` | `scripts/plamen_mechanical.py:1051` | every producer finding artifact in the scratchpad (breadth/depth/scanner/inventory outputs) | canonical finding identity map JSON, unmapped ID tokens JSON | Writes deterministic content-fingerprint + canonical-ID (CID) sidecars for every parseable finding block across all producer artifacts, without mutating or merging anything |
| `_canonical_identity_records_from_artifact` | `scripts/plamen_mechanical.py:968` | one producer artifact file | list of identity record dicts (feeds `_write_canonical_finding_identity_map`) | Extracts one identity record per finding block in a single artifact: a content hash, canonical ID, title/severity/location/root-cause fields, and cross-referenced internal IDs |

### Severity / report assembly

Compute final severity, body-vs-appendix disposition, and the assembled report deterministically, so the same input always produces the same report ID and severity.

| Function | Location | Consumes | Produces | Purpose |
|----------|----------|----------|----------|---------|
| `_write_mechanical_report_index` | `scripts/plamen_mechanical.py:9292` | `verification_queue.md`, `verify_<ID>.md` files, typed lifecycle decisions, `finding_records.json` | `report_index.md` | Deterministically builds report_index.md without granting negative authority to verifier prose, failed PoCs, or consolidation hints. `poc_demotion_proposals` remains review context and cannot alter the tier. |
| `_cap_severity_at` | `scripts/plamen_mechanical.py:9282` | a severity string, a cap severity string | the capped severity string | Pure helper applying a maximum-severity ceiling to a finding's severity without ever upgrading a lower one |
| `_load_poc_demotion_caps` | `scripts/plamen_mechanical.py:7863` | legacy scratchpad state | empty cap dict | Explicit cutover interlock: legacy `poc_demotions.md` is inert. No live PoC-negative severity issuer exists; `_apply_poc_fail_demotions` now writes non-authoritative `poc_demotion_proposals` instead. |
| `_write_mechanical_report_tier` | `scripts/plamen_mechanical.py:10618` | `report_records.json`, tier assignments, `verification_queue.md` | `report_critical_high.md`, `report_medium.md`, or `report_low_info.md` | Writes a severity-tier report markdown file directly from verified finding records, with per-severity H2 headers so the assembler can route each finding to the correct section |
| `_assemble_report_python` | `scripts/plamen_mechanical.py:2160` | `report_index.md`, `report_critical_high.md`, `report_medium.md`, `report_low_info.md` | `AUDIT_REPORT.md`, `report_quality.md` | Mechanical AUDIT_REPORT.md assembly with no LLM call: merges the tier files, generates the Executive Summary and Priority Remediation Order from report_index.md's counts and Master Finding Index rows |
| `write_disposition_md` | `scripts/plamen_mechanical.py:3892` | `report_index.md` assignments, `verify_<ID>.md` files | `disposition.md` | Always-run BODY/APPENDIX classification per report ID, sourced from the same bounded ledgers report-index uses plus each finding's mapped verifier harm/verdict text, applying the material-harm classifier |
| `apply_material_harm_floor` / `enforce_material_harm_floor` | `scripts/plamen_mechanical.py:4296` | `disposition.md`, `AUDIT_REPORT.md` | rewritten `AUDIT_REPORT.md` | Enforces the material-harm body floor on the assembled report: relocates any body finding classified pure-quality/zero-security-consequence into the Quality & Hardening Observations appendix, never dropping it |

### Substrate

Shared, contract- and Markdown-parsing primitives that the categories above are built on.

| Function | Location | Consumes | Produces | Purpose |
|----------|----------|----------|----------|---------|
| `write_contract_sidecar` | `scripts/plamen_contracts.py:287` | a validated pydantic contract model, optional companion markdown path | `<sidecar_name>.json` | Writes a validated contract model to its JSON sidecar, idempotently (skips a byte-identical rewrite modulo timestamp) and embeds the companion Markdown's fingerprint for staleness detection |
| `read_contract_sidecar` | `scripts/plamen_contracts.py:319` | `<sidecar_name>.json`, optional companion markdown fingerprint | a validated contract model, or a raised `ContractError` | Reads and schema-validates a JSON sidecar; returns `None` only when the sidecar is absent, but hard-raises `ContractError` (never silently falls back) when present-but-invalid or stale relative to its companion Markdown |
| `load_contract` | `scripts/plamen_contracts.py:365` | scratchpad, a `PlamenContract` subclass, optional raw markdown | a validated contract model or `None` | Uniform contract resolution ladder: authoritative JSON sidecar if valid, hard-fail if present-but-invalid, else the legacy section-scoped Markdown importer, else `None` |
| `section_tokens` | `scripts/plamen_markdown.py:80` | raw markdown text, a heading pattern | a token-list slice | Section-scoped Markdown AST slice: returns only the tokens belonging to the first heading matching a pattern, up to the next equal-or-higher-level heading, so a same-named table in a different section can never bleed in |
| `section_text` | `scripts/plamen_markdown.py:125` | raw markdown text, a heading pattern | a source-text substring | Same section-scoping as `section_tokens` but returns the raw source substring, letting a caller keep its existing line-based row parser bounded to the correct section |
| `tables_in_tokens` / `first_section_table` | `scripts/plamen_markdown.py:207` | a parsed token list or raw markdown + heading pattern | list of row dicts keyed by normalized header | Parses every GFM table in a token slice into header-keyed row dicts, and a high-level helper that returns the first (or first column-matching) table's rows within one section |
| `source_fingerprint` | `scripts/plamen_markdown.py:253` | a file path | a fingerprint dict | Generic mtime_ns/sha256/size identity record for a source file, used by the contract layer to detect a JSON sidecar has gone stale relative to its companion Markdown |

---

## Worker contract

Worker artifacts (breadth, depth, rescan, per-contract) carry an HTML-comment envelope of `PLAMEN_*` markers. The canonical 7-line `PLAMEN_STATUS` marker block is defined in `docs/architecture.md`; internals.md summarizes how the driver consumes it.

### Marker-driven row verdicts

For each manifest row, `compute_phase_row_statuses` returns one of four verdicts (`scripts/plamen_validators.py:1488-1506`):

| Verdict | Meaning | Driver action |
|---------|---------|---------------|
| **complete** | File exists, `PLAMEN_STATUS: COMPLETE` is present, structural completeness passes | Row is locked in; not retried |
| **in_progress** | File has `PLAMEN_*` markers but `STATUS != COMPLETE`, or unmarked on a fresh-audit scratchpad | Re-queued on the next worker-pool attempt |
| **wrong-phase** (`structural_fail`) | File is `COMPLETE` but fails a required-heading / placeholder / receipts check | Re-queued with structural-failure reasons surfaced to the next worker |
| **stale-legacy** (`legacy_unmarked`) | Substantive content but no `PLAMEN_ARTIFACT` marker on a legacy/resumed scratchpad | Passes with warning; the supervision loop ignores it (treated as pre-existing) |

**`DONE` is advisory for worker phases.** The driver never trusts Claude's natural-language completion claim for breadth/depth/rescan/per-contract; only the marker envelope and the structural gate decide whether a row is locked in. This is the load-bearing rule that the entire artifact-complete PTY supervision design is built around.

### Agent-row routing markers

To reconcile the manifest with returned `agentId:` handles, every Task/Agent dispatch prompt the orchestrator builds embeds two routing markers verbatim:

```
AGENT_ROW: B3
EXPECTED_OUTPUT: analysis_access_control.md
```

`pty_exec.parse_transcript_agentids` (`scripts/pty_exec.py:384-460`) scans the session transcript and produces `{agent_row: {agent_id, expected_output, handle, description}}`, so the supervision loop can build a continuation message that names paused subagents by their manifest row (e.g. "B3 / analysis_access_control.md") instead of the opaque handle. Dispatches missing the `AGENT_ROW` marker are skipped (the parser never fabricates a row name from a handle).

---

## PTY transport

The PTY transport is what makes the worker-pool model viable: each worker is its own Claude session with its own bidirectional terminal, supervised by the driver. The architecture-level walkthrough lives in `docs/architecture.md`; the implementation contract is summarized here.

### POSIX

- Master/slave pair via `pty.openpty()`, child launched with `subprocess.Popen(..., stdin=slave_fd, stdout=slave_fd, stderr=slave_fd, preexec_fn=_child_setup)` (`scripts/pty_exec.py:574-606`).
- `_child_setup` resets `SIGCHLD` to `SIG_DFL`, calls `os.setsid()`, and assigns the controlling terminal via `fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)`. Each child becomes its own process group so `os.killpg` can clean up.
- Driver resets `SIGCHLD` before spawn (the parent may have inherited a non-default disposition from Claude Code, which otherwise causes children to appear reaped immediately).

### Windows

- `winpty.PtyProcess.spawn(argv, cwd=cwd, env=env, dimensions=(40, 120))` (`scripts/pty_exec.py:549-557`).
- `send_continuation` writes the message, waits 0.75s for the prompt box to settle, then sends a CR via `proc.sendcontrol("m")` with a `\r\n` fallback (`scripts/pty_exec.py:647-655`).

### Parent-Claude env stripping

At every spawn site, the child env is built via `_filtered_child_subprocess_environ`, which strips `CLAUDECODE`, `CLAUDE_CODE_SESSION_ID`, `CLAUDE_CODE_ENTRYPOINT`, `CLAUDE_CODE_EXECPATH`, and `AI_AGENT` (`scripts/plamen_driver.py:104-117`, mirrored in `scripts/preflight_pty_transports.py:77-83`). Without this filter, a child `claude` spawned from inside a Claude Code session detects a nested live session and exits `rc=0` without doing any work. The same filter is applied at all five spawn sites in `plamen_driver.py`.

### Preflight cache

`preflight_pty_transports.py` probes whether the host's PTY transport is functional and caches the result per-host. Cache schema version is `_SCHEMA_VERSION = 3` (`scripts/preflight_pty_transports.py:62`); v3 invalidates any pre-env-strip false-negative caches. Cache files written with an older schema are ignored.

---

## Discovery aids

A driver-generated artifact steers depth workers toward unbound or under-justified value flows without prescribing findings:

- **`security_feature_facts.json`** — run/source/hash-bound feature-fact authority derived from the mechanical graph, typed recon facts, and a source-locus-scoped compatibility fallback. V2 relation rows bind subject, object, and normalized symbol; legacy subject-only declarations cannot suppress exact classification debt.
- **Asset-representation provenance** — the [asset-representation foundation](asset-representation-foundation.md) records a closed provider capability matrix and occurrence-edge migration state. Model/v1/v2 declarations are proposal-only, and current graph providers cannot claim a universal wrapped-asset classification.
- **`security_obligation_authority.json`** — rule-owned obligation and receipt-reconciliation authority. Repeated trigger paths are aliases; accounted obligations are excluded from repair queueing.
- **`security_obligations.md`** — exact human/worker projection of the typed authority. Its alias table exposes every structural target and relation. When present, depth workers read it as input 5 (`prompts/shared/v2/phase4b-depth.md`) and emit one exact alias receipt per evaluated row (`[OBLIG:security_obligations.md:<SO-ID>] ALIAS:<SOT-ID> STATUS:R|D|C ...`).

Markdown is never parsed back into methodology authority. Current, run-bound receipts are reconciled from the depth work denominator; unresolved or malformed authority remains additive attention-repair debt.

---

## ID identity

Finding IDs flow through three regimes:

1. **Provisional analysis IDs** — assigned by breadth/depth/chain workers in their own output files (e.g. `[CS-1]`, `[TF-3]`, `[BLIND-2]`, `CH-2`). These are not stable and never appear in the client report.
2. **Canonical identity map** — `_write_canonical_finding_identity_map` (`scripts/plamen_mechanical.py:1049`) refreshes a driver-owned identity sidecar after every major discovery phase (`breadth`, `rescan`, inventory chunks, `depth`, `attention_repair`, `rag_sweep`, semantic dedup variants, chain variants, `post_verify_extract`, `skeptic`, `crossbatch`, `report_index`). Source artifacts are preserved; the map is additive.
3. **Final report IDs** — the `report_index` phase reassigns to clean sequential IDs grouped by severity tier: `C-01 / H-01 / M-01 / L-01 / I-01`. Tier writers and the report assembler consume only these IDs; internal pipeline IDs are explicitly forbidden in the client-facing report (see `rules/report-template.md`).

---

## Concurrency control

A per-scratchpad file lock prevents two driver invocations from racing on the same audit:

- Lock file: `<scratchpad>/.plamen_run.lock` (`_RUN_LOCK_NAME`, `scripts/plamen_driver.py:15820`).
- Payload records PID and acquisition timestamp; held for the lifetime of the driver process.

When the user presses Esc / halts the run, the driver cancels queued workers and terminates in-flight ones with a bounded grace period:

- `_cancel_pending_worker_futures` (`scripts/plamen_driver.py:1992-2007`) cancels each pending `Future` and calls `executor.shutdown(wait=False, cancel_futures=True)` — it does **not** wait for the pool to drain.
- In-flight workers receive `SIGTERM` (POSIX `os.killpg`) or `terminate(force=False)` (Windows winpty), then `SIGKILL` / `kill` after `_HALT_TERMINATE_GRACE_S = 2.0` seconds (`scripts/plamen_driver.py:1939`). The same grace window is used at every PTY-session termination site in the driver.

---

**See also**: [architecture.md](architecture.md) · [pipeline-phases-presentation.md](pipeline-phases-presentation.md) · [repository-structure.md](repository-structure.md) · [glossary.md](glossary.md) · [docs index](README.md)
