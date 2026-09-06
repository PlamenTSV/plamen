# Self-Check Checklists - Soroban

> **Usage**: Orchestrator reviews these checklists at the end of each phase.

---

## After Recon (Before Phase 2)

- [ ] `stellar contract build` or `cargo build --target wasm32v1-none --release` succeeded?
- [ ] `overflow-checks = true` in Cargo.toml release profile? (if false → HIGH finding: arithmetic bugs silent)
- [ ] `cargo clippy` run for lint warnings?
- [ ] `cargo audit` run for known vulnerable dependencies?
- [ ] Scout scan completed? (`cargo scout-audit --output-format json`) — or grep fallback documented?
- [ ] All cross-contract call targets inventoried in attack_surface.md?
- [ ] Upgrade authority type identified (no upgrade / admin-controlled / multisig)?
- [ ] All external contract dependencies identified (contract IDs, interfaces)?
- [ ] Storage type inventory completed? (instance / persistent / temporary per contract)?
- [ ] TTL management patterns identified? (extend_ttl calls for persistent entries)?
- [ ] All auth patterns detected? (require_auth / require_auth_for_args / mock_all_auths in tests)?
- [ ] Fork ancestry research completed (Soroban parents: OpenZeppelin Stellar ports, etc.)?
- [ ] BINDING MANIFEST present in template_recommendations.md?
- [ ] AUTH_VALIDATION marked as ALWAYS REQUIRED?
- [ ] meta_buffer.md populated with RAG results?

## After Breadth (Before Phase 4a)

- [ ] All REQUIRED templates have agents spawned?
- [ ] spawn_manifest.md created?
- [ ] AUTH_VALIDATION skill instantiated? (ALWAYS required for Soroban)
- [ ] CROSS_CONTRACT_SECURITY skill instantiated if cross-contract calls detected?
- [ ] STORAGE_LIFECYCLE skill instantiated if TTL-sensitive patterns detected?
- [ ] TOKEN_INTERFACE skill instantiated if Stellar Asset Contract or custom token detected?
- [ ] SEMI_TRUSTED_ROLES skill instantiated if SEMI_TRUSTED_ROLE flag detected?
- [ ] ORACLE skill instantiated if off-chain price feed or oracle pattern detected?
- [ ] All expected analysis_*.md files exist?
- [ ] All findings have Step Execution fields?
- [ ] All findings have Rules Applied field (R1-R16)?

## After Inventory (Phase 4a)

- [ ] phase4_gates.md created?
- [ ] Scout findings promoted? (or grep-based findings promoted)
- [ ] Gate 1 (Spawn): If BLOCKED, missing agents re-spawned?
- [ ] Side effect trace audit completed? (cross-contract side effects traced)
- [ ] All cross-contract targets with side effects traced to termination?
- [ ] New [SE-N] findings created for uncovered side effect chains?
- [ ] Storage key namespace collisions checked across all contracts?

## After Adaptive Depth Loop (Phase 4b)

### Iteration 1 (full coverage)
- [ ] All 4 depth agents spawned?
- [ ] Blind Spot Scanner A spawned? (Token/balance coverage, parameter coverage)
- [ ] Blind Spot Scanner B spawned? (Auth gaps, storage type misuse, TTL management)
- [ ] Blind Spot Scanner C spawned? (Upgrade authority lifecycle, cross-contract call validation)
- [ ] Validation Sweep Agent spawned?
- [ ] Storage type correctness checked for all stateful operations?
  - [ ] Persistent storage used for user balances and protocol state?
  - [ ] Instance storage not used for per-user data?
  - [ ] Temporary storage expiry risk assessed for all uses?
- [ ] TTL extension calls verified at all deposit/update entry points?
- [ ] require_auth coverage verified for all state-mutating functions?
- [ ] Arithmetic overflow risk assessed (i128 intermediate products in reward formulas)?
- [ ] Cross-contract call validation: are callee contract IDs checked against expected values?
- [ ] Upgrade authorization checked: is upgrade gated behind admin auth?
- [ ] Depth evidence tags present ([BOUNDARY:*], [VARIATION:*], [TRACE:*])?

### Confidence Scoring
- [ ] Driver-published consensus_map.md present after the depth wave?
- [ ] Transient routing tables returned in domain batches (≤15 per batch), or recall-safe fallback recorded?
- [ ] Driver-published confidence_scores.md present after the depth wave?
- [ ] confidence_distribution.md written?

### Adaptive Loop (iterations 2-3)
- [ ] Anti-dilution rules enforced? (AD-1 through AD-6: evidence-only carryover, no reasoning contamination, max 5 findings per agent, fresh tool calls, new-evidence-only re-scoring, error trace injection)
- [ ] Total depth spawns ≤ dynamic budget cap?
- [ ] adaptive_loop_log.md written?
- [ ] Budget redirect triggered if remaining_budget >= 3? (Design Stress Testing)

## After Chain Analysis (Phase 4c)

- [ ] Enabler enumeration completed (5 actor categories)?
- [ ] Anti-normalization check applied (Rule 13)?
- [ ] Anti-absorption rule applied?
- [ ] Chain analyzer read all depth/blind-spot/validation outputs?
- [ ] Storage type chains considered? (temporary storage expiry enabling secondary attack)?

## After Verification (Before Report)

- [ ] All chain hypotheses verified with PoC?
- [ ] All HIGH/CRITICAL verified with PoC?
- [ ] PoC uses `cargo test --features testutils` (NOT plain `cargo test`)?
- [ ] `env.register(ContractType, ())` used — NOT deprecated `env.register_contract()`?
- [ ] Storage access uses typed `.instance()` / `.persistent()` / `.temporary()` — NOT `.get()`?
- [ ] Auth tested WITHOUT `env.mock_all_auths()` for auth-sensitive hypotheses?
- [ ] Ledger time manipulation uses `env.ledger().with_mut(|li| {...})` pattern?
- [ ] No [MOCK]/[EXT-UNV] evidence supports REFUTED?
- [ ] Post-verification finding extraction completed? (Phase 5.5)

## After Independent Skeptic Challenge (Thorough mode, after standard verification)

- [ ] Driver-owned semantic trigger manifest considered eligible findings across all severity tiers, without a severity-tier filter?
- [ ] Ecosystem verifier stopped at standard verification and did not spawn skeptic or judge workers or apply a challenge?
- [ ] Hash-bound typed receipt contains exactly one row for every exact manifest finding ID, with no missing, duplicate, unknown, stale, or constituent-substituted IDs?
- [ ] Skeptic artifacts remained proposal-only and were not treated as final verdict, severity, or disposition authority?
- [ ] Every challenge requiring disposition went to a separate typed adjudicator with a different worker/session identity?
- [ ] Only a validated, report-authoritative typed severity/disposition ledger affected downstream severity or disposition?
- [ ] `UNRESOLVED` and `PARTIAL` findings preserved their highest supported upstream tier and remained visible in the report body?
- [ ] Any incomplete or invalid receipt retried or degraded to explicit human review rather than silently skipping an ID?

## After Report Generation (Phase 6)

- [ ] Quality gates passed? (every finding has own section, no internal IDs in body, finding count matches summary, cross-references valid, severity consistency)
- [ ] AUDIT_REPORT.md exists in project root?
- [ ] No internal pipeline IDs in report body?
- [ ] Finding counts match summary table?
