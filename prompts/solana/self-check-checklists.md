# Self-Check Checklists - Solana

> **Usage**: Orchestrator reviews these checklists at the end of each phase.

---

## After Recon (Before Phase 2)

- [ ] `anchor build` or `cargo build-sbf` succeeded?
- [ ] `overflow-checks = true` in Cargo.toml release profile? (if false → finding)
- [ ] `cargo clippy` run for lint warnings?
- [ ] `cargo audit` run for known vulnerable dependencies?
- [ ] Fender scan completed? (or grep fallback documented)
- [ ] All CPI targets inventoried in attack_surface.md?
- [ ] Upgrade authority type identified (immutable / multisig / single EOA)?
- [ ] All external program dependencies identified?
- [ ] All patterns detected (TASK 6)?
- [ ] Fork ancestry research completed (Solana parents: Marinade, Jupiter, Orca, etc.)?
- [ ] Production fetch completed? (TASK 11 - Helius or CLI)
- [ ] UNVERIFIED deps flagged with severity implications?
- [ ] BINDING MANIFEST present in template_recommendations.md?
- [ ] ACCOUNT_VALIDATION marked as ALWAYS REQUIRED?
- [ ] meta_buffer.md populated with RAG results?

## After Breadth (Before Phase 4a)

- [ ] All REQUIRED templates have agents spawned?
- [ ] spawn_manifest.md created?
- [ ] ACCOUNT_VALIDATION skill instantiated? (ALWAYS required for Solana)
- [ ] CPI_SECURITY skill instantiated if CPI flag detected?
- [ ] PDA_SECURITY skill instantiated if PDA flag detected?
- [ ] ACCOUNT_LIFECYCLE skill instantiated if ACCOUNT_CLOSING flag detected?
- [ ] TOKEN_2022_EXTENSIONS skill instantiated if TOKEN_2022 flag detected?
- [ ] INSTRUCTION_INTROSPECTION skill instantiated if INSTRUCTION_INTROSPECTION flag detected?
- [ ] SEMI_TRUSTED_ROLES skill instantiated if SEMI_TRUSTED_ROLE flag detected?
- [ ] ORACLE (R16 Solana) checked if ORACLE flag detected?
- [ ] All expected analysis_*.md files exist?
- [ ] All findings have Step Execution fields?
- [ ] All findings have Rules Applied field (R1-R16, S1-S10)?

## After Inventory (Phase 4a)

- [ ] phase4_gates.md created?
- [ ] Fender findings promoted? (or grep-based findings promoted)
- [ ] Gate 1 (Spawn): If BLOCKED, missing agents re-spawned?
- [ ] Side effect trace audit completed? (CPI side effects traced)
- [ ] All CPI targets with side effects traced to termination?
- [ ] New [SE-N] findings created for uncovered side effect chains?

## After Adaptive Depth Loop (Phase 4b)

### Iteration 1 (full coverage)
- [ ] All 4 depth agents spawned?
- [ ] Blind Spot Scanner A spawned? (Token/account coverage, parameter coverage)
- [ ] Blind Spot Scanner B spawned? (Access control gaps, PDA seed collisions, remaining_accounts)
- [ ] Blind Spot Scanner C spawned? (Upgrade authority lifecycle, CPI target validation completeness)
- [ ] Validation Sweep Agent spawned?
- [ ] Account reload after CPI checked for all CPI sites? (S5)
- [ ] Token-2022 extension impact traced for all token accounts? (S9)
- [ ] CU worst-case tested for bounded loops? (R10)
- [ ] Revival attack prevention verified for all close operations? (S4)
- [ ] PDA seed collision analysis completed? (S2)
- [ ] Remaining accounts validation checked for all remaining_accounts usage? (S6)
- [ ] Duplicate mutable account attack checked? (S7)
- [ ] Sysvar spoofing checked? (S8)
- [ ] Depth evidence tags present ([BOUNDARY:*], [VARIATION:*], [TRACE:*])?

### Confidence Scoring
- [ ] consensus_map.md created (orchestrator inline)?
- [ ] Scoring agents spawned in domain batches (≤15 per batch)?
- [ ] confidence_scores.md written?
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

## After Verification (Before Report)

- [ ] All chain hypotheses verified with PoC?
- [ ] All HIGH/CRITICAL verified with PoC?
- [ ] PoC uses LiteSVM for Solana programs?
- [ ] No [MOCK]/[EXT-UNV] evidence supports REFUTED?
- [ ] Post-verification finding extraction completed? (Phase 5.5)

## After Report Generation (Phase 6)

- [ ] Quality gates passed? (every finding has own section, no internal IDs in body, finding count matches summary, cross-references valid, severity consistency)
- [ ] AUDIT_REPORT.md exists in project root?
- [ ] No internal pipeline IDs in report body?
- [ ] Finding counts match summary table?
