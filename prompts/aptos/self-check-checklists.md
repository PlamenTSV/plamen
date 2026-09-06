# Self-Check Checklists -- Aptos Move

> **Usage**: Orchestrator reviews these checklists at the end of each phase to ensure nothing was missed.

---

## After Recon (Before Phase 2)

- [ ] All external module dependencies identified? (`use` statements traced)
- [ ] All patterns detected? (FA hooks, randomness, object refs, generic types, friend declarations)
- [ ] All artifacts in scratchpad?
- [ ] meta_buffer.md populated with RAG results?
- [ ] Fork ancestry research completed? (TASK 0 step 6)
- [ ] Production fetch completed? (TASK 11 -- MANDATORY)
- [ ] Move Prover probed? (if `spec` annotations exist in source)
- [ ] `aptos move compile` or `aptos move compile --check` successful?
- [ ] Module upgrade policy documented? (`can_change_*` flags from `PackageMetadata`)
- [ ] UNVERIFIED deps flagged with severity implications?
- [ ] BINDING MANIFEST present in template_recommendations.md?
- [ ] Trust Assumption Table present in design_context.md?

## After Breadth (Before Phase 4a)

- [ ] All REQUIRED templates have agents spawned?
- [ ] spawn_manifest.md created?
- [ ] All expected analysis_*.md files exist?
- [ ] All findings have Step Execution fields?
- [ ] All findings have Rules Applied field [R1-R17, MR1-MR5, AR1-AR4] where applicable?
- [ ] FLASH_LOAN_INTERACTION skill instantiated if FLASH_LOAN flag detected? (R15)
- [ ] ORACLE_ANALYSIS skill instantiated if ORACLE flag detected? (R16)
- [ ] ABILITY_ANALYSIS skill applied where struct definitions exist? (MR1)
- [ ] BIT_SHIFT_SAFETY skill applied where shift operators found? (MR2)
- [ ] TYPE_SAFETY skill applied where generic type parameters exist? (MR3)
- [ ] REF_LIFECYCLE skill applied where Object refs created/stored? (AR1)
- [ ] Breadth agent count <= target from merge hierarchy? If exceeded, skills merged per M1-M5 priority? (FLASH_LOAN and ORACLE_ANALYSIS never merged)
- [ ] ORACLE_ANALYSIS skill NOT merged with any other agent?
- [ ] ECONOMIC_DESIGN_AUDIT skill instantiated if MONETARY_PARAMETER flag detected?
- [ ] EXTERNAL_PRECONDITION_AUDIT skill instantiated if external module interactions detected?

## After Inventory (Phase 4a -- includes side effect trace audit)

- [ ] phase4_gates.md created?
- [ ] Move Prover violations promoted? (HIGH priority -- formal verification failures)
- [ ] Bit-shift findings promoted? (HIGH priority -- abort vector, MR2)
- [ ] Ability misuse findings promoted? (`copy` on value types, `drop` on obligations, MR1)
- [ ] Dispatchable hook reentrancy findings promoted? (AR2 + AR3)
- [ ] Gate 1 (Spawn): If BLOCKED, missing agents re-spawned?
- [ ] Side effect trace audit completed within inventory agent?
- [ ] All Side-Effect=YES tokens from attack_surface.md traced to termination?
- [ ] Dispatchable FungibleAsset hooks traced through all deposit/withdraw paths?
- [ ] New [SE-N] findings created for uncovered side effect chains?
- [ ] Side effect coverage gaps documented?

## After Adaptive Depth Loop (Phase 4b)

### Iteration 1 (full coverage)
- [ ] All 4 depth agents spawned?
- [ ] Blind Spot Scanner A spawned IN PARALLEL? (Tokens & Parameters)
- [ ] blind_spot_a_findings.md exists in scratchpad?
- [ ] Scanner A checked: external token coverage (R11), governance-changeable parameter coverage (R13)?
- [ ] Blind Spot Scanner B spawned IN PARALLEL? (Guards, Visibility & Module Access)
- [ ] blind_spot_b_findings.md exists in scratchpad?
- [ ] Scanner B checked: admin griefability (R2), function visibility (MR5), friend declaration scope, inherited/imported capability completeness?
- [ ] Blind Spot Scanner C spawned IN PARALLEL? (Role Lifecycle, Capability Exposure & Reachability)
- [ ] blind_spot_c_findings.md exists in scratchpad?
- [ ] Scanner C checked: role/capability lifecycle completeness (grant/revoke/store/extract), ref exposure gaps (AR1), function reachability audit?
- [ ] Validation Sweep Agent spawned IN PARALLEL with depth agents?
- [ ] validation_sweep_findings.md exists in scratchpad?
- [ ] Depth agents answered "What would make this exploitable?"
- [ ] Depth agents searched for enablers before REFUTED?
- [ ] No REFUTED based on mock behavior or documentation alone?
- [ ] Uncertain verdicts -> CONTESTED (not REFUTED)?
- [ ] REFUTED upgraded to PARTIAL/CONTESTED where needed?
- [ ] Timeout split-and-retry applied for timed-out agents?
- [ ] Depth agent findings contain Depth Evidence tags ([BOUNDARY:*], [VARIATION:*], [TRACE:*])?
- [ ] Depth-external traced nested call chains through outer function post-execution checks?

### Confidence Scoring (after iteration 1)
- [ ] Consensus pre-computation completed (consensus_map.md)?
- [ ] Transient routing tables returned in domain batches (<=15 per batch), or recall-safe fallback recorded?
- [ ] Driver-published confidence_scores.md present after the depth wave?
- [ ] confidence_distribution.md written to scratchpad?
- [ ] All findings have composite confidence scores?
- [ ] Severity-weighted spawn priorities computed for uncertain findings?
- [ ] Dynamic budget cap applied? (min(max(12, ceil(findings/5)+7), 20))
- [ ] Analysis Quality axis used dual-mode scoring (Mode A for depth, Mode B for breadth)?

### Adaptive Loop (iterations 2-3, if triggered)
- [ ] If UNCERTAIN findings exist: iteration 2 spawned targeted depth agents?
- [ ] Anti-dilution: iteration 2+ agents received evidence-only finding cards (no prior reasoning)?
- [ ] Anti-dilution: iteration 2+ agents made their own tool calls (Read, Grep, MCP)?
- [ ] Anti-dilution: max 5 findings per agent per iteration?
- [ ] If iteration 2 ran: re-scoring completed with new-evidence-only rule?
- [ ] If iteration 2 ran: progress check -- did any confidence improve?
- [ ] If no progress: remaining uncertain findings forced to CONTESTED?
- [ ] If iteration 3 ran: final re-scoring completed?
- [ ] If iteration 3 ran: remaining findings < 0.4 forced to CONTESTED?
- [ ] Severity-weighted spawn selection used for iterations 2-3?
- [ ] Loop dynamics classified after iteration 2? (CONTRACTIVE/OSCILLATORY/EXPLORATORY)
- [ ] If OSCILLATORY: all uncertain forced to CONTESTED and loop exited?
- [ ] Total depth agent spawns <= dynamic budget cap?
- [ ] adaptive_loop_log.md written (iteration count, exit condition, spawns used, loop dynamics)?
- [ ] Budget redirect triggered if remaining_budget >= 3?

### Rule Coverage (all iterations)
- [ ] Cross-module call return types verified? (Rule R1 -- generic type confusion, Object<T> type mismatch)
- [ ] Keeper AND admin precondition griefability checked? (Rule R2 -- resource creation front-running, FungibleStore donation)
- [ ] Transfer side effects documented with token types? (Rule R3 -- dispatchable hooks, Coin vs FA)
- [ ] "could/might" statements pursued to conclusion?
- [ ] CONTESTED treated with adversarial assumption? (Rule R4 -- upgradeable modules, unknown hooks)
- [ ] Combinatorial analysis for N-entity protocols? (Rule R5 -- gas limits on batch operations)
- [ ] Bidirectional role analysis (both directions)? (Rule R6 -- capability holders, friend modules)
- [ ] Donation-based DoS checked for thresholds? (Rule R7 -- FungibleStore/Coin deposit, resource creation blocking)
- [ ] Cached parameter staleness assessed for multi-step ops? (Rule R8 -- resource snapshots, object ownership, module upgrade between steps)
- [ ] Stranded assets checked for recovery paths? (Rule R9 -- immutable modules, lost SignerCapability, missing move_from/DeleteRef)
- [ ] Worst-state severity used (not current snapshot)? (Rule R10 -- Aptos gas limits, SmartVector sizes)
- [ ] Unsolicited external token transfer impact traced for all external tokens? (Rule R11 -- FA deposit, Coin deposit, AptosCoin transfer)
- [ ] Adversarial assumption applied for unknown externals? (Rule R4)
- [ ] Exhaustive enabler enumeration for dangerous states? (Rule R12)
- [ ] Anti-normalization check for "by design" conclusions? (Rule R13 -- non-deletable objects, resource accounts, immutable modules)
- [ ] Cross-variable invariants checked? (Rule R14 -- aggregates across Table entries, constraint coherence, setter regression)
- [ ] Flash loan precondition manipulation checked? (Rule R15 -- hot-potato pattern, within-tx balance inflation)
- [ ] Oracle integrity verified? (Rule R16 -- Pyth/Switchboard on Aptos, staleness, decimals, zero, config bounds)
- [ ] State transition completeness checked? (Rule R17 -- symmetric operation field coverage across resources)
- [ ] Ability annotations verified for all structs? (Rule MR1 -- copy/drop/store/key appropriateness)
- [ ] Bit-shift operations bounds-checked? (Rule MR2 -- abort on shift >= bit width)
- [ ] Generic type parameters constrained? (Rule MR3 -- type substitution attacks, phantom type confusion)
- [ ] External module dependencies audited? (Rule MR4 -- upgrade risk, interface stability)
- [ ] Function visibility minimized? (Rule MR5 -- public vs entry vs public(friend) vs internal)
- [ ] Object ref lifecycle traced? (Rule AR1 -- ConstructorRef escape, ExtendRef exposure, missing DeleteRef)
- [ ] Dispatchable FA hooks audited? (Rule AR2 -- reentrancy, abort risk, bypass via direct fungible_asset calls)
- [ ] Cross-module reentrancy patterns mapped? (Rule AR3 -- state-before-interaction, borrow-across-call)
- [ ] Randomness API safety verified? (Rule AR4 -- entry-only, no test-and-abort, #[randomness] attribute)
- [ ] Depth agents discovered NEW findings, not just re-verified?
- [ ] Depth agents checked attack_surface.md for unanalyzed vectors?
- [ ] MIGRATION skill instantiated if MIGRATION pattern detected?
- [ ] TEMPORAL_PARAMETER_STALENESS skill instantiated if TEMPORAL flag detected?
- [ ] SHARE_ALLOCATION_FAIRNESS skill instantiated if SHARE_ALLOCATION flag detected?
- [ ] Same-chain rate staleness checked for discrete-update patterns? (Scenario G)
- [ ] Shared utility findings list ALL consumers in Impact section?
- [ ] All privileged functions enumerated exhaustively? (via Grep if no static analyzer available)
- [ ] Rule R2 bidirectional: admin->user griefing checked? (admin parameter changes breaking user functions)
- [ ] Rule R16 oracle config bounds: oracle parameter setters have meaningful min/max?
- [ ] Struct parameters to external module calls validated? (Validation Sweep CHECK 5)
- [ ] Initialization ordering checked for multi-module systems? (depth-edge-case)
- [ ] Friend declaration scope checked for over-permissive access? (Blind Spot B)

## After Chain Analysis (Phase 4c -- includes enabler enumeration)

- [ ] PARTIAL/REFUTED findings documented preconditions?
- [ ] Enabler enumeration completed within chain analysis agent?
- [ ] All dangerous states from CONFIRMED/CONTESTED findings enumerated with 5 actor categories (Rule R12)?
- [ ] New [EN-N] findings created for missing enabler paths?
- [ ] Cross-state interactions documented?
- [ ] Anti-normalization check applied to any "by design" conclusions (Rule R13)?
- [ ] Passive attack modeling done for rate/timing findings (Rule R13)?
- [ ] Chain analyzer read depth findings + blind_spot_A/B/C_findings.md + validation_sweep_findings.md?
- [ ] Chain analyzer read confidence_scores.md for prioritization?
- [ ] Chain analyzer found postcondition->precondition matches?
- [ ] Severity reassessed with chain context?
- [ ] Chain severity matrix applied correctly?
- [ ] Anti-absorption rule applied?
- [ ] If chain upgrades on previously-CONFIDENT findings: post-chain iterative depth ran?

## After Verification (Before Report)

- [ ] All chain hypotheses verified with Move unit test PoC?
- [ ] All HIGH/CRITICAL verified with Move unit test PoC?
- [ ] No [MOCK]/[EXT-UNV] evidence supports REFUTED?
- [ ] External precedent treated as test/report context only under `precedent-evidence-policy.md`?
- [ ] Verifiers used real module constants?
- [ ] Move unit tests written for CONTESTED findings? (MANDATORY)
- [ ] Unit tests attempted for external module behavior hypotheses?
- [ ] Post-verification finding extraction completed? (Phase 5.5 -- scan verify_*.md for [VER-NEW-*])
- [ ] Error traces extracted from CONTESTED/FALSE_POSITIVE verifiers?
- [ ] Post-verification depth spawned if budget remains AND error traces exist?

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

- [ ] Step 6a: Index Agent completed -- report_index.md exists with clean IDs?
- [ ] Step 6a.1: Completeness assert passed? (hypothesis count == report IDs + excluded)
- [ ] Step 6a: Every hypothesis assigned to exactly one tier?
- [ ] Step 6a: Verification verdicts reflected in final severities?
- [ ] Step 6a: Trust assumption downgrades applied from Trust Assumption Table?
- [ ] Step 6b: All 3 tier writers spawned in parallel?
- [ ] Step 6b: report_critical_high.md exists and is non-empty?
- [ ] Step 6b: report_medium.md exists and is non-empty?
- [ ] Step 6b: report_low_info.md exists and is non-empty?
- [ ] Step 6c: Assembler model escalated to sonnet if >25 findings?
- [ ] Step 6c: Assembler completed -- AUDIT_REPORT.md exists in project root?
- [ ] Quality: Every finding has its own ### section (no catch-all tables)?
- [ ] Quality: NO internal pipeline IDs in report body (check CS-, AC-, TF-, BLIND-, EN-, SE-, VS-, DEPTH-, CH-, hypothesis H-)?
- [ ] Quality: Finding counts match summary table?
- [ ] Quality: Cross-references use report IDs only and all resolve?
- [ ] Quality: Severity reflects FINAL verdict (post-verification), not original hypothesis?
