# Self-Check Checklists

> **Usage**: Orchestrator reviews these checklists at the end of each phase to ensure nothing was missed.

---

## After Recon (Before Phase 2)

- [ ] All external deps identified?
- [ ] All patterns detected?
- [ ] All artifacts in scratchpad?
- [ ] meta_buffer.md populated with RAG results?
- [ ] Fork ancestry research completed? (TASK 0 step 6)
- [ ] Production fetch completed? (TASK 11 - MANDATORY)
- [ ] Farofino fallback used if Slither probe failed? (Aderyn + Pattern Analysis)
- [ ] UNVERIFIED deps flagged with severity implications?
- [ ] BINDING MANIFEST present in template_recommendations.md?

## After Breadth (Before Phase 4a)

- [ ] All REQUIRED templates have agents spawned?
- [ ] spawn_manifest.md created?
- [ ] All expected analysis_*.md files exist?
- [ ] All findings have Step Execution fields?
- [ ] All findings have Rules Applied field [R4, R5, R6, R8, R9, R10, R11, R12, R13, R14, R15, R16]?
- [ ] FLASH_LOAN_INTERACTION skill instantiated if FLASH_LOAN flag detected? (R15)
- [ ] ORACLE_ANALYSIS skill instantiated if ORACLE flag detected? (R16)
- [ ] Breadth agent count ≤ target from merge hierarchy? If exceeded, skills merged per M1-M5 priority? (FLASH_LOAN and ORACLE_ANALYSIS never merged)
- [ ] ORACLE_ANALYSIS skill NOT merged with any other agent?
- [ ] ECONOMIC_DESIGN_AUDIT skill instantiated if MONETARY_PARAMETER flag detected?
- [ ] EXTERNAL_PRECONDITION_AUDIT skill instantiated if external interactions detected?

## After Inventory (Phase 4a - includes side effect trace audit)

- [ ] phase4_gates.md created?
- [ ] Slither findings promoted? (calls-loop, reentrancy, unchecked-transfer, divide-before-multiply)
- [ ] Gate 1 (Spawn): If BLOCKED, missing agents re-spawned?
- [ ] Side effect trace audit completed within inventory agent?
- [ ] All Side-Effect=YES tokens from attack_surface.md traced to termination?
- [ ] New [SE-N] findings created for uncovered side effect chains?
- [ ] Side effect coverage gaps documented?

## After Adaptive Depth Loop (Phase 4b)

### Iteration 1 (full coverage)
- [ ] All 4 depth agents spawned?
- [ ] Blind Spot Scanner A spawned IN PARALLEL? (Tokens & Parameters)
- [ ] blind_spot_A_findings.md exists in scratchpad?
- [ ] Scanner A checked: external token coverage (R11), governance-changeable parameter coverage (R13)?
- [ ] Blind Spot Scanner B spawned IN PARALLEL? (Guards, Visibility & Inheritance)
- [ ] blind_spot_B_findings.md exists in scratchpad?
- [ ] Scanner B checked: admin griefability (R2), function visibility, inherited capability completeness, override safety?
- [ ] Blind Spot Scanner C spawned IN PARALLEL? (Role Lifecycle, Capability Exposure & Reachability)
- [ ] blind_spot_C_findings.md exists in scratchpad?
- [ ] Scanner C checked: role lifecycle completeness (grant/revoke pairs), inherited capability exposure gaps, function reachability audit?
- [ ] Validation Sweep Agent spawned IN PARALLEL with depth agents?
- [ ] validation_sweep_findings.md exists in scratchpad?
- [ ] Depth agents answered "What would make this exploitable?"
- [ ] Depth agents searched for enablers before REFUTED?
- [ ] No REFUTED based on mock behavior?
- [ ] Uncertain verdicts → CONTESTED (not REFUTED)?
- [ ] REFUTED upgraded to PARTIAL/CONTESTED where needed?
- [ ] Timeout split-and-retry applied for timed-out agents? (2 lite agents = 1 budget unit)
- [ ] Depth agent findings contain Depth Evidence tags ([BOUNDARY:*], [VARIATION:*], [TRACE:*])?

### Confidence Scoring (after iteration 1)
- [ ] Consensus pre-computation completed (consensus_map.md)? (orchestrator inline)
- [ ] Scoring agents spawned in domain batches (≤15 per batch)? (batched scoring)
- [ ] confidence_scores.md written to scratchpad?
- [ ] confidence_distribution.md written to scratchpad?
- [ ] All findings have composite confidence scores?
- [ ] Severity-weighted spawn priorities computed for uncertain findings?
- [ ] Dynamic budget cap applied? (min(max(12, ceil(findings/5)+7), 20))
- [ ] Analysis Quality axis used dual-mode scoring (Mode A for depth, Mode B for breadth)?

### Adaptive Loop (iterations 2-3, if triggered)
- [ ] If UNCERTAIN findings exist: iteration 2 spawned targeted depth agents?
- [ ] Anti-dilution: iteration 2+ agents received evidence-only finding cards (no prior reasoning)?
- [ ] Anti-dilution: iteration 2+ agents made their own MCP tool calls?
- [ ] Anti-dilution: max 5 findings per agent per iteration?
- [ ] If iteration 2 ran: re-scoring completed with new-evidence-only rule?
- [ ] If iteration 2 ran: progress check - did any confidence improve?
- [ ] If no progress: remaining uncertain findings forced to CONTESTED?
- [ ] If iteration 3 ran: final re-scoring completed?
- [ ] If iteration 3 ran: remaining findings < 0.4 forced to CONTESTED?
- [ ] Severity-weighted spawn selection used for iterations 2-3? (Critical first)
- [ ] Loop dynamics classified after iteration 2? (CONTRACTIVE/OSCILLATORY/EXPLORATORY)
- [ ] If OSCILLATORY: all uncertain forced to CONTESTED and loop exited?
- [ ] Total depth agent spawns ≤ dynamic budget cap?
- [ ] adaptive_loop_log.md written (iteration count, exit condition, spawns used, loop dynamics)?
- [ ] Budget redirect triggered if remaining_budget >= 3? (Design Stress Testing Agent)

### Rule Coverage (all iterations)
- [ ] External call return types verified? (Rule 1)
- [ ] Keeper AND admin precondition griefability checked? (Rule 2)
- [ ] Transfer side effects documented with token types? (Rule 3)
- [ ] "could/might" statements pursued to conclusion?
- [ ] CONTESTED treated with adversarial assumption? (Rule 4)
- [ ] Combinatorial analysis for N-entity protocols? (Rule 5)
- [ ] Bidirectional role analysis (both directions)? (Rule 6)
- [ ] Donation-based DoS checked for thresholds? (Rule 7)
- [ ] Cached parameter staleness assessed for multi-step ops? (Rule 8)
- [ ] Stranded assets checked for recovery paths? (Rule 9)
- [ ] Worst-state severity used (not current snapshot)? (Rule 10)
- [ ] Unsolicited external token transfer impact traced for all external tokens? (Rule 11)
- [ ] Adversarial assumption applied for unknown externals? (Rule 4)
- [ ] Depth agents discovered NEW findings, not just re-verified?
- [ ] Depth agents checked attack_surface.md for unanalyzed vectors?
- [ ] MIGRATION skill instantiated if pattern detected?
- [ ] TEMPORAL_PARAMETER_STALENESS skill instantiated if TEMPORAL flag detected?
- [ ] SHARE_ALLOCATION_FAIRNESS skill instantiated if SHARE_ALLOCATION flag detected?
- [ ] Same-chain rate staleness checked for discrete-update patterns? (Scenario G)
- [ ] Cross-variable invariants checked? (Rule 14: aggregates, constraint coherence, setter regression)
- [ ] Shared utility findings list ALL consumers in Impact section?
- [ ] All privileged functions enumerated exhaustively via Slither? (Step 6b)
- [ ] Rule 2 bidirectional: admin→user griefing checked? (admin parameter changes breaking user functions)
- [ ] Rule 16 oracle config bounds: oracle parameter setters have meaningful min/max?
- [ ] Struct parameters to external calls validated? (Validation Sweep CHECK 5)
- [ ] Initialization ordering checked for multi-contract systems? (depth-edge-case)
- [ ] Inherited capability configurability checked? (Blind Spot B Check 5)

## After Chain Analysis (Phase 4c - includes enabler enumeration)

- [ ] PARTIAL/REFUTED findings documented preconditions?
- [ ] Enabler enumeration completed within chain analysis agent?
- [ ] All dangerous states from CONFIRMED/CONTESTED findings enumerated with 5 actor categories (Rule 12)?
- [ ] New [EN-N] findings created for missing enabler paths?
- [ ] Cross-state interactions documented?
- [ ] Anti-normalization check applied to any "by design" conclusions (Rule 13)?
- [ ] Passive attack modeling done for rate/timing findings (Rule 13)?
- [ ] Chain analyzer read depth findings + blind_spot_A/B/C_findings.md + validation_sweep_findings.md?
- [ ] Chain analyzer read confidence_scores.md for prioritization?
- [ ] Chain analyzer found postcondition→precondition matches?
- [ ] Severity reassessed with chain context?
- [ ] Chain severity matrix applied correctly?
- [ ] Anti-absorption rule applied? (same fix required, no severity obscuring, both paths readable)
- [ ] If chain upgrades on previously-CONFIDENT findings: post-chain iterative depth ran?

## After Skeptic-Judge (Thorough mode only, after standard verification)

- [ ] All HIGH/CRIT findings received skeptic agent? (Thorough mode only)
- [ ] Skeptic agents used INVERSION MANDATE (opposite conclusion from standard)?
- [ ] Skeptic agents made their OWN tool calls (not reusing standard verifier output)?
- [ ] If skeptic DISAGREED: judge agent spawned with both verification files?
- [ ] Judge used strictly mechanical evidence hierarchy (POC-PASS > CODE-TRACE)?
- [ ] Final verdicts applied per ruling table (STANDARD_WINS/SKEPTIC_WINS/CONTESTED)?
- [ ] skeptic_*.md and judge_*.md files exist in scratchpad for all processed findings?

## After Verification (Before Report)

- [ ] All chain hypotheses verified with PoC?
- [ ] All Medium+ verified with PoC? (both Core and Thorough)
- [ ] No [MOCK]/[EXT-UNV] evidence supports REFUTED?
- [ ] RAG ≥ 6/8 findings not marked FALSE_POSITIVE?
- [ ] Verifiers used real contract constants?
- [ ] Fork testing MANDATORY for CONTESTED findings? (not just preferred)
- [ ] Fork testing used for external dep hypotheses?
- [ ] Post-verification finding extraction completed? (Phase 5.5 - scan verify_*.md for [VER-NEW-*])
- [ ] Error traces extracted from CONTESTED/FALSE_POSITIVE verifiers? (verification_error_traces.md)
- [ ] Post-verification depth spawned if budget remains AND error traces exist? (AD-6)

## After Report Generation (Phase 6)

- [ ] Step 6a: Index Agent completed - report_index.md exists with clean IDs?
- [ ] Step 6a.1: Completeness assert passed? (hypothesis count == report IDs + excluded)
- [ ] Step 6a: Every hypothesis assigned to exactly one tier?
- [ ] Step 6a: Verification verdicts reflected in final severities?
- [ ] Step 6b: All 3 tier writers spawned in parallel?
- [ ] Step 6b: report_critical_high.md exists and is non-empty?
- [ ] Step 6b: report_medium.md exists and is non-empty?
- [ ] Step 6b: report_low_info.md exists and is non-empty?
- [ ] Step 6c: Assembler model escalated to sonnet if >25 findings?
- [ ] Step 6c: Assembler completed - AUDIT_REPORT.md exists in project root?
- [ ] Quality: Every finding has its own ### section (no catch-all tables)?
- [ ] Quality: NO internal pipeline IDs in report body (check CS-, AC-, TF-, BLIND-, EN-, SE-, VS-, DEPTH-, SLITHER-, CH-, hypothesis H-)?
- [ ] Quality: Finding counts match summary table?
- [ ] Quality: Cross-references use report IDs only and all resolve?
- [ ] Quality: Severity reflects FINAL verdict (post-verification), not original hypothesis?
