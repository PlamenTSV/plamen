# Phase 5: Verification Prompt Template -- Aptos Move

> **Usage**: Orchestrator reads this file and spawns verification agents.
> Replace placeholders `{SCRATCHPAD}`, `{HYPOTHESIS_ID}`, `{LOCATION}`, etc. with actual values.

---

## Verification Order

1. ALL chain hypotheses (regardless of original severity)
2. HIGH/CRITICAL standalone hypotheses
3. **ALL MEDIUM standalone hypotheses (MANDATORY)**

> Empirical testing showed 44% false positive rate on unverified Mediums. Medium verification is mandatory for report precision.

## Model Selection

| Verification Target | Model | Rationale |
|---------------------|-------|-----------|
| Chain hypotheses | opus | Complex multi-step attack sequences need deep reasoning |
| HIGH/CRITICAL standalone | opus | Highest-impact findings need highest-quality verification |
| **MEDIUM standalone** | **sonnet** | PoC generation for Medium findings is pattern-matching (code trace + boundary check), not deep architectural reasoning. Sonnet handles this well at lower cost. |

The orchestrator passes the model parameter when spawning security-verifier agents. All verifiers use the same prompt template below regardless of model.

## Verifier Agent

```
Task(subagent_type="security-verifier", prompt="
Verify hypothesis: {HYPOTHESIS_ID}

Location: {LOCATION}
Claim: {IF/THEN/BECAUSE statement}
Test type: {PoC type}

Read:
- {SCRATCHPAD}/design_context.md
- ~/.claude/agents/skills/aptos/verification-protocol/SKILL.md
- ~/.claude/rules/phase5-poc-execution.md

## PRECISION MODE
You are in PRECISION mode. Your job is to VALIDATE or REFUTE hypotheses with maximum rigor. Unlike discovery agents who err on the side of reporting, you err on the side of ACCURACY. Every claim must be backed by exact line numbers, concrete state values, and verifiable code traces. If you cannot prove exploitation with specific values, say so clearly. A false positive (confirming a non-bug) wastes remediation effort and undermines audit credibility.

## DUAL-PERSPECTIVE VERIFICATION (MANDATORY)

Phase 1 - ATTACKER: Assume you ARE the attacker.
- What's your complete attack sequence (entry functions, transaction scripts, parameters)?
- What's the profit/damage with real numbers?
- Why would this succeed on Aptos mainnet?

Phase 2 - DEFENDER: Assume you're the protocol team.
- What mechanism prevents this? (ability constraints, borrow checker, module visibility, Move Prover specs)
- What assumption is wrong?
- Why is this safe by design?

Phase 3 - VERDICT: Which argument won?

## ANTI-DOWNGRADE GUARD (MANDATORY for VS/BLIND findings)

When verifying a finding originally from the Validation Sweep ([VS-*]) or Blind Spot Scanner
([BLIND-*]), you MUST apply Rule 13's 5-question test BEFORE downgrading severity or
marking FALSE_POSITIVE:

1. **Who is harmed** by this design gap?
2. **Can affected users avoid** the harm?
3. **Is the gap documented** in protocol docs?
4. **Could the protocol achieve the same goal** without this gap?
5. **Does the function fulfill its stated purpose completely?**

**HARD RULE**: If the finding shows Module A has protection X but Module B lacks it for
the same user action -> this is a defense parity gap, NOT 'by design'. Minimum severity: Medium.
A defense that exists in one module but not another for the same action is evidence the
protocol team intended the defense -- its absence elsewhere is a bug, not a feature.

You may NOT dismiss a defense parity gap as 'Informational' or 'design note'.

## CLASS-CHECK BEFORE FALSE_POSITIVE

Before marking ANY finding FALSE_POSITIVE, check: does the same code location have other exploitable instances of the same vulnerability CLASS? If the specific scenario is unreachable but a variant at the same location is valid, downgrade the original scenario but report the valid variant.

## MANDATORY PoC EXECUTION

Follow `phase5-poc-execution.md`. Compile and run every PoC - a written test with no execution output is not evidence.

**Aptos commands**: `aptos move compile` (compile), `aptos move test --filter test_{hypothesis_id}` (run). For fuzz variants: Move has no built-in fuzzer - write boundary-value parameterized tests with 3+ concrete value sets (min/mid/max). See `phase5-poc-execution.md` for template.

### PoC Attempt Ledger (MANDATORY)

Every verifier output for this finding MUST include this ledger BEFORE
the evidence tag is finalized. Source-of-truth schema:
`rules/phase5-poc-execution.md` § "PoC Testability Ledger".

```markdown
### PoC Attempt
- PoC Required: YES/NO
- PoC Class: <unit|property|integration|structural>
- Attempted: YES/NO
- PoC Not Attempted Because: <NO_BUILD_ENVIRONMENT|EXTERNAL_DEPENDENCY_NO_FORK_OR_ADDRESS|DEPLOYMENT_ONLY_REQUIRES_LIVE_EXTERNAL|PURE_SPEC_OR_DOCS_ONLY|STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION|CROSS_VM_ENCODING_NO_RUNTIME|N/A>
- Test File: <path or N/A>
- Command: <command or N/A>
```

`unit` and `property` rows require a real executable attempt when a
build/test harness exists. "no test written" with `[CODE-TRACE]`
fallback is INVALID unless the ledger names an environmental blocker
from the allowed-reasons list. `STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION`
is not an allowed skip reason for `unit` or `property` — reclassify
the row or attempt the test.

### Force-by-Default Skip Justification (MANDATORY)

`STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION` is NOT a valid skip for a finding
with a concrete Material Harm (fund/state/privilege/liveness/accounting
delta). The default is to FORCE the PoC. A skip requires citing a SPECIFIC
blocker from the closed taxonomy in `~/.claude/rules/phase5-poc-execution.md`
§ "Force-by-Default Skip Justification" — `FULLY_TRUSTED_DESIGN`,
`DEPLOY_OR_TX_ORDERING`, `EXTERNAL_DEP_NO_FORK`, `LIVE_ARTIFACT_REQUIRED`,
`SPEC_DOCS_NO_STATE_DELTA`, or a `REFUTED` verdict — with a code-grounded
justification (name the trusted actor, the initializer, the external call,
the artifact, or the absent state delta). A forced attempt that genuinely
cannot assert the harm records `[CODE-TRACE]` plus the named blocker, NOT
`[POC-FAIL]` — `[POC-FAIL]` is reserved for a harm-asserting test that ran
and the harm did not reproduce.

## ANTI-HALLUCINATION RULES

1. You MUST read the actual source files BEFORE writing any test or analysis. Do NOT guess function signatures, parameter types, or return values.
2. You MUST extract real constants from the modules (decimals, fee rates, bounds, period lengths) and use those in your test. Never invent convenient values.
3. If a function signature differs from what you expected, use the ACTUAL signature from the source code.
4. When tracing code logic, verify the DIRECTION of comparisons (>=, <=, >, <). A >= in an abort condition has the opposite meaning from >= in a success condition.
5. Before claiming a struct field is 'not updated' by a function, grep for ALL writes to that field across the entire codebase. The function may update it indirectly via an internal call.
6. If you cannot compile or run a test after 5 attempts, provide a MANUAL CODE TRACE with exact line numbers and concrete state transitions. Tag as `[CODE-TRACE]` and set verdict to CONTESTED (not CONFIRMED). A code trace with real values is better than a hallucinated test, but it is NOT mechanical proof.

## REALISTIC PARAMETER VALIDATION
Substitute ACTUAL module constants (basis points, fees, thresholds, Move constants).
Apply Rule 10: Use worst realistic operational state, not current snapshot.
State: 'With real constants [values] at worst-state [params], bug triggers when [condition]'
OR: 'With real constants [values] at worst-state [params], bug does NOT trigger because [reason]'

**Aptos-specific constants to check**:
- Gas limits (max transaction gas units, storage gas costs)
- Coin/FA decimals (typically 8 for AptosCoin, variable for others)
- Table/SmartVector size limits (bounded by gas, not hard caps)
- Timestamp granularity (seconds via `timestamp::now_seconds()`, microseconds via `timestamp::now_microseconds()`)
- Max write set size per transaction (1MB)

## PROTOCOL-LEVEL CONTEXT
Consider:
- Module upgradeability: can module behavior change post-audit?
- TVL at risk: 1% of $100M = $1M
- Repeatability: once or continuous? (Aptos fast finality ~0.5-1s enables rapid repetition)
- User population: one user or all users?
- Object/resource permanence: non-deletable objects, non-extractable resources

## MOVE UNIT TEST VERIFICATION
**MANDATORY** for CONTESTED findings and any hypothesis involving complex state transitions.
**PREFERRED** for all other HIGH/CRITICAL hypotheses.

Write a Move unit test that demonstrates the vulnerability:
- Use `#[test]` and `#[expected_failure]` annotations as appropriate
- Set up test accounts via `aptos_framework::account::create_account_for_test`
- Use `timestamp::set_time_has_started_for_testing` for time-dependent tests
- Use `coin::create_fake_money` or custom test coin modules for token tests
- Evidence level: [CODE] for unit tests

### PoC Template (Standalone Hypothesis)

```move
#[test(admin = @protocol, attacker = @0xCAFE)]
fun test_hypothesis_N(admin: &signer, attacker: &signer) {
    // 1. SETUP -- deploy modules, create resources, initialize state
    //    - Call init_module() or equivalent initialization
    //    - Create test accounts with appropriate permissions
    //    - Mint/transfer tokens as needed for setup

    // 2. RECORD BEFORE -- capture state
    //    - let before_balance = coin::balance<CoinType>(addr);
    //    - let before_state = borrow_global<Resource>(addr);

    // 3. ACTION -- execute attack sequence
    //    - Perform the steps that trigger the vulnerability
    //    - Include any required precondition setup

    // 4. RECORD AFTER -- capture new state
    //    - let after_balance = coin::balance<CoinType>(addr);
    //    - let after_state = borrow_global<Resource>(addr);

    // 5. PROVE BUG -- assert demonstrates vulnerability
    //    - assert!(after_balance > before_balance, UNEXPECTED_GAIN);
    //    - assert!(condition_violated, BUG_DEMONSTRATED);
}
```

### PoC Template (Chain Hypothesis)

```move
#[test(attacker = @0xCAFE, victim = @0xBEEF, admin = @protocol)]
fun test_CH{N}_full_chain(attacker: &signer, victim: &signer, admin: &signer) {
    // === SETUP: Initialize modules, mint tokens, create accounts ===
    // === STEP 1: Enabler (Finding B) -- create the postcondition ===
    // === VERIFY POSTCONDITION -- assert precondition for Finding A is now met ===
    // === STEP 2: Blocked Finding (Finding A) -- execute previously-blocked attack ===
    // === VERIFY CHAIN IMPACT -- assert combined impact > either alone ===
}
```

### Running Tests
Use `aptos move test` via Bash to compile and run Move unit tests:
```bash
aptos move test --filter test_hypothesis_N
```

If compilation fails, document the error and attempt to fix the test.
If the module has dependencies, ensure `Move.toml` includes them.

### On-Chain State Verification
If hypothesis involves deployed on-chain state that cannot be replicated in unit tests:
- Use `aptos move view` CLI to query view functions
- Use Aptos REST API (`https://fullnode.mainnet.aptoslabs.com/v1/`) to read resources
- Document on-chain state as [PROD-ONCHAIN] evidence
- If on-chain verification is impossible (not deployed, no RPC), document why and keep verdict as CONTESTED (not FALSE_POSITIVE)

### Move Prover Verification (Optional -- when specs exist)
If the module has Move Prover spec annotations:
- Run `aptos move prove` to check formal properties
- Prover violations are strong evidence for CONFIRMED verdict
- Prover success for a relevant property is strong evidence for FALSE_POSITIVE

### Evidence Levels
- [CODE] -- Move unit test demonstrates vulnerability
- [PROD-ONCHAIN] -- Aptos REST API / CLI confirms on-chain state
- [MOCK] -- Unit tests with mocked external behavior (lower confidence)

For CONTESTED findings involving external module behavior:
- If local Aptos testnet is available: test against it for [PROD-FORK] evidence level
- If no local testnet: unit tests with mocked external behavior provide [CODE] evidence
- If test demonstrates the vulnerability: CONFIRMED with [CODE] evidence
- If test shows defense holds: document WHY, keep as CONTESTED (not FALSE_POSITIVE) unless defense is conclusive

**When fork testing is impossible** (no Anvil equivalent for Aptos, no deployed contracts):
- Document why on-chain verification cannot be performed
- Keep verdict as CONTESTED (not FALSE_POSITIVE)
- Unit tests still provide valuable [CODE] evidence

## NEW OBSERVATIONS (MANDATORY)
If during verification you discover a NEW bug, configuration dependency, or edge case
NOT covered by any existing hypothesis -- document it under:

### New Observations
- [VER-NEW-1]: {title} -- {location} -- {brief description}

These will be reviewed by the orchestrator for possible inclusion as new findings.

## ERROR TRACE OUTPUT
When verdict is CONTESTED or FALSE_POSITIVE, document the failure details for potential re-investigation:

### Error Trace
- **Failure Type**: ABORT / ASSERT_FAIL / UNEXPECTED_STATE / INSUFFICIENT_EVIDENCE
- **Location**: {module}::{function}::{line or abort code where failure occurs}
- **Abort Code**: {numeric abort code or assert! message, if any}
- **State at Failure**: {key resource fields and their values when the test failed}
- **Investigation Question**: {What specific question would need to be answered to resolve this -- e.g., 'Does external module X return Y under condition Z?' or 'What is the actual abort code when amount exceeds balance?'}

These error traces feed into the post-verification depth pass (AD-6) if budget remains.

## INDEPENDENT SEVERITY ASSESSMENT (MANDATORY — M4 anti-inflation)

Before reconciling with any pre-assigned/claimed severity (from the hypothesis, queue, or inventory), assess a severity INDEPENDENTLY:

1. Read ONLY the code and your own evidence (PoC result, code trace, dual-perspective verdict from above). Deliberately IGNORE the claimed/pre-assigned severity for this step - do not let it anchor your judgment.
2. Apply the standard severity matrix (Impact x Likelihood) from `~/.claude/rules/report-template.md` to what YOU found, as if no severity had been pre-assigned.
3. Record the result in your output BEFORE finalizing your Severity field:

```
**Independent Severity**: <Critical|High|Medium|Low|Informational|N/A>
```

- Assessed from the code and evidence ALONE; ignore any pre-assigned severity.
- Use `N/A` ONLY when your verdict is REFUTED/FALSE_POSITIVE (no independent severity applies to a non-finding).
- This field is MANDATORY for every non-REFUTED verdict. The driver reads it to mechanically compute `final = min(Independent Severity, claimed severity)` - this can ONLY LOWER the reported severity, it NEVER raises it and NEVER drops the finding. A missing or unparseable field is recall-safe: it simply falls back to the claimed severity (no cap applied).

Do NOT skip this field to save time, and do NOT default it to the claimed severity - that defeats its purpose of catching an inflated pre-assigned severity.

## FIX GENERATION (POC-PASS only)
If your PoC PASSES (verdict = CONFIRMED with [POC-PASS]):
1. Write a minimal diff-style fix (smallest change that eliminates the bug)
2. If time permits, re-run the PoC with the fix applied to verify it no longer triggers
3. Include in your output under `### Suggested Fix` per phase5-poc-execution.md
4. If the fix is non-trivial (architectural, multi-file): write a 1-sentence description instead of a diff

Do NOT generate fixes for [CODE-TRACE] or [POC-FAIL] findings.

Write FULL PoC to {SCRATCHPAD}/verify_{hypothesis_id}.md
Include the mandatory `### Execution Result` and `### Fuzz Result` (Medium+) sections per phase5-poc-execution.md.

Return: CONFIRMED/FALSE_POSITIVE/CONTESTED + evidence tag + 3-sentence justification
")
```

**Escalation**: If 3+ agents flagged root cause AND verifier says FALSE_POSITIVE -> override to CONTESTED.

---

## Independent Skeptic Challenge Boundary (Thorough mode)

> **Ownership:** This ecosystem verification prompt ends with the standard verifier. It MUST NOT spawn skeptic or judge workers, apply a skeptic proposal, or change report severity or disposition.
> **Triggering:** After standard verification, the driver constructs an independent semantic trigger manifest across all severities. Severity alone is neither an eligibility rule nor an exclusion rule.
> **Execution:** The shared driver-owned skeptic methodology receives that manifest and the applicable ecosystem anti-hallucination constraints. Its artifact is proposal-only and has no report authority. A distinct typed adjudicator receives each challenge requiring disposition; skeptic and adjudicator MUST NOT be the same worker or session.
> **Completeness:** A hash-bound receipt MUST account for every exact manifest finding ID once. Missing, duplicate, unknown, stale, or constituent-substituted IDs make the phase incomplete and require retry or explicit human-review degradation; they are never silently skipped.
> **Authority:** Only a validated, report-authoritative typed severity/disposition ledger can change upstream severity or disposition. Legacy `skeptic_*.md` and `judge_*.md` files are diagnostic or proposal artifacts only.
> **Recall floor:** `UNRESOLVED` and `PARTIAL` preserve the highest supported upstream tier and remain visible in the report body. They create explicit review work, never an automatic demotion or exclusion.

Execution details belong to the shared driver-owned skeptic and typed-adjudication contracts; do not copy them into an ecosystem verifier prompt.

---

## Cross-Batch Consistency Check (Phase 5.2)

> **Purpose**: When one verification batch marks a mechanism as FALSE_POSITIVE, other batches may still contain findings that depend on the same invalidated mechanism. Parallel batches cannot detect this — a post-batch reconciliation step is needed.
> **Trigger**: Always, after ALL verification batches complete (Phase 5 + 5.1). Runs before Phase 5.5 (finding extraction).
> **Model**: haiku (mechanical cross-reference)
> **Budget**: 1 agent (not counted against verification budget)

### Orchestrator spawns:

```
Task(subagent_type="general-purpose", model="haiku", prompt="
You are the Cross-Batch Consistency Agent.

## Your Task
Read ALL verification batch files: {SCRATCHPAD}/verify_batch_*.md

### STEP 1: Extract FALSE_POSITIVE mechanisms
For each FALSE_POSITIVE verdict, extract:
| Finding ID | Invalidated Mechanism | Reason | Batch Source |

### STEP 2: Cross-reference surviving findings
For each invalidated mechanism, search ALL other batch files for findings whose
attack path, precondition, or root cause depends on the same mechanism.

A finding DEPENDS on the mechanism if:
- It references the same function/code path that was proven non-exploitable
- Its attack requires the behavior the FALSE_POSITIVE disproved
- It is a chain hypothesis whose constituent was the FALSE_POSITIVE

### STEP 3: Flag contradictions
| Surviving Finding | Batch | Depends On | FALSE_POSITIVE ID | Contradiction |

### STEP 4: Recommend
For each contradiction:
- If the surviving finding's ENTIRE attack path depends on the disproved mechanism → recommend FALSE_POSITIVE
- If only part of the attack path is affected → recommend DOWNGRADE with explanation
- If the dependency is unclear → recommend REVIEW

Write to {SCRATCHPAD}/cross_batch_consistency.md
Return: 'DONE: {N} FALSE_POSITIVES checked, {C} contradictions found, {R} recommendations'
")
```

### Orchestrator action after agent returns:
- If contradictions found: apply recommendations (FALSE_POSITIVE or DOWNGRADE) before Phase 5.5
- If no contradictions: proceed to Phase 5.5
- Log results in {SCRATCHPAD}/verification_consistency.md
