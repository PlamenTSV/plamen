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

## MANDATORY PoC EXECUTION (v9.9.5)

Follow `phase5-poc-execution.md`. Compile and run every PoC - a written test with no execution output is not evidence.

**Aptos commands**: `aptos move compile` (compile), `aptos move test --filter test_{hypothesis_id}` (run). For fuzz variants: Move has no built-in fuzzer - write boundary-value parameterized tests with 3+ concrete value sets (min/mid/max). See `phase5-poc-execution.md` for template.

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

Write FULL PoC to {SCRATCHPAD}/verify_{hypothesis_id}.md
Include the mandatory `### Execution Result` and `### Fuzz Result` (Medium+) sections per phase5-poc-execution.md.

Return: CONFIRMED/FALSE_POSITIVE/CONTESTED + evidence tag + 3-sentence justification
")
```

**Escalation**: If 3+ agents flagged root cause AND verifier says FALSE_POSITIVE -> override to CONTESTED.

---

## Skeptic-Judge Verification (Thorough mode only, HIGH/CRIT)

> **Purpose**: Challenge the standard verifier's reasoning. Nobody audits the auditor - this step does.
> **Trigger**: Thorough mode, findings with severity HIGH or CRITICAL, after standard Phase 5 verification completes.
> **Architecture**: Standard verifier → Skeptic agent (sonnet) → Judge agent (haiku, only if disagreement)

### Step 1: Spawn Skeptic Agent (per finding)

For each HIGH/CRIT finding after standard verification:

```
Task(subagent_type="security-verifier", model="sonnet", prompt="
You are the SKEPTIC VERIFIER. Your job is to challenge the standard verifier's conclusion.

## INVERSION MANDATE
The standard verifier concluded: {STANDARD_VERDICT} for hypothesis {HYPOTHESIS_ID}.
Your job is to argue the OPPOSITE:
- If standard said CONFIRMED → you MUST try to REFUTE. Find why this attack CANNOT work.
- If standard said FALSE_POSITIVE → you MUST try to CONFIRM. Find why this attack CAN work.
- If standard said CONTESTED → you MUST try to reach a definitive verdict (either direction).

## Your Inputs
Read:
- {SCRATCHPAD}/verify_{hypothesis_id}.md (standard verifier's full analysis)
- The source files at {LOCATION}
- {SCRATCHPAD}/design_context.md
- ~/.claude/rules/phase5-poc-execution.md

## HARD RULES
1. You MUST make your OWN tool calls. Do NOT rely on the standard verifier's code traces.
2. You MUST read the source code yourself. Do NOT trust the standard verifier's code quotes.
3. You MUST try to write and execute a PoC that proves the OPPOSITE of the standard verdict.
4. If the standard verifier's PoC passed, try to show why it doesn't prove what it claims (wrong setup, unrealistic parameters, missing preconditions).
5. If the standard verifier's PoC failed, try to show a variant that succeeds (different parameters, different entry point, different timing).

## Output
Write to {SCRATCHPAD}/skeptic_{hypothesis_id}.md:

### Skeptic Verdict
- **Standard Verdict**: {STANDARD_VERDICT}
- **Skeptic Verdict**: {CONFIRMED/FALSE_POSITIVE/CONTESTED}
- **Agreement**: {AGREE/DISAGREE}
- **Evidence Tag**: {[POC-PASS]/[POC-FAIL]/[CODE-TRACE]}
- **Reasoning**: {3-5 sentences explaining your position}

If DISAGREE: include your counter-PoC or counter-trace.

Return: '{AGREE/DISAGREE}: skeptic says {verdict} vs standard {STANDARD_VERDICT} - {1-line reason}'
")
```

### Step 2: Evaluate Agreement

After skeptic agent returns:
- If **AGREE** → final verdict = standard verdict (high confidence, both perspectives aligned)
- If **DISAGREE** → spawn Judge Agent (Step 3)

### Step 3: Spawn Judge Agent (only on disagreement)

```
Task(subagent_type="general-purpose", model="haiku", prompt="
You are the JUDGE. Two verifiers disagree on hypothesis {HYPOTHESIS_ID}. Your job is to determine which argument has STRONGER mechanical evidence.

## Prove It or Lose It
Read BOTH verification files:
- {SCRATCHPAD}/verify_{hypothesis_id}.md (standard verifier)
- {SCRATCHPAD}/skeptic_{hypothesis_id}.md (skeptic verifier)

## Decision Criteria (STRICTLY mechanical)
1. `[POC-PASS]` beats `[CODE-TRACE]` - always. Executed test > manual reasoning.
2. `[POC-PASS]` beats `[POC-FAIL]` - the test that passes wins.
3. If both have `[POC-PASS]` (conflicting tests) → verdict = CONTESTED
4. If both have `[CODE-TRACE]` only → whichever traces MORE concrete values with SPECIFIC line numbers wins. If roughly equal depth → CONTESTED.
5. If one has `[MEDUSA-PASS]` → that side wins (fuzzer counterexample is mechanical proof).

## Output
Write to {SCRATCHPAD}/judge_{hypothesis_id}.md:

### Judge Ruling
- **Standard Verdict**: {verdict} with {evidence_tag}
- **Skeptic Verdict**: {verdict} with {evidence_tag}
- **Ruling**: {STANDARD_WINS/SKEPTIC_WINS/CONTESTED}
- **Final Verdict**: {CONFIRMED/FALSE_POSITIVE/CONTESTED}
- **Reasoning**: {2-3 sentences - which evidence was mechanically stronger}

Return: 'RULING: {final_verdict} - {STANDARD_WINS/SKEPTIC_WINS/CONTESTED}'
")
```

### Step 4: Apply Final Verdict

| Outcome | Final Verdict | Confidence |
|---------|--------------|------------|
| Skeptic AGREES | Standard verdict | HIGH (dual-confirmed) |
| Judge: STANDARD_WINS | Standard verdict | MEDIUM-HIGH |
| Judge: SKEPTIC_WINS | Skeptic verdict | MEDIUM-HIGH (override) |
| Judge: CONTESTED | CONTESTED | LOW (genuine ambiguity) |

### Budget Impact

| Component | Cost |
|-----------|------|
| Skeptic agents | 1 sonnet per HIGH/CRIT finding (~3-8 agents typical) |
| Judge agents | 1 haiku per disagreement (~0-3 agents typical) |
| **Total** | ~3-11 agents (only in Thorough mode) |
