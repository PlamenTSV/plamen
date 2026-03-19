# Phase 5: Verification Prompt Template - Sui/Move

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
- ~/.claude/agents/skills/sui/verification-protocol/SKILL.md
- ~/.claude/rules/phase5-poc-execution.md

## PRECISION MODE
You are in PRECISION mode. Your job is to VALIDATE or REFUTE hypotheses with maximum rigor. Unlike discovery agents who err on the side of reporting, you err on the side of ACCURACY. Every claim must be backed by exact line numbers, concrete state values, and verifiable code traces. If you cannot prove exploitation with specific values, say so clearly. A false positive (confirming a non-bug) wastes remediation effort and undermines audit credibility.

## DUAL-PERSPECTIVE VERIFICATION (MANDATORY)

Phase 1 - ATTACKER: Assume you ARE the attacker.
- What's your complete attack sequence?
- What's the profit/damage with real numbers?
- Why would this succeed?
- Can this be composed into a single PTB (Programmable Transaction Block)?

Phase 2 - DEFENDER: Assume you're the protocol team.
- What mechanism prevents this?
- What assumption is wrong?
- Does object ownership / `key`+`store` restriction block this?
- Does the Sui runtime enforce safety here (e.g., borrow checker, linear types)?
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
protocol team intended the defense - its absence elsewhere is a bug, not a feature.

You may NOT dismiss a defense parity gap as 'Informational' or 'design note'.

## CLASS-CHECK BEFORE FALSE_POSITIVE

Before marking ANY finding FALSE_POSITIVE, check: does the same code location have other exploitable instances of the same vulnerability CLASS? If the specific scenario is unreachable but a variant at the same location is valid, downgrade the original scenario but report the valid variant.

## MANDATORY PoC EXECUTION (v9.9.5)

Follow `phase5-poc-execution.md`. Compile and run every PoC - a written test with no execution output is not evidence.

**Sui commands**: `sui move build` (compile), `sui move test --filter test_{hypothesis_id}` (run). For fuzz variants: Move has no built-in fuzzer - write boundary-value parameterized tests with 3+ concrete value sets (min/mid/max). See `phase5-poc-execution.md` for template.

## ANTI-HALLUCINATION RULES

1. You MUST read the actual source files BEFORE writing any test or analysis. Do NOT guess function signatures, parameter types, or return values.
2. You MUST extract real constants from the modules (decimals, fee rates, bounds, period lengths) and use those in your test. Never invent convenient values.
3. If a function signature differs from what you expected, use the ACTUAL signature from the source code.
4. When tracing code logic, verify the DIRECTION of comparisons (>=, <=, >, <). A >= in an abort condition has the opposite meaning from >= in a success condition.
5. Before claiming a struct field is 'not updated' by a function, grep for ALL writes to that field across the entire codebase. The function may update it indirectly via an internal call.
6. If you cannot compile or run a test after 5 attempts, provide a MANUAL CODE TRACE with exact line numbers and concrete state transitions. Tag as `[CODE-TRACE]` and set verdict to CONTESTED (not CONFIRMED). A code trace with real values is better than a hallucinated test, but it is NOT mechanical proof.

## REALISTIC PARAMETER VALIDATION
Substitute ACTUAL module constants (basis points, fees, thresholds, capability guards).
Apply Rule 10: Use worst realistic operational state, not current snapshot.
- **Gas budget**: Maximum 50 SUI per transaction on Sui mainnet
- **Epoch duration**: ~24 hours (86,400 seconds) on Sui mainnet
- **PTB limits**: Max 1024 commands, ~128KB serialized size, ~2048 objects per transaction
- **Checkpoint finality**: ~480ms on Sui mainnet
State: 'With real constants [values] at worst-state [params], bug triggers when [condition]'
OR: 'With real constants [values] at worst-state [params], bug does NOT trigger because [reason]'

## PROTOCOL-LEVEL CONTEXT
Consider:
- Shared object contention: does this affect ALL concurrent users?
- TVL at risk: 1% of $100M = $1M
- Repeatability: once or continuous?
- User population: one user or all users?
- PTB composability: can attacker chain multiple module calls in one transaction?

## SUI TEST FRAMEWORK

Use `sui move test` with `test_scenario` for state simulation. There is NO fork testing
on Sui - all verification uses Move unit tests with `test_scenario`.

**MANDATORY** for CONTESTED findings and any hypothesis involving cross-module interactions.
**PREFERRED** for all other HIGH/CRITICAL hypotheses.

### PoC Template

```move
#[test]
fun test_hypothesis_N() {
    use sui::test_scenario;
    let admin = @0xAD;
    let attacker = @0xAA;
    let mut scenario = test_scenario::begin(admin);

    // 1. SETUP - publish packages, create shared objects
    test_scenario::next_tx(&mut scenario, admin);
    {
        // Initialize protocol state
        // Create and share objects: transfer::public_share_object(obj)
    };

    // 2. PRECONDITION - establish any required state
    test_scenario::next_tx(&mut scenario, admin);
    {
        // Configure protocol parameters
        // For shared objects: let mut obj = test_scenario::take_shared<T>(&scenario);
        // ... modify state ...
        // test_scenario::return_shared(obj);
    };

    // 3. ATTACK - execute exploit via PTB-like sequence
    test_scenario::next_tx(&mut scenario, attacker);
    {
        // Execute exploit steps
        // For shared objects: let mut obj = test_scenario::take_shared<T>(&scenario);
        // ... exploit ...
        // test_scenario::return_shared(obj);
    };

    // 4. VERIFY - assert impact
    test_scenario::next_tx(&mut scenario, attacker);
    {
        // Assert vulnerability demonstrated
        // Check balances, state changes, ownership transfers
        // let obj = test_scenario::take_shared<T>(&scenario);
        // assert!(compromised_condition, ERROR_CODE);
        // test_scenario::return_shared(obj);
    };

    // 5. CLEANUP
    test_scenario::end(scenario);
}
```

### Shared Object Testing Pattern
For hypotheses involving shared objects:
- Use `test_scenario::take_shared<T>(&scenario)` to access shared objects
- Use `test_scenario::return_shared(obj)` to return them
- Each `next_tx` simulates a new transaction - use this to model PTB boundaries
- To simulate concurrent access patterns, alternate senders between `next_tx` calls

### Object Ownership Testing Pattern
For hypotheses involving ownership transfers or wrapping:
- Use `test_scenario::take_from_sender<T>(&scenario)` for owned objects
- Use `test_scenario::return_to_sender(&scenario, obj)` to return them
- Verify objects cannot be extracted from wrappers without proper authorization

### Capability Testing Pattern
For hypotheses involving capability abuse:
- Create capabilities in setup, transfer to appropriate parties
- Verify capability checks are enforced: attempt operations without capability
- Test capability lifecycle: creation, delegation, revocation

If PoC construction is impossible (module not compilable, missing dependencies),
document why and keep verdict as CONTESTED (not FALSE_POSITIVE).

## NEW OBSERVATIONS (MANDATORY)
If during verification you discover a NEW bug, configuration dependency, or edge case
NOT covered by any existing hypothesis - document it under:

### New Observations
- [VER-NEW-1]: {title} - {location} - {brief description}

These will be reviewed by the orchestrator for possible inclusion as new findings.

## ERROR TRACE OUTPUT
When verdict is CONTESTED or FALSE_POSITIVE, document the failure details for potential re-investigation:

### Error Trace
- **Failure Type**: ABORT / ASSERTION_FAIL / UNEXPECTED_STATE / INSUFFICIENT_EVIDENCE / TYPE_ERROR / BORROW_ERROR
- **Location**: {module}::{function}:{line where failure occurs}
- **Abort Code**: {abort code or custom error, if any}
- **State at Failure**: {key object fields and their values when the test failed}
- **Investigation Question**: {What specific question would need to be answered to resolve this - e.g., 'Does module X enforce capability check Y under condition Z?'}

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
