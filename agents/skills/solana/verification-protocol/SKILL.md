---
name: "verification-protocol"
description: "Trigger Pattern Always (used by all verifier agents) - Inject Into security-verifier agents (Phase 5)"
---

# VERIFICATION_PROTOCOL Skill (Solana)

> **Trigger Pattern**: Always (used by all verifier agents)
> **Inject Into**: security-verifier agents (Phase 5)
> **Purpose**: Prove hypotheses TRUE or FALSE using LiteSVM tests with Rust PoC code.

---

## Evidence Source Tracking (MANDATORY)

> **CRITICAL**: For EVERY piece of evidence used in verification, you MUST tag its source.
> Evidence from mocks or unverified external programs CANNOT support a REFUTED verdict.

### Evidence Source Tags

| Tag | Meaning | Valid for REFUTED? |
|-----|---------|-------------------|
| [PROD-ONCHAIN] | Production Solana account data (via `solana account` or RPC) | YES |
| [PROD-SOURCE] | Verified source from Solana Explorer / anchor-verified | YES |
| [PROD-LITESVM] | Tested on LiteSVM with mainnet account dumps | YES |
| [CODE] | Audited codebase (in-scope source) | YES |
| [MOCK] | Mock/test accounts or programs | **NO** |
| [EXT-UNV] | External, unverified program behavior | **NO** |
| [DOC] | Documentation/spec only | **NO** (needs verification) |

### Evidence Audit Table (REQUIRED in every verification output)

Before ANY verdict, fill this table:

```markdown
### Evidence Audit
| Claim | Evidence Source | Tag | Valid for REFUTED? |
|-------|-----------------|-----|-------------------|
| "CPI returns X" | Mock program | [MOCK] | NO |
| "PDA seeds match" | lib.rs:123 | [CODE] | YES |
| "Account layout is Y" | Solana Explorer verified | [PROD-SOURCE] | YES |
```

### Mock Rejection Rule

**AUTOMATIC OVERRIDE**: If ANY evidence supporting REFUTED has tag [MOCK] or [EXT-UNV]:
- CANNOT return REFUTED
- MUST return CONTESTED
- Triggers production verification

---

## Pre-Verification Understanding

Before writing ANY test code, you MUST answer:

### Question 1: What is the EXACT bug?
```
NOT: "Account validation is missing"
NOT: "State is inconsistent"

YES: "Instruction [X] accepts account [Y] without checking owner/type/seeds,
      allowing an attacker to substitute a crafted account with arbitrary data
      at field [Z] (file:line)"
```

### Question 2: What OBSERVABLE difference proves it?
```
NOT: "Accounts are different"
NOT: "Wrong state"

YES: "Before exploit: user_balance = 1000 tokens
      After exploit: user_balance = 0, attacker_balance = 1000
      Expected: transaction should have reverted with AccountConstraint error"
```

### Question 3: What is the EXACT assertion?
```
NOT: assert!(exploit_worked)

YES: assert_eq!(attacker_token_balance, expected_stolen_amount)
 OR: assert!(result.is_err(), "should have reverted but succeeded")
 OR: assert_ne!(state_before, state_after, "state changed when it should not")
```

**If you cannot answer all three -> ASK FOR CLARIFICATION**

---

## Pre-PoC Feasibility Gates (MANDATORY)

Before writing test code, verify these two gates. If either FAILS, adjust the hypothesis.

### Gate F1: Reachability
Trace a call path from a permissionless entry point to the vulnerable code.

- [ ] Entry point identified (public/external/entry function)
- [ ] Call path traced through intermediary functions
- [ ] All access checks on the path are passable by the attacker profile

If NO entry point reaches the vulnerable code → UNREACHABLE → FALSE_POSITIVE.
If reachable only through a restricted path → document the restriction, adjust likelihood.

### Gate F2: Math Bounds
Substitute real-world value domains into the expression that triggers the bug.

- [ ] Parameter domains identified (token decimals, max supply, TVL range, fee range, time bounds)
- [ ] Expression evaluated at worst-case feasible inputs
- [ ] Result crosses the bug threshold

If the bug requires values outside feasible domains → INFEASIBLE → FALSE_POSITIVE.
If feasible only at extreme but realistic parameters → document the threshold, proceed with adjusted severity.

**Both gates PASS → proceed to PoC. Either gate FAILS → document and stop.**

---


## LiteSVM Test Templates

> **See [`templates.md`](references/templates.md)** in this directory for all LiteSVM test templates (Templates 1-5), Trident fuzz test setup (Template 6), and Fork Testing Equivalent (production account loading).

## Dual-Perspective Verification (MANDATORY)

### Phase 1 - ATTACKER: Assume you ARE the attacker.
- What is the complete attack instruction sequence?
- What accounts do you need to create/craft?
- What is the profit/damage with real token amounts?
- Can you compose multiple instructions in one transaction for atomicity?
- Why would this succeed? (Which validation is missing/wrong?)

### Phase 2 - DEFENDER: Assume you are the protocol team.
- What account constraint prevents this?
- What PDA seeds ensure correct derivation?
- What CPI program ID check blocks substitution?
- Why is this safe by design?

### Phase 3 - VERDICT: Which argument won?

---

## Realistic Parameter Validation

Substitute ACTUAL program constants (basis points, fee rates, thresholds, account sizes).
Apply Rule 10: Use worst realistic operational state, not current snapshot.

```
State: 'With real constants [fee_bps=X, max_leverage=Y, tvl=Z] at worst-state
[max_users, max_positions], bug triggers when [condition]'
OR: 'With real constants, bug does NOT trigger because [reason]'
```

---

## Anti-Downgrade Guard (MANDATORY for VS/BLIND findings)

When verifying a finding from Validation Sweep ([VS-*]) or Blind Spot Scanner ([BLIND-*]), you MUST apply Rule 13's 5-question test BEFORE downgrading severity or marking FALSE_POSITIVE:

1. **Who is harmed** by this design gap?
2. **Can affected users avoid** the harm?
3. **Is the gap documented** in protocol docs?
4. **Could the protocol achieve the same goal** without this gap?
5. **Does the instruction fulfill its stated purpose completely?**

**HARD RULE**: If the finding shows Program A has protection X but Program B lacks it for the same user action -> defense parity gap, NOT "by design". Minimum severity: Medium.

---

## New Observations (MANDATORY)

If during verification you discover a NEW bug, account validation gap, or edge case NOT covered by any existing hypothesis, document it under:

### New Observations
- [VER-NEW-1]: {title} -- {program:instruction} -- {brief description}

These will be reviewed by the orchestrator for possible inclusion as new findings.

---

## Error Trace Output (MANDATORY for CONTESTED/FALSE_POSITIVE)

When verdict is CONTESTED or FALSE_POSITIVE, document the failure details:

### Error Trace
- **Failure Type**: ACCOUNT_CONSTRAINT / CPI_ERROR / ARITHMETIC_OVERFLOW / INSUFFICIENT_FUNDS / UNEXPECTED_STATE
- **Location**: {program}:{instruction}:{approximate line in handler}
- **Error Code**: {Anchor error code or custom error, if any}
- **State at Failure**: {key account fields and their values when test failed}
- **Investigation Question**: {What would need to be answered to resolve this}

---

## RAG Queries Before PoC (MANDATORY for HIGH/CRITICAL)

Before writing PoC tests for HIGH/CRITICAL findings:

### Step 1: Get Attack Vectors
```
mcp__unified-vuln-db__get_attack_vectors(bug_class="{category}")
```

### Step 2: Get Similar Findings
```
mcp__unified-vuln-db__get_similar_findings(pattern="{vulnerability description}")
```

### Step 3: Validate Hypothesis
```
mcp__unified-vuln-db__validate_hypothesis(hypothesis="{finding summary}")
```

### Step 4: Live Search for Solana-Specific Precedents
```
mcp__unified-vuln-db__search_solodit_live(
  keywords="{solana vulnerability pattern}",
  impact=["HIGH", "CRITICAL"],
  tags=["Access Control", "Logic Error"],
  language="Rust",
  quality_score=3,
  max_results=15
)
```

Document RAG evidence in output:
```markdown
### RAG Evidence
- **Attack Vectors Consulted**: [list bug classes queried]
- **Similar Exploits Found**: [count and brief descriptions]
- **Historical Precedent**: [matching Solana-specific vulnerabilities]
```

---

## RAG Confidence Override

| RAG Confidence | Local Verdict | Final Verdict | Action |
|----------------|---------------|---------------|--------|
| >= 7/8 matches | FALSE_POSITIVE | **CONTESTED** (override) | Cannot dismiss -- strong precedent |
| >= 6/8 matches | FALSE_POSITIVE | **CONTESTED** (override) | Cannot dismiss -- significant precedent |
| < 6/8 matches | FALSE_POSITIVE | FALSE_POSITIVE | Allowed -- limited precedent |

---

## Chain Hypothesis PoC Requirements

Chain hypotheses receive PRIORITY verification. Multi-step exploits must test the COMPLETE sequence:

```rust
#[test]
fn test_chain_hypothesis_full() {
    let mut svm = LiteSVM::new();
    // ... setup ...

    // ========================================
    // STEP 1: ENABLER (Finding B)
    // Execute action that creates the postcondition
    // ========================================
    let enabler_ix = Instruction::new_with_borsh(/* ... */);
    let tx1 = Transaction::new_signed_with_payer(
        &[enabler_ix],
        Some(&attacker.pubkey()),
        &[&attacker],
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx1).unwrap();

    // ========================================
    // VERIFY POSTCONDITION CREATED
    // Assert precondition for Finding A is now met
    // ========================================
    let postcondition_account = svm.get_account(&postcondition_pubkey);
    // assert postcondition state is as expected

    // ========================================
    // STEP 2: BLOCKED FINDING (Finding A)
    // Execute previously-blocked attack using postcondition
    // ========================================
    let exploit_ix = Instruction::new_with_borsh(/* ... */);
    let tx2 = Transaction::new_signed_with_payer(
        &[exploit_ix],
        Some(&attacker.pubkey()),
        &[&attacker],
        svm.latest_blockhash(),
    );
    let result = svm.send_transaction(tx2);

    // ========================================
    // VERIFY CHAIN IMPACT
    // Combined impact should exceed either finding alone
    // ========================================
    assert!(result.is_ok(), "Chain exploit should succeed");
    let profit = /* calculate attacker profit */;
    assert!(profit > 0, "Chain attack should be profitable");
}
```

### Bidirectional Chain Analysis (Rule 6 Extension)
For chains involving semi-trusted roles (operator/keeper/crank):
Verify BOTH directions: (1) role executes chain to harm users, AND (2) users exploit role timing to trigger chain.
If only one direction analyzed -> verdict CANNOT be FALSE_POSITIVE. Return CONTESTED.

---

## Interpreting Results

### Test PASSES -> Bug CONFIRMED
The assertion that "proves the bug" succeeded.

### Test FAILS -> Check Why

| Failure | Meaning | Action |
|---------|---------|--------|
| Account constraint error | Validation IS present | Re-examine hypothesis |
| Program error / custom error | Instruction logic rejects | Check if rejection is the bug or the fix |
| Insufficient funds | Setup amounts wrong | Fix test setup |
| Transaction too large | Too many accounts/instructions | Split transaction or reduce scope |
| Blockhash expired | LiteSVM state issue | Get fresh blockhash |

---

## Iteration Protocol

**Attempt 1:** Direct implementation of test strategy from hypothesis.
**Attempt 2:** Adjust parameters (different amounts, different account states, different instruction ordering).
**Attempt 3:** Re-examine assumptions (are account constraints correctly modeled? Are PDA seeds correct? Is instruction data serialization correct?).
**After 5 attempts:** If still fails -> FALSE_POSITIVE with documented reasoning.

---

## Severity Determination

### CRITICAL
- Direct fund theft (token drain, SOL extraction)
- Program upgrade to malicious code (if upgrade authority compromised and no timelock)
- Arbitrary CPI execution
- No special prerequisites needed

### HIGH
- Fund loss with specific setup (account pre-creation, timing)
- Broken core instruction (deposits, withdrawals, liquidations)
- Freeze authority abuse
- Significant TVL at risk

### MEDIUM
- Limited fund loss under specific conditions
- Account state corruption (non-fund data)
- Edge cases with real impact at design limits
- Moderate value at risk

### LOW
- Negligible direct impact
- Extreme edge cases only
- Authority-controlled risk (with multisig + timelock)
- View function / off-chain data issues

---

## Output Format

### CONFIRMED
```markdown
## Verdict: CONFIRMED

### Bug Mechanism Verified
{Explain what the LiteSVM test proves in 2-3 sentences}

### Test Code
{Full Rust test function}

### Test Output
{Relevant assertions and logged values}

### Key Evidence
| Metric | Value |
|--------|-------|
| Before | {value} |
| After | {value} |
| Expected | {value} |
| Difference | {calculation} |

### Evidence Audit
| Claim | Evidence Source | Tag | Valid for REFUTED? |
|-------|-----------------|-----|-------------------|

### Severity: {LEVEL}
{Justification in 1-2 sentences}
```

### FALSE_POSITIVE
```markdown
## Verdict: FALSE_POSITIVE

### Attempts Made
**Attempt 1:**
- Approach: {description}
- Result: {what happened -- include error codes}
- Learning: {insight}

**Attempt 2:**
- Approach: {description}
- Result: {what happened}
- Learning: {insight}

**Attempt 3:**
- Approach: {description}
- Result: {what happened}
- Learning: {insight}

### Evidence Audit
| Claim | Evidence Source | Tag | Valid for REFUTED? |

### Why It Is Not a Bug
{Explain the actual behavior and why hypothesis was wrong in 2-3 sentences}

### Error Trace
- **Failure Type**: {type}
- **Location**: {location}
- **Error Code**: {code}
- **State at Failure**: {state}
- **Investigation Question**: {question}
```

### CONTESTED
```markdown
## Verdict: CONTESTED

### Evidence Status
| Checkpoint | Status | Details |
|------------|--------|---------|
| External program behavior verified against PRODUCTION | YES/NO | {details} |
| All callers/instruction paths checked | YES/NO | {details} |
| Account validation completeness confirmed | YES/NO | {details} |

### Evidence Audit
| Claim | Evidence Source | Tag | Valid for REFUTED? |

### Why This Cannot Be REFUTED
{Explain what evidence is missing to definitively rule out the bug}

### Escalation Required
- [ ] Fetch production program source for {external dep}
- [ ] Dump production account state for {account}
- [ ] Check additional instruction paths: {list}

### Error Trace
{as above}
```

---

## Insufficient Evidence (HALT CONDITIONS)

Before marking REFUTED, check ALL boxes:
- [ ] External program behavior verified against PRODUCTION (not mock)
- [ ] Attack path checked on ALL instruction handlers that access the same accounts
- [ ] Profit calculated with attacker HOLDING tokens (not just sending)
- [ ] Missing precondition documented (type: STATE / ACCESS / TIMING / EXTERNAL / BALANCE)
- [ ] Searched other findings for matching postconditions (chain analysis integration)
- [ ] PDA derivation verified with correct seeds (not assumed)
- [ ] Account owner checks verified in source (not assumed from Anchor derive)

### Evidence That Does NOT Count
- "Mock program shows X" -- mocks are not production
- "Standard SPL Token" -- may have Token-2022 extensions (transfer hooks, fees)
- "Attacker loses by sending tokens" -- may profit via position held
- "Instruction is internal (pub(crate))" -- may be reachable via CPI
- "Requires authority" -- authority may be compromised or EOA
- "Attacker cannot acquire X" -- another finding may CREATE this condition
