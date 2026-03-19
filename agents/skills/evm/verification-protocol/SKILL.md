---
name: "verification-protocol"
description: "How to prove a hypothesis is TRUE or FALSE using Foundry tests."
---

# Verification Protocol

> How to prove a hypothesis is TRUE or FALSE using Foundry tests.

---

## Evidence Source Tracking (MANDATORY)

> **CRITICAL**: For EVERY piece of evidence used in verification, you MUST tag its source. Evidence from mocks or unverified external contracts CANNOT support a REFUTED verdict.

### Evidence Source Tags

| Tag | Meaning | Valid for REFUTED? |
|-----|---------|-------------------|
| [PROD] | Production contract (verified on-chain) | YES |
| [MOCK] | Mock/test contract | **NO** |
| [CODE] | Audited codebase (in-scope) | YES |
| [EXT-UNV] | External, unverified behavior | **NO** |
| [DOC] | Documentation/spec only | NO (needs verification) |

### Evidence Audit Table (REQUIRED in every verification output)

Before ANY verdict, fill this table:

```markdown
### Evidence Audit
| Claim | Evidence Source | Tag | Valid for REFUTED? |
|-------|-----------------|-----|-------------------|
| "External returns X" | Mock contract | [MOCK] | NO |
| "State changes to Y" | Protocol.sol:123 | [CODE] | YES |
| "Transfer triggers Z" | Etherscan source | [PROD] | YES |
```

### Mock Rejection Rule

**AUTOMATIC OVERRIDE**: If ANY evidence supporting REFUTED has tag [MOCK] or [EXT-UNV]:
- CANNOT return REFUTED
- MUST return CONTESTED
- Triggers production verification (Step 4a.5)

**Example**:
```markdown
## Verdict: REFUTED -> CONTESTED (mock evidence override)

### Evidence Audit
| Claim | Source | Tag | Valid? |
|-------|--------|-----|--------|
| "Staking returns shares" | StakingMock.sol:45 | [MOCK] | NO |

**Override reason**: REFUTED verdict relies on mock behavior at StakingMock.sol:45.
Production contract behavior is UNVERIFIED. Must fetch production source.
```

---

## Pre-Verification Understanding

Before writing ANY test code, you MUST answer:

### Question 1: What is the EXACT bug?
```
NOT: "Something is inconsistent"
NOT: "State is wrong"
NOT: "Reentrancy possible"

YES: "[Variable] is [read/written] at [location] but should be [read/written]
      at [other location] because [specific reason]"
```

### Question 2: What OBSERVABLE difference proves it?
```
NOT: "Values are different"
NOT: "State changed"

YES: "Before operation: [variable] = [expected value]
      After operation: [variable] = [actual value]
      Expected: [what it should be]"
```

### Question 3: What is the EXACT assertion?
```
NOT: assertTrue(bugExists)
NOT: assertFalse(isSecure)

YES: assertEq(actualValue, expectedValue, "description of what's wrong")
 OR: assertNotEq(before, after, "value changed when it shouldn't")
 OR: assertGt(error, threshold, "error exceeds acceptable threshold")
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

## Test File Template

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-std/console.sol";

/**
 * @title Test_H{N}: {Title}
 *
 * BUG: {2 sentence description}
 * EXPECTED: {what should happen}
 * ACTUAL: {what does happen}
 */
contract Test_H{N} is Test {

    // === CONTRACTS ===
    // Declare target contract and any dependencies

    // === ACTORS ===
    address attacker = makeAddr("attacker");
    address victim = makeAddr("victim");
    address owner = makeAddr("owner");

    // === SETUP ===
    function setUp() public {
        // Deploy contracts
        // Set initial state
        // Fund actors if needed
    }

    // === TEST: Direct bug demonstration ===
    function test_H{N}_bug_demonstration() public {
        // 1. RECORD BEFORE
        console.log("=== BEFORE ===");
        uint256 valueBefore = target.criticalValue();
        console.log("Critical value:", valueBefore);

        // 2. ACTION
        console.log("=== ACTION ===");
        // Perform the operation that triggers the bug

        // 3. RECORD AFTER
        console.log("=== AFTER ===");
        uint256 valueAfter = target.criticalValue();
        console.log("Critical value:", valueAfter);

        // 4. PROVE BUG
        console.log("=== VERIFICATION ===");
        // THE ASSERTION THAT PROVES THE BUG
        // Design this so it PASSES when the bug EXISTS
    }

    // === TEST: Impact demonstration (optional) ===
    function test_H{N}_impact() public {
        // Show cumulative impact or attacker profit
    }
}
```

---

## Interpreting Results

### Test PASSES -> Bug CONFIRMED
The assertion that "proves the bug" succeeded.
- If `assertNotEq(after, before)` passes -> values ARE different (bug exists)
- If `assertGt(error, threshold)` passes -> error IS above threshold (bug exists)

### Test FAILS -> Check Why

| Failure | Meaning | Action |
|---------|---------|--------|
| Assertion failed: values equal | Bug doesn't exist as hypothesized | Re-examine hypothesis |
| Revert in setup | Deployment/config wrong | Fix setup |
| Revert in action | Operation blocked | Check preconditions |
| Arithmetic error | Values wrong | Check calculations |

---

## Iteration Protocol

**Attempt 1:** Direct implementation of test strategy from hypothesis

**Attempt 2:** Adjust parameters
- Different amounts (larger/smaller)
- Different timing (more/fewer blocks)
- Different actors

**Attempt 3:** Re-examine assumptions
- Is setup correct?
- Are preconditions met?
- Is the bug mechanism correctly understood?

**After 5 attempts:**
- If still fails -> FALSE_POSITIVE with documented reasoning
- Explain why the hypothesis was wrong

---

## Severity Determination

### CRITICAL
- Direct fund theft possible
- Protocol insolvency
- No special prerequisites needed
- Attacker profits significantly

### HIGH
- Fund loss with some setup
- Broken core functionality
- Significant value at risk
- Cumulative error compounds quickly

### MEDIUM
- Limited fund loss
- Requires specific conditions
- Edge cases with real impact
- Moderate value at risk

### LOW
- Negligible direct impact
- Extreme edge cases only
- Owner/admin controlled risk
- Informational with minor consequence

---

## Output Format

### CONFIRMED

```markdown
## Verdict: CONFIRMED

### Bug Mechanism Verified
{Explain what the test proves in 2-3 sentences}

### Test File
`test/audit/Test_H{N}.t.sol`

### Test Output
```
{Paste relevant forge test output}
```

### Key Evidence
| Metric | Value |
|--------|-------|
| Before | {value} |
| After | {value} |
| Expected | {value} |
| Difference | {calculation} |

### Severity: {LEVEL}
{Justification in 1-2 sentences}
```

### FALSE_POSITIVE

```markdown
## Verdict: FALSE_POSITIVE

### Attempts Made

**Attempt 1:**
- Approach: {description}
- Result: {what happened}
- Learning: {insight}

**Attempt 2:**
- Approach: {description}
- Result: {what happened}
- Learning: {insight}

**Attempt 3:**
- Approach: {description}
- Result: {what happened}
- Learning: {insight}

### Why It's Not a Bug
{Explain the actual behavior and why hypothesis was wrong in 2-3 sentences}
```

### CONTESTED (NEW in v5 -- CRITICAL)

```markdown
## Verdict: CONTESTED

### Evidence Status
| Checkpoint | Status | Details |
|------------|--------|---------|
| External behavior verified against PRODUCTION | NO | Used mock behavior as evidence |
| All callers checked | YES | Checked A, B, C |
| Profit calculated with attacker holding | NO | Only analyzed donation loss |

### Why This Cannot Be REFUTED
{Explain what evidence is missing to definitively rule out the bug}

### Escalation Required
- [ ] Fetch production contract source for {external dep}
- [ ] Re-analyze with attacker holding shares
- [ ] Check additional caller paths: {list}

### Current Assessment
Likely: {TRUE_POSITIVE / FALSE_POSITIVE / UNKNOWN}
Confidence: {LOW / MEDIUM}
```

---

## Insufficient Evidence (HALT CONDITIONS - CRITICAL)

> **MANDATORY**: You MUST check ALL boxes before returning REFUTED.
> If ANY checkbox is NO -> Return CONTESTED, not REFUTED.

Before marking REFUTED, check:
- [ ] External behavior verified against PRODUCTION (not mock)
  - Read `{scratchpad}/external_production_behavior.md`
  - If external dep is marked 'UNVERIFIED' -> CANNOT use as evidence
  - If mock differs from production -> use PRODUCTION behavior
- [ ] Attack path checked on ALL callers (not just main path)
  - Use `mcp__slither-analyzer__get_function_callers()` to enumerate
- [ ] Profit calculated with attacker HOLDING tokens (not just donating)
  - "Attacker loses by donating" is NOT sufficient evidence
  - Check: what if attacker holds X% of shares BEFORE donating?
- [ ] **Missing precondition documented**
  - Document in structured format: precondition type + why it blocks
  - Types: STATE / ACCESS / TIMING / EXTERNAL / BALANCE
- [ ] **Searched other findings for matching postconditions**
  - Read `{scratchpad}/findings_inventory.md` for CONFIRMED/PARTIAL findings
  - Check if ANY finding creates the postcondition that would enable this attack
  - If match found -> CONTESTED, not REFUTED (chain analysis will combine)

### Evidence That Does NOT Count
- "Mock shows X" -- mocks != production (CRITICAL: always verify against production)
- "Standard ERC20" -- may have transfer hooks, side effects
- "Attacker loses by donating" -- may profit via shares held
- "Function is internal" -- may be called by public function
- "Requires admin" -- admin may be compromised or malicious
- "Attacker cannot acquire X" -- another finding may CREATE this condition

### Anti-Downgrade Halt for VS/BLIND Findings (HARD RULE)
For findings from Validation Sweep ([VS-*]) or Blind Spot Scanner ([BLIND-*]): apply Rule 13's 5-question test BEFORE any downgrade.
**HALT**: If test shows users harmed AND unavoidable AND undocumented -> you CANNOT return FALSE_POSITIVE. Minimum verdict: CONTESTED.
Defense parity gaps (Contract A has protection X, Contract B lacks it for same action) are NEVER "by design" -> minimum severity: Medium, minimum verdict: CONTESTED.
Violating this halt is a workflow error equivalent to using [MOCK] evidence for REFUTED.

### Chain Analysis Integration

A finding is NEVER truly REFUTED until chain analysis completes.

If you mark a finding as REFUTED but document a missing precondition, the chain analyzer
(Step 6b) will search for other findings whose postconditions match your missing precondition.
If found, the finding will be escalated to CONTESTED and combined into a chain hypothesis.

**Example**:
- Your finding: "Donation attack blocked because attacker cannot hold receipt tokens"
- Other finding: "External protocol interaction returns transferable receipt tokens"
- Chain: Other finding enables your finding -> Combined HIGH severity

---


---

> **Advanced Protocol Reference**: See [`advanced.md`](references/advanced.md) for RAG queries before PoC, exchange rate finding severity, design flaw escalation, bidirectional role analysis, RAG confidence override, chain hypothesis protection, fork testing, and Foundry PoC methodology.
