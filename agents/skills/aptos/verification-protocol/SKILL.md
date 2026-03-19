---
name: "verification-protocol"
description: "How to prove a hypothesis is TRUE or FALSE using Move unit tests."
---

# Verification Protocol -- Aptos Move

> How to prove a hypothesis is TRUE or FALSE using Move unit tests.

---

## Evidence Source Tracking (MANDATORY)

> **CRITICAL**: For EVERY piece of evidence used in verification, you MUST tag its source. Evidence from mocks or unverified external modules CANNOT support a REFUTED verdict.

### Evidence Source Tags

| Tag | Meaning | Valid for REFUTED? |
|-----|---------|-------------------|
| [PROD-ONCHAIN] | Production module verified on Aptos Explorer | YES |
| [PROD-SOURCE] | Source code verified on-chain (Aptos Explorer source verification) | YES |
| [CODE] | Audited codebase (in-scope) | YES |
| [MOCK] | Mock/test module | **NO** |
| [EXT-UNV] | External module, unverified behavior | **NO** |
| [DOC] | Documentation/spec only | NO (needs verification) |

### Evidence Audit Table (REQUIRED in every verification output)

Before ANY verdict, fill this table:

```markdown
### Evidence Audit
| Claim | Evidence Source | Tag | Valid for REFUTED? |
|-------|-----------------|-----|-------------------|
| "External module returns X" | Mock module | [MOCK] | NO |
| "State changes to Y" | protocol_module.move:123 | [CODE] | YES |
| "Coin transfer triggers Z" | Aptos Explorer source | [PROD-ONCHAIN] | YES |
```

### Mock Rejection Rule

**AUTOMATIC OVERRIDE**: If ANY evidence supporting REFUTED has tag [MOCK] or [EXT-UNV]:
- CANNOT return REFUTED
- MUST return CONTESTED
- Triggers production verification

**Example**:
```markdown
## Verdict: REFUTED -> CONTESTED (mock evidence override)

### Evidence Audit
| Claim | Source | Tag | Valid? |
|-------|--------|-----|--------|
| "Staking returns shares" | test_staking.move:45 | [MOCK] | NO |

**Override reason**: REFUTED verdict relies on mock behavior at test_staking.move:45.
Production module behavior is UNVERIFIED. Must verify against on-chain source.
```

---

## Pre-Verification Understanding

Before writing ANY test code, you MUST answer:

### Question 1: What is the EXACT bug?
```
NOT: "Something is inconsistent"
NOT: "State is wrong"
NOT: "Capability leak possible"

YES: "[Variable/resource] is [read/written/moved] at [location] but should be
      [read/written/moved] at [other location] because [specific reason]"
```

### Question 2: What OBSERVABLE difference proves it?
```
NOT: "Values are different"
NOT: "State changed"

YES: "Before operation: [resource/value] = [expected value]
      After operation: [resource/value] = [actual value]
      Expected: [what it should be]"
```

### Question 3: What is the EXACT assertion?
```
NOT: assert!(bug_exists, 0)
NOT: assert!(!is_secure, 0)

YES: assert!(actual_value == expected_value, ERROR_CODE)
 OR: assert!(before != after, ERROR_CODE)  // "value changed when it shouldn't"
 OR: assert!(error > threshold, ERROR_CODE)  // "error exceeds acceptable threshold"
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

> **See [`templates.md`](references/templates.md)** in this directory for all Move test file templates and Move-specific test patterns.

## Interpreting Results

### Test PASSES -> Bug CONFIRMED
The assertion that "proves the bug" succeeded.
- If `assert!(after != before, 0)` passes -> values ARE different (bug exists)
- If `assert!(error > threshold, 0)` passes -> error IS above threshold (bug exists)

### Test FAILS -> Check Why

| Failure | Meaning | Action |
|---------|---------|--------|
| Assertion failed (abort code) | Bug doesn't exist as hypothesized | Re-examine hypothesis |
| Abort in setup | Module initialization wrong | Fix setup (check init order, missing resources) |
| Abort in action | Operation blocked (access control, precondition) | Check preconditions, signer requirements |
| ARITHMETIC_ERROR (0x20001) | Overflow/underflow or division by zero | Check calculations, validate inputs |
| RESOURCE_NOT_FOUND | Missing `move_to` in setup | Ensure all required resources are initialized |
| ALREADY_EXISTS | Duplicate resource creation | Check init called only once |

### Common Aptos-Specific Test Issues

| Issue | Cause | Fix |
|-------|-------|-----|
| `ENOT_FOUND` on coin operations | Account not registered for coin type | Add `coin::register<CoinType>(user)` before operations |
| Timestamp not available | `timestamp` module not initialized | Add `timestamp::set_time_has_started_for_testing(aptos_framework)` |
| Object not found | Object created at unexpected address | Use `object::create_named_object` with deterministic seed |
| Module not published | Test module can't import protocol module | Check `Move.toml` dependencies and test address mapping |
| Signer mismatch | `@protocol_addr` doesn't match expected | Verify `#[test(...)]` signer addresses match module publish address |

---

## Iteration Protocol

**Attempt 1:** Direct implementation of test strategy from hypothesis

**Attempt 2:** Adjust parameters
- Different amounts (larger/smaller, boundary values)
- Different timing (advance more/fewer seconds)
- Different actors (swap attacker/victim roles)
- Different resource initialization order

**Attempt 3:** Re-examine assumptions
- Is setup correct? (all resources initialized, correct init order)
- Are preconditions met? (correct signer, sufficient balance, required state)
- Is the bug mechanism correctly understood?
- Are module dependencies correctly configured in Move.toml?

**After 5 attempts:**
- If still fails -> FALSE_POSITIVE with documented reasoning
- Explain why the hypothesis was wrong

---

## Severity Determination

### CRITICAL
- Direct fund theft possible (drain FungibleStore, mint unlimited tokens)
- Protocol insolvency (assets < liabilities)
- No special prerequisites needed (permissionless exploit)
- Attacker profits significantly
- Ref capability leak granting unrestricted mint/transfer/burn

### HIGH
- Fund loss with some setup (specific state required)
- Broken core functionality (deposits, withdrawals, swaps non-functional)
- Significant value at risk
- Cumulative error compounds quickly
- Ref capability leak with limited but significant blast radius

### MEDIUM
- Limited fund loss (bounded by rate limits, caps)
- Requires specific conditions (timing, state, multi-step)
- Edge cases with real impact
- Moderate value at risk
- Access control weakness that requires compromised friend module

### LOW
- Negligible direct impact
- Extreme edge cases only
- Admin/owner controlled risk with compensating controls
- Informational with minor consequence

---

## Output Format

### CONFIRMED

```markdown
## Verdict: CONFIRMED

### Evidence Audit
| Claim | Evidence Source | Tag | Valid for REFUTED? |
|-------|-----------------|-----|-------------------|

### Bug Mechanism Verified
{Explain what the test proves in 2-3 sentences}

### Test File
`tests/audit/test_hypothesis_N.move`

### Test Output
```
{Paste relevant `aptos move test` output}
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

### RAG Evidence
- **Attack Vectors Consulted**: [list bug classes queried]
- **Similar Exploits Found**: [count and brief descriptions]
- **PoC Template Used**: [yes/no, which template]
- **Historical Precedent**: [describe any matching historical vulnerabilities]
```

### FALSE_POSITIVE

```markdown
## Verdict: FALSE_POSITIVE

### Evidence Audit
| Claim | Evidence Source | Tag | Valid for REFUTED? |
|-------|-----------------|-----|-------------------|

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

### CONTESTED (CRITICAL)

```markdown
## Verdict: CONTESTED

### Evidence Audit
| Claim | Evidence Source | Tag | Valid for REFUTED? |
|-------|-----------------|-----|-------------------|

### Evidence Status
| Checkpoint | Status | Details |
|------------|--------|---------|
| External behavior verified against PRODUCTION | NO | Used mock behavior as evidence |
| All callers checked | YES | Checked A, B, C |
| Ref access paths fully traced | NO | Friend module re-export not analyzed |
| Profit calculated with attacker holding | NO | Only analyzed donation loss |

### Why This Cannot Be REFUTED
{Explain what evidence is missing to definitively rule out the bug}

### Escalation Required
- [ ] Fetch production module source from Aptos Explorer for {external dep}
- [ ] Re-analyze with attacker holding shares/tokens
- [ ] Check additional caller paths: {list}
- [ ] Trace Ref access through friend modules: {list}

### Current Assessment
Likely: {TRUE_POSITIVE / FALSE_POSITIVE / UNKNOWN}
Confidence: {LOW / MEDIUM}
```

---

## Insufficient Evidence (HALT CONDITIONS) -- CRITICAL

> **MANDATORY**: You MUST check ALL boxes before returning REFUTED.
> If ANY checkbox is NO -> Return CONTESTED, not REFUTED.

Before marking REFUTED, check:
- [ ] External behavior verified against PRODUCTION (not mock)
  - Check Aptos Explorer for on-chain module source verification
  - If external module is marked 'UNVERIFIED' -> CANNOT use as evidence
  - If mock differs from production -> use PRODUCTION behavior
- [ ] Attack path checked on ALL callers (not just main path)
  - Enumerate all `public fun` and `public entry fun` that reach the vulnerable code
  - Check `public(friend) fun` callers via friend module analysis
- [ ] Ref capability paths fully traced
  - For Ref-related findings: trace every path from Ref creation to Ref usage
  - Check friend modules for transitive Ref access
  - Check if ExtendRef-derived signer enables unexpected access
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
- "Standard Coin module" -- may have custom transfer hooks via fungible_asset dispatch
- "Attacker loses by donating" -- may profit via shares held
- "Function is private/friend" -- friend module may expose it publicly
- "Requires admin signer" -- admin may be compromised or malicious
- "Attacker cannot acquire X" -- another finding may CREATE this condition
- "Ref is in private storage" -- friend module may provide access path

### Anti-Downgrade Halt for VS/BLIND Findings (HARD RULE)
For findings from Validation Sweep ([VS-*]) or Blind Spot Scanner ([BLIND-*]): apply Rule 13's 5-question test BEFORE any downgrade.
**HALT**: If test shows users harmed AND unavoidable AND undocumented -> you CANNOT return FALSE_POSITIVE. Minimum verdict: CONTESTED.
Defense parity gaps (Module A has protection X, Module B lacks it for same action) are NEVER "by design" -> minimum severity: Medium, minimum verdict: CONTESTED.
Violating this halt is a workflow error equivalent to using [MOCK] evidence for REFUTED.

### Chain Analysis Integration

A finding is NEVER truly REFUTED until chain analysis completes.

If you mark a finding as REFUTED but document a missing precondition, the chain analyzer
will search for other findings whose postconditions match your missing precondition.
If found, the finding will be escalated to CONTESTED and combined into a chain hypothesis.

**Example**:
- Your finding: "Drain attack blocked because attacker cannot get TransferRef"
- Other finding: "Friend module exposes TransferRef via public function"
- Chain: Other finding enables your finding -> Combined HIGH severity

---



---

> **Advanced Protocol Reference**: See [`advanced.md`](references/advanced.md) for RAG queries before PoC, exchange rate finding severity, design flaw escalation, bidirectional role analysis, chain hypothesis, and Aptos-specific verification considerations.
