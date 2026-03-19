---
name: "verification-protocol"
description: "Trigger Pattern Always (used by all verifier agents) - Inject Into security-verifier agents (Phase 5)"
---

# Verification Protocol (Sui Move)

> **Trigger Pattern**: Always (used by all verifier agents)
> **Inject Into**: security-verifier agents (Phase 5)
> **Purpose**: Prove hypotheses TRUE or FALSE using Sui Move test framework with `test_scenario` PoC code.

---

## Evidence Source Tracking (MANDATORY)

> **CRITICAL**: For EVERY piece of evidence used in verification, you MUST tag its source.
> Evidence from mocks or unverified external packages CANNOT support a REFUTED verdict.

### Evidence Source Tags

| Tag | Meaning | Valid for REFUTED? |
|-----|---------|-------------------|
| [PROD-ONCHAIN] | Production Sui object data (via Sui Explorer or RPC) | YES |
| [PROD-SOURCE] | Verified source from Sui Explorer / published package | YES |
| [PROD-PUBLISHED] | Test against published package bytecode | YES |
| [CODE] | Audited codebase (in-scope source) | YES |
| [MOCK] | Mock/test modules or objects | **NO** |
| [EXT-UNV] | External, unverified package behavior | **NO** |
| [DOC] | Documentation/spec only | **NO** (needs verification) |

### Evidence Audit Table (REQUIRED in every verification output)

Before ANY verdict, fill this table:

```markdown
### Evidence Audit
| Claim | Evidence Source | Tag | Valid for REFUTED? |
|-------|-----------------|-----|-------------------|
| "External package returns X" | Mock module | [MOCK] | NO |
| "Object ownership is Y" | sources/module.move:123 | [CODE] | YES |
| "Shared object state is Z" | Sui Explorer object view | [PROD-ONCHAIN] | YES |
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
| "External module validates input" | test_helper.move:45 | [MOCK] | NO |

**Override reason**: REFUTED verdict relies on mock behavior at test_helper.move:45.
Production package behavior is UNVERIFIED. Must fetch published package source.
```

---

## Pre-Verification Understanding

Before writing ANY test code, you MUST answer:

### Question 1: What is the EXACT bug?
```
NOT: "Object ownership is wrong"
NOT: "Access control is missing"
NOT: "State is inconsistent"

YES: "Function [X] in module [Y] accepts shared object [Z] as `&mut` without
      verifying caller holds [CapabilityType], allowing any address to mutate
      field [W] at line [N]"
```

### Question 2: What OBSERVABLE difference proves it?
```
NOT: "State changed"
NOT: "Object was modified"

YES: "Before exploit: pool.total_supply = 1000, attacker_balance = 0
      After exploit: pool.total_supply = 1000, attacker_balance = 500
      Expected: transaction should have aborted with ENotAuthorized"
```

### Question 3: What is the EXACT assertion?
```
NOT: assert!(exploit_worked, 0)

YES: assert!(coin::value(&stolen_coin) > 0, ERR_EXPLOIT_FAILED)
 OR: // Transaction should abort -- if it succeeds, the bug exists
 OR: assert!(state_after.field != state_before.field, ERR_STATE_UNCHANGED)
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


## Test File Templates

> **See [`templates.md`](references/templates.md)** in this directory for all Sui Move test templates (Templates 1-6: shared object mutation, capability theft, dynamic fields, object wrapping, PTB exploit, concurrent access).

## Interpreting Results

### Test PASSES -> Bug CONFIRMED
The assertion that "proves the bug" succeeded.

### Test FAILS -> Check Why

| Failure | Meaning | Action |
|---------|---------|--------|
| Abort with error code | Function validation rejected the action | Check if rejection IS the bug or a fix |
| `test_scenario::take_from_sender` fails | Object not at expected address | Check transfer logic in setup |
| `test_scenario::take_shared` fails | Shared object not published | Check initialization creates shared objects |
| Type mismatch | Wrong object type taken from scenario | Fix type parameters |
| Arithmetic abort (overflow/underflow) | Math operation failed | Check if this IS the bug or setup error |
| Borrow checker error (compile) | Cannot borrow object mutably | Restructure test to respect Move borrow rules |

---

## Iteration Protocol

**Attempt 1:** Direct implementation of test strategy from hypothesis.

**Attempt 2:** Adjust parameters:
- Different coin amounts (larger/smaller, edge values like 0, 1, u64::MAX)
- Different transaction ordering (swap next_tx blocks)
- Different actor addresses
- Different object states (empty pool, full pool, single-user, multi-user)

**Attempt 3:** Re-examine assumptions:
- Are shared objects properly published in setup?
- Are capability objects at the right addresses?
- Is the module's initialization complete (all shared objects created)?
- Are type parameters correct (generic type instantiation)?
- Does the function require a `Clock` or `TxContext` argument not provided?

**After 5 attempts:** If still fails -> FALSE_POSITIVE with documented reasoning.

---

## Severity Determination

### CRITICAL
- Direct fund theft (Coin drain from shared pools)
- Unauthorized admin capability acquisition
- Arbitrary package upgrade (if upgrade cap compromised and no timelock)
- No special prerequisites needed
- Attacker profits significantly

### HIGH
- Fund loss with specific setup (object pre-creation, ordering dependency)
- Broken core functionality (deposits, withdrawals, swaps, liquidations)
- Shared object state corruption affecting all users
- Significant TVL at risk

### MEDIUM
- Limited fund loss under specific conditions
- Object state corruption (non-fund data)
- Edge cases with real impact at design limits
- Dynamic field pollution affecting protocol behavior
- Moderate value at risk

### LOW
- Negligible direct impact
- Extreme edge cases only
- Admin-controlled risk (with multisig governance)
- View function / event emission issues
- Stranded non-value objects

---

## Exchange Rate Finding Severity (MANDATORY)

> **CRITICAL**: Before assigning severity to ANY finding affecting share/asset ratios or exchange rates, you MUST complete this quantitative analysis.

### Required Quantitative Analysis

For findings affecting exchange rates, fill in this table:

| Metric | Value | Source |
|--------|-------|--------|
| Protocol TVL | [X SUI or USD] | Production or documented estimate |
| Attack cost | [Y] | Calculated from attack steps (gas, tokens, opportunity) |
| Attacker profit | [Z] | Calculated (extraction - cost) |
| Victim loss per user | [W] | Calculated per affected user |
| Affected user count | [N] | one / some / all |
| Profit ratio | [Z/Y] | Attacker profit / attack cost |

### Severity Calculation

**Step 1**: Calculate total impact = W * N (victim loss * affected users)
**Step 2**: Calculate profitability = Z/Y (attacker profit / cost)
**Step 3**: Apply severity matrix:

| Total Impact | Profitability > 2x | Profitability 1-2x | Profitability < 1x |
|--------------|-------------------|-------------------|-------------------|
| > $100,000 | CRITICAL | HIGH | HIGH |
| $10,000 - $100,000 | HIGH | HIGH | MEDIUM |
| $1,000 - $10,000 | HIGH | MEDIUM | MEDIUM |
| < $1,000 | MEDIUM | LOW | LOW |

### What NOT to Do
- "This enables extraction" (qualitative, no numbers)
- "Attacker can profit significantly" (undefined)
- "Loss of funds possible" (unquantified)

### What TO Do
- "Attacker profits 500,000 SUI ($500,000) from 1,000 SUI ($1,000) investment"
- "Each victim loses up to 2% of deposit value, affecting all pool users"
- "Total extractable value: $500,000 with 500x profit ratio -> CRITICAL"

---

## Design Flaw Severity Escalation

When a finding is classified as a "design flaw" rather than an exploit, apply this escalation check:

| Criterion | YES/NO |
|-----------|--------|
| Risk-free for the attacker (no capital at risk, or attacker profits even if partial) | |
| Repeatable (can be executed on every occurrence of a triggering event) | |
| Scales with protocol usage (impact grows with TVL, user count, or time) | |
| No mitigation without code change (off-chain monitoring cannot prevent, only detect) | |

**If ALL 4 criteria are YES**: Severity floor = MEDIUM (cannot be rated LOW or Informational)
**If 3 of 4 criteria are YES**: Recheck -- the remaining criterion may not actually block the attack at scale

---



---

> **Advanced Protocol Reference**: See [`advanced.md`](references/advanced.md) for RAG queries, RAG confidence override, chain hypothesis protection, Sui-specific testing considerations, dual-perspective verification, realistic parameter validation, anti-downgrade guard, new observations, error trace output, and bidirectional role analysis.

## Output Format

### CONFIRMED

```markdown
## Verdict: CONFIRMED

### Bug Mechanism Verified
{Explain what the test_scenario test proves in 2-3 sentences}

### Test Code
{Full Move test function}

### Test Output
{Relevant assertions and logged values from `sui move test`}

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

### RAG Evidence
- **Attack Vectors Consulted**: [list]
- **Similar Exploits Found**: [count]
- **Historical Precedent**: [description]

### Severity: {LEVEL}
{Justification in 1-2 sentences}
```

### FALSE_POSITIVE

```markdown
## Verdict: FALSE_POSITIVE

### Attempts Made

**Attempt 1:**
- Approach: {description}
- Result: {what happened -- include abort codes}
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
|-------|-----------------|-----|-------------------|

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
| External package behavior verified against PRODUCTION | YES/NO | {details} |
| All entry functions checked | YES/NO | {details} |
| Object ownership model verified | YES/NO | {details} |
| Shared object access control confirmed | YES/NO | {details} |

### Evidence Audit
| Claim | Evidence Source | Tag | Valid for REFUTED? |
|-------|-----------------|-----|-------------------|

### Why This Cannot Be REFUTED
{Explain what evidence is missing to definitively rule out the bug}

### Escalation Required
- [ ] Fetch published package source for {external dep}
- [ ] Dump production object state for {object}
- [ ] Check additional entry function paths: {list}

### Error Trace
- **Failure Type**: {type}
- **Location**: {location}
- **Error Code**: {code}
- **State at Failure**: {state}
- **Investigation Question**: {question}
```

---

## Insufficient Evidence (HALT CONDITIONS)

Before marking REFUTED, check ALL boxes:
- [ ] External package behavior verified against PRODUCTION (not mock)
- [ ] Attack path checked on ALL public entry functions that access the same shared objects
- [ ] Profit calculated with attacker HOLDING tokens (not just transferring in)
- [ ] Missing precondition documented (type: STATE / ACCESS / TIMING / EXTERNAL / BALANCE)
- [ ] Searched other findings for matching postconditions (chain analysis integration)
- [ ] Object ownership verified in source (not assumed from naming)
- [ ] Capability access control verified for ALL shared object mutation paths
- [ ] Dynamic field access patterns verified (correct key types, no collisions)

### Evidence That Does NOT Count
- "Mock module shows X" -- mocks are not production behavior
- "Standard Coin<T>" -- may be wrapped in custom module with hooks/restrictions
- "Attacker loses by sending coins" -- may profit via position held in pool
- "Function is `public(package)`" -- may be callable via CPI from another module in the same package
- "Requires AdminCap" -- AdminCap may have `store` ability and be transferable
- "Attacker cannot acquire X" -- another finding may CREATE this condition
- "Object is owned by admin" -- ownership may be transferable if object has `store`
