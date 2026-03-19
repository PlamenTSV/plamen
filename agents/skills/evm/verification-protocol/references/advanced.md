# Verification Protocol - Advanced Reference (EVM)

> Part of the EVM Verification Protocol skill. Read `SKILL.md` for the core workflow first.

## RAG Queries Before PoC (MANDATORY for HIGH/CRITICAL)

Before writing PoC tests for HIGH/CRITICAL findings, query the vulnerability database:

### Step 1: Get Attack Vectors
```
mcp__unified-vuln-db__get_attack_vectors(bug_class="{category}")
```
Returns step-by-step attack strategies from real exploits.

### Step 2: Get PoC Templates
```
mcp__unified-vuln-db__get_poc_template(bug_class="{category}", framework="foundry")
```
Returns example test structures for this vulnerability type.

### Step 3: Get Similar Exploit Code
```
mcp__unified-vuln-db__get_similar_findings(pattern="{vulnerability description}")
```
Returns similar historical findings with code examples.

### Step 4: Validate Before Committing
```
mcp__unified-vuln-db__validate_hypothesis(hypothesis="{your finding summary}")
```
Returns supporting/contradicting evidence from historical exploits.

### RAG Integration Rules

| RAG Result | Impact on Verification |
|------------|----------------------|
| Attack vector found | Use documented steps as test basis |
| PoC template available | Adapt template to this protocol |
| Similar exploit exists | Extract key attack pattern |
| No similar findings | Proceed with manual analysis, note uncertainty |

### Document RAG Evidence

In the verification output, add:

```markdown
### RAG Evidence
- **Attack Vectors Consulted**: [list bug classes queried]
- **Similar Exploits Found**: [count and brief descriptions]
- **PoC Template Used**: [yes/no, which template]
- **Historical Precedent**: [describe any matching historical vulnerabilities]
```

---

## Exchange Rate Finding Severity (MANDATORY)

> **CRITICAL**: Before assigning severity to ANY finding affecting share/asset ratios or exchange rates, you MUST complete this quantitative analysis. Do NOT use qualitative terms without numbers.

### Required Quantitative Analysis

For findings affecting exchange rates, fill in this table:

| Metric | Value | Source |
|--------|-------|--------|
| Protocol TVL | [X ETH or USD] | Production or documented estimate |
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

### Example Calculation (Donation Attack)

```markdown
| Metric | Value | Source |
|--------|-------|--------|
| Protocol TVL | $100M | Documentation |
| Attack cost | 1000 TOKEN (~$500) | Direct donation amount |
| Attacker profit | 100,000 TOKEN (~$50,000) | Exchange rate * shares held |
| Victim loss per user | Variable | Depends on timing |
| Affected user count | All future depositors | Until reconciliation |
| Profit ratio | 100x | $50,000 / $500 |

**Severity**: HIGH (Total impact > $10k, profitability > 2x)
```

### What NOT to Do

- "This enables MEV-style extraction" (qualitative, no numbers)
- "Attacker can profit significantly" (undefined)
- "Loss of funds possible" (unquantified)
- "Medium severity due to complexity" (no calculation)

### What TO Do

- "Attacker profits 100,000 TOKEN ($50,000) from 1,000 TOKEN ($500) investment"
- "Each victim loses up to 1% of deposit value, affecting all users"
- "Total extractable value: $50,000 with 100x profit ratio -> HIGH"

---

## Design Flaw Severity Escalation

When a finding is classified as a "design flaw" or "accounting inaccuracy" rather than an exploit, apply this escalation check:

| Criterion | YES/NO |
|-----------|--------|
| Risk-free for the attacker (no capital at risk, or attacker profits even if partial) | |
| Repeatable (can be executed on every occurrence of a triggering event) | |
| Scales with protocol usage (impact grows with TVL, user count, or time) | |
| No mitigation without code change (off-chain monitoring cannot prevent, only detect) | |

**If ALL 4 criteria are YES**: Severity floor = MEDIUM (cannot be rated LOW or Informational)
**If 3 of 4 criteria are YES**: Recheck -- the remaining criterion may not actually block the attack at scale

**Rationale**: Design flaws that are risk-free, repeatable, scaling, and unmitigable are effectively permanent value extraction channels. Even if per-event profit is small, cumulative impact over protocol lifetime is significant. "Attacker loses money" is only a valid downgrade if the loss is CERTAIN and PROPORTIONAL -- not if the attacker can structure the trade to break even or profit.

---

## Using RAG for Test Ideas

If stuck on how to write a test:

```
mcp__unified-vuln-db__get_poc_template(
  vulnerability_type="{category from hypothesis}"
)
```

This returns example test structures for common vulnerability types.

---

## Bidirectional Role Analysis (MANDATORY)

> **CRITICAL**: Semi-trusted role findings CANNOT be marked REFUTED unless BOTH directions are analyzed.

### HALT CONDITIONS for Semi-Trusted Role Findings

Before marking ANY finding involving BOT/KEEPER/OPERATOR roles as REFUTED:

- [ ] **Direction 1 analyzed**: ROLE -> USER harm scenarios (Steps 1-4 of SEMI_TRUSTED_ROLES.md)
- [ ] **Direction 2 analyzed**: USER -> ROLE exploitation (Steps 5-6 of SEMI_TRUSTED_ROLES.md)
- [ ] **Precondition Griefability table completed**: All role function preconditions checked
- [ ] **User exploitation scenarios documented**: Scenarios D, E, F from skill

### Direction 2 Enforcement

If Direction 2 (USER -> ROLE) is NOT analyzed:
- CANNOT return REFUTED
- MUST return CONTESTED with note: "Direction 2 not analyzed"
- Finding flagged for depth review

**Example**:
```markdown
## Finding [SR-3]: Keeper timing abuse

**Verdict**: CONTESTED (not REFUTED)
**Reason**: Only Direction 1 (keeper->user) analyzed. Direction 2 (user->keeper) not analyzed.

### Missing Analysis
- [ ] Can users predict keeper timing?
- [ ] Can users manipulate preconditions to block keeper?
- [ ] What is system degradation if keeper is blocked?

**Step Execution**: checkmark1,2,3,4 | x5,6(not analyzed) -> INCOMPLETE
```

---

## RAG Confidence Override

> **PURPOSE**: Prevent dismissal of findings with strong historical precedent.

### RAG Confidence Scoring

When validating a hypothesis, RAG returns a confidence score based on:
- Number of similar findings in database
- Severity distribution of similar findings
- Match quality (exact pattern vs. related pattern)

### Override Rules

| RAG Confidence | Local Verdict | Final Verdict | Action |
|----------------|---------------|---------------|--------|
| >= 7/8 matches | FALSE_POSITIVE | **CONTESTED** (override) | Cannot dismiss -- strong precedent |
| >= 6/8 matches | FALSE_POSITIVE | **CONTESTED** (override) | Cannot dismiss -- significant precedent |
| < 6/8 matches | FALSE_POSITIVE | FALSE_POSITIVE | Allowed -- limited precedent |

**Implementation**:
```markdown
### RAG Confidence Check
- Similar findings found: 8
- HIGH severity matches: 5
- RAG confidence: 8/8 (>=6 threshold)
- **Override applied**: Cannot mark FALSE_POSITIVE

## Verdict: CONTESTED (RAG override)
**Reason**: 8 similar HIGH findings in database. Local analysis suggests FALSE_POSITIVE but historical precedent too strong to dismiss.
```

---

## Chain Hypothesis Protection

> **CRITICAL**: Chain hypotheses receive elevated protection because they represent multi-step attacks that were initially missed.

### Protection Rules

1. **RAG >= 6/8 + Chain**: Cannot be dismissed as FALSE_POSITIVE
2. **3+ agents flagged + Chain**: Need PRODUCTION evidence to refute
3. **Chain PoC MUST test full sequence**: Both enabler AND blocked finding

### Chain PoC Requirements

```solidity
// Chain PoC MUST demonstrate COMPLETE sequence
function test_CH1_full_chain() public {
    // ========================================
    // STEP 1: ENABLER (Finding B)
    // Execute the action that creates postcondition
    // ========================================

    // Record state BEFORE enabler
    uint256 tokensBefore = token.balanceOf(attacker);

    // Execute enabler action
    // ... enabler code ...

    // ========================================
    // VERIFY POSTCONDITION CREATED
    // Assert the precondition for Finding A is now met
    // ========================================

    uint256 tokensAfter = token.balanceOf(attacker);
    assertTrue(tokensAfter > tokensBefore, "Enabler created tokens");

    // ========================================
    // STEP 2: BLOCKED FINDING (Finding A)
    // Execute the attack that was previously blocked
    // ========================================

    // ... blocked attack code using acquired tokens ...

    // ========================================
    // VERIFY CHAIN IMPACT
    // Assert combined impact (should exceed either alone)
    // ========================================

    uint256 profit = /* calculate */;
    assertGt(profit, 0, "Chain attack profitable");
}
```

### Chain Dismissal Requirements

To mark a chain hypothesis as FALSE_POSITIVE, you MUST:
1. Prove enabler finding does NOT create the postcondition, OR
2. Prove blocked finding still blocked EVEN WITH the postcondition, OR
3. Prove chain sequence is impossible due to timing/access/state constraints

Each proof requires [PROD] or [CODE] evidence -- no [MOCK] evidence allowed.

### Bidirectional Chain Analysis (Rule 6 Extension)
For chain hypotheses where enabler OR blocked finding involves a semi-trusted role (BOT/KEEPER/OPERATOR):
Verify BOTH directions: (1) role executes chain to harm users, AND (2) users exploit role's timing/sequencing to trigger chain.
If only one direction analyzed -> verdict CANNOT be FALSE_POSITIVE. Return CONTESTED with note: "Chain bidirectional analysis incomplete."
This extends standalone Rule 6 halt to multi-step chain sequences.

---

## Fork Testing (Preferred for External Dependencies)

When hypothesis involves external contract behavior, **prefer Anvil fork testing** over mocked tests:

1. **Start Anvil fork**: `mcp__foundry-suite__anvil_start(fork_url=RPC_URL)` -- forks mainnet state
2. **Run PoC against forked state**: Real external contracts, real balances, real behavior
3. **Evidence level**: Fork tests provide [PROD-FORK] evidence (valid for REFUTED verdicts)
4. **When to use**: Any hypothesis where external contract behavior is central to the verdict

Fork testing eliminates the need for manual production source fetching in most cases.

## Foundry Suite PoC Methodology

When writing PoC tests, use these MCP tools for realistic verification:

### Local Fork Testing
1. Start local mainnet fork: `mcp__foundry-suite__anvil_start` with fork URL
2. Execute PoC script: `mcp__foundry-suite__forge_script` for realistic execution
3. Inspect state: `mcp__foundry-suite__cast_call` to read contract state
4. Send transactions: `mcp__foundry-suite__cast_send` for state changes
5. Check balances: `mcp__evm-chain-data__get_token_balance` / `get_balance`

### Production Contract Verification
- Read contract state directly: `mcp__evm-chain-data__read_contract(address, network, function_name, args)`
- Get contract ABI: `mcp__evm-chain-data__get_contract_abi(address, network)`
- Check transaction receipts: `mcp__evm-chain-data__get_transaction_receipt`

### Evidence Tagging
Tag all evidence with source type:
- [PROD-ONCHAIN]: From production contract read
- [PROD-SOURCE]: From verified source on block explorer
- [PROD-FORK]: From mainnet fork test
- [CODE]: From audited codebase
- [MOCK]: From mock/test contract -- CANNOT support REFUTED for external behavior
- [EXT-UNV]: External, unverified -- CANNOT support REFUTED for external behavior
