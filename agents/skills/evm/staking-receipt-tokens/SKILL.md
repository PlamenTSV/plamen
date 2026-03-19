---
name: "staking-receipt-tokens"
description: "Type Thought-template (instantiate before use) - Research basis Donation attacks via unsolicited token transfers"
---

# Skill: Staking Receipt Token Analysis

> **Type**: Thought-template (instantiate before use)
> **Research basis**: Donation attacks via unsolicited token transfers

## Trigger Patterns
```
delegation|staking.*receipt|liquid.*staking|getLiquidRewards|unbond|
stake.*share|validator|deposit.*voucher|withdraw.*voucher|claimReward
```

## Reasoning Template

### Step 1: Identify Receipt Tokens
- In {CONTRACTS}, find all external calls that return tokens
- For each, determine:
  - What token type is returned? (shares, vouchers, receipts, LP tokens)
  - Is the returned token ERC20-compatible?
  - Does the protocol hold these tokens?

### Step 2: Check Transferability
- For each receipt token {RECEIPT_TOKEN}:
  - Can it be acquired externally? (stake directly with {EXTERNAL_STAKING})
  - Can it be transferred via standard `transfer()`/`transferFrom()`?
  - Can anyone transfer it to {PROTOCOL_CONTRACT} unsolicited?

### Step 2b: External Token Transferability

For each EXTERNAL staking/delegation token the protocol interacts with (not just the protocol's own receipt token):

1. Is it ERC20-transferable? (check if extends IERC20/IERC20Upgradeable)
2. Can it be transferred TO the protocol contract unsolicited (without calling deposit/stake)?
3. If YES to both:
   a. Does the protocol iterate over these tokens or their sources? (gas DoS from many unsolicited transfers)
   b. Does `getTotalStake(protocol)` or equivalent change? (accounting impact on withdrawal calculations)
   c. Does `transfer()` trigger side effects? (reward auto-claim, delegation state changes)
   d. Does non-zero balance block any admin/privileged operations? (e.g., entity removal requires balance == 0)

| External Token | ERC20? | Unsolicited Transfer? | Iteration DoS? | Balance Impact? | Side Effects? | Blocks Operations? |
|----------------|--------|----------------------|-----------------|-----------------|---------------|-------------------|
| {token_name} | YES/NO | YES/NO | YES/NO | YES/NO | YES/NO | YES/NO |

**RULE**: If ANY external token is ERC20-transferable AND affects protocol state → finding with severity >= MEDIUM.

### Step 3: Trace Balance Dependencies
- In {PROTOCOL_CONTRACT}, find all uses of `balanceOf(address(this))` for {RECEIPT_TOKEN}
- For each usage at {BALANCE_CHECK_LOCATIONS}:
  - What calculation depends on this balance?
  - Is there a tracked state variable that should match?
  - What's the gap risk: tracked vs actual?

### Step 4: Model Donation Attack
```
1. Attacker acquires {RECEIPT_TOKEN} externally via {EXTERNAL_ACQUISITION}
2. Attacker transfers {DONATION_AMOUNT} to {PROTOCOL_CONTRACT}
3. Protocol's balanceOf(this) increases by {DONATION_AMOUNT}
4. Next operation at {AFFECTED_FUNCTION} uses inflated balance
5. Impact: {IMPACT_DESCRIPTION}
```

### Step 5: Assess Severity
- Can attacker profit from this manipulation?
- Can attacker grief other users?
- What's the minimum donation needed for impact?
- Is there a defense (e.g., balance reconciliation)?

## Key Questions (must answer all)
1. Can {RECEIPT_TOKEN} be acquired without going through {PROTOCOL_CONTRACT}?
2. Does {PROTOCOL_CONTRACT} use `balanceOf(this)` for {RECEIPT_TOKEN} in any calculation?
3. Is there a tracked state variable that should equal the actual balance?
4. What happens if tracked ≠ actual?

## Common False Positives
- **Balance reconciliation**: If protocol calls `balanceOf` and compares to tracked state, donation is detected
- **Isolated accounting**: If receipt tokens are accounted separately per user (not pooled), donation doesn't affect others
- **No balance dependency**: If protocol never calls `balanceOf(this)` for this token, donation has no effect
- **Burn on transfer**: Some receipt tokens are non-transferable or burn on transfer

## Multi-Entity Dust Attack Analysis

### Step 6: Identify Multi-Entity Patterns
- Does the protocol interact with MULTIPLE staking entities? (validators, pools, vaults)
- Are there separate receipt tokens per entity?
- How does the protocol aggregate across entities?

### Step 7: Model Compounding Dust
For protocols with N entities:
```
Single entity dust: X tokens (below threshold, ignored)
N entities with dust: N × X tokens
Compounding factor: If dust compounds over time → N × X × T

Check: Can attacker spread small amounts across many entities to:
1. Accumulate significant total value?
2. Avoid per-entity dust thresholds?
3. Exploit aggregation rounding?
```

### Step 8: On-Transfer Side Effects
When receipt tokens are transferred:
- Does `transfer()` trigger reward claims?
- Does `transfer()` update internal delegation state?
- Does `transfer()` call any hooks or callbacks?

**Specific checks**:
| Token | transfer() Side Effect | Exploitable? |
|-------|----------------------|--------------|
| Staking receipts | May claim rewards | Check if rewards go to sender/receiver/neither |
| stETH | Rebases on transfer | Check exchange rate impact |
| LP tokens | May trigger sync | Check for manipulation window |
| cTokens/aTokens | May accrue interest | Check balance vs shares discrepancy |

### Step 9: Cross-Validator Attack Patterns
For protocols managing multiple validators:
```
Pattern A: Dust Spreading
- Attacker creates dust positions across N validators
- Each position below withdrawal threshold
- Total value: significant
- Impact: locked value, accounting discrepancies

Pattern B: Selective Validator Manipulation
- Attacker identifies validator with exploitable state
- Moves delegation to that specific validator
- Exploits validator-specific vulnerability
- Impact: depends on vulnerability

Pattern C: Aggregation Rounding
- Protocol rounds down per-validator withdrawals
- Attacker exploits: N validators × rounding_error = significant loss/gain
```

### Step 10: External Adverse Events on Pending Operations

When the protocol has multi-step operations (request → wait → claim), check what happens if the external entity (validator, pool, vault, market) experiences an adverse event between steps.

| Multi-Step Operation | External Entity | Adverse Event | Impact on Pending Operation | Recovery Path? |
|---------------------|-----------------|---------------|----------------------------|----------------|
| {request→claim} | {entity} | Entity paused/frozen | {what happens to pending claim} | YES/NO |
| {request→claim} | {entity} | Entity slashed/penalized | {what happens to pending claim} | YES/NO |
| {request→claim} | {entity} | Entity deprecated/removed | {what happens to pending claim} | YES/NO |
| {request→claim} | {entity} | Entity liquidated/drained | {what happens to pending claim} | YES/NO |

**Adverse events to check**: pause, slash, penalize, deprecate, remove, liquidate, drain, migrate, upgrade

**RULE**: If a pending multi-step operation has no recovery path when the external entity experiences an adverse event → apply Rule 9 (stranded asset severity floor).

## Instantiation Parameters
```
{CONTRACTS}              - Contracts to analyze
{RECEIPT_TOKEN}          - Specific token (stETH, rETH, cToken, aToken, LP token, etc.)
{EXTERNAL_STAKING}       - Where token can be acquired externally
{PROTOCOL_CONTRACT}      - Contract that holds receipt tokens
{BALANCE_CHECK_LOCATIONS}- Lines where balanceOf(this) is called
{EXTERNAL_ACQUISITION}   - How attacker gets tokens (stake directly, buy on DEX)
{DONATION_AMOUNT}        - Amount transferred in attack
{AFFECTED_FUNCTION}      - Function affected by inflated balance
{IMPACT_DESCRIPTION}     - What goes wrong
```

## Output Schema
| Field | Required | Description |
|-------|----------|-------------|
| receipt_tokens | yes | List of identified receipt tokens |
| transferable | yes | YES/NO for each token |
| balance_dependencies | yes | Functions using balanceOf(this) |
| donation_impact | yes | What happens if balance is inflated |
| tracked_vs_actual | yes | Gap analysis |
| finding | yes | CONFIRMED / REFUTED / CONTESTED / NEEDS_DEPTH |
| evidence | yes | Code locations with line numbers |
| step_execution | yes | ✓/✗/? for each step |

---

## Step Execution Checklist (MANDATORY)

> **CRITICAL**: You MUST report completion status for ALL steps. Findings with incomplete steps (✗ or ? without valid reason) will be flagged for depth review.

Before finalizing ANY finding, complete this checklist:

| Step | Required | Completed? | Notes |
|------|----------|------------|-------|
| 1. Identify Receipt Tokens | YES | ✓/✗/? | |
| 2. Check Transferability | YES | ✓/✗/? | |
| 2b. External Token Transferability | **YES** | ✓/✗/? | **MANDATORY** - never skip |
| 3. Trace Balance Dependencies | YES | ✓/✗/? | |
| 4. Model Donation Attack | YES | ✓/✗/? | |
| 5. Assess Severity | YES | ✓/✗/? | |
| 6. Identify Multi-Entity Patterns | **IF N>1** | ✓/✗(N/A)/? | Skip only if protocol has single entity |
| 7. Model Compounding Dust | **IF N>1** | ✓/✗(N/A)/? | Skip only if protocol has single entity |
| 8. On-Transfer Side Effects | **YES** | ✓/✗/? | **MANDATORY** - never skip |
| 9. Cross-Validator Attack Patterns | **IF validators** | ✓/✗(N/A)/? | Skip only if no validators |

### Cross-Reference Markers

**After Step 5** (Assess Severity):
- IF protocol manages multiple entities (validators, pools, vaults) → **MUST complete Steps 6-7**
- IF protocol has staking receipts → **MUST complete Step 8**

**After Step 8** (On-Transfer Side Effects):
- IF side effects UNKNOWN → mark CONTESTED (not REFUTED)
- IF side effects may exist → assume YES (adversarial default), trace impact

### Output Format for Step Execution

```markdown
**Step Execution**: ✓1,2,3,4,5,8 | ✗6,7(N/A-single validator) | ✗9(N/A-no multi-validator)
```

OR if incomplete:

```markdown
**Step Execution**: ✓1,2,3,4,5 | ?6,7(need multi-entity analysis) | ?8(transfer effects unknown)
**FLAG**: Incomplete analysis - requires depth review
```
