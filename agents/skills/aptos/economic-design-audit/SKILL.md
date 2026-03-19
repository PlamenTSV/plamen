---
name: "economic-design-audit"
description: "Trigger Pattern MONETARY_PARAMETER flag (required) - Inject Into Breadth agents (merged via M4 hierarchy)"
---

# ECONOMIC_DESIGN_AUDIT Skill

> **Trigger Pattern**: MONETARY_PARAMETER flag (required)
> **Inject Into**: Breadth agents (merged via M4 hierarchy)
> **Purpose**: Analyze admin-settable economic parameters (fees, rates, thresholds, emission schedules) for boundary violations, invariant breaks, interaction extremes, and fee formula correctness

For every monetary parameter setter (rate, rebase, supply, mint, burn, emission, inflation,
peg, price cap/floor, fee, reward rate) in the protocol:

## 1. Parameter Boundary Analysis

| Parameter | Setter Function | Min Value | Max Value | Enforced? | Impact at Min | Impact at Max |
|-----------|----------------|-----------|-----------|-----------|---------------|---------------|
| {param} | {set_fn} | {min} | {max} | YES/NO | {impact} | {impact} |

For each parameter: substitute min and max into ALL consuming functions.
Tag: [BOUNDARY:param=val -> outcome]

**Aptos-specific checks**:
- Are bounds enforced via `assert!()` in the setter? If not, admin can set any value within the type range (`u64::MAX`, `u128::MAX`)
- Does the protocol use `u64` or `u128` for monetary values? Check for overflow at max values.
- Are there separate bounds for testnet vs mainnet? (Sometimes hardcoded differently)

## 2. Economic Invariant Identification

List all economic invariants the protocol must maintain:

| Invariant | Parameters Involved | Can Admin Break It? | Functions That Assume It |
|-----------|-------------------|--------------------|-----------------------|
| total_supply == sum(all_balances) | mint/burn params | YES/NO | {fn list} |
| fees < principal | fee_rate | YES/NO | {fn list} |
| collateral_ratio >= min_ratio | ratio_param | YES/NO | {fn list} |
| rewards_distributed <= rewards_pool | emission_rate | YES/NO | {fn list} |

For each setter: can changing this parameter break an invariant that user-facing
functions depend on? If yes -> finding.

**Aptos-specific invariants**:
- `FungibleAsset` total supply tracking via `supply()` must match minted - burned
- Object-based accounting: sum of all store balances == total assets managed
- Resource conservation: tokens entering protocol == tokens accounted internally

## 3. Rate/Supply Interaction Matrix

For protocols with multiple monetary parameters that interact:

| Parameter A | Parameter B | Interaction | Can A*B Produce Extreme Output? |
|-------------|-------------|-------------|-------------------------------|
| {param_a} | {param_b} | {relationship} | YES/NO: {at what values} |

Check: can two independently-valid parameter settings combine to create an
extreme or invalid economic state? (Rule 14 constraint coherence)

**Examples**:
- Fee rate A = 50% AND fee rate B = 50% -> combined 75% fee (not 100%, because B applies to post-A amount)
- Reward rate = max AND lock period = min -> excessive reward extraction
- Borrow rate = max AND liquidation threshold lowered -> cascade liquidations

## 4. Fee Formula Verification at Normal Values

For every fee-related computation (fee calculation, fee deduction, fee distribution):

### 4a. Concrete Example Computation

Pick 3 representative fee rates (e.g., 1% = 100 BPS, 5% = 500 BPS, 10% = 1000 BPS) and trace through the actual code formula:

| Fee Param | Value | Formula | Input Amount | Expected Output | Actual Output | Match? |
|-----------|-------|---------|-------------|----------------|---------------|--------|
| {fee_bps} | 100 | {code formula} | 1_000_000_00 (1e8) | {expected} | {computed} | YES/NO |
| {fee_bps} | 500 | {code formula} | 1_000_000_00 (1e8) | {expected} | {computed} | YES/NO |
| {fee_bps} | 1000 | {code formula} | 1_000_000_00 (1e8) | {expected} | {computed} | YES/NO |

Tag: `[BOUNDARY:fee_bps={val} -> effective_rate={computed_rate}]`

**Red flags**:
- Gross-up formulas: `amount * MAX / (MAX - fee)` charges effective rate of `fee/(MAX-fee)`, not `fee/MAX`. At 5% this is 5.26%, not 5%. Document whether this is intentional.
- Fee-on-fee: Does fee A's output feed into fee B's input? If so, the combined effective rate is not simply A + B.
- Rounding direction: In Move integer math, division truncates. `amount * fee / 10000` always rounds DOWN (favoring user). Check if protocol uses `(amount * fee + 9999) / 10000` for ceiling (favoring protocol).
- Precision loss: With `u64` at 1e8 scale (Aptos standard), do intermediate products overflow? `u64::MAX = 18.4e18`, so `amount * fee` overflows if both are large. Check for `u128` intermediate or `math::mul_div` usage.

### 4b. Fee Interaction Matrix

For protocols with multiple fee types:

| Fee A | Fee B | A Output Feeds B Input? | Combined Effective Rate | Independent Rate Sum | Discrepancy? |
|-------|-------|------------------------|------------------------|---------------------|-------------|

### 4c. Fee Impact on Share Price

If the protocol uses share-based accounting (vaults, LP tokens):
- After fee deduction: does the share price change?
- Does the fee mechanism create a spread between deposit and immediate withdrawal?
- Is the spread documented and within reasonable bounds?

### 4d. Fee-Base Consistency

For every fee computation, trace the base amount (the value the fee is computed on) through ALL subsequent code paths:

| Fee Site | Base Amount Variable | Modified After Fee? | Modified How | Fee Recomputed? | Overcharge? |
|----------|---------------------|--------------------:|-------------|-----------------|-------------|

**Methodology**:
- Identify the variable used as fee base (e.g., `amount`, `deposit_amount`)
- Trace that variable FORWARD from the fee computation to the end of the function
- If the variable is reduced (capped, downscaled, adjusted to remaining capacity, slippage-adjusted) AFTER the fee was computed -> the fee was charged on a larger base than what was actually used
- **Concrete test**: If `fee = amount * fee_rate / MAX`, then `amount` is reduced to `leftover` (e.g., remaining allocation), the user paid `fee` on `amount` but only `leftover` was processed -- overcharge of `fee * (1 - leftover/amount)`

## 5. Emission/Inflation Sustainability

For protocols with emission/inflation/rebase mechanics:

| Check | Value | Sustainable? | Impact if Unsustainable |
|-------|-------|-------------|----------------------|
| Max emission rate per day | {amount} | YES/NO | {impact} |
| Max emission rate per year | {amount} | YES/NO | {impact} |
| Supply cap exists? | YES/NO | N/A | {impact if no cap} |
| Can cap be bypassed by param changes? | YES/NO | N/A | {how} |
| Reward pool sufficient for emission schedule? | YES/NO | N/A | {what happens when depleted} |

**Aptos-specific emission checks**:
- Does the module use `timestamp::now_seconds()` for emission calculations? Verify time-based math is correct.
- Are emissions denominated in the correct decimal scale (1e8 for most Aptos tokens)?
- Can emission rate be set to drain reward pool in a single epoch/transaction?

## Instantiation Parameters
```
{CONTRACTS}              -- Move modules to analyze
{MONETARY_PARAMS}        -- Admin-settable economic parameters
{FEE_FUNCTIONS}          -- Functions containing fee calculations
{INVARIANTS}             -- Expected economic invariants
{EMISSION_MECHANICS}     -- Emission/inflation/rebase mechanics (if any)
```

## Finding Template

```markdown
**ID**: [ED-N]
**Severity**: [based on fund impact at boundary/extreme values]
**Step Execution**: checkmark1,2,3,4,5 | x(reasons) | ?(uncertain)
**Rules Applied**: [R10:Y, R14:Y]
**Location**: module::function:LineN
**Title**: [Parameter/invariant/fee] issue in [function] enables [attack/failure]
**Description**: [Specific economic design issue with concrete boundary values]
**Impact**: [Quantified impact at boundary conditions]
```

## Output Schema

| Field | Required | Description |
|-------|----------|-------------|
| parameter_boundaries | yes | All monetary parameters with min/max analysis |
| invariants | yes | Economic invariants and whether they can break |
| fee_verification | yes | Fee formula verification at normal values |
| interaction_matrix | yes | Parameter interaction analysis |
| finding | yes | CONFIRMED / REFUTED / CONTESTED |
| evidence | yes | Code locations with line numbers |
| step_execution | yes | Status for each step |

---

## Step Execution Checklist (MANDATORY)

| Section | Required | Completed? | Notes |
|---------|----------|------------|-------|
| 1. Parameter Boundary Analysis | YES | Y/N/? | |
| 2. Economic Invariant Identification | YES | Y/N/? | |
| 3. Rate/Supply Interaction Matrix | IF >1 monetary param | Y/N(N/A)/? | |
| 4a. Fee Formula Verification (concrete examples) | IF fee parameters detected | Y/N(N/A)/? | |
| 4b. Fee Interaction Matrix | IF multiple fee types | Y/N(N/A)/? | |
| 4c. Fee Impact on Share Price | IF share-based accounting | Y/N(N/A)/? | |
| 4d. Fee-Base Consistency | IF fee parameters detected | Y/N(N/A)/? | |
| 5. Emission/Inflation Sustainability | IF emission/rebase detected | Y/N(N/A)/? | |
