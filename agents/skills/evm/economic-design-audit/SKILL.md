---
name: "economic-design-audit"
description: "Trigger Pattern MONETARY_PARAMETER flag (required) - Inject Into Breadth agents (merged via M6 hierarchy)"
---

# ECONOMIC_DESIGN_AUDIT Skill

> **Trigger Pattern**: MONETARY_PARAMETER flag (required)
> **Inject Into**: Breadth agents (merged via M6 hierarchy)

For every monetary parameter setter (rate, rebase, supply, mint, burn, emission, inflation,
peg, price cap/floor, fee, reward rate) in the protocol:

## 1. Parameter Boundary Analysis

| Parameter | Setter | Min Value | Max Value | Enforced? | Impact at Min | Impact at Max |
|-----------|--------|-----------|-----------|-----------|---------------|---------------|

For each parameter: substitute min and max into ALL consuming functions.
Tag: [BOUNDARY:param=val -> outcome]

## 2. Economic Invariant Identification

List all economic invariants the protocol must maintain:
| Invariant | Parameters Involved | Can Admin Break It? | Functions That Assume It |

For each setter: can changing this parameter break an invariant that user-facing
functions depend on? If yes -> finding.

## 3. Rate/Supply Interaction Matrix

For protocols with multiple monetary parameters that interact:
| Parameter A | Parameter B | Interaction | Can A*B Produce Extreme Output? |

Check: can two independently-valid parameter settings combine to create an
extreme or invalid economic state? (Rule 14 constraint coherence)

## 4. Fee Formula Verification at Normal Values

For every fee-related computation (fee calculation, fee deduction, fee distribution):

### 4a. Concrete Example Computation
Pick 3 representative fee rates (e.g., 1% = 100 BPS, 5% = 500 BPS, 10% = 1000 BPS) and trace through the actual code formula:

| Fee Param | Value | Formula | Input Amount | Expected Output | Actual Output | Match? |
|-----------|-------|---------|-------------|----------------|---------------|--------|
| {fee_bps} | 100 | {code formula} | 1e18 | {expected} | {computed} | YES/NO |
| {fee_bps} | 500 | {code formula} | 1e18 | {expected} | {computed} | YES/NO |
| {fee_bps} | 1000 | {code formula} | 1e18 | {expected} | {computed} | YES/NO |

Tag: `[BOUNDARY:fee_bps={val} → effective_rate={computed_rate}]`

**Red flags**:
- Gross-up formulas: `amount * MAX / (MAX - fee)` charges effective rate of `fee/(MAX-fee)`, not `fee/MAX`. At 5% this is 5.26%, not 5%. Document whether this is intentional.
- Fee-on-fee: Does fee A's output feed into fee B's input? If so, the combined effective rate is not simply A + B.
- Rounding direction: Does rounding favor the protocol or the user? For fee deductions, rounding UP (ceiling via `mulDivUp` or equivalent) favors the protocol.
- Precision loss: With `uint256` math at `1e18` scale, do intermediate products overflow or lose precision? Check `mulDiv` ordering.

### 4d. Fee-Base Consistency
For every fee computation, trace the base amount (the value the fee is computed on) through ALL subsequent code paths:

| Fee Site | Base Amount Variable | Modified After Fee? | Modified How | Fee Recomputed? | Overcharge? |
|----------|---------------------|--------------------:|-------------|-----------------|-------------|

**Methodology**:
- Identify the variable used as fee base (e.g., `amount`, `depositAmount`)
- Trace that variable FORWARD from the fee computation to the end of the function
- If the variable is reduced (capped, downscaled, adjusted to remaining capacity, slippage-adjusted) AFTER the fee was computed → the fee was charged on a larger base than what was actually used
- **Concrete test**: If `fee = amount * feeRate / MAX`, then `amount` is reduced to `leftover` (e.g., remaining allocation), the user paid `fee` on `amount` but only `leftover` was processed - overcharge of `fee * (1 - leftover/amount)`

### 4b. Fee Interaction Matrix
For protocols with multiple fee types:

| Fee A | Fee B | A Output Feeds B Input? | Combined Effective Rate | Independent Rate Sum | Discrepancy? |
|-------|-------|------------------------|------------------------|---------------------|-------------|

### 4c. Fee Impact on Share Price
If the protocol uses share-based accounting (ERC4626 vaults, LP tokens):
- After fee deduction: does the share price change?
- Does the fee mechanism create a spread between deposit and immediate withdrawal?
- Is the spread documented and within reasonable bounds?

## 5. Emission/Inflation Sustainability

For protocols with emission/inflation/rebase mechanics:
- What is the maximum emission rate over 1 day / 1 week / 1 year?
- Can emissions exceed the protocol's capacity to back them?
- Is there a supply cap? Can it be bypassed by parameter changes?

## Step Execution Checklist
| Section | Required | Completed? |
|---------|----------|------------|
| 1. Parameter Boundary Analysis | YES | Y/N/? |
| 2. Economic Invariant Identification | YES | Y/N/? |
| 3. Rate/Supply Interaction Matrix | IF >1 monetary param | Y/N(N/A)/? |
| 4. Fee Formula Verification at Normal Values | IF fee parameters detected | Y/N(N/A)/? |
| 5. Emission/Inflation Sustainability | IF emission/rebase detected | Y/N(N/A)/? |
