---
name: "economic-design-audit"
description: "Trigger Pattern MONETARY_PARAMETER flag (required) - Inject Into Breadth agents (merged via M4 hierarchy)"
---

# ECONOMIC_DESIGN_AUDIT Skill (Sui)

> **Trigger Pattern**: MONETARY_PARAMETER flag (required)
> **Inject Into**: Breadth agents (merged via M4 hierarchy)
> **Purpose**: Analyze economic design of monetary parameters in Sui Move protocols for boundary violations, invariant breaks, and fee formula errors

For every monetary parameter setter (rate, supply, mint, burn, emission, inflation,
peg, price cap/floor, fee, reward rate) in the protocol:

## 1. Parameter Boundary Analysis

Enumerate all admin-settable monetary parameters stored in shared config objects:

| Parameter | Setter Function | Required Cap | Min Value | Max Value | Enforced? | Impact at Min | Impact at Max |
|-----------|----------------|-------------|-----------|-----------|-----------|---------------|---------------|
| {param} | {module::set_param} | {AdminCap} | {min} | {max} | {YES/NO} | {trace impact} | {trace impact} |

For each parameter: substitute min and max into ALL consuming functions.
Tag: [BOUNDARY:param=val -> outcome]

**Sui-specific**: Parameters are typically stored in shared objects (e.g., `Config`, `Registry`, `Pool`). Check:
- Are bounds enforced in the setter function? (`assert!(value >= MIN && value <= MAX)`)
- Can the setter bypass bounds? (e.g., separate `force_set` function)
- Are bounds hardcoded or stored (and themselves admin-settable)?

**Move arithmetic model**: Move uses unsigned integers only (`u8`, `u64`, `u128`, `u256`). No native BPS type.
- `u64` max: 18,446,744,073,709,551,615 (~1.8e19). SUI has 9 decimals, so max `u64` represents ~18.4 billion SUI.
- Overflow: Move aborts on arithmetic overflow/underflow by default (no silent wrapping). An overflow in a fee calculation aborts the entire transaction.
- Division by zero: Move aborts. Check all divisions where divisor is a parameter or derived from state.
- `amount * fee_bps` where amount is large: e.g., 1e18 * 10000 = 1e22 which OVERFLOWS u64. Check for `u128` intermediate casts.

## 2. Economic Invariant Identification

List all economic invariants the protocol must maintain:

| Invariant | Parameters Involved | Can Admin Break It? | Functions That Assume It |
|-----------|-------------------|--------------------|-----------------------|
| total_supply == sum(user_balances) | supply, balances | {YES/NO via mint/burn cap} | {list} |
| fee_rate <= MAX_FEE | fee_rate, MAX_FEE | {YES/NO} | {list} |
| collateral_value >= debt_value | collateral_ratio, prices | {YES/NO via param change} | {list} |

For each setter: can changing this parameter break an invariant that user-facing
functions depend on? If yes -> finding.

**Sui invariant patterns**:
- `TreasuryCap<T>` controls minting -- does unlimited minting break a peg or backing invariant?
- Shared pool balances must satisfy: `balance::value(&pool.token_a) * balance::value(&pool.token_b) >= k` (AMM invariant)
- Vault invariant: `total_shares * price_per_share <= total_assets` (no unbacked shares)

## 3. Rate/Supply Interaction Matrix

For protocols with multiple monetary parameters that interact:

| Parameter A | Parameter B | Interaction | Can A*B Produce Extreme Output? |
|-------------|-------------|-------------|--------------------------------|
| {reward_rate} | {total_supply} | reward_per_token = rate / supply | YES if supply -> 0 while rate > 0 |
| {fee_rate_A} | {fee_rate_B} | compound fee = A then B | YES if both at max -> excessive total fee |
| {mint_cap} | {burn_rate} | net supply = minted - burned | YES if mint >> burn -> inflation spiral |

Check: can two independently-valid parameter settings combine to create an
extreme or invalid economic state? (Rule 14 constraint coherence)

**Sui-specific interactions**:
- `TreasuryCap` mint + admin fee rate: can mint + fee combine to extract more than pool holds?
- Epoch-based emission + stake/unstake delay: can users game emission timing around epoch boundaries?

## 4. Fee Formula Verification at Normal Values

For every fee-related computation (fee calculation, fee deduction, fee distribution):

### 4a. Concrete Example Computation
Pick 3 representative fee rates (e.g., 1% = 100 BPS, 5% = 500 BPS, 10% = 1000 BPS) and trace through the actual code formula:

| Fee Param | Value | Formula | Input Amount | Expected Output | Actual Output | Match? |
|-----------|-------|---------|-------------|----------------|---------------|--------|
| {fee_bps} | 100 | {code formula} | 1_000_000_000 | {expected} | {computed} | YES/NO |
| {fee_bps} | 500 | {code formula} | 1_000_000_000 | {expected} | {computed} | YES/NO |
| {fee_bps} | 1000 | {code formula} | 1_000_000_000 | {expected} | {computed} | YES/NO |

Tag: `[BOUNDARY:fee_bps={val} -> effective_rate={computed_rate}]`

**Red flags**:
- Gross-up formulas: `amount * MAX / (MAX - fee)` charges effective rate of `fee/(MAX-fee)`, not `fee/MAX`. At 5% this is 5.26%, not 5%. Document whether this is intentional.
- Fee-on-fee: Does fee A's output feed into fee B's input? If so, the combined effective rate is not simply A + B.
- Rounding direction: In Sui Move, integer division truncates (rounds toward zero). Does this favor the protocol or the user? For fee deductions, `amount * fee / MAX` rounds down (user-favorable). Is `(amount * fee + MAX - 1) / MAX` used for protocol-favorable rounding?
- Precision loss: With `u64` math, do intermediate products overflow? Sui Move aborts on overflow -- is `u128` used for intermediate calculations? Check for `(amount as u128) * (fee as u128) / (MAX as u128)` patterns.
- **Gas budget constraint**: Sui transaction gas budget cap is 50 SUI (~50 billion MIST). If fee computation involves iteration, dynamic field traversal, or complex math, can gas exhaustion prevent fee collection or cause user transactions to fail? Check: are there unbounded loops in fee distribution paths?

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
- If the variable is reduced (capped, downscaled, adjusted to remaining capacity) AFTER the fee was computed -> the fee was charged on a larger base than what was actually used
- **Concrete test**: If `fee = amount * fee_rate / MAX`, then `amount` is reduced to `leftover` (e.g., remaining allocation), the user paid `fee` on `amount` but only `leftover` was processed -- overcharge of `fee * (1 - leftover/amount)`

## 5. Emission/Inflation Sustainability

For protocols with emission/inflation/rebase mechanics:

| Emission Param | Max Rate | Over 1 Day | Over 1 Week | Over 1 Year | Sustainable? |
|---------------|---------|-----------|------------|------------|-------------|
| {reward_rate} | {max} | {computed} | {computed} | {computed} | {analysis} |

- What is the maximum emission rate over 1 day / 1 week / 1 year?
- Can emissions exceed the protocol's capacity to back them?
- Is there a supply cap enforced by `TreasuryCap` or explicit checks? Can it be bypassed by parameter changes?
- **Epoch-based emissions**: If rewards are distributed per epoch (~24h on Sui), can reward pool be drained faster than replenished?

## Finding Template

```markdown
**ID**: [ED-N]
**Severity**: [based on fund impact and parameter reachability]
**Step Execution**: check1,2,3,4,5 | x(reasons) | ?(uncertain)
**Rules Applied**: [R10:check, R14:check]
**Location**: module::function:LineN
**Title**: [Parameter/invariant issue] in [function] enables [impact]
**Description**: [Specific economic design issue with parameter trace]
**Impact**: [Quantified impact at boundary values]
```

## Instantiation Parameters
```
{CONTRACTS}           -- Move modules to analyze
{CONFIG_OBJECTS}      -- Shared config/registry objects
{MONETARY_PARAMS}     -- Admin-settable monetary parameters
{FEE_FUNCTIONS}       -- Functions computing or deducting fees
{INVARIANTS}          -- Known economic invariants
{EMISSION_PARAMS}     -- Emission/inflation parameters
{CAP_TYPES}           -- Capability types required for parameter changes
```

## Output Schema
| Field | Required | Description |
|-------|----------|-------------|
| parameter_boundaries | yes | All monetary params with min/max analysis |
| invariants | yes | Economic invariants and breakability |
| interaction_matrix | yes | Cross-parameter interactions |
| fee_verification | yes | Fee formula correctness at normal values |
| finding | yes | CONFIRMED / REFUTED / CONTESTED |
| evidence | yes | Code locations with line numbers |
| step_execution | yes | Status for each step |

---

## Step Execution Checklist (MANDATORY)

| Section | Required | Completed? |
|---------|----------|------------|
| 1. Parameter Boundary Analysis | YES | Y/N/? |
| 2. Economic Invariant Identification | YES | Y/N/? |
| 3. Rate/Supply Interaction Matrix | IF >1 monetary param | Y/N(N/A)/? |
| 4. Fee Formula Verification at Normal Values | IF fee parameters detected | Y/N(N/A)/? |
| 4d. Fee-Base Consistency | IF fee parameters detected | Y/N(N/A)/? |
| 5. Emission/Inflation Sustainability | IF emission/rebase detected | Y/N(N/A)/? |
