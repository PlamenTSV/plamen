---
name: "economic-design-audit"
description: "Trigger Pattern MONETARY_PARAMETER flag (required) - Inject Into Breadth agents (merged via M4 hierarchy)"
---

# Skill: Economic Design Audit (Solana)

> **Trigger Pattern**: MONETARY_PARAMETER flag (required)
> **Inject Into**: Breadth agents (merged via M4 hierarchy)
> **Finding prefix**: `[EDA-N]`
> **Rules referenced**: S1, S4, S9, R2, R10, R13, R14

```
rate|rebase|supply|mint_authority|burn|emission|inflation|peg|price.*cap|price.*floor|
fee|reward.*rate|basis_points|bps
```

## 1. Parameter Boundary Analysis

For every monetary parameter setter (rate, fee, reward rate, emission, cap, floor, BPS values):

| Parameter | Setter Instruction | Min Value | Max Value | Enforced? | Impact at Min | Impact at Max |
|-----------|-------------------|-----------|-----------|-----------|---------------|---------------|

For each parameter: substitute min and max into ALL consuming instructions.
Tag: `[BOUNDARY:param=val -> outcome]`

**Solana-specific boundary checks**:
- Does a parameter at MAX cause arithmetic overflow in `u64`/`u128` operations? (Solana uses Rust's checked math by default in debug, but `unchecked_*` or release mode may overflow silently)
- Does a parameter at 0 cause division-by-zero panics? (Solana programs abort on panic -- entire transaction fails)
- Does a fee parameter at MAX (e.g., 10000 BPS = 100%) cause the user to receive 0 tokens?

## 2. Economic Invariant Identification

List all economic invariants the protocol must maintain:

| Invariant | Parameters Involved | Can Authority Break It? | Instructions That Assume It |
|-----------|--------------------|-----------------------|---------------------------|

For each setter: can changing this parameter break an invariant that user-facing instructions depend on? If yes -> finding.

**Solana-specific invariants**:
- **Lamport conservation**: Total lamports in program-owned accounts must be conserved across instructions (Solana runtime enforces this per-instruction, but multi-instruction sequences can violate economic invariants)
- **Mint supply == sum of token account balances**: If program has mint authority, can minting break supply-tracking invariants?
- **Rent-exempt minimums**: Parameter changes that reduce account sizes may violate rent-exempt requirements, making accounts eligible for garbage collection

## 3. Rate/Supply Interaction Matrix

For protocols with multiple monetary parameters that interact:

| Parameter A | Parameter B | Interaction | Can A x B Produce Extreme Output? |
|-------------|-----------|-------------|----------------------------------|

Check: can two independently-valid parameter settings combine to create an extreme or invalid economic state? (Rule 14 constraint coherence)

**Example**: `reward_rate_bps = 5000` (valid alone) and `boost_multiplier = 20` (valid alone) combine to `effective_rate = 100000 BPS = 1000%`, draining the reward vault in one epoch.

## 4. Fee Formula Verification at Normal Values

For every fee-related computation (fee calculation, fee deduction, fee distribution):

### 4a. Concrete Example Computation
Pick 3 representative fee rates (e.g., 1% = 100 BPS, 5% = 500 BPS, 10% = 1000 BPS) and trace through the actual code formula:

| Fee Param | Value | Formula | Input Amount | Expected Output | Actual Output | Match? |
|-----------|-------|---------|-------------|----------------|---------------|--------|
| {fee_bps} | 100 | {code formula} | 10000 | {expected} | {computed} | YES/NO |
| {fee_bps} | 500 | {code formula} | 10000 | {expected} | {computed} | YES/NO |
| {fee_bps} | 1000 | {code formula} | 10000 | {expected} | {computed} | YES/NO |

Tag: `[BOUNDARY:fee_bps={val} → effective_rate={computed_rate}]`

**Red flags**:
- Gross-up formulas: `amount * MAX / (MAX - fee)` charges effective rate of `fee/(MAX-fee)`, not `fee/MAX`. At 5% this is 5.26%, not 5%. Document whether this is intentional.
- Fee-on-fee: Does fee A's output feed into fee B's input? If so, the combined effective rate is not simply A + B.
- Rounding direction: Does rounding favor the protocol or the user? For fee deductions, rounding UP (ceiling) favors the protocol.

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
If the protocol uses share-based accounting:
- After fee deduction: does the share price change?
- Does the fee mechanism create a spread between deposit and immediate withdrawal?
- Is the spread documented and within reasonable bounds?

## 5. Emission/Inflation Sustainability

For protocols with emission/inflation/reward distribution mechanics:

- What is the maximum emission rate over 1 epoch / 1 day / 1 year?
- Can emissions exceed the reward vault's SOL/token balance?
- Is there a supply cap on the mint? Can the authority bypass it?
- What happens when the reward vault is depleted? (revert? zero rewards? proportional reduction?)

| Emission Parameter | Max Rate | Vault Balance Required | Time to Depletion at Max | Cap Exists? |
|-------------------|----------|----------------------|------------------------|-------------|

## 6. Compute Unit Cost Modeling

For batch operations (mass distributions, multi-user updates, reward claims):

| Operation | Per-User CU Cost | Users at Design Limit | Total CU | Exceeds 1.4M Limit? | Exceeds 200k/Ix Limit? |
|-----------|-----------------|----------------------|----------|---------------------|----------------------|

**Solana-specific cost analysis**:
- Per-transaction CU limit: 1,400,000 (1.4M)
- Per-instruction CU limit: 200,000 default (can request up to 1.4M with `set_compute_unit_limit`)
- Each account access: ~100-200 CU; each CPI: ~1000-5000 CU; each SHA256: ~100 CU per 64 bytes
- **Priority fee dynamics**: During congestion, priority fees can spike 100-1000x. Model whether time-sensitive operations (liquidations, rebalances, crank actions) remain economically viable during congestion.
- Can an attacker spam the network to make crank operations uneconomical?

## 7. Rent and Account Creation Economics

For protocols that create accounts on behalf of users:

| Account Type | Size (bytes) | Rent-Exempt Cost (SOL) | Who Pays | Max Accounts at Design Limit | Total Rent Cost |
|-------------|-------------|----------------------|----------|----------------------------|----------------|

**Checks**:
- Can an attacker force excessive account creation to drain protocol SOL? (e.g., creating reward claim accounts for non-existent users)
- Are account creation costs passed to users or absorbed by the protocol?
- If protocol absorbs cost: what is the total cost at design limit? Does the protocol hold enough SOL?
- Can accounts be closed to reclaim rent? Who receives the lamports?
- **Account creation griefing**: Can a user create Associated Token Accounts or PDA accounts that the protocol must later interact with, forcing the protocol to pay rent for accounts it did not intend to create?

## Finding Template

```markdown
**ID**: [EDA-N]
**Verdict**: CONFIRMED / PARTIAL / REFUTED / CONTESTED
**Step Execution**: (see checklist below)
**Rules Applied**: [S1:___, S4:___, S9:___, R2:___, R10:___, R13:___, R14:___]
**Severity**: Critical/High/Medium/Low/Info
**Location**: programs/{program}/src/{file}.rs:LineN
**Title**: {parameter boundary violation / invariant break / economic unsustainability}
**Description**: {specific issue with code reference and numerical example}
**Impact**: {quantified at worst-state operational parameters -- Rule 10}
```

---

## Step Execution Checklist (MANDATORY)

| Section | Required | Completed? | Notes |
|---------|----------|------------|-------|
| 1. Parameter Boundary Analysis | YES | | |
| 2. Economic Invariant Identification | YES | | |
| 3. Rate/Supply Interaction Matrix | IF >1 monetary param | | |
| 4. Fee Formula Verification at Normal Values | IF fee parameters detected | | |
| 5. Emission/Inflation Sustainability | IF emission/reward detected | | |
| 6. Compute Unit Cost Modeling | YES | | |
| 7. Rent and Account Creation Economics | IF protocol creates accounts | | |

If any step skipped, document valid reason (N/A, single parameter, no emissions, no account creation).
