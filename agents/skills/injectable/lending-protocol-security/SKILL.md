---
name: "lending-protocol-security"
description: "Protocol Type Trigger lending (detected when recon finds liquidate|borrow|repay|collateral|lend|loan|LTV|healthFactor|interestRate|debtToken) - Inject Into Breadth agents, depth..."
---

# Injectable Skill: Lending Protocol Security

> **Protocol Type Trigger**: `lending` (detected when recon finds: liquidate|borrow|repay|collateral|lend|loan|LTV|healthFactor|interestRate|debtToken)
> **Inject Into**: Breadth agents, depth-token-flow, depth-edge-case, depth-state-trace
> **Language**: Language-agnostic methodology
> **Finding prefix**: `[LEND-N]`

## Orchestrator Decomposition Guide
When decomposing this skill into depth agent investigation questions, map sections to domains:
- Sections 1, 4: depth-edge-case (health factor boundaries, first borrower)
- Sections 2, 5: depth-state-trace (interest accrual, collateral state, pause mechanics)
- Sections 3, 3b, 3c: depth-token-flow (liquidation flows, bad debt socialization)
- Section 6: depth-external (oracle dependency for pricing)

## When This Skill Activates

Recon classifies protocol as `lending` type based on indicators: liquidate, borrow, repay, collateral, lend, loan, LTV, healthFactor, interestRate, debtToken, reserve, utilizationRate, debtShare.
This skill adds lending-specific checks that the general ECONOMIC_DESIGN_AUDIT does not cover.

---

## 1. Health Factor Boundary Analysis

### 1a. Health Factor Computation
Identify the health factor (HF) formula and trace each input:
- What is the formula? (typically: `HF = (collateralValue * liquidationThreshold) / debtValue`)
- How is `collateralValue` derived? (oracle price * collateral amount * collateral factor)
- How is `debtValue` derived? (oracle price * borrow amount including accrued interest)
- Is interest included in the HF check at the moment of the check, or from a stale snapshot?

Substitute boundary values into the formula:
| State | HF Value | Expected Behavior | Actual? |
|-------|----------|-------------------|---------|
| HF = 1.0 exactly | | Liquidation threshold - which side? | |
| HF = 1.0 + 1 wei | | Should NOT be liquidatable | |
| HF = 1.0 - 1 wei | | Should be liquidatable | |
| HF after max interest accrual | | Worst case between check intervals | |
| HF with dust collateral | | Liquidation gas > reward? | |

### 1b. Check-to-Execution Consistency
- Between HF check and liquidation execution: can any state change (oracle update, interest accrual, collateral deposit) alter the HF?
- If a user's borrow increases their debt: is HF re-checked atomically or can they borrow below HF=1.0?
- Can a user borrow, then in the same transaction, remove collateral before the HF check?

### 1c. Dust Position Economics
- What is the minimum borrow size? Is it enforced at creation AND after partial repayment?
- For positions where remaining debt < gas cost of liquidation: is there a mechanism to handle them? (minimum borrow, dust threshold, protocol liquidation)
- Can a borrower deliberately create a dust position to avoid liquidation?

Tag: `[BOUNDARY:HF={value} → liquidatable={YES/NO} → operator={>=/>}]`

---

## 2. Interest Accrual Correctness

### 2a. Accrual Timing
Identify the interest accrual mechanism and trace when it updates:
- Is interest accrued per-block, per-second, or on-demand (lazy accrual on interaction)?
- For lazy accrual: which functions trigger accrual? (borrow, repay, deposit, withdraw, liquidate)
- Can a user interact without triggering accrual? (view functions used for state-changing decisions)
- Is there a maximum time gap the accrual formula handles correctly? (overflow risk for long-dormant positions)

### 2b. Index Update Ordering
For index-based interest (where `debt = principal * currentIndex / borrowIndex`):
- Is the global interest index updated BEFORE or AFTER the user's balance change?
- If AFTER: the user's new balance accrues interest from the wrong base
- Trace the exact ordering: `accrueInterest() → updateIndex → updateUserBalance → updateUserIndex`
- If any step is out of order or conditional: flag for depth review

### 2c. Precision Loss
- Compound interest over many small intervals vs one large interval: is the result equivalent?
- For utilization-rate-based interest: does the utilization rate use pre- or post-operation values?
- Over 365 days of per-second compounding: does accumulated precision error become material? (compute concrete drift using the protocol's actual rate model constants)

### 2d. Pause-Interest Interaction
- During pause: does interest continue to accrue?
- If interest accrues during pause BUT repayment is blocked: borrowers accumulate debt they cannot repay, potentially becoming liquidatable upon unpause
- If interest does NOT accrue during pause: lenders lose yield for the paused period

Tag: `[TRACE:accrueInterest() → index_update_order={before/after} → user_balance_change → {correct/misordered}]`

---

## 3. Liquidation Mechanism Safety

### 3a. Liquidation Profitability
For the liquidation incentive structure:
- What is the liquidation bonus/discount? Is it configurable per asset?
- At what position size does liquidation become unprofitable after gas? (concrete calculation: bonus * seized_value - gas_cost)
- Is the liquidation bonus taken from the borrower's collateral or from a protocol reserve?
- Can the liquidation bonus exceed the remaining collateral? (over-incentivized liquidation = protocol loss)

### 3b. Partial vs Full Liquidation
- Is partial liquidation supported? What is the close factor (max % of debt repayable per liquidation)?
- Can the close factor be bypassed? (rounding, minimum amounts, or repeated calls in same tx)
- After partial liquidation: is the remaining position still healthy? (HF should improve, not worsen)
- Can an attacker force full liquidation by manipulating the position to make partial liquidation insufficient?

### 3c. Collateral Selection
- If a borrower has multiple collateral types: can the liquidator choose which to seize?
- Can cherry-picking the most valuable collateral leave the position with only low-quality collateral?
- Is there a priority ordering for collateral seizure? If so, who defines it?

### 3d. Front-Running Protection
- Can a borrower front-run liquidation by removing collateral or adding debt?
- Can a borrower front-run liquidation by repaying just enough to raise HF above threshold?
- Are there any callbacks during liquidation that the borrower's contract can intercept?

Tag: `[TRACE:liquidate(amount={X}) → bonus={Y} → seized_collateral={Z} → remaining_HF={value}]`

---

## 3b. Liquidation DoS Vectors

### Callback Reverts
- Does the liquidation path call any function on the borrower's address? (token transfer hooks, onReceive callbacks)
- If the borrower is a contract: can it revert in a callback to block liquidation?
- Does the liquidation path use try/catch or pull-pattern to isolate borrower behavior?

### Token Blocklist Interaction
- If collateral or debt tokens have blocklist functionality (USDC, USDT): can a blocklisted borrower prevent liquidation?
- Pattern: borrower gets blocklisted → liquidator cannot receive seized collateral → liquidation reverts
- Is there a fallback path (escrow, protocol seizure) for blocklisted positions?

### Gas Bounds
- If liquidation iterates over the borrower's assets: is the iteration bounded?
- Can a borrower with many small collateral positions make liquidation exceed block gas limit?
- Are there maximum asset count limits per position?

### Reentrancy Guard Conflicts
- If liquidation acquires a reentrancy lock: do any internal calls (token transfers, oracle reads) also require the same lock?
- Pattern: liquidate() → nonReentrant → internal transfer → callback → another protocol function → same nonReentrant → revert

Tag: `[TRACE:liquidate() → callback_to_borrower={YES/NO} → revert_possible={YES/NO} → fallback={exists/missing}]`

---

## 3c. Bad Debt Socialization

### Bad Debt Detection
- What happens when a position's debt exceeds its collateral value? (underwater position)
- Is bad debt detected automatically or does it require manual trigger?
- Can bad debt exist silently (no revert, no event) while corrupting the pool's accounting?

### Socialization Mechanism
Trace the bad debt absorption path in order:
1. Is there an insurance fund or reserve? What fills it? (liquidation fees, protocol revenue)
2. If insurance is exhausted: is bad debt spread across all lenders? (share price reduction, or explicit socialization call)
3. Is there a protocol backstop? (treasury injection, governance action)
4. What is the ordering? (insurance → socialization → backstop)

### Bad Debt Amplification
- Can bad debt be created faster than the socialization mechanism can process it?
- During a cascade (multiple positions liquidated simultaneously): does each liquidation's bad debt compound?
- If the debt token accrues interest: does bad debt also accrue interest? (phantom interest on unrecoverable debt)

Tag: `[TRACE:position_underwater → insurance_fund={sufficient/exhausted} → socialization={mechanism} → lender_loss={amount}]`

---

## 4. Collateral Factor Manipulation

### 4a. Retroactive Factor Changes
- When admin changes collateral factor (LTV ratio): does it affect existing positions immediately?
- If immediate: can existing healthy positions become instantly liquidatable?
- Is there a buffer period or grace period for borrowers to adjust after factor changes?
- Is there a maximum single-step change (e.g., can factor go from 80% to 0% in one tx)?

### 4b. Boundary Positions
- For positions at exactly the collateral factor boundary: does a factor reduction by 1 bps make them liquidatable?
- Substitute concrete values: position with 80% LTV at 80% collateral factor → factor reduced to 79% → position immediately unhealthy
- Is there a notification mechanism or delay that protects these boundary positions?

Tag: `[VARIATION:collateralFactor 80%→79% → positions_at_80%_LTV → instantly_liquidatable={YES/NO}]`

---

## 5. Asymmetric Pause Analysis

### 5a. Pause Granularity
Enumerate all pausable functions and their pause groupings:
| Function | Pause Group | Paused Independently? |
|----------|-------------|----------------------|
| deposit | | |
| withdraw | | |
| borrow | | |
| repay | | |
| liquidate | | |

### 5b. Dangerous Asymmetries
Check for these specific asymmetric pause states:
- **Repay paused, liquidation active**: Borrowers cannot repay but can be liquidated (interest accrues, HF drops, user has no recourse)
- **Borrow paused, repay active**: Safe asymmetry (users can reduce risk but not increase it)
- **Withdraw paused, deposit active**: Users can add funds but cannot exit (potential trap)
- **Liquidation paused, interest active**: Underwater positions grow worse with no resolution

### 5c. Post-Unpause Grace Period
- After unpausing: is there a delay before liquidations can execute?
- If no delay: positions that became liquidatable during pause are immediately seized upon unpause
- Is there a mechanism to let borrowers repay before liquidators act? (repay-first window)

Tag: `[TRACE:pause(repay) → interest_accrues={YES/NO} → liquidation_active={YES/NO} → borrower_recourse={YES/NO}]`

---

## 6. Oracle Dependency for Pricing

> Cross-reference with ORACLE_ANALYSIS skill for general oracle checks. This section covers lending-specific oracle concerns only.

### 6a. Price-Token Matching
- Does the oracle price correspond to the EXACT token used as collateral/debt? (not a wrapper, not an underlying)
- For rebasing tokens or interest-bearing tokens: is the oracle price adjusted for the rebase/interest?
- For LP tokens used as collateral: how is the LP token priced? (underlying reserves * oracle prices, or direct LP oracle?)

### 6b. Stale Oracle Impact on Liquidation
- If the oracle returns a stale price: can liquidation proceed with outdated prices?
- If a staleness check reverts: does liquidation revert too? (stale oracle = liquidation DoS)
- Is there a fallback oracle for liquidation-critical price feeds?

### 6c. Self-Liquidation via Oracle Manipulation
- Can a borrower manipulate the oracle to inflate their collateral value, borrow maximum, then let the oracle correct?
- Can a liquidator manipulate the oracle to make a healthy position appear liquidatable?
- For oracle-based liquidation bonus: can the bonus be manipulated via price feeds?

Tag: `[TRACE:oracle_price={source} → token_match={exact/wrapper/underlying} → stale_revert_blocks_liquidation={YES/NO}]`

---

## Common False Positives
- **Admin-controlled collateral factor changes with timelock**: Retroactive effect is by design when timelock gives users notice period to adjust positions
- **Interest accrual paused during emergency pause IF repayment is also paused**: Symmetric pause - neither debt nor repayment ability changes
- **Dust positions below minimum borrow size**: If minimum borrow is enforced at creation AND after partial repayment, dust positions cannot be created by users
- **Liquidation bonus exceeding collateral for tiny positions**: If minimum borrow size prevents tiny positions, the economics are safe for all valid positions
- **Oracle staleness check reverting liquidation**: If a fallback oracle exists and is used when primary is stale, liquidation is not blocked

## Step Execution Checklist (MANDATORY)

| Section | Required | Completed? | Notes |
|---------|----------|------------|-------|
| 1. Health Factor Boundary Analysis | YES | | HF computation, boundaries, dust economics |
| 2. Interest Accrual Correctness | YES | | Timing, index ordering, precision, pause interaction |
| 3. Liquidation Mechanism Safety | YES | | Profitability, partial/full, collateral selection, front-running |
| 3b. Liquidation DoS Vectors | YES | | Callbacks, blocklists, gas bounds, reentrancy conflicts |
| 3c. Bad Debt Socialization | YES | | Detection, socialization mechanism, amplification |
| 4. Collateral Factor Manipulation | IF admin-configurable factors | | Retroactive changes, boundary positions |
| 5. Asymmetric Pause Analysis | IF pause mechanism detected | | Pause granularity, dangerous asymmetries, grace period |
| 6. Oracle Dependency for Pricing | IF oracle integration detected | | Price-token matching, stale oracle, self-liquidation |
