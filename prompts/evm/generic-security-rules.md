# Generic Security Rules

> **Usage**: Analysis agents and depth agents reference these rules during analysis.
> These rules apply to ALL protocols regardless of type.

---

## Rule 1: External Call Return Type Verification

**Pattern**: Any external call that returns tokens or values
**Check**: Does the ACTUAL return type match what the protocol EXPECTS?

| Mismatch Type | Example | Impact |
|---------------|---------|--------|
| Legacy vs upgraded | Token V1 → V2 after migration | Wrong token processed |
| Native vs wrapped | ETH vs WETH | Transfer failures, accounting errors |
| Bridged vs canonical | Bridged USDC vs native USDC | Incorrect balances |
| Different decimals | USDC (6) vs DAI (18) | Arithmetic overflow/underflow |

**Action**: For every external call returning tokens, trace what token the external contract ACTUALLY returns in production.

---

## Rule 2: Function Preconditions Are Griefable

**Pattern**: Any function (admin, keeper, OR permissionless) with preconditions based on externally-manipulable state
**Check**: Can external actors manipulate state to make the precondition fail or succeed at the wrong time?

```solidity
function keeperAction() external onlyKeeper {
    require(balance > threshold, "insufficient");  // USER CAN DRAIN TO GRIEF
    ...
}
```

This includes:
- Admin/keeper functions with user-manipulable preconditions (original scope)
- **Permissionless functions with oracle-dependent preconditions** (e.g., rebase requires TWAP > threshold - can TWAP be manipulated via flashloan?)
- **Permissionless functions with balance-dependent preconditions** (e.g., function requires contract balance > X - can donations trigger it?)

**Action**: For every function with a precondition, identify whether the precondition state can be manipulated by:
1. Direct user action (deposit/withdraw/transfer)
2. Flashloan-assisted manipulation (borrow → manipulate → call → repay in one tx)
3. Donation (unsolicited token transfer changing balanceOf)

**Direction 2 - Admin action impacts on user functions**: For every admin setter that modifies a parameter used in user-facing function preconditions or logic:
4. Can an admin parameter change make a user-facing function behave unexpectedly? (e.g., setting `cooldownPeriod = 0` removes timing protection, setting `maxDeviation = 0` disables oracle bounds)
5. Does the admin change retroactively affect users in active positions? (e.g., changing withdrawal delay while users are mid-withdrawal)

---

## Rule 3: Transfer Side Effects

**Pattern**: Any transfer()/transferFrom() to/from external token contracts
**Check**: Does the transfer trigger side effects?

Token types requiring this check:
- Yield-bearing tokens (stETH, aTokens, cTokens)
- Staking receipt tokens (validator shares, LP tokens)
- Rebasing tokens (OHM, AMPL)
- Tokens with transfer hooks (ERC777, ERC1363)

**Mandatory check**: What happens on `transfer()`?
- [ ] Claims pending rewards?
- [ ] Updates internal accounting?
- [ ] Triggers rebase calculation?
- [ ] Calls receiver hook?

**Output requirement** (in attack_surface.md Token Flow Matrix):
| Token | On-Transfer Side Effect | Documented? | Verified in Production? |
|-------|------------------------|-------------|------------------------|

---

## Rule 4: Uncertainty Handling (CONTESTED + Adversarial Assumption)

**CONTESTED is a TRIGGER, not a TERMINAL state.**

When marking any finding as CONTESTED:
1. **Enumerate**: List ALL plausible external behaviors (Scenario A, B, C...)
2. **Assess**: For each scenario, what's the severity IF that behavior is true?
3. **Escalate**: If ANY scenario results in HIGH/CRITICAL → flag for production verification
4. **Default**: Use WORST-CASE severity until production behavior is verified

**For any external contract behavior that is UNKNOWN, assume adversarial:**
1. Assume the behavior that causes MAXIMUM harm
2. Produce an impact trace for the adversarial case
3. Mark as CONDITIONAL until production verified
4. Cannot REFUTE based on mock behavior or documentation alone

**Workflow integration**:
- CONTESTED findings receive same verification priority as HIGH findings
- CONTESTED findings trigger production verification checkpoint (Step 4a.5)
- Cannot downgrade CONTESTED to REFUTED without production evidence

---

## Rule 5: Combinatorial Impact Analysis

**For protocols managing N similar entities, analyze cumulative impact.**

When protocol manages multiple validators, pools, vaults, or markets:

**Mandatory analysis**:
1. **Single-entity impact**: What's the impact on ONE entity?
2. **N-entity cumulative**: What's N × single_impact? (check if capped by constraints)
3. **Time-compound**: What's N × impact × T? (check for accumulation over time)

**Thresholds**:
- If N ≥ 10 AND cumulative impact > $1,000 → analyze further
- If N × dust > withdrawal_threshold → flag as potential griefing vector

---

## Rule 6: Semi-Trusted Role Bidirectional Analysis

**For any automated role, analyze BOTH directions.**

**Direction 1**: How can ROLE harm USERS?
- Timing attacks (front-running user transactions)
- Parameter manipulation (choosing worst values)
- Omission (failing to execute when needed)

**Direction 2**: How can USERS exploit ROLE?
- Front-run predictable keeper actions
- Grief preconditions to block keeper
- Force suboptimal keeper decisions

**Both directions are equally important. Do NOT stop at Direction 1.**

---

## Rule 7: Donation-Based DoS via Threshold Manipulation

**Pattern**: Protocol has thresholds that determine operational capability
**Check**: Can donations manipulate thresholds to block operations?

**Attack vectors**:
1. **Below-threshold injection**: Keep balance under required minimum
2. **Above-threshold injection**: Push balance over maximum to block removal
3. **Governance quorum manipulation**: Donate to shift voting power
4. **Counter-based gate inflation**: For every counter-based gate (e.g., `count >= minimum`), check: can entries be added that increment the counter but contribute zero/negligible value to the guarded computation? If yes, the gate passes but the computation it guards produces a meaningless or manipulable result. Example: TWAP requiring `validSnapshots >= 2` but accepting snapshots with `weight = 0`, making the TWAP computable from effectively 1 real data point.

**Action**: For every operational threshold, check if external donations can manipulate it to cause denial of service. For every counter-based gate, check if zero-value entries can satisfy the count requirement while undermining the guarded computation's integrity.

---

## Rule 8: Cached Parameters in Multi-Step Operations

**Pattern**: Operation spans multiple transactions with cached initial state
**Check**: Can parameters change between operation start and completion?

**Attack vectors**:
1. **Epoch staleness**: Cache epoch at start, governance changes duration mid-operation
2. **Rate staleness**: Cache exchange rate, rate updates before claim completes
3. **Delay manipulation**: Cache delay value, delay changed before execution
4. **External state staleness**: External state (ownership, approval, delegation, contract status) validated at one entry point, stored, and relied upon at a later entry point without re-verification. The external state may change between the two calls.

**Action**: For multi-step operations (request → wait → claim) AND for any function that stores a snapshot of external state, verify all cached/stored state remains valid or is re-validated at each subsequent consumption point.

---

## Rule 9: Stranded Asset Severity Floor

**Pattern**: Assets held by the protocol with no exit path after upgrade, migration, or state change
**Check**: Can ALL asset types the protocol holds be recovered?

**Severity floor enforcement**:
- If NO recovery path exists (no sweep, no admin rescue, no migration function) AND assets are currently held → minimum **MEDIUM**
- If NO recovery path AND amount > $10,000 at protocol scale → minimum **HIGH**
- If assets are theoretical only (not yet held) → standard severity matrix applies

**Mandatory analysis for upgrade/migration protocols**:

| Step | Check | If Failed |
|------|-------|-----------|
| 1 | Inventory ALL asset types held pre-upgrade | Coverage gap |
| 2 | Does post-upgrade logic handle each asset type? | Check step 3 |
| 3 | Recovery function exists? (sweep, admin rescue, migration) | STRANDED ASSET finding |
| 4 | Apply severity floor from above | - |

---

## Rule 10: Worst-State Severity Calibration

**Pattern**: Any severity assessment that references current on-chain state
**Check**: Is the assessment using the worst REALISTIC operational state?

When assessing severity, use the WORST REALISTIC operational state, not current on-chain snapshot:

- If protocol can hold 0 to MAX tokens → assess at realistic peak TVL
- If fee can be 0% to 10% → assess at boundary values
- If N validators can be 1 to 200 → assess at realistic maximum
- If time since last action can be 0 to MAX_DELAY → assess at maximum delay

**Current on-chain state is a SNAPSHOT, not the operational envelope.**

**Action**: For every severity assessment, state the operational parameters assumed and why. Format:
```
Severity assessed at: N_validators=200, TVL=$100M, fee=10%
Rationale: Protocol designed for up to 200 validators per documentation
```

---

## Rule 11: Unsolicited External Token Transfer Impact

**Pattern**: Protocol interacts with external contracts that hold or manage transferable tokens
**Check**: What happens if tokens associated with external contracts are transferred TO the protocol unsolicited?

This goes BEYOND `balanceOf(this)`. Any external contract whose state the protocol reads (balance queries, delegation queries, staking queries, share queries) may be affected by unsolicited token transfers.

**5-Dimension Analysis** (for each external token type):

| Dimension | Question | Impact Pattern |
|-----------|----------|----------------|
| **Transferability** | Can this token be sent to the protocol without calling protocol functions? | If YES → analyze all 4 dimensions below |
| **Accounting** | Does any protocol accounting query (not just `balanceOf(this)`) change when this token arrives unsolicited? | Inflated rewards, incorrect exchange rates, fee miscalculation |
| **Operation Blocking** | Does the unsolicited token create state that blocks protocol operations? (non-zero balances preventing removal, unexpected token types in accounting) | DoS on admin/keeper functions |
| **Loop Iteration** | Does the unsolicited token create new entries in any enumerated collection? (new token IDs, new delegation entries) | Gas DoS via unbounded iteration |
| **Side Effects** | Does receiving this token trigger callbacks, reward claims, or state changes in external contracts? | Reentrancy, unexpected state mutations |

**Severity floors**:
- Accounting corruption with no profitable attack → LOW
- Operation blocking on critical functions → minimum MEDIUM
- Gas DoS via unbounded loop growth → minimum MEDIUM
- Profitable extraction via accounting manipulation → standard matrix (usually HIGH)

**Action**: For every external token the protocol interacts with, check if it can be transferred TO the protocol unsolicited, and trace the impact through all 5 dimensions. This includes tokens returned by external calls (staking receipts, LP tokens, reward tokens) - not just the protocol's primary token.

---

## Rule 12: Exhaustive Enabler Enumeration

**Pattern**: Any finding identifies a dangerous state S that is a precondition for exploitation
**Check**: Have ALL paths to state S been enumerated?

When a finding identifies a dangerous state (e.g., "balance reaches zero", "rate diverges from expected", "queue grows unbounded"), enumerate ALL paths to that state using these 5 actor categories:

| # | Actor Category | Examples |
|---|----------------|----------|
| 1 | **External attacker** | Permissionless function calls, unsolicited token transfers, direct interactions |
| 2 | **Semi-trusted role** | Keeper/bot/operator acting within their permissions but with adversarial timing or parameter choices |
| 3 | **Natural operation** | Reward accrual, user deposits/withdrawals, fee accumulation, passage of time |
| 4 | **External event** | Slashing, pausing, governance parameter changes, external contract upgrades |
| 5 | **User action sequence** | Normal user operations that in combination create an edge state |

**Mandatory output** (for each dangerous state S identified in any finding):

| # | Path to State S | Actor Category | Existing Finding Covers It? | If Not: New Finding ID |
|---|-----------------|----------------|-----------------------------|----------------------|

**Rules**:
- Fill for ALL 5 categories. If a category cannot reach state S, document WHY (not just "N/A")
- Each MISSING path that IS reachable → new finding or addition to existing finding
- Each new finding inherits severity from the original finding's impact assessment
- Cross-reference with Rule 5 (combinatorial): if N actors × same path → amplified impact

**Action**: For every dangerous precondition state in the findings inventory, verify that all reachable paths have been documented. Missing paths are coverage gaps.

---

## Rule 13: User Impact Evaluation (Anti-Normalization)

**Pattern**: Any analysis concludes a behavior is "by design", "intended", or "correct architecture"
**Check**: Does this design choice harm users?

Before marking any behavior as non-issue because it appears intentional:

**5-Question Test** (ALL must be answered):
1. **Who is harmed** by this design? (specific user class: depositors, withdrawers, LPs, etc.)
2. **Can affected users avoid** the harm through their own actions? (or is it imposed on them?)
3. **Is the harm documented** in protocol documentation, comments, or UI? (informed consent?)
4. **Could the protocol achieve the same goal** without this harm? (alternative designs exist?)
5. **Does the function fulfill its stated purpose completely?** (e.g., an `emergencyWithdraw` that only withdraws LP tokens but not individual tokens is incomplete - users with individual token deposits cannot emergency-exit)

**Verdict rules**:
- Harmed AND unavoidable AND undocumented → FINDING (design flaw category, apply severity matrix)
- Harmed AND unavoidable AND documented → INFO finding (users accepted known risk)
- Harmed AND avoidable → INFO finding (user choice)
- No one harmed → genuinely non-issue

### Passive Attack Modeling

For ANY finding involving exchange rates, multi-step timing, or parameter updates:

Model BOTH attack types:

| Attack Type | Description | Example |
|-------------|-------------|---------|
| **Active** | Attacker front-runs or back-runs a specific transaction | Sandwich attack, MEV extraction |
| **Passive** | Attacker uses normal protocol functions at strategically chosen times, waiting for natural state changes | Deposit before accrual, withdraw after rate increase |
| **Design gap** | Protocol provides mechanism X for purpose Y, but X does not cover all cases Y requires | Emergency function that does not handle all asset types, recovery that only works for some user states |

**Common passive patterns**:
- Deposit → wait for natural reward accrual → withdraw (timing arbitrage)
- Use normal function when parameter is at favorable boundary
- Wait for external state change (governance, oracle update) then act

**Action**: When modeling attacks, do NOT stop at "requires front-running" (active only). Always also check: "can an attacker achieve a similar result by simply timing their normal operations?" (passive).

---

## Rule 14: Cross-Variable Invariant Verification

**Pattern**: Two or more state variables that MUST maintain a relationship for correctness (e.g., `sum(array) == total`, `mapping.length == counter`, `balance >= sum(allocations)`)
**Check**: Can any setter, admin function, or state transition break the invariant?

**Methodology**:
1. For each aggregate variable (total, count, sum, length), identify ALL individual variables it should track
2. For each setter that modifies individual variables, verify the aggregate is updated atomically
3. For each setter that modifies the aggregate directly, verify individual variables are consistent
4. Check: can the aggregate and individuals be modified through DIFFERENT code paths that desync them?
5. **Constraint coherence**: For independently-settable limits that must satisfy a mathematical relationship (e.g., `max_total == sum(max_per_category)`), can one be changed without the other?
6. **Setter regression**: For each admin setter of a limit/bound/capacity - can the new value be set BELOW already-accumulated state? If yes, check `while` loops (infinite loop), comparisons (bypass), arithmetic (overflow). Also check `>` vs `>=` boundary precision.

**Common invariant classes**:
- Sum invariants: `totalSupply == sum(balances)`, `totalAllocated == sum(individual_allocations)`
- Count invariants: `array.length == activeCount + removedCount`
- Balance invariants: `contract.balance >= sum(unclaimed_rewards)`
- Mapping consistency: `mapping[key].exists == true` for all keys in the enumeration array
- Constraint coherence: `max_total == sum(max_per_category)`, `globalCap >= sum(localCaps)`

**Action**: For every aggregate/total variable, trace ALL modification paths for both the aggregate AND its components. If any path modifies one without the other → FINDING. For every admin setter of a limit/bound, verify it cannot regress below accumulated state.

---

## Rule 15: Flash Loan Precondition Manipulation

**Pattern**: Any function precondition that depends on state manipulable via flash-borrowed capital
**Check**: Can the precondition be satisfied/bypassed atomically within a single transaction?

| State Type | Manipulation Method | Flash Accessible? | Check |
|-----------|-------------------|-------------------|-------|
| `balanceOf(this)` | Donation / deposit | YES (0 cost) | Can inflated balance bypass checks? |
| Oracle spot price | Trade on source pool | YES (slippage cost) | Is spot used instead of TWAP? |
| Threshold / quorum | Deposit / stake | YES (deposit amount) | Can threshold be crossed atomically? |
| Exchange rate | Deposit to inflate | YES | Does rate affect minting/redemption? |
| Collateral ratio | Deposit collateral | YES | Can temporary collateral enable actions? |

**Mandatory sequence modeling**: For each flash-accessible state, model the full atomic sequence:
1. BORROW → 2. MANIPULATE → 3. CALL target function → 4. EXTRACT value → 5. RESTORE → 6. REPAY
7. Compute: profit = extracted_value - flash_fee - gas. If profit > 0 → FINDING.

**Action**: For every function with a balance/oracle/threshold/rate precondition, check if a flash loan can satisfy it atomically. See FLASH_LOAN_INTERACTION skill for full methodology.

---

## Rule 16: Oracle Integrity

**Pattern**: Any protocol logic that consumes oracle data for decisions
**Check**: Is the oracle data validated for all failure modes?

| Check | What to Verify | Impact if Missing |
|-------|---------------|-------------------|
| Staleness | `updatedAt` checked against heartbeat | Stale price → unfair liquidations, mispricing |
| Decimals | Oracle decimals match consumer expectations | Over/undervalued by 10^N |
| Zero return | `price > 0` validated | Division by zero, infinite minting |
| Negative | `price` cast safely (int256 → uint256) | Underflow, negative collateral |
| Round completeness | `answeredInRound >= roundId` | Stale incomplete round data |
| Sequencer (L2) | Uptime feed checked | Actions during sequencer downtime |
| TWAP window | Window length vs pool liquidity | Short TWAP manipulable via flash loan |
| Fallback | Behavior on oracle revert | DoS on all oracle-dependent functions |
| Config bounds | Oracle config setters (window size, deviation, heartbeat) have meaningful min/max | Setter with no floor → deviation check disabled, TWAP window = 0 |

**Action**: For every oracle data consumption point, verify ALL applicable checks from the table above. Missing checks → FINDING at severity based on impact. See ORACLE_ANALYSIS skill for full methodology.
- For every oracle configuration setter (window size, max deviation, heartbeat), check: can the parameter be set to a value that effectively disables the oracle validation? If yes → FINDING (Rule 14 setter regression applies).

---

## Rule R17: State Transition Completeness

**Pattern**: Operations with symmetric branches - profit/loss, deposit/withdraw, mint/burn, stake/unstake, increase/decrease
**Check**: All state fields modified in one branch are either (a) also modified in the other branch, or (b) explicitly documented as intentionally asymmetric.

**Methodology**:
1. For each pair of symmetric operations, list ALL state fields modified by the "positive" branch (profit, deposit, mint, stake, increase)
2. For the "negative" branch (loss, withdraw, burn, unstake, decrease), verify each field from step 1 is also handled
3. If a field is missing from the negative branch: trace what happens to dependent computations when that field retains its old value while other fields changed
4. Flag branch size asymmetry > 3x in code volume (lines of code) as a review trigger - large asymmetry often indicates incomplete handling

**Common miss patterns**:
- Profit branch updates `locked_profit` + `total_value` + `high_water_mark`, loss branch updates only `total_value` → `locked_profit` can exceed `total_value` → underflow
- Deposit updates `total_deposited` + mints shares, emergency withdraw burns shares but doesn't update `total_deposited` → accounting desync
- Stake updates `total_staked` + `last_stake_time`, unstake updates `total_staked` but not `last_stake_time` → stale time-dependent calculations

**EVM-specific**: State may be spread across multiple contracts (proxy, implementation, storage). Ensure ALL storage slots updated in the positive branch are also updated in the negative branch.

**Action**: For every operation pair, produce a field-by-field comparison table. Missing fields in the negative branch that have dependent consumers → FINDING.

---

## Evidence Source Enforcement

**Any REFUTED verdict where ALL external behavior evidence is tagged [MOCK], [EXT-UNV], or [DOC] is automatically escalated to CONTESTED.** Only these evidence types can support REFUTED for external contract behavior:

| Tag | Description | Valid for REFUTED? |
|-----|-------------|-------------------|
| [PROD-ONCHAIN] | Read from production contract on-chain | YES |
| [PROD-SOURCE] | Verified source from block explorer | YES |
| [PROD-FORK] | Tested on mainnet fork | YES |
| [CODE] | From audited codebase source | YES |
| [MOCK] | From mock/test contract | **NO** |
| [EXT-UNV] | External, unverified | **NO** |
| [DOC] | From documentation only | **NO** |

---

## Enforcement Mechanisms

### Devil's Advocate FORCING

When any agent identifies a potential attack path with "could" or "might":
- MUST pursue the path to conclusion (CONFIRMED/REFUTED with evidence)
- "Further investigation needed" → MUST do the investigation NOW

### CONTESTED Triggers Production Fetch

When any finding gets CONTESTED verdict:
1. Orchestrator MUST spawn production verification
2. If production source unavailable → stays CONTESTED (not REFUTED)
3. CONTESTED findings get same verification priority as HIGH severity

### REFUTED Priority Chain Analysis

Before any finding is marked REFUTED:
1. Chain analyzer MUST search ALL other findings for enablers
2. If potential enabler exists → PARTIAL (not REFUTED)
3. Only mark REFUTED if NO plausible enabler exists

### Cross-Validation Before REFUTED

Before marking ANY finding REFUTED, the analyst MUST:
1. State what evidence would PROVE this IS exploitable
2. Confirm they have checked for that evidence
3. If evidence is unavailable (not "doesn't exist") → CONTESTED
