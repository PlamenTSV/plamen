---
name: "share-allocation-fairness"
description: "Trigger Pattern SHARE_ALLOCATION flag detected in pattern scan - Inject Into Breadth agents, depth-edge-case"
---

# Skill: Share Allocation Fairness (Sui)

> **Trigger Pattern**: SHARE_ALLOCATION flag detected in pattern scan
> **Inject Into**: Breadth agents, depth-edge-case
> **Finding prefix**: `[SAF-N]`
> **Rules referenced**: R5, R10, R13, R14

```
shares|allocation|distribute|pro.rata|proportional|vest|reward.*per.*share|
balance::join|balance::split|coin::mint|reward_index|cumulative|epoch.*reward
```

## Purpose
Analyze fairness of share/token allocation mechanisms on Sui where users receive Coin<T> shares or Balance<T> proportional to deposits, contributions, or participation -- checking for late-entry advantages, PTB-based timing exploitation, queue-position gaming, and time-weighting omissions.

**Sui-specific share representations**:
- `Coin<ShareToken>`: Fungible, freely transferable (has `key + store`). User holds as owned object.
- `Balance<ShareToken>` inside a position object: Non-transferable accounting. Locked within the protocol's object model.
- `u64` field in a shared/owned struct: Simple numerical tracking, no token representation.
- Check which representation is used -- it affects transferability, composability, and gaming vectors.

---

## Methodology

### STEP 1: Classify Allocation Mechanism

Identify which pattern the protocol uses:

| Type | Sui Pattern | Key Risk |
|------|------------|----------|
| Pro-rata snapshot | Shares minted at fixed ratio via `balance::split`/`coin::mint_balance` at deposit time | Late depositors dilute early depositors' accrued value |
| Time-weighted | Per-user owned object tracks `reward_per_share_paid` and `accrued_rewards` with `clock::timestamp_ms()` | Checkpoint manipulation, discrete vs continuous accrual |
| Queue-based | Table/VecMap in shared object stores pending deposits | Queue position gaming, PTB-based front-running |
| Epoch-based | Shares valued per Sui epoch boundary via `tx_context::epoch()` | Cross-epoch timing arbitrage at epoch transition |

### STEP 2: Late Entry Attack Model

For each allocation entry function:

1. **Identify accrual source**: What generates value for existing share holders? (yield from external DeFi, fees collected in shared pool, token emissions via TreasuryCap)
2. **Trace timing**: When does accrued value become claimable vs when can new shares enter? Is there a separate crank/update function?
3. **Check for time-weighting**: Does allocation account for HOW LONG shares were held, or only THAT shares are held at checkpoint time?
4. **Model attack**: Can a depositor enter AFTER value accrues but BEFORE distribution, capturing value they did not earn?

| Entry Function | Accrual Source | Time-Weighted? | Late Entry Possible? | Impact |
|---------------|----------------|----------------|---------------------|--------|

**Sui timing model**:
- `clock::timestamp_ms()` provides millisecond-precision timestamps (read from the `Clock` shared object)
- Timestamps advance per checkpoint (~0.5-2s), NOT per transaction
- Multiple transactions within the same checkpoint see the SAME timestamp
- Implication: time-weighted calculations based on `clock::timestamp_ms()` have ~0.5-2s granularity. An attacker can deposit and withdraw within the same checkpoint and see zero time elapsed, potentially capturing rewards with zero time commitment.

**PTB-specific timing**: With PTB composability, an attacker can compose multiple function calls in a single atomic transaction: [deposit] -> [trigger_distribution] -> [withdraw] within one PTB. This is more powerful than EVM flash loans for timing attacks because PTBs execute atomically with no inter-step cost.

#### STEP 2c: Cross-Address Deposit Model

For each entry function accepting a recipient address parameter:

| Entry Function | Accepts Recipient? | Default State for New Recipient | Exploitable? | Impact |
|---------------|-------------------|-------------------------------|-------------|--------|

**Check**: When a new position object or dynamic field is created for a recipient:
- What is the DEFAULT state? (`reward_per_share_paid = 0`? `last_deposit_epoch = 0`?)
- If `reward_per_share_paid` starts at 0 while the global index is at N, the new position holder captures ALL historical rewards on their deposit -- FINDING
- Can `deposit(recipient, coin)` where `recipient != sender` create a position that captures historical rewards the recipient did not earn?
- On Sui, this may manifest as a new owned object created for the recipient (clean state -- typically safe) or a new dynamic field added to a shared object keyed by address (check default values).

#### STEP 2d: Pre-Setter Timing Model

For each admin-settable reward/rate parameter:

| Parameter Setter | Cap Required | Staked-Before-Set? | Retroactive Rewards? | Fair? |
|-----------------|-------------|-------------------|---------------------|-------|

Model: user deposits (position created with current index) -> admin sets reward rate -> rewards accrue.
- Does the user receive retroactive rewards for the period BEFORE the rate was set?
- Is the global reward index updated atomically with the rate change in the same function call?

### 2e. Pre-Configuration State Analysis

For the allocation mechanism identified in Step 1:

| Configuration Step | Parameter Set | Functions Available Before Set | Exploitable Default? |
|--------------------|-------------|-------------------------------|---------------------|

1. What is the deployment/initialization sequence? In Sui, `init` runs once at package publish. What configuration happens in `init` vs subsequent admin transactions?
2. For each step: what functions are callable BEFORE this configuration completes?
3. Are there reward/share calculations that use unconfigured (zero/default) values in shared objects?
4. Can a user deposit/stake before full configuration and receive outsized rewards/shares?
5. Is there a version flag or `is_initialized` check that gates user interactions?

**Sui-specific**: `init()` runs atomically at publish. If configuration requires MULTIPLE transactions (init -> configure_pool -> set_rates), there are windows between these transactions where the protocol is partially configured.

If users can interact during partial configuration AND default values create unfair advantage -> FINDING (minimum Medium, Rule 13: design gap).

### STEP 3: Queue Position and Batch Processing

For protocols with batch/queue processing:

1. **Ordering fairness**: Is queue order FIFO (Table insertion order), arbitrary (admin-chosen), or manipulable (PTB composition order)?
2. **Partial processing**: Can admin process some deposits but not others within a batch? Does the batch function iterate with a limit?
3. **Cross-batch state**: Does processing order within a batch affect allocation ratios?
4. **Deposit splitting**: Can a user split one large `Coin<T>` into many small deposits (via `coin::split` in a PTB) for queue advantage or per-deposit limit bypass?

**Sui-specific ordering**:
- Transactions touching only owned objects are processed without consensus (fast path) -- no ordering manipulation
- Transactions touching shared objects go through consensus -- validator-influenced ordering within checkpoint
- PTB atomicity: all commands execute atomically, batch processing within a single PTB is all-or-nothing
- An attacker can use PTB to atomically: read queue state -> deposit at favorable position -> trigger processing -> claim

### STEP 4: Share Redemption Symmetry

Check that entry and exit use consistent valuation:

1. **Mint vs burn ratio**: Are shares minted at the same exchange rate they can be burned? (check share price calculation in both deposit and withdraw)
2. **Pending claims**: Can unclaimed reward Balance<T> dilute active shares' value? (rewards already owed but counted in TVL)
3. **Withdrawal queue**: Does withdrawal ordering create unfair priority?

**Sui-specific redemption**:
- If shares are `Coin<ShareToken>`, user burns them via protocol function. Check: can user transfer shares to another address and redeem there to bypass cooldowns?
- If shares are `Balance<ShareToken>` inside position object, redemption requires the position object. Check: can position object be transferred (has `store`?) to bypass restrictions?
- First-depositor / last-withdrawer edge cases: what happens when `total_supply == 0` and someone deposits? (division by zero in share calculation?)

**TreasuryCap authority risks**:
- Can TreasuryCap be used outside of deposit logic to inflate share supply?
- Is TreasuryCap stored in a shared object with access control? If `store` allows extraction from the wrapper -> unauthorized minting.
- If freeze authority pattern exists (rare on Sui): who controls it?

#### STEP 4b: Aggregate Constraint Coherence (Rule 14)

For independently-settable allocation rates/shares (e.g., per-pool weights, fee splits, distribution percentages):

| Rate/Weight Setter | Aggregate Constraint | Enforced On-Chain? | What if Sum Exceeds/Falls Short? |
|-------------------|---------------------|-------------------|--------------------------------|

**Sui-specific**: If weights are stored as dynamic fields on a shared object (one field per pool), the setter function may not iterate all fields to validate the sum. Check: does the setter read all weight dynamic fields and validate the total?

If aggregate constraint NOT enforced and rates independently settable -> FINDING (Rule 14).

---

## Output

For each finding, specify:
- Allocation mechanism type (pro-rata, time-weighted, queue, epoch)
- Whether time-weighting is present or missing
- Concrete attack sequence with numerical example (SUI/token amounts)
- Who benefits and who is harmed
- Whether the attack requires PTB composition or is achievable with single function calls
- Sui-specific timing factors (`clock::timestamp_ms()` granularity, checkpoint ordering)

## Finding Template

```markdown
**ID**: [SAF-N]
**Verdict**: CONFIRMED / PARTIAL / REFUTED / CONTESTED
**Step Execution**: (see checklist below)
**Rules Applied**: [R5:___, R10:___, R13:___, R14:___]
**Severity**: Critical/High/Medium/Low/Info
**Location**: sources/{module}.move:LineN
**Title**: {fairness violation type}
**Description**: {specific issue with numerical example}
**Impact**: {quantified at worst-state parameters -- who loses how much}
```

---

## Step Execution Checklist (MANDATORY)

| Step | Required | Completed? | Notes |
|------|----------|------------|-------|
| 1. Classify Allocation Mechanism | YES | | |
| 2. Late Entry Attack Model | YES | | PTB composition timing check |
| 2c. Cross-Address Deposit Model | YES | | Check recipient != sender patterns |
| 2d. Pre-Setter Timing Model | YES | | Model deposit-before-rate-set sequence |
| 2e. Pre-Configuration State Analysis | YES | | Post-init() window + unconfigured defaults |
| 3. Queue Position and Batch Processing | IF queue/batch detected | | Include PTB deposit splitting |
| 4. Share Redemption Symmetry | YES | | Include TreasuryCap access check |
| 4b. Aggregate Constraint Coherence | IF multiple settable weights | | Rule 14 enforcement check |

If any step skipped, document valid reason (N/A, no queue, single pool, no settable weights).
