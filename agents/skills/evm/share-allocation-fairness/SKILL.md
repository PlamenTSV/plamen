---
name: "share-allocation-fairness"
description: "Trigger SHARE_ALLOCATION flag detected in pattern scan - Used by Breadth agents, depth-edge-case"
---

# Skill: SHARE_ALLOCATION_FAIRNESS

> **Trigger**: SHARE_ALLOCATION flag detected in pattern scan
> **Used by**: Breadth agents, depth-edge-case

## Purpose
Analyze fairness of share/token allocation mechanisms where users receive shares proportional to deposits, contributions, or participation -- checking for late-entry advantages, queue-position gaming, and time-weighting omissions.

## Methodology

### STEP 1: Classify Allocation Mechanism
Identify which pattern the protocol uses:

| Type | Pattern | Key Risk |
|------|---------|----------|
| Pro-rata snapshot | Shares minted at fixed ratio at deposit time | Late depositors dilute early depositors' accrued value |
| Time-weighted | Shares accrue value based on duration held | Checkpoint manipulation, discrete vs continuous accrual |
| Queue-based | Deposits processed in batch/queue order | Queue position gaming, front-running batch processing |
| Epoch-based | Shares valued per epoch/period boundary | Cross-epoch timing arbitrage |

### STEP 2: Late Entry Attack Model
For each allocation entry point:

1. **Identify accrual source**: What generates value for existing share holders? (yield, fees, rewards, appreciation)
2. **Trace timing**: When does accrued value become claimable vs when can new shares enter?
3. **Check for time-weighting**: Does allocation account for HOW LONG shares were held, or only THAT shares are held?
4. **Model attack**: Can a depositor enter AFTER value accrues but BEFORE distribution, capturing value they did not earn?

| Entry Function | Accrual Source | Time-Weighted? | Late Entry Possible? | Impact |
|---------------|----------------|----------------|---------------------|--------|

#### STEP 2c: Cross-Address Deposit Model
For each entry function accepting an `address` beneficiary parameter (e.g., `stake(address to, uint256 amount)`):
Check: what is the DEFAULT state for a never-before-seen `to` address? Can depositing for `to` where `to` has zero-initialized accounting unlock historical rewards, bypass cooldowns, or inherit accrued value?

| Entry Function | Accepts Beneficiary? | Default State for New Address | Exploitable? | Impact |
|---------------|---------------------|------------------------------|-------------|--------|

If `to != msg.sender` enables reward capture the recipient did not earn -> FINDING (late-entry variant).

#### STEP 2d: Pre-Setter Timing Model
For each admin-settable reward/rate parameter: model the sequence user_stakes -> admin_sets_rate -> rewards_accrue.
Does the user receive retroactive rewards for the period BEFORE the rate was set? Does a staker after rate-setting receive the same, more, or less?

| Parameter Setter | Staked-Before-Set? | Retroactive Rewards? | Fair? |
|-----------------|-------------------|---------------------|-------|

If staking before rate-setting yields unearned rewards or causes reward loss for post-set stakers -> FINDING (timing fairness).

### 2e. Pre-Configuration State Analysis

For the allocation mechanism identified in Step 1:

| Configuration Step | Parameter Set | Functions Available Before Set | Exploitable Default? |
|--------------------|-------------|-------------------------------|---------------------|

1. What is the deployment/initialization sequence? List all configuration steps in order.
2. For each step: what functions are callable BEFORE this configuration completes?
3. Are there reward/share calculations that use unconfigured (zero/default) values?
4. Can a user deposit/stake before full configuration and receive outsized rewards/shares?
5. Is there a `pause` mechanism that prevents interaction before configuration completes?

If users can interact during partial configuration AND default values create unfair advantage → FINDING (minimum Medium, Rule 13: design gap).

### STEP 3: Queue Position and Batch Processing
For protocols with batch/queue processing:

1. **Ordering fairness**: Is queue order FIFO, arbitrary (operator-chosen), or manipulable?
2. **Partial processing**: Can operator process some deposits but not others within a batch?
3. **Cross-batch state**: Does processing order within a batch affect allocation ratios?
4. **Deposit splitting**: Can a user split one large deposit into many small ones for queue advantage?

### STEP 4: Share Redemption Symmetry
Check that entry and exit use consistent valuation:

1. **Mint vs burn ratio**: Are shares minted at the same exchange rate they can be burned?
2. **Pending claims**: Can unredeemed shares dilute active shares' value?
3. **Withdrawal queue**: Does withdrawal ordering create unfair priority?

#### STEP 4b: Aggregate Constraint Coherence (Rule 14)
For independently-settable allocation rates/shares (e.g., per-pool weights, fee splits, distribution %):
Is the sum constraint enforced ON-CHAIN in the setter? Can each rate be changed independently without validating the aggregate?

| Rate/Weight Setter | Aggregate Constraint | Enforced On-Chain? | What if Sum Exceeds/Falls Short? |
|-------------------|---------------------|-------------------|--------------------------------|

If aggregate constraint NOT enforced and rates independently settable -> FINDING (Rule 14).

## Output
For each finding, specify:
- Allocation mechanism type
- Whether time-weighting is present or missing
- Concrete attack sequence with numerical example
- Who benefits and who is harmed

---

## Step Execution Checklist (MANDATORY)

| Step | Required | Completed? | Notes |
|------|----------|------------|-------|
| 1. Classify Allocation Mechanism | YES | ✓/✗/? | |
| 2. Late Entry Attack Model | YES | ✓/✗/? | |
| 2c. Cross-Address Deposit Model | YES | ✓/✗/? | Check beneficiary != msg.sender patterns |
| 2d. Pre-Setter Timing Model | YES | ✓/✗/? | Model deposit-before-rate-set sequence |
| 2e. Pre-Configuration State Analysis | YES | ✓/✗/? | Deployment window + unconfigured defaults |
| 3. Queue Position and Batch Processing | IF queue/batch detected | ✓/✗(N/A)/? | |
| 4. Share Redemption Symmetry | YES | ✓/✗/? | |
| 4b. Aggregate Constraint Coherence | IF multiple settable weights | ✓/✗(N/A)/? | Rule 14 enforcement check |

If any step skipped, document valid reason (N/A, no queue, single pool, no settable weights).
