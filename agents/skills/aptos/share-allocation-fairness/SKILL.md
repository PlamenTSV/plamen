---
name: "share-allocation-fairness"
description: "Trigger SHARE_ALLOCATION flag detected in pattern scan - Used by Breadth agents, depth-edge-case"
---

# Skill: SHARE_ALLOCATION_FAIRNESS

> **Trigger**: SHARE_ALLOCATION flag detected in pattern scan
> **Used by**: Breadth agents, depth-edge-case

## Purpose
Analyze fairness of share/token allocation mechanisms where users receive shares proportional to deposits, contributions, or participation -- checking for late-entry advantages, queue-position gaming, and time-weighting omissions. Adapted for Aptos Move FungibleAsset-based accounting and resource model.

## Methodology

### STEP 1: Classify Allocation Mechanism
Identify which pattern the protocol uses:

| Type | Pattern | Key Risk |
|------|---------|----------|
| Pro-rata snapshot | Shares minted at fixed ratio at deposit time | Late depositors dilute early depositors accrued value |
| Time-weighted | Shares accrue value based on duration held | Checkpoint manipulation, discrete vs continuous accrual |
| Queue-based | Deposits processed in batch/queue order | Queue position gaming, front-running batch processing |
| Epoch-based | Shares valued per epoch/period boundary | Cross-epoch timing arbitrage |

**Aptos-specific**: Identify whether shares are represented as:
- `FungibleAsset` with custom metadata (standard FA shares)
- `Coin<ShareType>` (legacy coin shares)
- Custom resource with balance field (non-standard)
- `Object<T>` with proportional ownership (object-based shares)

### STEP 2: Late Entry Attack Model
For each allocation entry point:

1. **Identify accrual source**: What generates value for existing share holders? (yield, fees, rewards, appreciation)
2. **Trace timing**: When does accrued value become claimable vs when can new shares enter?
3. **Check for time-weighting**: Does allocation account for HOW LONG shares were held, or only THAT shares are held?
4. **Model attack**: Can a depositor enter AFTER value accrues but BEFORE distribution, capturing value they did not earn?

| Entry Function | Accrual Source | Time-Weighted? | Late Entry Possible? | Impact |
|---------------|----------------|----------------|---------------------|--------|

**Aptos timing specifics**: Aptos block time is ~1 second. `timestamp::now_seconds()` granularity allows sub-epoch manipulation if epoch boundaries are timestamp-based. Check if the protocol uses `reconfiguration::last_reconfiguration_time()` or custom epoch tracking.

#### STEP 2c: Cross-Address Deposit Model
For each entry function accepting a beneficiary address or object parameter:

Check: what is the DEFAULT state for a never-before-seen beneficiary? Can depositing for a new address where that address has zero-initialized accounting unlock historical rewards, bypass cooldowns, or inherit accrued value?

| Entry Function | Accepts Beneficiary? | Default State for New Address | Exploitable? | Impact |
|---------------|---------------------|------------------------------|-------------|--------|

**Aptos-specific**: When a new `FungibleStore` is created for an address via `primary_fungible_store::ensure_primary_store_exists`, is the associated accounting state also initialized? Or does the share accounting resource exist independently from the token store?

If beneficiary != caller enables reward capture the recipient did not earn -> FINDING (late-entry variant).

#### STEP 2d: Pre-Setter Timing Model
For each admin-settable reward/rate parameter: model the sequence user_deposits -> admin_sets_rate -> rewards_accrue.
Does the user receive retroactive rewards for the period BEFORE the rate was set? Does a depositor after rate-setting receive the same, more, or less?

| Parameter Setter | Deposited-Before-Set? | Retroactive Rewards? | Fair? |
|-----------------|----------------------|---------------------|-------|

If depositing before rate-setting yields unearned rewards or causes reward loss for post-set depositors -> FINDING (timing fairness).

### STEP 2e: Pre-Configuration State Analysis

For the allocation mechanism identified in Step 1:

| Configuration Step | Parameter Set | Functions Available Before Set | Exploitable Default? |
|--------------------|-------------|-------------------------------|---------------------|

1. What is the module initialization sequence? List all `init_module` and manual configuration steps in order.
2. For each step: what functions are callable BEFORE this configuration completes?
3. Are there reward/share calculations that use unconfigured (zero/default) values?
4. Can a user deposit/stake before full configuration and receive outsized rewards/shares?
5. Is there a pause mechanism or `is_initialized` guard that prevents interaction before configuration completes?

**Aptos-specific**: `init_module` runs automatically on module publish. But additional configuration (setting rates, adding pools, registering tokens) often requires separate transactions. The window between `init_module` and full configuration is the attack surface.

If users can interact during partial configuration AND default values create unfair advantage -> FINDING (minimum Medium, Rule 13: design gap).

### STEP 3: Queue Position and Batch Processing
For protocols with batch/queue processing:

1. **Ordering fairness**: Is queue order FIFO, arbitrary (admin-chosen), or manipulable?
2. **Partial processing**: Can operator process some deposits but not others within a batch?
3. **Cross-batch state**: Does processing order within a batch affect allocation ratios?
4. **Deposit splitting**: Can a user split one large deposit into many small ones for queue advantage?

**Aptos-specific**: Aptos transaction ordering within a block is determined by the validator. If batch processing reads from a `Table` or `SmartTable`, iteration order may not be deterministic or FIFO. Check if the protocol uses `SmartVector` with explicit ordering or `Table` with unordered access.

### STEP 4: Share Redemption Symmetry
Check that entry and exit use consistent valuation:

1. **Mint vs burn ratio**: Are shares minted at the same exchange rate they can be burned?
2. **Pending claims**: Can unredeemed shares dilute active shares value?
3. **Withdrawal queue**: Does withdrawal ordering create unfair priority?

**Aptos-specific**: If shares are `FungibleAsset`, verify that `fungible_asset::supply()` is correctly tracked. If shares have `burn` capability, verify the burn-to-underlying ratio matches the mint ratio.

#### STEP 4b: Aggregate Constraint Coherence (Rule 14)
For independently-settable allocation rates/shares (e.g., per-pool weights, fee splits, distribution percentages):
Is the sum constraint enforced ON-CHAIN in the setter? Can each rate be changed independently without validating the aggregate?

| Rate/Weight Setter | Aggregate Constraint | Enforced On-Chain? | What if Sum Exceeds/Falls Short? |
|-------------------|---------------------|-------------------|--------------------------------|

If aggregate constraint NOT enforced and rates independently settable -> FINDING (Rule 14).

## Instantiation Parameters

```
{CONTRACTS}           -- List of modules to analyze
{SHARE_TOKEN}         -- Share/receipt token type (FA metadata, Coin type, custom resource)
{ENTRY_FUNCTIONS}     -- Functions that create/mint shares
{EXIT_FUNCTIONS}      -- Functions that burn/redeem shares
{RATE_SETTERS}        -- Admin functions that set allocation rates
{ACCRUAL_SOURCE}      -- What generates yield/value for share holders
```

## Output Schema

For each finding, specify:
- Allocation mechanism type
- Whether time-weighting is present or missing
- Concrete attack sequence with numerical example
- Who benefits and who is harmed

```markdown
## Finding [SA-N]: Title

**Verdict**: CONFIRMED / PARTIAL / REFUTED / CONTESTED
**Step Execution**: check1,2,2c,2d,2e,3,4,4b | X(reasons) | ?(uncertain)
**Rules Applied**: [R5:Y, R10:Y, R13:Y, R14:Y]
**Severity**: Critical/High/Medium/Low/Info
**Location**: module::function (source_file.move:LineN)

**Allocation Mechanism**: {type from Step 1}
**Fairness Violation**: {late-entry / queue-gaming / retroactive-reward / constraint-incoherence}

**Description**: What is wrong
**Impact**: Who is harmed and by how much (numerical example)
**Evidence**: Code showing allocation logic
```

---

## Step Execution Checklist (MANDATORY)

| Step | Required | Completed? | Notes |
|------|----------|------------|-------|
| 1. Classify Allocation Mechanism | YES | Y/X/? | |
| 2. Late Entry Attack Model | YES | Y/X/? | |
| 2c. Cross-Address Deposit Model | YES | Y/X/? | Check beneficiary != caller patterns |
| 2d. Pre-Setter Timing Model | YES | Y/X/? | Model deposit-before-rate-set sequence |
| 2e. Pre-Configuration State Analysis | YES | Y/X/? | init_module window + unconfigured defaults |
| 3. Queue Position and Batch Processing | IF queue/batch detected | Y/X(N/A)/? | |
| 4. Share Redemption Symmetry | YES | Y/X/? | |
| 4b. Aggregate Constraint Coherence | IF multiple settable weights | Y/X(N/A)/? | Rule 14 enforcement check |

If any step skipped, document valid reason (N/A, no queue, single pool, no settable weights).
