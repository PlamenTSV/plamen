---
name: "share-allocation-fairness"
description: "Trigger Pattern SHARE_ALLOCATION flag detected in pattern scan - Inject Into Breadth agents, depth-edge-case"
---

# Skill: Share Allocation Fairness (Solana)

> **Trigger Pattern**: SHARE_ALLOCATION flag detected in pattern scan
> **Inject Into**: Breadth agents, depth-edge-case
> **Finding prefix**: `[SAF-N]`
> **Rules referenced**: S1, S4, S9, R5, R10, R13, R14

```
shares|allocation|distribute|pro.rata|proportional|vest|reward.*per.*share|
mint_to|burn_from|reward_index|cumulative
```

## Purpose
Analyze fairness of share/token allocation mechanisms on Solana where users receive SPL Token shares proportional to deposits, contributions, or participation -- checking for late-entry advantages, PDA-based accounting manipulation, queue-position gaming, and time-weighting omissions.

## Methodology

### STEP 1: Classify Allocation Mechanism

Identify which pattern the protocol uses:

| Type | Solana Pattern | Key Risk |
|------|---------------|----------|
| Pro-rata snapshot | SPL shares minted at fixed ratio via mint_to at deposit time | Late depositors dilute early depositors' accrued value |
| Time-weighted | Per-user PDA tracks `reward_per_share_paid` and `accrued_rewards` | Checkpoint manipulation, stale reward index |
| Queue-based | Account-based queue (Vec in PDA or linked PDAs) | Queue position gaming, front-running batch processing via MEV bundles |
| Epoch-based | Shares valued per epoch boundary, epoch tracked in global PDA | Cross-epoch timing arbitrage at epoch transition slots |

### STEP 2: Late Entry Attack Model

For each allocation entry instruction:

1. **Identify accrual source**: What generates value for existing share holders? (yield from CPI, fees collected in vault PDA, SOL rewards, token emissions via mint authority)
2. **Trace timing**: When does accrued value become claimable vs when can new shares enter? Is there a checkpoint instruction separate from deposit?
3. **Check for time-weighting**: Does allocation account for HOW LONG shares were held, or only THAT shares are held at checkpoint time?
4. **Model attack**: Can a depositor enter AFTER value accrues but BEFORE distribution, capturing value they did not earn?

| Entry Instruction | Accrual Source | Time-Weighted? | Late Entry Possible? | Impact |
|------------------|----------------|----------------|---------------------|--------|

**Solana-specific timing**: With 400ms slots, timing attacks are tighter but MEV bundles allow precise instruction ordering within a slot. An attacker can bundle: [deposit_ix] -> [crank_distribute_ix] to enter just before distribution.

#### STEP 2c: Cross-Address Deposit Model

For each entry instruction accepting a `beneficiary: Pubkey` parameter or deriving a PDA from a user key that is NOT the signer:

| Entry Instruction | Accepts Beneficiary? | Default State for New PDA | Exploitable? | Impact |
|------------------|---------------------|--------------------------|-------------|--------|

**Check**: When a PDA is initialized for a new beneficiary address:
- What is the DEFAULT state? (`reward_per_share_paid = 0`? `last_deposit_slot = 0`?)
- If `reward_per_share_paid` starts at 0 while the global index is at N, the new PDA holder is entitled to ALL historical rewards on their deposit -- FINDING (late-entry variant)
- Can `deposit(beneficiary, amount)` where `beneficiary != signer` be used to create a new PDA that captures historical rewards the beneficiary did not earn?
- Does the instruction check `init` vs `init_if_needed`? With `init_if_needed`, repeated deposits for the same beneficiary reuse the existing PDA, but first deposit creates it with potentially exploitable defaults.

#### STEP 2d: Pre-Setter Timing Model

For each authority-settable reward/rate parameter:

| Parameter Setter | Staked-Before-Set? | Retroactive Rewards? | Fair? |
|-----------------|-------------------|---------------------|-------|

Model the sequence: user deposits (PDA created with current index) -> authority sets reward rate -> rewards accrue.
- Does the user receive retroactive rewards for the period BEFORE the rate was set?
- Does a depositor AFTER rate-setting receive the same, more, or less?
- Is the global reward index updated atomically with the rate change, or can a window exist?

### 2e. Pre-Configuration State Analysis

For the allocation mechanism identified in Step 1:

| Configuration Step | Account/PDA Initialized | Instructions Available Before Init | Exploitable Default? |
|--------------------|------------------------|-----------------------------------|---------------------|

1. What is the deployment/initialization sequence? List all `initialize_*` instructions in order.
2. For each step: what instructions are invocable BEFORE this initialization completes?
3. Are there reward/share calculations that read uninitialized PDA fields (defaulting to 0)?
4. Can a user call deposit/stake instructions before all PDAs are initialized and receive outsized rewards/shares?
5. Is there an authority check or `is_initialized` flag that prevents interaction before configuration completes?

If users can interact during partial initialization AND default PDA values create unfair advantage → FINDING (minimum Medium, Rule 13: design gap).

### STEP 3: Queue Position and Batch Processing

For protocols with batch/queue processing:

1. **Ordering fairness**: Is queue order FIFO (append to Vec), arbitrary (authority-chosen), or manipulable (MEV bundle ordering)?
2. **Partial processing**: Can the crank process some deposits but not others within a batch? (CU limits may force partial processing -- who gets processed first?)
3. **Cross-batch state**: Does processing order within a batch affect allocation ratios? (first processed gets better rate if rate changes with each processing)
4. **Deposit splitting**: Can a user split one large deposit into many small PDA accounts for queue advantage or to bypass per-account limits?

**CU-aware batching**: If batch processing iterates over a Vec<Pubkey> in a PDA:
- What is the max batch size before exceeding 1.4M CU / 200k CU per instruction?
- Can an attacker bloat the queue with dust deposits to force partial processing?
- Does partial processing create unfair ordering advantages for early entries?

### STEP 4: Share Redemption Symmetry

Check that entry and exit use consistent valuation:

1. **Mint vs burn ratio**: Are SPL shares minted at the same exchange rate they can be burned? (check the share price calculation in both deposit and withdraw instructions)
2. **Pending claims**: Can unclaimed reward tokens dilute active shares' value? (rewards sitting in vault PDA counted as TVL but already owed to specific users)
3. **Withdrawal queue**: Does withdrawal ordering create unfair priority? (first to withdraw gets actual tokens, later withdrawers face depleted vault)

**SPL Token authority risks**:
- **Mint authority**: Can the mint authority (if held by program PDA) be misused to inflate share supply? Is minting gated by deposit logic only?
- **Freeze authority**: Can the freeze authority freeze specific user token accounts, preventing them from redeeming shares? (denial of service on targeted users)
- If freeze authority exists: who controls it? Can it be revoked? FINDING if freeze authority is active and can target individual users.

#### STEP 4b: Aggregate Constraint Coherence (Rule 14)

For independently-settable allocation rates/shares (e.g., per-pool weights, fee splits, distribution percentages stored in separate PDAs):

| Rate/Weight Setter | Aggregate Constraint | Enforced On-Chain? | What if Sum Exceeds/Falls Short? |
|-------------------|---------------------|-------------------|--------------------------------|

**Solana-specific**: If weights are stored in separate PDA accounts (one per pool/vault), the setter instruction may update ONE PDA without checking the sum across ALL PDAs. This requires reading multiple accounts in one instruction -- check if the instruction accounts struct includes ALL weight PDAs for validation.

If aggregate constraint NOT enforced and rates independently settable -> FINDING (Rule 14).

**Also check**: Can the authority set a weight to 0 for an active pool? What happens to users with deposits in that pool? (Rule 14 setter regression -- setting weight below accumulated state)

## Output

For each finding, specify:
- Allocation mechanism type (pro-rata, time-weighted, queue, epoch)
- Whether time-weighting is present or missing
- Concrete attack sequence with numerical example (SOL/token amounts)
- Who benefits and who is harmed
- Whether the attack requires MEV bundle ordering or is achievable with normal transactions

## Finding Template

```markdown
**ID**: [SAF-N]
**Verdict**: CONFIRMED / PARTIAL / REFUTED / CONTESTED
**Step Execution**: (see checklist below)
**Rules Applied**: [S1:___, S4:___, S9:___, R5:___, R10:___, R13:___, R14:___]
**Severity**: Critical/High/Medium/Low/Info
**Location**: programs/{program}/src/instructions/{file}.rs:LineN
**Title**: {fairness violation type}
**Description**: {specific issue with numerical example}
**Impact**: {quantified at worst-state parameters -- who loses how much}
```

---

## Step Execution Checklist (MANDATORY)

| Step | Required | Completed? | Notes |
|------|----------|------------|-------|
| 1. Classify Allocation Mechanism | YES | | |
| 2. Late Entry Attack Model | YES | | |
| 2c. Cross-Address Deposit Model | YES | | Check beneficiary != signer patterns |
| 2d. Pre-Setter Timing Model | YES | | Model deposit-before-rate-set sequence |
| 2e. Pre-Configuration State Analysis | YES | | Deployment window + unconfigured defaults |
| 3. Queue Position and Batch Processing | IF queue/batch detected | | Include CU-aware batch analysis |
| 4. Share Redemption Symmetry | YES | | Include mint/freeze authority check |
| 4b. Aggregate Constraint Coherence | IF multiple settable weights | | Rule 14 enforcement check |

If any step skipped, document valid reason (N/A, no queue, single pool, no settable weights).
