---
name: "outcome-determinism"
description: "Protocol Type Trigger outcome_determinism - detected when EITHER of these code patterns are present - - Selection from finite depletable pool with fallback behavior (while(full)..."
---

# Injectable Skill: Outcome Determinism - Selection Fairness & Strategic Timing

> **Protocol Type Trigger**: `outcome_determinism` - detected when EITHER of these code patterns are present:
>   - Selection from finite depletable pool with fallback behavior (`while(full) next`, `modulo` with shrinking domain, category/slot/validator selection)
>   - Time-gated actions with observable default/fallback outcomes (`deadline`, `claimPeriod`, `defaultSelection`, `expiry` + fallback path that computes from predictable state)
> **Inject Into**: Breadth agents, depth-edge-case
> **Language**: All (rational actor patterns are chain-agnostic)
> **Finding prefix**: `[OD-N]`
> **Added in**: v1.1
>
> **NOTE**: Callback selective revert (Section 1a of the original skill) and RNG consumption enumeration (Section 1b) are now ALWAYS-ON checks in the depth agent template - they do not require this injectable to trigger.

## What This Injectable Adds (beyond always-on checks)

The always-on depth template already covers:
- **Callback selective revert**: Full taxonomy of external execution transfers (ERC-721/1155/777/1363, flash loans, hooks, low-level calls, ETH transfers) - see depth-templates.md "CALLBACK SELECTIVE REVERT ANALYSIS"
- **Tainted source consumption enumeration**: RNG/oracle consumed by multiple functions → rate severity by worst consumer - see depth-templates.md PART 1 item 6

This injectable adds analysis that only applies when SPECIFIC structural patterns exist:

---

## 1. Selection Fairness Under Constraint Changes

For every selection algorithm operating on a set that can shrink, grow, or be modified between selections:

### 1a. Probability Redistribution on Depletion

| Selection Function | Pool Size | Depletion Mechanism | Fallback Behavior | Redistribution Fair? |
|-------------------|-----------|--------------------|--------------------|---------------------|

**Fairness test**: When element X is removed from a pool of N:
- **Fair**: Each remaining element gets probability 1/(N-1) - uniform redistribution
- **Biased**: Sequential fallback (`index++`, `next slot`) - adjacent element gets doubled probability
- **Broken**: Infinite loop (no exit when all depleted) or unreachable elements

**Common biased patterns across protocol types**:
- `while (slot_full) { index++ }` - next-in-line gets 2/N probability (NFT categories, validator slots, LP positions)
- `if (depleted) skip` - skipped element's share goes entirely to next check, not distributed
- `modulo(N)` where N decreases - specific indices get boosted as N shrinks

**Quantify**: At each depletion level (1-of-N, N/2-of-N, N-1-of-N), what is the maximum probability deviation from uniform? Is it exploitable (can the actor influence which elements deplete first)?

Tag: `[VARIATION:pool N→N-K → element X probability 1/N→{new_prob} → bias={factor}x]`

### 1b. Admin Parameter Regression on Selection Algorithms

For bounded parameters (caps, limits, quotas) where the bound can be LOWERED below already-accumulated state and the bound is used by a selection/iteration algorithm:

| Parameter | Setter | Current Accumulated | Can Set Below Accumulated? | Selection Algorithm Affected | What Breaks? |
|-----------|--------|--------------------|--------------------------|-------|--------------|

**This extends Rule 14** (Setter Regression) specifically for selection/allocation algorithms: when a cap is lowered below the current count, does the selection algorithm's termination condition still hold? (e.g., `while (count == max)` becomes unreachable when count > max)

---

## 2. Strategic Timing - Delay, Front-Run, Sequence

**Core question**: For each user-facing action, is the TIMING of the action exploitable by a rational self-interested actor?

### 2a. Delay-vs-Act Rationality

For every time-gated action with a default or fallback:

| Action | Active Path | Default/Fallback Path | Default Predictable? | Default Sometimes Better? | Delay Cost |
|--------|-----------|----------------------|---------------------|--------------------------|-----------|

**A rational actor will delay when ALL THREE hold**:
1. The default outcome is **predictable** (computed from observable on-chain state, not future unknowns)
2. The default is **sometimes better** than the active choice (different formula, different prices, different parameters)
3. The **cost of waiting** (opportunity cost, gas, penalty) is lower than the expected value gain

**Cross-protocol examples**:
- DeFi: Defer unstaking claim when penalty decreases over time and rate may improve
- NFT: Defer coin/trait claiming when default allocation uses more favorable prices than current
- Governance: Defer vote to observe other votes and vote strategically
- Staking: Defer withdrawal when accrued rewards during delay exceed the withdrawal amount
- Auctions: Defer bid to last block to prevent counter-bidding (sniping)

**Methodology**:
1. Identify the active path (user calls function before deadline)
2. Identify the default path (what happens if user doesn't act - system assigns default, claim expires, fallback triggers)
3. Is the default outcome computable from CURRENT on-chain state? (If it depends on future block hash or unresolved oracle → not predictable → no strategic edge)
4. Compare: under what market/state conditions is default > active? How often do those conditions occur?
5. What does delay cost? (forfeiture, penalty, opportunity cost, gas savings)

Tag: `[TRACE:action={fn} deadline={T} → default={fallback_fn} → computed_from={state_vars} → predictable={YES/NO} → default_better_when={condition}]`

### 2b. Admin Action Information Asymmetry

For every admin-settable parameter that affects pending or future user operations:

| Parameter | Setter | Timelock? | Event Emitted? | Affects Pending Operations? | Asymmetry Window |
|-----------|--------|-----------|---------------|---------------------------|-----------------|

**Applies universally** - any `onlyOwner`/`onlyAdmin` setter that changes a parameter used in user-facing calculations creates a window where the admin knows the new value but users don't.

**Severity factors**:
- Instant setter (no timelock): 1-block asymmetry - exploitable via same-block front-running
- No event emission: window extends until users discover change via failed transaction or manual inspection
- Retroactive effect on pending state: admin changes rules for operations already in progress
- Combined (instant + no event + retroactive): maximum exploitation window

### 2c. Sequence-Dependent Outcomes

For actions where the ORDER of multiple actors matters:

| Action | Same-Block Ordering Matters? | Cross-Block Ordering Matters? | First-Mover Advantage? | Last-Mover Advantage? |
|--------|----------------------------|------------------------------|----------------------|---------------------|

**Check**: Can an actor observe others' pending actions (mempool) and position before/after them for profit?

---

## Key Questions (must answer all)
1. For each selection from a shrinking pool: does probability redistribute uniformly? Quantify the bias.
2. For each time-gated action: is the default/fallback predictable and sometimes better than active choice?
3. For each admin setter: what is the information asymmetry window? Does it affect pending operations?
4. For each multi-actor sequence: can ordering be exploited?

## Common False Positives
- **Truly unpredictable defaults**: If fallback depends on future block hash or external oracle not yet published, strategic delay has no edge
- **Equal-value outcomes in selection**: If all pool elements have identical economic value, selection bias has no incentive
- **Timelock-protected setters**: If admin changes require N-block delay with public announcement, asymmetry is mitigated (but verify ALL setters have the timelock, not just some)
- **Uniform delay cost**: If delaying always costs more than the potential gain, rational delay is not profitable

## Step Execution Checklist (MANDATORY)

| Section | Required | Completed? | Notes |
|---------|----------|------------|-------|
| 1a. Depletion Redistribution | IF selection from finite/depletable pool | | Quantify bias at each depletion level |
| 1b. Parameter Regression on Selection | IF admin can lower cap below accumulated AND cap used by selection algo | | Extends Rule 14 |
| 2a. Delay-vs-Act Rationality | IF time-gated action with default/fallback | | Check all three conditions |
| 2b. Admin Information Asymmetry | IF admin setter affects pending user operations | | Check timelock AND event emission |
| 2c. Sequence-Dependent Outcomes | IF multiple actors' ordering affects results | | Check same-block and cross-block |
