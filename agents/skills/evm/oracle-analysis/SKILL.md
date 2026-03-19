---
name: "oracle-analysis"
description: "Trigger Pattern ORACLE flag (required) - Inject Into Breadth agents, depth-external, depth-edge-case"
---

# ORACLE_ANALYSIS Skill

> **Trigger Pattern**: ORACLE flag (required)
> **Inject Into**: Breadth agents, depth-external, depth-edge-case

For every oracle the protocol consumes:

**⚠ STEP PRIORITY**: Steps 6 (Failure Modes) and 5c (Deviation Reference) are where HIGH/CRITICAL severity findings most commonly hide. Do NOT rush these steps. If constrained, skip conditional sections (4a-4d, 5a) before skipping 5c or 6.

## 1. Oracle Inventory

Enumerate ALL oracle data sources the protocol reads:

| Oracle | Type | Source Contract | Functions Called | Consumers (protocol functions) | Update Frequency | Heartbeat |
|--------|------|-----------------|-----------------|-------------------------------|-----------------|-----------|
| {name} | Chainlink / TWAP / Spot / Custom / Band / Pyth | {address} | {latestRoundData / observe / etc.} | {list all} | {expected} | {documented or UNKNOWN} |

**For each oracle**: What decision does the protocol make based on this data? (pricing, liquidation threshold, reward rate, rebase trigger, etc.)

## 2. Staleness Analysis

For each oracle identified in Step 1:

### 2a. Staleness Checks Present?

| Oracle | `updatedAt` Checked? | Max Staleness Enforced? | Staleness Threshold | Appropriate? |
|--------|---------------------|------------------------|--------------------:|-------------|
| {name} | YES/NO | YES/NO | {seconds or NONE} | {analysis} |

**If NO staleness check**: What happens when the oracle returns stale data?
- [ ] Protocol uses stale price for liquidations → unfair liquidations
- [ ] Protocol uses stale price for minting → mispriced assets
- [ ] Protocol uses stale price for swaps → arbitrage opportunity
- [ ] Protocol uses stale rate for rewards → incorrect distribution

### 2b. Stale Data Impact Trace

For each consumer function, trace the impact of receiving data that is {heartbeat × 2} old:

| Consumer Function | Data Used | If Stale By {X}: Impact | Severity |
|-------------------|-----------|------------------------|----------|
| {function} | {price/rate} | {specific impact} | {H/M/L} |

### 2c. Chainlink-Specific Checks

| Check | Code Reference | Status |
|-------|---------------|--------|
| `latestRoundData()` return values ALL checked? | {location} | YES/NO |
| `answeredInRound >= roundId` verified? | {location} | YES/NO |
| `price > 0` validated? | {location} | YES/NO |
| `updatedAt != 0` validated? | {location} | YES/NO |
| Sequencer uptime feed checked? (L2 only) | {location} | YES/NO/N/A |

## 3. Decimal Normalization Audit

For each oracle data flow:

| Oracle | Oracle Decimals | Consumer Expects | Normalization Applied? | Correct? |
|--------|----------------|-----------------|----------------------|----------|
| {name} | {decimals()} | {expected by math} | YES/NO | {analysis} |

**Check**: Does the protocol call `decimals()` dynamically or hardcode it? If hardcoded → what if oracle upgrades and changes decimals?

**MANDATORY GREP**: Search all oracle consumer files for `1e18`, `1e8`, `1e6`, `10**18`, `10**8`, `10**6`, `1e10`, `10**10`. For each hit: (1) Is this a decimal normalization constant? (2) Does it match the ACTUAL oracle's `decimals()` return value? (3) If the oracle is swapped or upgraded, does this constant break?

**Decimal chain trace**: For each arithmetic operation using oracle data, trace the full decimal chain: `oracle_output_decimals` → `normalization_step` → `consumer_expected_decimals`. If any step uses a hardcoded constant rather than reading `decimals()` dynamically → FINDING.

**Common decimal mismatches**:
- Chainlink USD feeds: 8 decimals, but protocol assumes 18
- Chainlink ETH feeds: 18 decimals
- Token decimals: varies (6 for USDC, 18 for DAI)
- Cross-multiplication without normalization: `price * amount` where price and amount have different decimal bases

**Trace**: For each arithmetic operation using oracle data, verify dimensional consistency:
```
result_decimals = oracle_decimals + token_decimals - normalization_decimals
Expected: result_decimals == output_decimals
```

### 3d. Decimal Grep Sweep (MECHANICAL - MANDATORY)
Grep ALL oracle consumer files for `10**|decimals()|1e[0-9]|normaliz`. For each match, fill:

| File:Line | Pattern | Hardcoded Value | Oracle's Actual Decimals | Match? |
|-----------|---------|-----------------|-------------------------|--------|

If ANY row shows Match=NO or oracle decimals UNKNOWN with hardcoded constant → FINDING (R16).
Skipping this step is a Step Execution violation (✗3d).

<!-- LOAD_IF: TWAP -->
## 4. TWAP-Specific Analysis

If protocol uses any TWAP oracle (Uniswap V3 `observe()`, custom TWAP, etc.):

### 4a. TWAP Window Analysis

| TWAP Oracle | Window Length | Pool Liquidity | Manipulation Cost (est.) | Sufficient? |
|-------------|-------------|----------------|-------------------------|-------------|
| {oracle} | {seconds} | {USD value} | {estimated} | YES/NO |

**Rule of thumb**: TWAP window < 30 min AND pool TVL < $10M → potentially manipulable.

### 4b. TWAP Arithmetic

| Check | Status | Impact if Wrong |
|-------|--------|-----------------|
| Overflow protection on `tickCumulatives` difference? | YES/NO | {impact} |
| Geometric vs arithmetic mean - correct for use case? | {which used} | {impact if wrong} |
| Time-weighted vs block-weighted - which is used? | {which} | {manipulation vector} |
| Empty observation slots handled? | YES/NO | {impact} |

### 4c. TWAP Lagging Behavior

During rapid price movements, TWAP lags spot price. Trace:
- What happens when TWAP price is significantly lower than spot? (discounted minting/borrowing)
- What happens when TWAP price is significantly higher than spot? (premium liquidations)
- Is this lag exploitable by attackers who can predict the direction?

### 4d. TWAP Cold-Start Analysis

Check oracle behavior when history is insufficient: (1) zero snapshots, (2) single snapshot, (3) window period not yet elapsed.

| Cold-Start State | Oracle Return Value | Protocol Behavior | Exploitable? |
|------------------|--------------------:|-------------------|-------------|

For each exploitable state: can attacker act during cold-start window at manipulated price? Tag: [BOUNDARY:snapshots=0], [BOUNDARY:snapshots=1].
If TWAP returns 0 or reverts during cold-start with no fallback → FINDING (R16, minimum Medium).
<!-- END_LOAD_IF: TWAP -->

## 5. Oracle Weight / Threshold Boundaries

For multi-oracle systems or oracle-based thresholds:

<!-- LOAD_IF: MULTI_ORACLE -->
### 5a. Multi-Oracle Systems

| Oracle System | Aggregation Method | Oracle Count | Agreement Required | What if Disagreement? |
|---------------|-------------------|-------------|-------------------|----------------------|
| {system} | Median / Mean / Weighted / First-valid | {N} | {M of N} | {fallback behavior} |

**Check**: What happens at exact threshold boundaries?
- If median of [100, 100, 101]: result = 100. Is that correct?
- If weighted average with equal weights rounds down: impact?
- If one oracle reverts: does fallback handle it gracefully?
<!-- END_LOAD_IF: MULTI_ORACLE -->

### 5b. Oracle-Based Thresholds

| Threshold | Oracle Data Used | Threshold Value | At Exact Boundary | Off-by-One? |
|-----------|-----------------|----------------|-------------------|-------------|
| {name} | {oracle field} | {value} | {behavior at exact value} | YES/NO |

**Check `>` vs `>=`**: At the exact threshold value, does the protocol behave as intended?

### 5c. Deviation Reference Point Audit

For each deviation check in the protocol (maxDeviation, priceDeviation, deviationThreshold, etc.):

| Parameter | Measured Against | Reference Source | Reference Manipulable? | Reference Staleable? |
|-----------|-----------------|-----------------|----------------------|---------------------|

Checks:
1. What is the deviation MEASURED AGAINST? (previous on-chain price, TWAP, external oracle, hardcoded value)
2. Is the reference point itself manipulable? (e.g., if deviation checks current vs last-recorded, and last-recorded is admin-settable → admin can set a stale reference that makes all future prices "within deviation")
3. Can the reference become stale? (e.g., if reference is updated only on specific actions, and those actions stop occurring)
4. Is the first recorded price special? (no prior reference → deviation check may be bypassed on first update)
Tag: `[TRACE:deviation check: current vs {reference} → reference source: {X} → manipulable: {Y/N}]`

## 6. Oracle Failure Modes

For each oracle, model failure scenarios:

| Failure Mode | Oracle Behavior | Protocol Response | Impact | Mitigation Present? |
|-------------|-----------------|-------------------|--------|-------------------|
| Zero return | Returns 0 | {what happens} | {impact} | YES/NO |
| Revert | Call reverts | {what happens} | {impact} | YES/NO - try/catch? |
| Stale (heartbeat exceeded) | Returns old data | {what happens} | {impact} | YES/NO - staleness check? |
| Extreme value | Returns outlier | {what happens} | {impact} | YES/NO - bounds check? |
| Negative price (Chainlink int256) | Returns < 0 | {what happens} | {impact} | YES/NO - sign check? |
| Sequencer down (L2) | Stale + backlog | {what happens} | {impact} | YES/NO - uptime feed? |

**For each unmitigated failure mode**: What is the worst-case impact? Can it lead to fund loss?

**Circuit breaker check**: Does the protocol have a mechanism to pause oracle-dependent operations if the oracle enters a failure state?

## Finding Template

```markdown
**ID**: [OR-N]
**Severity**: [based on fund impact and likelihood of oracle failure/manipulation]
**Step Execution**: ✓1,2,3,4,5,6 | ✗(reasons) | ?(uncertain)
**Rules Applied**: [R1:✓, R4:✓, R10:✓, R16:✓]
**Location**: Contract.sol:LineN
**Title**: Oracle [issue type] in [function] enables [attack/failure]
**Description**: [Specific oracle issue with data flow trace]
**Impact**: [Quantified impact under worst-case oracle scenario]
```

---

## Step Execution Checklist (MANDATORY)

| Section | Required | Completed? | Notes |
|---------|----------|------------|-------|
| 1. Oracle Inventory | YES | ✓/✗/? | |
| 2. Staleness Analysis | YES | ✓/✗/? | For each oracle |
| 3. Decimal Normalization Audit | YES | ✓/✗/? | |
| 3d. Decimal Grep Sweep | YES | ✓/✗/? | MANDATORY mechanical step |
| 4. TWAP-Specific Analysis | IF TWAP used | ✓/✗(N/A)/? | |
| 4d. TWAP Cold-Start Analysis | IF TWAP used | ✓/✗(N/A)/? | Zero/single snapshot states |
| 5. Oracle Weight / Threshold Boundaries | IF multi-oracle or thresholds | ✓/✗(N/A)/? | |
| 5c. Deviation Reference Point Audit | IF deviation checks exist | ✓/✗(N/A)/? | Reference manipulability |
| 6. Oracle Failure Modes | YES | ✓/✗/? | For each oracle |
