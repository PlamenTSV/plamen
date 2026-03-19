---
name: "oracle-analysis"
description: "Trigger Pattern ORACLE flag (required) - Inject Into Breadth agents, depth-external, depth-edge-case"
---

# ORACLE_ANALYSIS Skill

> **Trigger Pattern**: ORACLE flag (required)
> **Inject Into**: Breadth agents, depth-external, depth-edge-case
> **Purpose**: Analyze all oracle integrations in Aptos Move protocols for staleness, decimal errors, zero/negative prices, confidence intervals, multi-oracle aggregation, and failure modes

For every oracle the protocol consumes:

**STEP PRIORITY**: Steps 6 (Failure Modes) and 5c (Deviation Reference) are where HIGH/CRITICAL severity findings most commonly hide. Do NOT rush these steps. If constrained, skip conditional sections (4a-4d, 5a) before skipping 5c or 6.

## 1. Oracle Inventory

Enumerate ALL oracle data sources the protocol reads:

| Oracle | Type | Module Path | Functions Called | Consumers (protocol functions) | Update Frequency | Freshness Guarantee |
|--------|------|-------------|-----------------|-------------------------------|-----------------|---------------------|
| {name} | Pyth / Switchboard / Custom / On-chain TWAP | {module::path} | {get_price / get_result / etc.} | {list all} | {expected} | {documented or UNKNOWN} |

**Aptos oracle landscape**:
- **Pyth Network**: `pyth::price_feed` module, returns `Price { price: I64, conf: u64, expo: I64, publish_time: u64 }`
- **Switchboard**: `switchboard::aggregator` module, returns aggregator results with `mantissa` and `scale`
- **Custom price feeds**: Protocol-specific oracles using `Table` or `SmartTable` for price storage
- **On-chain TWAP**: DEX-derived time-weighted prices (Thala, LiquidSwap, Pontem)

**For each oracle**: What decision does the protocol make based on this data? (pricing, liquidation threshold, reward rate, rebase trigger, collateral valuation, etc.)

## 2. Staleness Analysis

For each oracle identified in Step 1:

### 2a. Staleness Checks Present?

| Oracle | Timestamp Checked? | Max Staleness Enforced? | Staleness Threshold | Appropriate? |
|--------|-------------------|------------------------|--------------------:|-------------|
| {name} | YES/NO | YES/NO | {seconds or NONE} | {analysis} |

**Pyth-specific**: Is `price.publish_time` compared against `timestamp::now_seconds()`? What max age is enforced?
**Switchboard-specific**: Is the aggregator's `latest_confirmed_round.round_open_timestamp` validated?

**If NO staleness check**: What happens when the oracle returns stale data?
- [ ] Protocol uses stale price for liquidations -- unfair liquidations
- [ ] Protocol uses stale price for minting -- mispriced assets
- [ ] Protocol uses stale price for swaps -- arbitrage opportunity
- [ ] Protocol uses stale rate for rewards -- incorrect distribution

### 2b. Stale Data Impact Trace

For each consumer function, trace the impact of receiving data that is {freshness_guarantee x 2} old:

| Consumer Function | Data Used | If Stale By {X}: Impact | Severity |
|-------------------|-----------|------------------------|----------|
| {function} | {price/rate} | {specific impact} | {H/M/L} |

### 2c. Pyth-Specific Checks

| Check | Code Reference | Status |
|-------|---------------|--------|
| `get_price()` or `get_price_no_older_than()` used? | {location} | {which} |
| `price.publish_time` freshness validated? | {location} | YES/NO |
| `price.price` (I64) sign checked (> 0)? | {location} | YES/NO |
| `price.conf` confidence interval checked? | {location} | YES/NO |
| `price.expo` (negative exponent) handled correctly? | {location} | YES/NO |
| Price feed ID hardcoded or configurable? | {location} | {which} |

### 2d. Switchboard-Specific Checks

| Check | Code Reference | Status |
|-------|---------------|--------|
| Aggregator authority validated? | {location} | YES/NO |
| Result staleness checked? | {location} | YES/NO |
| Min/max response thresholds enforced? | {location} | YES/NO |
| Aggregator config (min oracle results, variance threshold) appropriate? | {location} | YES/NO |

## 3. Decimal Normalization Audit

For each oracle data flow:

| Oracle | Oracle Decimals/Exponent | Consumer Expects | Normalization Applied? | Correct? |
|--------|------------------------|-----------------|----------------------|----------|
| {name} | {expo or scale} | {expected by math} | YES/NO | {analysis} |

**Pyth decimal handling**: Pyth uses `expo` field (typically negative, e.g., `expo = -8` means 8 decimal places). The actual price = `price.price * 10^expo`. Common errors:
- Treating `expo` as positive when it is negative
- Not converting I64 exponent to unsigned for power calculation
- Mixing Pyth's expo-based decimals with token decimals (Aptos Coin typically uses 8 decimals, but FungibleAsset varies)

**Switchboard decimal handling**: Uses `mantissa` and `scale` (or `decimals`). Actual value = `mantissa * 10^(-scale)`.

**MANDATORY GREP**: Search all oracle consumer files for hardcoded decimal constants: `100000000`, `1e8`, `10_000_000`, `DECIMAL`, `PRECISION`. For each hit: (1) Is this a decimal normalization constant? (2) Does it match the ACTUAL oracle's decimal format? (3) If the oracle feed changes or is swapped, does this constant break?

**Decimal chain trace**: For each arithmetic operation using oracle data, trace the full decimal chain: `oracle_output_decimals` -> `normalization_step` -> `consumer_expected_decimals`. If any step uses a hardcoded constant rather than reading decimals dynamically -> FINDING.

**Common decimal mismatches on Aptos**:
- Pyth USD feeds: `expo = -8` (8 decimals), but protocol assumes 18
- Aptos native Coin<T>: typically 8 decimals
- FungibleAsset: varies per metadata configuration
- Cross-multiplication without normalization: `price * amount` where price and amount have different decimal bases

### 3d. Decimal Grep Sweep (MECHANICAL -- MANDATORY)

Grep ALL oracle consumer files for `10_u128|pow\(10|DECIMALS|PRECISION|100000000|normalize`. For each match, fill:

| File:Line | Pattern | Hardcoded Value | Oracle's Actual Decimals | Match? |
|-----------|---------|-----------------|-------------------------|--------|

If ANY row shows Match=NO or oracle decimals UNKNOWN with hardcoded constant -> FINDING (R16).
Skipping this step is a Step Execution violation (x3d).

<!-- LOAD_IF: TWAP -->
## 4. TWAP-Specific Analysis

If protocol uses any TWAP oracle (DEX-derived, custom accumulator, etc.):

### 4a. TWAP Window Analysis

| TWAP Oracle | Window Length | Pool Liquidity | Manipulation Cost (est.) | Sufficient? |
|-------------|-------------|----------------|-------------------------|-------------|
| {oracle} | {seconds} | {USD value} | {estimated} | YES/NO |

**Rule of thumb**: TWAP window < 30 min AND pool TVL < $10M -> potentially manipulable.

### 4b. TWAP Arithmetic

| Check | Status | Impact if Wrong |
|-------|--------|-----------------|
| Overflow protection on cumulative price difference? | YES/NO | {impact} |
| Geometric vs arithmetic mean -- correct for use case? | {which used} | {impact if wrong} |
| Time-weighted vs block-weighted -- which is used? | {which} | {manipulation vector} |
| Empty observation slots handled? | YES/NO | {impact} |
| Aptos epoch boundaries handled? (epoch changes can affect timestamps) | YES/NO | {impact} |

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
If TWAP returns 0 or aborts during cold-start with no fallback -> FINDING (R16, minimum Medium).
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
- If one oracle call aborts: does fallback handle it gracefully?
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
2. Is the reference point itself manipulable? (e.g., if deviation checks current vs last-recorded, and last-recorded is admin-settable -> admin can set a stale reference that makes all future prices "within deviation")
3. Can the reference become stale? (e.g., if reference is updated only on specific actions, and those actions stop occurring)
4. Is the first recorded price special? (no prior reference -> deviation check may be bypassed on first update)
Tag: `[TRACE:deviation check: current vs {reference} -> reference source: {X} -> manipulable: {Y/N}]`

## 6. Oracle Failure Modes

For each oracle, model failure scenarios:

| Failure Mode | Oracle Behavior | Protocol Response | Impact | Mitigation Present? |
|-------------|-----------------|-------------------|--------|-------------------|
| Zero return | Returns price = 0 | {what happens} | {impact} | YES/NO |
| Abort | Call aborts (Move has no try/catch) | {what happens} | {impact} | YES/NO -- can_* check first? |
| Stale (freshness exceeded) | Returns old data | {what happens} | {impact} | YES/NO -- staleness check? |
| Extreme value | Returns outlier | {what happens} | {impact} | YES/NO -- bounds check? |
| Negative price (Pyth I64) | Returns < 0 | {what happens} | {impact} | YES/NO -- sign check? |
| Feed not initialized | Resource does not exist | {what happens} | {impact} | YES/NO -- exists<T> check? |

**Aptos-specific failure note**: Move does not have try/catch. Oracle call failures result in transaction abort. This means:
- External oracle call that aborts -> entire transaction reverts
- No graceful fallback unless protocol pre-checks oracle state with `exists<>` or similar
- Oracle DoS (feed stops updating) -> all dependent functions become uncallable

**For each unmitigated failure mode**: What is the worst-case impact? Can it lead to fund loss?

**Circuit breaker check**: Does the protocol have a mechanism to pause oracle-dependent operations if the oracle enters a failure state?

## Instantiation Parameters
```
{CONTRACTS}           -- Move modules to analyze
{ORACLE_MODULES}      -- Oracle module paths (pyth::price_feed, switchboard::aggregator, custom)
{CONSUMER_FUNCTIONS}  -- Functions that read oracle data
{PRICE_FEED_IDS}      -- Pyth price feed identifiers or Switchboard aggregator addresses
{TOKEN_DECIMALS}      -- Decimal configuration of tokens in scope
```

## Finding Template

```markdown
**ID**: [OR-N]
**Severity**: [based on fund impact and likelihood of oracle failure/manipulation]
**Step Execution**: checkmark1,2,3,4,5,6 | x(reasons) | ?(uncertain)
**Rules Applied**: [R1:Y, R4:Y, R10:Y, R16:Y]
**Location**: module::function:LineN
**Title**: Oracle [issue type] in [function] enables [attack/failure]
**Description**: [Specific oracle issue with data flow trace]
**Impact**: [Quantified impact under worst-case oracle scenario]
```

## Output Schema

| Field | Required | Description |
|-------|----------|-------------|
| oracle_inventory | yes | All oracle data sources and consumers |
| staleness_vectors | yes | Unmitigated staleness paths |
| decimal_mismatches | yes | Decimal normalization issues |
| failure_modes | yes | Oracle failure scenarios and protocol response |
| finding | yes | CONFIRMED / REFUTED / CONTESTED |
| evidence | yes | Code locations with line numbers |
| step_execution | yes | Status for each step |

---

## Step Execution Checklist (MANDATORY)

| Section | Required | Completed? | Notes |
|---------|----------|------------|-------|
| 1. Oracle Inventory | YES | Y/x/? | |
| 2. Staleness Analysis | YES | Y/x/? | For each oracle |
| 2c. Pyth-Specific Checks | IF Pyth used | Y/x(N/A)/? | |
| 2d. Switchboard-Specific Checks | IF Switchboard used | Y/x(N/A)/? | |
| 3. Decimal Normalization Audit | YES | Y/x/? | |
| 3d. Decimal Grep Sweep | YES | Y/x/? | MANDATORY mechanical step |
| 4. TWAP-Specific Analysis | IF TWAP used | Y/x(N/A)/? | |
| 4d. TWAP Cold-Start Analysis | IF TWAP used | Y/x(N/A)/? | Zero/single snapshot states |
| 5. Oracle Weight / Threshold Boundaries | IF multi-oracle or thresholds | Y/x(N/A)/? | |
| 5c. Deviation Reference Point Audit | IF deviation checks exist | Y/x(N/A)/? | Reference manipulability |
| 6. Oracle Failure Modes | YES | Y/x/? | For each oracle |
