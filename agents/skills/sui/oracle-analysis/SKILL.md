---
name: "oracle-analysis"
description: "Trigger Pattern ORACLE flag (required) - Inject Into Breadth agents, depth-external, depth-edge-case"
---

# ORACLE_ANALYSIS Skill (Sui)

> **Trigger Pattern**: ORACLE flag (required)
> **Inject Into**: Breadth agents, depth-external, depth-edge-case
> **Purpose**: Analyze oracle integrations in Sui Move protocols for staleness, decimal handling, failure modes, and manipulation vectors

For every oracle the protocol consumes:

**STEP PRIORITY**: Steps 6 (Failure Modes) and 5c (Deviation Reference) are where HIGH/CRITICAL severity findings most commonly hide. Do NOT rush these steps. If constrained, skip conditional sections (4a-4d, 5a) before skipping 5c or 6.

## 1. Oracle Inventory

Enumerate ALL oracle data sources the protocol reads:

| Oracle | Type | Module / Object | Functions Called | Consumers (protocol functions) | Update Frequency | Heartbeat |
|--------|------|-----------------|-----------------|-------------------------------|-----------------|-----------|
| {name} | Pyth / Switchboard V2 / Supra / Custom / On-chain TWAP | {module::function or shared object ID} | {get_price / get_price_no_older_than / etc.} | {list all} | {expected} | {documented or UNKNOWN} |

**For each oracle**: What decision does the protocol make based on this data? (pricing, liquidation threshold, reward rate, share price, swap amount, etc.)

**Sui-specific inventory checks**:
- Is the oracle data passed as a shared object parameter (`&PriceInfoObject`) or read from on-chain state?
- Does the protocol use `pyth::price_info::get_price_info_from_price_info_object()` or a wrapper?
- Are oracle objects passed by reference (`&`) or by mutable reference (`&mut`)?
- **Shared object contention**: Oracle objects like Pyth's `PriceInfoObject` are shared objects. During high-volatility periods, multiple transactions compete to read/update the same oracle object, causing transaction ordering dependencies and potential stale reads due to sequencing delays.

## 2. Staleness Analysis

For each oracle identified in Step 1:

### 2a. Staleness Checks Present?

| Oracle | Timestamp Checked? | Max Staleness Enforced? | Staleness Threshold | Clock Source | Appropriate? |
|--------|-------------------|------------------------|--------------------:|-------------|-------------|
| {name} | YES/NO | YES/NO | {seconds or NONE} | {clock::timestamp_ms / custom} | {analysis} |

**CRITICAL -- Sui uses MILLISECONDS**: `clock::timestamp_ms(clock)` returns milliseconds, not seconds. Pyth's `price.timestamp` returns seconds. If the protocol compares these without unit conversion, the staleness check is 1000x too lenient or too strict. Check for:
- `publish_time` (seconds from Pyth) vs `clock::timestamp_ms()` (milliseconds) -- MUST convert one to match the other
- Direct subtraction without unit normalization
- Constants like `MAX_STALENESS` -- is the value in seconds or milliseconds?

**Correct Sui staleness pattern**:
```move
// Pyth on Sui -- check price freshness
let price = pyth::price_info::get_price_info_from_price_info_object(price_info_object);
let price_data = price_info::get_price_feed(&price);
let current_price = price_feed::get_price(price_data);
let timestamp = price::get_timestamp(&current_price); // SECONDS
let now_ms = clock::timestamp_ms(clock); // MILLISECONDS -- Clock is shared object at 0x6
let now_s = now_ms / 1000; // Convert to seconds to match Pyth
assert!(now_s - timestamp <= MAX_STALENESS_SECONDS, E_STALE_PRICE);
```

**If NO staleness check**: What happens when the oracle returns stale data?
- [ ] Protocol uses stale price for liquidations -- unfair liquidations
- [ ] Protocol uses stale price for minting/deposits -- mispriced assets
- [ ] Protocol uses stale price for swaps -- arbitrage opportunity
- [ ] Protocol uses stale price for rewards -- incorrect distribution

### 2b. Stale Data Impact Trace

For each consumer function, trace the impact of receiving data that is {heartbeat x 2} old:

| Consumer Function | Data Used | If Stale By {X}: Impact | Severity |
|-------------------|-----------|------------------------|----------|
| {function} | {price/rate} | {specific impact} | {H/M/L} |

### 2c. Pyth-Specific Checks

| Check | Code Reference | Status |
|-------|---------------|--------|
| `get_price()` return values checked? | {location} | YES/NO |
| `price.price` validated > 0? | {location} | YES/NO |
| `price.conf` (confidence interval) checked? | {location} | YES/NO |
| `price.expo` (exponent) handled correctly? | {location} | YES/NO |
| `price.timestamp` staleness validated? | {location} | YES/NO |
| `get_price_no_older_than()` used vs manual check? | {location} | YES/NO |
| Pyth price update fee paid via `Coin<SUI>`? | {location} | YES/NO |

### 2d. Switchboard V2-Specific Checks

| Check | Code Reference | Status |
|-------|---------------|--------|
| `aggregator::latest_value()` return validated? | {location} | YES/NO |
| Result timestamp checked for staleness? | {location} | YES/NO |
| Decimal scaling applied correctly? (Switchboard custom decimals per feed) | {location} | YES/NO |
| Min response count checked? | {location} | YES/NO |
| Aggregator authority validated? | {location} | YES/NO |

### 2e. Supra-Specific Checks

| Check | Code Reference | Status |
|-------|---------------|--------|
| Price feed ID validated? | {location} | YES/NO |
| Decimal precision from feed metadata used? | {location} | YES/NO |
| Timestamp freshness checked? | {location} | YES/NO |
| Round completeness verified? | {location} | YES/NO |

## 3. Decimal Normalization Audit

For each oracle data flow:

| Oracle | Oracle Decimals / Exponent | Consumer Expects | Normalization Applied? | Correct? |
|--------|---------------------------|-----------------|----------------------|----------|
| {name} | {e.g., expo = -8 for Pyth} | {expected by math} | YES/NO | {analysis} |

**Pyth exponent handling**: Pyth returns `Price { price: i64, conf: u64, expo: i32, timestamp: u64 }`. The `expo` field is typically negative (e.g., -8 means price has 8 decimal places). Verify:
- Is `expo` read dynamically or assumed to be a fixed value?
- Is the sign of `expo` handled correctly (negative exponent = division, positive = multiplication)?
- Does `10^|expo|` computation overflow for large exponents?

**MANDATORY GREP**: Search all oracle consumer modules for hardcoded decimal constants: `1_000_000_000`, `100_000_000`, `1_000_000`, `10_000`, `1e8`, `1e6`, `1e9`, `DECIMAL`, `PRECISION`. For each hit: (1) Is this a decimal normalization constant? (2) Does it match the ACTUAL oracle's exponent? (3) If the oracle feed changes exponent, does this constant break?

**Decimal chain trace**: For each arithmetic operation using oracle data, trace the full decimal chain: `oracle_output_decimals` -> `normalization_step` -> `consumer_expected_decimals`. If any step uses a hardcoded constant rather than reading the exponent dynamically -> FINDING.

**Common Sui decimal mismatches**:
- Pyth price expo = -8, but protocol assumes -18 (or vice versa)
- SUI has 9 decimals (`MIST_PER_SUI = 1_000_000_000`)
- USDC on Sui has 6 decimals
- Cross-multiplication without normalization: `price * amount` where price and amount have different decimal bases

### 3d. Decimal Grep Sweep (MECHANICAL -- MANDATORY)
Grep ALL oracle consumer modules for `10_|decimals|PRECISION|SCALE|expo|pow`. For each match, fill:

| File:Line | Pattern | Hardcoded Value | Oracle's Actual Decimals/Expo | Match? |
|-----------|---------|-----------------|------------------------------|--------|

If ANY row shows Match=NO or oracle decimals UNKNOWN with hardcoded constant -> FINDING (R16).
Skipping this step is a Step Execution violation (x3d).

<!-- LOAD_IF: TWAP -->
## 4. TWAP-Specific Analysis

If protocol uses any TWAP oracle (on-chain pool observation, custom TWAP accumulator, etc.):

### 4a. TWAP Window Analysis

| TWAP Oracle | Window Length | Pool Liquidity | Manipulation Cost (est.) | Sufficient? |
|-------------|-------------|----------------|-------------------------|-------------|
| {oracle} | {seconds} | {USD value} | {estimated} | YES/NO |

**Rule of thumb**: TWAP window < 30 min AND pool TVL < $10M -> potentially manipulable.
**Sui-specific**: On Sui, TWAP typically relies on CLOB or AMM observation points. Check if the TWAP source is a CLOB (orderbook DEX) or AMM. CLOB TWAPs can be manipulated with limit orders that are never filled.

### 4b. TWAP Arithmetic

| Check | Status | Impact if Wrong |
|-------|--------|-----------------|
| Overflow protection on cumulative price difference? | YES/NO | {impact} |
| Geometric vs arithmetic mean -- correct for use case? | {which used} | {impact if wrong} |
| Time-weighted vs observation-count-weighted? | {which} | {manipulation vector} |
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
- If one oracle aborts: does fallback handle it gracefully?
<!-- END_LOAD_IF: MULTI_ORACLE -->

### 5b. Oracle-Based Thresholds

| Threshold | Oracle Data Used | Threshold Value | At Exact Boundary | Off-by-One? |
|-----------|-----------------|----------------|-------------------|-------------|
| {name} | {oracle field} | {value} | {behavior at exact value} | YES/NO |

**Check `>` vs `>=`**: At the exact threshold value, does the protocol behave as intended?

### 5c. Deviation Reference Point Audit

For each deviation check in the protocol (max_deviation, price_deviation, deviation_threshold, etc.):

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
| Abort | Function call aborts | {what happens} | {impact} | YES/NO -- caught? |
| Stale (heartbeat exceeded) | Returns old data | {what happens} | {impact} | YES/NO -- staleness check? |
| Extreme value | Returns outlier | {what happens} | {impact} | YES/NO -- bounds check? |
| Negative price (Pyth i64) | Returns < 0 | {what happens} | {impact} | YES/NO -- sign check? |
| High confidence interval | conf > threshold | {what happens} | {impact} | YES/NO -- conf check? |
| Price update not called | PriceInfoObject never refreshed | {what happens} | {impact} | YES/NO -- update enforced? |

**Sui-specific failure**: Pyth on Sui requires explicit price update transactions (`pyth::update_price_feeds`). If the protocol does not enforce fresh updates before reading, prices can be arbitrarily stale. Check:
- Does the protocol call `update_price_feeds` in the same PTB before reading?
- Or does it rely on external keepers to update? If so, what if keepers stop?
- Does the protocol use `get_price_no_older_than()` which enforces freshness?

**For each unmitigated failure mode**: What is the worst-case impact? Can it lead to fund loss?

**Circuit breaker check**: Does the protocol have a mechanism to pause oracle-dependent operations if the oracle enters a failure state?

## Finding Template

```markdown
**ID**: [OR-N]
**Severity**: [based on fund impact and likelihood of oracle failure/manipulation]
**Step Execution**: check1,2,3,4,5,6 | x(reasons) | ?(uncertain)
**Rules Applied**: [R1:check, R4:check, R10:check, R16:check]
**Location**: module::function:LineN
**Title**: Oracle [issue type] in [function] enables [attack/failure]
**Description**: [Specific oracle issue with data flow trace]
**Impact**: [Quantified impact under worst-case oracle scenario]
```

## Instantiation Parameters
```
{CONTRACTS}           -- Move modules to analyze
{ORACLE_MODULES}      -- Oracle integration modules (pyth, supra, custom)
{PRICE_OBJECTS}       -- Shared oracle objects (PriceInfoObject, etc.)
{CONSUMER_FUNCTIONS}  -- Functions that read oracle data
{ORACLE_TYPE}         -- Pyth / Supra / Switchboard / Custom
{HEARTBEAT}           -- Expected update frequency
```

## Output Schema
| Field | Required | Description |
|-------|----------|-------------|
| oracle_inventory | yes | All oracle sources and consumers |
| staleness_analysis | yes | Staleness checks and impact |
| decimal_audit | yes | Decimal normalization correctness |
| failure_modes | yes | Each oracle's failure scenarios |
| finding | yes | CONFIRMED / REFUTED / CONTESTED |
| evidence | yes | Code locations with line numbers |
| step_execution | yes | Status for each step |

---

## Step Execution Checklist (MANDATORY)

| Section | Required | Completed? | Notes |
|---------|----------|------------|-------|
| 1. Oracle Inventory | YES | check/x/? | |
| 2. Staleness Analysis | YES | check/x/? | For each oracle |
| 3. Decimal Normalization Audit | YES | check/x/? | |
| 3d. Decimal Grep Sweep | YES | check/x/? | MANDATORY mechanical step |
| 4. TWAP-Specific Analysis | IF TWAP used | check/x(N/A)/? | |
| 4d. TWAP Cold-Start Analysis | IF TWAP used | check/x(N/A)/? | Zero/single snapshot states |
| 5. Oracle Weight / Threshold Boundaries | IF multi-oracle or thresholds | check/x(N/A)/? | |
| 5c. Deviation Reference Point Audit | IF deviation checks exist | check/x(N/A)/? | Reference manipulability |
| 6. Oracle Failure Modes | YES | check/x/? | For each oracle |
