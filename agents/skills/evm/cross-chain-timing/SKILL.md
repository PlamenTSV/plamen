---
name: "cross-chain-timing"
description: "Type Thought-template (instantiate before use) - Research basis Multi-block arbitrage windows, bridge latency exploitation"
---

# Skill: Cross-Chain Timing Analysis

> **Type**: Thought-template (instantiate before use)
> **Research basis**: Multi-block arbitrage windows, bridge latency exploitation

## Trigger Patterns
```
bridge|L1|L2|tunnel|messenger|crossChain|sendMessage|receiveMessage|
_processMessageFrom|LayerZero|CCIP|Wormhole|Arbitrum|Optimism
```

## Reasoning Template

### Step 1: Identify Sync Mechanism
- Find all cross-chain messaging calls in {CONTRACTS}
- For each call, determine:
  - What state is being synced? (rates, balances, epochs, totals)
  - What triggers the sync? (every operation, periodic, manual)
  - What bridge/messenger is used?

### Step 2: Measure Timing Window
- Research {BRIDGE_PROTOCOL} documentation for realistic latency
- Typical ranges: optimistic rollups (10-30 min), zk-rollups (minutes), standard bridges (20-60 min)
- Document: submission -> finality -> execution timeline

### Step 3: Trace Stale State Usage
- From {SYNC_POINT}, identify all state that depends on synced values
- For each dependent operation at {DEPENDENT_FUNCTIONS}:
  - Is fresh state required or is stale acceptable?
  - What decisions are made with potentially stale data?

### Step 4: Model Arbitrage Sequence
```
1. Attacker monitors {SOURCE_CHAIN} for state changes at {MONITOR_POINT}
2. State change triggers sync message (latency window opens)
3. Attacker executes on {DEST_CHAIN} at {EXPLOIT_FUNCTION} using stale {STALE_STATE}
4. Sync message arrives, state updates
5. Attacker profits: {PROFIT_CALCULATION}
```

### Step 5: Quantify Viability
- Maximum {STALE_STATE} delta during sync window: {MAX_DELTA}
- Profit calculation: {PROFIT_FORMULA}
- Cost calculation: gas + bridge fees + capital lockup
- Viable if: profit > cost AND repeatable

## Key Questions (must answer all)
1. What is the realistic sync latency for {BRIDGE_PROTOCOL}? (cite documentation)
2. Can an attacker monitor {SOURCE_CHAIN} and front-run sync on {DEST_CHAIN}?
3. What is the maximum {STALE_STATE} change during normal operation?
4. Is this attack repeatable or one-time?

## Common False Positives
- **Monotonic state**: If {STALE_STATE} only increases (never decreases), arbitrage may not be profitable in both directions -- verify directionality
- **Negligible delta**: If max delta during sync window is <0.1%, may not be economically viable after costs
- **Rate limiting**: If operations have cooldowns longer than sync latency, window may not be exploitable
- **Same-block dependency**: If dependent operation requires same-block freshness (checked via block number), stale state is rejected

## Instantiation Parameters
```
{CONTRACTS}           -- List of contracts to analyze
{BRIDGE_PROTOCOL}     -- Specific bridge (LayerZero, CCIP, Arbitrum Messenger, etc.)
{SYNC_POINT}          -- Function/event where sync occurs
{DEPENDENT_FUNCTIONS} -- Functions that read synced state
{SOURCE_CHAIN}        -- Chain where state originates
{DEST_CHAIN}          -- Chain where stale state is exploited
{MONITOR_POINT}       -- What attacker monitors on source chain
{EXPLOIT_FUNCTION}    -- Function attacker calls on dest chain
{STALE_STATE}         -- Specific state variable that becomes stale
{PROFIT_CALCULATION}  -- Formula for attacker profit
{MAX_DELTA}           -- Maximum observed state change
{PROFIT_FORMULA}      -- (new_value - old_value) * position_size
```

## Output Schema
| Field | Required | Description |
|-------|----------|-------------|
| sync_mechanism | yes | How state is synced (bridge, function, event) |
| latency_estimate | yes | Realistic sync latency with source |
| stale_operations | yes | List of operations using potentially stale state |
| arbitrage_sequence | yes | Step-by-step attack if viable |
| profit_viability | yes | VIABLE / NOT_VIABLE / NEEDS_VERIFICATION |
| finding | yes | CONFIRMED / REFUTED / NEEDS_DEPTH |
| evidence | yes | Code locations with line numbers |
