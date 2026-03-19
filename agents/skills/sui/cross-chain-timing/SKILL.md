---
name: "cross-chain-timing"
description: "Type Thought-template (instantiate before use) - Trigger Pattern bridge|wormhole|axelar|layerzero|sui_bridge|cross_chain|relay|vaa|guardian|emitter|ccip"
---

# Skill: Cross-Chain Timing Analysis (Sui)

> **Type**: Thought-template (instantiate before use)
> **Trigger Pattern**: `bridge|wormhole|axelar|layerzero|sui_bridge|cross_chain|relay|vaa|guardian|emitter|ccip`
> **Inject Into**: Breadth agents, depth-external
> **Finding prefix**: `[CCT-N]`
> **Rules referenced**: R1, R2, R4, R8, R10, R16
> **Research basis**: Multi-block arbitrage windows, bridge latency exploitation

Covers: cross-chain message verification, timing asymmetry between Sui and other chains, object creation requirements for bridged assets, nonce/sequence replay protection, and cross-chain price relay staleness.

Sui's consensus model produces checkpoints every ~0.5-2 seconds and epochs every ~24 hours. Cross-chain messaging relies on bridge protocols (Wormhole, Axelar, Sui Bridge native) that verify Sui checkpoints before relaying messages. Sui's fast finality (~2-3s checkpointed) creates timing asymmetry with slower chains (Ethereum ~12min, rollups 10-60min).

---

## Trigger Patterns
```
bridge|wormhole|axelar|layerzero|sui_bridge|cross_chain|vaa|relay|messenger|
send_message|receive_message|bridge_transfer
```

---

## Step 1: Identify Cross-Chain Messaging Infrastructure

Find all cross-chain messaging calls in {CONTRACTS}:

| # | Function | Module | Direction | Bridge Protocol | State Synced | Trigger |
|---|----------|--------|-----------|-----------------|-------------|---------|
| 1 | {func} | {module} | OUTBOUND/INBOUND | {protocol} | {what state} | {when sent} |

For each call, determine:
- What state is being synced? (rates, balances, epochs, totals, oracle prices)
- What triggers the sync? (every operation, periodic, manual keeper call)
- What bridge/messenger is used? (Wormhole VAA, Axelar GMP, Sui Bridge native, custom relay)
- Is the message authenticated? (VAA signatures, validator attestations, committee signatures)

### Wormhole-Specific Inventory (Sui)
If Wormhole is detected:

| Component | Function/Object | Purpose | Location |
|-----------|----------------|---------|----------|
| VAA Verification | `vaa::parse_and_verify()` | Guardian signature verification | {module:line} |
| Message Posting | `publish_message()` | Send message from Sui | {module:line} |
| Token Bridge | `complete_transfer()` / `create_wrapped()` | Token bridging | {module:line} |
| Emitter Object | Shared or owned emitter state | Message source identity | {module:line} |

### Sui Bridge (Native) Inventory
If the native Sui Bridge is detected:

| Component | Function/Object | Purpose | Location |
|-----------|----------------|---------|----------|
| Bridge Committee | Shared committee object | Validator attestation | {module:line} |
| Message Verification | `verify_and_execute()` | Committee signature check | {module:line} |
| Token Transfer | Bridge treasury operations | Lock/unlock bridged tokens | {module:line} |

**Sui-specific outbound/inbound**:
- Outbound messages: typically emitted as events or written to shared objects for relayer pickup
- Inbound messages: typically processed by a function receiving a VAA or equivalent proof
- `clock::timestamp_ms()` provides millisecond timestamps -- check if timestamp freshness is validated on message receipt

---

## Step 2: Cross-Chain Message Verification Audit

For EACH inbound cross-chain message consumed by the protocol:

### 2a. Wormhole VAA Verification Checklist (Sui)

| # | Check | Status | Location | Notes |
|---|-------|--------|----------|-------|
| 1 | Guardian signature count >= quorum (13/19) | YES/NO | {line} | Does protocol verify `guardian_set_index` is current? |
| 2 | Guardian set is current (not expired) | YES/NO | {line} | Old guardian sets may be compromised |
| 3 | Emitter chain ID validated | YES/NO | {line} | Reject messages from unexpected source chains |
| 4 | Emitter address validated | YES/NO | {line} | Reject messages from unexpected contracts |
| 5 | Sequence number replay check | YES/NO | {line} | Each VAA should be processed exactly once |
| 6 | Consistency level validated | YES/NO | {line} | `finalized` vs `confirmed` |
| 7 | Payload format validated | YES/NO | {line} | Malformed payload handling |
| 8 | VAA object authenticity | YES/NO | {line} | Is VAA object from the actual Wormhole package? Type check on package address. |

**Critical**: Missing checks 1-5 = **CRITICAL** (arbitrary cross-chain message injection). Missing checks 6-8 = **HIGH**.

**Sui-specific**: On Sui, Wormhole VAAs are represented as objects. Verify the VAA object type comes from the authentic Wormhole package (check package address) -- an attacker could deploy a fake Wormhole package with matching type names.

### 2b. Generic Bridge Verification

For non-Wormhole bridges:

| # | Check | Status | Location | Notes |
|---|-------|--------|----------|-------|
| 1 | Message source authenticated (signatures/proofs) | YES/NO | {line} | |
| 2 | Source chain ID validated | YES/NO | {line} | |
| 3 | Source contract/address validated | YES/NO | {line} | |
| 4 | Replay protection (nonce/sequence/Table lookup) | YES/NO | {line} | |
| 5 | Message freshness (timestamp check vs `clock::timestamp_ms`) | YES/NO | {line} | |
| 6 | Relayer authorization (if applicable) | YES/NO | {line} | |

---

## Step 3: Timing Window Analysis

### 3a. Finality Asymmetry Model

| Chain | Optimistic Finality | Checkpointed Finality | Protocol Assumes |
|-------|--------------------|-----------------------|-----------------|
| Sui | ~400ms (execution) | ~2-3s (checkpoint) | {which level?} |
| {Remote Chain} | {time} | {time} | {which level?} |
| **Asymmetry Window** | -- | -- | **{max delay between chains}** |

**Critical question**: When Sui processes a message about remote chain state, how old can that state be? Compute: `max_staleness = remote_finality + bridge_relay_delay + sui_processing_time`

### 3b. Stale State Usage Trace

For each piece of state synced cross-chain:

| State Variable | Source Chain | Sync Trigger | Max Staleness | Sui Functions Using It | Fresh Required? |
|----------------|-------------|-------------|--------------|----------------------|----------------|
| {state} | {chain} | {event/periodic/manual} | {time} | {list functions} | YES/NO |

For each dependent function on Sui:
- Is fresh state required or is stale acceptable?
- What decisions are made with potentially stale data?
- Is there a staleness check (e.g., comparing `clock::timestamp_ms()` against message timestamp)?

**Sui-specific checks**:
- Are there epoch-boundary effects? (Sui epoch changes can affect staking rewards, validator sets)
- Is the synced state stored in a shared object that other transactions can race against?
- No mempool in Sui: front-running model differs from EVM (but sequencing attacks via validator collusion possible for shared objects)

### 3c. Sui-to-Remote Timing Attack

Sui's fast finality means actions on Sui are visible almost immediately, but take time to propagate to remote chains:

```
1. Attacker acts on Sui (visible in ~2-3s checkpoint)
2. Sui message posted via bridge (begins relay)
3. TIMING WINDOW: Remote chain does not yet know about Sui action
4. Attacker acts on remote chain using pre-Sui-action state
5. Bridge message arrives on remote chain -- state updates
6. Attacker profited from acting on both chains during asymmetry
```

### 3d. Remote-to-Sui Timing Attack

```
1. State changes on remote chain (e.g., price moves, governance action)
2. Bridge message relay begins (latency: {estimate})
3. TIMING WINDOW: Sui still uses old remote state
4. Attacker acts on Sui using stale remote state (low tx cost)
5. Bridge message arrives on Sui -- state updates
6. Attacker profited from Sui action with stale state
```

---

## Step 4: Object Creation Requirements

Cross-chain operations on Sui have unique object requirements:

| # | Check | Status | Notes |
|---|-------|--------|-------|
| 1 | Recipient object/account exists before transfer arrival? | YES/NO | Who creates it? Who pays gas? |
| 2 | Are wrapped/bridged coin types created correctly? | YES/NO | `TreasuryCap` held by bridge, OTW consumed correctly? |
| 3 | What happens if recipient cannot receive the object? | {revert/queue/escrow} | Reverted transfers may be lost on source chain |
| 4 | Can attacker manipulate shared objects between message arrival and execution? | YES/NO | Consensus ordering is non-deterministic from user's perspective |
| 5 | Are bridged asset objects shared or owned? | {shared/owned} | Shared: contention risk. Owned: only recipient can use. |
| 6 | Is there a claim/complete mechanism or auto-delivery? | {claim/auto} | Claim: user must submit tx. Auto: relayer delivers. |

**Sui-specific**: Bridged tokens on Sui are typically `Coin<BridgedType>` where `BridgedType` was registered by the bridge via OTW. Verify: is the `TreasuryCap` for bridged tokens held exclusively by the bridge? Can anyone else mint bridged tokens? If TreasuryCap is stored in a shared object, check that access control prevents unauthorized minting.

---

## Step 5: Nonce and Sequence Management

| # | Check | Status | Location | Notes |
|---|-------|--------|----------|-------|
| 1 | Replay protection exists | YES/NO | {line} | Method: {Table<Hash,bool> / dynamic field / counter / unique object per message} |
| 2 | Replay check is BEFORE state changes | YES/NO | {line} | If after: partial replay possible |
| 3 | Out-of-order messages handled | YES/NO | {line} | Strict ordering vs any-order processing |
| 4 | Sequence gaps handled | YES/NO | {line} | What if message N+1 arrives before N? |
| 5 | Replay storage bounded | YES/NO | {line} | Table/Bag may grow unbounded (DoS via storage cost) |
| 6 | Double-spend across chains | YES/NO | {line} | Same asset spent on both chains during relay |

**Sui replay patterns**:
- **Table<Hash, bool>**: Store processed message hashes. Reliable but Table grows unbounded.
- **Dynamic field per message**: Add dynamic field with message ID as key. Same growth concern.
- **Unique object per message**: Create an object per processed message (exists = processed). Objects persist permanently on-chain.
- **Counter**: Only process sequence N if N-1 was processed. Enforces ordering but blocks on gaps.

---

## Step 6: Cross-Chain Price Relay Audit

If oracle prices are relayed cross-chain:

| # | Check | Status | Notes |
|---|-------|--------|-------|
| 1 | Price freshness validated on Sui side (`clock::timestamp_ms`) | YES/NO | Max acceptable age? |
| 2 | Price source authenticated (bridge signature) | YES/NO | Can fake price be relayed? |
| 3 | Price deviation bounds | YES/NO | Max delta from last known price? |
| 4 | Fallback if relay is delayed/offline | YES/NO | What happens to price-dependent operations? |
| 5 | Flash loan on source chain can manipulate relayed price | YES/NO | Is source price spot or TWAP? |

**Staleness calculation**: `relay_staleness = source_price_age + bridge_latency + sui_processing`

If `relay_staleness > acceptable_threshold` at worst case, price is stale. Apply Rule 16 (Oracle Integrity).

---

## Step 7: Quantify Arbitrage Viability

```
1. Attacker monitors {SOURCE_CHAIN} for state changes at {MONITOR_POINT}
2. State change triggers sync message (latency window opens: ~{LATENCY} minutes)
3. Attacker executes on Sui at {EXPLOIT_FUNCTION} using stale {STALE_STATE}
   - Sui transaction cost is very low (<$0.01 per tx)
   - PTB allows multi-step atomic exploitation
4. Sync message arrives on Sui, state updates
5. Profit = {PROFIT_FORMULA}
6. Cost = bridge_fees + Sui_gas + capital_lockup_cost
7. Viable if: profit > cost AND repeatable
```

**Sui cost model**: Sui gas is paid in SUI, typically very low (<$0.01 per tx). Cost barrier is primarily bridge fees and capital requirements. Low gas makes small-margin attacks more viable than on EVM.

---

## Key Questions (must answer all)

1. What is the realistic sync latency for {BRIDGE_PROTOCOL} on Sui? (cite documentation)
2. Can an attacker monitor {SOURCE_CHAIN} and exploit stale state on Sui (or vice versa) before sync completes?
3. What is the maximum {STALE_STATE} change during normal operation within the sync window?
4. Is this attack repeatable or one-time?
5. Does the protocol validate message timestamps against `clock::timestamp_ms()`?
6. Are bridged token TreasuryCaps exclusively held by the bridge?
7. Is replay protection complete (covers all message types, all chains)?
8. Are cross-chain prices validated for freshness AND deviation bounds?

---

## Common False Positives

- **Monotonic state**: If synced state only increases, arbitrage may not be profitable in both directions
- **Negligible delta**: If max delta during sync window is <0.1%, may not be economically viable after costs
- **Rate limiting**: If operations have cooldowns longer than sync latency, window may not be exploitable
- **Timestamp freshness check**: If protocol compares message timestamp against `clock::timestamp_ms()` and rejects stale messages, window is bounded
- **Epoch-aligned sync**: If sync happens once per epoch (~24h) and this is documented/intended, staleness within an epoch may be by design
- **Bridge-level protections**: Some bridges have rate limiting or value caps that bound exploitation

---

## Instantiation Parameters

```
{CONTRACTS}           -- List of modules to analyze
{BRIDGE_PROTOCOL}     -- Specific bridge (Wormhole, Axelar, Sui Bridge, custom)
{SYNC_POINT}          -- Function where inbound sync occurs
{DEPENDENT_FUNCTIONS} -- Functions that read synced state
{SOURCE_CHAIN}        -- Chain where state originates
{DEST_CHAIN}          -- Chain where stale state is exploited (may be Sui)
{MONITOR_POINT}       -- What attacker monitors on source chain
{EXPLOIT_FUNCTION}    -- Function attacker calls using stale state
{STALE_STATE}         -- Specific state variable that becomes stale
{PROFIT_FORMULA}      -- (new_value - old_value) * position_size
{MAX_DELTA}           -- Maximum observed state change during sync window
{LATENCY}             -- Estimated bridge latency in minutes
```

---

## Output Schema

| Field | Required | Description |
|-------|----------|-------------|
| bridge_inventory | yes | All cross-chain messaging infrastructure |
| verification_audit | yes | Message verification completeness |
| timing_windows | yes | Asymmetry windows with duration estimates |
| object_creation | yes | Bridged asset object requirements and failure modes |
| replay_protection | yes | Nonce/sequence management assessment |
| price_relay_audit | if applicable | Cross-chain price freshness and manipulation risk |
| arbitrage_viability | yes | Quantified attack profitability or NOT_VIABLE |
| finding | yes | CONFIRMED / REFUTED / CONTESTED |
| evidence | yes | Code locations with line numbers |

---

### Denylist Enforcement Lag
- **Denylist enforcement lag**: For cross-chain denylist/blocklist updates, check the window between message receipt and enforcement. Can transactions from denylisted addresses execute during this window? Are in-flight operations for denylisted addresses cancelled or allowed to complete?

---

## Step Execution Checklist (MANDATORY)

| Step | Required | Completed? | Notes |
|------|----------|------------|-------|
| 1. Identify Cross-Chain Messaging Infrastructure | YES | | All cross-chain calls enumerated |
| 2. Cross-Chain Message Verification Audit | YES | | VAA/message verification complete |
| 3. Timing Window Analysis (both directions) | YES | | Cite bridge documentation |
| 4. Object Creation Requirements | YES | | Bridged token TreasuryCap security |
| 5. Nonce and Sequence Management | YES | | Replay storage boundedness |
| 6. Cross-Chain Price Relay Audit | IF price relay detected | | |
| 7. Quantify Arbitrage Viability | YES | | Profit vs cost with real numbers |

### Cross-Reference Markers

**After Step 2**: If message verification is incomplete -> immediate finding, do not wait for timing analysis.

**After Step 3**: Feed timing windows to TEMPORAL_PARAMETER_STALENESS skill for parameters cached across chain boundaries.

**After Step 4**: If bridged token TreasuryCap is not exclusively held by bridge -> cross-reference with TYPE_SAFETY Coin/Balance section.

**After Step 6**: Feed price staleness findings to ORACLE_ANALYSIS if applicable.

If any step skipped, document valid reason (N/A, no cross-chain messaging, single chain only).
