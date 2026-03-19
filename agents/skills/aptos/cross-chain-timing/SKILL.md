---
name: "cross-chain-timing"
description: "Trigger Pattern wormhole|layerzero|ccip|bridge|cross_chain|vaa|guardian|emitter|relay|remote_chain|payload|nonce.sequence - Inject Into Breadth agents, depth-external"
---

# CROSS_CHAIN_TIMING Skill (Aptos)

> **Trigger Pattern**: `wormhole|layerzero|ccip|bridge|cross_chain|vaa|guardian|emitter|relay|remote_chain|payload|nonce.*sequence`
> **Inject Into**: Breadth agents, depth-external
> **Finding prefix**: `[CCT-N]`
> **Rules referenced**: R1, R2, R4, R8, R10, R16

Covers: cross-chain message verification, timing asymmetry between Aptos and other chains, resource creation requirements, nonce/sequence replay protection, and cross-chain price relay staleness.

Aptos's fast finality (~1 second with BFT consensus) creates a fundamental timing asymmetry with slower chains (Ethereum ~12min, rollups 10-60min). This asymmetry is the primary attack vector for cross-chain timing exploits on Aptos. Additionally, Move's type-safe resource model introduces unique account/resource requirements for cross-chain operations.

---

## Step 1: Identify Cross-Chain Messaging Infrastructure

Find all cross-chain messaging calls and infrastructure:

| # | Bridge/Protocol | Direction | Aptos Function | Remote Chain | Message Type |
|---|----------------|-----------|---------------|-------------|-------------|
| 1 | {Wormhole/LayerZero/CCIP/custom} | {Aptos->Remote / Remote->Aptos} | {function name} | {Ethereum/Arbitrum/etc.} | {token transfer / state sync / price relay / governance} |

### Wormhole-Specific Inventory
If Wormhole is detected:

| Component | Module/Function | Purpose | Location |
|-----------|----------------|---------|----------|
| VAA Verification | `vaa::parse_and_verify` / guardian signature check | Guardian signature verification | {file:line} |
| Message Posting | `wormhole::publish_message` | Send message from Aptos | {file:line} |
| Token Bridge | `complete_transfer` / `create_wrapped_coin` | Token bridging | {file:line} |
| Emitter Resource | Emitter capability or resource | Message source identity | {file:line} |

### LayerZero-Specific Inventory
If LayerZero is detected:

| Component | Module/Function | Verification Method | Location |
|-----------|----------------|-------------------|----------|
| Endpoint | `endpoint::lz_receive` / receive handler | Oracle + Relayer attestation | {file:line} |
| Remote Mapping | Trusted remote configuration | Address/chain validation | {file:line} |
| Nonce Tracking | Inbound/outbound nonce resources | Replay prevention | {file:line} |

### Generic Bridge Inventory
For custom or other bridges:

| Component | Module/Function | Verification Method | Location |
|-----------|----------------|-------------------|----------|
| Message Resource | {resource type} | {signature/merkle/optimistic} | {file:line} |
| Relayer | {relayer constraint} | {how relayer is validated} | {file:line} |
| Nonce Tracking | {nonce storage} | {replay prevention method} | {file:line} |

---

## Step 2: Cross-Chain Message Verification Audit

For EACH inbound cross-chain message consumed by the module:

### 2a. Wormhole VAA Verification Checklist

| # | Check | Status | Location | Notes |
|---|-------|--------|----------|-------|
| 1 | Guardian signature count >= quorum (13/19) | YES/NO | {line} | Does module verify `guardian_set_index` is current? |
| 2 | Guardian set is current (not expired) | YES/NO | {line} | Old guardian sets may be compromised |
| 3 | Emitter chain ID validated | YES/NO | {line} | Reject messages from unexpected source chains |
| 4 | Emitter address validated | YES/NO | {line} | Reject messages from unexpected contracts on source chain |
| 5 | Sequence number replay check | YES/NO | {line} | Each VAA sequence should be processed exactly once |
| 6 | Consistency level validated | YES/NO | {line} | `finalized` vs `confirmed` - determines security guarantee |
| 7 | Payload format validated | YES/NO | {line} | Malformed payload handling - Move's `bcs::from_bytes` may abort on bad data |
| 8 | VAA resource authenticity | YES/NO | {line} | Is the VAA resource created by the Wormhole module (not user-supplied)? |

**Critical**: Missing checks 1-5 = **CRITICAL** (arbitrary cross-chain message injection). Missing checks 6-8 = **HIGH** (message quality/integrity issues).

**Aptos-specific**: Move's type system provides some protection - a `VAA` resource type can only be created by the Wormhole module. However, verify that the consuming module checks the VAA was created by the CORRECT Wormhole deployment (not a cloned module at a different address).

### 2b. Generic Bridge Verification

For non-Wormhole bridges:

| # | Check | Status | Location | Notes |
|---|-------|--------|----------|-------|
| 1 | Message source authenticated (signatures/proofs) | YES/NO | {line} | |
| 2 | Source chain ID validated | YES/NO | {line} | |
| 3 | Source contract/address validated | YES/NO | {line} | |
| 4 | Replay protection (nonce/sequence/Table lookup) | YES/NO | {line} | |
| 5 | Message freshness (timestamp check against `timestamp::now_seconds()`) | YES/NO | {line} | |
| 6 | Relayer authorization (if applicable) | YES/NO | {line} | |

---

## Step 3: Timing Window Analysis

### 3a. Finality Asymmetry Model

| Chain | Optimistic Finality | Confirmed Finality | Protocol Assumes |
|-------|--------------------|--------------------|-----------------|
| Aptos | ~1s (BFT commit) | ~1s (BFT - single round) | {which level?} |
| {Remote Chain} | {time} | {time} | {which level?} |
| **Asymmetry Window** | - | - | **{max delay between chains}** |

**Critical question**: When Aptos processes a message about remote chain state, how old can that state be? Compute: `max_staleness = remote_finality + bridge_relay_delay + aptos_processing_time`

### 3b. Stale State Usage Trace

For each piece of state synced cross-chain:

| State Variable | Source Chain | Sync Trigger | Max Staleness | Aptos Functions Using It | Fresh Required? |
|----------------|-------------|-------------|--------------|--------------------------|----------------|
| {state} | {chain} | {event/periodic/manual} | {time estimate} | {list functions} | YES/NO |

For each dependent function on Aptos:
- Is fresh state required or is stale acceptable?
- What decisions are made with potentially stale data?
- Can an attacker exploit the staleness window?

**Aptos-specific**: Check if synced state is stored in a global resource (`move_to`/`borrow_global`) or a `Table`. If a global resource, ALL functions reading it are affected by staleness. If a Table, trace which keys are stale.

### 3c. Aptos-to-Remote Timing Attack

Aptos's fast finality means actions on Aptos are visible almost immediately, but take time to propagate to remote chains:

```
1. Attacker acts on Aptos (visible in ~1s due to BFT finality)
2. Aptos message posted via bridge (begins relay)
3. TIMING WINDOW: Remote chain does not yet know about Aptos action
4. Attacker acts on remote chain using pre-Aptos-action state
5. Bridge message arrives on remote chain - state updates
6. Attacker profited from acting on both chains during asymmetry
```

### 3d. Remote-to-Aptos Timing Attack

```
1. State changes on remote chain (e.g., price moves, governance action)
2. Bridge message relay begins (latency: {estimate})
3. TIMING WINDOW: Aptos still uses old remote state
4. Attacker acts on Aptos using stale remote state
5. Bridge message arrives on Aptos - state updates
6. Attacker profited from Aptos action with stale state
```

---

## Step 4: Resource Creation Requirements

Cross-chain operations on Aptos have unique resource requirements due to Move's ownership model:

| # | Check | Status | Notes |
|---|-------|--------|-------|
| 1 | Recipient `CoinStore<CoinType>` registered before transfer arrival? | YES/NO | If NO: who registers it? Who pays gas? |
| 2 | `coin::register<CoinType>` called for recipient? | YES/NO | If NO: transfer aborts with `ECOIN_STORE_NOT_PUBLISHED` |
| 3 | What happens if recipient has not registered the coin type? | {abort/skip/queue} | Aborted transfers may be lost if no recovery path |
| 4 | Are wrapped coin types (`WrappedCoin<T>`) registered before first bridge transfer? | YES/NO | First bridged token of a type requires coin creation + registration |
| 5 | Are resources created for cross-chain escrow (`move_to`)? | YES/NO | Check signer requirements - does the bridge module have the correct signer capability? |
| 6 | Is there a recovery mechanism for failed deliveries? | YES/NO | Lost funds if no recovery |
| 7 | Can an attacker front-run resource creation with a malicious resource? | YES/NO | Move type system prevents this for same types, but check wrapper types |

**Critical Aptos pattern**: Cross-chain token transfers require the destination account to have a `CoinStore<T>` registered for the specific coin type. If it does not:
- The transfer transaction aborts - tokens may be stuck on the source chain
- Some bridges auto-register (requires signer capability or resource account)
- Some bridges queue the transfer for later claim (is the queue bounded? Who can claim?)

**Resource account pattern**: Many Aptos bridge modules use resource accounts (`account::create_resource_account`) for escrow. Verify:
- The resource account seed is deterministic and collision-free per message
- The resource account signer capability is stored securely (not extractable)
- Resource account creation cannot be front-run by an attacker

---

## Step 5: Nonce and Sequence Management

| # | Check | Status | Location | Notes |
|---|-------|--------|----------|-------|
| 1 | Replay protection exists | YES/NO | {line} | Method: {Table lookup/counter/EventHandle sequence/resource per message} |
| 2 | Replay check is BEFORE state changes | YES/NO | {line} | If after: partial replay possible |
| 3 | Out-of-order messages handled | YES/NO | {line} | Strict ordering vs any-order processing |
| 4 | Sequence gaps handled | YES/NO | {line} | What if message N+1 arrives before N? |
| 5 | Table storage sized for growth | YES/NO | {line} | `Table<u64, bool>` grows unboundedly - gas cost implications |
| 6 | Double-spend across chains | YES/NO | {line} | Same asset spent on both chains during relay |

**Aptos replay patterns**:
- **Table per message**: Store processed sequences in `Table<u64, bool>` or `Table<vector<u8>, bool>`. If key exists, already processed. Reliable but `Table` lookups have gas cost proportional to depth.
- **Counter**: Only process sequence N if N-1 was processed. Enforces ordering but blocks on gaps.
- **Resource per message**: Create a unique resource per processed message hash. Existence check prevents replay. Creates many resources (storage cost).
- **EventHandle sequence**: Use `event::counter` on an EventHandle as implicit sequence. Not reliable for replay - events are not queryable on-chain.

**Move-specific concern**: `Table` entries cannot be iterated or enumerated on-chain. If replay state is in a Table, ensure the lookup key is deterministic from message content (not relayer-supplied).

---

## Step 6: Cross-Chain Price Relay Audit

If oracle prices are relayed cross-chain:

| # | Check | Status | Notes |
|---|-------|--------|-------|
| 1 | Price freshness validated on Aptos side (`timestamp::now_seconds() - price_timestamp < MAX_STALENESS`) | YES/NO | Max acceptable age? |
| 2 | Price source authenticated | YES/NO | Can fake price be relayed? |
| 3 | Price deviation bounds | YES/NO | Max delta from last known price? |
| 4 | Fallback if relay is delayed/offline | YES/NO | What happens to price-dependent operations? |
| 5 | Flash loan on source chain can manipulate relayed price | YES/NO | Is source chain price spot or TWAP? |

**Staleness calculation**: `relay_staleness = source_price_age + bridge_latency + aptos_processing`

If `relay_staleness > acceptable_threshold` at worst case, price is stale. Apply Rule 16 (Oracle Integrity).

**Aptos-specific**: `timestamp::now_seconds()` returns seconds (not milliseconds). Ensure staleness comparisons use consistent units. Also verify `timestamp::now_microseconds()` is not confused with `now_seconds()` - a 1000x unit mismatch could make staleness checks ineffective.

---

## Step 7: Quantify Arbitrage Viability

```
1. Attacker monitors {SOURCE_CHAIN} for state changes at {MONITOR_POINT}
2. State change triggers sync message (latency window opens: {LATENCY_ESTIMATE})
3. Attacker executes on Aptos at {EXPLOIT_FUNCTION} using stale {STALE_STATE}
   -- Aptos execution is near-instant (~1s), so attacker can react quickly
4. Sync message arrives on Aptos, state updates in resource
5. Profit = {PROFIT_FORMULA}
6. Cost = bridge_fees + Aptos_gas + capital_lockup_cost
7. Viable if: profit > cost AND repeatable
```

**Reverse direction** (Aptos -> remote chain):
```
1. Attacker monitors Aptos state change (near-instant visibility due to BFT finality)
2. Attacker front-runs the bridge message on remote chain (longer finality window)
3. Attacker exploits stale state on remote chain before sync arrives
```

**Aptos cost model**: Aptos gas costs are low (~0.001 APT per tx). The primary cost is capital lockup and bridge fees, not gas. This makes small-margin attacks more viable on Aptos than EVM.

---

## Key Questions (must answer all)

1. What is the realistic sync latency for {BRIDGE_PROTOCOL}? (cite documentation)
2. Can an attacker monitor the remote chain and front-run sync on Aptos? (Aptos's low fees make this cheap)
3. What is the maximum state change during normal operation within the sync window?
4. Is this attack repeatable or one-time?
5. Are recipient CoinStores registered before cross-chain transfer arrival?
6. Is replay protection complete (covers all message types, all chains)?
7. Can an attacker exploit Aptos's fast finality to act before the remote chain sees Aptos state?
8. Are cross-chain prices validated for freshness AND deviation bounds?
9. Does VAA/message verification check BOTH source chain AND source address?

---

## Common False Positives

- **Monotonic state**: If synced state only increases, arbitrage may not be profitable in both directions
- **Negligible delta**: If max delta during sync window is <0.1%, may not be economically viable after bridge fees
- **Rate limiting**: If operations have cooldowns longer than sync latency, window may not be exploitable
- **Move type safety**: Move's resource type system prevents fake VAA/message resource injection from incorrect modules - but still verify the module address is correct
- **Bridge-level protections**: Some bridges (Wormhole) have rate limiting or value caps that bound exploitation
- **Freshness enforcement**: If protocol requires `timestamp::now_seconds() - last_sync < MAX_STALENESS`, stale state is rejected

---

## Instantiation Parameters
```
{CONTRACTS}           -- Modules to analyze
{BRIDGE_PROTOCOL}     -- Specific bridge (Wormhole, LayerZero, CCIP, custom)
{SYNC_POINT}          -- Function where cross-chain state is consumed
{DEPENDENT_FUNCTIONS} -- Functions that read synced state
{SOURCE_CHAIN}        -- Chain where state originates
{DEST_CHAIN}          -- Chain where stale state is exploited
{MONITOR_POINT}       -- What attacker monitors on source chain
{EXPLOIT_FUNCTION}    -- Function attacker calls on dest chain
{STALE_STATE}         -- Specific state variable/resource field that becomes stale
{LATENCY_ESTIMATE}    -- Realistic bridge latency
{PROFIT_FORMULA}      -- (new_value - old_value) * position_size
```

---

## Output Schema

| Field | Required | Description |
|-------|----------|-------------|
| bridge_inventory | yes | All cross-chain messaging infrastructure |
| verification_audit | yes | VAA/message verification completeness |
| timing_windows | yes | Asymmetry windows with duration estimates |
| resource_creation | yes | Recipient resource requirements and failure modes |
| replay_protection | yes | Nonce/sequence management assessment |
| price_relay_audit | if applicable | Cross-chain price freshness and manipulation risk |
| arbitrage_viability | yes | Quantified attack profitability or NOT_VIABLE |
| finding | yes | CONFIRMED / REFUTED / CONTESTED |
| evidence | yes | Code locations with line numbers |
| step_execution | yes | Status for each step |

---

### Denylist Enforcement Lag
- **Denylist enforcement lag**: For cross-chain denylist/blocklist updates, check the window between message receipt and enforcement. Can transactions from denylisted addresses execute during this window? Are in-flight operations for denylisted addresses cancelled or allowed to complete?

---

## Step Execution Checklist (MANDATORY)

| Step | Required | Completed? | Notes |
|------|----------|------------|-------|
| 1. Identify Cross-Chain Messaging Infrastructure | YES | | |
| 2. Cross-Chain Message Verification Audit | YES | | |
| 3. Timing Window Analysis (both directions) | YES | | |
| 4. Resource Creation Requirements | YES | | |
| 5. Nonce and Sequence Management | YES | | |
| 6. Cross-Chain Price Relay Audit | IF price relay detected | | |
| 7. Quantify Arbitrage Viability | YES | | |

### Cross-Reference Markers

**After Step 2**: If VAA verification is incomplete -> immediate finding, do not wait for timing analysis.

**After Step 3**: Feed timing windows to TEMPORAL_PARAMETER_STALENESS skill for parameters cached across chain boundaries.

**After Step 4**: If resource creation can fail -> cross-reference with REF_LIFECYCLE skill for stranded asset analysis.

**After Step 6**: Feed price staleness findings to ORACLE_ANALYSIS (Aptos version) if applicable.
