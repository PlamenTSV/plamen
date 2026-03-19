---
name: "dex-integration-security"
description: "Protocol Type Trigger dex_integration (detected when recon finds swap|addLiquidity|removeLiquidity|IUniswapV2Router|ISwapRouter|amountOutMin|amountOutMinimum|slippage - AND the..."
---

# Injectable Skill: DEX Integration Security

> **Protocol Type Trigger**: `dex_integration` (detected when recon finds: swap|addLiquidity|removeLiquidity|IUniswapV2Router|ISwapRouter|amountOutMin|amountOutMinimum|slippage - AND the protocol is NOT itself a DEX implementation)
> **Inject Into**: Breadth agents, depth-external, depth-edge-case
> **Language**: Primarily EVM; applicable to Sui PTB-based DEX interactions
> **Finding prefix**: `[DEX-N]`

## Orchestrator Decomposition Guide
When decomposing this skill into depth agent investigation questions, map sections to domains:
- Sections 1, 2: depth-external (external DEX call safety, return value handling)
- Sections 3, 4: depth-edge-case (boundary conditions, fee tier assumptions)
- Section 5: depth-state-trace (approval state management)

## When This Skill Activates

Recon detects DEX integration patterns: `swap`, `addLiquidity`, `removeLiquidity`, `IUniswapV2Router`, `ISwapRouter`, `amountOutMin`, `amountOutMinimum`, `slippage`, `exactInputSingle`, `exactInput`, `swapExactTokensForTokens` - but the protocol itself is NOT a DEX/AMM implementation. This skill analyzes the CALLER's integration with an external DEX, not the DEX internals.

---

## 1. Slippage Parameter Analysis

For each function that calls a DEX swap:

### 1a. Parameter Origin
- Is `amountOutMin` (or equivalent) user-provided or computed on-chain?
- If computed: what oracle or price source feeds the computation? (cross-reference ORACLE_ANALYSIS if applicable)
- Can the parameter be set to 0? If yes: trace all callers - does ANY code path pass 0 as slippage tolerance?

### 1b. Parameter Forwarding
- Is the slippage parameter forwarded through intermediate functions? At each hop: is it modified, scaled, or silently dropped?
- For protocols that apply their own fee before swapping: is `amountOutMin` adjusted to account for the fee deduction from the input amount?

### 1c. Multi-Hop and Multi-Swap
- For multi-hop swaps (encoded path): is slippage checked on intermediate amounts or only the final output?
- For operations requiring multiple sequential swaps: is slippage enforced per-swap or only on aggregate output?

Tag: `[TRACE:swap_call → amountOutMin_source={user/computed/hardcoded} → value_can_be_zero={YES/NO} → forwarded_through={functions}]`

---

## 2. Deadline Enforcement

For each function that calls a DEX router:

### 2a. Deadline Value
- Is a `deadline` parameter passed to the DEX router?
- Is `block.timestamp` used as the deadline? (provides no MEV protection - always passes)
- Is the deadline hardcoded to `type(uint256).max` or equivalent? (same issue - no protection)

### 2b. Queued or Delayed Swaps
- For protocols that queue swaps for later execution: is the deadline relative to queue time or execution time?
- If relative to queue time: a long queue delay can cause the swap to execute at a stale price with an expired market context

### 2c. L2 Considerations
- For L2 deployments: does the deadline account for sequencer delay or batch submission lag?
- Can the sequencer hold a transaction to execute it at a favorable time within the deadline window?

Tag: `[TRACE:router_call → deadline={value_or_source} → block.timestamp_used={YES/NO} → queue_delay_considered={YES/NO}]`

---

## 3. Return Value Handling

For each DEX call that returns swap output amounts:

### 3a. Actual vs Expected
- Does the protocol check the actual amount received vs the expected output?
- For fee-on-transfer tokens: does the protocol use the router return value (pre-fee) or re-check balance (post-fee)?
- If the protocol uses `balanceOf` delta: is the delta computed correctly (post-balance minus pre-balance in the same transaction)?

### 3b. Multi-Output Validation
- For `removeLiquidity` calls: are BOTH output token amounts validated?
- For swaps returning multiple values: are all return values consumed, or are some silently ignored?

### 3c. Failure Handling
- If the DEX call reverts: does the protocol handle the revert gracefully, or does it propagate and brick a larger operation (e.g., batch liquidation blocked by one failed swap)?
- For try/catch wrapped swaps: does the catch path leave state consistent?

Tag: `[TRACE:swap_return → checked={YES/NO} → fee_on_transfer_aware={YES/NO} → revert_handling={propagate/catch/ignore}]`

---

## 4. Fee Tier and Pool Assumptions

### 4a. Hardcoded Pool or Fee Tier
- Are pool addresses or fee tiers (e.g., Uniswap V3 fee tiers: 100, 500, 3000, 10000) hardcoded?
- If hardcoded: can the optimal pool change over time due to liquidity migration or new pool deployment?
- Does the protocol verify the pool contract is genuine (not a malicious contract deployed at an expected address)?

### 4b. Pool Liquidity Assumptions
- Does the protocol assume sufficient liquidity exists in the target pool?
- For large swap amounts: can the swap fail or produce extreme slippage if pool liquidity drops?
- For protocols specifying pools by fee tier: what happens if multiple pools exist for the same pair with different fee tiers?

Tag: `[TRACE:pool_selection → hardcoded={YES/NO} → fee_tier={value} → pool_verified={YES/NO} → liquidity_assumption={documented/implicit}]`

---

## 5. Router Approval Safety

### 5a. Approval Scope
- Does the protocol grant unlimited (`type(uint256).max`) approval to the router?
- Is the approval granted once in initialization or per-transaction?
- If per-transaction with exact amounts: is a race condition possible between approval and swap execution?

### 5b. Router Mutability
- Is the router address upgradeable or replaceable (via admin setter)?
- After a router migration: are stale approvals to the old router revoked?
- Can the old router still spend tokens if approvals remain?

### 5c. Permit Usage
- For protocols using permit (EIP-2612) instead of approve: is the permit deadline scoped tightly?
- Is the permit nonce managed correctly to prevent replay?
- Can a permit intended for one router be used by a different contract?

Tag: `[TRACE:approval → scope={unlimited/exact} → router_upgradeable={YES/NO} → stale_revoked={YES/NO}]`

---

## Common False Positives
- **`amountOutMin = 0` in atomic flash loan context**: If the entire operation reverts on net loss within the same transaction, zero slippage tolerance is acceptable (atomic protection guarantees revert on unfavorable outcome)
- **Hardcoded pool address for canonical immutable pair**: Stable pairs on immutable DEX deployments (e.g., WETH/USDC on Uniswap V3 mainnet) carry low migration risk
- **Unlimited approval to verified immutable router**: If the router contract is non-upgradeable and its code is verified, unlimited approval is low risk
- **`block.timestamp` deadline on private/protected functions**: If the swap function is only callable by a trusted keeper within a controlled execution flow, MEV deadline protection may be enforced upstream

## Step Execution Checklist (MANDATORY)

| Section | Required | Completed? | Notes |
|---------|----------|------------|-------|
| 1. Slippage Parameter Analysis | YES | | Origin, forwarding, multi-hop |
| 2. Deadline Enforcement | YES | | Value, queue delay, L2 |
| 3. Return Value Handling | YES | | Actual vs expected, fee-on-transfer |
| 4. Fee Tier and Pool Assumptions | IF hardcoded pool/fee tier | | Pool verification, liquidity |
| 5. Router Approval Safety | IF protocol approves router | | Scope, mutability, stale approvals |
