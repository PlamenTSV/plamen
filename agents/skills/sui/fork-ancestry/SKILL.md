---
name: "fork-ancestry"
description: "Trigger Pattern Always (run during recon TASK 0, not breadth) - Inject Into Recon agent only (meta_buffer.md enrichment)"
---

# FORK_ANCESTRY Skill (Sui)

> **Trigger Pattern**: Always (run during recon TASK 0, not breadth)
> **Inject Into**: Recon agent only (meta_buffer.md enrichment)
> **Finding prefix**: `[FA-N]`
> **Purpose**: Detect known parent Sui packages and inherit their historical vulnerability patterns.

---

## 1. Detect Fork Indicators

Grep the codebase for known parent Sui package signatures:

| Parent Project | Detection Patterns | Common Forks |
|---------------|-------------------|--------------|
| Cetus | `cetus\|clmm\|tick\|concentrated_liquidity\|cetus_clmm\|tick_math\|sqrt_price_math\|CetusPool` | Concentrated liquidity forks |
| Suilend | `suilend\|lending_market\|reserve\|obligation\|refresh_reserve\|LendingMarket\|ObligationKey` | Lending protocol forks |
| NAVI | `navi\|navi_protocol\|lending\|pool_manager\|incentive\|StoragePool\|navi_lending` | Lending protocol forks |
| Scallop | `scallop\|s_coin\|market\|obligation\|borrow_dynamics\|ScallopMarket\|sCoin` | Lending protocol forks |
| Turbos | `turbos\|pool_factory\|position_manager\|turbos_clmm\|TurbosPool\|TurbosPosition` | Concentrated liquidity forks |
| DeepBook | `deepbook\|clob\|order_book\|custodian\|deep_book\|DeepBookPool\|BalanceManager` | Order book DEX forks |
| Aftermath | `aftermath\|af_lp\|pool_registry\|amm_v2\|AftermathPool\|StakedSui` | AMM / liquid staking forks |
| Bucket | `bucket\|bucket_protocol\|tank\|well\|fountain\|BucketProtocol\|BUCK` | Stablecoin / CDP forks |
| Kriya | `kriya\|kriya_dex\|spot_dex\|clmm\|KriyaPool\|KriyaPosition` | DEX forks |
| FlowX | `flowx\|flowx_clmm\|router\|pair_v2\|FlowXPool\|FlowXRouter` | DEX forks |
| Sui System Staking | `staking_pool\|validator\|sui_system\|delegation\|StakedSui\|StakingPool\|ValidatorCap` | Liquid staking / validator forks |

**Also check**:
- `Move.toml` dependencies for parent package addresses or names (e.g., `cetus_clmm = "0x..."`, `deepbook = { addr = "0x..." }`)
- Import paths in Move source: `use cetus_clmm::`, `use deepbook::`, `use suilend::`, etc.
- Struct names and function signatures matching known parent interfaces
- Published package addresses in dependency declarations (known mainnet addresses of parent protocols)

**Output**: List of detected parents with confidence level:
- **HIGH**: 3+ unique patterns matched, OR parent package in Move.toml dependencies
- **MEDIUM**: 2 patterns matched
- **LOW**: 1 pattern matched (may be coincidental naming)

---

## 2. Query Known Parent Issues

For each detected parent (confidence MEDIUM or HIGH):

### 2a. Solodit Search (two queries, run in parallel)
```
// Query 1: Known high-quality issues
search_solodit_live(
  keywords="{parent_name} sui move",
  impact=["HIGH", "CRITICAL"],
  language="Move",
  quality_score=3,
  sort_by="Quality",
  max_results=15
)
// Query 2: Fork-specific divergence issues
search_solodit_live(
  keywords="{parent_name} fork modified sui object",
  impact=["HIGH", "MEDIUM"],
  language="Move",
  sort_by="Rarity",
  max_results=10
)
```

### 2b. Tavily Search
```
tavily_search(query="{parent_name} sui move vulnerability exploit audit finding 2024 2025 2026")
```

### 2c. Known Issue Catalog

Compile results into:

| Parent | Known Issue | Severity | Root Cause | Solodit Ref | Applicable to Fork? |
|--------|-----------|----------|------------|-------------|---------------------|
| {parent} | {issue title} | {severity} | {brief root cause} | {link/ID} | YES / NO / CHECK |

**Applicability criteria**:
- **YES**: Fork retains the vulnerable code path unchanged
- **NO**: Fork modified the vulnerable code path (document what changed)
- **CHECK**: Cannot determine without deeper analysis (flag for breadth agent)

### 2d. Hardcoded Known-Issue Floor (Web Search Fallback)

If Solodit AND Tavily BOTH fail, use this minimum catalog -- check EACH applicable parent:

| Parent | Critical Known Issue | Root Cause | Search Keywords |
|--------|---------------------|------------|-----------------|
| CLMM DEX | Tick boundary crossing precision loss + liquidity accounting desync | sqrt_price calculation at tick boundaries, Position NFT state vs pool liquidity mismatch | `clmm tick precision sqrt_price` |
| Lending protocol (obligation-based) | Obligation refresh staleness + liquidation racing on shared objects | Reserve refresh not enforced before obligation health check, concurrent tx ordering | `lending obligation refresh stale liquidation shared object` |
| Lending protocol (pool-based) | Pool balance desync via flash loan deposit/withdraw + incentive calculation overflow | Balance tracking diverges from actual Coin balance, large TVL causes incentive arithmetic overflow | `lending balance flash loan pool desync` |
| Lending protocol (receipt-token) | Receipt token exchange rate manipulation via first depositor + borrow dynamics staleness | Empty market rounding in receipt token minting, stale interest rate applied across epochs | `lending receipt token exchange rate first deposit borrow dynamics` |
| Orderbook DEX | Order matching priority manipulation + balance manager accounting edge cases | Self-trading for priority manipulation, dust amounts in partial fills | `orderbook order priority self-trade balance dust` |
| CDP/stablecoin protocol | Reward distribution fairness + overflow at extreme collateral ratios | Discrete epoch distribution timing, arithmetic overflow in collateral ratio calculation | `cdp reward epoch collateral overflow` |
| Sui System Staking | Validator list manipulation via stake deposit ordering + reward fee timing | Stake account priority ordering in validator selection, reward distribution during epoch boundary | `sui staking validator reward epoch boundary` |
| Aftermath/AMM | LP share price manipulation via donation to pool + StakedSui exchange rate lag | Direct Coin transfer to pool object inflates share price, staking rewards not reflected immediately | `aftermath pool share price donation stakedSui` |

---

## 3. Divergence Analysis

For each detected parent:

### 3a. Identify What Changed

Compare fork vs parent in security-critical paths:

| Component | Parent Behavior | Fork Behavior | Security Impact |
|-----------|----------------|---------------|-----------------|
| {component} | {original} | {modified or SAME} | {new risk or NONE} |

**Sui-specific divergence focus areas** (ordered by criticality):

#### Object Ownership Model Changes (HIGHEST PRIORITY)
- Did the fork change any object from OWNED to SHARED or vice versa? Ownership model changes fundamentally alter the access control surface.
- Did the fork add or remove `store` ability from objects? Adding `store` = anyone can transfer; removing `store` = module-controlled transfer only.
- Did the fork change shared object access control patterns (different capability checks, different admin verification)?
- **Critical**: Shared object without proper access control = anyone can mutate protocol state.

#### Capability and Admin Pattern Changes
- Did the fork change which capabilities gate admin operations (different Cap objects, different verification logic)?
- Did the fork add `store` to capability objects that the parent kept module-restricted? This allows capability transfer, potentially weakening admin control.
- Did the fork introduce new admin functions without corresponding capability checks?
- **Critical**: Capability objects with `store` can be transferred to arbitrary addresses, including contracts that auto-execute.

#### Balance and Coin Handling Changes
- Did the fork modify how `Balance<T>` or `Coin<T>` objects are split, joined, or transferred?
- Are there new code paths where Balance could be created (via `balance::zero()` then never destroyed) or destroyed (via unmatched `balance::destroy_zero()`)?
- Did the fork add support for additional coin types without updating all code paths?
- **Critical**: Balance accounting mismatches between protocol state and actual Coin holdings.

#### Dynamic Field Schema Changes
- Did the fork change dynamic field key types or naming conventions?
- Are there new dynamic field additions without corresponding removal logic?
- Did the fork change which objects have dynamic fields attached?

#### Other Divergence Areas
- Modified mathematical formulas (fee calculations, exchange rates, reward distribution)
- Changed access control (added/removed capabilities, modified authority checks)
- Removed safety checks (assertions removed, constraints removed)
- Changed struct layouts (fields reordered, types changed, new fields added)
- Added/removed public functions (new attack surface or missing safety functions)
- Changed event emissions (may affect off-chain monitoring and indexers)

### 3b. New Attack Surface from Divergence

For each modification:
- Does the change introduce a NEW vulnerability not in the parent?
- Does the change REMOVE a parent fix/mitigation?
- Does the change create an INCONSISTENCY with parent's invariants?
- **Does the change break assumptions that other unchanged code relies on?** (e.g., parent assumes PoolConfig is always shared; fork sometimes wraps it inside another object)

---

## 4. Output to meta_buffer.md

Append to `{SCRATCHPAD}/meta_buffer.md`:

```markdown
## Fork Ancestry Analysis

### Detected Parents
| Parent | Confidence | Patterns Found | Move.toml Dependency? |
|--------|-----------|---------------|----------------------|

### Inherited Vulnerabilities to Verify
| # | Parent Issue | Severity | Location in Fork | Status |
|---|-------------|----------|------------------|--------|
| 1 | {issue} | {severity} | {fork location: module::function} | CHECK / VERIFIED_SAFE / VULNERABLE |

### Fork Divergences (Security-Critical)
| # | Component | Change Type | Change Description | New Risk? |
|---|-----------|------------|-------------------|-----------|
| 1 | {component} | OWNERSHIP_MODEL / CAPABILITY / BALANCE / DYNAMIC_FIELD / OTHER | {what changed} | YES/NO/CHECK |

### Questions for Breadth Agents
1. {derived from inherited vulnerabilities}
2. {derived from divergence analysis}
3. {derived from ownership model changes}
```

---

## Step Execution Checklist (MANDATORY)

| Section | Required | Completed? | Notes |
|---------|----------|------------|-------|
| 1. Detect Fork Indicators | YES | Y/N/? | Check Move.toml deps + source patterns |
| 2. Query Known Parent Issues | IF parent detected | Y/N(no parent)/? | |
| 2d. Hardcoded Known-Issue Floor | IF Solodit+Tavily both fail | Y/N(not needed)/? | |
| 3. Divergence Analysis | IF parent detected | Y/N(no parent)/? | |
| 3a. Object Ownership Model Changes | IF parent detected | Y/N(no parent)/? | Highest priority |
| 3a. Capability and Admin Pattern Changes | IF parent detected | Y/N(no parent)/? | |
| 3a. Balance and Coin Handling Changes | IF parent detected | Y/N(no parent)/? | |
| 3a. Dynamic Field Schema Changes | IF parent detected | Y/N(no parent)/? | |
| 4. Output to meta_buffer.md | YES | Y/N/? | |

### Cross-Reference Markers

**After Step 1**: If Move.toml shows specific parent package address dependencies, verify the addresses match known mainnet deployments (not test/devnet).

**After Step 3a (Ownership Model)**: Feed changed ownership models to OBJECT_OWNERSHIP skill for targeted re-analysis of affected objects.

**After Step 3a (Capability)**: Feed new/changed capabilities to SEMI_TRUSTED_ROLES skill for admin privilege analysis.

**After Step 3a (Balance)**: Feed changed balance handling to TOKEN_FLOW_TRACING skill for flow analysis.
