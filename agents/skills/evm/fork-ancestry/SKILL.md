---
name: "fork-ancestry"
description: "Trigger Pattern Always (run during recon TASK 0, not breadth) - Inject Into Recon agent only (meta_buffer.md enrichment)"
---

# FORK_ANCESTRY Skill

> **Trigger Pattern**: Always (run during recon TASK 0, not breadth)
> **Inject Into**: Recon agent only (meta_buffer.md enrichment)
> **Purpose**: Detect known parent codebases and inherit their historical vulnerability patterns.

## 1. Detect Fork Indicators

Grep the codebase for known parent signatures:

| Parent Project | Detection Patterns | Common Forks |
|---------------|-------------------|--------------|
| Synthetix | `SNX\|synthetix\|StakingRewards\|RewardsDistribution\|Issuer` | Staking rewards forks |
| Compound | `CToken\|Comptroller\|cToken\|comptroller\|InterestRateModel` | Lending protocol forks |
| Uniswap V2 | `UniswapV2\|PairFactory\|getReserves\|MINIMUM_LIQUIDITY` | DEX forks |
| Uniswap V3 | `UniswapV3\|TickMath\|SqrtPriceMath\|NonfungiblePositionManager` | Concentrated liquidity forks |
| Aave | `aToken\|LendingPool\|flashLoan.*initiator\|AAVE` | Lending forks |
| MasterChef | `MasterChef\|poolInfo\|userInfo\|pendingReward\|massUpdatePools` | Yield farming forks |
| Curve | `StableSwap\|get_dy\|A_PRECISION\|get_virtual_price` | Stableswap forks |
| OpenZeppelin | `Ownable\|AccessControl\|Pausable\|ERC20Upgradeable` | Most projects (check version) |
| Basis/Tomb | `Boardroom\|Treasury\|seigniorage\|epoch\|TWAP.*peg` | Algorithmic stablecoin forks |
| Olympus | `OHM\|gOHM\|staking.*rebase\|bond.*discount` | Rebase token forks |
| Balancer | `BPool\|WeightedPool\|BVault\|flashLoan.*userData` | Weighted pool forks |
| Yearn | `Vault\|Strategy\|harvest\|totalDebt\|debtRatio` | Yield vault forks |

**Output**: List of detected parents with confidence level (HIGH: 3+ patterns, MEDIUM: 2 patterns, LOW: 1 pattern).

## 2. Query Known Parent Issues

For each detected parent (confidence MEDIUM or HIGH):

### 2a. Solodit Search (two queries, run in parallel)
```
// Query 1: Known high-quality issues
search_solodit_live(
  protocol="{parent_name}",
  impact=["HIGH", "CRITICAL"],
  language="Solidity",
  quality_score=3,
  sort_by="Quality",
  max_results=15
)
// Query 2: Rare/unusual patterns specific to fork divergences
search_solodit_live(
  keywords="{parent_name} fork modified divergence",
  impact=["HIGH", "MEDIUM"],
  language="Solidity",
  sort_by="Rarity",
  max_results=10
)
```

### 2b. Tavily Search
```
tavily_search(query="{parent_name} smart contract vulnerability exploit audit finding 2024 2025 2026")
```

### 2c. Known Issue Catalog

Compile results into:

| Parent | Known Issue | Severity | Root Cause | Solodit Ref | Applicable to Fork? |
|--------|-----------|----------|------------|-------------|---------------------|
| {parent} | {issue title} | {severity} | {brief root cause} | {link/ID} | YES / NO / CHECK |

**Applicability criteria**:
- YES: Fork retains the vulnerable code path unchanged
- NO: Fork modified the vulnerable code path (document what changed)
- CHECK: Cannot determine without deeper analysis (flag for breadth agent)

### 2d. Hardcoded Known-Issue Floor (Web Search Fallback)
If Solodit AND Tavily BOTH fail, use this minimum catalog -- check EACH applicable parent:

| Parent | Critical Known Issue | Root Cause | Search Keywords |
|--------|---------------------|------------|-----------------|
| Synthetix/StakingRewards | Reward rate manipulation via notifyRewardAmount timing | Reward duration reset on notify | `staking reward notify duration` |
| Compound/CToken | First-depositor exchange rate manipulation | Empty market rounding | `ctoken exchange rate first deposit` |
| Aave/LendingPool | Flash loan + oracle manipulation for unfair liquidation | Spot price dependency | `aave flash liquidation oracle` |
| Uniswap V2 | First LP inflation attack (MINIMUM_LIQUIDITY bypass) | LP share rounding at low liquidity | `uniswap v2 minimum liquidity first` |
| Basis/Tomb/Boardroom | Epoch-boundary seigniorage front-running + stake timing | Discrete epoch distribution | `boardroom seigniorage epoch timing` |
| Klondike/Tomb V2 | Epoch-boundary timing + treasury allocation fairness + role privilege scope | Extended seigniorage model with additional operator roles and cooldown mechanisms | `klondike tomb v2 seigniorage treasury operator` |
| MasterChef V2 | Reward rate manipulation via deposit(0) + unfair early-user dilution | Checkpoint timing + zero-amount deposit triggers reward update | `masterchef deposit zero reward rate timing` |
| Curve StableSwap | Reentrancy via raw ETH transfer in remove_liquidity + read-only reentrancy | ETH callback before state update, view function reads stale state | `curve reentrancy remove liquidity read-only` |
| Balancer V2 Vault | Flash loan + price oracle manipulation via pool balance change | Spot price manipulation within single transaction | `balancer vault flash loan oracle manipulation` |
| Yearn V2 Vault | Share price manipulation via strategy report timing + first depositor | Donation before first deposit inflates pricePerShare | `yearn vault share price first deposit strategy` |

## 3. Divergence Analysis

For each detected parent:

### 3a. Identify What Changed

Compare fork vs parent in security-critical paths:

| Component | Parent Behavior | Fork Behavior | Security Impact |
|-----------|----------------|---------------|-----------------|
| {component} | {original} | {modified or SAME} | {new risk or NONE} |

Focus on:
- Modified access control (added/removed roles, changed modifiers)
- Changed mathematical formulas (fee calculations, exchange rates, reward distribution)
- Added external dependencies (new oracles, new tokens, new protocols)
- Removed safety checks (validation removed, guard removed)
- Changed state variable types or visibility

### 3b. New Attack Surface from Divergence

For each modification:
- Does the change introduce a NEW vulnerability not in the parent?
- Does the change REMOVE a parent fix/mitigation?
- Does the change create an INCONSISTENCY with parent's invariants?

## 4. Output to meta_buffer.md

Append to `{SCRATCHPAD}/meta_buffer.md`:

```markdown
## Fork Ancestry Analysis

### Detected Parents
| Parent | Confidence | Patterns Found |
|--------|-----------|---------------|

### Inherited Vulnerabilities to Verify
| # | Parent Issue | Severity | Location in Fork | Status |
|---|-------------|----------|------------------|--------|
| 1 | {issue} | {severity} | {fork location} | CHECK / VERIFIED_SAFE / VULNERABLE |

### Fork Divergences (Security-Critical)
| # | Component | Change | New Risk? |
|---|-----------|--------|-----------|

### Questions for Breadth Agents
1. {derived from inherited vulnerabilities}
2. {derived from divergence analysis}
```

---

## Step Execution Checklist (MANDATORY)

| Section | Required | Completed? | Notes |
|---------|----------|------------|-------|
| 1. Detect Fork Indicators | YES | Y/N/? | |
| 2. Query Known Parent Issues | IF parent detected | Y/N(no parent)/? | |
| 3. Divergence Analysis | IF parent detected | Y/N(no parent)/? | |
| 4. Output to meta_buffer.md | YES | Y/N/? | |
