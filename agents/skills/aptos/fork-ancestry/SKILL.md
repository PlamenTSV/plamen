---
name: "fork-ancestry"
description: "Trigger Pattern Always (run during recon TASK 0, not breadth) - Inject Into Recon agent only (meta_buffer.md enrichment)"
---

# FORK_ANCESTRY Skill -- Aptos

> **Trigger Pattern**: Always (run during recon TASK 0, not breadth)
> **Inject Into**: Recon agent only (meta_buffer.md enrichment)
> **Purpose**: Detect known parent codebases and inherit their historical vulnerability patterns.

## 1. Detect Fork Indicators

Grep the codebase for known parent signatures:

| Parent Project | Detection Patterns | Common Forks |
|---------------|-------------------|--------------|
| Thala | `thala\|thalaswap\|move_staking\|thala_manager\|stability_pool\|mod_coin` | Stableswap/staking forks |
| Echelon | `echelon\|lending_pool\|borrow_pool\|echelon_market\|lending_config` | Lending protocol forks |
| Aries | `aries\|aries_market\|margin_trade\|aries_profile` | Margin trading forks |
| Aptos Framework Staking | `delegation_pool\|stake_pool\|validator_set\|staking_config` | Delegation/staking forks |
| Liquidswap | `liquidswap\|curves\|liquidity_pool\|coin_helper\|lp_coin` | DEX forks (Pontem) |
| Pancakeswap | `pancake\|masterchef\|smart_router\|pancakeswap\|cake_token` | Yield farming forks |
| Amnis Finance | `amnis\|amnis_staking\|amapt\|stapt\|amnis_router` | Liquid staking forks |
| Cellana Finance | `cellana\|ve_token\|gauge\|voter\|bribe` | ve(3,3) / gauge forks |
| Merkle Trade | `merkle\|trading\|pnl_manager\|fee_distributor\|merkle_trading` | Perp DEX forks |
| Aptos Names (ANS) | `aptos_names\|domains\|ans_v2\|name_service` | Name service forks |
| Tortuga | `tortuga\|staked_aptos\|tortuga_staking\|tAPT` | Liquid staking forks |
| Ditto | `ditto\|ditto_staking\|staked_coin\|ditto_vault` | Liquid staking/vault forks |
| Aptos Token V2 / Digital Assets | `token::TokenV2\|collection\|aptos_token\|digital_asset` | NFT/token standard forks |
| Aptos Fungible Asset Framework | `fungible_asset\|FungibleStore\|FungibleAsset\|primary_fungible_store` | FA standard consumers |
| Pendleswap (Aptos) | `pendle\|pendleswap\|sy_token\|pt_token\|yt_token\|market_factory` | Yield tokenization forks |

**Output**: List of detected parents with confidence level (HIGH: 3+ patterns, MEDIUM: 2 patterns, LOW: 1 pattern).

## 2. Query Known Parent Issues

For each detected parent (confidence MEDIUM or HIGH):

### 2a. Solodit Search (two queries, run in parallel)
```
// Query 1: Known high-quality issues
search_solodit_live(
  protocol="{parent_name}",
  impact=["HIGH", "CRITICAL"],
  language="Move",
  quality_score=3,
  sort_by="Quality",
  max_results=15
)
// Query 2: Rare/unusual patterns specific to fork divergences
search_solodit_live(
  keywords="{parent_name} fork modified divergence aptos move",
  impact=["HIGH", "MEDIUM"],
  language="Move",
  sort_by="Rarity",
  max_results=10
)
```

### 2b. Tavily Search
```
tavily_search(query="{parent_name} aptos move smart contract vulnerability exploit audit finding 2024 2025 2026")
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
| Thala | Stability pool share manipulation on first deposit | Empty pool rounding in share calculation | `thala stability pool first deposit share` |
| Liquidswap | LP token inflation via small initial liquidity | MINIMUM_LIQUIDITY equivalent missing or insufficient | `liquidswap lp token inflation first liquidity` |
| DEX yield farm (Aptos) | Reward rate manipulation via zero-amount deposit | Checkpoint timing + zero-amount triggers reward update | `masterchef aptos deposit zero reward` |
| Amnis Finance | Exchange rate manipulation between stAPT and amAPT | Discrete update timing allows entry at stale rate | `amnis finance exchange rate staleness stAPT` |
| Aptos Framework Staking | Delegation pool unlock timing + commission rate change | Validator can change commission before pending unlock completes | `delegation pool commission unlock timing aptos` |
| Echelon | Oracle price staleness in liquidation path | Stale price allows unfair liquidation or avoids valid liquidation | `echelon lending oracle staleness liquidation` |
| Cellana Finance | Vote-escrowed token lock bypass via gauge interaction | ve token accounting inconsistency during gauge deposit/withdraw | `cellana ve token lock gauge bypass` |
| Tortuga | Liquid staking share price manipulation via rewards timing | Reward distribution timing creates extractable arbitrage window | `tortuga liquid staking share price reward timing` |
| Aptos Fungible Asset Framework | Ref capability leak via public friend function | MintRef/TransferRef/BurnRef exposed through insufficiently restricted public(friend) function | `fungible asset ref capability leak public friend` |
| Aptos Token V2 | Object ownership transfer bypassing royalty enforcement | Token transfer via object::transfer bypasses marketplace royalty hooks | `aptos token v2 royalty bypass transfer` |

## 3. Divergence Analysis

For each detected parent:

### 3a. Identify What Changed

Compare fork vs parent in security-critical paths:

| Component | Parent Behavior | Fork Behavior | Security Impact |
|-----------|----------------|---------------|-----------------|
| {component} | {original} | {modified or SAME} | {new risk or NONE} |

Focus on:
- Modified access control (changed signer requirements, added/removed friend declarations)
- Changed mathematical formulas (fee calculations, exchange rates, reward distribution)
- Added external dependencies (new oracles, new CPI targets, new coin types)
- Removed safety checks (assertions removed, type constraints relaxed)
- Changed Ref storage patterns (different access control on stored MintRef/BurnRef/TransferRef)
- Module upgrade policy changes (parent `immutable` -> fork `compatible`, or vice versa)
- Generics changes (parent uses concrete types -> fork uses generics, or vice versa)

### 3b. New Attack Surface from Divergence

For each modification:
- Does the change introduce a NEW vulnerability not in the parent?
- Does the change REMOVE a parent fix/mitigation?
- Does the change create an INCONSISTENCY with parent's invariants?
- Does the change alter the Ref lifecycle (e.g., storing a Ref the parent consumed immediately)?

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
