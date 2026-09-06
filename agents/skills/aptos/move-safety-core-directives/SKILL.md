---
name: "move-safety-core-directives"
description: "Lightweight core directives for Aptos Move always-required skills — injected into every breadth agent. Full methodology lives in the dedicated Move-Safety Agent."
type: "core-directive"
---

# Move Safety Core Directives (Aptos)

> **Purpose**: These are the INVENTORY + FLAG directives extracted from the 4 always-required Aptos skills (ABILITY_ANALYSIS, BIT_SHIFT_SAFETY, TYPE_SAFETY, REF_LIFECYCLE). Every breadth agent receives these to flag Move-specific patterns for depth review. The full trace methodology lives in the dedicated Move-Safety Agent (spawned separately).
> **Inject Into**: Breadth agents
> **Total**: ~130 lines (vs ~950 lines for 4 full skills)

## 1. Ability Inventory (from ABILITY_ANALYSIS)

Enumerate ALL structs. For each:

| Struct | Module | Abilities | Value-Bearing? | Obligation? | Excess Abilities? |
|--------|--------|-----------|---------------|-------------|------------------|

**Flag for depth review**:
- Struct with `copy` that represents economic value (Coin, LP token, shares) → [FLAG:ABILITY-COPY-VALUE]
- Struct with `drop` that represents an obligation (receipt, lock, flash loan) → [FLAG:ABILITY-DROP-OBLIGATION]
- Struct with `key + store` that should be non-transferable → [FLAG:ABILITY-EXCESS-STORE]
- Struct WITHOUT `drop` that has no explicit consumption path → [FLAG:ABILITY-STUCK-VALUE]

## 2. Bit Shift Inventory (from BIT_SHIFT_SAFETY)

**GREP**: Search all `.move` files for `<<` and `>>`.

For each shift operation:

| Location | Operand Type | Bit Width | Shift Amount Source | User-Controllable? | Bounded? |
|----------|-------------|-----------|--------------------|--------------------|----------|

**Flag for depth review**:
- Shift amount is user-controllable or computed AND unbounded → [FLAG:SHIFT-UNBOUND]
- Shift amount is constant but >= bit width → [FLAG:SHIFT-OVERFLOW-CONST]
- Shift in public/entry function with external input path → [FLAG:SHIFT-EXTERNAL]

## 3. Generic Type Inventory (from TYPE_SAFETY)

**GREP**: Search all `.move` files for `fun .*<` to find every generic function.

For each generic function:

| Function | Module | Type Params | Constraints | Entry? | Creates/Destroys T? |
|----------|--------|-------------|-------------|--------|---------------------|

**Flag for depth review**:
- Generic function accepting `Coin<T>` or `FungibleAsset` without verifying T matches expected type → [FLAG:TYPE-COIN-CONFUSION]
- Generic with only `store` constraint where `key` or specific type is needed → [FLAG:TYPE-WEAK-CONSTRAINT]
- Generic entry function callable by anyone with attacker-chosen type → [FLAG:TYPE-ATTACKER-CHOSEN]
- Phantom type parameter used for access control without runtime verification → [FLAG:TYPE-PHANTOM-GUARD]

## 4. Ref Lifecycle Inventory (from REF_LIFECYCLE)

**GREP**: Search for `ConstructorRef|TransferRef|MintRef|BurnRef|DeleteRef|ExtendRef|generate_mint_ref|generate_burn_ref|generate_transfer_ref`.

For each Ref:

| Ref Type | Created In | Stored Where | Access Control | Public Access? |
|----------|-----------|-------------|---------------|----------------|

**Flag for depth review**:
- MintRef/BurnRef/TransferRef stored in a resource with public accessor → [FLAG:REF-LEAK]
- ConstructorRef used to generate multiple Ref types (MintRef + BurnRef + TransferRef) in same function → [FLAG:REF-OVER-GENERATION]
- ExtendRef stored anywhere (grants signer capability to object) → [FLAG:REF-EXTEND-STORED]
- Any Ref type returned from a public/public(friend) function → [FLAG:REF-RETURNED]
- DeleteRef exists but object holds Balance/FungibleStore → [FLAG:REF-DELETE-WITH-VALUE]

## Self-Check

Before completing analysis, verify you produced inventories for ALL 4 sections above. Missing inventories = missing coverage for Move-specific vulnerability classes.
