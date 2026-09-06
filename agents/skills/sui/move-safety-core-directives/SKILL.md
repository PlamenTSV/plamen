---
name: "move-safety-core-directives"
description: "Lightweight core directives for Sui Move always-required skills - injected into every breadth agent. Full methodology lives in the dedicated Move-Safety Agent."
type: "core-directive"
---

# Move Safety Core Directives (Sui)

> **Purpose**: These are the INVENTORY + FLAG directives extracted from the 4 always-required Sui skills (ABILITY_ANALYSIS, BIT_SHIFT_SAFETY, TYPE_SAFETY, OBJECT_OWNERSHIP). Every breadth agent receives these to flag Move-specific patterns for depth review. The full trace methodology lives in the dedicated Move-Safety Agent (spawned separately).
> **Inject Into**: Breadth agents
> **Total**: ~155 lines (vs ~900 lines for 4 full skills)

## 1. Ability Inventory (from ABILITY_ANALYSIS)

Enumerate ALL structs. For each:

| Module | Struct | Abilities | Has `id: UID`? | Is Object? | Transferable? | Notes |
|--------|--------|-----------|----------------|------------|---------------|-------|

**Flag for depth review**:
- Struct with `copy` that holds `Balance<T>` or represents economic value -> [FLAG:ABILITY-COPY-VALUE]
- Struct with `drop` that represents an obligation (receipt, hot potato) -> [FLAG:ABILITY-DROP-OBLIGATION]
- Receipt/hot potato consumed against an object without checking a stored source object ID (order_id, pool_id, position_id, loan_id) -> [FLAG:RECEIPT-ID-MISMATCH]
- Object (`key`) with `store` that should restrict transfers -> [FLAG:ABILITY-EXCESS-STORE]
- Hot potato (no abilities) with no consumption path in the protocol -> [FLAG:ABILITY-STUCK-HOTPOTATO]
- `copy + key` combination (impossible in Sui; compilation error) -> [FLAG:ABILITY-INVALID-COMBO]

## 2. Bit Shift Inventory (from BIT_SHIFT_SAFETY)

**GREP**: Search all `.move` files for `<<` and `>>`.

For each shift operation:

| Location | Operand Type | Bit Width | Shift Amount Source | User-Controllable? | Bounded? |
|----------|-------------|-----------|--------------------|--------------------|----------|

**Flag for depth review**:
- Shift amount is user-controllable or computed AND unbounded -> [FLAG:SHIFT-UNBOUND]
- Shift amount is constant but >= bit width -> [FLAG:SHIFT-OVERFLOW-CONST]
- Shift in public/entry function with external input path -> [FLAG:SHIFT-EXTERNAL]

## 3. Generic Type Inventory (from TYPE_SAFETY)

**GREP**: Search all `.move` files for `fun .*<` to find every generic function.

For each generic function:

| Function | Module | Type Params | Constraints | Entry? | Creates/Destroys T? |
|----------|--------|-------------|-------------|--------|---------------------|

**Flag for depth review**:
- Generic function accepting `Coin<T>` or `Balance<T>` without verifying T matches expected type -> [FLAG:TYPE-COIN-CONFUSION]
- Generic function accepting both `T` and a runtime selector/config/index/object (asset id, pool id, position id) without binding them together -> [FLAG:TYPE-CONFIG-MISMATCH]
- Generic with only `store` constraint where `key` or specific type is needed -> [FLAG:TYPE-WEAK-CONSTRAINT]
- Generic entry function callable by anyone with attacker-chosen type -> [FLAG:TYPE-ATTACKER-CHOSEN]
- One-Time Witness (OTW) type used outside `init()` or not consumed -> [FLAG:TYPE-OTW-LEAK]

## 4. Move Reference Assignment Inventory

**GREP**: Search all `.move` files for destructuring from mutable references and assignments between destructured names:
- `let Struct { ... } = <expr returning &mut Struct>`
- assignments inside the same function where the left-hand identifier came from a `&mut` destructure
- reset/accounting code that uses `left = limit`, `remaining = cap`, `field_ref = other_ref` instead of `*left = *limit`

For each candidate:

| Function | Destructured Ref Fields | Assignment | LHS Dereferenced? | RHS Dereferenced? | Intended Field Written? |
|----------|-------------------------|------------|-------------------|-------------------|-------------------------|

**Flag for depth review**:
- Assignment to a mutable reference variable without `*` on the LHS when the intent is to update the stored field value -> [FLAG:REF-REASSIGN-WRONG-FIELD]
- Destructured mutable reference later reassigned to another field reference, causing writes to affect the wrong field -> [FLAG:REF-ALIAS-CORRUPTION]
- Epoch/limit/cooldown/quota reset logic using field references where value copy was intended -> [FLAG:REF-RESET-BUG]

## 5. Object Ownership Inventory (from OBJECT_OWNERSHIP)

Classify every object (`key` ability) by ownership model:

| Object | Ownership | Created Via | Has `store`? | Transfer Restricted? | Dynamic Fields? |
|--------|-----------|-------------|-------------|---------------------|-----------------|

**Flag for depth review**:
- Shared object mutated without access control -> [FLAG:OBJ-SHARED-UNGUARDED]
- `public` function returns `&mut` or exposes `borrow_mut`/dynamic-field mutable access to internal sensitive state without a capability or `public(package)` restriction -> [FLAG:OBJ-PUBLIC-MUT-REF]
- Object with `store` that should NOT be freely transferable -> [FLAG:OBJ-EXCESS-TRANSFER]
- Object deleted via `object::delete` without cleaning up dynamic fields -> [FLAG:OBJ-DELETE-DIRTY]
- Owned object wrapped/unwrapped in ways that change its accessibility -> [FLAG:OBJ-WRAP-ESCAPE]
- Object with `Balance<T>` field but no withdrawal function -> [FLAG:OBJ-STRANDED-BALANCE]

## Self-Check

Before completing analysis, verify you produced inventories for ALL 5 sections above. Missing inventories = missing coverage for Move-specific vulnerability classes.
