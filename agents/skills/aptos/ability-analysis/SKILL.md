---
name: "ability-analysis"
description: "Trigger Pattern Always (Aptos Move) - foundational security check - Inject Into Breadth agents, depth agents"
---

# ABILITY_ANALYSIS Skill

> **Trigger Pattern**: Always (Aptos Move) --- foundational security check
> **Inject Into**: Breadth agents, depth agents

For every struct defined in the audited modules:

**STEP PRIORITY**: Steps 2 (Copy Ability Audit) and 6 (Ability Combination Analysis) are where HIGH/CRITICAL severity findings most commonly hide. Do NOT rush these steps. If constrained, skip conditional sections (7) before skipping 2 or 6.

## 1. Struct Ability Inventory

Enumerate ALL structs defined in the audited modules:

| Struct | Module | Abilities | Represents Value? | Represents Obligation? | Is Resource? | Security Assessment |
|--------|--------|-----------|-------------------|----------------------|-------------|---------------------|
| {name} | {module} | copy, drop, store, key | YES/NO | YES/NO | YES/NO | {assessment} |

**Classification guide**:
- **Value-bearing**: Coins, LP tokens, shares, receipts, vouchers, NFTs --- anything that represents transferable economic value or a claim to value
- **Obligation-bearing**: Hot potatoes, flash loan receipts, callback obligations, lock receipts --- anything that MUST be consumed before transaction ends
- **Resource**: Singleton state containers, registries, configuration stores --- things that should exist at most once per address/globally
- **Data**: Purely informational structs with no security-sensitive lifecycle (events, parameters, intermediate computation results)

**For each struct**: What abilities does it NEED vs what abilities does it HAVE? Excess abilities are the attack surface.

## 2. Copy Ability Audit

For each struct with the `copy` ability:

### 2a. Value Duplication Check

| Struct | Has `copy`? | Represents Value? | Duplication Exploitable? | Severity |
|--------|-------------|-------------------|-------------------------|----------|
| {name} | YES/NO | YES/NO | YES/NO --- {reason} | {H/M/L/N/A} |

**CRITICAL**: `copy` on a value-bearing type means the value can be duplicated at zero cost. This is the Move equivalent of a double-spend.

**Check for each `copy` struct**:
1. Can this struct be copied and then used multiple times? (e.g., copied receipt redeemed twice)
2. Does the module rely on move semantics to enforce single-use? If yes, `copy` breaks that assumption.
3. Is `copy` needed for legitimate operations? (e.g., snapshot reads, event emission) --- if not, it should be removed.
4. Trace all functions that accept this struct as a parameter: do they consume (move) or borrow (&) it? If they consume, copy lets callers retain the original.

**MANDATORY GREP**: Search all `.move` files for `has copy` and `copy,` in struct definitions. For each hit: (1) classify the struct, (2) if value-bearing, mark as FINDING.

### 2b. Copy-Then-Use Trace

For each `copy` struct identified as potentially dangerous:

```
1. Caller obtains instance I of struct S
2. Caller copies: I_copy = copy I
3. Caller uses I in function F1 (consumed/moved)
4. Caller uses I_copy in function F2 (consumed/moved)
5. Impact: {double-spend, double-claim, double-vote, obligation bypass}
```

Tag: `[TRACE:copy S → use1 in F1 → use2 in F2 → impact: {X}]`

## 3. Drop Ability Audit

For each struct with the `drop` ability:

### 3a. Obligation Bypass Check

| Struct | Has `drop`? | Represents Obligation? | Drop Bypasses Cleanup? | Severity |
|--------|-------------|----------------------|----------------------|----------|
| {name} | YES/NO | YES/NO | YES/NO --- {reason} | {H/M/L/N/A} |

**CRITICAL**: `drop` on an obligation-bearing struct means the obligation can be silently discarded. This is the Move equivalent of skipping a required finally-block.

**Hot potato pattern check**: The hot potato pattern relies on structs having NO `drop` ability, forcing the caller to pass them to a consuming function. If `drop` is present, the pattern is broken.

**Check for each `drop` struct**:
1. Is this struct a receipt or proof that must be returned to a specific function? (flash loan receipt, lock receipt, callback proof)
2. Does any function create this struct with the expectation that a corresponding "finalize" function will consume it?
3. What state changes happen in the finalize function? If the struct is dropped instead, those state changes never occur.
4. Does dropping this struct leave the protocol in an inconsistent state? (borrowed funds not returned, locks not released, counters not decremented)

### 3b. Drop-Instead-of-Consume Trace

For each obligation struct:

```
1. Function F_create creates struct S (e.g., flash_loan returns receipt)
2. EXPECTED: Caller passes S to F_consume (e.g., repay(receipt))
3. ACTUAL (if drop): Caller drops S, F_consume never called
4. Impact: {funds not returned, lock not released, state inconsistent}
```

Tag: `[TRACE:drop obligation S → F_consume skipped → impact: {X}]`

## 4. Store Ability Audit

For each struct with the `store` ability:

### 4a. Module Control Escape Check

| Struct | Has `store`? | Can Escape Module? | Invariant Break If Escaped? | Severity |
|--------|-------------|-------------------|---------------------------|----------|
| {name} | YES/NO | YES --- via {mechanism} / NO | YES/NO --- {which invariant} | {H/M/L/N/A} |

**Check for each `store` struct**:
1. `store` allows the struct to be placed inside other structs, into `Table`/`SmartTable`, or moved to global storage via a wrapping resource. Can an attacker store this struct in their own resource, bypassing module-controlled access?
2. Does the module rely on controlling where instances of this struct live? If instances escape to user-controlled storage, can they be replayed, hoarded, or used out of context?
3. For structs with `store` but without `key`: can they be wrapped in a user-defined `key` struct to achieve unauthorized global storage?
4. If the struct contains mutable references to shared state (e.g., via `&mut` in the functions that operate on it), does escaping the module allow stale or orphaned references?

### 4b. Unauthorized Persistence Trace

For structs not intended to persist outside module control:

```
1. Module M creates struct S with `store` ability
2. Attacker wraps S in their own struct W (has key + store)
3. Attacker calls move_to<W>(@attacker, W { s: obtained_S })
4. S now persists at attacker's address outside M's control
5. Impact: {replay, hoarding, context-escape, stale state}
```

## 5. Key Ability Audit

For each struct with the `key` ability:

### 5a. Resource Lifecycle Check

| Struct | Has `key`? | Intended as Global Resource? | move_from Protected? | move_to Protected? | Severity |
|--------|-----------|----------------------------|---------------------|-------------------|----------|
| {name} | YES/NO | YES/NO | YES --- {by what} / NO | YES --- {by what} / NO | {H/M/L/N/A} |

**Check for each `key` struct**:
1. Who can call `move_to` for this resource? Is creation properly gated by access control (signer capability, admin checks)?
2. Who can call `move_from` for this resource? Can an attacker remove a critical resource from an address?
3. Is the resource intended to be a singleton (one per address/globally)? If yes, can an attacker cause duplicate creation or premature deletion?
4. Does the module use `exists<S>(addr)` checks? Can an attacker manipulate resource existence to bypass guards?
5. For resources published at a shared/module address: what happens if the resource is removed? Does the protocol become non-functional?

### 5b. Resource Deletion Impact

For each resource that other functions depend on:

| Resource | Functions That Read It | Functions That Require exists<S> | Impact If Deleted |
|----------|----------------------|--------------------------------|-------------------|
| {name} | {list} | {list} | {abort, DoS, state corruption} |

## 6. Ability Combination Analysis

Analyze dangerous ability combinations:

| Struct | Abilities | Combination Risk | Attack Vector | Severity |
|--------|-----------|-----------------|---------------|----------|
| {name} | copy + store | Replicate and persist duplicates in global storage | Infinite value creation via copy then store each copy | Critical |
| {name} | drop + key | Abandon a top-level resource | Delete critical protocol state, DoS | High |
| {name} | copy + drop | Infinite creation + no cleanup obligation | Value duplication with no consumption requirement | Critical (if value-bearing) |
| {name} | copy + drop + store | All of the above combined | Maximum exploitation surface | Critical (if value-bearing) |
| {name} | key + copy | Resource duplication at global level | Move resource to address, copy, move copy elsewhere | High |

**MANDATORY**: For every value-bearing or obligation-bearing struct, verify that NONE of these dangerous combinations are present. If present, classify as FINDING with severity based on the struct's role.

**Safe combinations**:
- `store` alone on data structs (stored inside other resources, no standalone risk)
- `copy + drop` on purely informational structs (events, read-only parameters)
- `key + store + drop` on administrative resources with proper access control

## 7. Generic Type Parameter Abilities

For every generic struct and generic function in the audited modules:

### 7a. Generic Struct Constraints

| Struct | Type Param | Constraint | Sufficient? | Unexpected Instantiation? |
|--------|-----------|-----------|-------------|--------------------------|
| `Wrapper<T: store>` | T | store | {analysis} | {can attacker use T = MaliciousType?} |

**Check**:
1. Is the ability constraint on the type parameter the MINIMUM required? Overly permissive constraints (e.g., `T: store + copy + drop` when only `store` is needed) expand the attack surface.
2. Can an attacker instantiate the generic with a type that has unexpected properties? Example: `Pool<T: store>` instantiated with a custom token type that has transfer hooks or non-standard behavior.
3. For phantom type parameters (`phantom T`): does the module correctly use them for type-level discrimination without relying on runtime properties of T?
4. Do ability constraints on generic parameters match the constraints required by all functions that operate on the containing struct?

### 7b. Ability Constraint Mismatch

Check for mismatches between struct definition and function signatures:

```
struct Container<T: store> has key, store { item: T }

// POTENTIAL ISSUE: Function requires T: copy + store, but Container only requires T: store
// Can Container be created with a non-copy T, then this function fails?
public fun clone_item<T: copy + store>(c: &Container<T>): T { *&c.item }
```

**Impact**: If a module publishes a Container<NonCopyType>, the clone_item function aborts at runtime. Is this a DoS vector?

## Finding Template

When this skill identifies an issue:

```markdown
**ID**: [AB-N]
**Severity**: [based on struct role and exploitation impact]
**Step Execution**: check1,2,3,4,5,6,7 | X(reasons) | ?(uncertain)
**Rules Applied**: [R4:Y, R5:Y, R10:Y, R17:Y]
**Location**: module::struct_name (source_file.move:LineN)
**Title**: [Struct] has [ability] enabling [attack: duplication/obligation bypass/escape/deletion]
**Description**: [Trace the ability exploitation from struct definition to impact]
**Impact**: [What breaks: double-spend, obligation bypass, state corruption, DoS]
```

---

## Step Execution Checklist (MANDATORY)

> **CRITICAL**: You MUST report completion status for ALL sections. Steps 2 and 6 are highest priority.

| Section | Required | Completed? | Notes |
|---------|----------|------------|-------|
| 1. Struct Ability Inventory | YES | Y/X/? | Enumerate ALL structs |
| 2. Copy Ability Audit | **YES** | Y/X/? | **MANDATORY** --- highest-severity source |
| 2b. Copy-Then-Use Trace | IF copy on value type | Y/X(N/A)/? | |
| 3. Drop Ability Audit | YES | Y/X/? | Hot potato pattern check |
| 3b. Drop-Instead-of-Consume Trace | IF drop on obligation type | Y/X(N/A)/? | |
| 4. Store Ability Audit | YES | Y/X/? | Module control escape |
| 5. Key Ability Audit | YES | Y/X/? | Resource lifecycle |
| 5b. Resource Deletion Impact | IF key resources found | Y/X(N/A)/? | |
| 6. Ability Combination Analysis | **YES** | Y/X/? | **MANDATORY** --- dangerous combos |
| 7. Generic Type Parameter Abilities | IF generics present | Y/X(N/A)/? | Constraint sufficiency |

### Cross-Reference Markers

**After Section 2** (Copy Ability Audit):
- IF copy on value-bearing struct found -> cross-reference with `TYPE_SAFETY.md` Section 2 for type substitution amplification
- IF copy enables double-use -> severity minimum HIGH

**After Section 3** (Drop Ability Audit):
- IF drop on obligation struct found -> cross-reference with token flow analysis for flash loan receipt handling
- IF drop bypasses repayment -> severity minimum CRITICAL

**After Section 6** (Ability Combination Analysis):
- IF dangerous combination found on value-bearing struct -> severity minimum HIGH
- Document all structs with safe ability justification for audit trail
