---
name: "ability-analysis"
description: "Trigger Pattern Always (Sui Move) -- foundational security check - Inject Into Breadth agents, depth agents"
---

# ABILITY_ANALYSIS Skill

> **Trigger Pattern**: Always (Sui Move) -- foundational security check
> **Inject Into**: Breadth agents, depth agents

For every struct defined in the protocol:

**STEP PRIORITY**: Steps 5 (Hot Potato Enforcement) and 7 (Dynamic Field Ability Propagation) are where HIGH/CRITICAL severity findings most commonly hide. Do NOT rush these steps. If constrained, skip conditional sections before skipping 5 or 7.

## 1. Struct Ability Inventory

Enumerate ALL structs across all modules:

| Module | Struct | Abilities | Has `id: UID`? | Is Object? | Transferable? | Notes |
|--------|--------|-----------|----------------|------------|---------------|-------|
| {mod} | {name} | {key, store, drop, copy} | YES/NO | YES/NO | YES/NO | {context} |

**Sui ability semantics**:
- `key` = Object type. MUST have `id: UID` as the first field. Can be owned, shared, or frozen.
- `store` = Can be transferred freely via `public_transfer` / `public_share_object`. Can be stored inside other objects via dynamic fields or wrapping.
- `drop` = Can be implicitly discarded. Without `drop`, the value MUST be explicitly consumed (unpacked, transferred, or destroyed).
- `copy` = Can be duplicated. `copy + key` is IMPOSSIBLE in Sui -- objects cannot be copied.
- No abilities at all = Hot potato pattern. Value must be consumed within the same transaction.

**Consistency check**: For each struct with `key`:
- [ ] Does it have `id: UID` as the FIRST field? If not -> compilation error (catch misplaced UID).
- [ ] Is `store` intentionally included or omitted? `key` without `store` = only the defining module can transfer it (custom transfer rules).

## 2. Object Model Classification

Classify each object (`key` ability) by ownership model:

| Object | Ownership | Created Via | Transfer Restricted? | Freeze Possible? |
|--------|-----------|-------------|---------------------|-----------------|
| {name} | Owned / Shared / Frozen / Wrapped | {function} | YES (no `store`) / NO (`store`) | YES/NO |

**Security checks per ownership type**:

### 2a. Owned Objects
- Can the owner transfer to themselves via `transfer::transfer` to reset state?
- Are there time-locks or cooldowns that reset on transfer?
- Can owned objects be wrapped inside other objects to bypass module restrictions?

### 2b. Shared Objects
- Is the object made shared via `transfer::share_object` at creation?
- Once shared, can never be un-shared -- is this intended?
- Shared objects require consensus ordering -- are there ordering-dependent operations?
- **Critical**: Can an attacker create a competing shared object of the same type?

### 2c. Frozen Objects (Immutable)
- Is the object frozen via `transfer::freeze_object`?
- Once frozen, can never be mutated -- is this intended?
- Are there references to the frozen object that expect mutation?

### 2d. Wrapped Objects
- Objects stored as fields inside other objects lose their independent existence.
- Can wrapping bypass transfer restrictions (object with `key` only, no `store`, wrapped inside a `key + store` parent)?
- When unwrapped, does the object retain its original ID and state?

## 3. Ability Mismatch Analysis

For each struct, verify ability assignments match intended behavior:

### 3a. Missing `drop` -- Intentional?
| Struct | Has `drop`? | Explicit Destroy Function? | Can Leak? |
|--------|------------|---------------------------|-----------|
| {name} | NO | YES: `destroy_{name}()` / NO | YES/NO |

**Rule**: A struct without `drop` that has no explicit destroy/consume path creates a resource leak. The transaction will abort if the value is not consumed. This is sometimes intentional (hot potato) but often a bug when the struct is created in error paths.

### 3b. Unnecessary `store` -- Over-Permissive?
| Struct | Has `store`? | Stored in Dynamic Fields? | Freely Transferable? | Should Be Restricted? |
|--------|-------------|--------------------------|---------------------|----------------------|
| {name} | YES | YES/NO | YES | {analysis} |

**Check**: If a struct has `store` but the protocol intends restricted transfers (e.g., non-transferable receipts, bound tickets), the `store` ability enables bypass via `public_transfer`. Does any security invariant depend on transfer restriction?

### 3c. `copy` Abuse Potential
| Struct | Has `copy`? | Contains Balances/IDs? | Duplication Dangerous? |
|--------|------------|----------------------|----------------------|
| {name} | YES/NO | YES/NO | YES/NO |

**Rule**: `copy` on a struct containing `Balance<T>`, capability tokens, or unique identifiers is almost always a bug -- it enables double-spending or capability duplication. `copy + key` is impossible (enforced by Sui), but `copy + store` on inner structs is allowed and dangerous if they hold value.

## 4. Capability Pattern Audit

Identify all capability/admin structs:

| Capability | Abilities | Created In | Transferred To | Can Be Duplicated? | Revocable? |
|-----------|-----------|------------|---------------|-------------------|-----------|
| {name} | {abilities} | `init()` | {recipient} | YES (`copy`) / NO | YES/NO |

**Checks**:
- Is the capability created only in `init()` (module initializer)? If created elsewhere, can it be minted by unauthorized parties?
- Does the capability have `store`? If yes, the holder can transfer it freely -- is this intended?
- Is there a revocation mechanism? (Capability patterns in Sui are typically one-way -- once issued, not revocable without wrapping in a shared object with access control.)
- **One-Time Witness (OTW) vs Capability**: Is this struct actually an OTW being misused as a persistent capability? OTW types should be consumed in `init`, not stored.

## 5. Hot Potato Enforcement

Identify all structs with NO abilities:

| Struct | Module | Created By | Must Be Consumed By | Enforced? |
|--------|--------|------------|--------------------|---------:|
| {name} | {mod} | {function} | {function} | YES/NO |

**Hot potato security checks**:
- [ ] Is the hot potato created and consumed within a single PTB (Programmable Transaction Block)?
- [ ] Can the consumption function be called by anyone, or only specific callers?
- [ ] Does the consumption function validate the hot potato's contents match expectations?
- [ ] Can an attacker create a fake hot potato of the same type from a different module? (NO -- Move type system prevents cross-module struct creation.)
- [ ] Can the hot potato be stored if someone adds `store` via a wrapper? (Check: is there a public wrapper that accepts arbitrary `store` types.)
- [ ] **Transaction abort impact**: If the hot potato cannot be consumed (e.g., consumption function reverts), the entire PTB aborts. Can this be used for griefing? (e.g., attacker causes the consumption precondition to fail after the hot potato is created.)

**Pattern validation**: Trace every hot potato from creation to consumption. Document the full lifecycle:
```
create: module::start_action() -> HotPotato
  ... intervening calls that rely on HotPotato's existence ...
consume: module::finish_action(potato: HotPotato)
```
If any code path creates a hot potato without a guaranteed consumption path -> FINDING (transaction will always abort on that path).

## 6. Transfer Restriction Analysis

For objects with `key` but NOT `store`:

| Object | Module Transfer Function | Custom Rules | Bypass Possible? |
|--------|------------------------|-------------|-----------------|
| {name} | {function or NONE} | {description} | YES/NO |

**Sui transfer rules**:
- `key + store`: Anyone can transfer via `transfer::public_transfer`.
- `key` only: Only the defining module can transfer via `transfer::transfer` (requires module-level access).
- **Bypass check**: Can the restricted object be wrapped inside a `store`-capable struct, then the wrapper transferred freely? If the wrapping struct is from a DIFFERENT module, this is a transfer restriction bypass.

**Check each restricted object**:
1. Does any public function accept this object type and wrap it?
2. Does any public function accept this object type and place it in a dynamic field of a freely transferable object?
3. If yes to either -> the transfer restriction is bypassable -> FINDING.

## 7. Dynamic Field Ability Propagation

For every use of `dynamic_field::add` or `dynamic_object_field::add`:

| Parent Object | Field Key Type | Field Value Type | Value Has `store`? | Parent Has `store`? |
|--------------|---------------|-----------------|-------------------|-------------------|
| {parent} | {key_type} | {value_type} | YES/NO | YES/NO |

**Rules**:
- `dynamic_field::add` requires the value type to have `store`.
- `dynamic_object_field::add` requires the value type to have `key + store`.
- **Security check**: If a value with `store` is added as a dynamic field, anyone who can access the parent object can potentially extract it via `dynamic_field::remove`. Is extraction access-controlled?
- **Orphan check**: If the parent object is destroyed, are dynamic fields cleaned up? Orphaned dynamic fields remain in storage and can never be accessed again -> permanent storage leak.
- **Type confusion**: Dynamic fields are keyed by type. Can an attacker add a dynamic field with a key type that collides with an expected key type? (Unlikely due to Move type system, but check for generic key types like `vector<u8>` or `String`.)

## 8. Module Initializer Audit

For each module with an `init` function:

| Module | `init` Parameters | Objects Created | Capabilities Issued | OTW Consumed? |
|--------|------------------|-----------------|--------------------|--------------:|
| {mod} | {params} | {list} | {list} | YES/NO/N/A |

**Checks**:
- Is `init` the ONLY place critical capabilities are created?
- Does `init` properly consume the One-Time Witness if one is passed?
- Can the module be re-initialized via package upgrade? (Sui package upgrades do NOT re-run `init`.)
- Are shared objects created in `init`? (They must be -- you cannot share an owned object after creation in Sui.)

## Finding Template

```markdown
**ID**: [AB-N]
**Severity**: [based on ability misuse impact]
**Step Execution**: check1,2,3,4,5,6,7,8 | X(reasons) | ?(uncertain)
**Rules Applied**: [R4:Y, R5:Y, R10:Y, ...]
**Location**: module::struct_name
**Title**: [Ability issue type] in [struct] enables [attack/bypass]
**Description**: [Specific ability misconfiguration with type-level trace]
**Impact**: [What breaks: transfer restriction bypass, capability duplication, resource leak, hot potato griefing]
```

---

## Step Execution Checklist (MANDATORY)

> **CRITICAL**: You MUST report completion status for ALL sections. Findings with incomplete sections will be flagged for depth review.

| Section | Required | Completed? | Notes |
|---------|----------|------------|-------|
| 1. Struct Ability Inventory | YES | Y/X/? | |
| 2. Object Model Classification | YES | Y/X/? | |
| 2b. Shared Object Analysis | IF shared objects | Y/X(N/A)/? | |
| 3. Ability Mismatch Analysis | YES | Y/X/? | |
| 3b. Unnecessary `store` Check | YES | Y/X/? | |
| 3c. `copy` Abuse Check | YES | Y/X/? | |
| 4. Capability Pattern Audit | YES | Y/X/? | |
| 5. Hot Potato Enforcement | IF hot potatoes exist | Y/X(N/A)/? | **HIGH PRIORITY** |
| 6. Transfer Restriction Analysis | IF `key`-only objects | Y/X(N/A)/? | |
| 7. Dynamic Field Ability Propagation | IF dynamic fields used | Y/X(N/A)/? | **HIGH PRIORITY** |
| 8. Module Initializer Audit | YES | Y/X/? | |

### Cross-Reference Markers

**After Section 4** (Capability Pattern Audit):
- Cross-reference with `TYPE_SAFETY.md` Section on OTW analysis
- IF capability has `store` -> flag for SEMI_TRUSTED_ROLES analysis

**After Section 5** (Hot Potato Enforcement):
- IF hot potato consumption depends on external state -> cross-reference with EXTERNAL_PRECONDITION_AUDIT
- IF hot potato abort causes shared object locking -> document consensus impact

**After Section 7** (Dynamic Field Ability Propagation):
- IF dynamic field values extractable by non-owners -> FINDING (minimum Medium)
- Cross-reference with TOKEN_FLOW_TRACING for dynamic field token storage
