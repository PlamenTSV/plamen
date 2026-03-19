---
name: "object-ownership"
description: "Trigger Pattern Always required for Sui Move audits -- object lifecycle and ownership model - Inject Into Breadth agents, depth-state-trace, depth-token-flow"
---

# OBJECT_OWNERSHIP Skill

> **Trigger Pattern**: Always required for Sui Move audits -- object lifecycle and ownership model
> **Inject Into**: Breadth agents, depth-state-trace, depth-token-flow
> **Finding prefix**: `[OO-N]`
> **Rules referenced**: R4, R5, R9, R10, R13

Sui's object-centric model is fundamentally different from account-based chains. Every struct with the `key` ability is an on-chain object with a globally unique ID, and its ownership model (owned/shared/frozen/wrapped) determines who can access and mutate it. Incorrect ownership choices, missing transfer restrictions, orphaned UIDs, and uncontrolled dynamic fields are the primary Sui-specific vulnerability classes.

---

## 1. Object Inventory

For EVERY struct with `key` ability in the codebase, build this table:

| # | Object Name (Module) | Abilities | Ownership Model | Created Where | Transferred Where | Destroyed Where | Has `store`? |
|---|---------------------|-----------|-----------------|---------------|-------------------|-----------------|-------------|
| 1 | {name} ({module}) | {key, store, ...} | OWNED / SHARED / FROZEN / WRAPPED / MIXED | {function:line} | {function:line or NEVER} | {function:line or NEVER} | YES/NO |

**Ability rules**:
- `key` alone: Object can exist on-chain but CANNOT be transferred by generic `transfer::public_transfer` (requires module-defined transfer logic).
- `key + store`: Object CAN be transferred by anyone via `transfer::public_transfer`. This is a **permissive** choice -- verify it is intentional.
- `key + store + copy`: Object can be duplicated -- extremely rare for value-bearing objects. FLAG if found on any object holding balances.
- `key + store + drop`: Object can be silently discarded without calling a destructor. FLAG if the object holds `Balance<T>` or other value -- tokens can be lost.

**Ownership model classification**:
- **OWNED**: Created and transferred to a specific address via `transfer::transfer` or `transfer::public_transfer`. Only the owner can pass it as a transaction argument.
- **SHARED**: Made accessible to all via `transfer::public_share_object`. Any transaction can read/write it. CRITICAL access control implications.
- **FROZEN**: Made immutable via `transfer::public_freeze_object`. Anyone can read, no one can mutate.
- **WRAPPED**: Stored as a field inside another object (not directly addressable on-chain). Accessible only through the parent.
- **MIXED**: Object starts as one type and transitions to another (e.g., created as owned, then shared). Document the transition path.

---

## 2. Ownership Model Analysis

### 2a. Owned Object Audit

For each OWNED object:

| Object | Should Be Shared Instead? | Ownership Transfer Possible? | Transfer Restriction Correct? | Assumption Risk |
|--------|--------------------------|-----------------------------|-----------------------------|----------------|
| {name} | YES/NO ({reason}) | YES (has `store`) / NO (no `store`) | {analysis} | {risk if ownership changes} |

**Check patterns**:
- **Should this be shared?** If multiple unrelated parties need to mutate the object in the same epoch, owned model creates bottlenecks or requires trust delegation. Common mistake: config objects that should be shared are kept owned, forcing single-admin bottleneck.
- **Ownership change undermines assumptions?** If code assumes "only admin holds AdminCap", but AdminCap has `store` ability, it can be transferred to anyone. Verify that transfer does not break invariants downstream.
- **Phantom ownership**: Object is "owned" but the owner address is a PDA-like derived address that nobody controls (e.g., `@0x0`). The object is effectively inaccessible -- equivalent to locked funds if it holds value.

### 2b. Shared Object Audit

For each SHARED object:

| Object | Mutation Functions | Access Guards | Concurrent Mutation Risk | Ordering Dependency |
|--------|-------------------|---------------|------------------------|-------------------|
| {name} | {list all functions that take `&mut` ref} | {what prevents unauthorized mutation} | YES/NO ({analysis}) | YES/NO ({analysis}) |

**CRITICAL checks**:
- **Access control on mutation**: Shared objects can be passed as arguments by ANY transaction. If a function takes `&mut SharedObj` without verifying the caller has authority (e.g., checking a capability object), anyone can mutate it. This is the #1 Sui vulnerability pattern.
- **Consensus ordering**: Transactions touching the same shared object are ordered by Sui's consensus. If the protocol relies on specific transaction ordering (e.g., "admin sets fee before user trades"), front-running is possible because consensus ordering is non-deterministic from the user's perspective.
- **Race conditions**: Two transactions that both mutate the same shared object field can produce different final states depending on execution order. If the protocol assumes sequential access, this is a bug.
- **Gas-based DoS**: An attacker can submit many transactions touching a shared object to increase contention and gas costs for legitimate users.

### 2c. Frozen Object Audit

For each FROZEN object:

| Object | Should Updates Be Possible? | Freezing Reversible? | Data Staleness Risk |
|--------|-----------------------------|---------------------|-------------------|
| {name} | YES/NO ({reason}) | NO (by design) | {risk if frozen data becomes stale} |

**Check**: If frozen object holds configuration that may need updating (fee rates, oracle addresses, admin keys), freezing is likely wrong -- should be shared with access control instead.

### 2d. Wrapped Object Audit

For each WRAPPED object:

| Parent Object | Wrapped Object | Unwrap Path Exists? | Dynamic Fields on Wrapped? | Destruction Safety |
|--------------|---------------|--------------------|--------------------------|--------------------|
| {parent} | {wrapped} | YES ({function}) / NO | YES/NO | {what happens to wrapped when parent destroyed} |

**Check patterns**:
- **No unwrap path**: If a wrapped object holds value (Balance, Coin) but there is no function to extract it, funds are permanently locked inside the parent. Apply Rule 9: stranded asset = minimum MEDIUM.
- **Parent destruction without unwrap**: If the parent object can be destroyed (has `drop` ability or explicit destructor) without first unwrapping/extracting the inner object, the inner object's value is lost.
- **Dynamic fields on wrapped objects**: Dynamic fields added to a wrapped object's UID are NOT accessible when the object is wrapped. They become orphaned until unwrap. If the protocol adds dynamic fields and then wraps, those fields are inaccessible.

---

## 3. Object Transfer Analysis

For each `transfer::transfer`, `transfer::public_transfer`, `transfer::share_object`, `transfer::public_share_object`, `transfer::freeze_object`, `transfer::public_freeze_object` call:

| # | Transfer Call | Object Type | Initiator | `store` Required? | `store` Present? | Recipient Validation | Stranded Risk |
|---|-------------|------------|-----------|-------------------|-----------------|---------------------|---------------|
| 1 | {function:line} | {type} | {who calls} | YES (public_*) / NO (module-only) | YES/NO | {is recipient validated?} | {can object be sent to address that cannot use it?} |

**Check patterns**:
- **`store` ability gate**: `transfer::public_transfer` requires `store`. `transfer::transfer` does not -- it is module-restricted. If an object should NOT be freely transferable by holders, it should NOT have `store`.
- **Recipient validation**: If an object is transferred to an arbitrary address and that address does not have the matching module to use it, the object is stranded. This is especially dangerous for capability objects (AdminCap sent to a contract that cannot invoke admin functions).
- **Transfer to self**: Transferring an object to the transaction sender is sometimes used as a "commit" pattern. Verify this does not bypass any state transitions.
- **Conditional transfer**: If transfer happens inside a conditional branch, check the else branch -- does the object leak (neither transferred, shared, frozen, wrapped, nor destroyed)?

---

## 4. Shared Object Mutation Safety

For each shared object, build the mutation map:

| Shared Object | Function | Mutation Type | Guard | Re-entrancy Risk | Ordering Sensitivity |
|--------------|----------|--------------|-------|-----------------|---------------------|
| {obj} | {func} | FIELD_UPDATE / BALANCE_CHANGE / CHILD_ADD / CHILD_REMOVE | {capability check, address check, or NONE} | {can another function on same object be called mid-execution?} | {does outcome depend on call order?} |

**Sui-specific re-entrancy note**: Move's borrow checker prevents re-entrancy within a single module (you cannot pass `&mut Obj` to a function that also borrows `&mut Obj`). However, cross-module re-entrancy is possible if Object A's mutation calls a function in Module B that calls back to Module A with a different entry point that accesses a DIFFERENT shared object whose state is coupled with Object A.

**Concurrent mutation checklist**:
- [ ] Can two independent transactions mutate the same field to conflicting values?
- [ ] Does the protocol rely on reading a value from the shared object and then writing back a derived value? (TOCTOU with consensus ordering)
- [ ] Can an attacker observe a pending transaction on a shared object and submit a competing transaction that front-runs it?
- [ ] Are balance operations on shared objects atomic? (Balance::split + Balance::join should not be interruptible across objects)

---

## 5. Object Wrapping/Unwrapping

For each wrapping relationship (object stored as field in another object):

| Wrapper | Wrapped | Wrap Point | Unwrap Point | Dynamic Fields Before Wrap | UID Preserved on Unwrap? |
|---------|---------|-----------|-------------|--------------------------|-------------------------|
| {parent} | {child} | {function:line} | {function:line or NONE} | YES/NO | YES/NO/N/A |

**Check patterns**:
- **Dynamic field orphaning**: If `dynamic_field::add(child_uid, ...)` is called before `child` is wrapped into `parent`, those dynamic fields become inaccessible. They still exist on-chain (consuming storage) but cannot be read or removed until the child is unwrapped.
- **UID preservation**: When an object is unwrapped and re-created, does it get the same UID or a new one? If new UID, all dynamic fields on the old UID are orphaned permanently.
- **Nested wrapping depth**: Objects wrapped inside objects wrapped inside objects create deep access chains. Each level adds complexity and potential for state inconsistency.
- **Balance preservation invariant**: If the wrapped object holds `Balance<T>`, verify that total balance is preserved across wrap/unwrap cycles. No balance should be created or destroyed during wrapping.

---

## 6. UID Lifecycle Audit

Every call to `object::new(ctx)` creates a UID. Every UID must be either:
1. Stored in an object with `key` ability (the object's `id` field), OR
2. Explicitly destroyed via `object::delete(id)`

For each `object::new(ctx)` call:

| # | Creation Location | UID Stored In | Destruction Location | Lifecycle Complete? | Orphan Risk |
|---|------------------|--------------|---------------------|--------------------|-----------|
| 1 | {function:line} | {object field or VARIABLE} | {function:line or NONE} | YES/NO | {if NO: resource leak} |

**Check patterns**:
- **Orphaned UID**: If `object::new(ctx)` is called but the resulting UID is not stored in an object that gets transferred/shared/frozen, and not deleted, it is a resource leak. The UID exists on-chain consuming storage but is unreachable.
- **UID in error paths**: If a function creates a UID, then hits an abort/assert before storing it -- the transaction reverts, so no leak. BUT if the function returns early (non-abort) with the UID in a local variable -- this is a compiler error in Move (linear type), so it should not be possible. Verify the compiler catches this.
- **UID reuse**: A UID should never be reused after `object::delete`. Move's type system should prevent this, but verify in any `unsafe` or `native` code paths.
- **Dynamic field cleanup before delete**: Before calling `object::delete(id)`, ALL dynamic fields on that UID should be removed. Otherwise, the dynamic fields become permanently orphaned (the UID no longer exists to access them through). Apply Rule 9: orphaned dynamic fields holding value = stranded assets = minimum MEDIUM.

---

## 7. Dynamic Field Audit

For each `dynamic_field::add`, `dynamic_field::remove`, `dynamic_object_field::add`, `dynamic_object_field::remove`:

| # | Operation | Parent UID | Field Name/Type | Value Type | Access Control | Unbounded Growth? | Cleanup on Delete? |
|---|-----------|-----------|----------------|-----------|---------------|-------------------|-------------------|
| 1 | ADD | {parent:line} | {name type + value} | {type} | {who can add} | YES/NO | {is field removed before parent UID deleted?} |

**Check patterns**:
- **Unbounded growth**: If `dynamic_field::add` is called in a loop or user-facing function without a cap, the parent object's dynamic field set grows without limit. This increases gas costs for operations that iterate related state and can be used as a DoS vector.
- **Unauthorized field addition**: If ANY caller can add dynamic fields to a shared object's UID, an attacker can pollute the object's field namespace. This may cause `dynamic_field::borrow` to return unexpected data if field names collide.
- **Name collision**: Dynamic fields are keyed by `(TypeTag, name_value)`. If two different code paths add fields with the same key type and value, they overwrite each other. Verify field name uniqueness across all add operations on the same UID.
- **Type safety**: `dynamic_field::borrow<Name, Value>` will abort if the stored value type does not match `Value`. Verify all borrow calls use consistent type parameters with the corresponding add calls.
- **Object fields vs value fields**: `dynamic_object_field::add` stores objects (with `key` ability) that retain their own UID and are independently addressable. `dynamic_field::add` wraps values. Using the wrong variant can make objects inaccessible or create unexpected behavior.
- **Removal completeness**: Before an object is destroyed (`object::delete`), ALL dynamic fields must be removed. Build a removal completeness table:

| Parent Object | Destruction Function | Dynamic Fields Added | Dynamic Fields Removed Before Delete | Complete? |
|--------------|---------------------|---------------------|--------------------------------------|----------|
| {obj} | {func:line} | {list all add operations} | {list all remove operations in destructor} | YES/NO |

---

## Finding Template

```markdown
## Finding [OO-N]: Title

**Verdict**: CONFIRMED / PARTIAL / REFUTED / CONTESTED
**Step Execution**: checkmark1,2,3,4,5,6,7 | x(reasons) | ?(uncertain)
**Rules Applied**: [R4:Y/N, R5:Y/N, R9:Y/N, R10:Y/N, R13:Y/N]
**Severity**: Critical/High/Medium/Low/Info
**Location**: sources/{module}.move:LineN
**Description**: [Specific ownership/lifecycle issue with code reference]
**Impact**: [What can happen -- fund loss, state corruption, DoS, stranded assets]

### Precondition Analysis (if PARTIAL or REFUTED)
**Missing Precondition**: [What blocks this attack]
**Precondition Type**: STATE / ACCESS / TIMING / EXTERNAL / BALANCE
**Why This Blocks**: [Specific reason]

### Postcondition Analysis (if CONFIRMED or PARTIAL)
**Postconditions Created**: [What conditions this creates]
**Postcondition Types**: [STATE, ACCESS, TIMING, EXTERNAL, BALANCE]
**Who Benefits**: [Who can use these]
```

---

## Step Execution Checklist (MANDATORY)

| Section | Required | Completed? | Notes |
|---------|----------|------------|-------|
| 1. Object Inventory | YES | Y/N/? | Every struct with `key` ability |
| 2a. Owned Object Audit | IF owned objects exist | Y/N(none)/? | Transfer restriction + assumption risk |
| 2b. Shared Object Audit | IF shared objects exist | Y/N(none)/? | Access control on mutation |
| 2c. Frozen Object Audit | IF frozen objects exist | Y/N(none)/? | Staleness risk |
| 2d. Wrapped Object Audit | IF wrapped objects exist | Y/N(none)/? | Unwrap path + value preservation |
| 3. Object Transfer Analysis | YES | Y/N/? | Every transfer/share/freeze call |
| 4. Shared Object Mutation Safety | IF shared objects mutated | Y/N(none)/? | Concurrent mutation + ordering |
| 5. Object Wrapping/Unwrapping | IF wrapping relationships exist | Y/N(none)/? | Dynamic field orphaning + UID preservation |
| 6. UID Lifecycle Audit | YES | Y/N/? | Every `object::new` matched to storage or delete |
| 7. Dynamic Field Audit | IF dynamic fields used | Y/N(none)/? | Growth bounds + cleanup completeness |

### Cross-Reference Markers

**After Section 2b (Shared Object Audit)**: Feed unguarded mutation functions to SEMI_TRUSTED_ROLES skill if roles are involved in access control.

**After Section 3 (Transfer Analysis)**: Feed objects with `store` ability to TOKEN_FLOW_TRACING skill for balance flow analysis.

**After Section 6 (UID Lifecycle)**: Feed orphaned UIDs and incomplete dynamic field cleanup to depth-edge-case for stranded asset analysis (Rule 9).

**After Section 7 (Dynamic Field Audit)**: Feed unbounded growth patterns to ECONOMIC_DESIGN_AUDIT for DoS cost analysis.
