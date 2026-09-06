---
name: "storage-lifecycle"
description: "Trigger Pattern Always required for Soroban audits - Inject Into Breadth agents, depth agents"
---

# STORAGE_LIFECYCLE Skill (Soroban)

> **Trigger Pattern**: Always required for Soroban audits
> **Inject Into**: Breadth agents, depth-state-trace, depth-edge-case
> **Finding prefix**: `[SL-N]`
> **Rules referenced**: R8, R10, R14

Soroban has three distinct storage types — Instance, Persistent, and Temporary — with fundamentally different lifetime semantics. Using the wrong storage type is a critical design flaw. Instance and Persistent entries expire if TTL is not extended; Temporary entries are permanently deleted at expiration with no recovery path.

## 1. Storage Type Audit

For every storage key defined (typically in a `DataKey` enum or equivalent), verify the correct storage type is used:

| DataKey Variant | Storage Type Used | Correct Type? | Justification |
|----------------|------------------|--------------|---------------|
| `{key}` | Instance / Persistent / Temporary | YES/NO | `{why this type is correct or wrong}` |

**Selection rules**:
- **Instance**: Contract-wide config that lives and dies with the contract itself (admin address, fee parameters, pause flag). Shared 64KB limit with all other Instance entries for this contract.
- **Persistent**: User-specific state that must survive indefinitely (balances, positions, allowances that should not expire). Requires explicit TTL extension. Archived entries can be restored but require a fee.
- **Temporary**: Truly ephemeral data that becomes invalid after a period (short-lived signatures, nonces with expiry, one-time-use proofs). Permanently deleted at expiry — **no recovery**.

**Common misclassifications to flag**:
- User balances stored as Temporary (funds permanently lost at expiry)
- Escrow or locked funds stored as Temporary
- Allowances stored as Temporary without the protocol communicating expiry to users
- Voting records or governance state stored as Temporary (votes silently discarded)

## 2. TTL Management

Soroban entries expire if their TTL is not extended. Identify all critical entries and verify TTL extension logic:

| DataKey | Storage Type | TTL Extended? | Extension Location | Threshold Value | Extend-To Value | Reasonable? |
|---------|-------------|--------------|-------------------|----------------|-----------------|-------------|
| `{key}` | Persistent/Instance | YES/NO | `{fn:line or NONE}` | `{ledgers or NONE}` | `{ledgers or NONE}` | YES/NO |

**Check for**:
- Critical entries (admin, balances, config) never having their TTL extended → will expire after the initial minimum TTL (~17 days at default settings)
- `extend_ttl` called with `threshold = 0` (extends on every call, expensive) vs reasonable threshold
- `extend_ttl` called only in some code paths but not others (e.g., extended on deposit but not on query)
- Extend-to value set too low (e.g., 100 ledgers ≈ 8 minutes) causing rapid re-expiry

**TTL extension pattern (correct)**:
```rust
let max_ttl = env.ledger().max_entry_ttl();
env.storage().persistent().extend_ttl(&key, max_ttl / 2, max_ttl);
```

**Dangerous anti-pattern**:
```rust
// Never extends TTL — entry will expire after initial minimum
env.storage().persistent().set(&DataKey::Balance(user), &balance);
// (no extend_ttl call anywhere for this key)
```

## 3. Instance Storage Bounds

Instance storage is shared across ALL instance entries for a contract and has a hard cap of approximately 64KB. Unbounded growth causes contract failure.

| DataKey | Stored in Instance? | Data Type | Can Grow Unboundedly? | Current Bound | Risk |
|---------|--------------------|-----------|-----------------------|---------------|------|
| `{key}` | YES/NO | `{type}` | YES/NO | `{N entries or unbounded}` | HIGH/MED/LOW |

**Check for**:
- `Vec<T>` stored in Instance storage — grows with each `push`
- `Map<K, V>` stored in Instance storage — grows with each new key
- Any collection type in Instance storage that users or external callers can add to

**Attack**: If Instance storage approaches 64KB, ALL contract operations that touch instance storage fail, effectively bricking the contract. An attacker who can add entries (e.g., via a public function that appends to an Instance-stored Vec) can DoS the entire contract.

**Estimate growth**: For each unbounded Instance collection, estimate: what is the maximum realistic entry size? How many entries before 64KB is reached? Is that number reachable by a malicious actor?

### 3b. Persistent Storage Single-Entry Growth DoS

Even though Persistent storage has no shared size limit, each individual ledger entry has a ~64KB size limit. A single Persistent key holding a growing collection hits this limit the same way Instance storage does.

| Persistent Key | Data Type | Grows With Users? | Approx Entries Before ~64KB | Permissionless Append? | Risk |
|---------------|-----------|-------------------|----------------------------|------------------------|------|
| `{key}` | `{Vec/Map}` | YES/NO | `{estimate}` | YES/NO | HIGH/MED/LOW |

**Dangerous pattern**: `DataKey::AllUsers` → `Vec<Address>` stored as a single Persistent entry. At ~32 bytes per Address, this hits ~64KB at ~2,000 entries.

**Correct pattern**: Variable DataKeys — one Persistent entry per user/item: `DataKey::User(address)` → `UserData`. This distributes data across unlimited entries with no single-entry size constraint.

**Check for**: Any Persistent storage key that stores a collection type (`Vec<T>`, `Map<K,V>`) where the collection grows with protocol usage (new users, new positions, new orders). If the append operation is permissionless or low-cost, flag as DoS risk (same severity as Instance storage DoS).

## 4. Archival Risk Assessment

Persistent entries that are not extended will eventually be archived by the network. Archived entries can be restored but this requires paying a fee and providing a Merkle proof — not a default user flow.

| DataKey | Persistent? | TTL Extended? | Archive Risk | Recovery Path Exists? | User Impact if Archived |
|---------|------------|--------------|-------------|----------------------|------------------------|
| `{key}` | YES/NO | YES/NO | HIGH/MED/LOW | YES/NO | `{impact description}` |

**High-risk patterns**:
- User positions/balances that are never TTL-extended → users who haven't interacted for ~17 days lose access until they (or someone) pays for restoration
- Protocol-owned accounts (liquidity pools, vaults) with no TTL extension mechanism → pool becomes inaccessible
- Admin key archived → protocol loses all admin capabilities

**For each HIGH risk entry**: verify whether the protocol documentation communicates archival risk to users and whether the smart contract itself provides a `restore` helper function.

## 5. Temporary Data Critical Assessment

Temporary storage is permanently deleted when it expires — there is no archival, no restoration, no recovery. Verify no critical value is stored as Temporary:

| DataKey | Temporary Storage? | Critical Value? | Deletion Impact | Finding? |
|---------|-------------------|-----------------|----------------|---------|
| `{key}` | YES/NO | YES/NO | `{what is lost}` | `[SL-N]` if critical + Temporary |

**Critical values that MUST NOT use Temporary storage**:
- Token balances or positions
- Locked/escrowed funds
- Governance votes or proposals
- Access control grants
- Any value that represents user funds or irreversible commitments

**Acceptable Temporary storage uses**:
- Price oracle observations with explicit expiry
- Short-lived authorization proofs (e.g., CLOB order validity windows)
- Rate-limiting counters that naturally reset
- Replay-protection nonces where expiry is intentional

## 6. Storage Key Collision

Soroban storage keys are arbitrary `Val` types. If the same key value is written to different storage types, they are separate entries (no collision). However, within the same storage type, key values must be unique across all uses.

| Storage Type | Key Values in Use | Any Duplicates? | Collision Impact |
|-------------|------------------|----------------|-----------------|
| Instance | `{list DataKey variants}` | YES/NO | `{if YES: which keys collide and what is overwritten}` |
| Persistent | `{list DataKey variants}` | YES/NO | `{if YES: which keys collide and what is overwritten}` |
| Temporary | `{list DataKey variants}` | YES/NO | `{if YES: which keys collide and what is overwritten}` |

**Collision patterns to check**:
- DataKey enum variants that serialize to the same byte representation (e.g., tuple variants with the same structure but different semantic meaning)
- Dynamic keys using `(symbol, address)` tuples where two different contexts could produce the same tuple
- Integer keys used across multiple logical namespaces without a discriminator prefix

## Finding Template

```markdown
**ID**: [SL-N]
**Severity**: [Critical if funds permanently lost, High if DoS/archival risk, Medium if config risk]
**Step Execution**: ✓1,2,3,4,5,6 | ✗(reasons) | ?(uncertain)
**Rules Applied**: [R8:✓/✗, R10:✓/✗, R14:✓/✗]
**Location**: src/{contract}.rs:LineN
**Title**: {DataKey} stored as {wrong type / missing TTL extension} — {impact}
**Description**: [Specific storage type misuse with the key, the type used, and why it is wrong]
**Impact**: [Permanent fund loss / contract DoS / config expiry / inaccessible protocol]
```

---

## Step Execution Checklist (MANDATORY)

| Section | Required | Completed? | Notes |
|---------|----------|------------|-------|
| 1. Storage Type Audit | YES | ✓/✗/? | Every DataKey variant |
| 2. TTL Management | YES | ✓/✗/? | Every Persistent and Instance key |
| 3. Instance Storage Bounds | YES | ✓/✗/? | All collections in Instance storage |
| 4. Archival Risk Assessment | YES | ✓/✗/? | All Persistent keys without TTL extension |
| 5. Temporary Data Critical Assessment | YES | ✓/✗/? | All Temporary keys |
| 6. Storage Key Collision | YES | ✓/✗/? | All DataKey variants per storage type |
