---
name: "ref-lifecycle"
description: "Type Thought-template (instantiate before use) - Trigger Pattern Always (Aptos Move) -- ConstructorRef/TransferRef/MintRef/BurnRef lifecycle"
---

# Skill: Reference Lifecycle Analysis

> **Type**: Thought-template (instantiate before use)
> **Trigger Pattern**: Always (Aptos Move) -- ConstructorRef/TransferRef/MintRef/BurnRef lifecycle
> **Inject Into**: Breadth agents, depth-state-trace, depth-token-flow
> **Research basis**: Aptos Object model capability-based access control, permanent reference semantics

## Background

In Aptos Move, object capabilities (Refs) are unforgeable tokens that grant specific permissions over objects. Unlike role-based access control in EVM, Refs are permanent once created -- they CANNOT be revoked. A leaked or improperly stored Ref grants permanent capability to its holder.

Key Ref types:
- **ConstructorRef**: Created once during `object::create_*`. Parent of all other Refs. Grants ability to generate TransferRef, MintRef, BurnRef, DeleteRef, and ExtendRef.
- **TransferRef**: Grants ability to transfer an object even when its `TransferRef` is frozen. Bypasses `ungated_transfer` restrictions.
- **MintRef**: Grants ability to mint FungibleAsset. Unlimited minting if held.
- **BurnRef**: Grants ability to burn FungibleAsset from any FungibleStore.
- **DeleteRef**: Grants ability to delete an object.
- **ExtendRef**: Grants ability to generate a signer for the object, enabling further resource manipulation.

## Trigger Patterns
```
ConstructorRef|TransferRef|MintRef|BurnRef|DeleteRef|ExtendRef|
object::create_named_object|object::create_sticky_object|object::create_object|
fungible_asset::generate_mint_ref|fungible_asset::generate_burn_ref|
fungible_asset::generate_transfer_ref|object::generate_delete_ref|
object::generate_extend_ref|object::generate_transfer_ref
```

## Reasoning Template

### Step 1: Reference Inventory

Enumerate ALL Ref types found in the codebase. For each:

| Ref Type | Created In (module::function) | Stored Location | Access Control | Capability Granted |
|----------|-------------------------------|-----------------|----------------|--------------------|
| ConstructorRef | {module}::{init_fn} | {consumed / stored in resource} | {who can access} | Generate all other Refs |
| MintRef | {module}::{init_fn} | {global resource at @addr} | {who can access} | Unlimited minting of {asset} |
| BurnRef | {module}::{init_fn} | {global resource at @addr} | {who can access} | Burn {asset} from any store |
| TransferRef | {module}::{init_fn} | {global resource at @addr} | {who can access} | Transfer {asset} bypassing freeze |
| DeleteRef | {module}::{init_fn} | {global resource at @addr} | {who can access} | Delete {object} |
| ExtendRef | {module}::{init_fn} | {global resource at @addr} | {who can access} | Generate signer for {object} |

**Completeness check**: Search for ALL `generate_*_ref` calls and `object::create_*` calls. Every Ref created MUST appear in the table.

### Step 2: ConstructorRef Analysis

The ConstructorRef is the root capability. It exists only during the `init_module` or object creation call.

**Check 2a: Is ConstructorRef stored?**
- Search for any struct field of type `ConstructorRef` -- this type has `drop` but NOT `store`, so it CANNOT be stored in global storage directly.
- If code attempts to extract a signer from ConstructorRef via `object::generate_signer(&constructor_ref)` and stores the signer reference indirectly, trace what that signer can do.
- **Expected pattern**: ConstructorRef is consumed during init to generate other Refs, then dropped. It should NOT persist beyond the creation transaction.

**Check 2b: What Refs are generated from it?**
- List every `generate_*_ref` call that uses this ConstructorRef
- For each generated Ref: is it stored with appropriate access control?
- **FINDING trigger**: If ConstructorRef generates MintRef AND that MintRef is stored with `public` visibility or weak access control -> unlimited minting capability leak.

**Check 2c: ExtendRef derived signer**
- If `object::generate_extend_ref` is called, the resulting ExtendRef can later produce a signer via `object::generate_signer_for_extending`
- Trace ALL uses of this derived signer -- it can move resources, modify object state, and call `move_to`/`move_from`
- **FINDING trigger**: If ExtendRef is stored with weaker access control than the operations its signer can perform.

### Step 3: MintRef / BurnRef Analysis

**Check 3a: Storage access control**
- Where is MintRef stored? (must be in a resource at a controlled address)
- Who can call functions that borrow the MintRef? (check `acquires` and signer requirements)
- Is there any `public fun` that exposes MintRef via return value or mutable reference?
- **FINDING trigger**: `public fun` returning `&MintRef` or `&mut MintRef` = capability leak to any module.

**Check 3b: Mint amount validation**
- Does the minting function validate the amount? (cap, rate limit, per-epoch limit)
- Is there a supply cap enforced? (`fungible_asset::supply` check before mint)
- **FINDING trigger**: Unlimited minting with no cap = inflation vulnerability.

**Check 3c: BurnRef scope**
- `fungible_asset::burn_from` with a BurnRef can burn tokens from ANY FungibleStore
- Check: does the burn function require the store owner's authorization, or only the BurnRef?
- **FINDING trigger**: If BurnRef holder can burn from arbitrary user stores without authorization.

**Check 3d: Mint/Burn symmetry**
- If protocol has both MintRef and BurnRef: are they held by the same entity?
- Can one be used without the other? (mint without ability to burn = permanent inflation; burn without mint = permanent deflation)
- Are there economic invariants that depend on mint/burn balance?

### Step 4: TransferRef Analysis

**Check 4a: Freeze bypass**
- `fungible_asset::transfer_with_ref` bypasses frozen store checks
- If the protocol uses `fungible_asset::set_frozen_flag` for compliance/security: does a stored TransferRef undermine the freeze?
- **FINDING trigger**: TransferRef stored alongside freeze functionality = freeze can always be bypassed by TransferRef holder.

**Check 4b: Transfer direction**
- Can TransferRef be used to transfer FROM any store (withdrawal) or only TO (deposit)?
- `fungible_asset::transfer_with_ref` takes `from: Object<FungibleStore>` and `to: Object<FungibleStore>` -- the holder controls BOTH ends
- **FINDING trigger**: TransferRef holder can drain any FungibleStore of the associated asset.

**Check 4c: Who holds TransferRef?**
- If protocol stores TransferRef: who can invoke the transfer function?
- Is there a path where an external caller (not admin) can trigger a TransferRef-backed transfer?
- Trace all call paths from `public entry fun` to the `transfer_with_ref` invocation.

### Step 5: DeleteRef Analysis

**Check 5a: Resource cleanup before deletion**
- If `object::delete(delete_ref)` is called, what happens to resources stored at the object address?
- Move does NOT automatically clean up resources when an object is deleted -- resources become orphaned
- **FINDING trigger**: Object deletion without prior `move_from` of all resources = stranded assets (Rule 9: minimum MEDIUM).

**Check 5b: Deletion authorization**
- Who holds the DeleteRef? Can they delete an object that other users depend on?
- Is there a dependency check before deletion? (e.g., are there outstanding balances, active positions?)
- **FINDING trigger**: DeleteRef holder can delete a shared object (LP pool, vault) = griefing or fund loss.

### Step 6: Ref Leakage Path Analysis

**Check 6a: Public function returns**
- Search for ANY `public fun` or `public(friend) fun` that returns a Ref type
- Even `&MintRef` (immutable reference) leak is dangerous because it can be passed to `fungible_asset::mint` within the same transaction
- **Leakage severity**: `public fun` returning Ref = Critical leak (any module can use). `public(friend) fun` returning Ref = Medium leak (friend modules can use -- check friend list).

**Check 6b: Friend module exposure**
- List all `friend` declarations in modules that store Refs
- For each friend module: does it re-export the Ref or expose a `public fun` that uses the Ref without additional access control?
- **Transitive leak**: Module A stores MintRef, Module B is friend of A and gets MintRef access, Module B has `public fun` that calls Module A's mint function = any module can mint via Module B.

**Check 6c: Store ability check**
- Refs with `store` ability can be placed in arbitrary global storage locations
- Check: do any Ref types in the protocol have `store`? (standard Aptos Refs: ConstructorRef has `drop` only; MintRef/BurnRef/TransferRef/DeleteRef/ExtendRef have `drop` and `store`)
- **FINDING trigger**: Ref with `store` ability placed in a resource with weak access control = Ref can migrate to uncontrolled storage.

### Step 7: Ref Revocation Assessment

**Critical fact**: Aptos Refs CANNOT be revoked once created. There is no `revoke_mint_ref` function in the framework.

**Check 7a: Maximum blast radius**
- For each stored Ref: what is the maximum damage if the Ref holder is compromised?
- Document: if MintRef is compromised -> unlimited inflation. If TransferRef is compromised -> drain all stores. If ExtendRef is compromised -> arbitrary object state modification.

**Check 7b: Compensating controls**
- Since Refs cannot be revoked, does the protocol have compensating controls?
  - Pause mechanism that blocks functions using the Ref?
  - Multi-signer requirement before Ref-backed operations?
  - Rate limiting on Ref-backed operations?
- **FINDING trigger**: No compensating controls on a stored Ref with high blast radius = single point of failure.

**Check 7c: Module upgrade path**
- If the module is upgradeable (`compatible` or `immutable` policy?): can an upgrade change who accesses the Ref?
- If the module is immutable: the Ref access pattern is permanent -- any vulnerability is permanent.

### Step 8: Cross-Ref Interaction

**Check 8a: Ref combination attacks**
- Can MintRef + TransferRef be combined? (Mint tokens, then force-transfer them to a target store)
- Can BurnRef + TransferRef be combined? (Transfer tokens from victim store, then burn the evidence)
- Can ExtendRef + any other Ref be combined? (Generate signer to bypass access control, then use Ref)

**Check 8b: Ref holder alignment**
- Are all Refs held by the same entity? If different entities hold different Refs, model adversarial interaction.
- Example: Admin holds MintRef, Operator holds TransferRef. If Operator is compromised, they can drain stores. Admin cannot revoke TransferRef.

---

## Finding Template

```markdown
## Finding [{PREFIX}-N]: {Title}

**Verdict**: CONFIRMED / PARTIAL / REFUTED / CONTESTED
**Step Execution**: {see checklist below}
**Ref Type**: {ConstructorRef / MintRef / BurnRef / TransferRef / DeleteRef / ExtendRef}
**Severity**: {Critical/High/Medium/Low/Info}
**Location**: {SourceFile:LineN}
**Description**: {What capability is exposed and how}
**Impact**: {What an attacker/compromised entity can do with the Ref}
**Evidence**: {Code showing Ref creation, storage, and access path}

### Blast Radius
- **If compromised**: {Maximum damage description}
- **Revocable**: NO (Aptos Refs are permanent)
- **Compensating controls**: {pause/multisig/rate-limit or NONE}
```

---

## Step Execution Checklist (MANDATORY)

| Step | Required | Completed? | Notes |
|------|----------|------------|-------|
| 1. Reference Inventory | YES | Y/N/? | Must enumerate ALL Refs |
| 2. ConstructorRef Analysis | YES | Y/N/? | |
| 3. MintRef/BurnRef Analysis | IF present | Y/N(none)/? | |
| 4. TransferRef Analysis | IF present | Y/N(none)/? | |
| 5. DeleteRef Analysis | IF present | Y/N(none)/? | |
| 6. Ref Leakage Path Analysis | YES | Y/N/? | Check public returns + friends |
| 7. Ref Revocation Assessment | YES | Y/N/? | Always: Refs are permanent |
| 8. Cross-Ref Interaction | IF 2+ Ref types | Y/N(single)/? | |

### Output Format for Step Execution

```markdown
**Step Execution**: check1,2,3,4,6,7,8 | x5(no DeleteRef)
```

OR if incomplete:

```markdown
**Step Execution**: check1,2,3 | ?4,6,7(TransferRef not fully traced)
**FLAG**: Incomplete analysis -- requires depth review (leakage paths not exhausted)
```

## Instantiation Parameters
```
{CONTRACTS}           -- Move modules to analyze
{ASSET_NAME}          -- Primary fungible asset name
{REF_STORAGE}         -- Where Refs are stored (resource name and address)
{ACCESS_CONTROL}      -- Who can access stored Refs (signer requirements)
{FRIEND_MODULES}      -- Modules declared as friends
{FREEZE_USED}         -- Whether protocol uses freeze functionality (YES/NO)
{UPGRADE_POLICY}      -- Module upgrade policy (compatible/immutable)
```

## Output Schema
| Field | Required | Description |
|-------|----------|-------------|
| ref_inventory | yes | Complete table of all Refs in codebase |
| constructor_ref_analysis | yes | ConstructorRef lifecycle and consumption |
| mint_burn_analysis | if present | MintRef/BurnRef storage and access control |
| transfer_ref_analysis | if present | TransferRef and freeze bypass potential |
| delete_ref_analysis | if present | DeleteRef and resource cleanup |
| leakage_paths | yes | Public/friend exposure of Refs |
| revocation_assessment | yes | Blast radius and compensating controls |
| cross_ref_interactions | if 2+ types | Combined Ref attack scenarios |
| finding | yes | CONFIRMED / REFUTED / CONTESTED / NEEDS_DEPTH |
| evidence | yes | Code locations with line numbers |
| step_execution | yes | Status for each step |
