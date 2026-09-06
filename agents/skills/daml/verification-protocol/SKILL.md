---
name: "verification-protocol"
description: "Trigger Pattern Always (used by all verifier agents) - Inject Into security-verifier agents (Phase 5)"
---

# VERIFICATION_PROTOCOL Skill (DAML)

> **Trigger Pattern**: Always (used by all verifier agents)
> **Inject Into**: security-verifier agents (Phase 5)
> **Purpose**: Prove hypotheses TRUE or FALSE using `daml test` over `Script ()` functions on the in-memory ledger, with `submit`/`submitMustFail`/`query@T` as the harm oracles.

---

## Evidence Source Tracking (MANDATORY)

> **CRITICAL**: For EVERY piece of evidence, tag its source. Evidence from mocks, documentation, or unverified external packages CANNOT support a REFUTED verdict. There is no public Canton read RPC, so production-onchain tags do not exist for DAML — `[CODE]` (in-scope source) plus an executed `daml test` is the strongest evidence available.

| Tag | Meaning | Valid for REFUTED? |
|-----|---------|-------------------|
| `[CODE]` | Audited codebase (in-scope `.daml` source) + executed `daml test` | YES |
| `[POC-PASS]` | A `Script ()` compiled, `daml test` ran, harm assertion PASSED | YES (CONFIRM) |
| `[POC-FAIL]` | A `Script ()` compiled and ran, but the encoded harm assertion was not established | NO — proposal/review evidence only; it MUST NOT lower severity or authorize a candidate-wide refutation |
| `[CODE-TRACE]` | Manual trace with concrete party/contract values, no execution | NO (caps at CONTESTED) |
| `[MOCK]` | Helper template / test-only state that does not exist in the audited templates | **NO** |
| `[DOC]` | Documentation / spec only | **NO** |

The driver may project `[POC-FAIL]` into `poc_demotion_proposals` for independent
review. That projection has no verdict, severity, exclusion, or merge authority.

### Evidence Audit Table (REQUIRED in every verification output)

```markdown
### Evidence Audit
| Claim | Evidence Source | Tag | Valid for REFUTED? |
|-------|-----------------|-----|-------------------|
```

### Mock Rejection Rule

If ANY evidence supporting REFUTED has tag `[MOCK]` or `[DOC]`: CANNOT return REFUTED, MUST return CONTESTED, triggers a re-PoC against the actual in-scope templates.

---

## Pre-Verification Understanding

Before writing ANY Script code, answer these three questions:

1. **What is the EXACT bug?** — Not "Authorization is missing" but "Choice `Iou.Transfer` lists only `owner` as `controller` and never re-asserts the `issuer`/co-signatory, so any single owner can move the asset without the joint authorization the template otherwise requires (Iou.daml:line N, template Iou, choice Transfer)".
2. **What OBSERVABLE difference proves it?** — Concrete before/after ACS state: which party holds which contract, what `query@T party` returns, what amount each child carries.
3. **What is the EXACT assertion?** — e.g., `submit attacker (exerciseCmd cid Transfer with newOwner = attacker)` SUCCEEDS and then `query @Iou victim` returns `[]` while `query @Iou attacker` is non-empty; or `submitMustFail attacker (...)` proves the guard holds (REFUTES).

**If you cannot answer all three → ASK FOR CLARIFICATION.**

---

## Pre-PoC Feasibility Gates (MANDATORY)

### Gate F1: Reachability
- [ ] Entry point identified (a `choice` exercisable by the attacker party, or a `create` the attacker can submit)
- [ ] Required authorizers traced: the choice's `controller` parties (AND-joined) and, for `create`, the new contract's `signatory` parties
- [ ] All required authorizers are parties the attacker profile actually controls or can obtain

If the choice's controllers / the contract's signatories include a party the attacker cannot supply → UNREACHABLE → FALSE_POSITIVE.
If reachable only by a fully-trusted operator party acting maliciously → document trust assumption, adjust likelihood.

### Gate F2: Value / Boundary Bounds
- [ ] Parameter domains identified (amount type `Int`/`Decimal`, list lengths, deadline range, cap)
- [ ] Expression evaluated at worst-case feasible inputs (0, 1, negative, max, empty list)
- [ ] Result crosses the bug threshold (invalid contract creatable, conservation violated, reachable abort, outsider query non-empty)

If values outside feasible domains → INFEASIBLE → FALSE_POSITIVE.

**Both gates PASS → proceed to PoC. Either gate FAILS → document and stop.**

---

## DAML Anti-Hallucination Rules (MANDATORY)

Verify EVERY API call against these known-correct patterns. Do NOT assume EVM/Solana/Rust shapes apply.

```haskell
-- Party allocation
attacker <- allocateParty "Attacker"          -- NOT: newParty, Address::generate
[a, b]   <- mapA allocateParty ["A", "B"]

-- Create / Exercise / ExerciseByKey
cid  <- submit issuer  (createCmd Iou with issuer; owner; amount)
cid' <- submit owner   (exerciseCmd cid Transfer with newOwner = bob)
res  <- submit p        (exerciseByKeyCmd @Account (issuer, label) Some_Choice with ...)

-- Negative test (the cmd is EXPECTED to FAIL)
submitMustFail attacker (exerciseCmd cid Transfer with newOwner = attacker)
-- ^ a PASSING submitMustFail means the action was BLOCKED → proves SAFETY → REFUTES the bug.

-- Party-scoped visibility oracle (the privacy harm oracle)
cids <- query @Iou outsider          -- what `outsider` can actually SEE; NEVER a god-view
mb   <- queryContractId owner cid     -- Some payload if `owner` is a stakeholder, None if not visible

-- Time control (deadline PoCs) — requires Daml.Script with time control
setTime (time (date 2024 Jan 1) 0 0 0)
passTime (days 8)
now <- getTime

-- Multi-command submit
submit p $ do
  c1 <- createCmd T1 with ...
  exerciseCmd c1 SomeChoice with ...
```

**Authorization model facts (the spine of every DAML auth/asset PoC):**
1. **Controller vs signatory**: the required authorizers of an `Exercise`/`Fetch` are the choice's listed `controller` parties (AND-joined); the required authorizers of a `Create`/`Archive` are the new/old contract's `signatory` parties. `submit p cmd` supplies authority for party `p` only.
2. **Consuming kind**: a `consuming` (default) choice ARCHIVES the contract on first exercise — a 2nd `exerciseCmd` on the same `ContractId` MUST fail with CONTRACT_NOT_FOUND. That failure REFUTES a double-spend claim; a SUCCEEDING second exercise on a wrongly-`nonconsuming` value-mover CONFIRMS double-spend.
3. **`ensure` violation** throws `PreconditionFailed`: a `create` whose `ensure` is `False` never enters the ACS.
4. **Keys**: maintainers MUST be signatories. `lookupByKey` returning `None` means "the submitter cannot SEE a contract with that key" (visibility), NOT "no such contract exists" — a false-None PoC must allocate a party that genuinely cannot see the keyed contract, then show the None branch mints/duplicates state.
5. **`submitMustFail` semantics**: `submitMustFail p cmd` PASSES when `cmd` FAILS. So the CONFIRM direction for an auth bug is `submit attacker (...)` SUCCEEDING plus a harm assertion; a passing `submitMustFail` proves SAFETY (REFUTES). State this explicitly whenever a `submitMustFail` is the deciding test.
6. **`query@T party` is the privacy harm oracle** — it returns only what `party` is a stakeholder of. Never assert against a god-view; an outsider seeing a contract = `not (null (query @T outsider))`.
7. **Divulgence vs observer**: `fetch` inside a shared transaction divulges a contract incidentally (transient, only to that transaction's witnesses), whereas `observer` is persistent visibility. A privacy finding must distinguish which mechanism is the leak.

---

## DAML PoC Script Templates

Every PoC is a top-level `Script ()`. `daml test` runs every in-scope `Script ()`; isolation is file-scoped (one PoC file per finding: `daml-test/PoC_{id}.daml`).

### Template 1: Missing / Single-Where-Joint Authorization

```haskell
-- AUTHORIZATION: buggy direction — attacker succeeds + harm assertion
test_single_where_joint_auth : Script ()
test_single_where_joint_auth = do
  issuer   <- allocateParty "Issuer"
  owner    <- allocateParty "Owner"
  attacker <- allocateParty "Attacker"
  cid <- submit issuer do createCmd Asset with issuer; owner; amount = 100.0
  -- EXPLOIT: the choice lists only `owner` as controller; no co-auth from issuer
  submit owner do exerciseCmd cid Transfer with newOwner = attacker
  -- HARM: ownership moved without the joint authorization the template implies
  victimCids   <- query @Asset owner
  attackerCids <- query @Asset attacker
  assert (null victimCids)
  assert (not (null attackerCids))

-- REFUTATION direction: if co-auth IS required, this proves SAFETY
test_auth_is_enforced : Script ()
test_auth_is_enforced = do
  issuer <- allocateParty "Issuer"; owner <- allocateParty "Owner"; attacker <- allocateParty "Attacker"
  cid <- submit issuer do createCmd Asset with issuer; owner; amount = 100.0
  submitMustFail owner do exerciseCmd cid Transfer with newOwner = attacker
  -- PASSING submitMustFail ⇒ guard holds ⇒ REFUTES the bug.
```

### Template 2: Double-Exercise via Wrong Consume-Mode

```haskell
test_double_spend_nonconsuming : Script ()
test_double_spend_nonconsuming = do
  issuer <- allocateParty "Issuer"; owner <- allocateParty "Owner"
  cid <- submit issuer do createCmd Iou with issuer; owner; amount = 100.0
  -- If Spend is wrongly `nonconsuming`, the SAME cid can be exercised twice
  submit owner do exerciseCmd cid Spend with to = issuer
  submit owner do exerciseCmd cid Spend with to = issuer   -- succeeds ⇒ double-spend CONFIRMED
  -- (If Spend is correctly `consuming`, the 2nd exercise fails CONTRACT_NOT_FOUND ⇒ REFUTED)
```

### Template 3: Value Conservation Across Split / Merge

```haskell
test_value_conservation_split : Script ()
test_value_conservation_split = do
  issuer <- allocateParty "Issuer"; owner <- allocateParty "Owner"
  cid <- submit issuer do createCmd Iou with issuer; owner; amount = 100.0
  (c1, c2) <- submit owner do exerciseCmd cid Split with splitAmount = 30.0
  Some a1 <- queryContractId owner c1
  Some a2 <- queryContractId owner c2
  -- HARM: children must sum to the parent — a mint/burn breaks conservation
  assert (a1.amount + a2.amount == 100.0)
```

### Template 4: lookupByKey False-None (visibility ≠ absence)

```haskell
test_lookup_false_none_duplicate : Script ()
test_lookup_false_none_duplicate = do
  issuer <- allocateParty "Issuer"; outsider <- allocateParty "Outsider"
  -- A keyed contract exists but `outsider` is NOT a stakeholder, so cannot see it
  _ <- submit issuer do createCmd Registered with issuer; label = "x"
  -- A choice controlled by `outsider` that does `lookupByKey` will get None (not visible)
  -- and (buggily) treats None as "absent" → mints a duplicate keyed contract
  submit outsider do createAndExerciseCmd (Registrar with p = outsider) (Register with label = "x")
  -- HARM: two contracts now share the same key (uniqueness invariant broken)
```

### Template 5: CID-Capability — Lookalike / Fail-Open / Stale-Brick

```haskell
test_caller_cid_not_bound : Script ()
test_caller_cid_not_bound = do
  issuer <- allocateParty "Issuer"; attacker <- allocateParty "Attacker"
  good <- submit issuer do createCmd Config with issuer; allowed = True
  evil <- submit attacker do createCmd Config with issuer = attacker; allowed = True
  -- EXPLOIT: choice accepts a caller-supplied `cfg : ContractId Config` and does not
  -- bind it to the trusted issuer → attacker passes their own lookalike config
  op <- submit issuer do createCmd Op with issuer
  submit attacker do exerciseCmd op Run with cfg = evil   -- succeeds with forged capability ⇒ CONFIRMED
```

### Template 6: Privacy / Disclosure (party-scoped query oracle)

```haskell
test_observer_over_broad : Script ()
test_observer_over_broad = do
  issuer <- allocateParty "Issuer"; owner <- allocateParty "Owner"
  outsider <- allocateParty "Outsider"
  _ <- submit issuer do createCmd Position with issuer; owner; secret = 42
  -- HARM: an outsider who should NOT be a stakeholder can nonetheless see the contract
  cids <- query @Position outsider
  assert (not (null cids))   -- non-empty ⇒ over-broad observer / disclosure CONFIRMED
```

### Template 7: Boundary-Value Scripts (no fuzzer / SAST fallback, Aptos-style)

```haskell
-- ensure-gap, arithmetic abort, or deadline boundary via a shared helper
runBoundary : Decimal -> Script ()
runBoundary amt = do
  issuer <- allocateParty "Issuer"
  _ <- submit issuer do createCmd Asset with issuer; owner = issuer; amount = amt
  pure ()

boundaryMin : Script ()
boundaryMin = runBoundary 0.0       -- ensure-gap: does a zero-amount contract create?

boundaryNeg : Script ()
boundaryNeg = runBoundary (-1.0)    -- ensure-gap: does a negative-amount contract create?

boundaryMax : Script ()
boundaryMax = runBoundary 9999999999999999.0  -- arithmetic abort downstream ⇒ liveness brick
```

---

## HARM vs MECHANISM (HARD GATE)

Asserting only that a choice CAN be exercised, a contract CAN be created, or a path is reachable is a **mechanism test** → `[CODE-TRACE]` at best, NOT `[POC-PASS]`. A `[POC-PASS]` requires a HARM assertion:

| Class | Required harm assertion |
|-------|------------------------|
| Authorization | ownership/contract moved to attacker without the implied co-auth (`query` shows transfer) |
| Choice/Asset | same cid exercised twice (double-spend), or `child1.amount + child2.amount /= parent.amount` (conservation), or locked contract still moved |
| CID-capability | forged/lookalike `ContractId` accepted and harmful state produced; or whitelist-absent fail-open succeeds; or stale CID ⇒ CONTRACT_NOT_FOUND brick |
| State/key | duplicate keyed contract created via false-None; or exerciseByKey succeeds where maintainer authority should block |
| Privacy | `not (null (query @T outsider))` for a party that should NOT be a stakeholder |
| Boundary | invalid contract creates (ensure-gap), OR the choice aborts (ArithmeticError, liveness brick), OR a past-deadline action SUCCEEDS |

If the harm assertion fails (correct amounts, action blocked, outsider sees nothing) → `[POC-FAIL]`.

---

## Dual-Perspective Verification (MANDATORY)

**Phase 1 — ATTACKER**: Complete submit sequence? Which party does each `submit` use? What contract/value moves? Compose multiple `exerciseCmd` in one `submit`? Which `controller`/`signatory`/`ensure` is missing or bypassable?

**Phase 2 — DEFENDER**: What `controller`/`signatory` authorization blocks this? What `ensure` precondition rejects the input? What `key`+`maintainer` uniqueness prevents the duplicate? Does `consuming` archival prevent the replay? Does `observer` scoping prevent the disclosure? Why safe by design?

**Phase 3 — VERDICT**: Which argument won? If DEFENDER relies on a defense present in one template but ABSENT in a sibling for the same action → defense parity gap → do NOT REFUTE; minimum Medium.

---

## Realistic Parameter Validation

Substitute ACTUAL template constants. Apply Rule 10: worst realistic operational state, not current snapshot.

```
State: 'With real fields [amount type=Decimal, cap=X, deadline=Y] at worst-state
[max holders, min amount, empty observer list], bug triggers when [condition]'
OR: 'With real fields, bug does NOT trigger because [reason: ensure rejects it / controller blocks it / key is unique]'
```

**DAML-specific facts**: `Int`/`Decimal` THROW on overflow (no silent wrap → liveness/brick, never silent-value) | `ensure False` ⇒ `PreconditionFailed` | a consuming choice archives once | maintainers ⊆ signatories | `query@T party` is party-scoped.

---

## Anti-Downgrade Guard (MANDATORY for VS/BLIND findings)

Apply Rule 13's 5-question test BEFORE downgrading severity or marking FALSE_POSITIVE:
1. **Who is harmed** by this design gap?
2. **Can affected parties avoid** the harm?
3. **Is the gap documented** in protocol docs?
4. **Could the protocol achieve the same goal** without this gap?
5. **Does the choice fulfill its stated purpose completely?**

**HARD RULE**: Template A has co-authorization (or an `ensure`, or an `observer` scoping) for a choice but sibling Template B lacks it for the same action → defense parity gap, NOT "by design". Minimum severity: Medium.

**Severity-modifier caveat (DAML)**: the "on-chain-only exploit → −1 tier" modifier is EVM-framed. Do NOT auto-downgrade a liveness-brick (Int/Decimal abort) or a privacy-disclosure finding with it — an outsider `query@T` leak crosses the disclosure boundary and a reachable abort is a liveness consequence.

---

## New Observations (MANDATORY)

If during verification you discover a NEW bug not covered by any hypothesis:
- [VER-NEW-1]: {title} — {Module.daml: template/choice} — {brief description}

---

## Error Trace Output (MANDATORY for CONTESTED/FALSE_POSITIVE)

- **Failure Type**: PRECONDITION_FAILED / AUTHORIZATION_ERROR / CONTRACT_NOT_FOUND / NO_SUCH_KEY / ASSERTION_FAILED / INSUFFICIENT_EVIDENCE / COMPILE_ERROR
- **Location**: {Module}.daml: {template / choice} : {approximate line}
- **Error Message**: {DAML Script error, e.g., `PreconditionFailed`, `failed to find contract`, `requires authorizers ... but only ... were given`}
- **State at Failure**: {which parties hold which contracts in the ACS}
- **Investigation Question**: {What would resolve this}

---

### Shared External Precedent Boundary

Read `~/.claude/rules/precedent-evidence-policy.md`.
Do not query vulnerability databases, WebSearch, or fresh RAG before or during
PoC adjudication. Seal the code-derived hypothesis, plan, and executed result
without historical anchoring. Centralized precedent can only create additive
test ideas in a separate post-plan phase; it is never verifier evidence and
cannot support a negative verdict, severity, proof, demotion, or report claim.

---

## Chain Hypothesis PoC Requirements

Chain hypotheses receive PRIORITY verification. Test the COMPLETE sequence in one Script: (1) execute the enabler `submit`, (2) assert the postcondition is created via `query@T`/`queryContractId` (e.g. the false-None state, the forged config in the ACS), (3) execute the previously-blocked exploit `submit`, (4) assert the combined impact exceeds either finding alone. Use standard `allocateParty` + `submit` setup.

---

## Interpreting Results

### Test PASSES (harm assertion holds) → Bug CONFIRMED

### Test FAILS → Check Why

| Failure | Meaning | Action |
|---------|---------|--------|
| `requires authorizers ... but only ... given` | Controller/signatory auth IS present | Re-examine hypothesis (likely REFUTED) |
| `PreconditionFailed` | `ensure` rejected the input | Check if the ensure IS the defense (REFUTE) or if a weaker path bypasses it |
| `failed to find contract` (CONTRACT_NOT_FOUND) | Consuming choice already archived it | A double-spend claim is REFUTED; for stale-CID a brick is CONFIRMED |
| `couldn't find key` (NO_SUCH_KEY) | Key absent or not visible | Distinguish true-absent vs false-None (visibility) |
| `submitMustFail` PASSED | The action was BLOCKED | This proves SAFETY → REFUTES the auth/bypass bug |
| Wrong amount | Conservation held / setup wrong | Verify Decimal scale and party setup |

---

## Iteration Protocol

**Attempt 1**: Direct implementation from hypothesis.
**Attempt 2**: Adjust setup (which party submits, contract field values, command ordering) — keep the SAME `exerciseCmd`/choice + SAME harm assertion + SAME location.
**Attempt 3**: Re-examine assumptions (controller vs signatory, consuming vs nonconsuming, key visibility).
**Attempt 4**: Verify choice/template signatures in source — do NOT assume EVM/Rust shapes.
**Attempt 5**: Re-read anti-hallucination rules — confirm correct DAML-Script API.
**After 5 attempts**: FALSE_POSITIVE with documented reasoning.

> **Retry guard**: changing WHICH choice is exercised or WHICH `query@T` is asserted between attempts caps the result at `[CODE-TRACE]` (it is a different test, not a setup fix).

---

## Insufficient Evidence (HALT CONDITIONS)

Before marking REFUTED, check ALL boxes:
- [ ] Required-authorizer set verified by reading the actual `controller`/`signatory` clauses (not assumed)
- [ ] Consume-mode of the choice verified (`consuming`/`nonconsuming`/`pre`/`postconsuming`) by reading source
- [ ] For key findings: `maintainer` set verified ⊆ `signatory` set; false-None tested with a genuinely non-stakeholder party
- [ ] Missing precondition documented (STATE / ACCESS / TIMING / EXTERNAL / BALANCE)
- [ ] Searched other findings for matching postconditions (chain integration)
- [ ] For privacy: harm tested with a party-scoped `query@T outsider`, not a god-view
- [ ] `ensure` clause read directly from source (not assumed present)
- [ ] External package (`data-dependencies`) behavior marked UNVERIFIED, not relied on for REFUTE

### Evidence That Does NOT Count
- "Helper template shows X" — helper templates are `[MOCK]`, not the audited templates
- "Choice is `nonconsuming`" — does not by itself bypass controller authorization
- "Attacker loses by transferring" — may profit via a position held in another template
- "Requires the operator party" — operator may be a compromised key or malicious signatory
- "Key cannot collide" — verify the actual `key`/`maintainer` and visibility scope
- "`submitMustFail` passed" — that proves SAFETY (REFUTES), it is NOT evidence the bug exists

---

## Output Format

### CONFIRMED
```markdown
## Verdict: CONFIRMED
### Bug Mechanism Verified
{2-3 sentences on what daml test proves}
### Test Code
{Full Script () using allocateParty/createCmd/exerciseCmd + harm assertion}
### Test Output
{Assertions and ACS values from `daml test --files daml-test/PoC_{id}.daml`}
### Key Evidence
| Metric | Value |
|--------|-------|
| Before / After / Expected / Difference | {which party holds which contract, amounts} |
### Evidence Audit
| Claim | Evidence Source | Tag | Valid for REFUTED? |
### Severity: {LEVEL}
{1-2 sentence justification; note liveness/privacy are NOT auto-downgraded}
### Suggested Fix
{diff block + Fix scope + Verified: YES/NO}
```

### FALSE_POSITIVE
```markdown
## Verdict: FALSE_POSITIVE
### Attempts Made
**Attempt 1-N:** Approach, Result (Failure Type / error message), Learning
### Evidence Audit
| Claim | Evidence Source | Tag | Valid for REFUTED? |
### Why It Is Not a Bug
{2-3 sentences — e.g., a passing submitMustFail proved the controller co-auth holds}
### Error Trace
{Failure Type, Location, Error Message, State at Failure, Investigation Question}
```

### CONTESTED
```markdown
## Verdict: CONTESTED
### Evidence Status
| Checkpoint | Status | Details |
|------------|--------|---------|
| Controller/signatory set verified from source | YES/NO | |
| Consume-mode verified from source | YES/NO | |
| Key maintainer ⊆ signatory verified | YES/NO | |
| Privacy harm tested via party-scoped query@T | YES/NO | |
### Evidence Audit
| Claim | Evidence Source | Tag | Valid for REFUTED? |
### Why This Cannot Be REFUTED
{What evidence is missing — e.g., external data-dependency behavior unverified}
### Escalation Required
- [ ] Read actual controller/signatory clauses for {template.choice}
- [ ] Confirm key+maintainer against source
- [ ] Test additional choice paths: {list}
### Error Trace
{as above}
```
