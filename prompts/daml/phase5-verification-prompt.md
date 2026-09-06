# Phase 5: Verification Prompt Template - DAML (Canton)

> **Usage**: Orchestrator reads this file and spawns verification agents for DAML/Canton contract audits.
> Replace placeholders `{SCRATCHPAD}`, `{HYPOTHESIS_ID}`, `{LOCATION}`, etc. with actual values.

---

## Verification Order

1. ALL chain hypotheses (regardless of original severity)
2. HIGH/CRITICAL standalone hypotheses
3. **ALL MEDIUM standalone hypotheses (MANDATORY)**

> Empirical testing showed 44% false positive rate on unverified Mediums. Medium verification is mandatory for report precision.

## Model Selection

| Verification Target | Model | Rationale |
|---------------------|-------|-----------|
| Chain hypotheses | opus | Complex multi-step attack sequences need deep reasoning |
| HIGH/CRITICAL standalone | opus | Highest-impact findings need highest-quality verification |
| **MEDIUM standalone** | **sonnet** | PoC generation for Medium findings is pattern-matching (code trace + boundary check), not deep architectural reasoning. Sonnet handles this well at lower cost. |

The orchestrator passes the model parameter when spawning security-verifier agents. All verifiers use the same prompt template below regardless of model.

## Verifier Agent

```
Task(subagent_type="security-verifier", prompt="
Verify hypothesis: {HYPOTHESIS_ID}

Location: {LOCATION}
Claim: {IF/THEN/BECAUSE statement}

Read:
- {SCRATCHPAD}/design_context.md
- ~/.claude/agents/skills/daml/verification-protocol/SKILL.md (if it exists)
- ~/.claude/rules/phase5-poc-execution.md

## PRECISION MODE
You are in PRECISION mode. Your job is to VALIDATE or REFUTE hypotheses with maximum rigor. Unlike discovery agents who err on the side of reporting, you err on the side of ACCURACY. Every claim must be backed by exact line numbers, concrete party/contract values, and verifiable code traces. If you cannot prove exploitation with specific values, say so clearly. A false positive (confirming a non-bug) wastes remediation effort and undermines audit credibility.

## DUAL-PERSPECTIVE VERIFICATION (MANDATORY)

Phase 1 - ATTACKER: Assume you ARE the attacker party.
- What's your complete attack sequence (which choices, exercised by which party, in what order)?
- What's the profit/damage with real numbers (contracts/assets gained, parties disclosed to)?
- Why would this succeed?

Phase 2 - DEFENDER: Assume you're the contract team.
- What mechanism prevents this? Consider DAML's defense primitives: signatory/controller authorization, `ensure` precondition, key+maintainer uniqueness, consuming archival, observer scoping.
- What assumption is wrong?
- Why is this safe by design?

Phase 3 - VERDICT: Which argument won?

## ANTI-DOWNGRADE GUARD (MANDATORY for VS/BLIND findings)

When verifying a finding originally from the Validation Sweep ([VS-*]) or Blind Spot Scanner
([BLIND-*]), you MUST apply Rule 13's 5-question test BEFORE downgrading severity or
marking FALSE_POSITIVE:

1. **Who is harmed** by this design gap?
2. **Can affected parties avoid** the harm?
3. **Is the gap documented** in contract docs?
4. **Could the contract achieve the same goal** without this gap?
5. **Does the choice fulfill its stated purpose completely?**

**HARD RULE**: If the finding shows Template A has co-authorization (multi-controller / multi-signatory)
for a choice but Template B lacks it for the same party action → this is a defense parity gap, NOT
'by design'. Minimum severity: Medium.

You may NOT dismiss a defense parity gap as 'Informational' or 'design note'.

## CLASS-CHECK BEFORE FALSE_POSITIVE

Before marking ANY finding FALSE_POSITIVE, check: does the same code location have other exploitable instances of the same vulnerability CLASS? If the specific scenario is unreachable but a variant at the same location is valid, downgrade the original scenario but report the valid variant.

## MANDATORY PoC EXECUTION

Follow `phase5-poc-execution.md`. Build and run every PoC - a written Script with no execution output is not evidence.

**DAML commands**:
- Build: `daml build` (produces `.dar` under `.daml/dist/`)
- Run tests (PRIMARY): `daml test --files daml-test/PoC_{id}.daml` — runs every `Script ()` defined in the named file on an in-memory ledger, no external process. `daml test` has NO per-test name filter; isolation is file-scoped, so write the PoC for {HYPOTHESIS_ID} into its own `daml-test/PoC_{id}.daml`.
- Optional named-against-sandbox: `daml script --dar .daml/dist/*.dar --script-name {Module}:{fn} --ledger-host localhost --ledger-port 6865` (requires a running `daml sandbox`/`daml start`; treat as OPTIONAL — the in-memory `daml test` path is authoritative).
- Fuzz: there is NO native fuzzer and NO security SAST for DAML. The boundary-value fallback is Aptos-style parameterized `Script ()` functions (min / mid / max / empty-list) calling a shared helper. See PoC framework section below.

### PoC Attempt Ledger (MANDATORY)

Every verifier output for this finding MUST include this ledger BEFORE
the evidence tag is finalized. Source-of-truth schema:
`rules/phase5-poc-execution.md` § \"PoC Testability Ledger\".

```markdown
### PoC Attempt
- PoC Required: YES/NO
- PoC Class: <unit|property|integration|structural>
- Attempted: YES/NO
- PoC Not Attempted Because: <NO_BUILD_ENVIRONMENT|N/A>
- Test File: <path or N/A>
- Command: <command or N/A>
```

`unit` and `property` rows require a real executable attempt when a
build/test harness exists. \"no Script written\" with `[CODE-TRACE]`
fallback is INVALID unless the ledger names an environmental blocker.
For DAML the default legitimate no-attempt reason is `NO_BUILD_ENVIRONMENT`:
once `daml build` succeeds, `daml test` is always available (single-participant,
in-memory ledger, no fork or live address needed) for single-participant
claims, so the external-dependency / live-deployment / spec-only / structural
skip reasons rarely apply. See the Force-by-Default block below for the
narrow, code-grounded exceptions.

### Force-by-Default Skip Justification (MANDATORY)

`STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION` is NOT a valid skip for a finding
with a concrete Material Harm (a locked/lost asset, an unauthorized
archive/exercise, a controller/signatory privilege escalation, an
`ensure`-gap that lets an invalid contract become creatable, or a liveness
brick that denies a party its only path to a choice). The default is to
FORCE the `daml test` Script proof. A skip requires citing a SPECIFIC
blocker from the closed taxonomy in `~/.claude/rules/phase5-poc-execution.md`
§ "Force-by-Default Skip Justification" — `FULLY_TRUSTED_DESIGN`,
`DEPLOY_OR_TX_ORDERING`, `EXTERNAL_DEP_NO_FORK`, `LIVE_ARTIFACT_REQUIRED`,
`SPEC_DOCS_NO_STATE_DELTA`, or a `REFUTED` verdict — with a code-grounded
justification (name the fully-trusted signatory/controller and the absent
counter-authorization, the cross-`submit` transaction-ordering race, the
out-of-scope external/cross-domain participant, the separately-deployed
DAR/sandbox artifact, or the absent contract-state delta). A forced attempt
that genuinely cannot assert the harm records `[CODE-TRACE]` plus the named
blocker, NOT `[POC-FAIL]` — `[POC-FAIL]` is reserved for a harm-asserting
Script that ran and the claimed harm did not reproduce.

**`daml test`'s in-memory ledger is not, by itself, a valid
`EXTERNAL_DEP_NO_FORK` / `LIVE_ARTIFACT_REQUIRED` excuse.** Once `daml build`
succeeds, `daml test` runs a single default participant with no external
process: party allocation (`allocateParty`), time advance (`passTime`), and
multi-choice/multi-party sequences are all directly testable, so a bare
\"cannot model this\" claim is INVALID for single-participant harm. Those two
blockers remain available ONLY for a claim whose harm genuinely depends on
multi-participant / cross-domain Canton topology (for example a
disclosed-contract or divulgence claim that requires a second participant
node) that a single-participant `daml test` Script cannot model — name the
specific cross-participant mechanism when citing either blocker.

## ANTI-HALLUCINATION RULES

1. You MUST read the actual source files BEFORE writing any Script or analysis. Do NOT guess choice names, parameter types, controller expressions, or field types.
2. You MUST extract real constants from the templates (fee rates, thresholds, caps, deadlines, amount bounds) and use those in your PoC. Never invent convenient values.
3. If a choice signature differs from what you expected, use the ACTUAL signature from the source code.
4. When tracing choice logic, verify the DIRECTION of comparisons (>=, <=, >, <) inside `ensure` clauses and guards. A `>=` in an `ensure` (must-hold) has the opposite meaning from a `>=` in an abort guard.
5. Before claiming a `(Template, field)` is 'not updated' by a choice, grep for ALL choices whose consequences `create`/`archive` that template across the entire codebase. The field may change indirectly via a choice that exercises another template's choice (authority one hop).
6. If you cannot build or run a Script after 5 attempts, provide a MANUAL CODE TRACE with exact line numbers and concrete (party, contract, field) transitions. Tag as `[CODE-TRACE]` and set verdict to CONTESTED (not CONFIRMED). A code trace with real values is better than a hallucinated test, but it is NOT mechanical proof.

## DAML ANTI-HALLUCINATION RULES (CRITICAL)

These rules prevent the most common DAML-specific PoC misreads. A PoC that
misinterprets `submitMustFail` or consuming archival will report the OPPOSITE
verdict from ground truth.

1. **Controller vs signatory**: the required authorizers of an `Exercise` node are the listed `controller` parties, AND-joined (every controller party must authorize). The required authorizers of `Create`/`Archive` are the template `signatory` parties. Authority propagates exactly ONE hop into a choice's consequences. Read the `controller`/`signatory` clauses at {LOCATION} before asserting who can do what.
2. **Consuming kind**: a `consuming` choice (the default) ARCHIVES the contract on its first exercise. Therefore a second `exerciseCmd` on the SAME `ContractId` MUST fail with `CONTRACT_NOT_FOUND`. If your double-spend claim requires exercising a consuming choice twice on one CID, that failure REFUTES the claim. A double-spend is only real on a `nonconsuming` choice (or via a fresh CID), so confirm the consume-mode in source first.
3. **`ensure` violation**: a `create` whose `ensure` clause evaluates `False` throws `PreconditionFailed`. To prove an ensure-GAP (an invalid contract IS creatable), you must show `submit ... createCmd` SUCCEEDS for a value that should have been rejected; to prove an ensure HOLDS, `submitMustFail ... createCmd` passes.
4. **Keys & maintainers**: `maintainer` parties MUST be a subset of `signatory` parties (the compiler enforces this, but a finding may concern a key whose maintainer set is wrong by design). `lookupByKey k` returning `None` does NOT mean \"no such contract exists\" — it means \"the contract is not visible to the parties authorizing this lookup\" (visibility), and the lookup must be authorized by all maintainers. A FALSE-NONE PoC MUST `allocateParty` a party that genuinely cannot see the keyed contract, then show the choice taking the `None` branch (e.g. minting fresh duplicate state) — NOT a party that simply hasn't created it yet.
5. **`submitMustFail` semantics**: `submitMustFail p cmd` PASSES when `cmd` FAILS. Therefore a passing `submitMustFail` proves SAFETY and REFUTES an authorization/bypass claim. The CONFIRM direction for an auth bug is `submit attacker cmd` SUCCEEDING followed by a HARM assertion on resulting state — NOT a passing `submitMustFail`. State this explicitly whenever you use `submitMustFail`.
6. **`query@T party` is the privacy harm oracle**: `query @T party` returns ONLY the contracts of template `T` that `party` is a stakeholder of (signatory or observer) or has had divulged. It is NEVER a god-view. A privacy/disclosure finding is CONFIRMED only when `query @T outsider` returns a NON-EMPTY result for a party who should not see the contract.
7. **Divulgence vs observer**: `fetch` inside a shared transaction divulges a contract INCIDENTALLY and TRANSIENTLY (the divulgee sees it only because it appeared in a transaction they were party to). `observer` is PERSISTENT disclosure (the observer can `query` the contract for its whole life). Distinguish these: a divulgence finding's PoC queries AFTER the divulging transaction; an over-broad-observer finding's PoC queries at any later point.

## REALISTIC PARAMETER VALIDATION
Substitute ACTUAL template constants (fee rates, thresholds, caps, deadlines, amount bounds).
Apply Rule 10: Use worst realistic operational state, not current snapshot.
State: 'With real constants [values] at worst-state [params], bug triggers when [condition]'
OR: 'With real constants [values] at worst-state [params], bug does NOT trigger because [reason]'

## PROTOCOL-LEVEL CONTEXT
Consider:
- Value at risk: what's the maximum extractable contract/asset value?
- Repeatability: once or continuous (e.g. a nonconsuming choice re-exercisable indefinitely)?
- Party population: one party or all parties of a role?
- Disclosure scope: stakeholders (signatories + observers) vs divulgees — a contract leaking to a divulgee mid-transaction is a distinct attack class from a persistently over-broad observer set.

## DAML PoC FRAMEWORK (DAML-Script)

Every PoC is a top-level `Script ()` function in a `.daml` file under `daml-test/`. `daml test --files daml-test/PoC_{id}.daml` runs every Script in that file on an in-memory ledger. The PoC MUST end in a HARM assertion via `queryContractId`/`query @T`, not merely a successful exercise.

### Basic Script Structure

```daml
module PoC_{id} where

import Daml.Script

-- Import the templates under test
-- import MyModule

test_exploit : Script ()
test_exploit = do
  -- 1. SETUP: allocate parties
  issuer   <- allocateParty \"Issuer\"
  attacker <- allocateParty \"Attacker\"
  victim   <- allocateParty \"Victim\"

  -- 2. SETUP: create the contract(s) under test with REAL constants from source
  cid <- submit issuer do
    createCmd MyTemplate with
      owner = victim
      issuer = issuer
      amount = 100  -- use the actual field names/types from source

  -- 3. ATTACK: attacker exercises the choice that should be denied
  -- 4. HARM ASSERTION: prove a party gained/lost a contract or value, or an
  --    action that should fail succeeded.
  pure ()
```

### Authorization PoC (CONFIRM vs REFUTE)

```daml
-- CONFIRM (bug exists): attacker can exercise a choice they should not.
-- `submit attacker` SUCCEEDS, then assert harmful state.
test_missing_auth_confirm : Script ()
test_missing_auth_confirm = do
  issuer   <- allocateParty \"Issuer\"
  attacker <- allocateParty \"Attacker\"
  cid <- submit issuer do createCmd Asset with owner = issuer, ..

  -- attacker exercises a transfer/privileged choice WITHOUT issuer/owner co-auth
  newCid <- submit attacker do exerciseCmd cid Transfer with newOwner = attacker

  -- HARM: attacker now owns the asset
  Some asset <- queryContractId attacker newCid
  assert (asset.owner == attacker)  -- BUG CONFIRMED: ownership moved without authority

-- REFUTE (safe): the same exercise MUST fail. A passing submitMustFail proves SAFETY.
test_missing_auth_refute : Script ()
test_missing_auth_refute = do
  issuer   <- allocateParty \"Issuer\"
  attacker <- allocateParty \"Attacker\"
  cid <- submit issuer do createCmd Asset with owner = issuer, ..
  -- If this PASSES, the auth bug is REFUTED (the action is correctly blocked).
  submitMustFail attacker do exerciseCmd cid Transfer with newOwner = attacker
```

### Choice / Asset-Semantics PoC

```daml
-- Double-spend via wrongly-nonconsuming choice: exercise the SAME cid twice.
-- (If the choice is `consuming`, the 2nd exercise fails CONTRACT_NOT_FOUND and REFUTES.)
test_double_spend : Script ()
test_double_spend = do
  owner <- allocateParty \"Owner\"
  cid <- submit owner do createCmd Iou with owner, amount = 100
  _ <- submit owner do exerciseCmd cid Redeem with qty = 100
  -- HARM: a second redeem succeeds on the same contract → value drained twice
  _ <- submit owner do exerciseCmd cid Redeem with qty = 100
  pure ()

-- Value conservation across split/merge/transfer: out1 + out2 == in.
test_conservation : Script ()
test_conservation = do
  owner <- allocateParty \"Owner\"
  cid <- submit owner do createCmd Iou with owner, amount = 100
  (a, b) <- submit owner do exerciseCmd cid Split with splitAmount = 30
  Some ia <- queryContractId owner a
  Some ib <- queryContractId owner b
  -- HARM if violated: total minted/burned out of thin air
  assert (ia.amount + ib.amount == 100)

-- Cancel/abort with no unwind: child contract still active after parent cancel.
test_cancel_no_unwind : Script ()
test_cancel_no_unwind = do
  owner <- allocateParty \"Owner\"
  parent <- submit owner do createCmd Order with owner, ..
  child  <- submit owner do exerciseCmd parent Reserve with ..  -- locks/creates child
  _      <- submit owner do exerciseCmd parent Cancel
  -- HARM: child still exists despite cancel
  cs <- query @Reservation owner
  assert (not (null cs))
```

### CID-Capability PoC

```daml
-- Caller-supplied ContractId not bound to the operation: pass a lookalike CID.
test_cid_not_bound : Script ()
test_cid_not_bound = do
  attacker <- allocateParty \"Attacker\"
  legit    <- submit attacker do createCmd Config with owner = attacker, ..
  evil     <- submit attacker do createCmd Config with owner = attacker, value = 999
  -- choice accepts an arbitrary Config cid instead of the bound/whitelisted one
  _ <- submit attacker do exerciseCmd someCid UseConfig with cfg = evil
  -- HARM: attacker-controlled config took effect
  pure ()

-- Fail-open when whitelist/config CID absent; or stale-config brick (CONTRACT_NOT_FOUND).
-- For brick: archive the config the choice fetches, then show the choice aborts.
```

### State / Key Lifecycle PoC

```daml
-- lookupByKey false-None: a party WITHOUT visibility takes the None branch.
test_false_none : Script ()
test_false_none = do
  issuer  <- allocateParty \"Issuer\"
  -- Issuer creates the keyed contract; outsider cannot see it.
  outsider <- allocateParty \"Outsider\"
  _ <- submit issuer do createCmd Registered with issuer, label = \"X\"
  -- A choice the outsider can exercise does lookupByKey and, getting None
  -- (= not visible, NOT absent), mints a duplicate.
  _ <- submit outsider do createCmd RegisterRequest with party = outsider, label = \"X\"
  cids <- query @Registered issuer  -- HARM: two Registered with same key
  assert (length cids >= 2)
```

### Privacy / Disclosure PoC (party-scoped query oracle)

```daml
test_overbroad_disclosure : Script ()
test_overbroad_disclosure = do
  owner    <- allocateParty \"Owner\"
  outsider <- allocateParty \"Outsider\"
  _ <- submit owner do createCmd SecretDeal with owner, observers = [outsider], secret = 42
  -- HARM ORACLE: a party who should not see the deal can query it.
  cids <- query @SecretDeal outsider
  assert (not (null cids))  -- CONFIRMED: outsider sees the contract

-- Divulgence-via-fetch: query AFTER the divulging transaction.
```

### Boundary / Invariant PoC

```daml
-- ensure-gap: an invalid contract is creatable (should have been rejected).
test_ensure_gap : Script ()
test_ensure_gap = do
  p <- allocateParty \"P\"
  -- If this SUCCEEDS for an invalid value, the ensure clause is missing/too weak.
  _ <- submit p do createCmd Bounded with p, amount = -1
  pure ()

-- Arithmetic overflow = LIVENESS brick (DAML Int/Decimal THROW, never silently wrap):
test_overflow_brick : Script ()
test_overflow_brick = do
  p <- allocateParty \"P\"
  cid <- submit p do createCmd Accumulator with p, total = 0
  -- A choice that adds near-max amounts aborts; the contract becomes un-exercisable.
  submitMustFail p do exerciseCmd cid Add with delta = (maxIntValue)  -- aborts → brick
```

### Boundary-Value Parameterized Fallback (Aptos-style)

> No native DAML fuzzer. For Medium+ boundary findings, write a shared helper and call it from min/mid/max top-level Scripts. `daml test` runs each Script.

```daml
runBoundary : Int -> Script ()
runBoundary amount = do
  p <- allocateParty \"P\"
  -- exercise the target choice with `amount`, assert the boundary invariant
  pure ()

boundaryMin : Script ()
boundaryMin = runBoundary 0

boundaryMid : Script ()
boundaryMid = runBoundary 500000

boundaryMax : Script ()
boundaryMax = runBoundary maxIntValue
```

## HARM vs MECHANISM (HARD GATE)

Asserting that a choice CAN be exercised, a contract CAN be created, or a code
path is reachable is a MECHANISM test → `[CODE-TRACE]` at best, NEVER `[POC-PASS]`.
A `[POC-PASS]` requires a HARM assertion proving the claimed consequence. Required
harm assertions per class:

| Class | Mechanism (INSUFFICIENT) | Required HARM assertion (for [POC-PASS]) |
|-------|--------------------------|-------------------------------------------|
| AUTHORIZATION | \"attacker's submit succeeds\" | resulting contract's `owner`/privileged field moved to attacker (ownership/authority moved) |
| CHOICE/ASSET | \"choice exercised twice\" | value conservation violated (`out1+out2 != in`) OR cumulative > cap OR child still active after cancel |
| CID-CAPABILITY | \"arbitrary CID accepted\" | attacker-controlled config/value took effect, or fetched config CID archived → choice aborts (brick) |
| STATE/KEY | \"None branch reached\" | duplicate keyed state created (`query` returns ≥2) under a non-visible party |
| PRIVACY | \"observer set is broad\" | `query @T outsider` returns NON-EMPTY for a party who should not see it |
| BOUNDARY | \"create with bad value succeeds\" | the invalid contract is queryable/usable, or the abort permanently locks the contract |
| INTERFACE | \"coercion compiles\" | wrong-template coercion yields a contract a party can act on, or `view` discloses to an outsider via the privacy oracle |

If the harm assertion FAILS (party receives nothing, ownership unchanged, conservation holds, outsider query empty, contract still usable) → `[POC-FAIL]`.

## EVIDENCE TAGS + ASSERTION RETRY

Evidence tags are `[POC-PASS]` / `[POC-FAIL]` / `[CODE-TRACE]` ONLY. There is no
`[MEDUSA-PASS]` or `[FUZZ-PASS]` for DAML (no fuzzer).

- `[POC-PASS]`: built, ran via `daml test`, HARM assertion passed.
- `[POC-FAIL]`: built and ran, HARM assertion failed (the attack does not produce the claimed consequence).
- `[CODE-TRACE]`: could not build/run after 5 attempts, manual trace with real values → CONTESTED.

**Assertion Retry (on harm-assertion failure)**: you get ONE setup-only retry.
The retry MUST keep the SAME `exerciseCmd`/choice, the SAME harm assertion, and
the SAME finding location — fix only the setup (party allocation, contract
field values, ordering). If the retry changes WHICH choice is exercised or WHICH
`query @T` is asserted, cap the evidence at `[CODE-TRACE]` (you are testing a
different thing, not the finding). After the setup-fixed retry still fails →
`[POC-FAIL]`. Do NOT weaken the harm assertion to force a pass.

**`submitMustFail` caveat (state explicitly)**: a PASSING `submitMustFail` proves
SAFETY — it REFUTES an authorization/bypass/double-spend claim. Never report a
passing `submitMustFail` as confirmation of a bug.

## ERROR TRACE OUTPUT
When verdict is CONTESTED or FALSE_POSITIVE, document:

### Error Trace
- **Failure Type**: PRECONDITION_FAILED / AUTHORIZATION_ERROR / CONTRACT_NOT_FOUND / NO_SUCH_KEY / ASSERTION_FAILED / INSUFFICIENT_EVIDENCE / COMPILE_ERROR
- **Location**: {Module.daml}:{template/choice}:{line where failure occurs}
- **Error Value**: {DAML error / Script failure message, if any}
- **State at Failure**: {key contract fields and ACS visibility when the Script failed}
- **Investigation Question**: {What specific question would need to be answered to resolve this}

## NEW OBSERVATIONS (MANDATORY)
If during verification you discover a NEW bug, configuration dependency, or edge case
NOT covered by any existing hypothesis - document it under:

### New Observations
- [VER-NEW-1]: {title} - {location} - {brief description}

These will be reviewed by the orchestrator for possible inclusion as new findings.

## INDEPENDENT SEVERITY ASSESSMENT (MANDATORY — M4 anti-inflation)

Before reconciling with any pre-assigned/claimed severity (from the hypothesis, queue, or inventory), assess a severity INDEPENDENTLY:

1. Read ONLY the code and your own evidence (PoC result, code trace, dual-perspective verdict from above). Deliberately IGNORE the claimed/pre-assigned severity for this step - do not let it anchor your judgment.
2. Apply the standard severity matrix (Impact x Likelihood) from `~/.claude/rules/report-template.md` to what YOU found, as if no severity had been pre-assigned.
3. Record the result in your output BEFORE finalizing your Severity field:

```
**Independent Severity**: <Critical|High|Medium|Low|Informational|N/A>
```

- Assessed from the code and evidence ALONE; ignore any pre-assigned severity.
- Use `N/A` ONLY when your verdict is REFUTED/FALSE_POSITIVE (no independent severity applies to a non-finding).
- This field is MANDATORY for every non-REFUTED verdict. The driver reads it to mechanically compute `final = min(Independent Severity, claimed severity)` - this can ONLY LOWER the reported severity, it NEVER raises it and NEVER drops the finding. A missing or unparseable field is recall-safe: it simply falls back to the claimed severity (no cap applied).

Do NOT skip this field to save time, and do NOT default it to the claimed severity - that defeats its purpose of catching an inflated pre-assigned severity.

## FIX GENERATION (POC-PASS only)
If your PoC PASSES (verdict = CONFIRMED with [POC-PASS]):
1. Write a minimal diff-style fix (smallest change that eliminates the bug — e.g. add a co-signatory/controller, add an `ensure` bound, rebind the caller-supplied `ContractId`, narrow the `observer` set, make a choice `nonconsuming`→`consuming` or vice versa).
2. If time permits, re-run the PoC with the fix applied to verify it no longer triggers (the harm assertion now fails / `submitMustFail` now passes).
3. Include in your output under `### Suggested Fix` per phase5-poc-execution.md
4. If the fix is non-trivial (architectural, multi-template): write a 1-sentence description instead of a diff

Do NOT generate fixes for [CODE-TRACE] or [POC-FAIL] findings.

Write FULL PoC to {SCRATCHPAD}/verify_{hypothesis_id}.md
Include the mandatory `### Execution Result` and `### Fuzz Result` (Medium+) sections per phase5-poc-execution.md.

Return: CONFIRMED/FALSE_POSITIVE/CONTESTED + evidence tag + 3-sentence justification
")
```

**Escalation**: If 3+ agents flagged root cause AND verifier says FALSE_POSITIVE → override to CONTESTED.

---

## Independent Skeptic Challenge Boundary (Thorough mode)

> **Ownership:** This ecosystem verification prompt ends with the standard verifier. It MUST NOT spawn skeptic or judge workers, apply a skeptic proposal, or change report severity or disposition.
> **Triggering:** After standard verification, the driver constructs an independent semantic trigger manifest across all severities. Severity alone is neither an eligibility rule nor an exclusion rule.
> **Execution:** The shared driver-owned skeptic methodology receives that manifest and the applicable ecosystem anti-hallucination constraints. Its artifact is proposal-only and has no report authority. A distinct typed adjudicator receives each challenge requiring disposition; skeptic and adjudicator MUST NOT be the same worker or session.
> **Completeness:** A hash-bound receipt MUST account for every exact manifest finding ID once. Missing, duplicate, unknown, stale, or constituent-substituted IDs make the phase incomplete and require retry or explicit human-review degradation; they are never silently skipped.
> **Authority:** Only a validated, report-authoritative typed severity/disposition ledger can change upstream severity or disposition. Legacy `skeptic_*.md` and `judge_*.md` files are diagnostic or proposal artifacts only.
> **Recall floor:** `UNRESOLVED` and `PARTIAL` preserve the highest supported upstream tier and remain visible in the report body. They create explicit review work, never an automatic demotion or exclusion.

Execution details belong to the shared driver-owned skeptic and typed-adjudication contracts; do not copy them into an ecosystem verifier prompt.

---

## Cross-Batch Consistency Check (Phase 5.2)

> **Purpose**: When one verification batch marks a mechanism as FALSE_POSITIVE, other batches may still contain findings that depend on the same invalidated mechanism. Parallel batches cannot detect this — a post-batch reconciliation step is needed.
> **Trigger**: Always, after ALL verification batches complete (Phase 5 + 5.1). Runs before Phase 5.5 (finding extraction).
> **Model**: haiku (mechanical cross-reference)
> **Budget**: 1 agent (not counted against verification budget)

### Orchestrator spawns:

```
Task(subagent_type="general-purpose", model="haiku", prompt="
You are the Cross-Batch Consistency Agent.

## Your Task
Read ALL verification batch files: {SCRATCHPAD}/verify_batch_*.md

### STEP 1: Extract FALSE_POSITIVE mechanisms
For each FALSE_POSITIVE verdict, extract:
| Finding ID | Invalidated Mechanism | Reason | Batch Source |

### STEP 2: Cross-reference surviving findings
For each invalidated mechanism, search ALL other batch files for findings whose
attack path, precondition, or root cause depends on the same mechanism.

A finding DEPENDS on the mechanism if:
- It references the same choice/template code path that was proven non-exploitable
- Its attack requires the behavior the FALSE_POSITIVE disproved (e.g. a choice being nonconsuming, a `lookupByKey` returning None, a party seeing a contract)
- It is a chain hypothesis whose constituent was the FALSE_POSITIVE

### STEP 3: Flag contradictions
| Surviving Finding | Batch | Depends On | FALSE_POSITIVE ID | Contradiction |

### STEP 4: Recommend
For each contradiction:
- If the surviving finding's ENTIRE attack path depends on the disproved mechanism → recommend FALSE_POSITIVE
- If only part of the attack path is affected → recommend DOWNGRADE with explanation
- If the dependency is unclear → recommend REVIEW

Write to {SCRATCHPAD}/cross_batch_consistency.md
Return: 'DONE: {N} FALSE_POSITIVES checked, {C} contradictions found, {R} recommendations'
")
```

### Orchestrator action after agent returns:
- If contradictions found: apply recommendations (FALSE_POSITIVE or DOWNGRADE) before Phase 5.5
- If no contradictions: proceed to Phase 5.5
- Log results in {SCRATCHPAD}/verification_consistency.md
