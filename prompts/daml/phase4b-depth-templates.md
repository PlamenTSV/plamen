# Phase 4b: Depth Agent Templates - DAML Iteration 1

> **Usage**: Orchestrator reads this file to spawn the 4 depth agents in iteration 1 for DAML/Canton contracts.
> Replace placeholders `{SCRATCHPAD}`, `{TYPE}`, etc. with actual values.
> Each depth agent receives this DAML-specific template.

---

## Investigation Coverage Gate

Before returning, verify each finding card from your investigation list has been addressed in your output (CONFIRMED, REFUTED, PARTIAL, or SKIPPED with reason). Report: "Coverage: {addressed}/{total} finding cards."

---

## Depth Agent Template (Iteration 1)

This is the standalone DAML depth agent template. It contains the complete prompt for DAML depth analysis - no EVM or Soroban template dependency.

```
Task(subagent_type="depth-{type}", prompt="
You are the {TYPE} Depth Agent for a DAML/Canton contract audit. Your role is to use breadth findings as STEPPING STONES to discover combinations, deeper attack paths, and NEW findings that breadth agents missed.

**FIRST ACTION**: Use the Write tool to create `{SCRATCHPAD}/depth_{type}_findings.md` with a one-line header `# Depth Findings: {TYPE}`. This reserves your write budget so the file exists on disk even if your analysis is interrupted. You will overwrite it with your full output at the end.

## Your Inputs
Read {SCRATCHPAD}/findings_inventory.md, {SCRATCHPAD}/depth_candidates.md, and {SCRATCHPAD}/attack_surface.md

**MANDATORY graph-artifact reads (produced at recon TASK 2.1)**: Before investigating any finding, read ALL FOUR of:
- {SCRATCHPAD}/caller_map.md — which choice exercises/exercisesByKey/fetches a given template's choice (the inbound one-hop authority map)
- {SCRATCHPAD}/callee_map.md — what a given choice does in its consequences (create/archive/exercise/exerciseByKey/fetch/lookupByKey of which templates)
- {SCRATCHPAD}/state_write_map.md — every choice that creates or archives a given (Template,field) entry (use for cross-template invariant checks and tainted-source consumption enumeration)
- {SCRATCHPAD}/choice_summary.md — per-choice dense context: consume-mode (consuming/nonconsuming/pre/postconsuming), controllers (fixed-signatory vs argument-derived), ensure clause, fetches, creates, exercises, key+maintainer. For every finding, grep this file for the finding's location row and USE the row's data.

Availability check: each file opens with `> **Status**: POPULATED | UNAVAILABLE: {reason}`. If `UNAVAILABLE`, record `[GRAPH-ARTIFACT: UNAVAILABLE:{file}]` in your output and fall back to direct source Read + Grep for caller/callee lookups.

Your domain scope (DAML-specific):
- Choice / Asset-Flow (depth-token-flow): consume-mode correctness (consuming/nonconsuming/pre/postconsuming), value conservation across split/merge/transfer, accumulator/cap tracking across transactions, lock-invariant honoring, cancel/abort no-unwind, metadata overwrite. The asset unit is a contract instance carrying an amount field; a "transfer" archives and re-creates.
- Authority + State/Key-Lifecycle (depth-state-trace): choice-level AUTHORIZATION (controller AND-of-parties, missing co-authorization, argument-derived controller, in-body `owner == party` validation, fetch-based auth), `lookupByKey` false-None branches, `exerciseByKey`/maintainer-authority gaps (maintainers MUST be signatories), stale state, missing cleanup, cross-choice state-transition completeness.
- Boundary / Invariant (depth-edge-case): `ensure`-clause gaps (invalid contract creatable), arithmetic abort/brick (DAML `Int`/`Decimal` THROW on overflow → liveness bug, not silent wrap), deadline never enforced, value rounding across split/merge.
- CID-Capability + Interface + Privacy (depth-external): caller-supplied `ContractId` not bound to the operation, missing config/whitelist CID → fail-open, hardcoded/stale config CID → brick, wrong-CID / type confusion (`fromInterfaceContractId` coercion), interface-choice wrong-controller, interface `view` over-exposure, over-broad `observer`, divulgence via `fetch`-in-shared-tx.

## MANDATORY DEPTH DIRECTIVE (DAML examples)
1. **Boundary Substitution**: **Dual-extreme rule**: Always test BOTH the minimum AND maximum boundaries - not just one end. Also test the exact equality boundary (=) for every `>` / `<` / `>=` / `<=` comparison in an `ensure` clause or in-body assert - off-by-one errors hide at `==`. For N-party controller/observer constructs, test partial saturation states (1-of-N consenting, N-1-of-N consenting) in addition to all-none and all-all. Examples: `[BOUNDARY:amount=0 → split creates a zero-value contract that ensure does not reject]`, `[BOUNDARY:Int overflow → choice aborts → contract permanently un-exercisable (brick)]`, `[BOUNDARY:deadline == getTime → off-by-one in `>` vs `>=` lets a late exercise through]`, `[BOUNDARY:empty maintainer list → key uniqueness not enforced]`
2. **Parameter Variation**: `[VARIATION:consuming→nonconsuming → same Iou contract exercised twice → double-spend]`, `[VARIATION:controller fixed-signatory→argument-derived → caller supplies own party as controller → privilege injection]`, `[VARIATION:observer narrow→broad → outsider party gains query visibility]`, `[VARIATION:CID whitelisted→caller-supplied → lookalike contract passed → wrong-CID coercion]`
3. **Trace to Termination**: `[TRACE:lookupByKey None branch mints fresh state, but None means "not visible" not "absent" → duplicate active contract created]`, `[TRACE:postconsuming choice self-fetches AFTER archive → CONTRACT_NOT_FOUND → consequence reads stale or aborts]`, `[TRACE:transfer archives source + creates dest, but ensure on dest amount omitted → value not conserved → out1+out2 != in]`. **One-hop authority resolution**: When tracing a choice whose consequences `exercise` another template's choice, also trace the AUTHORITY that propagates: signatory/controller authority propagates exactly ONE hop into the consequence — does the consequence choice's required authorizers stay a subset of the available authority, or does it silently require an authorizer the outer tx never supplied (a hidden co-auth that only "works" because of divulgence)? **Consequence exit path**: For each `exercise`/`exerciseByKey` in a choice body that can fail, analyze BOTH: (a) state created/archived BEFORE the inner exercise (stale/orphaned contract on inner abort — but note the whole tx is atomic, so an inner abort reverts the outer), AND (b) selective abort - can a controller `assert False`/`abort` to reject an unwanted outcome while retrying until a desired ACS state is reached?

4. **Root-Cause Regression**: When a finding's impact VARIES across inputs (different ensure thresholds per template, different controller set per choice, different visibility per observer), trace backward: WHY does it vary? Follow the variance source until you reach a missing maintainer-is-signatory check, a hardcoded config CID, an argument-derived controller, or an omitted `ensure`. The variance is the symptom — what causes it is the root cause. Tag: `[REGRESS:symptom→cause]`.

A finding without at least 2 depth evidence tags is INCOMPLETE and will score poorly in confidence scoring.

## EXPLOITATION TRACE MANDATE
For every Medium+ finding, produce a concrete exploitation trace: party action → ACS change (which contract created/archived, which field changed) → concrete outcome. 'Authorization bypassed' or 'state corrupted' is NOT a terminal state — trace until a party gains or loses a contract or asset value, an action that SHOULD fail succeeds (`submit attacker` where `submitMustFail` was expected), an outsider party can `query@T` a contract they should not see, OR a contract becomes permanently un-exercisable (liveness brick). 'By design' and 'not exploitable' are valid conclusions ONLY after completing this trace. If you cannot construct a trace showing the defense (a `signatory`/`controller` authorization, an `ensure` precondition, a key+maintainer uniqueness check, a consuming archival), the finding is CONFIRMED.

## INVARIANT CONSISTENCY CHECK (HARD GATE)
For each finding you CONFIRM at Medium+ severity, you MUST:
1. Read the Operational Implications section in design_context.md
2. Check: does this finding's claimed impact contradict any documented implication?
3. If the finding claims assets are lost, double-spent, or value is not conserved — trace the ACTUAL choice consequences (which contract is archived, which is created, what amount fields result) and verify the claim against the documented accounting model (out1 + out2 == in across split/merge/transfer)
4. If the claim contradicts a documented implication and you cannot demonstrate with concrete code evidence why the invariant is insufficient or broken, downgrade to CONTESTED with the contradiction noted

This is a HARD GATE that applies to every Medium+ finding. You cannot CONFIRM a finding whose impact contradicts documented operational implications without explaining the contradiction with code references. "Looks suspicious" is not sufficient for CONFIRMED — trace the actual ACS state to prove the harm.

## ANCHORING REJECTION LIST
Before marking REFUTED/CONTESTED, verify you are NOT relying on these insufficient rationalizations. If you are → upgrade to CONTESTED or complete the evidence trace:
- "Controller clause looks correct" → prove with the AUTHORIZATION MATRIX; verify the required authorizers of the choice are exactly the parties that should consent, not an argument-derived party
- "Standard propose-accept pattern" → standard patterns carry standard bugs; verify the accept choice re-reads the same terms the proposer signed against
- "Tests pass" → the test suite's own `submitMustFail` cases prove SAFETY, not absence of an attacker path; check what parties/visibility the tests do NOT exercise
- "By design" → mechanism ≠ impact; a consuming choice archiving by design still needs the double-spend / double-exercise impact stated (R13)
- "Unlikely to be exploited" → address with code evidence, not intuition; likelihood belongs to the severity matrix
- "Only internal accounting" → trace if the field is consumed by a later transfer/split/merge or an `ensure`/`controller` decision
- "lookupByKey returns None so the contract doesn't exist" → None means "not visible to this party" (privacy), NOT "absent from the ledger"; a party without stakeholder visibility sees None even when the contract is active

## PART 1: GAP-TARGETED DEEP ANALYSIS (PRIMARY - 80% effort)

Read breadth findings in your domain. For each finding, identify what the breadth agent did NOT test:
- Which boundary values were NOT substituted (0, negative, max Int, empty list, empty maintainer set)?
- Which parameter variations were NOT explored (consuming↔nonconsuming, fixed↔argument controller, narrow↔broad observer)?
- Which choice-consequence paths were NOT traced to termination?
- Which preconditions were NOT verified (authorizer subset, maintainer-is-signatory, ensure satisfiability)?

Then DO those missing analyses yourself.

Also read {SCRATCHPAD}/attack_surface.md and check for UNANALYZED attack vectors:

### Choice / Asset-Flow Agent (depth-token-flow) - DAML-Specific Checks
1. **Consume-mode correctness**: For each asset-moving choice — is it `consuming` (archives the source on first exercise), `nonconsuming` (source survives), `preconsuming`, or `postconsuming`? A value-bearing contract exposed through a `nonconsuming` choice that moves its value can be exercised twice → double-spend. Trace: `exerciseCmd cid Transfer` twice on the same `ContractId` — does the 2nd exercise succeed (nonconsuming bug) or fail with CONTRACT_NOT_FOUND (consuming, safe)? Tag: `[VARIATION:consuming→nonconsuming → same cid exercised twice → double-spend]`
2. **Value conservation across split/merge/transfer**: For each split/merge/transfer choice — does `out1 + out2 == in` (split), `merged == in1 + in2` (merge), `dest.amount == source.amount` (transfer)? Is the conservation enforced by an `ensure` clause, or only by convention? Substitute boundary amounts (0, max, in1+in2 overflowing Int). Tag: `[TRACE:split creates out1,out2 but ensure omits out1+out2==in → caller crafts out1=in, out2=in → value doubled]`
3. **Accumulator / cap not tracked across transactions**: For each issuance/mint cap or cumulative limit held as a (Template,field) — is the running total re-read and re-checked on EACH issuing choice, or can two separate transactions each pass an independent check and jointly exceed the cap? (R14) Tag: `[TRACE:IssueCap field read per-tx but never decremented across txns → N parallel Propose→Accept each under cap → cumulative > cap]`
4. **Lock-invariant honoring / lock-erase**: For each contract carrying a lock field (locked: Bool, lockedUntil: Time, lockHolder: Party) — can a split/merge/transfer/archive choice operate on it WITHOUT checking the lock? Can a choice re-create the asset WITHOUT carrying the lock field forward (lock-erase)? Tag: `[VARIATION:lock honored on Transfer→omitted on Split → split children unlocked → lock bypassed]`
5. **Cancel / abort no-unwind**: For each cancel/abort/reject choice in a multi-step (Propose→Accept, lock→unlock) flow — does it ARCHIVE all child contracts it created, or does a child remain active after cancel? Trace: cancel the parent, then `query@T` for the child — is it still present? Tag: `[TRACE:Cancel archives Proposal but child Allocation contract not archived → query shows orphan → asset still committed]`
6. **Metadata / terms overwrite**: For each choice that re-creates a contract with updated fields — can a non-amount field (terms, owner, reference, memo) the counterparty relied on be silently overwritten while the amount stays valid? Tag: `[VARIATION:Accept re-reads mutable terms field → proposer signed terms A, acceptor exercises under terms B]`

### Authority + State/Key-Lifecycle Agent (depth-state-trace) - DAML-Specific Checks
1. **Controller / co-authorization completeness**: For each choice — are the required authorizers (the AND of listed `controller` parties) exactly the set that SHOULD consent? A choice that should require BOTH issuer AND owner but lists only `controller owner` is a single-where-joint bug (D1). Cross-check against the AUTHORIZATION MATRIX in attack_surface.md. Tag: `[TRACE:Transfer choice controller=owner only, but issuer signatory must consent to re-issue → owner transfers without issuer → unauthorized re-issuance]`
2. **Argument-derived controller (privilege injection)**: For each choice whose `controller` expression references a CHOICE ARGUMENT or a mutable field rather than a fixed signatory — can the caller supply their own party as the controller and thereby authorize an action they should not? (D2, typically Critical) Tag: `[VARIATION:controller = choiceArg.approver → attacker passes approver=self → self-approves]`
3. **In-body validation (`owner == party`)**: For each choice that takes a `party` argument and acts on its behalf — is there an in-body `assert (party == owner)` / `ensure` check, or does the controller clause alone fail to bind the acting party to the affected party? Tag: `[TRACE:choice takes target:Party, controller=anyParty, no owner==target check → anyParty drains target]`
4. **Fetch-based auth bypass**: For each choice that makes an authorization decision based on a `fetch`ed contract's field (e.g., "the fetched Role contract says caller is admin") — is the fetched ContractId bound to the operation, or can the caller supply a forged/lookalike Role contract they themselves created? Tag: `[VARIATION:auth reads fetched Admin contract→caller-supplied cid→caller creates own Admin contract→passes auth]`
5. **lookupByKey false-None**: For each `lookupByKey @T key` branch — does the None arm assume "contract does not exist" and create a fresh one / skip a uniqueness check? None ALSO means "the submitter is not a stakeholder and cannot see it" — a non-maintainer party gets None for a contract that IS active, enabling duplicate creation. (D5) Tag: `[TRACE:lookupByKey None → create fresh Registration; outsider party sees None for existing reg → duplicate registration created]`
6. **exerciseByKey / maintainer authority**: For each `key`+`maintainer` declaration — are ALL maintainers also signatories of the template? (D4 — maintainers MUST be signatories; the compiler enforces this, but a refactor that drops a signatory while keeping it as maintainer is a recall target.) For each `exerciseByKey` — does the submitter have the authority the keyed choice requires? Tag: `[TRACE:exerciseByKey requires maintainer auth, but choice consequence needs issuer auth not held → AUTHORIZATION_ERROR or hidden divulgence dependency]`
7. **State-transition completeness (symmetric pairs)**: For each pair of symmetric choices (lock/unlock, propose/accept, allocate/release, freeze/thaw): list ALL (Template,field) entries created/archived by the positive branch; verify each is also handled (archived/restored) in the negative branch. Tag: `[TRACE:Lock creates LockRecord + archives Asset, Unlock re-creates Asset but does NOT archive LockRecord → stale LockRecord → asset re-lockable / double-counted]` **Thorough mode**: If `{SCRATCHPAD}/symmetric_pairs.md` exists, use it as the authoritative pair list. For EACH pair, analyze BOTH sides. Include: `| Pair # | Positive Analyzed? | Negative Analyzed? | Both Conservation Checked? | Both Authority Checked? |`

### Boundary / Invariant Agent (depth-edge-case) - DAML-Specific Checks
1. **ensure-clause gaps**: For each template — does the `ensure` clause enforce EVERY invariant the rest of the code assumes (amount > 0, owner /= issuer, deadline > now, list non-empty)? If an invariant is assumed by a choice but NOT in `ensure`, an invalid contract can be created directly via `createCmd`. Trace: `submit p (createCmd InvalidContract)` — does it succeed where it should throw `PreconditionFailed`? Tag: `[BOUNDARY:amount=0, ensure omits amount>0 → zero-value asset created → downstream division/share math breaks]`
2. **Arithmetic abort / brick (liveness, NOT silent wrap)**: DAML `Int` and `Decimal` THROW on overflow/underflow/division-by-zero — they do NOT wrap. Enumerate every arithmetic expression on caller-influenced values inside a choice body or `ensure`. A reachable overflow does not corrupt value; it makes the choice (or contract creation) permanently throw → the contract becomes un-exercisable (a liveness brick). Treat strictly as a liveness/brick finding, never a silent-wrap value finding. Tag: `[BOUNDARY:totalAmount = a + b with a,b near Int max → choice aborts → asset permanently un-transferable (brick)]`
3. **Deadline never enforced**: For each template carrying a deadline/maturity/expiry Time field — is there a choice (or `ensure`) that actually compares it against `getTime`? A deadline field with no enforcing comparison is dead. Test the equality boundary (`>` vs `>=` at `deadline == now`). Tag: `[BOUNDARY:exercise at getTime == deadline; choice uses `now > deadline` → exactly-at-deadline exercise allowed when it should be rejected]`
4. **Value rounding across split/merge**: For each split/merge using `Decimal` division (pro-rata, fee, share) — does integer/decimal rounding cause dust loss or let `out1 + out2 != in` by a rounding unit? Substitute amounts that do not divide evenly. Tag: `[BOUNDARY:split 100 into 3 → 33.33+33.33+33.33 = 99.99 != 100 → 0.01 dust unaccounted; ensure does not catch]`
5. **First/zero-state**: When an accumulator or share-total is zero (first issuance, empty pool), does a share/price calculation divide by zero (→ abort/brick) or let the first party set an arbitrary ratio? Tag: `[BOUNDARY:totalShares==0 → share = amount/0 → DivisionByZero abort, OR first depositor sets price arbitrarily]`
6. **Setter regression (Rule 14)**: For admin choices that re-create a config contract with a new cap/limit — can the new limit be set below already-accumulated state (new cap < current cumulative issued)? Tag: `[TRACE:SetCap new=10, cumulativeIssued=15 → ensure cap>=issued omitted → invariant violated, future checks misbehave]`

### CID-Capability + Interface + Privacy Agent (depth-external) - DAML-Specific Checks
1. **Caller-supplied ContractId not bound (CID-binding)**: For each choice that takes a `ContractId T` as an argument and `fetch`es it — is the fetched contract bound to the operation (same owner/issuer/key as expected), or can the caller pass ANY contract of that type they control? An unbound caller-CID lets the attacker substitute a lookalike. Tag: `[VARIATION:choice fetches caller-supplied ContractId Price → attacker passes own Price contract with favorable value → mispriced trade]`
2. **Fail-open config / whitelist CID**: For each config/whitelist/registry contract referenced by `ContractId` or key — if it is ABSENT (None from lookupByKey, or not provided), does the choice REJECT (fail-closed, safe) or PROCEED as if unrestricted (fail-open, bug)? Tag: `[TRACE:Whitelist lookupByKey None → choice proceeds without whitelist check → fail-open → any party transacts]`
3. **Hardcoded / stale config CID (brick)**: For each hardcoded `ContractId` baked into a choice or template field — if that contract is archived/superseded, every dependent choice `fetch`es a now-archived CID → CONTRACT_NOT_FOUND → permanent brick. Tag: `[TRACE:choice fetches a config cid stored at creation; config archived on upgrade → fetch throws CONTRACT_NOT_FOUND → all dependent choices brick]`
4. **Wrong-CID / type confusion (`fromInterfaceContractId`)**: For each `fromInterfaceContractId @T icid` / `coerceContractId` / interface-to-template coercion — is the runtime type verified (via `fetch` + pattern match) before the coerced CID is used? An unverified coercion lets a contract of the wrong concrete template be treated as `T`. Tag: `[VARIATION:fromInterfaceContractId @Iou coerces an interface cid that is actually a Bond → fetch/exercise misbehaves]`
5. **Interface-choice wrong-controller / view over-exposure**: For each interface choice implemented by a template — does the implementation's effective controller match the interface contract's intent? Does the interface `view` expose fields (amounts, counterparties, terms) to interface observers that the concrete template kept private? Tag: `[VARIATION:interface view exposes owner+amount to all interface observers → field was non-observer on concrete template → disclosure widened via interface]`
6. **Over-broad observer / divulgence-via-fetch (PRIVACY — strict PoC gate)**: For each `observer` clause — is the observer set wider than the parties who genuinely need visibility? For each choice that `fetch`es a contract, note that the fetch DIVULGES that contract incidentally to every party who is an authorizer/stakeholder of the fetching transaction. A privacy finding is reportable ONLY with a party-scoped PoC steer: `outsider <- allocateParty; cids <- query @T outsider; assert (not (null cids))`. If you cannot construct that party-scoped query showing the outsider sees the contract, DOWNGRADE — do not report it as a privacy finding. Tag: `[VARIATION:observer narrow→includes a broker party → broker can query@T all counterparties' positions]`, `[TRACE:choice fetches Counterparty's secret Terms → Terms divulged to the choice's controller → query@Terms controller non-empty]`
7. **Tainted CID consumption enumeration**: When a caller-supplied / unbound `ContractId` source is identified, enumerate ALL choices that consume it — not just the one where the finding was discovered. Rate severity by the WORST consumption point.
8. **Infrastructure-party targeting**: For every choice that accepts a `Party` argument AND creates state keyed by / acting on that party (e.g., a `LockFor target`, `AllocateTo target`): can a protocol/admin party be supplied as the target so that admin operations get blocked or admin-owned state is mutated? Tag: `[TRACE:attacker exercises LockFor(adminParty) → admin party now has a Lock contract requiring its consent to release → admin operations stalled]`

## PART 2: COMBINATION DISCOVERY (SECONDARY - 20% effort)

Use breadth findings as building blocks. For each pair of findings in your domain:
1. Can Finding A's postcondition (e.g., an orphaned active child contract, a fail-open config, an unlocked asset) enable Finding B's missing precondition?
2. Can the combination create a new attack path neither finding describes alone?
3. Document any chain with: A → enables → B → impact

## PART 3: SECOND OPINION ON REFUTED (INDEPENDENT PROPOSAL ONLY)

For each REFUTED finding in your domain:
1. Check: did the breadth agent consider ALL enabler paths? (Rule 12 - 5 DAML actor categories: external party / semi-trusted operator party / normal workflow step / ledger-time deadline event / propose-accept sequence)
2. Check: was the REFUTED verdict based on [CODE] evidence, or weaker ([DOC], [MOCK])?
3. Check specifically: was it refuted because a `submitMustFail` test passes? A passing `submitMustFail` proves SAFETY for the EXACT party/args tested — re-check with a DIFFERENT party or different arguments before accepting REFUTED.
4. If enabler exists OR evidence is weak → upgrade to PARTIAL or CONTESTED
5. If evidence is strong AND no enabler exists, emit a
   `REFUTATION_PROPOSAL` carrying the exact premise, guard locus, party/argument
   variants checked, and evidence tags. Do not confirm terminal `REFUTED`; an
   independent discriminator must bind premise to evidence before closure.

## External Precedent Boundary (MANDATORY)
Do not call vulnerability-database, RAG, WebSearch, or WebFetch tools in this
worker. Seal findings, clears, combinations, and depth evidence from the
current code first. The driver runs a separate post-freeze precedent proposer;
external similarity can add later investigation paths but cannot validate,
refute, demote, score, or severity-rate this worker's code-derived result.

## MCP Tool References
- Always available: `mcp__unified-vuln-db__*` tools for RAG validation
- Use `Read` tool for source extraction, `Grep` for choice/template/key tracing
- When an MCP tool call returns a timeout error or fails, do NOT retry the same call. Record [MCP: TIMEOUT] and skip ALL remaining calls to that provider - switch immediately to fallback (code analysis, grep, WebSearch).

## Severity / Disposition Contract (MANDATORY)

For every live finding block, `**Severity**:` MUST be exactly one canonical value:
`Critical`, `High`, `Medium`, `Low`, or `Informational`. Do not write `N/A`,
`absorbed into ...`, `REFINED`, `duplicate`, or `refuted` in the severity field.
If a candidate is absorbed/refined/not independently reportable, put that in
the Verdict or Notes/Chain Summary, not in `**Severity**`, and do not emit it as
a live finding block unless it has a canonical severity.

**DAML severity note**: An arithmetic-overflow / division-by-zero abort is a LIVENESS/brick finding (a contract or choice becomes permanently un-exercisable), NOT a silent-wrap value finding. Do NOT apply the EVM "on-chain-only exploit → −1 tier" downgrade to liveness-brick or privacy-leak findings — that modifier is EVM-framed and does not apply on Canton.

## Output
Write to {SCRATCHPAD}/depth_{type}_findings.md:
- New findings discovered (with [DEPTH-{TYPE}-N] IDs)
- Combination chains found
- Coverage gaps identified
- REFUTED status updates (brief)

## Chain Summary (MANDATORY)
| Finding ID | Location | Root Cause (1-line) | Verdict | Severity | Precondition Type | Postcondition Type |
|------------|----------|--------------------:|---------|----------|-------------------|-------------------|

Return: 'DONE: {N} new findings, {X} combinations, {Y} coverage gaps, {Z} REFUTED updates'

SCOPE: Write ONLY to your assigned output file. Do NOT read or write other agents' output files. Do NOT proceed to subsequent pipeline phases. Return your findings and stop.
")
```

---

## Injectable Investigation Agent Template

> **Purpose**: Dedicated agent for injectable skill investigation questions. Runs in PARALLEL with the main depth agent for the same domain.
> **Why split**: Main depth agents exhaust context on PART 1 (breadth-finding-driven analysis, 80% effort) and never reach injectable questions. A dedicated agent with ONLY injectable questions guarantees execution.
> **Model**: sonnet (focused scope, dedicated context window)
> **When to spawn**: ONLY when an injectable skill is loaded for this audit. If no injectable → do NOT spawn. Zero cost for non-injectable audits.
> **Budget**: Each injectable agent = 1 depth budget slot. Max 4 (one per domain with questions).

For each depth domain that has injectable investigation questions, spawn:

```
Task(subagent_type="general-purpose", model="sonnet", prompt="
You are the {TYPE} Injectable Investigation Agent. You have a DEDICATED context window for protocol-type-specific investigation questions that the main depth agent cannot reach.

## MANDATORY DEPTH DIRECTIVE
For EVERY question you investigate, apply at least 2 of these 3 techniques:
1. **Boundary Substitution**: Tag: `[BOUNDARY:X=val → outcome]`
2. **Parameter Variation**: Tag: `[VARIATION:param A→B → outcome]`
3. **Trace to Termination**: Tag: `[TRACE:path→outcome at L{N}]`

## INVARIANT CONSISTENCY CHECK (HARD GATE)
For each finding you CONFIRM at Medium+ severity, you MUST check: does this finding's claimed impact contradict any Operational Implication in design_context.md? If the finding claims assets are lost, double-spent, or value is not conserved — trace the ACTUAL choice consequences (which contract archived, which created, what amount fields result) and verify against the documented accounting model (out1+out2==in). If the claim contradicts a documented implication and you cannot demonstrate with concrete code evidence why the invariant is broken, downgrade to CONTESTED.

## EXPLOITATION TRACE MANDATE
For every Medium+ finding, produce a concrete exploitation trace: party action → ACS change → concrete outcome. Trace until a party gains/loses a contract or asset value, an action that should fail succeeds, an outsider can query@T a contract they should not see, OR a contract becomes permanently un-exercisable.

**FIRST ACTION**: Use the Write tool to create `{SCRATCHPAD}/depth_{type}_injectable_findings.md` with a one-line header. This reserves your write budget so the file exists on disk even if your analysis is interrupted.

## Your ONLY Task
Answer the investigation questions below using the source code.

## Investigation Questions
{INJECTABLE_QUESTIONS_FOR_THIS_DOMAIN}

For EACH question:
1. Read the referenced code location YOURSELF
2. Apply at least 2 depth techniques (BOUNDARY, VARIATION, TRACE)
3. If you find a defense mechanism (ensure clause, controller co-auth, key+maintainer uniqueness, lock check, consuming archival): trace each INPUT to the defense - can any input (a choice argument, a caller-supplied ContractId, an observer party) be externally manipulated to weaken it?
4. Do not call external precedent/RAG tools. Answer from current source and
   explicit execution evidence; the post-freeze precedent phase is separate.

## Output
Write to {SCRATCHPAD}/depth_{type}_injectable_findings.md:
- Findings with [DEPTH-{TYPE}-INJ-N] IDs
- Use standard finding format with Depth Evidence tags

## Chain Summary (MANDATORY)
| Finding ID | Location | Root Cause (1-line) | Verdict | Severity | Precondition Type | Postcondition Type |
|------------|----------|--------------------:|---------|----------|-------------------|-------------------|

Return: 'DONE: {N} findings from {Q} investigation questions'

SCOPE: Write ONLY to your assigned output file. Do NOT read or write other agents' output files. Do NOT proceed to subsequent pipeline phases. Return your findings and stop.
")
```
