# Handoff Input — "Arm-Before-Trust" / Mutual-Zero Validation Coverage Gap

**Date:** 2026-07-16 · **From:** Claude (adversarial methodology-coverage pass) · **To:** Codex (program lead) + maintainer
**Type:** methodology-coverage INPUT for the next adversarial handoff — **NOT a code change, NOT a repo edit, NOT an approved change.** The repo freeze stands; this is a proposal for Codex to investigate and the maintainer to gate.

## Provenance & independent verification (Claude reviewer)
- Motivated by a public, disclosed DeFi incident (oracle price-feed drained via a zero-byte signature accepted against an unregistered committee key). Used as **one unnamed illustrative example only** — everything below is generic, Part-0 clean.
- Grounded against the actual methodology at `<LOCAL_USER_ROOT>/.plamen` (skills / rules / depth agents / Phase-4c chain).
- **I independently verified the load-bearing "genuine absence" claim** (the same discipline that caught an overcall in the prior code review): grep of `agents/skills/niche/signature-verification-audit/SKILL.md` for anchor-arming / key-registration / empty-signature-length coverage → **empty**; grep of `prompts/evm/generic-security-rules.md` (R16) + `agents/skills/evm/oracle-analysis/SKILL.md` for any auth-path term (signer/signature/armed/register/committee/public-key) → **zero auth-path rows** (only price-value checks). The gap is real; the classification is **RC-METHOD**, not RC-AGENT.
- **Governance:** ship-EVM-first, then validate the anchor-family match on **≥2 repos across ≥2 ecosystems** before any cross-tree mirror (the historical over-fit guard). This is a discovery-lens `extend` — recall-positive, precision-neutral — so the bar is lower than an architectural change, but the ≥2-ecosystem gate still applies.

---

## 1. Generic vuln-class (protocol-agnostic)
A verifier `V` gates a privileged effect behind proof that some input `p` (signature, proof, witness, caller identity) was authorized by a **trust anchor** `K` (verifying key, signer set, threshold, merkle root, admin, guardian). Verification is fundamentally an equality/membership test: **`V` accepts iff `derive(p) ∈ K`.** The class exists when two independent defects compose:

- **(A) Uninitialized trust anchor.** `K` is security-critical but defaults to the type's zero/empty element (`0`, zero-address, empty set, zero root, null), and **the system stays operational while `K` is still at that default** — `V` can run and *succeed* before `K` is ever bound to real key material.
- **(B) Degenerate-input acceptance.** `V` does not unconditionally reject the degenerate members of `p`'s domain — empty signature, zero recovered signer, zero proof, empty witness — that **derive to the anchor's zero element**.

**Lethal core (mutual-zero):** neither zero alone is a bug. A zero anchor with a verifier that rejects zero derivations fails *closed* (liveness bug, no theft). An armed non-zero anchor with a sloppy verifier is safe because `0 ≠ K`. When **both** hold, the attacker supplies a degenerate `p` where `derive(∅)=0`, and since `K=0`, `0 ∈ {0}` returns **true** — the proof system is bypassed not by breaking crypto but by making the "secret" equal to a trivially-producible null. **Either fix alone breaks the composition**: refuse to operate until `K` is armed (kills A), or reject degenerate inputs / zero derivations unconditionally (kills B).

**Reachability is usually by OMISSION (null-action):** registration never performed; deploy-gap (live before the separate arm step); admin-set-to-zero; rotate-to-empty (silently de-arms a once-armed verifier); uninitialized-proxy / fresh-storage slot reading zero. Passes that hunt for a *bad call* miss it; the correct lens is a **state-existence question** — *"is there any reachable state where the anchor is zero AND the verifier can still succeed?"*

**One unnamed illustrative example:** a generic price/attestation verifier whose signer key was never registered checks a zero-byte signature — `recover(empty)=0`, stored `key=0`, so `0 == 0` passes and a forged report authorizes a privileged effect.

**Siblings (same schema):** recover-to-zero vs unset stored authority; empty BLS/aggregate set or zero total weight; empty multisig / zero threshold (over-permissive) vs threshold > set size (unsatisfiable → liveness); unregistered guardian/reporter whose registry lookup returns the zero default; default-zero owner/governor while functions are owner-gated; uninitialized proxy admin/impl (mirror image — a re-callable initializer lets an attacker *arm it to themselves*); zero merkle/commitment root accepting a zero-leaf/empty proof; default-zero nonce/epoch/domain-separator enabling zero-context or cross-context replay.

---

## 2. Arm-before-trust detection checklist (generic; a "no" is a candidate finding)

**Arming — kills defect A**
1. Hard `require`/`assert` that the anchor is **non-zero / non-empty on every verification path** so `V` **cannot succeed** while un-armed (fail-closed).
2. Anchor armed **atomically at deploy/init** — no operational window where it is zero; if arming is a separate step, gated functionality is **inert until it completes** (a state-machine gate, not a convention).
3. All setters / rotation reject zero/empty **and** reject shrinking below a safe floor (`threshold > 0`, `set.size ≥ threshold`, `threshold ≤ set.size`); no path **de-arms** a previously-armed verifier.
4. On upgrade/migration/proxy, the anchor is re-established in the new storage layout, and `initialize()` is **non-re-callable and non-front-runnable**.

**Degenerate-input rejection — kills defect B**
5. `V` rejects an **empty / zero-length** proof/signature/witness *before* any derivation.
6. `V` explicitly rejects a **zero recovered signer / zero derived identity** (`recovered == 0 → revert`) **independent of** comparing it to the anchor.
7. Membership/threshold logic rejects the **empty set and zero threshold** — no vacuous truth (`signedWeight >= 0` / `count >= 0` are not checks).
8. Accept predicate enforces `derive(p) != ⊥ ∧ K != ⊥` **in addition to** `derive(p) ∈ K`, so a mutual-zero can never satisfy it.

**Meta**
9. Is "verified" a **positive, provable match against armed material** — not the *absence of a mismatch*? Equality against an unset default is the trap.

**Boundary values (paired, not isolated):** for each verifier + anchor setter, `[BOUNDARY:...]` each degenerate element and trace to accept/reject — signature `=∅`/all-zero `(r,s,v)`; recovered signer `=0`; key/identity `=0`; signer set `=∅`; threshold `=0` (and `> set.size`); merkle root `=0`; nonce/epoch/domain `=0`; total weight `=0`. **The critical test is the conjunction** — substitute the empty input **and** the un-armed anchor simultaneously and check whether the predicate returns `true`. Harm assertion: *"a degenerate proof authorizes a privileged effect while the anchor is unset,"* never merely *"an empty sig is accepted"* or *"the key can be zero"* — either boundary alone under-rates it.

---

## 3. Coverage verdict — **NOT RELIABLY CAUGHT (MISS)**

Grounded coverage census (file:line in the source pass; key verdicts):
- **(a) reject empty/zero signature** — PARTIAL: sig-niche `CHECK 1` only asserts `ecrecover != address(0)` (frames zero as an *invalid-sig symptom*); no "reject empty-blob before recovery."
- **(b) reject zero/uninitialized key or signer-set** — ABSENT for SC (only L1 BLS/P2P, flag-gated).
- **(c) arm-before-trust** — PARTIAL + scope-gated (storage-layout §5c is best but `STORAGE_LAYOUT`-gated and names `admin`, not key material).
- **(d) oracle AUTH integrity** — ABSENT: R16 + oracle-analysis are exhaustively price-VALUE; **zero rows on the source's authentication path** (independently verified).
- **(e) external-dependency auth premise** — PARTIAL: machinery holds "trusts external X" but nothing directs "is X itself armed?"
- **two-zeros composition shape** — PRESENT but SILOED: the only explicit instance is `cross-chain-message-integrity §3b` ("does `sender == peers[chainId]` pass when BOTH are zero?"), hard-gated to `CROSS_CHAIN_MSG` and never generalized.

**Single-agent:** NO agent catches the whole composition — the sig-niche catches at most half of (B) and reports it as a hardening nit; edge-case boundary substitution reaches (A) in the wrong (arithmetic/staleness) domain with no *paired* substitution; the oracle lens catches neither.

**Chaining:** Phase-4c is **structurally capable** (STEP 0a-LC low-confidence candidate enablers + STATE postcondition→precondition matching) but **starved and vocabulary-blocked**: it is a matcher, not a discoverer (both halves rarely surface together), and defect (A) surfaces under a storage/slot vocabulary while (B) surfaces under a recovered-signer vocabulary, so the same-variable STATE match misses even when both exist.

**Cross-boundary (primary independent axis):** the bug lives on the consumer↔verifier seam. `HAS_SIGNATURES` is set by grepping recovery patterns **within audited scope**; when the verifying contract is out of the consumer's scope, the flag never sets and the signature agent never spawns. External machinery audits **return VALUES**, never "is the external verifier's own anchor armed." Correct disposition if surfaced: `[EXTERNAL-ASSUMPTION: external verifier unarmed — signer key unregistered]` at worst-case (fund-loss) severity per R10, requiring `[EXT-CITED]` / `NEEDS_DEPENDENCY_RESEARCH`. The machinery to *hold* the finding exists; the methodology to *generate* it does not.

**Gap classification — RC-AGENT presumption test (all 3 pass → RC-METHOD, RC-AGENT excluded):** (1) methodology search → zero always-on coverage of the composition outside the flag-gated cross-chain silo; (2) reasoning trace → agents clear the value surface correctly while the auth sub-surface is skipped *by construction*; (3) gap statable without naming the finding → *"no always-on step instructs an agent to enumerate a trust anchor's uninitialized default, test whether an authenticating op is reachable while the anchor holds it, AND confirm degenerate inputs are rejected before the equality/membership comparison — nor to flag the mutual-zero composition."* **Primary RC-METHOD + secondary RC-CONTEXT (out-of-scope verifier).**

---

## 4. Improvement proposal (scoped) — `extend` + `trigger-fix`, NOT a new rule/injectable/agent

- **Edit 1 — extend the signature-verification niche skill (`CHECK 1`):** alongside `recovered != address(0)`, require the agent to (i) identify the **anchor** the recovery is compared against (stored key/signer-set/root/authority), (ii) enumerate its default/uninitialized value, (iii) test reachability of a *successful* verification while the anchor holds that default, (iv) **flag the mutual-zero composition explicitly**; also add "reject empty/zero-length signature blob before recovery." (~6–8 lines; within skill cap.)
- **Edit 2 — extend R16 with one "authentication armed?" row:** *for oracle/attestation inputs, is the source's signature-verification path armed — signer/committee key registered non-empty, empty-sig and zero-signer rejected — independent of value checks.* Routes the auth premise into the always-on oracle lens **and** into the `[EXTERNAL-ASSUMPTION]`/`NEEDS_DEPENDENCY_RESEARCH` escalation for out-of-scope verifiers, closing the RC-CONTEXT seam. (~2–4 lines.)
- **Edit 3 — chain matching directive (trigger-fix):** in the chain-prompt STEP 2.1 STATE-matching, add the anchor-family to the postcondition→precondition vocabulary so an "anchor defaults zero" postcondition matches a "degenerate input accepted" precondition **even when the two findings name the anchor differently** — match on anchor *role*, not identical variable string. Makes the existing engine actually assemble the composition. (~2 lines.)

**Files (EVM-first):** the signature-verification niche `SKILL.md`; the EVM `generic-security-rules.md` R16 section; the shared chain prompt. No per-tree fan-out for the initial ship.
**Anti-bloat gates:** line budget PASS (all small); duplication PASS (each concern in its single most-shared location); marginal value PASS (generalizes the proven cross-chain §3b question, invents no new pattern); prefer extend over new-rule → chosen.
**HOW-not-WHAT / Part-0:** teaches two generic questions — *(i) can this anchor be zero/empty while the system operates? (ii) does the verifier accept the input whose derivation is zero/empty?* — with one unnamed illustrative shape. Names no protocol/token/contract/oracle/chain/struct/function. **PASS.**
**Recall/precision-safety:** recall-positive (adds a discovery lens where there is none outside a flag-gated silo); precision-neutral by construction (the always-on additions only *ask a question*; the composition flag fires only when a zero-able anchor **and** a degenerate-acceptable input coexist, and the harm assertion gates severity; the chain edit's downstream verify-the-positives filter refutes spurious enabler chains).

---

## 5. What Codex should adversarially investigate (before trusting Edit 3)
The load-bearing uncertainty is **does the chain phase REALLY assemble the two-zeros composition, or only look capable on paper?** Prove it on synthetic fixtures:
1. **Two-finding fixture** — Finding X: "anchor `K` defaults zero / no arming check" (STATE postcondition); Finding Y: "verifier accepts degenerate input whose derivation is zero" (STATE missing-precondition). Give X and Y **different anchor variable names** (slot vocabulary vs recovered-signer vocabulary), mirroring the real mismatch.
2. **Run the chain phase as-is** → confirm the failure mode: does STEP 2.1 produce **zero** chains because the strings differ? If it accidentally matches, the vocabulary-mismatch claim is weaker than asserted — re-scope Edit 3.
3. **Apply Edit 3 (role-based match) and re-run** → confirm it emits a chain hypothesis carrying a **justified Combined-Impact** (privileged effect under an unset anchor — a consequence neither half produces alone) that survives to verification.
4. **Precision probe:** a fixture with an *armed* (non-zero) anchor + sloppy input guard, and one with a zero anchor but a verifier that fails *closed* → confirm **neither** produces a chain (the composition must require *both* zeros). If either fires, Edit 3 over-matches — gate it behind the explicit mutual-zero harm assertion.
5. **Cross-boundary probe:** put the verifier contract *out of audited scope* → confirm Edit 2 makes the oracle lens emit `[EXTERNAL-ASSUMPTION: verifier unarmed]` with the escalation, without the in-scope signature flag.

If step 2 shows the engine already matches across vocabularies, downgrade Edit 3 to documentation only. If step 4 shows over-matching, gate the composition flag behind the explicit harm assertion before ship.

---
*Part-0 self-certification: this note names no protocol, token, contract, oracle, chain, struct, or function; all methodology is generic HOW-to-find-the-class content with a single unnamed illustrative example. Independently verified by the Claude reviewer against the live methodology tree.*
