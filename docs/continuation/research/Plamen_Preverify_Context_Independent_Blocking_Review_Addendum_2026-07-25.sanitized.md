# Plamen Preverify/Context Independent Blocking Review Addendum

**Review boundary:** 2026-07-25T14:06:46.1017695+03:00  
**Disposition:** **NOT ACCEPTED / BLOCKING**  
**Authorization:** This is a review and fixture artifact only. It authorizes no merge, push, cutover, install, or audit.

## 1. Scope and reviewed state

This review independently attacked the current B1-B4 preverify successor and B3 optional-context live integration at:

`<LOCAL_USER_ROOT>\plamen-codex-implementation`

The review specifically tested:

- current-generation recomputation boundaries;
- exact-input denominator completeness;
- optional-context snapshot, selection, arming, and commit drift;
- compound-chain producer authority;
- SC/L1, backend, mode, ecosystem, and run isolation;
- safe-base debt behavior; and
- absence of `chain.degraded` mutation.

The exact reviewed implementation boundary was:

| Artifact | SHA-256 |
|---|---|
| `scripts/preverify_inventory_successor.py` | `18BADD815AE8B6FAD64BA3E8DBA87585696C08BA35DC89CF844BC9813090EBC9` |
| `scripts/verify_queue_context_authority.py` | `3FD342F95005FD360F15D0109147DB35A0D4B3F5BC51A260832FFF9340BDD8CE` |
| `scripts/plamen_driver.py` | `FDC91ED4847F2B0A331882F4E0C51D95A5426BC9844278582DF8DA8481A83479` |
| `scripts/plamen_parsers.py` | `CA46742D295CF26A611286670087B88E98E4FFC7FDECA48EA687B247B794435D` |
| `scripts/phase_io_contracts.py` | `B52A3004E369D1AE38DD0CE4E0BEA0B8B222BDF33BA424E5D76C1C28CF938A31` |

The new independent fixture is:

`scripts/test_preverify_context_authority_independent_blocking_20260725.py`

SHA-256:

`B7E4353AC736CFB6BA56E9A80F68209AC2B8D4AF8678335D29D77F7EA82465A3`

No production file or pre-existing test was modified by this review. The fixture remains untracked and unchanged.

## 2. Blocking verdict

Four independently reproduced defects prevent acceptance.

### B1. Content identity is being mistaken for producer authority

The successor captures exact hashes and recomputes its generation, but a schema-valid PhaseIO record can still classify unowned scratchpad bytes as active when `producer_work_unit_key` and its digest are empty. Producer validation is conditional on the producer key being present. As a result, the capture transaction can faithfully hash and commit bytes whose origin it never established.

The blocking fixture creates a present v2 ledger, an unowned inventory, paired `finding_records.json`, and a registered capture producer. Capture returns no issues and commits the unowned semantic preimages.

**Required correction:**

- Add a capture-specific strict preflight under which every scratchpad semantic input must have current-run active producer authority or a narrowly defined, validated external-preimage receipt.
- Treat inventory and finding records as one current, same-owner, additive successor pair.
- Require registry-producer artifacts to have current-run ownership.
- Derive mutation lineage from ledger authority, not path presence.
- If legacy/no-ledger compatibility is retained, isolate it behind an explicit migration or test-only path; it must not silently weaken production authority.

Recomputation is necessary but does not cure this defect: it proves that the same bytes were used, not that those bytes were authorized.

### B2. Successor authority is not isolated by runtime tuple

Stable successor payloads bind a run identifier but not the complete runtime identity. The validator takes its expected run from the payload itself, while the routing arm accepts an owner ending in `/preverify_successors`. A successor captured for one configuration can therefore be armed under a different backend, mode, ecosystem, pipeline kind, or run.

Five independent cases reproduced successful arming of an SC/Thorough/EVM/Claude successor under:

- Codex backend;
- Core mode;
- Solana ecosystem;
- L1 pipeline; and
- a different run.

Every case returned `execute=True` with no issues. A later commit check is not sufficient: the arm-before-trust boundary has already been crossed and derived outputs may already have been written. Same-run cross-dimension substitution can also evade a run-only boundary.

**Required correction:**

- Bind `pipeline_kind`, `mode`, `ecosystem`, `backend`, and `run_id` into the capture plan, generation identity, and stable successor pair.
- Pass the expected current runtime tuple into the validator; never derive the expected authority from the candidate payload.
- Require the exact producer-key prefix, phase, and registered producer-to-consumer relationship before routing arms.
- Treat a backend change as a new generation.

### B3. Compound-chain authority is not mode-correct and drops valid Core evidence

The declared context policy allows `chain/state_resolution` in all modes and permits `chain_iter2/tail_reconcile` only in Thorough mode. The live compound adapter does not implement that policy. When a typed source exists, it hard-requires committed ancestry from `/chain_iter2/tail_reconcile`.

The blocking fixture supplied:

- a legitimate `chain/state_resolution` typed candidate; and
- a committed `ChainAgent2` compound finding.

In Core mode, routing failed with:

`chain-tail typed candidate lacks committed final producer ancestry`

Core has no Thorough-only tail-reconcile phase. The earlier typed state-resolution sidecar also shadows the later committed ChainAgent2 result. This is a direct recall loss, not merely a provenance-hardening concern.

**Required correction:**

- Make final compound-producer authority mode-aware.
- In Light/Core, either emit a typed post-ChainAgent2 final compound successor or consume the committed ChainAgent2 output directly.
- Do not let an initial state-resolution sidecar shadow later, current chain work.
- In Thorough, retain the exact final tail authority whenever that phase is prepared or present.
- Preserve strict failure on stale or malformed final-authority artifacts; do not add permissive fallback.

### B4. Compound-delivery debt is a hidden semantic input

`_write_empty_compound_adapter_artifacts_from_delivery_debt` derives compound outputs from `compound_verification_delivery_debt.json`, but the outer routing transaction does not bind the compound receipt/debt as an exact input and does not delegate the derivation to a typed child work unit.

The blocking fixture created valid compound-delivery debt after the arm. The debt generated compound outputs, and the outer routing commit reported no issues even though those outputs depended on an unbound input.

**Required correction:**

- Move conditional compound-delivery handling into a separate typed child transaction.
- Require receipt XOR debt, with exact bytes, current-run ownership, and current generation.
- Bind the debt before deriving safe-base outputs.
- Validate the receipt digest as well as its schema and ownership.
- Make outer routing consume the child status/output rather than rediscovering the mutable path.
- Enforce registered contract lineage rather than hard-coding a suffix that would prevent future valid producers.

This also demonstrates that the current exact-input denominator remains incomplete. Compound receipt/debt, queue evidence excluded/debt projections, and mandatory nested receipts must be audited as semantic inputs or typed child outputs.

## 3. Evidence

### Independent blocking fixture

Command:

```text
python -m pytest -q --tb=short scripts/test_preverify_context_authority_independent_blocking_20260725.py
```

Result:

```text
8 failed, 2 passed in 4.19s
```

The eight red cases are the B1 authority failure, five runtime-isolation failures, the Core compound-authority recall failure, and the unbound compound-debt input failure.

### Existing focused acceptance lane

Command:

```text
python -m pytest -q --tb=short scripts/test_preverify_inventory_successor_p0_al.py scripts/test_preverify_successor_provenance_blockers_p0_al.py scripts/test_verify_queue_context_authority_provider_b3.py scripts/test_verify_queue_optional_context_ownership_b3.py
```

Result:

```text
79 passed in 3.87s
```

These green tests establish that current-generation recomputation, late-producer detection, ordinary mutation-after-arm checks, paired finding-record freshness, and the existing provider cases remain intact. They do not cover the four blocking authority and denominator defects above.

### Fixture integrity

Commands:

```text
python -m py_compile scripts/test_preverify_context_authority_independent_blocking_20260725.py
git diff --check -- scripts/test_preverify_context_authority_independent_blocking_20260725.py
git status --short -- scripts/test_preverify_context_authority_independent_blocking_20260725.py
```

Results:

- compilation: pass;
- diff check: pass;
- status: only the new untracked fixture.

## 4. Green findings and residual limits

- Ordinary post-arm optional-context drift is detected by live PhaseIO input validation.
- Safe-base optional-context debt writes queue-owned `COMPLETED_WITH_DEBT_SAFE_BASE`, sets `safe_base_routing=True` and `proof_authority=NONE`, and preserves pre-existing `chain.degraded` bytes exactly, including CRLF bytes.
- No active verify-queue optional-context path was found that mutates `chain.degraded`.
- The snapshot/selection provider has a strong fixed policy, exact owner prefix for the selected runtime, same-run enforcement, hash/size binding, pair handling, and safe-base debt.

Residual concurrency limitation: consumers still reread live paths instead of exclusively consuming frozen `AcceptedContext.content`. Pre/post hash checks can miss a mutate-read-restore ABA race. This review did not classify that as a separate reproduced blocker because the accepted design permits bind-and-revalidate, but acceptance must either document a single-writer/no-concurrent-mutation assumption or move child consumers to immutable accepted-content capabilities.

The safe-base green case covers the direct arm path. Retry and failure paths still need a full phase matrix before claiming universal non-mutation of `chain.degraded`.

## 5. Document boundary

The review was checked against the following artifacts:

| Artifact | SHA-256 |
|---|---|
| `Plamen_Preverify_Successor_Independent_Blocking_Review_2026-07-25.md` | `260588EE1E2640155886E5951197724DE48F10EB95E350220AE451BDA3CBFD73` |
| `Plamen_Goal_Acceptance_Ledger_2026-07-17.md` | `0D05542B851609A1B81565BD69F7824AC8C677B2440FF072D50DD79F4EC66060` |
| `Plamen_Plan_Completion_Audit_2026-07-24.md` | `357E049C1A738D2E8682F1F2E0C339DAD77D876172E7CF0F1DDC8BF6D947A5DE` |
| `Plamen_Inventory_PhaseIO_Split_Ledger_Transaction_Closure_Receipt_2026-07-24.md` | `C1EE9934C260798F6B91987D377C177AFFEC4F40FD2BECF5EBBAAC2D78E47333` |

Production changed concurrently during the review, including a correction that now requires paired `finding_records.json`. The fixture was rebased to the corrected denominator. All findings and hashes in this document refer only to the exact timestamped implementation boundary in Section 1; later modifications require rerunning this fixture and the focused acceptance lane.

## 6. Acceptance boundary

The preverify/context successor is not ready for acceptance until:

1. all ten tests in the independent fixture pass for the intended authority rules;
2. the existing 79-test focused lane remains green;
3. new red-to-green fixtures prove exact current-runtime and producer/consumer lineage;
4. compound delivery is made an explicit typed transaction or otherwise fully bound in the outer exact-input denominator;
5. Core and Thorough compound authority each have positive and stale/malformed negative cases;
6. a full retry/failure matrix confirms that queue-owned debt never mutates chain-owned degradation state; and
7. the broader blast-radius suite passes on the same source hashes.

This review performed no production edit, existing-test edit, commit, push, install, or audit.
