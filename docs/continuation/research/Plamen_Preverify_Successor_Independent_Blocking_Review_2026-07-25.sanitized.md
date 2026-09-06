# Plamen Pre-Verification Successor / Queue — Independent Blocking Review

Date: 2026-07-25  
Repository: `<LOCAL_USER_ROOT>\plamen-codex-implementation`  
Disposition: **NOT CUTOVER-READY; NOT TREE_QUIESCENT**  
Authorization: **none** — no commit, push, install, or audit launch

## Reviewed implementation

The review covered the final-inventory → registered-delivery → verification-
queue successor wave, including:

- `scripts/preverify_inventory_successor.py`
- `scripts/phase_io_contracts.py`
- `scripts/plamen_driver.py`
- `scripts/plamen_validators.py`
- `scripts/mandatory_reverification.py`
- `scripts/plamen_mechanical.py`
- `scripts/plamen_parsers.py`
- the focused successor, compound, dynamic-verifier, queue-ledger, and smoke
  fixtures.

The implementer reported 76/76 focused tests and the root independently
reproduced 76/76. Those results establish useful local behavior, but several
fixtures encode false authority and the transaction is not accepted.

## Blocking findings

### B1 — False provenance root in the content-addressed capture

`preverify_capture.<digest>` declares `exact_inputs=()`, although its generated
payload semantically observes the final inventory, registered producer bytes,
mutation authorities, registry-derived delivery state, and transitive
enum-gap/exploration authorities.

Content addressing proves internal byte consistency, not active-owner
provenance. Because this generation is the sole immutable input to the stable
successor receipts and then to queue routing, the zero-input contract can
legitimize bytes that were directly mutated outside an owner transition.

Required correction:

- derive the exact dynamic semantic-input roster before parsing;
- require current-run ACTIVE owners or a narrow validated external preimage;
- bind the exact scratchpad and project-locus inputs before capture;
- include the registry/method digest in the contract identity;
- re-enumerate the roster and revalidate inputs before commit;
- derive mutation lineage from the ledger rather than a static filename list.

### B2 — Live-inventory TOCTOU after queue arm

Both SC and L1 queue paths finalize and arm the successor, then read and rewrite
from live `findings_inventory.md`. The routing contract binds the successor
JSON files but not the live inventory. A reproduced mutation after arm changed
the routed finding identity, and queue commit still returned clean.

Required correction:

- either route exclusively from an immutable content-addressed inventory
  snapshot; or
- bind the exact live inventory and every other semantic source at arm and
  revalidate them at commit.

### B3 — Unbound optional context is accepted when a ledger exists

An existing optional file with no `artifact_bindings` entry is currently
included even when `_artifact_state.json` exists. One focused fixture
explicitly expects this behavior.

Required correction:

- compatibility applies only when no ledger exists at all, or through an
  explicit legacy/test-only entry point;
- present ledger plus missing binding means omit plus visible typed debt.

### B4 — Routing resolver silently weakens mandatory inputs

The routing resolver accepts an empty `exact_inputs` denominator and silently
falls back to `findings_inventory.md`.

Required correction:

- reject any routing contract that lacks the mandatory stable successor pair;
- also require the live inventory if routing continues to read it;
- no implicit fallback at the authority boundary.

### B5 — Outer queue output denominator is incomplete

Live SC and L1 replays create undeclared outputs while the outer routing work
unit still commits cleanly. Confirmed examples include:

- `compound_verification_delivery_receipt.json`
- `compound_verification_delivery_debt.json`
- `verification_queue_evidence_excluded.md`
- `verification_queue_evidence_excluded.json`
- `verification_queue_evidence_debt.md`
- `verification_queue_evidence_debt.json`
- `finding_records.json`
- `mandatory_reverification_queue_transaction.receipt.json`

Required correction:

- remove `finding_records.json` from the queue boundary and publish it with the
  paired inventory owner before capture;
- declare queue exclusion/debt projections;
- model mutually exclusive delivery/debt and nested transaction status as
  typed conditional outputs or separate child work units.

### B6 — Queue arm mutates another phase’s debt artifact

`_set_verify_queue_optional_context_debt` rewrites or deletes `chain.degraded`
before the routing transaction is armed.

Required correction:

- publish an always-present, schema-valid queue-owned optional-context status;
- do not mutate the chain phase’s artifact from queue routing.

### B7 — Empty compound fallback lacks producer authority

The schema-valid empty compound fallback consumes the bytes of
`compound_verification_delivery_debt.json`, but that artifact is neither a
routing immutable input nor a declared output. The mutually exclusive
receipt/debt state is outside PhaseIO.

Required correction:

- publish compound delivery disposition through a typed conditional
  producer/status transaction;
- bind its exact bytes before deriving empty candidate/work-plan outputs.

## Missing acceptance tests

Transaction-specific failpoint and foreign-state fixtures are required for:

- crash after capture arm;
- capture output written before commit;
- only one of the two stable successor outputs written;
- partial outer queue output set;
- input mutation after arm;
- arbitrary foreign third state;
- stale/missing owner;
- malformed or partial artifact ledger;
- a new producer/mutation artifact appearing after roster enumeration;
- exact resume and successor refresh.

The matrix must cover SC and L1. Backend parity must cover Claude and Codex
after the semantic transaction is correct.

## Exact semantic-input denominator discovered so far

The zero-input capture actually depends on:

1. `findings_inventory.md`;
2. the exact registry-materialized producer roster and bytes;
3. every present inventory-mutation authority;
4. registry payload/digest and parsing-method TCB;
5. exploration-clear receipts, obligations, and bound source artifact;
6. enum-gap worklist, model output, disposition receipt, and residual
   obligations;
7. current enumeration obligations and exploration-clear receipt/queue;
8. optional prior-alias and canonical-finding-ID authorities;
9. optional enum-gap promotion receipt and inventory-append commit;
10. project-locus files revalidated by enum-gap CLEAR dispositions;
11. artifact-ledger lineage as transactional control state, not as an ordinary
    immutable data input.

The denominator must be produced by pure enumeration and rechecked for
late/new artifacts. Merely validating rows listed in the successor payload is
not a completeness proof.

## Corrective sequence

1. Stabilize inventory owners and bind the capture’s exact dynamic inputs.
2. Require strict routing inputs and remove live-source TOCTOU.
3. Close every output and conditional child-work denominator.
4. Add the transaction-specific crash/resume/third-state matrix.
5. Rerun focused and full smoke only on a quiescent tree.

## Verdict

The successor concept is still worth retaining: a final, stable
inventory/delivery authority is necessary because producer-local receipts go
stale after additive repair. The current implementation is not accepted
because it converts a valid freshness observation into stronger provenance
authority than its inputs justify. No cutover or `TREE_QUIESCENT` claim is
permitted until B1–B7 and the fault matrix are closed.
