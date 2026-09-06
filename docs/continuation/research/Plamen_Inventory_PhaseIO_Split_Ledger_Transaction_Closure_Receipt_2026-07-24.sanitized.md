# Plamen Inventory PhaseIO Split-Ledger Transaction — Closure Receipt

Date: 2026-07-24  
Repository: `<LOCAL_USER_ROOT>\plamen-codex-implementation`  
Disposition: **locally implemented and transaction-refrozen; no commit, push, install, or audit launch**

## 1. Outcome

The inventory I-1–I-4 PhaseIO transaction now has one explicit writer/owner
boundary per transition:

1. Attempt-scoped MODEL inventory shards produce only their assigned shard.
2. DRIVER canonical aggregation consumes an exact frozen shard denominator and
   emits:
   - `findings_inventory.md`
   - `finding_records.json`
   - `inventory_merge_receipt.md`
   - `inventory_id_allocation_delta.json`
3. A separate DRIVER/MERGE work unit consumes the immutable allocation delta
   and performs the only `_id_ledger.json` compare-and-swap transition.
4. Additive re-emission descends from the committed typed ledger-merge
   successor and cannot reinterpret a partial output as a new preimage.

The canonical aggregate no longer reads and writes the same global ID-ledger
artifact. Existing valid but untyped ledgers are admitted only through the
closed `plamen.strict_id_ledger.v1` external-preimage validator. That receipt
attests schema, exact identities, exact row fingerprints, policy digest, and
preimage bytes; it does not grant prior semantic truth or global ownership.

## 2. Safety properties established

- Pure chunk validation: validation writes no sidecars.
- Exact attempt ownership: shard MODEL outputs are attempt-scoped and
  backend-neutral.
- Exact source denominator: late shard, manifest, input, mode, backend, or
  output drift invalidates replay.
- Crash-resume: aggregate, merge receipt, ledger write, and additive re-emission
  partial states resume only from their exact armed predecessor.
- Compare-and-swap: concurrent compliant resumes converge to one exact
  successor; a third state is rejected without overwrite.
- Preserve-before-merge: LF/CRLF legacy rows and non-inventory identities remain
  present after a successful additive merge.
- Collision monotonicity: a same-ID/different-title-hash collision writes no
  successor, preserves the exact ledger bytes, and quarantines the work unit.
- Malformed preimage monotonicity: malformed legacy bytes are never armed or
  rewritten and remain visible as external-preimage validation debt.
- No legacy overwrite: once any canonical inventory plan/work unit exists,
  canonical debt checkpoints and exits degraded before the legacy
  `inventory/model` writer can launch.
- Receipt anti-forgery: status, authority, identity algebra, compatible-set
  intersection, predecessor/successor rows, and partial receipts are
  deterministically re-derived.
- Full-title identity: the allocation hash uses the complete title while the
  stored preview remains truncated to 120 characters.
- Exact JSON types: schema fields cannot pass by string coercion.
- Physical alias safety: the widened suite covers Windows case aliases,
  cross-root aliases, hardlinks, and symlink escapes.

## 3. Test evidence

### Fixture-first baseline

The initial split-ledger specification had **11/11 red fixtures** before the
implementation existed.

### Final focused refreeze

```text
python -m py_compile \
  scripts/external_preimage_authority.py \
  scripts/inventory_id_ledger_merge.py \
  scripts/inventory_aggregate_authority.py \
  scripts/phase_io_contracts.py \
  scripts/artifact_ledger.py \
  scripts/plamen_driver.py

python -m pytest -q \
  scripts/test_validated_external_preimage_p0_l.py \
  scripts/test_inventory_canonical_aggregate_phaseio_p0_l.py -x

66 passed
```

### Final widened inventory/identity/PhaseIO/assurance refreeze

The denominator included every `test_inventory_*.py` file plus validated
external prestates, PhaseIO contract/commit authority, three assurance-delivery
sets, legacy ID-ledger behavior, false-positive fixes, and canonical finding
identity mapping.

```text
292 passed
```

### Additional commit-controller blast radius

Artifact-ledger v2, phase-contract compiler, phase-commit controller,
structural ratchet, PhaseIO contract, and PhaseIO commit authority:

```text
123 passed
```

`git diff --check` passed for the stamped file boundary. The only output was
Git's informational LF→CRLF warning for `.gitignore`.

### Global smoke disposition

Scenario K was intentionally **not accepted as evidence** during this closure.
Its attempted run stopped at `bake:pre-execution` because the shared repository
methodology changed while the subprocess was running; the checkpoint had zero
completed phases and inventory was never reached. Other implementation agents
were editing the same tree. The root orchestrator directed that global smoke be
rerun only in a quiescent repository window.

## 4. Exact stamped file boundary

```text
471da0d755cfce9e35d261499130d241df985bf7a3be7a79f84ffd89cf201d7a  .gitignore
d4832e36e310d91999bd833380df3042c61504865ac90705f66ac68ca37d889c  scripts/plamen_validators.py
703793de7f2434c5bf555bccf181b31270acd28e2b2c27d1f5ad78203b8cb1a0  scripts/phase_io_contracts.py
34eb97753b5f834589939e44e398b77d9989c7e4cb5ee67050eecec64e7d1da7  scripts/artifact_ledger.py
26dda3e9011db912a1b2997aec38c53f53b56fcf182a40f6d190e612b38a87da  scripts/plamen_driver.py
aa195e19ab1ee9ee039241350664ae43d67b11d666816dfe459ed2a349eede29  scripts/inventory_reconciliation.py
05348fdd40cb4eff99630cda6f05435176b11c3d6fceee612fb3822ed92db46a  scripts/inventory_aggregate_authority.py
e207df1f4c530c515976e103d9984e45d4d9bb0959ac94302c1d4f11dc932825  scripts/inventory_id_ledger_merge.py
34e7f1802dd9adbe7f72c7a71a29dfe1fc540ec74bbde5219699a009c87ab023  scripts/external_preimage_authority.py
d6788ba811727dd55c228c1e6a4938b3fea8abcf2109042428de03bb22910e91  scripts/test_inventory_preferred_tag_default.py
90176229d001e70041c22cf1ee5b319f1ac726483928ad1974d2c4a0c2e5bf45  scripts/test_inventory_canonical_aggregate_phaseio_p0_l.py
96de1a2d243f8c8966986ebdc197fe8a1c84f871f3a0ba4373cf4139507a9c81  scripts/test_validated_external_preimage_p0_l.py
7c00a22300c25368c67ccbe834875f8bfd8b3270589a81642e36694695a35371  scripts/test_inventory_reconciliation_assurance_refresh.py
5695c37cc0b4e2040704e1a0f5da72f794b5c29454e83cf947318185702f075f  scripts/test_inventory_exact_reconciliation_p0_l.py
4859eef82de030abe2f49ad903b39b0cb23747fb9a6f90a24a1c85087dddfca7  scripts/test_inventory_reemit_repair_nc2.py
```

These hashes are a review boundary, not an authorization to merge or ship.

## 5. Deliberately unresolved acceptance conditions

### Global haltless behavior is not yet accepted

The new canonical-debt boundary safely stops before a conflicting legacy writer.
It does not yet prove the final repair-then-degrade target. Before
`TREE_QUIESCENT`, the program must either:

1. make downstream identity consumers operate safely from typed inventory and
   allocation-delta artifacts while exposing ledger debt, or
2. provide an explicit, authorized, collision-safe migration/repair
   transaction.

Malformed, collision, and CAS debt must never be silently cleared, and
candidates must not be lost.

### Separate validator-purity/owner-boundary wave is required

An independent read-only call-graph review found 89 production functions with
`validate/check/compute/read/parse/ensure/scan` name tokens and an intra-module
filesystem-sink path (five semantic false positives; six presently
unreachable/public-only).

The highest-priority residual is a possible **MODEL retro-bless** path:
`_run_phase_validators` runs before `_record_typed_model_phase_artifacts`, while
some validators can rewrite model primaries such as inventory, report body,
report index, spawn manifest, or template recommendations. Later registration
could therefore attribute DRIVER-repaired bytes to MODEL.

Other confirmed mutation classes include:

- ID-ledger collision/consumer validators that mutate the central ledger;
- invariant validation that can append recovery candidates;
- verifier precommit that creates a runtime roster outside its typed
  transaction;
- P0AF current-queue reads that can create/migrate queue authority;
- parsers/validators that write or remove debt, retry, parse-health, or coverage
  artifacts;
- severity reconciliation validation that rewrites its subject (currently no
  production caller).

Recommended closure is a dedicated purity wave:

- pure derive/validate APIs;
- explicit DRIVER publisher/repair transactions;
- MODEL-preimage → DRIVER-successor ownership receipts;
- crash fixtures at pre-arm, post-write, and pre-commit;
- a cross-module static lint rejecting filesystem sinks reachable from
  validation/read/parser functions, with narrow `artifact_producer` and
  `temp_only` annotations.

## 6. Final transaction verdict

The inventory split-ledger transaction is worthy of retaining and proceeding
with. It directly closes a structural finding-loss and attribution risk without
granting arbitrary legacy artifacts authority. It is not evidence that the
whole pipeline is finished: global smoke, downstream ledger-debt continuation,
and validator purity remain explicit program tasks.

