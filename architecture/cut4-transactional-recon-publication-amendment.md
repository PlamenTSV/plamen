# Cut-4 transactional recon publication amendment

Date: 2026-08-10
Status: Part-0 architecture only
Authority: implementation design; no production GREEN, cutover, release, or
audit-readiness claim

## 0. Decision and boundaries

Cut-4 shall use two deterministic DRIVER transactions and no public
write-discovery:

1. `recon/prepass` owns one immutable, typed, private seed namespace.
2. `recon/canonical_merge` is the sole owner of the stable SC or L1 canonical
   recon files and `recon_signal_transform_receipt.json`.

The exact output bundles are compiled from one registry before either
transaction is armed. Pipeline, ecosystem, normalized config, and the selected
provider plan are inputs to that compilation. A provider result may change
typed content, never the output-path denominator. MODEL shard work units and
the existing dependency units are unchanged.

This is the smallest architecture that closes the real ownership gap. It does
not copy the accepted V7 fixture's selected 11-file prepass tuple into
production. The real EVM prepass can currently attempt at least 18 public
files, and optional scanners add more. Registering only the V7 subset would
leave found output unowned and preserve the Cut-4 defect.

Part-0 has no protocol-analysis hints, prompt changes, MethodCard authority,
G3 authority, or G3 pin/hash changes. `scripts/artifact_ledger.py` remains
unchanged. The amendment does not edit production or tests.

## 1. Authenticated basis

The accepted bounded V7 review is
`review_fixtures/phaseio_cut4_recon_red_v7_independent_review_r1_20260809.md`,
SHA-256
`c8e19b0f089b3e671e5191244aed2e56e277b20190b6db7d06087b1e4fd39223`.
It independently proved a contract-derived complete-set predicate over 11
fixture prepass outputs and 12 SC canonical/transform outputs, plus exact
owner, attempt, generation, path, byte, order, no-op, debt, and representative
live-callsite controls. Its claim ceiling is a bounded RED denominator, not a
production inventory.

The relevant current implementation surfaces are:

- `scripts/phase_io_contracts.py`: `_RECON_CANONICAL_OUTPUTS`,
  `_L1_RECON_CANONICAL_OUTPUTS`, `resolve_phase_io_contract()`, and the current
  `recon/prepass` and `recon/canonical_merge` branches;
- `scripts/recon_prepass.py`: `run_recon_prepass()` and all current mechanical,
  graph, build, niche, tool-ledger, and optional-provider writers;
- `scripts/plamen_mechanical.py`: `_merge_recon_worker_shards()`,
  `_merge_l1_recon_worker_shards()`, and marker helpers;
- `scripts/plamen_driver.py`: `_recon_worker_jobs()`, dependency wave/parity,
  fanout, completed-resume, and phase-loop degrade callsites; and
- `scripts/dependency_obligations.py`: deterministic dependency enumeration and
  reconciliation renderers.

The live inventory establishes these correction points:

- production `recon/prepass` currently registers only `meta_buffer.md` and
  `external_dependency_research.md`;
- the ordinary non-DAML SC prepass attempts 13 baseline files;
- EVM normally adds two niche files, `_mechanical_graph.json`, and the two
  tool-coverage ledger files, for an observed 18-file public denominator when
  external providers are unavailable;
- optional graph/scanner success and failure can currently change public path
  membership;
- L1 unconditionally attempts eight prepass files while its canonical
  projection is seven files; and
- canonical merge writes `recon_signal_transform_receipt.json`, but the current
  canonical PhaseIO contract omits it.

## 2. Ownership graph

The new graph is closed and acyclic:

```text
exact project/config inputs
        |
        v
recon/prepass (DRIVER, one private namespace)
        |                     existing dependency units
        |                               |
        +-----------+-------------------+
                    |
existing recon/worker.* MODEL shards
                    |
                    v
recon/canonical_merge (DRIVER, sole canonical owner)
                    |
                    +--> canonical SC/L1 files
                    +--> recon_signal_transform_receipt.json
                    |
                    v
optional recon/supplementary_disposition sidecar
                    |
                    v
existing instantiate/breadth consumers
```

There is no `recon/resume_marker_strip` owner and no `recon/prepass_degrade`
owner. Resume, marker normalization, degrade, and shard remerge are causes for
deterministic reexecution of `recon/canonical_merge`; they do not acquire the
canonical paths. No provider process owns a scratchpad or project-root path.

## 3. The registry and exact plan

### 3.1 One compiler

Add pure registry types and `compile_recon_publication_plan()` in
`scripts/phase_io_contracts.py`. The compiler accepts only normalized typed
values:

- pipeline and ecosystem (canonical PhaseIO key dimensions);
- mode and backend (recorded even when they do not change a bundle);
- a closed config projection, excluding runtime-only and secret values;
- a closed provider plan whose provider IDs come from the registry; and
- a sorted, alias-free exact project-input capture.

It returns an immutable plan with registry version, exact ordered seed outputs,
exact provider slots, exact MODEL/dependency input identities, exact ordered
canonical outputs, a projection map, and one stable digest. The resolver and
renderers consume this same plan; no second SC/L1 tuple is maintained in
`plamen_mechanical.py`.

The plan shape is equivalent to this valid JSON example:

```json
{
  "schema": "plamen.recon_publication_plan.v1",
  "registry_version": "cut4.recon.v1",
  "dimensions": {
    "pipeline": "sc",
    "mode": "core",
    "ecosystem": "evm",
    "backend": "codex"
  },
  "provider_plan": [
    {"provider_id": "build_probe", "enabled": true},
    {"provider_id": "opengrep", "enabled": false},
    {"provider_id": "slither", "enabled": true},
    {"provider_id": "source_graph", "enabled": true}
  ],
  "seed_root": "_recon/prepass_seed",
  "canonical_outputs": [
    "recon_summary.md",
    "design_context.md",
    "attack_surface.md",
    "state_variables.md",
    "function_list.md",
    "contract_inventory.md",
    "template_recommendations.md",
    "detected_patterns.md",
    "setter_list.md",
    "emit_list.md",
    "build_status.md",
    "recon_signal_transform_receipt.json"
  ]
}
```

Lists are already in registry order. JSON object keys are encoded in sorted
order for hashing. The compiler rejects unknown providers, duplicate or
case-fold-colliding identities, absolute paths, dot/parent components, glob
metacharacters, output/input overlap, and an empty output bundle.

### 3.2 Private prepass seed bundle

`recon/prepass` owns every path below `scratchpad:_recon/prepass_seed/` and no
other path. Every output is DRIVER-generated, `REPLACE`, typed, nonempty, and
bound to the exact contract. The fixed base bundle is:

| Path under `_recon/prepass_seed/` | Typed responsibility |
|---|---|
| `plan.json` | Exact registry/provider/projection plan and digest |
| `source_capture.json` | Sorted project input identities, hashes, sizes, and capture debt |
| `base_evidence.json` | Contracts/subsystems, functions, state, setters/disclosures, and source loci |
| `design_evidence.json` | Design, threat, attack, trust, and scope evidence as applicable |
| `template_pattern_evidence.json` | Template recommendations, flags, and pattern rows |
| `build_evidence.json` | Canonical build capability result or typed limitation |
| `mechanical_graph.json` | Precise graph, deterministic approximation, or explicit approximation debt |
| `niche_findings.json` | Complete deterministic niche rows, including explicit zero |
| `dependency_seed.json` | Pre-research dependency rows or typed zero; not the public reconciled ledger |
| `tool_coverage.json` | One composed tool coverage record; no competing ledger writers |
| `render_seed.json` | Normalized headings/context needed for canonical rendering |
| `namespace_capture.json` | Planned/observed private namespace equality and sibling byte records |

For every provider registered for the selected ecosystem, the compiler also
adds exactly these three paths, irrespective of enabled state or terminal
outcome:

```text
_recon/prepass_seed/providers/<provider-id>/outcome.json
_recon/prepass_seed/providers/<provider-id>/evidence.json
_recon/prepass_seed/providers/<provider-id>/debt.json
```

Disabled is a typed terminal outcome, not absence. An enabled provider that is
unavailable, times out, exits nonzero, emits malformed data, or cannot be
canonically represented still writes all three nonempty slots. `evidence.json`
contains an explicit typed zero; `debt.json` is OPEN with exact reason codes.
Success writes the same paths with evidence and a CLEAR debt state. A typical
outcome has this valid shape:

```json
{
  "schema": "plamen.recon_provider_outcome.v1",
  "provider_id": "slither",
  "enabled": true,
  "terminal_state": "UNAVAILABLE",
  "evidence_count": 0,
  "reason_codes": ["EXECUTABLE_NOT_AVAILABLE"]
}
```

Provider raw output exists only inside an attempt-private execution root. It
is parsed into the typed evidence slot and never moved directly to a public
path. The provider plan therefore fixes the denominator before execution, and
provider success/failure cannot make an output disappear.

### 3.3 Namespace capture and conservation

`namespace_capture.json` records:

- the exact contract output identities in registry order;
- an exact sorted walk of the attempt-private seed staging root;
- equality between those two sets, including case-fold equality;
- `{sha256,size}` for every sibling output (the capture receipt excludes its
  own digest to avoid recursion; ArtifactLedger binds its bytes);
- the exact project-input capture digest;
- zero attempted public scratchpad writes by prepass;
- zero project-root writes by prepass/providers; and
- every evidence row's stable identity and later projection disposition.

The private walk is a containment check, not output discovery. Public outputs
are never inferred from a glob, a directory walk, or files observed after a
writer ran. An unexpected private file fails containment and produces a
quarantined transaction; it is not adopted.

## 4. Provider and platform isolation

All external commands run in an attempt-private provider workspace created by
the DRIVER. The child receives read-only/copy-on-write source inputs and an
allowlisted environment. Its cwd, cache, result, and temporary config roots
are inside that workspace. The provider API returns bytes/typed records to the
DRIVER; it receives no writable scratchpad or project-root handle.

Foundry never creates or edits project-root `foundry.toml`, `out/`, cache, or
dependency state. When the selected source lacks config, the DRIVER creates a
transaction-private Foundry overlay from the captured manifests/remappings,
runs Foundry against that overlay, and discards it after typed capture. The
project tree is snapshotted before/after provider execution; any mutation is a
provider isolation failure and opens debt. It is never normalized into a clean
outcome.

Windows locked-destination/rename errors, POSIX permission errors, symlink or
junction escapes, path-length failures, process timeouts, and malformed output
are terminal typed failure outcomes. A provider failure is haltless for recon
only because its debt slot is nonempty and downstream-bound. A transaction or
containment failure is not haltless: it leaves the prior generation
authoritative or quarantines the new attempt before any consumer.

## 5. Canonical projection and exclusive ownership

### 5.1 Exact outputs

The plan derives the canonical projection from the same registry used for the
seed bundle.

SC publishes exactly the existing 11 canonical Markdown files plus the
transform receipt:

```text
recon_summary.md
design_context.md
attack_surface.md
state_variables.md
function_list.md
contract_inventory.md
template_recommendations.md
detected_patterns.md
setter_list.md
emit_list.md
build_status.md
recon_signal_transform_receipt.json
```

L1 publishes exactly the existing seven canonical Markdown files plus the
transform receipt:

```text
recon_summary.md
threat_model.md
subsystem_map.md
attack_surface.md
trust_boundaries.md
template_recommendations.md
scope_leftover.md
recon_signal_transform_receipt.json
```

`recon/canonical_merge` is the only owner and writer of those paths. It binds
the complete committed `recon/prepass` seed bundle, the unchanged exact MODEL
shards selected by `_recon_worker_jobs()`, and the unchanged dependency
obligation/research/reconcile outputs. Dependency reconcile completes before
canonical arm. The merge does not read its prior public outputs as semantic
inputs.

The transform receipt is part of the same atomic output denominator. For each
seed/provider/model/dependency row it records source digest, row count,
normalization, destination section or `RETAINED_PRIVATE` consumer, and one of
`PROJECTED`, `EXPLICIT_ZERO`, or `DEBT`. Exact source-row conservation is a
minimum gate. No evidence row may be silently dropped merely because a parser
or provider produced no legacy filename.

### 5.2 Supplementary disposition

The current idea of an inline fallback rewriting `attack_surface.md`,
`detected_patterns.md`, `setter_list.md`, or `emit_list.md` is retired. Those
paths already belong to canonical merge.

If post-render validation needs a durable disposition, register
`recon/supplementary_disposition` with one output only:

`scratchpad:recon_supplementary_disposition.json`.

It binds the canonical transform receipt, writes no canonical file, and says
CLEAR or DEBT with exact missing section/row identities. Downstream clean gates
must bind it. Deterministically repairable content belongs in the canonical
renderer before commit; a later canonical change is another canonical-merge
reexecution, never a supplementary co-writer.

## 6. PhaseIO keys, contracts, and V7 correction

The operative keys remain ordinary six-component keys:

```text
<pipeline>/<mode>/<ecosystem>/<backend>/recon/prepass
<pipeline>/<mode>/<ecosystem>/<backend>/recon/worker.<agent>
<pipeline>/<mode>/<ecosystem>/<backend>/recon/dependency_obligations
<pipeline>/<mode>/<ecosystem>/<backend>/recon/worker.r-ext
<pipeline>/<mode>/<ecosystem>/<backend>/recon/dependency_reconcile
<pipeline>/<mode>/<ecosystem>/<backend>/recon/canonical_merge
<pipeline>/<mode>/<ecosystem>/<backend>/recon/supplementary_disposition
```

`recon/prepass` and `recon/canonical_merge` are `model_invoked=False`, require
commit actor DRIVER, use exact output manifests, reject zero-byte members, and
bind an exact `LaunchSpec`. MODEL shard contracts and dependency contracts do
not change. Instantiate continues to bind its exact eight recon consumers plus
the separate skill row; breadth continues to bind its exact six recon inputs,
but both now require the current `canonical_merge` producer binding.

The accepted V7 fixtures remain byte-frozen. A copy-on-write successor RED
denominator replaces these four invalid production expectations:

| Invalid V7 expectation | Replacement RED |
|---|---|
| A successor is a manually inserted `<canonical-key>/attempt-N` work-unit key. | `test_reexecution_reuses_canonical_key_and_increments_commit_ordinal`: the six-component key is unchanged; existing commit authority and `semantic_reexecution_history` carry the next ordinal/history. |
| Changing `language` retries beneath the old ecosystem key. | `test_ecosystem_change_rejects_old_key_and_selects_new_key`: ecosystem drift rejects the old binding and resolves a different canonical key or requires a new run. |
| Truncating an output then calling `read_artifact_ledger()` mutates authority. | `test_zero_byte_requires_explicit_reconciliation_before_quarantine`: reads are pure; an explicit validation/reconciliation call detects zero bytes and quarantines/degrades. |
| A glob over `recon_unplanned_semantic*.md` is an authority input. | `test_namespace_capture_rejects_unregistered_private_write_without_glob_denominator`: the precompiled namespace is authoritative; an extra private write fails exact containment and is never adopted. |

The V7 complete-set, owner, byte, order, reason/debt, no-op, MODEL lifecycle,
dependency, and consumer controls remain useful. Its selected SC 11-output
prepass tuple is not promoted to the registry.

## 7. Transaction protocol and recovery

Both DRIVER producers use a shared new helper in planned file
`scripts/recon_publication_transaction.py`. It composes existing
`scripts/artifact_ledger.py` APIs; the ledger module itself is frozen.

For one execution:

1. Compile and digest the registry plan and exact input capture.
2. If the same committed contract, inputs, outputs, bytes, and bindings replay
   exactly, return immediately. Do not invoke providers, touch mtimes, append
   history, or rewrite the ledger.
3. Render every new output to an attempt-private stage, normalize and validate
   it, reject zero bytes, and verify exact stage/contract set equality.
4. Call `plan_driver_successor_transaction()` with the complete immutable byte
   mapping, then `record_work_unit_inputs()` with that exact successor plan.
5. Publish the ordered tuple under the ledger/process lease, using the existing
   successor step APIs and same-volume backup/stage files. No consumer may run
   while the transaction is armed.
6. Call `record_work_unit_artifacts(..., actor="DRIVER",
   expected_output_records=...)` and validate the complete committed tuple.
7. Remove transaction-private backup/stage data only after commit validation.

The named failpoint order is fixed:

```text
after_capture -> after_arm -> after_stage -> after_publish -> before_commit
```

On restart, the same public entry point first calls
`load_driver_successor_plan()` and validates live progress. If every public
member equals the sealed postimage, it finishes the commit. Otherwise it
restores the complete sealed preimage (including explicit absence), validates
all-old equality, and either retries from the sealed stage or records typed
quarantine/debt. A mixed tuple is never released to a PhaseIO consumer. Thus
recovery exposes only all-old authoritative bytes or all-new committed bytes.

Input drift uses `authorize_deterministic_work_unit_reexecution()` before any
overwrite, reuses the canonical work-unit key, and preserves the existing
`semantic_reexecution_history`. Output-only drift is tamper, not refresh
authority. It is quarantined/recovered before replay.

Marker strip, marker degrade, completed resume, and shard remerge are canonical
producer causes such as `LEGACY_MARKER_NORMALIZATION`, `PREPASS_DEGRADE`, and
`RESUME_RECONCILIATION`. They alter a committed seed/policy input and then
reexecute `recon/canonical_merge`; they are not separate work units. An exact
resume is a strict no-op. New canonical outputs never contain the legacy
prepass marker.

## 8. Determinism and precision rules

- Text is NFC-normalized UTF-8 without BOM and with LF endings and one terminal
  newline.
- JSON rejects duplicate keys and non-finite numbers, distinguishes booleans
  from integers, uses sorted keys and registry-ordered arrays, and hashes the
  compact UTF-8 representation.
- Source/private walks sort canonical relative POSIX paths before reading;
  case-fold collisions, symlink/junction escapes, unstable reads, and path
  aliases are debt or rejection.
- Sets/maps from parsers are sorted by stable typed row identity before
  encoding. Provider order, filesystem enumeration order, timestamps, absolute
  temp paths, and process IDs do not enter semantic bytes.
- A provider result that cannot be represented canonically becomes typed
  approximation debt. It is never converted to a clean empty graph or safe
  conclusion.
- Every committed semantic output must have size greater than zero. A typed
  zero is a nonempty schema-valid document.

Recall improves because every detected row has one registry identity, one seed
owner, and a conservation disposition; provider failure cannot shrink the
denominator; and later writers cannot overwrite earlier evidence. Precision
improves because raw provider noise remains private, canonical output has one
renderer, aliases/extras/zero bytes are rejected, and explicit debt cannot be
mistaken for evidence of safety.

## 9. Existing scratchpads and compatibility

Startup distinguishes four states before any recon consumer:

1. **Fresh/no legacy bytes.** Run the new prepass and canonical transactions.
2. **Incomplete legacy recon.** Read only the registry's exact legacy roster;
   capture recognized nonempty bytes into typed private seed records, label
   their provenance, and rewind/reexecute recon. Do not glob or adopt unknown
   files.
3. **Completed checkpoint with legacy canonical bytes but no Cut-4 authority.**
   Capture the exact known tuple and markers into the private seed transaction,
   place public legacy files in the transaction backup, and republish through
   `recon/canonical_merge`. Completion is honored only after its full commit.
4. **Incompatible, zero-byte, mixed, aliased, or unrecoverable state.** Restore
   the last exact preimage where possible; otherwise record explicit migration
   debt and use the existing safe recon rewind/degraded exit. Never bless it as
   a current generation.

Legacy markers are provenance in the private capture, not public ownership.
Known legacy graph/niche/tool outputs are losslessly normalized into the typed
seed aggregates before their old paths are retired. Current stable SC/L1
canonical names remain unchanged for downstream compatibility. Consumers of
legacy graph/tool/niche paths must bind the typed seed artifacts or transform
receipt; no compatibility shim may recreate a public shared writer.

An existing active work unit whose static contract differs from
`cut4.recon.v1` is not silently rewritten. It requires the bounded migration
path/new run or degrades. G3 vectors and pins are not regenerated or changed by
this cut; any later G3 rebase is separately authorized and reviewed.

## 10. Files, functions, and serialized implementation ownership

Implementation is split into nonoverlapping leases and lands in this order:

1. **Contract/registry worker** owns only `scripts/phase_io_contracts.py` and
   new `scripts/recon_publication_transaction.py`. It adds registry types,
   `compile_recon_publication_plan()`, exact recon resolver branches, canonical
   encoders, and the shared transaction/recovery helper. It does not edit the
   ledger.
2. **Prepass worker** owns only `scripts/recon_prepass.py`. It converts current
   writers into pure byte/typed-row producers, uses a temp Foundry/provider
   overlay, and publishes solely through `recon/prepass`.
3. **Canonical worker** owns only `scripts/plamen_mechanical.py`. It makes SC/L1
   renderers pure, consumes the compiled projection, removes direct marker
   writes, and publishes the complete canonical/receipt tuple.
4. **Driver integration worker** owns only `scripts/plamen_driver.py`. It
   orders prepass -> dependency -> MODEL shards -> canonical, routes
   resume/degrade causes to canonical reexecution, blocks consumers until
   recovery, and publishes the optional supplementary sidecar.
5. **Fixture worker** owns only new copy-on-write Cut-4 successor test modules
   and their receipt. It never edits the accepted V1-V7 fixtures.

No two workers edit a shared file concurrently. MODEL shard definitions and
dependency-unit implementations are observed controls, not worker-owned
changes. `scripts/artifact_ledger.py` and all G3 artifacts are excluded.

## 11. Exact bounded test phases

The successor denominator is 69 new nodes, executed in order with pytest cache
disabled and unique temp roots:

| Phase | Nodes | Exact denominator |
|---|---:|---|
| A. Registry/contracts | 18 | Nine supported SC/L1 ecosystem plan cells; unknown provider, duplicate, case alias, dot/parent path, unregistered bundle, empty bundle, conditional-path, and resolver/plan mismatch rejections; one exact replay. |
| B. Prepass transaction | 18 | Six mode/route live cells; five named failpoints; source/config/provider-plan drift; exact no-op; zero-byte rejection; namespace-extra rejection; project-root mutation rejection. |
| C. Canonical transaction | 14 | Complete SC and L1 output sets; five named failpoints; seed and shard drift; exact no-op; zero-byte rejection; transform conservation; three history causes (marker, degrade, resume). |
| D. Application/compatibility | 12 | Six unchanged MODEL fanout cells; three unchanged dependency-wave routes; typed dependency zero; instantiate binding; breadth binding. |
| E. Migration/platform | 7 | Fresh, incomplete legacy, completed legacy, and corrupt/mixed legacy states; Windows locked replace, POSIX rename failure, and symlink/case-collision containment. |

The four named replacement REDs in section 6 are included once in phases A-C,
not duplicated. First run contract/complete-set tests, then MODEL/dependency
controls, then prepass crash/no-op, canonical crash/no-op, resume/degrade,
migration/platform, and finally all 69 together. After GREEN, run the accepted
V7 freeze and unaffected lifecycle selectors, followed by the recon adjacency
and smoke suites. The full repository regression, external live providers,
native cross-platform execution, release, and audit-quality assessment are
separate gates and are not claimed by this bounded cut.

## 12. Acceptance and non-goals

Cut-4 is acceptable only when both DRIVER units commit their complete compiled
sets, every provider has a nonempty outcome/evidence/debt triple, every
canonical input has current producer authority, the transform receipt proves
row conservation, exact replay is a byte/mtime/ledger no-op, and all failpoints
recover all-old or all-new. No public file may be discovered after writing,
zero bytes may not satisfy authority, and no second unit may own a canonical
path.

Non-goals are protocol hints, prompt/methodology changes, MODEL shard redesign,
dependency research redesign, semantic dedup, severity, suppression, report
authority, MethodCard/model application, ArtifactLedger changes, G3 authority
or pins, production implementation in Part-0, and release/audit-readiness
claims.
