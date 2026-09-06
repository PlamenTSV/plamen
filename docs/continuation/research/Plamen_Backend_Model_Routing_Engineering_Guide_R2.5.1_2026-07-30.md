# Plamen Backend Model Routing Engineering Guide R2.5.1

Date: 2026-07-30

Status: bounded author conformance candidate; self-validated, not
independently accepted and not authorized for production integration.

## 1. Exact successor boundary

R2.5.1 is an additive, bounded successor to the frozen R2.5 package. R2.5
remains immutable and independently blocked. This successor closes exactly
the four root causes in:

```text
backend_model_routing_r2_5_independent_review_r1_20260730.md
whole SHA-256:
97db9904fd4aa53161d436206bf558b03df86a60ba512675331c9c43b2842cf8
body SHA-256:
5b0d5e836b9843c9317bdbb2ef714f39970fa964415a21cea54efec8f53f690f
```

The four corrections are:

- B1: a proof object is not a spawn capability until the sink authenticates
  the HMAC and every bound input;
- B2: Resume compares a separately persisted prior identity with a current
  identity recomputed internally from the actual rooted closure;
- B3: observation values and claims are derived by a closed neutral parser
  from immutable provider bytes and a rooted proof-rule authority;
- B4: the root preimage and transaction parents are closed, typed,
  self-digested records loaded through an independently established
  read-only store capability.

R2.5.1 adds no model choice, provider claim, pricing fact, production caller,
protocol methodology, audit answer, finding, severity rule, default change,
or Codex redesign.

## 2. Normative artifacts

- this guide;
- `Plamen_Backend_Model_Routing_R2.5.1_Schemas_2026-07-30.json`;
- `Plamen_Backend_Model_Routing_R2.5.1_Conformance_Vectors_2026-07-30.json`;
- `validate_plamen_model_routing_r2_5_1.py`;
- `Plamen_Backend_Model_Routing_R2.5.1_Validation_Receipt_2026-07-30.json`;
- `claude_r3_backend_routing_joint_implementation_plan_r5_1_20260730.md`.

The validator hash-checks and executes the exact frozen R2.5 validator.
R2.5 itself executes the frozen R2.3 and R2.4 denominators. The resulting
`596 + 50 = 646` number is an executed denominator, not a count of unique
requirements.

## 3. Root-of-trust law

No pure in-process record can prove its own external provenance. R2.5.1
therefore makes the root-of-trust boundary explicit instead of describing a
caller-owned digest as independently frozen.

Three opaque capabilities originate outside the candidate closure:

1. a governed preimage trust anchor binds the exact immutable authority-store
   snapshot digest, revision, and source identity;
2. a neutral transport receipt binds the exact immutable provider-byte
   digest, attempt identity, and spool source;
3. a secret-proof mint authority is confined to the verification module and
   cannot be supplied as a durable record.

The reference validator contains underscore-prefixed fixture establishment
helpers so offline conformance can construct a positive world. They are test
fixtures, not production APIs or evidence of origin. Production integration
must receive equivalent opaque capabilities from a separately initialized
governance/preimage loader and neutral process-I/O spooler before it accepts
any candidate route or provider claim. J4-0 must prove that separation.

Python name privacy or object identity alone is not treated as cryptographic
security. Every security-relevant sink also recomputes the governed snapshot
digest, provider-byte digest, or HMAC over the actual supplied inputs.

## 4. B1: verified secret-proof and spawn capabilities

`VerifiedSecretProofCapabilityV3` has no normal public raw-tag constructor.
The mint operation accepts the actual:

- complete V4 attempt envelope;
- exact V3 predecessor envelope;
- environment-policy authority;
- policy-ordered raw secret set;
- 32-byte process nonce;
- 32-byte object nonce;
- 32-byte HMAC key;
- consumed-attempt authority.

The HMAC payload remains the length-delimited R2.5 payload over the complete
canonical V4 and V3 records, both nonces, and every policy-ordered secret
name/value pair. The minted opaque state additionally binds:

- V4 and V3 digests;
- policy digest;
- secret-set digest;
- execution-attempt and consumed-launch digests;
- process- and object-nonce digests;
- authentication tag.

`VerifiedSpawnCapabilityV3` can be minted only after the proof has been
verified. The final spawn validator repeats HMAC authentication with the
actual policy, raw secrets, nonces, key, V4/V3 records, attempt, and consume
authority. It does not trust a copied digest or Python object identity.

Proof, spawn, transport, store, and trust-anchor capabilities are immutable,
non-copyable, non-deep-copyable, non-serializable, and redacted in
representations where they can contain proof state. A proof-required policy
with no secret rows rejects instead of minting a meaningless zero-secret
proof.

The vectors cover direct construction, arbitrary tag, wrong V3, wrong
policy, wrong secret set, wrong process nonce, wrong object nonce, wrong key,
cross-attempt replay, forged spawn construction, copy, zero-secret policy,
and the valid twice-authenticated path.

## 5. B2: Resume actual-parent binding

`PriorResumeIdentityAuthorityV1` is a closed, versioned, self-digested record
persisted under a governed store key and revision. It contains the complete
typed `ResumeIdentityVectorV2`, its digest, run identity, generation, and
attempt ordinal.

The Resume V2.5.1 validation API does not accept caller-selected `before` or
`after` vectors:

```text
before := trusted_store.load("resume/prior").identity_vector
after  := resume_identity(actual_current_records)
changes := exact_diff(before, after)
```

The authority's before/after digests, family-grant fields, changed-field set,
generation/attempt transition, and terminal evidence are then validated by
the preserved R2.5 exact state-machine law. A caller-provided vector is an
API error, not an alternate evidence source.

The vectors include fabricated current, fabricated prior, fabricated both,
caller-selected prior input, stale revision, wrong key, seal tamper, valid
single and multiple actual identity changes, retry, completed no-relaunch,
and ambiguous consumed debt.

The reference does not claim that a store object created by the route
candidate is trusted. Store capability origin is the external prerequisite in
Section 3.

## 6. B3: neutral provider observation

Provider bytes enter through `ImmutableProviderArtifactBytesV1`. It can be
opened only against a neutral transport receipt that already binds the exact
raw digest and attempt. Mutation after receipt creation fails before parsing.

The normative neutral frame grammar is a closed two-frame JSON-lines stream:

1. sequence zero, `launch`, containing stream ID, attempt, effective model,
   effective effort, and thinking state;
2. sequence one, `terminal`, containing the same stream ID and attempt,
   fallback state, terminal category, and usage.

Duplicate object members, wrong field sets, missing frames, extra frames,
wrong order, duplicate sequence, mixed streams, and cross-attempt frames
reject. The parser computes:

- raw-stream and ordered-frame digests from the immutable bytes;
- usage digest from the terminal frame;
- `ProviderArtifactAuthorityV1`;
- five observed values;
- five `NeutralObservationClaimV1` records;
- one `NeutralObservationEvidenceV1`.

`ObservationProofRuleAuthorityV1` is a separately persisted, closed,
self-digested five-row authority. It fixes field-to-frame and proof-rule
mapping:

```text
effective_model_id  -> LAUNCH_FRAME_EXACT
effective_effort    -> LAUNCH_FRAME_EXACT
thinking_state      -> LAUNCH_FRAME_EXACT
fallback_state      -> TERMINAL_FRAME_EXACT
terminal_category   -> TERMINAL_FRAME_EXACT
```

Claimed evidence is compared to the neutral derivation byte-for-byte after
schema and digest validation. The claimant cannot select a proof rule,
purported raw digest, frame membership, observed value, usage, or terminal
state. The vectors cover the two R2.5 unexpected accepts plus wrong bytes,
mixed streams, omitted and reordered frames, duplicate sequence, wrong
attempt, usage tamper, fallback tamper, terminal tamper, and the valid neutral
path.

This proves parser provenance relative to an authenticated immutable byte
artifact. It does not prove that a real provider emitted those bytes until
the production transport spooler is independently integrated and tested.

## 7. B4: typed external root and transaction parents

The candidate closure no longer contains either `frozen_root_digest` or a
flat `transaction` dictionary. Supplying either is rejected as an embedded
anchor.

The governed read-only store contains:

- `RootPreimageAuthorityV1`;
- `TransactionParentSetV1`;
- `ReservationParentV1`;
- `MaterializationParentV1`;
- `ConsumptionParentV1`;
- `ReconciliationParentV1`;
- the prior Resume authority;
- the observation proof-rule authority.

Every record is closed, versioned, self-digested, and loaded by an exact key.
The store snapshot digest and revision are authenticated before any record is
loaded. Unknown fields, including raw-secret aliases, reject by schema.

`TransactionParentSetV1` joins one run/generation/attempt to exact parent
digests. The closure validator checks:

- generation reservation against Launch;
- attempt reservation, resource entry/ledger, prompt, work directory, and
  preparation time against the V4 envelope;
- consume event, consumed resource entry/ledger, and CAS against Consume;
- WorkPlan and PhaseIO launch identities against their typed records;
- reconciliation and incorporation identities as independently loaded
  terminal parents.

Only after all seals, store joins, generation joins, and candidate-child
joins pass is the legacy R2.5 closure assembled in memory and sent to the
frozen validator.

There is exactly one external root preimage. Axes, profile, selection,
customization, environment, and route remain transitive descendants of that
root; R2.5.1 does not falsely describe each as a separately persisted anchor.

The vectors cover co-rehashed root plus candidate anchor, co-rehashed
transaction child state, unknown raw-secret parent field, stale parent,
cross-generation parent, seal tamper, missing parent, wrong root key, root
seal tamper, untrusted store construction, embedded legacy anchor, and the
valid externally loaded path.

## 8. Closed durable schemas

The successor adds these closed definitions:

- root preimage authority;
- reservation, materialization, consumption, and reconciliation parents;
- transaction parent set;
- prior Resume identity authority;
- proof-rule row and authority;
- provider artifact authority;
- neutral field claim and evidence.

Every top-level durable authority uses `additionalProperties: false`. The
validator also performs independent raw-secret/key/token/nonce alias
injections against every new durable definition. Ephemeral keys, secret
values, nonces, tags, immutable raw provider bytes, and opaque capabilities
are not serialized into schema records, receipts, logs, or reports.

## 9. Conformance law

Each negative vector constructs a valid successor context, mutates a concrete
input or authority edge, and invokes the same reusable operation as the
positive path. Scenario dispatch may directly reject only an unknown scenario;
it may not manufacture an assigned expected error.

The assigned partition is:

| Blocker | New vectors |
| --- | ---: |
| B1 proof/spawn authenticity | 13 |
| B2 Resume actual parents | 12 |
| B3 neutral observation provenance | 13 |
| B4 external typed anchors | 12 |
| Total | 50 |

The validator additionally checks:

- exact R2.5 guide-independent validator hash and isolated output;
- exact R2.5 blocking-review body and whole hashes;
- Draft 2020-12 meta-schema validity;
- duplicate-aware JSON;
- ASCII, LF-only, final-LF transport;
- stable deterministic schema/vector generation;
- capability copy/serialization/repr boundaries;
- closed-world durable-secret aliases;
- no direct expected-error manufacture.

## 10. Manifest discrepancy adjudication

The frozen R2.4 declaration remains:

```text
2851 bytes
61981cac2042e9c7854737e6de759ef6fae2f3fe7ad405f721b431e8dbceabca
```

The exact stated restricted-JSON recipe independently reproduces:

```text
2851 bytes
fad68edc4f82e09c0eed8d5bc1139e389e32c70f14efa783bb419d93bcbf8f9b
```

R2.5.1 adopts `fad68edc...f9b` as the label-manifest truth because it is the
reproducible digest of the specified preimage. It preserves
`61981cac...abca` as an immutable historical declaration. Neither value is
silently discarded or rewritten.

## 11. Implementation gate

The required sequence is:

```text
exact R2.5.1 author package
-> new independent R2.5.1 exact-hash PASS
-> J4-0 frozen preimage and external-capability provenance gate
-> bounded J4-1 through J4-4 implementation
-> unchanged later joint-plan gates
```

J4-0 must prove that production trust anchors and transport receipts are
created outside the candidate routing/evidence path, survive restart, reject
stale/cross-run state, and are never replaced by fixture helpers. Production
fixtures must use actual persistent-store and process-I/O implementations,
not the in-memory conformance reference.

No author receipt can substitute for independent acceptance.

## 12. Limits and non-claims

R2.5.1 does not prove:

- production integration;
- real provider behavior, current model availability, or pricing;
- native cross-OS store/spool durability;
- downstream runtime, evaluator, BB, repair, packaging, or CI completion;
- Codex parity;
- audit recall or precision;
- default-change or cutover readiness.

It authorizes no production/test/config edit, provider or audit launch,
network call, installation, commit, push, merge, or default change.

End of R2.5.1 engineering guide body.
