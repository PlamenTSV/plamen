# Plamen Backend Model Routing Engineering Guide R2.5.2

Date: 2026-07-30

Status: bounded author conformance candidate; self-validated, not
independently accepted and not authorized for production integration.

## 1. Exact successor boundary

R2.5.2 is an additive successor to the exact frozen R2.5.1 package. It
addresses only the four blockers in the sealed independent review:

```text
backend_model_routing_r2_5_1_independent_review_r1_20260730.md
whole SHA-256:
255952072991a889bb7119d744eabc1c77570bd9701f5f8ddd22d314663edf9a
body SHA-256:
c769bf229a2046456a7424457028953edf8256b42b5f098c8bbd839b8e319276
fresh operations: 73
unexpected accepts: 15
disposition: BLOCK
```

The correction set is:

- B1: authenticate the actual policy and consumed authority at the spawn
  sink, and remove the consume/proof/spawn order contradiction;
- B2: Resume accepts only an opaque completed-current closure rooted in the
  authenticated current store/run snapshot;
- B3: provider bytes, neutral evidence, rules, usage, and reconciliation are
  mandatory and load-bearing in the completed-current closure;
- B4: one current-run authority closes the exact store namespace and binds
  root, transaction, prior Resume, rules, run, generation, and attempt.

R2.5.2 adds no provider selection, model recommendation, price claim,
production caller, audit answer, default change, protocol hint, finding, or
severity rule.

## 2. Normative artifacts

- this guide;
- `Plamen_Backend_Model_Routing_R2.5.2_Schemas_2026-07-30.json`;
- `Plamen_Backend_Model_Routing_R2.5.2_Conformance_Vectors_2026-07-30.json`;
- `validate_plamen_model_routing_r2_5_2.py`;
- `Plamen_Backend_Model_Routing_R2.5.2_Validation_Receipt_2026-07-30.json`;
- `claude_r3_backend_routing_joint_implementation_plan_r5_2_20260730.md`.

The validator hash-checks and executes the exact frozen R2.5.1 validator.
R2.5.1 executes the frozen R2.5 denominator, which executes the R2.3 and
R2.4 denominators. The resulting `646 + 40 = 686` is an executed vector
denominator, not a count of unique requirements.

## 3. Corrected causal lifecycle

R2.5.1's written J4-4 order was impossible: it attempted to mint and
authenticate a proof before the consumed authority that the proof binds.
A first R2.5.2 implementation draft also exposed a different causal cycle:
one capability cannot both contain post-provider neutral evidence and
authorize the earlier provider-process spawn.

R2.5.2 therefore uses two distinct ephemeral authorities:

1. `ValidatedLaunchClosureCapabilityV2` is minted after consume and before
   spawn. It contains no provider-output claim.
2. `ValidatedCurrentClosureCapabilityV2` is minted only after immutable
   provider bytes have been neutrally parsed and reconciled. Resume accepts
   only this completed-current capability.

The normative lifecycle is:

```text
load governed store/current-run authority
-> compile launch candidate
-> persist consume CAS and typed consumption parent
-> validate rooted post-consume launch closure
-> mint opaque launch-closure capability
-> mint secret proof from that capability
-> authenticate actual policy + consume + proof at spawn sink
-> spawn
-> spool immutable provider bytes
-> neutral parse and reconcile legacy observation
-> validate completed-current closure
-> mint opaque completed-current capability
-> Resume/reconciliation consumers use only completed-current capability
```

The launch candidate's legacy observation fields are diagnostic
compatibility data only. They are not provider evidence and cannot enter the
completed-current authority until replaced by and compared with the neutral
derivation.

## 4. B1: policy and consume closure at the sink

The launch-closure mint validates the authenticated store, exact root,
transaction parents, environment policy, every environment-policy row,
public environment, raw environment projection, consumed authority, attempt,
generation, CAS, and required `CONSUMED_NOT_SPAWNED` state.

The launch capability stores only the minimum canonical launch subset:
root, attempt, route, V4/V3 envelopes, environment policy, public
environment, and consumed authority. It excludes raw environment values,
legacy observation/evidence, and the flat transaction compatibility record.
It binds:

- exact store snapshot and current-run authority digests;
- run, generation, and attempt;
- the exact validated minimum launch subset;
- policy and consumed records through those immutable bytes.

Proof mint and spawn authentication both require the launch capability.
The final spawn operation receives the actual policy, every actual policy
row, raw environment, and actual consumed record. It validates schemas and
self-digests, compares policy and consume records exactly with the launch
closure, checks the required pre-spawn state, then invokes the preserved
R2.5.1 HMAC proof/spawn validation. A re-sealed best-case policy mutation or
consume/CAS mutation cannot pass by preserving a copied digest.

The corrected order is:

```text
consume CAS
-> post-consume launch closure
-> proof mint
-> spawn authentication
-> spawn
```

The completed-current closure is deliberately later because provider output
cannot exist before spawn.

## 5. B2: opaque completed-current Resume input

Resume V2.5.2 has no raw current-record path. Its current input is an opaque
`ValidatedCurrentClosureCapabilityV2` minted by the completed-current closure
operation. The capability contains canonical immutable bytes for:

- rooted completed records, excluding raw environment values;
- provider-artifact authority;
- neutral observation evidence;
- neutral reconciliation authority.

It also binds the exact store snapshot, current-run authority, run,
generation, and attempt. Copy, deep copy, serialization, direct construction,
reflective object construction, and post-mint field mutation reject in the
reference boundary.

Resume loads the prior identity from `resume/prior`, validates its nested
identity seal, joins its run/generation/attempt to `run/current`, recomputes
the current identity from the immutable completed records, and then invokes
the preserved R2.5.1 state-machine validator. Raw caller records, fabricated
prior/current dictionaries, cross-run state, snapshot substitution, and
generation/attempt drift reject.

The Python object registry in the conformance reference detects reflective
post-mint mutation. It is a fixture integrity mechanism, not a production
trust primitive. Production must use an access-controlled capability issuer
and authenticated durable snapshot handle established outside the candidate
path.

## 6. B3: mandatory neutral evidence and reconciliation

The completed-current closure operation requires an authenticated immutable
provider artifact. Omission is an error. It validates the exact attempt,
closed two-frame grammar, ordered frames, stream, raw digest, and usage.

R2.5.2 adds closed grammars for:

- effort: `low`, `medium`, `high`, `xhigh`, or `not_applicable`;
- thinking: confirmed adaptive/manual states or `UNKNOWN_ADVERSE`;
- fallback: confirmed none/used or `UNKNOWN_ADVERSE`;
- terminal: completed, failed, cancelled, timed out, or
  `UNKNOWN_ADVERSE`;
- usage: exactly non-negative safe-integer input/output token counts.

Unknown state values, extra usage fields, strings, booleans, negative
integers, and out-of-range integers reject. `UNKNOWN_ADVERSE` is explicit;
unknown input is never silently normalized to a favorable state.

`NeutralObservationEvidenceV2` binds the five neutral claims plus exact
usage and raw-stream digests. The completed-current operation projects those
neutral values into the preserved legacy observation/evidence shape and
requires exact equality. Legacy caller-authored values, rule IDs, claim
order/count, usage, and raw-stream digests have no independent authority.

`NeutralReconciliationAuthorityV1` joins:

- run, generation, attempt, root, execution attempt, and consumed launch;
- provider artifact and neutral evidence;
- legacy observation and evidence manifest;
- proof-rule authority;
- usage and raw-stream digests.

Provider artifacts and neutral evidence are mandatory in the same
completed-current closure transaction. The legacy self-authored observation
path is pre-launch diagnostic compatibility only.

## 7. B4: exact current-run store closure

`CurrentRunAuthorityV1` is a closed, versioned, self-digested authority at
the exact key `run/current`. It binds:

- store revision;
- run, generation, and attempt;
- root-preimage authority;
- transaction parent set;
- prior Resume authority;
- proof-rule authority;
- digest of the complete permitted namespace.

The permitted namespace is exactly:

```text
observation/rules
resume/prior
root/current
run/current
transaction/consumption
transaction/current
transaction/materialization
transaction/reconciliation
transaction/reservation
```

Missing or extra records reject, even if an extra record is otherwise typed.
This prevents unscoped authorities and raw-secret side records from entering
the trusted snapshot.

Every record is schema-validated and self-digest validated. Exact key and
revision checks apply to root, transaction/current, prior Resume, rules, and
run/current. All transaction parents and prior Resume join the one current
run/generation/attempt. The transaction parent set joins every exact parent
digest. The current-run authority joins root, transaction, prior, and rules.

The store and transport establishment helpers remain explicitly
fixture-only. Production J4-0 must use separately initialized,
access-controlled, restart-safe storage and process-I/O capabilities.
Python underscore names, object identity, or caller-created records are not
external provenance.

## 8. Added durable schemas

R2.5.2 adds four closed definitions:

- `CurrentRunAuthorityV1`;
- `ProviderUsageV1`;
- `NeutralObservationEvidenceV2`;
- `NeutralReconciliationAuthorityV1`.

All use `additionalProperties: false`. No raw secret, API key, proof tag,
HMAC key, nonce, or raw provider bytes is durable in these records.
Ephemeral launch/current capabilities are deliberately not JSON schemas.

## 9. Conformance partition

The 40 successor vectors are assigned as follows:

| Blocker | Vectors | Boundary |
| --- | ---: | --- |
| B1 | 8 | actual policy/consume sink and correct launch order |
| B2 | 8 | opaque completed-current Resume closure |
| B3 | 13 | mandatory neutral evidence and closed grammars |
| B4 | 11 | exact current-run/key/run/namespace store closure |
| Total | 40 | |

Every negative vector starts from a valid successor context, mutates a
concrete authority edge, and invokes the same operation as the positive
path. Scenario dispatch cannot directly manufacture an expected error.

The validator additionally executes 12 author hardening probes for reflective
capability construction, post-mint rehashing, prior/parent/revision drift,
closed effort/usage, and exact re-sealed policy/consume joins.

## 10. Preservation and manifest truth

The exact frozen R2.5.1 artifacts are hash-bound. Its validator executes
before any R2.5.2 vector. No R2.5.1 byte is changed.

The reproducible 2,851-byte restricted label-manifest digest remains:

```text
fad68edc4f82e09c0eed8d5bc1139e389e32c70f14efa783bb419d93bcbf8f9b
```

The frozen historical declaration remains recorded without being used as
manifest truth:

```text
61981cac2042e9c7854737e6de759ef6fae2f3fe7ad405f721b431e8dbceabca
```

## 11. Implementation gate

The required order is:

```text
exact R2.5.2 author package
-> fresh independent exact-hash R2.5.2 PASS
-> J4-0 production trust/store/spool provenance gate
-> bounded launch-closure and completed-current slices
-> unchanged later R5/R4 gates
```

The independent reviewer must attack causal order, both capability types,
actual policy/consume sink joins, raw-record Resume inputs, fabricated
current/prior closures, omitted/mutated neutral evidence, unknown state and
usage grammars, wrong store key/run/generation/attempt, rollback, and extra
namespace records. A green author validator is not independent acceptance.

## 12. Limits and non-claims

R2.5.2 does not prove:

- production integration or provider-process behavior;
- secure OS-backed capability provenance or restart durability;
- current model availability, quality, pricing, or cost;
- cross-OS, ecosystem, BB, evaluator, packaging, CI, or audit completion;
- audit recall or precision;
- default-change, cutover, commit, push, or release readiness.

It authorizes no production/config edit, provider call, network call, audit,
installation, commit, push, merge, or default change.

End of R2.5.2 engineering guide body.
