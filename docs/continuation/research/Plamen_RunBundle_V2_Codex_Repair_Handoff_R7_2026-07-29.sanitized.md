# RunBundle V2 frozen-vote integrity repair handoff R7

Date: 2026-07-29  
Author role: repair implementer; **not** acceptance authority  
Disposition: **IMPLEMENTATION COMPLETE - FRESH INDEPENDENT BLOCKING REVIEW REQUIRED**  
Claim scope: local implementation, deterministic replay, packaging, and fixture validation only  
B1 effectiveness claim: **NONE**

## 0. Incoming independent boundary

This repair responds to the fresh R6 independent review:

`<LOCAL_USER_ROOT>\plamen-codex-implementation\review_fixtures\runbundle_v2_independent_review_r6.md`

SHA-256:

`5e54931c468a0fcbd713e7a368dfbbaba3a35a00bc2e10c53e1c731152f7566c`

That review independently closed the original B04 and B05 blockers:

1. the Pashov V3 receipt is now bound to exact out-of-band public case-lock
   bytes and a trusted capture-inventory roster;
2. all tested bidi embedding, override, isolate, and pop controls reject in
   visible blind content; and
3. the authenticated private map and complete pre-render identity authorities
   reject token-roster pruning, context substitution, and packet rebinding.

The same review found one new exact blocker, B06: unblinding trusted the
`votes_sha256` text stored inside a frozen-vote object without recomputing it
from the exact sealed vote bytes. A modified vote could therefore retain the
old digest and still be mapped to a candidate.

The independent counterexample changed:

- verdict: `TP` to `FN_AFTER_FREEZE`; and
- reviewer ID: `reviewer-A` to `attacker`;

while retaining the old `votes_sha256` and every packet, candidate, case, key,
map, and context authority. API and CLI both accepted the stale digest.

The review recorded:

| Object | SHA-256 |
|---|---|
| original frozen vote file | `f07e412d7db886b4791d2568f54da3983b1cae336497207d983eb575f3342f3c` |
| asserted original payload digest | `53c673b7254d19f7d4400ca8feb7023fbf4bc733888786822e533ed9b983a231` |
| tampered frozen vote file | `858aaaff18eaa89e9adf0590c547f4896dffa4d8ebfd121e7c908c7907c081a9` |
| actual tampered payload digest | `70bb55ab7e5b82965afd1e7c7ab836afe6a96ced40af9ad81111b77c4a14b240` |
| incorrectly accepted adjudication | `6eca2cd52ad6c64c179561b025143de4d95e14a205b0f580c9a979267c6e76d5` |

Repository HEADs are context only because both worktrees are shared and dirty:

| Repository | HEAD |
|---|---|
| production | `67a0f85adc7a8169d79a286908b00bef7adb764a` |
| evaluator | `345d016d0c86b6201e90cec908c37c6a66f739c3` |

No commit, push, merge, provider launch, benchmark campaign, or live audit was
performed. No production RunBundle source was changed by R7.

## 1. Fixture-first evidence

Before the validator implementation, adversarial fixtures exercised:

- stale verdict replacement;
- stale reviewer replacement;
- stale review-label replacement;
- vote omission;
- vote duplication;
- an extra vote-row field;
- an extra frozen-object field;
- stale reordering of two otherwise valid rows;
- an invalid vote-row field contract at freeze; and
- API and CLI reproductions of the R6 review's exact stale-digest attack.

The initial focused checkpoint produced **8 failed tests**. Failures included
direct acceptance of stale content and non-contractual exceptions on malformed
rows. The tests were therefore red on the absent control rather than on an
incidental packet or private-map guard.

After implementation, the focused R7 Pashov/blinding/CLI suite produced:

`79 passed`

## 2. R7 closure design

### 2.1 Closed frozen-vote object

The evaluator-private frozen-vote object now has an exact six-field roster:

```text
schema_version
packet_sha256
permutation_sha256
votes
sealed
votes_sha256
```

Any omitted or additional top-level field rejects. `schema_version` must be
`plamen.blind-review-votes.v1`; `sealed` must be the JSON boolean `true`; and
`votes_sha256` must be exactly 64 lowercase hexadecimal characters.

### 2.2 Exact digest preimage

Before candidate-bound adjudication, unblinding reconstructs the complete
frozen payload by removing only `votes_sha256`. It serializes that closed
payload with the evaluator's strict canonical JSON implementation, computes
SHA-256, and compares the result to the asserted digest with
`hmac.compare_digest`.

Digest verification therefore covers:

- schema version;
- packet digest;
- permutation digest;
- complete ordered vote array;
- every exact vote-row value; and
- the sealed state.

There is no field selected from untrusted input and no partially covered vote
projection.

### 2.3 Closed vote-row contract

Each vote row must be a plain JSON object with exactly:

```text
review_label
verdict
reviewer_id
```

All three values must be non-empty strings. The vote array must be a plain JSON
array. The validator rejects duplicate labels and requires exact set equality
between vote labels and the unique labels in the schema-validated blind packet.
Frozen rows must appear in canonical label order.

This closes omission, duplication, unknown-label, extra-field, and ordering
ambiguities independently of digest mismatch.

### 2.4 Shared freeze/unblind validation

One `_validated_vote_rows()` implementation enforces the row and packet-label
contract:

- `freeze_review_votes()` validates and canonicalizes proposed rows before
  producing the digest; and
- `_validated_frozen_review_votes()` validates exact frozen bytes and calls the
  same row validator before `unblind_adjudication()` may access a vote.

The unblind path consumes only the returned validated rows. It no longer reads
candidate-bound vote content from the raw submitted object after validation.

### 2.5 API and CLI behavior

Both Python API and `adjudicate-v2` CLI reach the same validator. The R6 stale
verdict/reviewer attack now fails before private-map candidate mapping. There
is no permissive legacy path.

## 3. Security property and explicit trust limit

R7 establishes this local property:

> A frozen-vote object cannot be adjudicated under a stale `votes_sha256`;
> exact sealed content, digest, packet labels, row roster, coverage,
> uniqueness, and canonical order must agree before any candidate binding.

The digest is an integrity commitment, not a signature or MAC. R7 deliberately
does **not** claim to authenticate reviewer intent. A party able to replace
both valid three-field vote content and its digest can construct a different
self-consistent frozen-vote object. Governance must retain the accepted
`votes_sha256` outside the submitted object or add a separately reviewed
reviewer-signature authority.

That limit was explicitly classified as a separate, nonblocking governance
boundary by the R6 independent review. It is documented in the public README
so the local digest cannot be mistaken for reviewer authentication.

## 4. Exact R7 freeze authority

Manifest:

`<LOCAL_USER_ROOT>\Downloads\Plamen_RunBundle_V2_Local_Freeze_R7_2026-07-29.json`

| Binding | Value |
|---|---|
| raw manifest SHA-256 | `961c8556551f1ef432bad1f0e11a9329daf312f914ba34a5585a8ea4f2aac845` |
| embedded canonical self-digest | `cd7be59ee425b22bc15b32ce72e3e63f6bd029c2295951ec2157eb2977e04a59` |
| schema | `plamen.runbundle-v2-local-freeze.v2` |
| claim scope | `LOCAL_IMPLEMENTATION_AND_FIXTURE_VALIDATION_ONLY` |
| `not_B1_effectiveness_evidence` | `true` |

Replay:

```json
{"freeze_manifest_sha256":"cd7be59ee425b22bc15b32ce72e3e63f6bd029c2295951ec2157eb2977e04a59","status":"REPLAYED"}
```

### Source, API, and protocol hashes

| Source set | Files | Tree SHA-256 |
|---|---:|---|
| production runtime | 7 | `89f8b180f421c5079bb35b5fe21227778a8a9a57c4d4cd80da5697f0a93c53e2` |
| production tests | 6 | `31be45ad9521c54feefb80ff2da289be0d1453780450867fd4c75069f7266e67` |
| evaluator source | 28 | `d8eaa59a5aeac8d34b6cc5e59ecf5271d25bb2297ad3f0003f5bb0f801bd9131` |
| evaluator schemas | 47 | `2423f116380205e01c6d7114112c2b95d24081a0fb7f09aa8a113ccc6484cad8` |
| evaluator tests | 29 | `a64a84636c7771c7df0196c7680eab9f12873cf646b2fff1a20eabebc5870d9b` |
| evaluator packaging | 2 | `e2fc6d9fd29aeff2fa21f0aef5212644226279232b81b3a87854b241adeabe34` |
| freeze tooling | 2 | `f24b707632887106e231f4906fe304d2c26f670f88f20f7b8838c697e2fdcb39` |

| Public API | Symbols | SHA-256 |
|---|---:|---|
| production runtime | 107 | `dd507961432faa427d6a20f917ea78dabb6aa08e42e246357fbb673a48e664a3` |
| evaluator source | 103 | `f9284041b26a4ff2108b729ba21e24ef6e03a1bd2755d3e180b744c71ab2f801` |

Protocol hashes remain:

- smart-contract: `28779f0e8bfb0358f0b496661b61918f7b837530c05ff1295f63e83d5d5ac9ae`
- L1: `1eb129d128fc47427b1de2d0502aa82f3162546246f57d6d738090d441c526a6`

## 5. Immutable wheels

All prior wheel boundaries remain byte-identical:

| Boundary | SHA-256 | Size |
|---|---|---:|
| R3 `dist/frozen-v2/...whl` | `b51883f100137115523794561711132a7040526d4e27df58d9fd2460fc09fb67` | 157,867 |
| R5 `dist/frozen-v4/...whl` | `19023fba9fbf4f786b185c50a6de495cecb976bed278e84faa0e873064d8b1fd` | 159,828 |
| R6 `dist/frozen-v6/...whl` | `f2f3e618ad241655b519a4f8ceb210b4c9bf01844240f1d6d27e8338fa7acedb` | 161,608 |

The R7 source wheel is:

`dist/frozen-v7/plamen_eval_control-0.2.0-py3-none-any.whl`

| Binding | Value |
|---|---|
| SHA-256 | `8ccc90f531f5ac788e23d78184be875ad1f0e5e936e41d00b767346b82bdf33f` |
| size | 162,258 bytes |
| members | 80 |
| member-roster SHA-256 | `0828df80c035f5a428f0c43b17c7841b652a153287ef04bc30843f778c04b256` |

The full evaluator suite built the wheel twice from independent clean external
temporary copies, required byte equality, and required equality with the
preserved `frozen-v7` wheel.

The exact wheel was also installed offline with `--no-index --no-deps` into a
fresh virtual environment. It was invoked with `python -I`, empty
`HOME`/`USERPROFILE`, `PYTHONNOUSERSITE=1`, and no `PYTHONPATH`. Version
`0.2.0`, `plamen_eval.blinding`, `plamen_eval.contracts`, and all 47 installed
schemas loaded. The verified temporary environment was then removed.

## 6. R7 repair-file hashes

Paths are relative to `<LOCAL_USER_ROOT>\<PRIVATE_EVALUATOR_REPO>`.

| File | SHA-256 |
|---|---|
| `src/plamen_eval/blinding.py` | `0659a85aebede5277d91039ddc5fa06d28e489a51b28d5ad5fc4ec21a6bdfbb3` |
| `tests/test_real_v2_blinding_comparison.py` | `c92ce54eb097a0c6d3b9b3db5c4a2aeb93f371898595e46bc4039c6d2d013a52` |
| `tests/test_real_v2_cli.py` | `da3dd102b3ed314ca6dda4cf499e5ca98bc7ad11a39279c19eec6c92daf4fcf5` |
| `tools/runbundle_v2_freeze.py` | `16dc3bb6defb269d9198e8e6bf8b2c5950e1a5973c35351e056ad576e95c58ff` |
| `docs/runbundle-v2-freeze.md` | `7fc09f864be66e90af118b4185ce2f1a5c6d0891b3f8be5018845ac5ae2fa78b` |
| `README.md` | `30597e992ab7b4ec4a8e41797c43104c825b53570f2807e4fcdef7c03580b63b` |

The vote object is evaluator-private, so no production or public JSON Schema
change was required.

## 7. Final validation denominators

| Validation | Result |
|---|---:|
| R7 Pashov/blinding/CLI focused | **79 passed** |
| full neutral evaluator | **229 passed, 6 subtests passed** |
| production RunBundle exact six-file suite | **509 passed** |
| production Python + public packaging/fresh archive | **9 passed** |
| cross-OS/toolchain pre-handoff gate | **22 passed** |
| native Windows RunBundle ADS/ABI/junction focus | **4 passed, 120 deselected** |
| R7 double clean build and preserved equality | **PASS** |
| R7 isolated offline install/import | **PASS** |
| R7 exact freeze replay | **REPLAYED** |
| `python -m compileall -q src tests tools` | **PASS** |
| `git diff --check` | **PASS; line-ending warnings only** |

The first packaging attempt correctly found one concurrently introduced
Program Facts helper still excluded by `scripts/*`. Its owning lane corrected
the exact package-visibility rule without touching evaluator or RunBundle
files. The complete fresh-archive denominator then passed 9/9.

## 8. Recall, precision, and robustness effect

This repair is an integrity/precision control for the neutral evaluator. It
does not change Plamen discovery, verification, severity, reporting, provider,
or ecosystem behavior.

- Recall measurement is protected because a frozen `TP` cannot silently become
  `FN_AFTER_FREEZE` while retaining the accepted digest.
- Precision measurement is protected symmetrically because a frozen negative
  vote cannot silently become a positive under stale authority.
- Exact coverage and uniqueness prevent omissions or duplicate votes from
  changing denominators.
- Canonical order and closed field rosters prevent alternate encodings from
  carrying unreviewed semantics.
- Failures are deterministic `BlindingError` rejections before candidate
  mapping; there is no partial adjudication.

No comparative recall/precision improvement is claimed until the external B1
campaign is governed and executed.

## 9. Required fresh R7 independent review

The fresh reviewer must not use this handoff or the author's tests as its
oracle. At minimum it should:

1. reproduce the exact R6 stale verdict/reviewer attack through Python API and
   CLI under the original digest;
2. independently mutate verdict, reviewer, label, order, omission,
   duplication, row fields, frozen fields, schema, sealed state, packet hash,
   and permutation hash;
3. exercise both stale digests and newly recomputed digests for structurally
   invalid content;
4. prove exact packet-label coverage, uniqueness, and canonical order;
5. prove freeze and unblind enforce the same row contract;
6. confirm that valid changed content plus a new digest remains outside local
   reviewer authentication and that the documentation states this limit;
7. rerun the R6 B04 Pashov joint-replacement cases and B05 bidi/token/context
   cases to ensure the new early validator did not bypass or weaken them;
8. replay every R7 source/API/protocol/wheel preimage and raw/embedded manifest
   hash;
9. repeat clean double wheel builds and isolated import;
10. rerun full evaluator, production RunBundle, packaging, cross-OS, and
    native-Windows denominators; and
11. issue a new hash-stamped `PASS` or `BLOCK` disposition.

The repair author requests independent review and makes no acceptance claim.
