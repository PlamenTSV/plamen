# Program Facts G3-00 stdlib cross-check transport-totality amendment

Status: `CONTRACT_ONLY_PENDING_INDEPENDENT_REVIEW`

The exact accepted parent and its accepted independent receipt are:

| Accepted input | Bytes | SHA-256 |
|---|---:|---|
| `architecture/program-facts-g3-00-schema-vector-clarification-amendment.md` | 80,218 | `f03b07bea209dde4cf2cf8dcebd3e4c618a5fd56196c4448594a9d744136f7fa` |
| `review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/PROGRAM_FACTS_G3_00_SCHEMA_VECTOR_CLARIFICATION_AMENDMENT_INDEPENDENT_REVIEW.v1.json` | 15,568 | `3db4b56a2132bbd5d8dd7cb59bb68cdb4e32aa5f109da55420b05b786fee5e92` |

The exact frozen candidate baseline is:

| Candidate input | Bytes | SHA-256 |
|---|---:|---|
| `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/crosscheck_schema_contracts_stdlib_v1.py` | 190,456 | `e3cdd2599cf05d7f0c2b256d45d88e52f04fe15890d74a38bb296be44c1b5fb5` |
| `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_IMPLEMENTATION_HANDOFF.PENDING.v1.json` | 12,054 | `e6bb2fa49d8bb7f81d510cc9212532cb3c8ac36ab3781fc2b2e9c48a43fa24e6` |

All four identities above were recomputed from strict repository-relative bytes.
The two accepted inputs are immutable. The candidate source and PENDING handoff
are historical pre-repair inputs, not accepted artifacts. They MUST remain
byte-for-byte unchanged until this amendment has a passing independent receipt.

An independent review of the candidate returned `REPAIR` with exactly the two
consolidated blockers closed by this amendment: noncanonical text stdout
transport and incorrect treatment of a direction with zero enumerated coverage
atoms. There is no stable review artifact for that disposition. This amendment
does not name, hash, imply, or authorize creation of a retrospective review
artifact for it. The four pinned files above, the source lines they contain, and
future fixture-first evidence defined here are the only durable inputs at this
boundary.

This is a narrow successor only for the stdlib cross-check's import/CLI stdout
transport and occurrence-direction zero-atom totality. It does not modify the
accepted parent, its receipt, any subject schema, vector carrier, predicate,
proof, witness, count, digest, principal binding, launcher policy, candidate
handoff, or vector meaning. Every accepted requirement not explicitly replaced
below remains unchanged. `MUST`, `MUST NOT`, `REQUIRED`, `SHOULD`, and `MAY` have
RFC 2119 meaning. `CJ`, `CF`, `UTF8`, `LF`, occurrence, coverage atom,
disposition, direction, and vector retain their accepted meanings.

## 1. Closed scope and precedence

This amendment replaces only:

1. the accepted four-module stdlib cross-check import boundary, solely to add a
   direct `sys` import for exact binary stdout transport;
2. the cross-check CLI emission operation that currently uses text `print`; and
3. the accepted empty occurrence-direction rule, solely to distinguish an exact
   zero-atom denominator from a nonzero denominator whose atoms require vectors
   or closed impossibility proofs.

The exact successor import-module set is
`{hashlib,json,pathlib,typing,sys}`. The first four modules retain their accepted
uses. `sys` has only the syntactic and semantic use fixed in section 2. `re`
remains forbidden. The successor does not add a general-purpose process,
terminal, environment, argument, filesystem, reflection, or operating-system
capability.

The following accepted values remain exact and MUST NOT change as a consequence
of this amendment:

```text
subject schema count                              12
keyword occurrence count                      7,517
coverage atom count                          21,578
impossibility proof row count                   891
coverage atom counts by subject
  [1879,1812,2950,2283,2881,1445,1959,2018,1436,1160,992,763]
atom-set preimage bytes                    5,102,113
atom-set SHA-256
  286aa2a4477aa46f632c590020d3a49e1e147cef0194471d9893f8898a903915
impossibility-proof preimage bytes            338,716
impossibility-proof SHA-256
  0103ea85b210693908f2c7fb7368ca8c823afd959da6e1ae3d65d3563bf746c3
```

The 891 proof rows include zero `NEG-11-IF-DIRECT` rows. A direct `if`
occurrence has two `VALID` atoms and no `INVALID` atom. This is an example of a
zero-atom direction, not an impossible atom, omitted atom, new proof, or reduced
denominator. No predicate count, proof value, atom ID, occurrence row, vector ID
preimage, vector-to-atom association, vector expected result, vector target, or
singleton `covers` rule changes.

## 2. Exact import and `sys` confinement

### 2.1 Import syntax

The repaired candidate and any canonical copy MUST have import statements whose
resolved top-level module names are exactly these five names and no others:

```text
hashlib
json
pathlib
sys
typing
```

Direct `import sys` is REQUIRED, with no alias. Dotted, relative, wildcard, and
aliased imports are forbidden. Existing direct name imports from `pathlib` and
`typing` MAY remain. No module may be reached through `__import__`, `importlib`,
`eval`, `exec`, `compile`, `globals`, `locals`, `vars`, `getattr`, `setattr`,
`delattr`, `__builtins__`, a function `__globals__`, a class MRO/subclass walk,
or another reflection or dynamic-import path. An object imported from `pathlib`
or `typing` MUST NOT be traversed to obtain `sys` or another module. Dunder
attribute traversal is forbidden; the ordinary module names `__file__` and
`__name__` retain their existing non-attribute uses.

The source MUST NOT import, execute, or traverse as a module `re`, `os`,
`socket`, `subprocess`, `importlib`, `io`, `codecs`, `locale`, `tempfile`,
`builtins`, a provider, generator, evaluator, launcher, or production source.
The accepted allowlisted `pathlib` stable-read surface MAY continue to read the
launcher source's inherited bytes solely to derive and compare its fixed file
identity. That narrow input-only byte read is not launcher module access: the
bytes MUST NOT be parsed as executable code, imported, executed, compiled,
reflected over, used to obtain a symbol, or passed to an execution API. The
cross-check MUST NOT invoke the launcher or any launcher member.

The source MUST NOT call direct `open`, create a new file descriptor, open a
terminal, inspect or change an encoding, inspect arguments or environment
variables, or perform a network or child-process operation. The existing closed
`pathlib` stable-read surface otherwise remains input-only. `Path.write_text`,
`Path.write_bytes`, `Path.open`, rename, replace, unlink, touch, mkdir, and all
other filesystem mutation remain forbidden.

### 2.2 Closed `sys` use

The top-level statement `import sys` is the sole exception to the rule confining
executable `sys` use to `main`. Apart from that one direct, unaliased import, the
identifier `sys` may appear in executable source only in `main` and only in the
single attribute expression `sys.stdout.buffer`. It MUST NOT be rebound, passed
as a value, returned, stored, indexed, reflected over, or used through an alias.
`sys.stdout` may not be used as a text stream. `sys.stderr`,
`sys.__stdout__`, `sys.__stderr__`, `sys.argv`, `sys.environ`, `sys.modules`,
`sys.path`, `sys.exit`, and every other `sys` member are forbidden.

The obtained buffer may be stored in one local named `stdout_buffer`. That local
may be used only for one `stdout_buffer.write(raw)` call followed, after a
successful exact byte-count check, by one `stdout_buffer.flush()` call. It may
not be returned, passed to a helper, wrapped, reconfigured, closed, detached,
queried for encoding, or used by any other method. No text `print`, text
`write`, `writelines`, `reconfigure`, encoding conversion, or newline
translation is permitted anywhere in the source.

The intended closed implementation shape is semantically exact to:

```python
def main() -> None:
    try:
        raw = canonical_stdout_bytes(run_crosscheck())
        stdout_buffer = sys.stdout.buffer
        written = stdout_buffer.write(raw)
        if type(written) is not int or written != len(raw):
            raise CrosscheckFailure("canonical stdout write was not complete")
        flush_result = stdout_buffer.flush()
        if flush_result is not None:
            raise CrosscheckFailure("canonical stdout flush result was not None")
    except BaseException:
        raise SystemExit(1) from None
```

Equivalent means the same data dependencies, operation count, ordering, type
checks, output bytes, and failure behavior. It does not permit another API or a
second output path. The two constant diagnostic strings above are internal and
MUST NOT be emitted. `BaseException` and `SystemExit` are built-in names; this
shape does not permit another `sys` access.

On success there is exactly one binary write call and exactly one flush call.
The write argument is the identical `raw` object assigned by
`raw = canonical_stdout_bytes(run_crosscheck())`. The full-byte-count check uses
both `type(written) is int` and `written == len(raw)`. A Boolean, `None`, a
negative value, zero for nonempty output, or any other short or oversized count
fails. Flush occurs only after that check and its result must be exactly `None`.

If construction, buffer acquisition, write, count validation, or flush raises;
if write returns `None`; if only a prefix is written; if the returned count is
short; or if flush returns a non-`None` value, the CLI exits with status 1. It
MUST NOT retry, resume, loop, perform a second write, perform a second flush, or
echo an exception, secret, input, traceback, diagnostic, or rejected bytes to
stdout or stderr. A short write may already have exposed its prefix; the process
does not try to repair it. The external launcher rejects the nonzero exit and
noncanonical/truncated capture. Successful execution exits with status 0.

## 3. Exact canonical stdout boundary

`canonical_stdout_bytes(document)` remains the sole constructor of governed
stdout. It returns exactly:

```text
CF(document) = CJ(document) || LF
```

The result is strict UTF-8, has no BOM prefix, contains no raw CR byte, has no
leading or trailing bytes outside the canonical JSON value, and ends in exactly
one LF. It is emitted byte-for-byte without decode/re-encode, locale lookup,
code-page conversion, text newline translation, or platform dependence.

The exact stdout maximum remains 33,554,432 bytes, including the one final LF.
A result of exactly 33,554,432 bytes is allowed. A result of 33,554,433 bytes is
rejected before `sys.stdout.buffer` is obtained and before any write or flush.
The separate 16,777,216-byte control-document ceiling is unchanged and MUST NOT
be substituted for, added to, or used to raise this stdout maximum.

The external launcher remains responsible for raw byte capture, the exact
33,554,432-byte cap, zero stderr, nonzero-exit rejection, stable capture, network
denial, empty environment, closed handles, empty argument list, shell denial,
source/principal/path binding, and atomic publication. Direct binary output
does not give the cross-check capture authority and does not weaken any launcher
check.

## 4. Exact symmetric occurrence-direction totality

For each enumerated occurrence pointer `p`, define two direction keys:

```text
POSITIVE(p) selects expected == "VALID" and positive_vector_ids
NEGATIVE(p) selects expected == "INVALID" and negative_vector_ids
```

For either direction `D`, let `A(p,D)` be the exact ordered projection of the
independently enumerated coverage-atom denominator for pointer `p` whose
`expected` equals the direction value. Let `L(p,D)` be the corresponding carried
vector-ID list. Let `X(a)` be the unique exact disposition joined to atom `a` by
`(schema_pointer,atom_id,expected)`.

The checker MUST receive or retain the enumerated `CoverageAtom` rows themselves;
it MUST NOT infer `A(p,D)` from disposition presence, vector presence, proof
presence, or a hard-coded per-keyword assumption. The internal plumbing may add
the exact atom sequence to `analyze_atom_coverage`'s internal return and pass it
to `verify_bidirectional_associations`. This is not a parity field, artifact
field, vector field, or denominator change.

Before an empty-direction decision, the checker MUST close these joins globally:

1. every enumerated atom joins exactly one disposition;
2. every disposition joins exactly one enumerated atom;
3. no atom or disposition key is duplicated;
4. the pointer is an exact enumerated occurrence pointer;
5. `expected` is exactly `VALID` or `INVALID` and agrees with the atom;
6. disposition is exactly `VECTOR` or `IMPOSSIBLE`;
7. a `VECTOR` disposition has the accepted nonempty, UTF-8-sorted,
   duplicate-free exact vector-ID list and all accepted vector joins;
8. an `IMPOSSIBLE` disposition has the accepted predicate, proof, direction,
   and exactly `vector_ids:[]`; and
9. a missing, extra, malformed, unknown, conflicting, or out-of-order row fails
   closed before vacuous-totality evaluation.

Then, symmetrically for `POSITIVE` and `NEGATIVE`, apply exactly:

```text
if |A(p,D)| == 0:
    valid exactly when L(p,D) == []

if |A(p,D)| >= 1 and L(p,D) == []:
    valid exactly when every a in A(p,D) has X(a).disposition == "IMPOSSIBLE"

if |A(p,D)| >= 1 and L(p,D) != []:
    apply every accepted bidirectional occurrence/vector and atom/vector join
    without change
```

The first rule is vacuous completeness. It creates no disposition row, proof,
predicate, vector, annotation, or surrogate. Because the global exact join is
already closed, a zero-atom direction has zero disposition rows for that key.

The second rule is the accepted all-atoms-impossible exception. One `VECTOR`
disposition, one atom without a disposition, one unproved atom, an unknown
disposition state, an unrecognized predicate, a malformed proof, a direction
mismatch, or a nonempty `vector_ids` member on an impossible row makes the empty
association invalid. A count of impossible rows is not sufficient; every exact
atom key must join its exact proof-bearing disposition.

The third rule changes no vector semantics. Existing exact association equality,
singleton cover, target pointer, subject, expected direction, vector ID,
instance identity, sorting, uniqueness, and reverse-join requirements remain in
force. An association list cannot contain a proof ID, a sibling vector, an
occurrence-presence surrogate, or an unknown vector.

Accepted fixture `G3VC-16` remains normative with this precise reading: for a
direction with one or more atoms, an empty ID list fails unless every exact atom
in that direction is discharged by a closed `IMPOSSIBLE` disposition. A
zero-atom direction is not a `G3VC-16` nonmatching occurrence-direction and is
valid only with an empty ID list. Thus direct `if` still requires witnesses for
both positive atoms, while its empty negative association is vacuously complete.

## 5. Fixture-first successor red suite

No repair may begin merely because this document exists. After and only after a
passing section-7 amendment receipt, a fixture author independent of the
amendment author, amendment reviewer, candidate author, and repair implementer
creates exactly these new fixture artifacts:

```text
review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/crosscheck_transport_totality_fixture_child_v1.py
review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/crosscheck_transport_totality_semantic_suite_v1.py
review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/test_crosscheck_schema_contracts_stdlib_v1_transport_totality_amendment_red.py
review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/STDLIB_CROSSCHECK_TRANSPORT_TOTALITY_AMENDMENT_RED_EVIDENCE.v1.json
```

The child is test-only and has no governed producer or launcher authority. It may
configure its own text wrapper to expose an old-source defect, replace
`run_crosscheck` with a closed synthetic return value, and install a fake stdout
buffer. None of those fixture-only powers enter the cross-check source or its
live process contract.

`crosscheck_transport_totality_semantic_suite_v1.py` contains exactly one
semantic method for each required ID below. Each method accepts a closed subject
binding supplied by its caller. That binding has exactly
`{path,size_bytes,sha256}` with the section-7 `file_identity` field semantics;
the suite stable-reads the bound path and requires the observed identity to equal
the binding before any method loads the subject. No semantic method contains a
candidate path, size, digest, `RED`/`GREEN` phase branch, or frozen/repaired
identity constant. The 20 method bodies and the child remain byte-identical when
a later contract reuses them against a repaired subject. Tests that inspect
source syntax parse the complete bound subject and fail on any unapproved
import, `sys` use, text output API, reflection escape, write API, or operation-
count drift. Tests that invoke `main` restore all test-owned process objects in
`finally` and never create governed evidence.

The red wrapper contains no semantic assertion logic. It stable-reads and binds
only the exact frozen candidate identity from section 0, imports the immutable
semantic suite, invokes all 20 methods in table order with that binding, and
records each underlying result for the evidence writer. The wrapper fails
before the first method if the subject identity differs. A future green wrapper
MUST bind a repaired identity separately and call the same exact semantic-suite
identity; section 8 reserves definition and authorization of that wrapper to a
separately accepted successor contract.

| Fixture ID | Exact construction | Repaired result | Exact frozen result |
|---|---|---|---|
| `G3CT-RED-01-WINDOWS-RAW-CRLF` | On native Windows, run the fixture child with raw stdout capture after forcing its text wrapper newline to `\r\n`; synthetic result is `{"probe":"ascii"}` | stdout is exact UTF-8 `{"probe":"ascii"}\n`, contains no CR, one write/flush, exit 0 | `EXPECTED_RED` |
| `G3CT-RED-02-CP1252-NONASCII` | Native Windows child forces `cp1252:strict`; synthetic result is `{"probe":"λ"}` | stdout is exact UTF-8 bytes for `{"probe":"λ"}\n`, independent of cp1252, exit 0 | `EXPECTED_RED` |
| `G3CT-RED-03-OVERSIZE-PLUS-ONE` | Synthetic document is an array of 2,048 strings: first 2,047 are 16,384 ASCII `a` characters and the last is 10,239; its `CJ || LF` is exactly 33,554,433 bytes | fail status 1 before buffer acquisition, zero writes, zero flushes, zero stderr | `EXPECTED_RED` |
| `G3CT-RED-04-EXACT-CAP` | Same array, except the last string is 10,238 characters; its `CJ || LF` is exactly 33,554,432 bytes | exact bytes accepted with one full binary write, one flush, zero stderr, exit 0 | `EXPECTED_RED` |
| `G3CT-RED-05-PARTIAL-WRITE` | Fake buffer records a strict nonempty prefix and returns that prefix length | status 1, exactly one write, zero flushes, no retry and no diagnostic echo | `EXPECTED_RED` |
| `G3CT-RED-06-NONE-WRITE` | Fake buffer returns `None` and records no bytes | status 1, exactly one write, zero flushes, no retry and no diagnostic echo | `EXPECTED_RED` |
| `G3CT-RED-07-SHORT-COUNT` | Fake buffer records all `raw` but returns `len(raw)-1` | status 1, exactly one write, zero flushes, no retry and no diagnostic echo | `EXPECTED_RED` |
| `G3CT-RED-08-FLUSH-FAILURE` | Full-count write succeeds; the first flush raises a fixture exception | status 1, exactly one write and one flush, no retry and no diagnostic echo | `EXPECTED_RED` |
| `G3CT-RED-09-ONE-WRITE-ONE-FLUSH` | Full-count fake buffer with flush returning exactly `None` | byte identity, exactly one write, exactly one flush, exit 0 | `EXPECTED_RED` |
| `G3CT-RED-10-IMPORT-SYS-CONFINEMENT` | Parse the complete repaired source and enumerate imports, name/attribute uses, calls, and write-capable APIs | exact five-module set; only the section-2 `sys` chain and binary operations exist; `re` and every escape/write API are absent | `EXPECTED_RED` |
| `G3CT-RED-11-ZERO-ATOM-VALID` | Generic occurrence-direction denominator has zero `VALID` atoms, `positive_vector_ids:[]`, and zero joined VALID dispositions | pass by vacuous completeness | `EXPECTED_RED` |
| `G3CT-RED-12-ZERO-ATOM-INVALID` | Generic occurrence-direction denominator has zero `INVALID` atoms, `negative_vector_ids:[]`, and zero joined INVALID dispositions | pass by vacuous completeness | `EXPECTED_RED` |
| `G3CT-RED-13-NONZERO-ALL-IMPOSSIBLE` | Direction has two exact atoms, both with unique valid `IMPOSSIBLE` dispositions, and an empty association | pass under the accepted all-impossible exception | `EXPECTED_PASS_UNCHANGED` |
| `G3CT-RED-14-NONZERO-ONE-VECTOR` | Same nonzero empty direction except one exact atom disposition is `VECTOR` | fail; G3VC-16 remains enforced | `EXPECTED_PASS_UNCHANGED` |
| `G3CT-RED-15-NONZERO-UNPROVED` | Same nonzero empty direction except one disposition state is `UNPROVED` | fail as unknown/malformed; no third disposition state exists | `EXPECTED_PASS_UNCHANGED` |
| `G3CT-RED-16-NONZERO-MISSING-DISPOSITION` | Same nonzero empty direction omits one exact atom disposition | fail exact denominator/disposition join | `EXPECTED_RED` |
| `G3CT-RED-17-DUPLICATE-DISPOSITION` | Two disposition rows claim the same exact atom key | fail before totality evaluation | `EXPECTED_RED` |
| `G3CT-RED-18-UNKNOWN-DISPOSITION-ATOM` | A disposition names an atom/pointer/direction outside the exact denominator | fail before totality evaluation | `EXPECTED_RED` |
| `G3CT-RED-19-DIRECT-IF-SYMMETRY` | Generic direct `if` has its exact two VALID atoms with vectors, zero INVALID atoms, and empty negative association | pass; removing a positive vector still fails | `EXPECTED_RED` |
| `G3CT-RED-20-CURRENT-12-SCHEMA-REGRESSION` | Independently rerun the complete current schema/occurrence/atom/proof census and all preexisting owned cross-check tests against the frozen 12 subjects | 12 / 7,517 / 21,578 / 891, exact per-subject atom vector and the two exact stream identities remain unchanged; vector semantics do not change | `EXPECTED_PASS_UNCHANGED` |

The size arithmetic for `G3CT-RED-03` and `G3CT-RED-04` is independently
checked in the test, not hard-coded as an assertion surrogate. For 2,048 JSON
strings, brackets, quotes, commas, and LF contribute 6,146 bytes. The first
2,047 string bodies contribute 33,538,048 bytes. A final body of 10,238 therefore
produces 33,554,432 bytes; 10,239 produces exactly one byte more. Every string
and the array remain within the accepted per-string and per-array bounds.

The frozen candidate MUST reproduce the exact table projection: 16
`EXPECTED_RED` results and four `EXPECTED_PASS_UNCHANGED` results. All 20 methods
MUST execute and record the underlying result. Any mismatch blocks; this
amendment defines no explanation, override, or reviewer-discretion escape. No
expected-red assertion may invert a failure into a test-framework pass without
recording the underlying old-source outcome.

## 6. Exact red evidence

The sole red-evidence path is the section-5 path. It is strict UTF-8 canonical
JSON plus exactly one LF, with no BOM or CR. It validates against the following
literal self-contained Draft-2020-12 schema. The schema is used in memory and is
not written as another artifact:

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_transport_totality_red_evidence.v1.schema.json",
  "$vocabulary":{
    "https://json-schema.org/draft/2020-12/vocab/core":true,
    "https://json-schema.org/draft/2020-12/vocab/applicator":true,
    "https://json-schema.org/draft/2020-12/vocab/validation":true
  },
  "$defs":{
    "file_identity":{"additionalProperties":false,"properties":{"path":{"maxLength":4096,"minLength":1,"pattern":"^(?!/)(?!.*//)(?!.*(?:^|/)\\.{1,2}(?:/|$))(?!.*[\\\\:\\x00-\\x1f\\x7f])[^/]+(?:/[^/]+)*$","type":"string"},"sha256":{"maxLength":64,"minLength":64,"pattern":"^[0-9a-f]{64}$","type":"string"},"size_bytes":{"maximum":9007199254740991,"minimum":0,"type":"integer"}},"required":["path","size_bytes","sha256"],"type":"object"},
    "fixture_id":{"enum":["G3CT-RED-01-WINDOWS-RAW-CRLF","G3CT-RED-02-CP1252-NONASCII","G3CT-RED-03-OVERSIZE-PLUS-ONE","G3CT-RED-04-EXACT-CAP","G3CT-RED-05-PARTIAL-WRITE","G3CT-RED-06-NONE-WRITE","G3CT-RED-07-SHORT-COUNT","G3CT-RED-08-FLUSH-FAILURE","G3CT-RED-09-ONE-WRITE-ONE-FLUSH","G3CT-RED-10-IMPORT-SYS-CONFINEMENT","G3CT-RED-11-ZERO-ATOM-VALID","G3CT-RED-12-ZERO-ATOM-INVALID","G3CT-RED-13-NONZERO-ALL-IMPOSSIBLE","G3CT-RED-14-NONZERO-ONE-VECTOR","G3CT-RED-15-NONZERO-UNPROVED","G3CT-RED-16-NONZERO-MISSING-DISPOSITION","G3CT-RED-17-DUPLICATE-DISPOSITION","G3CT-RED-18-UNKNOWN-DISPOSITION-ATOM","G3CT-RED-19-DIRECT-IF-SYMMETRY","G3CT-RED-20-CURRENT-12-SCHEMA-REGRESSION"],"type":"string"},
    "principal":{"additionalProperties":false,"properties":{"organization":{"maxLength":256,"minLength":1,"type":"string"},"principal_id":{"maxLength":256,"minLength":12,"pattern":"^executor:[a-z0-9-]+/[a-z0-9-]+$","type":"string"},"role":{"const":"Independent fixture-first transport-totality red executor","type":"string"}},"required":["principal_id","organization","role"],"type":"object"},
    "command":{"additionalProperties":false,"properties":{"argv":{"const":["python","-m","unittest","review_fixtures.program_facts_runtime_gate3.g3_00_schema_crosscheck.test_crosscheck_schema_contracts_stdlib_v1_transport_totality_amendment_red"],"type":"array"},"command_ordinal":{"const":0,"type":"integer"},"exit_code":{"const":0,"type":"integer"},"fixture_ids":{"const":["G3CT-RED-01-WINDOWS-RAW-CRLF","G3CT-RED-02-CP1252-NONASCII","G3CT-RED-03-OVERSIZE-PLUS-ONE","G3CT-RED-04-EXACT-CAP","G3CT-RED-05-PARTIAL-WRITE","G3CT-RED-06-NONE-WRITE","G3CT-RED-07-SHORT-COUNT","G3CT-RED-08-FLUSH-FAILURE","G3CT-RED-09-ONE-WRITE-ONE-FLUSH","G3CT-RED-10-IMPORT-SYS-CONFINEMENT","G3CT-RED-11-ZERO-ATOM-VALID","G3CT-RED-12-ZERO-ATOM-INVALID","G3CT-RED-13-NONZERO-ALL-IMPOSSIBLE","G3CT-RED-14-NONZERO-ONE-VECTOR","G3CT-RED-15-NONZERO-UNPROVED","G3CT-RED-16-NONZERO-MISSING-DISPOSITION","G3CT-RED-17-DUPLICATE-DISPOSITION","G3CT-RED-18-UNKNOWN-DISPOSITION-ATOM","G3CT-RED-19-DIRECT-IF-SYMMETRY","G3CT-RED-20-CURRENT-12-SCHEMA-REGRESSION"],"type":"array","uniqueItems":true},"stderr_sha256":{"maxLength":64,"minLength":64,"pattern":"^[0-9a-f]{64}$","type":"string"},"stderr_size_bytes":{"maximum":9007199254740991,"minimum":0,"type":"integer"},"stdout_sha256":{"maxLength":64,"minLength":64,"pattern":"^[0-9a-f]{64}$","type":"string"},"stdout_size_bytes":{"maximum":9007199254740991,"minimum":0,"type":"integer"}},"required":["command_ordinal","argv","exit_code","fixture_ids","stdout_size_bytes","stdout_sha256","stderr_size_bytes","stderr_sha256"],"type":"object"}
  },
  "additionalProperties":false,
  "properties":{
    "amendment":{"$ref":"#/$defs/file_identity"},
    "amendment_review":{"$ref":"#/$defs/file_identity"},
    "authority_ceiling":{"const":{"active_head_update":false,"clean_certification":false,"confidence":false,"consumer":false,"cutover":false,"finding":false,"package":false,"production_publication":false,"provider_launch":false,"refutation":false,"release":false,"replay":false,"runner":false,"runtime":false,"severity":false,"suppression":false,"terminal_negative":false},"type":"object"},
    "case_results":{"const":[{"fixture_id":"G3CT-RED-01-WINDOWS-RAW-CRLF","expected_frozen_result":"RED","observed_frozen_result":"RED"},{"fixture_id":"G3CT-RED-02-CP1252-NONASCII","expected_frozen_result":"RED","observed_frozen_result":"RED"},{"fixture_id":"G3CT-RED-03-OVERSIZE-PLUS-ONE","expected_frozen_result":"RED","observed_frozen_result":"RED"},{"fixture_id":"G3CT-RED-04-EXACT-CAP","expected_frozen_result":"RED","observed_frozen_result":"RED"},{"fixture_id":"G3CT-RED-05-PARTIAL-WRITE","expected_frozen_result":"RED","observed_frozen_result":"RED"},{"fixture_id":"G3CT-RED-06-NONE-WRITE","expected_frozen_result":"RED","observed_frozen_result":"RED"},{"fixture_id":"G3CT-RED-07-SHORT-COUNT","expected_frozen_result":"RED","observed_frozen_result":"RED"},{"fixture_id":"G3CT-RED-08-FLUSH-FAILURE","expected_frozen_result":"RED","observed_frozen_result":"RED"},{"fixture_id":"G3CT-RED-09-ONE-WRITE-ONE-FLUSH","expected_frozen_result":"RED","observed_frozen_result":"RED"},{"fixture_id":"G3CT-RED-10-IMPORT-SYS-CONFINEMENT","expected_frozen_result":"RED","observed_frozen_result":"RED"},{"fixture_id":"G3CT-RED-11-ZERO-ATOM-VALID","expected_frozen_result":"RED","observed_frozen_result":"RED"},{"fixture_id":"G3CT-RED-12-ZERO-ATOM-INVALID","expected_frozen_result":"RED","observed_frozen_result":"RED"},{"fixture_id":"G3CT-RED-13-NONZERO-ALL-IMPOSSIBLE","expected_frozen_result":"PASS_UNCHANGED","observed_frozen_result":"PASS_UNCHANGED"},{"fixture_id":"G3CT-RED-14-NONZERO-ONE-VECTOR","expected_frozen_result":"PASS_UNCHANGED","observed_frozen_result":"PASS_UNCHANGED"},{"fixture_id":"G3CT-RED-15-NONZERO-UNPROVED","expected_frozen_result":"PASS_UNCHANGED","observed_frozen_result":"PASS_UNCHANGED"},{"fixture_id":"G3CT-RED-16-NONZERO-MISSING-DISPOSITION","expected_frozen_result":"RED","observed_frozen_result":"RED"},{"fixture_id":"G3CT-RED-17-DUPLICATE-DISPOSITION","expected_frozen_result":"RED","observed_frozen_result":"RED"},{"fixture_id":"G3CT-RED-18-UNKNOWN-DISPOSITION-ATOM","expected_frozen_result":"RED","observed_frozen_result":"RED"},{"fixture_id":"G3CT-RED-19-DIRECT-IF-SYMMETRY","expected_frozen_result":"RED","observed_frozen_result":"RED"},{"fixture_id":"G3CT-RED-20-CURRENT-12-SCHEMA-REGRESSION","expected_frozen_result":"PASS_UNCHANGED","observed_frozen_result":"PASS_UNCHANGED"}],"type":"array","uniqueItems":true},
    "commands":{"items":{"$ref":"#/$defs/command"},"maxItems":1,"minItems":1,"type":"array"},
    "disposition":{"const":"RED_CONFIRMED_FIXTURE_FIRST_CROSSCHECK_REPAIR_MAY_BEGIN","type":"string"},
    "evidence_body_sha256":{"maxLength":64,"minLength":64,"pattern":"^[0-9a-f]{64}$","type":"string"},
    "evidence_id":{"maxLength":39,"minLength":39,"pattern":"^pfg3te-[0-9a-f]{32}$","type":"string"},
    "executor":{"$ref":"#/$defs/principal"},
    "fixture_child":{"$ref":"#/$defs/file_identity"},
    "fixture_red_wrapper":{"$ref":"#/$defs/file_identity"},
    "fixture_semantic_suite":{"$ref":"#/$defs/file_identity"},
    "frozen_candidate_source":{"const":{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/crosscheck_schema_contracts_stdlib_v1.py","sha256":"e3cdd2599cf05d7f0c2b256d45d88e52f04fe15890d74a38bb296be44c1b5fb5","size_bytes":190456},"type":"object"},
    "frozen_pending_handoff":{"const":{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_IMPLEMENTATION_HANDOFF.PENDING.v1.json","sha256":"e6bb2fa49d8bb7f81d510cc9212532cb3c8ac36ab3781fc2b2e9c48a43fa24e6","size_bytes":12054},"type":"object"},
    "independence":{"const":{"amendment_author_separate":true,"amendment_reviewer_separate":true,"candidate_author_separate":true,"no_self_generated_acceptance":true,"repair_implementer_separate":true},"type":"object"},
    "platform":{"additionalProperties":false,"properties":{"implementation":{"const":"CPython","type":"string"},"operating_system":{"const":"WINDOWS","type":"string"},"python_version":{"pattern":"^3\\.12\\.[0-9]+$","type":"string"},"stdout_capture_mode":{"const":"RAW_BYTES","type":"string"}},"required":["implementation","python_version","operating_system","stdout_capture_mode"],"type":"object"},
    "post_run_candidate_source":{"const":{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/crosscheck_schema_contracts_stdlib_v1.py","sha256":"e3cdd2599cf05d7f0c2b256d45d88e52f04fe15890d74a38bb296be44c1b5fb5","size_bytes":190456},"type":"object"},
    "post_run_pending_handoff":{"const":{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_IMPLEMENTATION_HANDOFF.PENDING.v1.json","sha256":"e6bb2fa49d8bb7f81d510cc9212532cb3c8ac36ab3781fc2b2e9c48a43fa24e6","size_bytes":12054},"type":"object"},
    "red_case_count":{"const":16,"type":"integer"},
    "schema_version":{"const":"plamen.program_facts_g3_00_stdlib_crosscheck_transport_totality_red_evidence.v1","type":"string"},
    "unchanged_pass_case_count":{"const":4,"type":"integer"}
  },
  "required":["schema_version","evidence_id","amendment","amendment_review","frozen_candidate_source","frozen_pending_handoff","fixture_child","fixture_semantic_suite","fixture_red_wrapper","executor","independence","platform","commands","case_results","red_case_count","unchanged_pass_case_count","post_run_candidate_source","post_run_pending_handoff","disposition","authority_ceiling","evidence_body_sha256"],
  "type":"object"
}
```

The three fixture identities bind exactly the three section-5 source paths.
`amendment` binds this amendment and `amendment_review` binds the sole section-7
receipt. The one command row's literal `fixture_ids` array is duplicate-free and
is byte-for-byte the ordered projection of `case_results[*].fixture_id`; it also
equals the complete section-5 table order. No second command, absent case,
duplicate case, reordered case, result outside the literal array, or command-to-
case mismatch validates. The exact result projection contains 16 `RED` and four
`PASS_UNCHANGED` rows. There is no unexpected-result, mismatch, explanation,
waiver, or external-review escape in the schema. If observation differs, no
passing red-evidence artifact can be formed and repair remains blocked.

Rejected stdout/stderr bytes are represented only by size and digest in the
command row; they are not copied into evidence. Secrets and error text are never
recorded. The frozen and post-run identities are literal and equal, closing the
no-mutation chronology. Schema validation is followed by independent checks of
the exact paths, identity formulas, command execution, raw Windows capture, case
projection, counts, and fixture-author provenance.

The passing disposition authorizes only the bounded repair described here.

The authority ceiling is the exact 17-member all-false object in section 9.
Let `identity_body` omit only `evidence_id` and `evidence_body_sha256`. Then:

```text
evidence_id = "pfg3te-" || SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_TRANSPORT_TOTALITY_RED_EVIDENCE_V1",
  evidence:identity_body
}))[0:32]
evidence_body_sha256 = SHA-256(CJ(full_evidence_without_only_evidence_body_sha256))
evidence_file = CF(full_evidence)
```

The fixture evidence is chronology and regression evidence only. It is not an
amendment review, source review, candidate acceptance, parity evidence, process
capture, vector evidence, or admission receipt.

## 7. Independent amendment review receipt

The identity reviewed is the stable file identity of exactly:

```text
architecture/program-facts-g3-00-stdlib-crosscheck-transport-totality-amendment.md
```

The amendment does not self-hash. An independent reviewer performs three
byte-identical reads; requires strict UTF-8, LF only, no BOM, no CR, no tab,
no trailing whitespace, and exactly one final LF; and places the external
identity in `subject`.

The one permitted receipt path is:

```text
review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_TRANSPORT_TOTALITY_AMENDMENT_INDEPENDENT_REVIEW.v1.json
```

The receipt MUST validate as a parsed value against this literal, self-contained
Draft-2020-12 schema. The schema is used in memory and MUST NOT be written as a
separate artifact:

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://plamen.local/schemas/program_facts_g3_00_stdlib_crosscheck_transport_totality_amendment_review.v1.schema.json",
  "$vocabulary":{
    "https://json-schema.org/draft/2020-12/vocab/core":true,
    "https://json-schema.org/draft/2020-12/vocab/applicator":true,
    "https://json-schema.org/draft/2020-12/vocab/validation":true
  },
  "$defs":{
    "file_identity":{"additionalProperties":false,"properties":{"path":{"maxLength":4096,"minLength":1,"pattern":"^(?!/)(?!.*//)(?!.*(?:^|/)\\.{1,2}(?:/|$))(?!.*[\\\\:\\x00-\\x1f\\x7f])[^/]+(?:/[^/]+)*$","type":"string"},"sha256":{"maxLength":64,"minLength":64,"pattern":"^[0-9a-f]{64}$","type":"string"},"size_bytes":{"maximum":9007199254740991,"minimum":0,"type":"integer"}},"required":["path","size_bytes","sha256"],"type":"object"},
    "finding":{"additionalProperties":false,"properties":{"description":{"maxLength":8192,"minLength":1,"type":"string"},"evidence":{"items":{"$ref":"#/$defs/file_identity"},"maxItems":10000000,"minItems":1,"type":"array","uniqueItems":true},"finding_id":{"maxLength":512,"minLength":1,"pattern":"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,511}$","type":"string"},"severity":{"enum":["BLOCKING","NONBLOCKING"],"type":"string"},"status":{"enum":["OPEN","CLOSED"],"type":"string"}},"required":["finding_id","severity","status","description","evidence"],"type":"object"}
  },
  "additionalProperties":false,
  "properties":{
    "accepted_scope":{"const":["G3_00_STDLIB_CROSSCHECK_TRANSPORT_TOTALITY_AMENDMENT_FOR_FIXTURE_FIRST_REPAIR_ONLY"],"type":"array"},
    "authority_ceiling":{"const":{"active_head_update":false,"clean_certification":false,"confidence":false,"consumer":false,"cutover":false,"finding":false,"package":false,"production_publication":false,"provider_launch":false,"refutation":false,"release":false,"replay":false,"runner":false,"runtime":false,"severity":false,"suppression":false,"terminal_negative":false},"type":"object"},
    "candidate_baseline":{"const":[{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/crosscheck_schema_contracts_stdlib_v1.py","sha256":"e3cdd2599cf05d7f0c2b256d45d88e52f04fe15890d74a38bb296be44c1b5fb5","size_bytes":190456},{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_IMPLEMENTATION_HANDOFF.PENDING.v1.json","sha256":"e6bb2fa49d8bb7f81d510cc9212532cb3c8ac36ab3781fc2b2e9c48a43fa24e6","size_bytes":12054}],"type":"array"},
    "checks":{"items":{"additionalProperties":false,"properties":{"check_id":{"enum":["G3CT-R01-PARENT-AND-BASELINE-PINS","G3CT-R02-NARROW-SCOPE-PRECEDENCE","G3CT-R03-IMPORT-AND-SYS-CONFINEMENT","G3CT-R04-CANONICAL-BINARY-STDOUT-CAP","G3CT-R05-WRITE-FLUSH-FAIL-CLOSED","G3CT-R06-ZERO-ATOM-SYMMETRIC-TOTALITY","G3CT-R07-NONZERO-DISPOSITION-G3VC16","G3CT-R08-FIXTURE-FIRST-RED-EVIDENCE","G3CT-R09-CENSUS-AND-VECTOR-SEMANTICS","G3CT-R10-AUTHORITY-DAG-INDEPENDENCE"],"type":"string"},"evidence":{"items":{"$ref":"#/$defs/file_identity"},"maxItems":10000000,"minItems":1,"type":"array","uniqueItems":true},"result":{"enum":["PASS","FAIL"],"type":"string"}},"required":["check_id","result","evidence"],"type":"object"},"maxItems":10,"minItems":10,"type":"array","uniqueItems":true},
    "disposition":{"enum":["PASS_G3_00_STDLIB_CROSSCHECK_TRANSPORT_TOTALITY_FOR_FIXTURE_FIRST_REPAIR_ONLY","REJECTED"],"type":"string"},
    "findings":{"items":{"$ref":"#/$defs/finding"},"maxItems":10000000,"minItems":0,"type":"array","uniqueItems":true},
    "independence":{"const":{"amendment_author_separate":true,"candidate_author_separate":true,"launcher_author_separate":true,"no_self_approval":true,"production_implementer_separate":true,"schema_builder_separate":true,"vector_author_separate":true},"type":"object"},
    "normative_parents":{"const":[{"path":"architecture/program-facts-g3-00-schema-vector-clarification-amendment.md","sha256":"f03b07bea209dde4cf2cf8dcebd3e4c618a5fd56196c4448594a9d744136f7fa","size_bytes":80218},{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/PROGRAM_FACTS_G3_00_SCHEMA_VECTOR_CLARIFICATION_AMENDMENT_INDEPENDENT_REVIEW.v1.json","sha256":"3db4b56a2132bbd5d8dd7cb59bb68cdb4e32aa5f109da55420b05b786fee5e92","size_bytes":15568}],"type":"array"},
    "open_findings":{"items":{"maxLength":512,"minLength":1,"pattern":"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,511}$","type":"string"},"maxItems":10000000,"minItems":0,"type":"array","uniqueItems":true},
    "protected_input_validation":{"const":{"post_review_reads_each":3,"pre_post_identities_equal":true,"pre_review_reads_each":3,"predicate":"EXACT_FOUR_PINNED_INPUTS_READ_THREE_TIMES_BEFORE_AND_AFTER_REVIEW;ALL_SIX_READS_BYTE_IDENTICAL_PER_PATH;PRE_IDENTITY_EQUALS_POST_IDENTITY;NO_WRITE_OPEN_OR_MUTATION_API_TARGETED_A_PROTECTED_PATH_DURING_THE_SCOPED_REVIEW","protected_inputs":[{"path":"architecture/program-facts-g3-00-schema-vector-clarification-amendment.md","sha256":"f03b07bea209dde4cf2cf8dcebd3e4c618a5fd56196c4448594a9d744136f7fa","size_bytes":80218},{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_closure/PROGRAM_FACTS_G3_00_SCHEMA_VECTOR_CLARIFICATION_AMENDMENT_INDEPENDENT_REVIEW.v1.json","sha256":"3db4b56a2132bbd5d8dd7cb59bb68cdb4e32aa5f109da55420b05b786fee5e92","size_bytes":15568},{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/crosscheck_schema_contracts_stdlib_v1.py","sha256":"e3cdd2599cf05d7f0c2b256d45d88e52f04fe15890d74a38bb296be44c1b5fb5","size_bytes":190456},{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_IMPLEMENTATION_HANDOFF.PENDING.v1.json","sha256":"e6bb2fa49d8bb7f81d510cc9212532cb3c8ac36ab3781fc2b2e9c48a43fa24e6","size_bytes":12054}],"review_observation_scope":"FROM_FIRST_PRE_REVIEW_READ_THROUGH_FINAL_POST_REVIEW_READ","write_operations_observed":[],"writes_permitted":[]},"type":"object"},
    "review_body_sha256":{"maxLength":64,"minLength":64,"pattern":"^[0-9a-f]{64}$","type":"string"},
    "review_id":{"maxLength":39,"minLength":39,"pattern":"^pfg3tr-[0-9a-f]{32}$","type":"string"},
    "reviewer":{"additionalProperties":false,"properties":{"organization":{"maxLength":256,"minLength":1,"type":"string"},"principal_id":{"maxLength":256,"minLength":12,"pattern":"^reviewer:[a-z0-9-]+/[a-z0-9-]+$","type":"string"},"role":{"maxLength":256,"minLength":1,"type":"string"}},"required":["principal_id","organization","role"],"type":"object"},
    "schema_version":{"const":"plamen.program_facts_g3_00_stdlib_crosscheck_transport_totality_amendment_review.v1","type":"string"},
    "subject":{"$ref":"#/$defs/file_identity"}
  },
  "required":["schema_version","review_id","subject","normative_parents","candidate_baseline","protected_input_validation","reviewer","independence","checks","findings","open_findings","disposition","accepted_scope","authority_ceiling","review_body_sha256"],
  "type":"object"
}
```

The exact 10 checks occur once each in displayed numeric order and mean:

1. `G3CT-R01-PARENT-AND-BASELINE-PINS`: the exact scoped protected-input
   predicate performs three byte-identical reads of each of the four section-0
   inputs before review and three afterward; all six reads per path are equal,
   pre/post identities match, no write is permitted or observed against those
   paths during that interval, and no nonexistent cross-check review artifact is
   claimed. It makes no whole-workspace cleanliness assertion.
2. `G3CT-R02-NARROW-SCOPE-PRECEDENCE`: the successor controls only the five-name
   import/CLI transport and zero-atom direction rule; every other accepted rule
   remains immutable.
3. `G3CT-R03-IMPORT-AND-SYS-CONFINEMENT`: the exact static boundary in section 2
   permits the one top-level direct `import sys` and otherwise permits `sys` only
   for `sys.stdout.buffer` in `main`; it closes text, reflection, transitive-
   module, filesystem-write, process, network, `re`, and error-echo paths while
   preserving only the inherited stable input-byte identity read of launcher
   source.
4. `G3CT-R04-CANONICAL-BINARY-STDOUT-CAP`: the reviewer independently recomputes
   `CF`, strict UTF-8/no-BOM/no-CR/one-LF requirements, inclusive 33,554,432-byte
   cap, +1 rejection, and code-page/newline independence.
5. `G3CT-R05-WRITE-FLUSH-FAIL-CLOSED`: exact one-write/one-flush success and all
   None/partial/short/count/flush failures have status 1, no retry, no second
   write, and no secret/error echo.
6. `G3CT-R06-ZERO-ATOM-SYMMETRIC-TOTALITY`: both directions derive their exact
   atom denominator independently; zero atoms plus an empty association are
   vacuously complete and do not create a proof or vector.
7. `G3CT-R07-NONZERO-DISPOSITION-G3VC16`: nonzero empty directions pass only
   when every exact atom has one closed impossible disposition; missing,
   duplicate, malformed, unknown, `VECTOR`, or unproved rows fail and G3VC-16 is
   preserved.
8. `G3CT-R08-FIXTURE-FIRST-RED-EVIDENCE`: sections 5-6 define the immutable
   parameterized semantic suite, separate frozen-subject red wrapper, exact
   paths/principals, 20-case and command projections, exact 16-red/four-unchanged
   result roster, raw Windows transport, cap arithmetic, recursively closed
   evidence schema/identity, and frozen-input chronology. This contract check
   does not claim that the future fixtures were authored or run.
9. `G3CT-R09-CENSUS-AND-VECTOR-SEMANTICS`: exact 12/7,517/21,578/891 counts,
   per-subject counts, atom/proof identities, predicate roster, proof semantics,
   and all vector semantics remain unchanged.
10. `G3CT-R10-AUTHORITY-DAG-INDEPENDENCE`: amendment, review, fixture, and repair
    principals are separated, no self-approval is possible, the repair-only DAG
    stops before green evidence or re-review, all 17 authority flags are false,
    and a pass grants fixture-first repair only.

Evidence arrays sort by `(UTF8(path),size_bytes,sha256)` and reject duplicates.
Findings sort by UTF-8 `finding_id`. `open_findings` is exactly the ordered
projection of IDs whose status is `OPEN`. A passing receipt requires all 10
checks `PASS` with nonempty evidence, no open blocking finding, exact pins,
the literal protected-input validation object, exact accepted scope, every
independence member true, and the exact all-false authority object. The scoped
predicate is realizable without requiring a clean concurrent worktree: it
observes only the four listed paths between its first pre-review and last
post-review read. JSON Schema validation alone is insufficient; the reviewer
independently performs each semantic check.

At receipt time the reviewer principal MUST be different from the amendment
author, candidate author, launcher author, schema builder, vector author, and
production implementer, exactly as the receipt can presently verify. The later
fixture author, repair implementer, successor-contract reviewer, repair reviewer,
canonical adopter, and admission reviewer must each prove separation from this
reviewer when and if a later authorized artifact binds that principal. Role-label
changes do not make one principal independent. The amendment author MUST NOT
write this receipt. The reviewer MUST NOT later implement or approve the repair
whose authority derives from it.

Let `identity_body` be the complete receipt excluding exactly `review_id` and
`review_body_sha256`. The identities are:

```text
review_id = "pfg3tr-" || SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_TRANSPORT_TOTALITY_AMENDMENT_REVIEW_V1",
  review:identity_body
}))[0:32]
review_body_sha256 = SHA-256(CJ(full_review_without_only_review_body_sha256))
review_file = CF(full_review)
```

The receipt is strict UTF-8 canonical JSON plus exactly one LF, with no BOM or
CR. It names and hashes neither itself nor any future fixture, repaired source,
repaired handoff, re-review, canonical copy, vector, parity output, launcher
capture, or admission artifact.

## 8. Acyclic fixture-first repair order and successor reservation

The only valid dependency order is:

1. preserve the accepted clarification amendment and receipt byte-for-byte;
2. preserve the exact candidate source and PENDING handoff byte-for-byte;
3. stable-read this amendment three times and derive its external identity;
4. the independent amendment reviewer writes only the section-7 receipt and a
   separate validator confirms its schema, formulas, pins, checks, independence,
   findings projection, disposition, scope, and all-false authority;
5. only after a passing receipt, the independent fixture author writes the
   child, immutable semantic suite, and red binding wrapper, runs the exact one-
   command/20-case projection against the still-frozen candidate, and writes
   only the canonical section-6 red evidence;
6. independently validate the red-evidence schema/formulas, exact 16-red/four-
   unchanged chronology, command-to-case projection, cap arithmetic, platform/
   raw-capture facts, fixture identities, and unchanged candidate/handoff
   post-run identities;
7. only after valid red evidence, one repair implementer modifies the candidate
   source strictly within sections 2-4 without modifying the child, semantic
   suite, red wrapper, red evidence, accepted pair, or historical PENDING
   handoff; and
8. stop. This amendment defines no green subject binding, green wrapper, green
   evidence, successor handoff, repair-review receipt, canonical-adoption
   receipt, or authority to create or execute any of them.

A later separately authored and independently accepted successor contract is
REQUIRED before any formal green execution, green evidence, successor handoff,
repair re-review, candidate acceptance, or canonical adoption. Their paths,
schemas, identities, ID/body formulas, principals, and dispositions are
intentionally undefined here and MUST NOT be inferred from a red artifact or
invented during repair. The later contract must at minimum pin this amendment,
its accepted receipt, the exact red evidence, the repaired candidate identity,
and the byte-identical semantic-suite identity; define a separate repaired-
subject binding wrapper; define recursively closed green, handoff, and review
artifacts; require red-before-repair-before-green chronology; and preserve every
independence and all-false authority boundary. Those are requirements on a
future contract, not authority granted by this one.

The bounded repair MUST NOT proceed unless every applicable fact below holds:

- the accepted parent pair and this amendment/receipt are exact stable inputs;
- the section-6 red evidence predates the first repaired source identity;
- the source imports exactly `hashlib`, `json`, `pathlib`, `typing`, and `sys`;
- `sys` and the buffer have only the closed section-2 use;
- raw success output is exact `CF`, including under forced CRLF and cp1252;
- exact-cap success and +1 pre-write failure are independently measured;
- None, partial, short-count, and flush failures make no retry or diagnostic echo;
- zero-atom VALID and INVALID directions pass only with empty associations;
- nonzero all-impossible passes, while `VECTOR`, unproved, missing, duplicate,
  malformed, and unknown dispositions fail;
- the direct-`if` regression and G3VC-16 both pass;
- the exact 12/7,517/21,578/891 census and stream identities reproduce;
- no accepted vector meaning, predicate, proof, atom, occurrence, or authority
  flag changed;
- the repair changes only the candidate source behavior controlled by sections
  2-4; and
- amendment-review, fixture, and repair provenance proves no self-authorship or
  self-approval.

No step may backfill red chronology, overwrite the historical handoff, treat an
old passing test as successor red evidence, or use a candidate/reviewer majority
vote. A failure at any step blocks later steps without degrading to a warning.
Completion of the repair is the terminal state under this amendment; it is not
a green result or review disposition.

## 9. Authority ceiling and Part-0 genericity

The exact authority ceiling for this amendment, its receipt, its fixture
evidence, and the bounded repaired candidate is:

```json
{"active_head_update":false,"clean_certification":false,"confidence":false,"consumer":false,"cutover":false,"finding":false,"package":false,"production_publication":false,"provider_launch":false,"refutation":false,"release":false,"replay":false,"runner":false,"runtime":false,"severity":false,"suppression":false,"terminal_negative":false}
```

All 17 flags are false. A passing amendment receipt permits only authorship and
execution of the fixture-first red suite followed by the bounded candidate
repair described here. It grants no formal green execution/evidence, successor
handoff, repair re-review, candidate acceptance, canonical promotion, canonical
installation, vector construction or acceptance, process capture, three-way
parity, G3-00 admission, replay, provider or runner authorization, runtime,
package, publication, release, commit, push, install, audit, or cutover
authority.

This is a Part-0 generic transport and relational-totality rule. Its synthetic
fixtures use only generic JSON values, occurrence pointers, directions, atoms,
dispositions, byte streams, and failure-injection buffers. They MUST NOT contain
ecosystem-, language-, provider-, contract-, instruction-, or vulnerability-
specific hints, seeds, names, expected findings, or semantic shortcuts. The one
current 12-subject regression is an identity/count preservation check and MUST
NOT be mined to add domain-specific fixture guidance. A later protocol-specific
consumer receives no new fact, waiver, or authority from this amendment.
