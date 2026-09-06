# Plamen Chain-Tail PhaseIO Residual Closure Receipt

Date: 2026-07-24  
Implementation repository: `<LOCAL_USER_ROOT>\plamen-codex-implementation`  
Branch: `codex/recall-app-benchmark-r10_1`  
Base `HEAD`: `67a0f85adc7a8169d79a286908b00bef7adb764a`  
Working-tree policy: uncommitted; nothing pushed

## Scope and disposition

This receipt closes only the residual B12, B14, and B15 blockers identified by
`Plamen_ChainTail_PhaseIO_Adversarial_Review_2026-07-24.md`. It does not
re-adjudicate the earlier B1-B16 implementation and does not authorize a merge,
push, benchmark, or production audit.

Disposition: the residual implementation blockers are fixture-closed and all
specified regression lanes are green. The state is ready for independent
read-only review and program-level refreeze.

## Red evidence before implementation

The six requested designs produced seven tests because the raw-byte success
case is parameterized over LF and CRLF. Before the production changes, the
focused command produced:

`7 failed, 41 deselected in 12.30s`

Observed failures:

- raw primary Markdown committed without any ChainAgent2 MODEL producer;
- exact LF producer lacked a receipt binding;
- unchanged CRLF bytes were re-encoded and hashed as normalized text;
- post-producer output-byte drift was not rejected;
- retry after a marker-unlink `OSError` left publication armed;
- orphan `HUMAN_REVIEW` debt failed authority and routing parity;
- one grouped chain over two composed pairs failed routing parity.

## Implemented closure

### B12: exact ChainAgent2 producer and byte-faithful authority

- `scripts/plamen_driver.py:6758` validates one exact same-run
  `chain_agent2/model` work unit.
- Validation covers the registered contract manifest and digest, exact input
  denominator and input-set digest, ACTIVE live input hashes, all three
  ACTIVE/OUTPUT_COMMITTED MODEL outputs, global ownership bindings, run ID,
  contract digest, raw output bytes, and output sizes.
- `scripts/chain_tail_authority.py:1106` requires the validated producer
  summary when writing the primary DRIVER receipt.
- `scripts/plamen_driver.py:7536` replays the embedded binding against the live
  PhaseIO ledger and raw source bytes before final reconciliation.
- `scripts/chain_tail_authority.py:939` hashes untouched raw bytes. It uses a
  separately newline-normalized text view only for parsing, preserving
  identical behavior for LF and CRLF without creating authority aliases.
- The terminal snapshot binds the embedded ChainAgent2 producer summary.

### B15: consumptive crash recovery

- `scripts/plamen_driver.py:8198` treats the durable publication marker as the
  recovery authority after an idempotent PhaseIO commit.
- If output commit succeeded and marker unlink crashed, an exact replay may
  return `execute=False` but still consumes the marker.
- The replay does not rewrite root outputs; the fixture proves root artifact
  hashes remain unchanged and re-arm remains control-only.

### B14: grouped unions and visible human-review debt

- `scripts/chain_tail_authority.py:3439` validates the complete deterministic
  candidate projection instead of reducing it to one `pair_id` per row.
- An ordinary composed chain carries the union of every COMPOSED `pair_ids`
  member and the corresponding constituent findings.
- An orphan chain section remains proof-less `HUMAN_REVIEW` debt with no pair
  IDs and does not block delivery of ordinary candidates.
- The validator separately constrains proof authority and the only two legal
  routes. No human-review row gains proof or report authority.

## Fixture evidence

Focused residual fixture locations:

- `scripts/test_chain_tail_isolated_phase_io_p0_t.py:312`
- `scripts/test_chain_tail_isolated_phase_io_p0_t.py:346`
- `scripts/test_chain_tail_isolated_phase_io_p0_t.py:394`
- `scripts/test_chain_tail_isolated_phase_io_p0_t.py:1499`
- `scripts/test_chain_tail_compound_delivery_p0_t.py:365`
- `scripts/test_chain_tail_compound_delivery_p0_t.py:410`

Focused post-implementation result:

`7 passed, 41 deselected in 9.70s`

Complete affected-file result:

`48 passed in 35.64s`

## Regression evidence

| Lane | Result |
|---|---:|
| Chain-tail aggregate | 129 passed |
| Former-red driver/compiler/adapter lane | 145 passed |
| PhaseIO and Claude-boundary lane | 224 passed |
| Broad authority lane | 354 passed |
| Python compilation | passed |
| Targeted `git diff --check` | passed |

One regression was detected during the chain-tail aggregate lane: keeping CRLF
in the parsing view made a line-anchored chain-heading regex miss an otherwise
unchanged heading. The fix explicitly separates raw authority bytes from a
newline-normalized parsing view. The failing standalone fixture then passed,
and the full 129-test lane was rerun green.

## Frozen file hashes

SHA-256 values are over the exact bytes reviewed by the test lanes:

| File | SHA-256 |
|---|---|
| `scripts/chain_tail_authority.py` | `8615451408952DD7804C80F055F845EDEE1C24F35576DE8AA63B998659E85936` |
| `scripts/plamen_driver.py` | `2077EE8E4A8BDFDFF1FB70FAF44B46EE3EDB92D1A22C59D32E0B78397E7DA9A1` |
| `scripts/test_chain_tail_isolated_phase_io_p0_t.py` | `CD28522CAE7720373F7D0A245AC842394BEC1C190CAA0A59FF76D9C9C26882D2` |
| `scripts/test_chain_tail_compound_delivery_p0_t.py` | `DFF145143888F6331D8B370E145BFDD6933C16F262837745F82F087CDED6F81A` |
| `Plamen_ChainTail_PhaseIO_Adversarial_Review_2026-07-24.md` | `CFFF6873B70246F87BFA6CCF2F303E001830DBFB4AB758B312950FC1C9AF6288` |

## Remaining boundary

The repository intentionally has a large pre-existing uncommitted program
delta, including untracked implementation files. This receipt therefore
freezes exact file bytes rather than claiming a clean Git commit boundary.
Independent review must compare these hashes and review only the B12/B14/B15
surface. Any subsequent edit to a frozen file invalidates this receipt and
requires rerunning the affected lanes.
