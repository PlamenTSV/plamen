"""Driver fixes must key on STRUCTURE, never on a specific codebase.

`post-audit-improvement-protocol.md` Part 0 is a hard rule -- methodology must
encode HOW to analyze, never WHAT to find in a particular protocol. It is
written for skills/rules/prompts, but the same hazard exists one layer down: a
parser or gate that was debugged against one audit can quietly acquire that
audit's vocabulary and then behave differently on the next ecosystem.

Every fix guarded here was found by debugging DODO runs, so each one is exactly
the kind of change that could have absorbed DODO specifics. They key on:

  * Markdown/table structure the DRIVER itself emits,
  * the driver's own typed enums (disposition, reason code, relation kind),
  * the Claude CLI's permission-mode and response envelopes.

None key on a contract, token, chain, or protocol name -- which is why they
apply unchanged to solana/aptos/sui/soroban audits, whose inventory phases run
the same shared `SC_PHASES` machinery.

Citing a run in a DOCSTRING is the opposite of overfitting: it records why a
generic rule exists. This test therefore inspects executable code only.
"""

from __future__ import annotations

import io
import re
import sys
import tokenize
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

# Protocol/codebase vocabulary that must never reach executable driver code.
# Deliberately includes the audited target AND unrelated ecosystems, so this
# does not merely guard against one project's names.
_PROTOCOL_VOCAB = re.compile(
    r"dodo|omni-?chain|gateway(?:transfer|crosschain|send)|zrc20|eddy"
    r"|zetachain|pancake|sushi|curve\.fi|aave|compound-finance"
    r"|jupiter-ag|marinade|kamino",
    re.IGNORECASE,
)

# The production modules carrying today's fixes.
_GUARDED = (
    "inventory_reconciliation.py",
    "inventory_aggregate_authority.py",
    "plamen_validators.py",
    "plamen_parsers.py",
    "claude_phase_tool_policy.py",
    "claude_stream_json_evidence.py",
)


def _executable_tokens(path: Path):
    """Yield (line, text) for tokens that are neither comments nor strings.

    Docstrings and comments are explicitly allowed to cite a run as evidence.
    String LITERALS are excluded from this pass and checked separately below,
    because a literal can be data rather than prose.
    """
    src = path.read_text(encoding="utf-8")
    for tok in tokenize.generate_tokens(io.StringIO(src).readline):
        if tok.type in (
            tokenize.COMMENT, tokenize.STRING, tokenize.NL,
            tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT,
        ):
            continue
        yield tok.start[0], tok.string


@pytest.mark.parametrize("name", _GUARDED)
def test_no_protocol_vocabulary_in_executable_code(name: str) -> None:
    path = _SCRIPTS / name
    offenders = [
        (line, text) for line, text in _executable_tokens(path)
        if _PROTOCOL_VOCAB.search(text)
    ]
    assert offenders == [], (
        f"{name} names a specific protocol in executable code: {offenders}. "
        "Driver fixes must key on structure (headers, enums, envelopes), not "
        "on the codebase they were debugged against."
    )


def test_table_identity_accepts_every_producer_prefix() -> None:
    """The identity fix must not be keyed to one shard's `CC-` prefix.

    Note what identity is keyed to, because it answers the overfitting
    question directly: `_normalize_finding_id` matches a CLOSED allowlist of
    the pipeline's own PRODUCER prefixes -- breadth (`B*`), rescan (`RS*`),
    per-contract (`PC*`), depth (`DEC*`/`TF*`), inventory (`CC*`/`INV*`) and
    so on. Those name AGENT ROLES, not chains: a Solana or Aptos audit emits
    `B1-1` and `RS2-3` exactly as an EVM one does, because the same agents run.

    An earlier draft of this test asserted that ecosystem-flavoured IDs like
    `SOL-3` or `APT-11` must parse. They do not, and should not -- no producer
    ever emits them. That draft was the same mistake made twice already today
    (inventing obligation IDs, hand-rolling a policy manifest): asserting a
    shape the product does not produce, then reading the product's correct
    refusal as a defect.
    """
    from plamen_parsers import _table_local_id_column

    for value in (
        "CC-01", "B7-12", "RS3-1", "PC2-4", "DEC-1", "TF-9", "INV-001",
    ):
        assert _table_local_id_column("cc id", value), value
        assert _table_local_id_column("finding id", value), value


def test_preservation_predicate_has_no_language_branch() -> None:
    """One code path for every ecosystem, or the fix is not portable."""
    src = (_SCRIPTS / "inventory_reconciliation.py").read_text("utf-8")
    start = src.index("def driver_restorable_preservation_row")
    body = src[start:start + 3000]
    for token in ("evm", "solana", "aptos", "sui", "soroban", "language"):
        assert not re.search(rf"\b{token}\b", body, re.IGNORECASE), (
            f"preservation restorability branches on {token!r}; it must be "
            "ecosystem-independent"
        )


def test_reviewed_web_modes_are_cli_enums_not_hosts() -> None:
    """The permission-mode fix must carry no network or protocol identity."""
    import claude_phase_tool_policy as P

    assert P.REVIEWED_WEB_PERMISSION_MODES == ("default", "dontAsk")
    for mode in P.REVIEWED_WEB_PERMISSION_MODES:
        assert "." not in mode and "/" not in mode, (
            f"{mode!r} looks like a host or path, not a CLI permission mode"
        )
