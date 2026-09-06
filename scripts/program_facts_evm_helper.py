"""Checked-in EVM Program Facts helper process boundary.

This module is intentionally not a launcher.  The only supported execution
parent is ``worker_transaction.NativeCommandAdapter``.  Until the reviewed
Slither-to-raw-schema extractor is implemented and independently accepted,
analysis requests fail closed with a stable non-zero exit and Program Facts
must publish explicit provider-unavailable debt.

Keeping the disabled helper checked in still gives the registry a portable,
hashable command/package identity and prevents an unreviewed system Slither
installation from silently becoming production authority.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence


HELPER_NAME = "plamen-evm-slither-helper"
HELPER_VERSION = "1.0.0"
SLITHER_DISTRIBUTION = "slither-analyzer"
SLITHER_VERSION = "0.11.5"
ANALYSIS_RELEASE_STATE = "DISABLED_PENDING_SEMANTIC_REVIEW"


def version_line() -> str:
    return (
        f"{HELPER_NAME} {HELPER_VERSION} "
        f"({SLITHER_DISTRIBUTION} {SLITHER_VERSION}; "
        f"{ANALYSIS_RELEASE_STATE.lower()})"
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=HELPER_NAME,
        allow_abbrev=False,
    )
    parser.add_argument("--version", action="store_true")
    parser.add_argument("--stdin-json", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.version:
        sys.stdout.write(version_line() + "\n")
        return 0
    if not args.stdin_json:
        sys.stderr.write("one reviewed operation is required\n")
        return 64

    # Bound the request parser without interpreting audit content.  This
    # proves the checked-in command is deterministic while avoiding any
    # unreviewed in-process Slither or subprocess path.
    try:
        request = json.load(sys.stdin)
    except (UnicodeDecodeError, json.JSONDecodeError):
        sys.stderr.write("helper request is not valid JSON\n")
        return 65
    if not isinstance(request, dict):
        sys.stderr.write("helper request must be a JSON object\n")
        return 65
    sys.stderr.write(
        "EVM Program Facts semantic helper is disabled pending independent "
        "review; publish PROVIDER_UNAVAILABLE debt\n"
    )
    return 78


if __name__ == "__main__":
    raise SystemExit(main())
