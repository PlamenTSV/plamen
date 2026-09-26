"""Run19 regression for canonical semantic-invariant payload hashing."""

from __future__ import annotations

import base64
import hashlib
import json
import zlib
from pathlib import Path

import plamen_driver as D
import semantic_invariant_authority as A
from plamen_types import Phase


RUN19_DECLARED_LF_DIGEST = (
    "69823a703f5a1530e6f3c8968d691f59f884ae8aa3bce8b78b17c85b25e9d98e"
)
RUN19_EXPECTED_CANONICAL_DIGEST = (
    "e1103ef0b5dfd11a53827c440c1e8b2fa5314ddb1cf5d0765b334203be066a4c"
)
RUN19_REJECTED_PAYLOAD_ZLIB_B64 = (
    "eNrNmk1v3DYQhv9KsefEJWf4MUxP/CyKtg6QOOihKBaURMVCnZUrrR0EQf57uQlaH3tizYMEAaKoeShy5n25+/mQH86367acPx2n5X3Zz4dXhyzzZKRhTAuhQUhj9DBxppnSCjMTnMY8MFUUzgwV5xwVy8wUZXjmOOHhxeE+f7pb8/TUpzIEmDXDWWYukRU140hG0VSfmqWZiUQulDMOY6FB08D1SHIAWcxkqFz63NbpYSzbcb0vWz6v21Pv9QlW+MjlYGhQExIxyhKHCcY8Ml7EyKdJ0kSDKGYegNRc9AQzU5DJFF5739aP++HV758P07Lfr/tyXtZT7TnEFN+8iaG2KI/LVE5jOd6t41KbHtYPp+XleJuX08txPZ23PJ7375+ufszn8jF/8tu67/7S6mpf7179AuLwR31d2R/uLqG79eE0lemH76Zyf779bit/PSxbma7qC/fyIZ/Oy3jcz/n8UKM7vI2/2uubn/zb47vrn69f/3Z9aVVvluMyXW7f2Jv4kntUKTpeR8GIKG1t87F+4HLcv57+6cu9fncdKtiXF+2ZkTVmJsacNRwcA2GFhQ6YwTRmRgzWgWcOtIPARQ/M1JpZkfdcaZYkQ2NcD8y6MXPQWtYpDZp77Y3kPTDLxsyMC+4VOKIYWOXvgRkbM1uuJXfG26S4ikb3wAyNmZMmLVzEaDFpE1QPzLwxs0QrBBqRjCfFJeuBWbWuz1wkJoRJkScdHPbA3FqTKGeIQDOjgncq9jC3sfV6FlZxl6JG4bRKpgdNgq3zttEBa2XmzEXpVRc6DFvXZ869td7GoEwwTvawnrG1DsMESVtICurURkM9MLeuVQqiZz56K1QV3awL5tb+2SoB2kqmOArULj0D89tymr7R8tYuMqIJSUsE73z1VvF5aVv7R0IhLpJTQvJJKP68tK2ztBGWCydN0NE6iOZ5aZv7ZJKMJ5mq4gLmPT4rbXN1ScYYK61j2lWP/NxZqrV/4LI64uBYjPXjavYcWepmy6d9Ltt1Pi+P5X/aB+EUa5rynosQuULeCXdz3QGWqosQgCZKSzb1wt16VVdlKV0QFIIl5ZPqZZ63ViHCueRr8jYeQkLmeuFuv5+tggIuAR0DD9gLd/N8bikwbRORcoIi64VbNNcoLOhUHQYZwfFr+F1wt94j8ZJcRB2jAqF50r1wt94PQx9F4MASSFf9JPTC3VqLa7JaMskJvSFy3dSx5rqFY9CUFMoUIDnRi25pvb4TXn60EkpqJxwa3wt3a31u9UW5VGzgDpMzvXC3Xt8SUnQJyFOqFRx60WvYWqcCGKh5rVruVA/Ziw9tvydqpAgotU+CBeDdcLeu3xAUUwwRjFXSCdsLd2t9rgO6yBC8Viah/s/1fYnm4XQcltO0nN4//THPMCyDkGzmWQMoQGnmOpiSj4xmxoBBnoQGSdrkaSKmjdCzIC5gzkPJ4yW28bYyHB/Ltn8b0vu7/KGcrv4lW06PeVvq9THf398tY74M/fEyiOXq8aviWrc/75b9/BQWYzMMeZhVESKbUfNspqxmXXINk880FKKMbKYyzwryOA6FF4YTU7yMg6DDl78BO5jChg=="
)


def _run19_payload() -> dict[str, object]:
    return json.loads(
        zlib.decompress(base64.b64decode(RUN19_REJECTED_PAYLOAD_ZLIB_B64))
    )


def test_run19_lf_digest_is_rejected_then_canonical_digest_replays() -> None:
    payload = _run19_payload()
    assert len(payload["rows"]) == 41
    assert payload["payload_digest"] == RUN19_DECLARED_LF_DIGEST

    unsigned = {
        key: value for key, value in payload.items() if key != "payload_digest"
    }
    canonical = json.dumps(
        unsigned,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    assert hashlib.sha256(canonical + b"\n").hexdigest() == RUN19_DECLARED_LF_DIGEST
    assert A.payload_digest(payload) == RUN19_EXPECTED_CANONICAL_DIGEST

    worklist = {
        "run_binding": {"binding_digest": payload["run_binding_digest"]},
        "authority_digest": payload["authority_digest"],
        "worklist_digest": payload["worklist_digest"],
        "states": [
            {"state_id": row["state_id"]} for row in payload["rows"]
        ],
    }
    _rows, _invalid, issues, fatal = A._validate_application_payload(
        payload, worklist
    )
    # Driver-sealed contract: the LF-variant digest the model wrote is replaced
    # by the driver's canonical digest; it is no longer a rejection or a retry.
    assert not fatal
    assert issues == []
    assert payload["payload_digest"] == A.payload_digest(payload)

    corrected = dict(payload)
    corrected["payload_digest"] = RUN19_EXPECTED_CANONICAL_DIGEST
    rows, invalid, issues, fatal = A._validate_application_payload(
        corrected, worklist
    )
    assert not fatal
    assert issues == []
    assert invalid == set()
    assert len(rows) == 41


def test_run19_digest_rejection_gets_one_strict_retry_hint(tmp_path: Path) -> None:
    failure = (
        "application trace payload digest mismatch: declared "
        f"{RUN19_DECLARED_LF_DIGEST}, expected "
        f"{RUN19_EXPECTED_CANONICAL_DIGEST}"
    )
    assert D._semantic_invariant_digest_retry_required([failure])
    assert not D._semantic_invariant_digest_retry_required(
        ["application trace schema fields mismatch"]
    )

    phase = Phase(
        "invariants",
        ["semantic invariant"],
        ["semantic_invariants.md"],
        60,
    )
    D._ensure_retry_hint(tmp_path, phase, [failure], str(tmp_path))
    hint = D._read_retry_hint(tmp_path, "invariants")
    assert "jq -j -S -c" in hint
    assert "`jq -S -c | shasum` is forbidden" in hint
    assert RUN19_DECLARED_LF_DIGEST in hint
    assert RUN19_EXPECTED_CANONICAL_DIGEST in hint

    D._ensure_retry_hint(tmp_path, phase, [failure], str(tmp_path))
    replayed = D._read_retry_hint(tmp_path, "invariants")
    assert replayed.count(
        "## Canonical semantic-invariant digest correction"
    ) == 1
