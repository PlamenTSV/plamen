"""Run11 regressions for the attention source-path denominator."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import plamen_mechanical as mechanical
import plamen_validators as validators
import attention_repair_shards as shards


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _write_recon_path_authority(scratchpad: Path, paths: list[str]) -> None:
    source_paths = sorted(set(paths))
    authority = {
        "schema": "plamen.report_source_path_authority.v1",
        "snapshot_digest": "1" * 64,
        "source_scope_digest": "2" * 64,
        "pipeline": "sc",
        "language": "evm",
        "source_paths": source_paths,
        "source_path_count": len(source_paths),
        "source_path_set_digest": hashlib.sha256(
            _canonical(source_paths)
        ).hexdigest(),
        "authority_digest": "",
    }
    authority["authority_digest"] = hashlib.sha256(
        _canonical({
            key: value
            for key, value in authority.items()
            if key != "authority_digest"
        })
    ).hexdigest()
    receipt = {
        "schema": "plamen.recon_prepass_publication.v2",
        "authority_capture": {
            "snapshot_digest": authority["snapshot_digest"],
            "source_scope_digest": authority["source_scope_digest"],
            "source_capture_digest": authority["authority_digest"],
            "production_source_capture_digest": authority["authority_digest"],
            "source_path_authority": authority,
        },
    }
    receipt["artifact_sha256"] = hashlib.sha256(
        _canonical(receipt)
    ).hexdigest().upper()
    (scratchpad / "recon_prepass_publication_receipt.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def test_dodo_like_narrative_alias_cannot_become_attention_queue_target(
    tmp_path: Path,
) -> None:
    canonical_paths = [
        "contracts/GatewayCrossChain.sol",
        "contracts/libraries/AccountEncoder.sol",
        "contracts/libraries/BytesHelperLib.sol",
    ]
    _write_recon_path_authority(tmp_path, canonical_paths)
    (tmp_path / "contract_inventory.md").write_text(
        "# Contracts\n\n"
        "| Contract | Path | Lines |\n"
        "|---|---|---:|\n"
        "| AccountEncoder.sol | `contracts/libraries/AccountEncoder.sol` | 54 |\n"
        "| BytesHelperLib.sol | `contracts/libraries/BytesHelperLib.sol` | 41 |\n"
        "\nNarrative shorthand: `libraries/AccountEncoder.sol` and "
        "`libraries/BytesHelperLib.sol`.\n",
        encoding="utf-8",
    )
    (tmp_path / "analysis_depth.md").write_text(
        "Reviewed contracts/GatewayCrossChain.sol:L10.\n",
        encoding="utf-8",
    )

    indexed = validators._collect_scip_indexed_paths(tmp_path)
    coverage = validators._compute_scip_coverage_sets(tmp_path)
    items = mechanical._build_attention_repair_items(tmp_path, "thorough")
    file_targets = {
        row["target"]
        for row in items
        if row["kind"] == "uncited-security-file"
    }

    assert indexed == set(canonical_paths)
    assert coverage["indexed_authority_source"] == (
        "recon-source-path-authority"
    )
    assert coverage["indexed_authority_debt"] == []
    assert file_targets == {
        "contracts/libraries/AccountEncoder.sol",
        "contracts/libraries/BytesHelperLib.sol",
    }
    assert not any(target.startswith("libraries/") for target in file_targets)


def test_tampered_recon_authority_retains_debt_even_with_scip_fallback(
    tmp_path: Path,
) -> None:
    _write_recon_path_authority(tmp_path, ["contracts/A.sol"])
    receipt_path = tmp_path / "recon_prepass_publication_receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["authority_capture"]["source_path_authority"]["source_paths"] = [
        "libraries/A.sol"
    ]
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    scip = tmp_path / "scip"
    scip.mkdir()
    (scip / "repo_map.md").write_text(
        "## contracts/A.sol\n",
        encoding="utf-8",
    )

    coverage = validators._compute_scip_coverage_sets(tmp_path)
    items = mechanical._build_attention_repair_items(tmp_path, "thorough")

    assert coverage["prod_indexed"] == {"contracts/A.sol"}
    assert coverage["indexed_authority_source"] == "scip-degraded-fallback"
    assert coverage["indexed_authority_debt"]
    assert any(
        row["kind"] == "source-path-authority-debt" for row in items
    )


def test_source_path_authority_debt_cannot_receive_safe_disposition(
    tmp_path: Path,
) -> None:
    mechanical._write_attention_repair_queue(
        tmp_path,
        [{
            "kind": "source-path-authority-debt",
            "target": "recon-production-source-path-authority-1",
            "reason": "authority unavailable",
            "source": "recon_prepass_publication_receipt.json",
            "evidence": "authority unavailable",
        }],
    )
    plan = shards.build_plan(tmp_path / "attention_repair_queue.md")
    shard = plan["shards"][0]

    def receipt(verdict: str) -> str:
        return "\n".join([
            "PARENT_QUEUE_BINDING_SHA256: "
            + plan["parent_queue_binding_sha256"],
            "SHARD_BINDING_SHA256: " + shard["row_binding_sha256"],
            "",
            "| Queue # | Kind | Target | Verdict | Evidence | Notes |",
            "|---|---|---|---|---|---|",
            "| 1 | source-path-authority-debt | "
            "`recon-production-source-path-authority-1` | "
            f"{verdict} | authority unavailable | retained |",
        ])

    _rows, safe_issues = shards.parse_shard_output(
        receipt("SAFE"),
        plan=plan,
        shard=shard,
    )
    _rows, retained_issues = shards.parse_shard_output(
        receipt("NEEDS_HUMAN"),
        plan=plan,
        shard=shard,
    )
    assert safe_issues == [
        "worker receipt row 1 cannot close source-path authority debt"
    ]
    assert retained_issues == []


def test_bound_application_receipt_keeps_authority_debt_incomplete(
    tmp_path: Path,
) -> None:
    target = "recon-production-source-path-authority-1"
    mechanical._write_attention_repair_queue(
        tmp_path,
        [{
            "kind": "source-path-authority-debt",
            "target": target,
            "reason": "authority unavailable",
            "source": "recon_prepass_publication_receipt.json",
            "evidence": "authority unavailable",
        }],
    )
    queue = (tmp_path / "attention_repair_queue.md").read_text(
        encoding="utf-8"
    )
    binding = next(
        line for line in queue.splitlines()
        if line.startswith("QUEUE_BINDING_SHA256:")
    )
    (tmp_path / "attention_repair_summary.md").write_text(
        "\n".join([
            "# Attention Repair",
            "",
            binding,
            "",
            "| Queue # | Kind | Target | Verdict | Evidence | Notes |",
            "|---|---|---|---|---|---|",
            "| 1 | source-path-authority-debt | "
            f"`{target}` | NEEDS_HUMAN | authority unavailable | retained |",
            "",
        ]),
        encoding="utf-8",
    )

    expected_receipt: list[bytes] = []
    hard, soft = validators._validate_attention_repair(
        tmp_path,
        "thorough",
        expected_receipt=expected_receipt,
        require_application_receipt=False,
    )
    assert not (tmp_path / "attention_repair_application_receipt.json").exists()
    application = json.loads(expected_receipt[0])
    assert hard == []
    assert any("NEEDS_HUMAN path debt" in issue for issue in soft)
    assert application["status"] == "INCOMPLETE"
    assert application["unresolved_paths"] == [target]
