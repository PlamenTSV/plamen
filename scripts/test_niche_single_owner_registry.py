"""Exactly-once registry ownership for specialized niche publication."""
from __future__ import annotations

from fnmatch import fnmatch

import finding_producer_registry as R


NICHE_ARTIFACTS = {
    "niche_semantic_gap_findings.md": "niche",
    "niche_interface_parity_findings.md": "recon_prepass_interface_parity",
    "niche_permissionless_setters_findings.md": (
        "recon_prepass_permissionless_setters"
    ),
}

NON_PUBLICATION_CONSUMERS = {
    "canonical_identity",
    "late_harvest",
    "containment",
    "resume_hashing",
    "human_review",
}


def _consumer_matches(artifact: str, consumer: str) -> bool:
    return any(
        fnmatch(artifact, pattern)
        for pattern in R.producer_patterns(consumer)
    )


def test_generic_pre_dedup_projection_excludes_specialized_niche_artifacts() -> None:
    for artifact in NICHE_ARTIFACTS:
        assert not _consumer_matches(artifact, "pre_dedup_promotion")
        assert R.producer_for_artifact(
            artifact, consumer="pre_dedup_promotion"
        ) is None


def test_niche_artifacts_remain_registered_for_identity_recovery_and_review() -> None:
    for artifact, expected_key in NICHE_ARTIFACTS.items():
        for consumer in NON_PUBLICATION_CONSUMERS:
            assert _consumer_matches(artifact, consumer)
            producer = R.producer_for_artifact(artifact, consumer=consumer)
            assert producer is not None
            assert producer.key == expected_key


def test_specialized_niche_lookup_and_registry_projection_remain_complete() -> None:
    for artifact, expected_key in NICHE_ARTIFACTS.items():
        producer = R.producer_for_artifact(artifact)
        assert producer is not None
        assert producer.key == expected_key
        assert producer.required_consumers == frozenset(
            NON_PUBLICATION_CONSUMERS
        )

    assert R.producer_for_artifact(
        "niche_interface_parity_findings.md"
    ).owner_phase == "recon"
    assert R.producer_for_artifact(
        "niche_permissionless_setters_findings.md"
    ).owner_phase == "recon"
    assert R.producer_for_artifact(
        "niche_semantic_gap_findings.md"
    ).owner_phase == "depth"

    assert R.validate_registry_projection_completeness() == []
