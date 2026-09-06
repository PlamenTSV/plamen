"""Regression contract for the generic arm-before-trust discovery lens.

The assertions lock HOW-to-analyze obligations, not any protocol answer.  The
chain matcher is covered separately because it must prove both halves before
forming a composition.
"""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SIGNATURE_SKILL = (
    ROOT / "agents" / "skills" / "niche" / "signature-verification-audit" / "SKILL.md"
)
EVM_RULES = ROOT / "prompts" / "evm" / "generic-security-rules.md"


def test_signature_skill_requires_paired_anchor_and_degenerate_input_analysis():
    text = SIGNATURE_SKILL.read_text(encoding="utf-8")
    required = (
        "identify the stored key, signer set, threshold, root, or",
        "Verification must remain",
        "fail-closed until the anchor is armed",
        "Test the paired boundary, not either half in isolation",
        "rejection of zero-length inputs before",
        "rejection of a zero/empty derived identity independently",
        "authorizes a privileged effect while the anchor is unarmed",
    )
    for obligation in required:
        assert obligation in text


def test_oracle_rule_covers_authentication_and_out_of_scope_evidence():
    text = EVM_RULES.read_text(encoding="utf-8")
    for obligation in (
        "| Authentication armed |",
        "empty proof and zero-derived identity are rejected independently",
        "[EXTERNAL-ASSUMPTION]",
        "route missing evidence to dependency research",
        "do not assume the verifier is armed or demote on that assumption",
    ):
        assert obligation in text


def test_new_methodology_is_generic_and_contains_no_incident_identity():
    combined = SIGNATURE_SKILL.read_text(encoding="utf-8") + EVM_RULES.read_text(
        encoding="utf-8"
    )
    # The methodology may name standards and ecosystem primitives, but must not
    # encode the motivating incident, project, or a known report identifier.
    forbidden = ("spectra", "h-01", "h-22", "solodit")
    assert not any(token in combined.casefold() for token in forbidden)
