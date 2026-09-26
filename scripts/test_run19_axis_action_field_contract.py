from __future__ import annotations

from pathlib import Path

import axis_disposition as AXIS


def test_axis_prompt_names_the_canonical_metadata_spelling() -> None:
    prompt = (
        Path(__file__).parents[1]
        / "prompts/shared/v2/phase4b8-axis-coverage.md"
    ).read_text(encoding="utf-8")

    for label in ("Severity", "Location", "Work Item ID", "Description"):
        assert f"`**{label}**:`" in prompt


def _action(action_id: str, work_item_id: str, *, bold: bool) -> str:
    def field(name: str, value: str) -> str:
        label = f"**{name}**" if bold else name
        return f"{label}: {value}\n"

    return (
        f"### Finding [{action_id}]: retained candidate\n\n"
        + field("Severity", "Pending verification")
        + field("Location", "contracts/Gateway.sol:L42")
        + field("Work Item ID", work_item_id)
        + field("Description", "The exact assigned axis remains unresolved.")
    )


def test_run19_plain_exact_action_fields_are_not_silently_discarded() -> None:
    action_id = "AXIS-V2-417435612958799249"
    work_item_id = "AXW-005C7EA6D99407D70EDEC145"

    actions, duplicate, issues = AXIS._v2_actions(
        _action(action_id, work_item_id, bold=False).encode()
    )

    assert not duplicate
    assert not issues
    assert actions[action_id]["work_item_id"] == work_item_id
    assert actions[action_id]["fields"] == {
        "Severity": "Pending verification",
        "Location": "contracts/Gateway.sol:L42",
        "Description": "The exact assigned axis remains unresolved.",
    }


def test_run19_mass_action_denominator_survives_plain_field_projection() -> None:
    expected = {
        f"AXIS-V2-{index + 1}": f"AXW-{index:024X}"
        for index in range(396)
    }
    markdown = "\n".join(
        _action(action_id, work_item_id, bold=False)
        for action_id, work_item_id in expected.items()
    )

    actions, duplicate, issues = AXIS._v2_actions(markdown.encode())

    assert not duplicate
    assert not issues
    assert len(actions) == 396
    assert {
        action_id: row["work_item_id"]
        for action_id, row in actions.items()
    } == expected


def test_axis_action_parser_keeps_bold_canonical_format() -> None:
    action_id = "AXIS-V2-1037325676161176045"
    work_item_id = "AXW-006AE61FE8331EA2AC5895FD"

    actions, duplicate, issues = AXIS._v2_actions(
        _action(action_id, work_item_id, bold=True).encode()
    )

    assert not duplicate
    assert not issues
    assert actions[action_id]["work_item_id"] == work_item_id


def test_plain_field_compatibility_does_not_weaken_action_uniqueness() -> None:
    action_id = "AXIS-V2-915434134693993878"
    first = _action(action_id, "AXW-0077CDFFA9A0D01F1A073C50", bold=False)
    second = _action(action_id, "AXW-00B1F35E12E74590E8B77E23", bold=False)

    actions, duplicate, issues = AXIS._v2_actions(
        (first + "\n" + second).encode()
    )

    assert actions == {}
    assert duplicate == {action_id}
    assert issues == [f"duplicate action heading {action_id}"]
