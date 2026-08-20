from __future__ import annotations

from saferansomsim.detection_validation import assert_detection_pack_valid, validate_detection_pack


def test_detection_pack_metadata_and_syntax_validate() -> None:
    result = validate_detection_pack()
    assert result["valid"], result["errors"]
    assert result["sigma_rules"] >= 2
    assert result["guidance_files"] >= 3


def test_detection_pack_assertion_helper() -> None:
    result = assert_detection_pack_valid()
    assert result["valid"] is True
