from saferansomsim.schema_validation import assert_repository_schemas_valid
from saferansomsim.scenarios import SCENARIOS


def test_repository_schemas_and_bundled_datasets_validate() -> None:
    result = assert_repository_schemas_valid()
    assert result["schemas"] >= 5
    assert result["dataset_events"] > 0
    assert result["scenarios"] == len(SCENARIOS)
