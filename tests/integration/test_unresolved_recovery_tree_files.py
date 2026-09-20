"""Original private-file custody preserves every unresolved branch across bounded replay."""

from pathlib import Path

import pytest

from tests.integration.test_channel_retention_journal import (
    _assert_no_recovery_credit,
    _assert_original_resume_preserves_channels,
)
from tests.integration.test_truncation_tree_manifest_files import (
    no_provider_or_operator_secrets as no_provider_or_operator_secrets,
)
from tests.unit.test_unresolved_recovery_tree import assert_exact_unresolved_tree
from tests.unresolved_recovery_tree_support import (
    TreeScenario,
    original_unresolved_tree,
    tree_scenarios,
)


@pytest.mark.parametrize("case", tree_scenarios(), ids=lambda case: case.name)
def test_original_owner_preserves_all_mixed_role_channel_cost_and_file_custody(
    tmp_path: Path, case: TreeScenario
) -> None:
    path = tmp_path / "original-unresolved-tree"
    with original_unresolved_tree(path, case) as tree:
        assert_exact_unresolved_tree(tree)
        parent = tree.journal.truncation_recovery_families[0].recovery_plan.parent
        _assert_no_recovery_credit(tree.journal, parent.parent_task_id)
        _assert_original_resume_preserves_channels(tree.journal, path)
