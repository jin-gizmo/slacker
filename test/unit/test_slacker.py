"""Test the main lambda handler."""

from pathlib import Path

import pytest

from conftest import RulesTestScenario
from slacker.lib.slacker import *


@pytest.mark.parametrize(
    'scenario_path',
    # List all the scenario files. Pity we can't use the td fixture here.
    (Path(__file__).parent.parent / 'data' / 'rule-scenarios-ok').glob('*.yaml'),
    # [Path(__file__).parent.parent / 'data/rule-scenarios-ok/text-matching-unnamed-re-groups.yaml'],
)
def test_process_message_rules_ok(scenario_path: Path):
    scenario = RulesTestScenario.from_file(scenario_path)
    test_msg = SlackerMsg(
        source_id=str(scenario_path),
        source_name=scenario_path.stem,
        subject=scenario_path.stem,
        text=scenario.input,
    )
    process_msg_rules(test_msg, scenario.rules)
    assert test_msg.text == scenario.output, scenario_path.stem


@pytest.mark.parametrize(
    'scenario_path',
    # List all the scenario files. Pity we can't use the td fixture here.
    (Path(__file__).parent.parent / 'data' / 'rule-scenarios-fail').glob('*.yaml'),
)
def test_process_message_rules_fail(scenario_path: Path):
    scenario = RulesTestScenario.from_file(scenario_path)
    test_msg = SlackerMsg(
        source_id=str(scenario_path),
        source_name=scenario_path.stem,
        subject=scenario_path.stem,
        text=scenario.input,
    )
    try:
        with pytest.raises(Exception, match=scenario.error):
            process_msg_rules(test_msg, scenario.rules)
    except AssertionError as e:  # pragma: no cover
        # This path only take if tests fail so exclude from coverage
        pytest.fail(f'Scenario {scenario_path.stem}: {e}')  # pragma: no cover
