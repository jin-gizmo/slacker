"""Test the main lambda handler."""

from pathlib import Path

import pytest

from conftest import RulesTestScenario
from lib.slacker import *


@pytest.mark.parametrize(
    'scenario_path',
    # List all the scenario files. Pity we can't use the td fixture here.
    (Path(__file__).parent.parent / 'data/rule-scenarios-ok').glob('*.yaml'),
    # [
    #     Path(__file__).parent.parent / 'data/rule-scenarios/object-not-match-drop-rule.yaml',
    # ],
)
def test_process_message_rules_ok(scenario_path: Path):
    scenario = RulesTestScenario.from_file(scenario_path)
    test_msg = SlackMsg(
        source_id=str(scenario_path),
        source_name=scenario_path.stem,
        subject=scenario_path.stem,
        message=scenario.input
    )
    process_msg_rules(test_msg, scenario.rules)
    assert test_msg.message == scenario.output, scenario_path.stem


@pytest.mark.parametrize(
    'scenario_path',
    # List all the scenario files. Pity we can't use the td fixture here.
    (Path(__file__).parent.parent / 'data/rule-scenarios-fail').glob('*.yaml'),
)
def test_process_message_rules_fail(scenario_path: Path):
    scenario = RulesTestScenario.from_file(scenario_path)
    test_msg = SlackMsg(
        source_id=str(scenario_path),
        source_name=scenario_path.stem,
        subject=scenario_path.stem,
        message=scenario.input
    )
    try:
        with pytest.raises(Exception, match=scenario.error):
            process_msg_rules(test_msg, scenario.rules)
    except AssertionError as e:
        pytest.fail(f'Scenario {scenario_path.stem}: {e}')
