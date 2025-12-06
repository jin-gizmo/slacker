"""Tests for the slacker CLI."""

import json
import sys
from io import StringIO
from pathlib import Path

import pytest
import yaml
from conftest import RulesTestScenario  # noqa

from slacker.cli import slacker
from slacker.version import __version__


# ------------------------------------------------------------------------------
def test_cprint(capsys):
    slacker.info('hello')
    assert 'hello' in capsys.readouterr().out


# ------------------------------------------------------------------------------
def test_get_webhook_schema_validator():
    validator = slacker.get_webhook_schema_validator()
    assert '$schema' in validator.schema


# ------------------------------------------------------------------------------
def test_slacker_cli_version(capsys, monkeypatch) -> None:
    """Test the "version" command."""

    monkeypatch.setattr(sys, 'argv', ['slacker', '--version'])

    # argparse will exit on it's own for --version option (grrr)
    with pytest.raises(SystemExit) as exc_info:
        slacker.main()

    assert exc_info.value.code == 0
    assert capsys.readouterr().out.strip() == __version__


# ------------------------------------------------------------------------------
def test_check_webhook_item_content_ok(td):
    webhook = yaml.safe_load((td / 'webhooks' / 'wildcard-ok.yaml').read_text())
    result = slacker.check_webhook_item_content(webhook)
    assert not result.errors and not result.warnings


def test_check_webhook_item_content_no_source_id(td):
    webhook = yaml.safe_load((td / 'webhooks' / 'no-source-id.yaml').read_text())
    result = slacker.check_webhook_item_content(webhook)
    assert result.errors and not result.warnings


def test_check_webhook_item_content_no_channel_or_url(td):
    webhook = yaml.safe_load((td / 'webhooks' / 'no-channel-or-url.yaml').read_text())
    result = slacker.check_webhook_item_content(webhook)
    assert result.errors and not result.warnings


def test_check_webhook_item_content_channel_and_url(td):
    webhook = yaml.safe_load((td / 'webhooks' / 'channel-and-url.yaml').read_text())
    result = slacker.check_webhook_item_content(webhook)
    # We get an error for having channel and url and a warning for having url at all
    assert result.errors and result.warnings


def test_check_webhook_item_content_url(td):
    webhook = yaml.safe_load((td / 'webhooks' / 'url.yaml').read_text())
    result = slacker.check_webhook_item_content(webhook)
    assert not result.errors and result.warnings


def test_check_webhook_item_content_extra_field(td):
    webhook = yaml.safe_load((td / 'webhooks' / 'extra-field.yaml').read_text())
    result = slacker.check_webhook_item_content(webhook)
    assert result.errors and not result.warnings


# ------------------------------------------------------------------------------
@pytest.mark.parametrize(
    'scenario_path',
    # List all the scenario files. Pity we can't use the td fixture here.
    (Path(__file__).parent.parent.parent / 'data' / 'rule-scenarios-ok').glob('*.yaml'),
)
def test_slacker_cli_test_ok(scenario_path: Path, tmp_path, monkeypatch):
    scenario = RulesTestScenario.from_file(scenario_path)
    webhook = {
        'sourceId': str(scenario_path),
        'channel': 'test',
        'rules': scenario.rules,
    }
    webhook_file = tmp_path / 'webhook.yaml'
    webhook_file.write_text(yaml.safe_dump(webhook))
    monkeypatch.setattr(sys, 'argv', ['slacker', 'test', str(webhook_file)])
    monkeypatch.setattr('sys.stdin', StringIO(json.dumps(scenario.input) + '\n'))

    assert slacker.main() == 0


# ------------------------------------------------------------------------------
@pytest.mark.parametrize(
    'scenario_path',
    # List all the scenario files. Pity we can't use the td fixture here.
    (Path(__file__).parent.parent.parent / 'data' / 'rule-scenarios-fail').glob('*.yaml'),
)
def test_slacker_cli_test_fail(scenario_path: Path, tmp_path, monkeypatch, capsys):
    scenario = RulesTestScenario.from_file(scenario_path)
    webhook = {
        'sourceId': str(scenario_path),
        'channel': 'test',
        'rules': scenario.rules,
    }
    webhook_file = tmp_path / 'webhook.yaml'
    webhook_file.write_text(yaml.safe_dump(webhook))
    monkeypatch.setattr(sys, 'argv', ['slacker', 'test', str(webhook_file)])
    monkeypatch.setattr('sys.stdin', StringIO(json.dumps(scenario.input) + '\n'))

    assert slacker.main() == 1
    assert f'{webhook_file}: Errors in webhooks entry' in capsys.readouterr().err.strip()
