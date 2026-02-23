"""Edge case tests for lib/slacker.py."""

import pytest

from conftest import RulesTestScenario
from slacker.cli.slacker import *
import json


# ------------------------------------------------------------------------------
class TestSlackMsg:
    """SlackMsg tests."""

    # --------------------------------------------------------------------------
    def test_from_object(self):
        obj = {'a': 'A'}
        msg = SlackerMsg.from_object(
            obj, source_id='source_id', source_name='source_name', subject='subject'
        )
        assert msg.source_id == 'source_id'
        assert msg.source_name == 'source_name'
        assert msg.data == obj

    # --------------------------------------------------------------------------
    def test_send_ok(self, mocker):
        msg = SlackerMsg(
            source_id='source_id',
            source_name='source_name',
            subject='subject',
            text='Hello world',
        )
        webhook_info = {'sourceId': 'source_id', 'url': 'https://example.com'}
        mock_post = mocker.patch('requests.post')
        mock_post.return_value.status_code = 200
        msg.send(webhook_info)
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args.kwargs
        data = json.loads(call_kwargs['data'])
        att0 = data['attachments'][0]
        assert att0['text'] == msg.text
        assert att0['title'] == msg.subject

    # --------------------------------------------------------------------------
    def test_send_fail_404(self, mocker):
        msg = SlackerMsg(
            source_id='source_id',
            source_name='source_name',
            subject='subject',
            text='Hello world',
        )
        webhook_info = {'sourceId': 'source_id', 'url': 'https://example.com'}
        mock_post = mocker.patch('requests.post')
        mock_post.return_value.status_code = 404
        mock_post.return_value.text = 'Uh oh'
        with pytest.raises(SlackerError, match='Slack response 404 - Uh oh'):
            msg.send(webhook_info)

    # --------------------------------------------------------------------------
    def test_send_fail_no_url(self, mocker):
        msg = SlackerMsg(
            source_id='source_id',
            source_name='source_name',
            subject='subject',
            text='Hello world',
        )
        webhook_info = {'sourceId': 'source_id'}
        mock_post = mocker.patch('requests.post')
        mock_post.return_value.status_code = 500
        mock_post.return_value.text = 'Should not get here'
        with pytest.raises(SlackerError, match='Cannot determine URL for webhook'):
            msg.send(webhook_info)


# ------------------------------------------------------------------------------
@pytest.mark.parametrize(
    'scenario_path',
    # List all the scenario files. Pity we can't use the td fixture here.
    (Path(__file__).parent.parent.parent / 'data' / 'rule-scenarios-ok').glob('*.yaml'),
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
    (Path(__file__).parent.parent.parent / 'data' / 'rule-scenarios-fail').glob('*.yaml'),
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


# ------------------------------------------------------------------------------
class TestGetChannel:
    """Tests for get_channel()."""

    def test_get_channel_fail(self, mock_slacker_dynamodb_tables):
        item = {'channel': 'whatever'}
        dynamodb_rsc, _, channels_table = mock_slacker_dynamodb_tables
        assert get_channel.__wrapped__(item['channel'], channels_table) is None

    def test_get_channel_ok(self, mock_slacker_dynamodb_tables):
        item = {'channel': 'whatever'}
        dynamodb_rsc, _, channels_table = mock_slacker_dynamodb_tables
        channels_table.put_item(Item=item)
        assert get_channel.__wrapped__(item['channel'], channels_table) == item


# ------------------------------------------------------------------------------
class TestGetWebhook:
    """Tests for get_webhook()."""

    def test_get_webhook_fail(self, mock_slacker_dynamodb_tables):
        item = {'sourceId': 'whatever'}
        dynamodb_rsc, webhooks_table, _ = mock_slacker_dynamodb_tables
        assert get_webhook.__wrapped__(item['sourceId'], webhooks_table) is None

    def test_get_webhook_ok(self, mock_slacker_dynamodb_tables):
        item = {'sourceId': 'whatever'}
        dynamodb_rsc, webhooks_table, _ = mock_slacker_dynamodb_tables
        webhooks_table.put_item(Item=item)
        assert get_webhook.__wrapped__(item['sourceId'], webhooks_table) == item
