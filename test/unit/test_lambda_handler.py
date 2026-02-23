"""Unit tests for lambda_handler.py."""

import json
import logging
from types import SimpleNamespace as Namespace

import pytest
from shortuuid import uuid

import lambda_handler
from lib.slacker import SlackerError, SlackerMsg


# ------------------------------------------------------------------------------
def lambda_context():
    """Mock the Lambda context argument."""
    return Namespace(function_name='slacker')


# ------------------------------------------------------------------------------
def test_lambda_handler_sns_ok(td, mock_slacker_dynamodb_tables, mocker, monkeypatch, caplog):
    event = json.loads((td / 'lambda-events' / 'sns-message-01.json').read_text())
    monkeypatch.setattr(lambda_handler, 'LOGLEVEL', 'debug')
    mock_process_msg = mocker.patch('lambda_handler.process_msg', autospec=True, return_value=None)

    with caplog.at_level(logging.DEBUG, logger=lambda_handler.LOGNAME):
        lambda_handler.lambda_handler(event, lambda_context())
    mock_process_msg.assert_called_once()
    args, kwargs = mock_process_msg.call_args
    msg = args[0]
    assert msg.source_id == event['Records'][0]['Sns']['TopicArn']
    assert 'Received event:' in caplog.text


# ------------------------------------------------------------------------------
def test_lambda_handler_sns_fail(td, mock_slacker_dynamodb_tables, mocker, caplog):
    """Force the process_msg to fail."""
    event = json.loads((td / 'lambda-events' / 'sns-message-01.json').read_text())
    mock_process_msg = mocker.patch(
        'lambda_handler.process_msg', autospec=True, side_effect=SlackerError('test error')
    )

    with caplog.at_level(logging.ERROR, logger=lambda_handler.LOGNAME):
        with pytest.raises(SlackerError, match='Error processing 1 message'):
            lambda_handler.lambda_handler(event, lambda_context())
    mock_process_msg.assert_called_once()
    assert 'Error processing message: test error' in caplog.text


# ------------------------------------------------------------------------------
def test_process_msg_url(td, mock_slacker_dynamodb_tables, mocker):

    _, webhooks_table, channels_table = mock_slacker_dynamodb_tables
    mock_send = mocker.patch.object(SlackerMsg, 'send', autospec=True, return_value=None)

    # This will drop through to a default msg.send()
    source_id = uuid()
    webhooks_table.put_item(Item={'sourceId': source_id, 'url': 'https://example.com'})

    msg = SlackerMsg(
        source_id=source_id,
        source_name='test',
        subject='Test subject',
        text='Test message.',
    )
    lambda_handler.process_msg(msg, webhooks_table, channels_table)
    mock_send.assert_called_once()
    args, kwargs = mock_send.call_args
    webhook_info = args[1]  # args[0] is "self" i.e. the SlackerMsg instance.
    assert webhook_info['sourceId'] == source_id
    assert webhook_info['url'] == 'https://example.com'


# ------------------------------------------------------------------------------
def test_process_msg_channel(td, mock_slacker_dynamodb_tables, mocker):

    _, webhooks_table, channels_table = mock_slacker_dynamodb_tables
    mock_send = mocker.patch.object(SlackerMsg, 'send', autospec=True, return_value=None)

    source_id = uuid()
    channel = uuid()
    webhooks_table.put_item(Item={'sourceId': source_id, 'channel': channel})
    channels_table.put_item(Item={'channel': channel, 'url': 'https://example.com'})

    msg = SlackerMsg(
        source_id=source_id,
        source_name='test',
        subject='Test subject',
        text='Test message.',
    )
    lambda_handler.process_msg(msg, webhooks_table, channels_table)
    mock_send.assert_called_once()
    args, kwargs = mock_send.call_args
    webhook_info = args[1]  # args[0] is "self" i.e. the SlackerMsg instance.
    assert webhook_info['sourceId'] == source_id
    assert webhook_info['url'] == 'https://example.com'


# ------------------------------------------------------------------------------
def test_process_msg_wildcard(mock_slacker_dynamodb_tables, mocker):

    _, webhooks_table, channels_table = mock_slacker_dynamodb_tables
    mock_send = mocker.patch.object(SlackerMsg, 'send', autospec=True, return_value=None)

    source_id = uuid()
    channel = uuid()
    webhooks_table.put_item(Item={'sourceId': '*', 'channel': channel})
    channels_table.put_item(Item={'channel': channel, 'url': 'https://example.com'})

    msg = SlackerMsg(
        source_id=source_id,
        source_name='test',
        subject='Test subject',
        text='Test message.',
    )

    lambda_handler.process_msg(msg, webhooks_table, channels_table)
    mock_send.assert_called_once()
    args, kwargs = mock_send.call_args
    webhook_info = args[1]  # args[0] is "self" i.e. the SlackerMsg instance.
    assert webhook_info['sourceId'] == '*'  # Found the wildcard?
    assert webhook_info['url'] == 'https://example.com'


# ------------------------------------------------------------------------------
def test_process_msg_no_webhook(mock_slacker_dynamodb_tables, mocker):

    _, webhooks_table, channels_table = mock_slacker_dynamodb_tables
    mock_send = mocker.patch.object(SlackerMsg, 'send', autospec=True, return_value=None)

    source_id = uuid()

    msg = SlackerMsg(
        source_id=source_id,
        source_name='test',
        subject='Test subject',
        text='Test message.',
    )

    with pytest.raises(SlackerError, match='Missing webhook'):
        lambda_handler.process_msg(msg, webhooks_table, channels_table)
    mock_send.assert_not_called()


# ------------------------------------------------------------------------------
def test_process_msg_disabled_webhook(mock_slacker_dynamodb_tables, mocker, caplog):

    _, webhooks_table, channels_table = mock_slacker_dynamodb_tables
    mock_send = mocker.patch.object(SlackerMsg, 'send', autospec=True, return_value=None)

    source_id = uuid()
    webhooks_table.put_item(
        Item={'sourceId': source_id, 'enabled': False, 'url': 'https://example.com'},
    )

    msg = SlackerMsg(
        source_id=source_id,
        source_name='test',
        subject='Test subject',
        text='Test message.',
    )
    with caplog.at_level(logging.INFO, logger=lambda_handler.LOGNAME):
        lambda_handler.process_msg(msg, webhooks_table, channels_table)
    mock_send.assert_not_called()
    assert 'webhook not enabled' in caplog.text


# ------------------------------------------------------------------------------
def test_process_msg_no_message_text(mock_slacker_dynamodb_tables, mocker):

    _, webhooks_table, channels_table = mock_slacker_dynamodb_tables
    mock_send = mocker.patch.object(SlackerMsg, 'send', autospec=True, return_value=None)

    source_id = uuid()
    webhooks_table.put_item(Item={'sourceId': source_id, 'url': 'https://example.com'})

    msg = SlackerMsg(source_id=source_id, source_name='test', subject='Test subject', text=None)
    lambda_handler.process_msg(msg, webhooks_table, channels_table)
    mock_send.assert_not_called()


# ------------------------------------------------------------------------------
def test_process_msg_missing_channel(mock_slacker_dynamodb_tables):
    _, webhooks_table, channels_table = mock_slacker_dynamodb_tables

    source_id = uuid()
    channel = uuid()
    webhooks_table.put_item(Item={'sourceId': source_id, 'channel': channel})

    msg = SlackerMsg(
        source_id=source_id,
        source_name='test',
        subject='Test subject',
        text='Test message.',
    )

    with pytest.raises(SlackerError, match=f'Missing channel entry for {channel}'):
        lambda_handler.process_msg(msg, webhooks_table, channels_table)


# ------------------------------------------------------------------------------
def test_process_msg_channel_with_no_url(mock_slacker_dynamodb_tables):
    _, webhooks_table, channels_table = mock_slacker_dynamodb_tables

    source_id = uuid()
    channel = uuid()
    webhooks_table.put_item(Item={'sourceId': source_id, 'channel': channel})
    channels_table.put_item(Item={'channel': channel})

    msg = SlackerMsg(
        source_id=source_id,
        source_name='test',
        subject='Test subject',
        text='Test message.',
    )

    with pytest.raises(SlackerError, match=f'Channel entry for {channel} has no url'):
        lambda_handler.process_msg(msg, webhooks_table, channels_table)
