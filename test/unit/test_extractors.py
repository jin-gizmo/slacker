"""Test the message extractors."""

import json

import pytest

from extractors import extract_event_messages
from lib.slacker import SlackerError


# ------------------------------------------------------------------------------
def test_extract_sns_messages_ok(td):
    event = json.loads((td / 'sns-message-01.json').read_text())
    records = list(extract_event_messages(event))
    assert len(records) == 1
    assert records[0].source_id == event['Records'][0]['Sns']['TopicArn']


# ------------------------------------------------------------------------------
def test_extract_sns_messages_unknown_source_fail(td):
    event = json.loads((td / 'unknown-message-01.json').read_text())
    with pytest.raises(Exception, match='Unexpected event source'):
        next(extract_event_messages(event))


# ------------------------------------------------------------------------------
def test_extract_cloudwatch_messages(td):
    event = json.loads((td / 'cwatch-log-message.json').read_text())
    decoded_event = json.loads((td / 'cwatch-log-decoded.json').read_text())
    records = list(extract_event_messages(event))

    assert len(records) == len(decoded_event['logEvents'])
    for record, expected in zip(records, decoded_event['logEvents']):
        assert record.source_id == f'logs:{decoded_event["logGroup"]}'
        assert record.message == expected['message']


# ------------------------------------------------------------------------------
def test_extract_event_messages_unknown_format_fail():
    event = {'format': 'unknown'}
    with pytest.raises(SlackerError, match='Unknown event type'):
        next(extract_event_messages(event))
