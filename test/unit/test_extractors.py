"""Test the message extractors."""

import json
from time import time

import pytest

# The omission of slacker prefix for this import is deliberate as we must match
# the import path in the module under test.
from lib.slacker import SlackerError
from slacker.extractors import extract_custom_object_messages, extract_event_messages


# ------------------------------------------------------------------------------
def test_extract_sns_messages_ok(td):
    event = json.loads((td / 'lambda-events' / 'sns-message-01.json').read_text())
    records = list(extract_event_messages(event))
    assert len(records) == 1
    assert records[0].source_id == event['Records'][0]['Sns']['TopicArn']


# ------------------------------------------------------------------------------
def test_extract_sns_messages_unknown_source_fail(td):
    event = json.loads((td / 'lambda-events' / 'unknown-message-01.json').read_text())
    with pytest.raises(Exception, match='Unexpected event source'):
        next(extract_event_messages(event))


# ------------------------------------------------------------------------------
def test_extract_cloudwatch_messages(td):
    event = json.loads((td / 'lambda-events' / 'cwatch-log-message.json').read_text())
    decoded_event = json.loads((td / 'lambda-events' / 'cwatch-log-decoded.json').read_text())
    records = list(extract_event_messages(event))

    assert len(records) == len(decoded_event['logEvents'])
    for record, expected in zip(records, decoded_event['logEvents']):
        assert record.source_id == f'logs:{decoded_event["logGroup"]}'
        assert record.text == expected['message']


# ------------------------------------------------------------------------------
def test_extract_event_messages_unknown_format_fail():
    event = {'format': 'unknown'}
    with pytest.raises(SlackerError, match='Unknown event type'):
        next(extract_event_messages(event))


# ------------------------------------------------------------------------------
def test_extract_eventbridge_messages(td):
    event = json.loads((td / 'lambda-events' / 'event-ec2-launch-ok-raw.json').read_text())
    records = list(extract_event_messages(event))
    assert len(records) == 1
    assert records[0].source_id == 'events:' + event['source']


# ------------------------------------------------------------------------------
def test_extract_eventbridge_messages_bad_timestamp(td):
    event = json.loads((td / 'lambda-events' / 'event-ec2-launch-ok-raw.json').read_text())
    event['time'] = 'bad timestamp'
    records = list(extract_event_messages(event))
    assert len(records) == 1
    assert time() - records[0].timestamp < 2
    assert records[0].source_id == 'events:' + event['source']


# ------------------------------------------------------------------------------
@pytest.mark.parametrize(
    'message, source_id, source_name',
    [
        ({'SlackerSourceId': 'id', 'x': 'Z'}, 'id', 'id'),
        ({'SlackerSourceId': 'id', 'SlackerSourceName': 'name', 'x': 'X'}, 'id', 'name'),
    ],
)
def test_extract_custom_object_messages_ok(message, source_id, source_name):
    records = list(extract_event_messages(message))
    assert len(records) == 1
    assert records[0].source_id == source_id
    assert records[0].source_name == source_name


def test_extract_custom_object_messages_fail():
    with pytest.raises(SlackerError, match='Unknown event type'):
        next(extract_custom_object_messages({'z': 'Z'}))
