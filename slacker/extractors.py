"""Extract messages from various AWS sources."""

from __future__ import annotations

import time
from collections.abc import Iterator
from logging import getLogger
from typing import Any

from config import LOGNAME
from lib.slacker import SlackMsg, SlackerError
from lib.utils import iso8601_to_ts, zip64_decode_data

log = getLogger(LOGNAME)

__author__ = 'Murray Andrews'


# ------------------------------------------------------------------------------
def extract_cloudwatch_messages(event: dict[str, Any]) -> Iterator[SlackMsg]:
    """
     Extract CloudWatch log messages into a canonical format.

    Sample event data after extraction:

    .. code-block:: json

        {
             "messageType": "DATA_MESSAGE",
             "owner": "123456789000",
             "logGroup": "logGroupName",
             "logStream": "logStreamName",
             "subscriptionFilters": ["cwatchTrigger"],
             "logEvents": [
                 {
                     "id": "32876629689493193824632746953207793042945191065307971584",
                     "timestamp": 1474231062274,
                     "message": "hello world"
                 }
             ]
         }

    """

    payload = zip64_decode_data(event['awslogs']['data'])

    log_group = payload['logGroup']
    log_stream = payload['logStream']
    for record in payload['logEvents']:
        yield SlackMsg(
            source_id=f'logs:{log_group}',
            source_name=f'Log:{log_group}',
            subject=f'{log_group} / {log_stream}',
            message=record['message'],
            timestamp=record['timestamp'] // 1000,
        )


# ------------------------------------------------------------------------------
def extract_sns_messages(event: dict[str, Any]) -> Iterator[SlackMsg]:
    """
    Sample event data.

    Extract SNS messages into a canonical format.
    {
      "Records": [
        {
          "EventVersion": "1.0",
          "EventSubscriptionArn": "eventSubscriptionArn",
          "EventSource": "aws:sns",
          "Sns": {
            "SignatureVersion": "1",
            "Timestamp": "1970-01-01T00:00:00.000Z",
            "Signature": "EXAMPLE",
            "SigningCertUrl": "EXAMPLE",
            "MessageId": "95df01b4-ee98-5cb9-9903-4c221d41eb5e",
            "Message": "Hello from SNS!",
            "MessageAttributes": {},
            "Type": "Notification",
            "UnsubscribeUrl": "EXAMPLE",
            "TopicArn": "topicArn",
            "Subject": "TestInvoke"
          }
        }
      ]
    }
    """

    for record in event['Records']:
        # This is in case we want to add SQS support at some point.
        event_source = record.get('eventSource', record.get('EventSource'))
        if event_source != 'aws:sns':
            raise SlackerError(f'Unexpected event source: {event_source}')

        topic_arn = record['Sns']['TopicArn']  # type: str
        yield SlackMsg(
            source_id=topic_arn,
            source_name='SNS:' + topic_arn.rsplit(':', 1)[1],
            subject=record['Sns']['Subject'],
            message=record['Sns']['Message'],
            timestamp=iso8601_to_ts(record['Sns']['Timestamp']),
        )


# ------------------------------------------------------------------------------
def extract_eventbridge_messages(event: dict[str, Any]) -> Iterator[SlackMsg]:
    """
    Extract raw EventBridge messages.

    These are messages from EventBridge that have not been manipulated with a
    transformer and hence still have elements like `detail` and `detail-type`.
    """

    # noinspection PyBroadException
    try:
        ts = iso8601_to_ts(event['time'])
    except Exception:
        ts = time.time()

    yield SlackMsg.from_object(
        event,
        source_id=f'events:{event.get("source", "?")}',
        source_name=f'EventBridge:{event.get("source", "?")}',
        subject=(event.get('detail-type')),
        timestamp=ts,
    )


# ------------------------------------------------------------------------------
def extract_custom_object_messages(event: dict[str, Any]) -> Iterator[SlackMsg]:
    """
    Extract custom object messages.

    These are custom objects that have been sent to the lambda. This is typically
    a result of an EventBridge message resulting from an input transformer or
    via direct invocation of the lambda.

    The message must have a `SlackerSourceId` field and may also have a
    `SlackerSourceName` field.

    """

    try:
        source_id = event['SlackerSourceId']
    except KeyError:
        raise SlackerError(f'Unknown event type: {event}')

    yield SlackMsg.from_object(
        event,
        source_id=source_id,
        source_name=event.get('SlackerSourceName', source_id),
        subject=event.get('SlackerSubject'),
        timestamp=time.time(),
    )


# ------------------------------------------------------------------------------
def extract_event_messages(event: dict[str, Any]) -> Iterator[SlackMsg]:
    """Extract messages from events data which may come from various AWS sources."""

    match event:
        case {'awslogs': _}:
            yield from extract_cloudwatch_messages(event)
        case {'Records': _}:
            yield from extract_sns_messages(event)
        case {'detail-type': _, 'detail': _}:
            yield from extract_eventbridge_messages(event)
        case {'SlackerSourceId': _}:
            yield from extract_custom_object_messages(event)
        case _:
            raise SlackerError(f'Unknown event type: {event}')
