"""Event worker plugin that forwards SNS messages to Slack channels."""

from __future__ import annotations

import json
import os
from typing import Any

import boto3

from config import LOGLEVEL, LOGNAME, WILDCARD_SOURCE_ID
from extractors import extract_event_messages
from lib.slacker import SlackMsg, SlackerError, get_channel, get_webhook, log, process_msg_rules
from lib.utils import json_default, setup_logging

__author__ = 'Murray Andrews'


# ------------------------------------------------------------------------------
# noinspection PyUnusedLocal
def lambda_handler(event: dict[str, Any], context) -> None:
    """
    AWS lambda entry point.

    :param event:       Lambda event data.
    :param context:     Lambda context.

    """

    setup_logging(os.environ.get('LOGLEVEL', LOGLEVEL), name=LOGNAME)
    webhooks_table_name = f'{context.function_name}.webhooks'
    channels_table_name = f'{context.function_name}.channels'

    if LOGLEVEL == 'debug':
        # We guard this with the if statement because json.dumps is expensive
        log.debug('Received event:\n%s', json.dumps(event, sort_keys=True, indent=2))

    aws_session = boto3.Session()
    try:
        webhooks_table = aws_session.resource('dynamodb').Table(webhooks_table_name)
    except Exception as e:
        raise SlackerError(f'Cannot get DynamoDB table {webhooks_table_name} - {e}')
    try:
        channels_table = aws_session.resource('dynamodb').Table(channels_table_name)
    except Exception as e:
        raise SlackerError(f'Cannot get DynamoDB table {channels_table_name} - {e}')

    log_incoming_messages = bool(int(os.environ.get('LOG_MESSAGES', 0)))

    error_count = 0
    msg_count = 0
    for msg_count, record in enumerate(extract_event_messages(event), 1):  # noqa B007
        if log_incoming_messages:
            log.info(
                json.dumps(
                    {
                        'type': 'incoming',
                        'sourceId': record.source_id,
                        'sourceName': record.source_name,
                        'subject': record.subject,
                        'message': record.msg_object or record.message,
                        'timestamp': record.timestamp,
                    },
                    sort_keys=True,
                    indent=4,
                    default=json_default,
                )
            )
        try:
            process_msg(record, webhooks_table, channels_table)
        except Exception as e:
            log.error('Error processing message: %s : %s', e, record)
            error_count += 1

    log.info('Processed %d messages with %d errors', msg_count, error_count)
    if error_count:
        raise SlackerError(f'Error processing {error_count} messages')


# ------------------------------------------------------------------------------
def process_msg(msg: SlackMsg, webhooks_table, channels_table) -> None:
    """Process a message intended for Slack."""

    webhook_info = get_webhook(msg.source_id, webhooks_table)
    webhook_of_last_resort = get_webhook(WILDCARD_SOURCE_ID, webhooks_table)
    common_rules = webhook_of_last_resort.get('rules', []) if webhook_of_last_resort else []

    if webhook_info:
        webhook_info.setdefault('rules', [])
        webhook_info['rules'].extend(common_rules)
    else:
        webhook_info = webhook_of_last_resort

    if not webhook_info:
        raise SlackerError(f'Missing webhook for {msg.source_id}')

    if not webhook_info.get('enabled', True):
        log.info('Dropping message "%s" - webhook not enabled', msg.subject)
        return

    process_msg_rules(msg, webhook_info.get('rules', []))
    if not msg.message:
        return

    url = {}
    # A channel can be specified not at all, or at the webhook parent # entry,
    # or at the level of the effective rule. The latter takes precedence. If no
    # channel is specified, a url must specified at the webhook level.
    channel = msg.channel or webhook_info.get('channel')
    if channel:
        if not (channel_info := get_channel(channel, channels_table)):
            raise SlackerError(f'Missing channel entry for {channel}')
        try:
            url = channel_info['url']
        except KeyError:
            raise SlackerError(f'Channel entry for {channel} has no url')
        url = {'url': url}
    msg.send(webhook_info | url)
