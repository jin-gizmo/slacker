"""Event worker plugin that forwards SNS messages to Slack channels."""

from __future__ import annotations

import json
import os
from itertools import chain
from typing import Any

import boto3

from config import LOGLEVEL, LOGNAME, WILDCARD_SOURCE_ID
from extractors import extract_event_messages
from lib.slacker import SlackerError, SlackerMsg, get_channel, get_webhook, log, process_msg_rules
from lib.utils import json_default, setup_logging

__author__ = 'Murray Andrews'

LOG_MESSAGES = bool(int(os.environ.get('LOG_MESSAGES', 1)))


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
    webhooks_table = aws_session.resource('dynamodb').Table(webhooks_table_name)
    channels_table = aws_session.resource('dynamodb').Table(channels_table_name)

    error_count = 0
    msg_count = 0
    for msg_count, record in enumerate(extract_event_messages(event), 1):  # noqa B007
        if LOG_MESSAGES:
            log.info(
                json.dumps(
                    {
                        'slackerId': record.slacker_id,
                        'type': 'incoming',
                        'sourceId': record.source_id,
                        'sourceName': record.source_name,
                        'subject': record.subject,
                        'message': record.data or record.text,
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
def process_msg(msg: SlackerMsg, webhooks_table, channels_table) -> None:
    """Process a message intended for Slack."""

    webhook_info = get_webhook(msg.source_id, webhooks_table)
    wildcard_webhook = get_webhook(WILDCARD_SOURCE_ID, webhooks_table)
    common_rules = wildcard_webhook.get('rules', []) if wildcard_webhook else []

    if webhook_info:
        rules = chain(webhook_info.setdefault('rules', []), common_rules)
    else:
        webhook_info = wildcard_webhook
        rules = common_rules

    if not webhook_info:
        raise SlackerError(f'Missing webhook for {msg.source_id}')

    if not webhook_info.get('enabled', True):
        log.info('Dropping message "%s" - webhook not enabled', msg.subject)
        return

    process_msg_rules(msg, rules)
    if not msg.text:
        return

    url = {}
    # A channel can be specified not at all, or at the webhook parent entry,
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
    # If the messages are being logged we include the slackerId to enabled them
    # to be looked up in the /aws/lambda/slacker log group. If we're not logging
    # messages, the slackerId has no relevance.
    msg.send(webhook_info | url, include_slacker_id=LOG_MESSAGES)
