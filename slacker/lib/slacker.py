"""Slacker related generic stuff."""

from __future__ import annotations

import json
import re
import time
from contextlib import suppress
from dataclasses import dataclass, field
from logging import getLogger
from threading import RLock
from typing import Any

import requests
from cachetools import TTLCache, cached

from config import (
    CACHE_TTL,
    DEFAULT_ACTION,
    DEFAULT_COLOUR,
    LOGNAME,
    MAX_MESSAGE_LEN,
    SLACK_API_TIMEOUT,
)
from lib.jinja import get_jenv
from lib.utils import str2bool

log = getLogger(LOGNAME)
webhook_cache = TTLCache(maxsize=200, ttl=CACHE_TTL) if CACHE_TTL > 0 else None
channel_cache = TTLCache(maxsize=200, ttl=CACHE_TTL) if CACHE_TTL > 0 else None


# ------------------------------------------------------------------------------
class SlackerError(Exception):
    """Generic slacker error."""

    pass


# ------------------------------------------------------------------------------
@dataclass
class SlackMsg:
    """Canonical content for a message to be sent to Slack."""

    source_id: str
    source_name: str
    subject: str | None
    message: str | None
    timestamp: float = None
    colour: str = None
    preamble: str = None
    channel: str = None
    _msg_object: Any = field(default=None, repr=False, compare=False)

    @classmethod
    def from_object(cls, obj: dict[str, Any], **kwargs) -> SlackMsg:
        """Create a SlackMsg from an already-decoded object."""
        return cls(message=json.dumps(obj, indent=4), _msg_object=obj, **kwargs)

    @property
    def msg_object(self) -> Any | None:
        """Try to decode the message as an object."""
        # If we have a pre-decoded object, use it
        if self._msg_object is not None:
            return self._msg_object

        # Otherwise try to decode from message string
        with suppress(Exception):
            return json.loads(self.message)
        return None

    # ------------------------------------------------------------------------------
    def send(self, webhook_info: dict[str, Any]):
        """
        Send a message to slack.

        At this point, any channel->url mapping (for the slacker webhook) must be
        fully resolved.
        """

        try:
            url = webhook_info['url']
        except KeyError:
            raise SlackerError(f'Cannot determine URL for webhook {webhook_info.get("sourceId")}')

        slack_msg = {
            'attachments': [
                {
                    'fallback': self.message[:MAX_MESSAGE_LEN],
                    'author_name': self.source_name,
                    'color': self.colour or webhook_info.get('colour', DEFAULT_COLOUR),
                    'title': self.subject,
                    'text': self.message[:MAX_MESSAGE_LEN],
                    'footer': 'Event time',
                    'ts': self.timestamp or int(time.time()),
                }
            ]
        }

        # Add in optional intro text (e.g. <!here>)
        with suppress(KeyError):
            slack_msg['text'] = self.preamble or webhook_info['preamble']

        response = requests.post(
            url,
            data=json.dumps(slack_msg),
            headers={'Content-Type': 'application/json'},
            timeout=SLACK_API_TIMEOUT,
        )
        if response.status_code != 200:
            raise SlackerError(f'Slack response {response.status_code} - {response.text}')

        log.info('Message from %s (%s) sent to Slack', self.source_name, self.source_id)


# ------------------------------------------------------------------------------
@cached(webhook_cache, lock=RLock(), key=lambda source_id, _: source_id)
def get_webhook(source_id: str, webhooks_table) -> dict[str, Any] | None:
    """
    Retrieve the Slack webhook for the given topic ARN from DynamoDB.

    These are cached.

    :param source_id:   AWS source identifier. e.g for an SNS message this
                        is the topic ARN.
    :param webhooks_table: Slack DynamoDB webhooks table resource.

    :return:            The DynamoDB entry for the given source ID which
                        contains the webhook URL and some supporting
                        information. Returns None if no webhook was found.

    """

    log.debug('Retrieving webhook for %s', source_id)
    with suppress(KeyError):
        return webhooks_table.get_item(Key={'sourceId': source_id})['Item']
    return None


# ------------------------------------------------------------------------------
@cached(channel_cache, lock=RLock(), key=lambda channel, _: channel)
def get_channel(channel: str, channels_table) -> dict[str, Any] | None:
    """
    Retrieve a Slack a channel config from DynamoDB.

    These are cached.

    :param channel:     Channel name.
    :param channels_table: Slack DynamoDB channels table resource.

    :return:            The DynamoDB entry for the given channel which contains
                        the webhook URL or None if no channel entry was found.

    """

    log.debug('Retrieving channel URL for %s', channel)
    with suppress(KeyError):
        return channels_table.get_item(Key={'channel': channel})['Item']
    return None


# ------------------------------------------------------------------------------
def process_msg_rules(msg: SlackMsg, rules: list[dict[str, Any]]) -> None:
    """
    Process the message transformation rules against a Slack message.

    If the message element is None, the message should be dropped.

    :param msg:     The message to process.
    :param rules:   The transformation / filtering rules from the webhooks table.
    """

    message = msg.message
    jenv = get_jenv()

    for rule_no, rule in enumerate(rules, 1):
        msg_object = msg.msg_object

        if 'match' in rule:
            if msg_object:
                log.debug(
                    '"match" in rule %d does not apply to object messages - skipping', rule_no
                )
                continue
            # For plain text messages we allow a regex to extract an object via capture groups
            if m := re.search(rule['match'], message):
                msg_object = m.groupdict()
            else:
                log.debug('Match failed in rule %d - skipping', rule_no)
                continue

        # Filter directive applies to messages from which we've managed to extract an
        # object, either by decoding JSON or via regex capture groups.

        if 'if' in rule:
            if not msg_object:
                log.debug('"if" in rule %d only applies to object messages - skipping', rule_no)
                continue

            try:
                condition = str2bool(
                    jenv.from_string(rule['if']).render(data=msg_object, msg=message)
                )
            except Exception as e:
                log.warning('Error evaluating if condition for rule %d: %s', rule_no, e)
                condition = False
            if not condition:
                log.debug('"if" condition not satisfied in rule %d - skipping', rule_no)
                continue

        match rule.get('action', DEFAULT_ACTION):
            case 'drop':
                log.info('Dropping message due to rule %d: %s', rule_no, message)
                msg.message = None
                return
            case 'send':
                log.debug('Proceeding to prepare phase for rule %d: %s', rule_no, message)
            case _:
                raise SlackerError(f'Unknown action in rule {rule_no}: {rule["action"]}')

        if 'template' not in rule:
            # Send message unchanged
            msg.colour = rule.get('colour', rule.get('color'))
            msg.preamble = rule.get('preamble')
            msg.channel = rule.get('channel')
            return

        # Prepare the transformed message content
        if not msg_object:
            # Templates only apply to messages from which an object has been extracted.
            log.debug('Cannot transform plain text msg - skipping rule: %s', message)
            continue

        try:
            msg.colour = rule.get('colour', rule.get('color'))
            msg.preamble = rule.get('preamble')
            msg.channel = rule.get('channel')
            msg.message = jenv.from_string(rule['template']).render(data=msg_object, msg=message)
            return
        except Exception as e:
            log.warning('Error evaluating template for rule %d: %s', rule_no, e)
            continue

    # Final return equivalent to an implicit unconditional send as the last rule.
