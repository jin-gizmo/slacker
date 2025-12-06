"""Slacker related generic stuff."""

from __future__ import annotations

import json
import re
import time
from collections.abc import Iterable
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
from .aws import account_name, region_name
from .jinja import get_jenv
from .utils import short_oid, str2bool

log = getLogger(LOGNAME)
webhook_cache = TTLCache(maxsize=200, ttl=CACHE_TTL) if CACHE_TTL > 0 else None
channel_cache = TTLCache(maxsize=200, ttl=CACHE_TTL) if CACHE_TTL > 0 else None


# ------------------------------------------------------------------------------
class SlackerError(Exception):
    """Generic slacker error."""

    pass


# ------------------------------------------------------------------------------
@dataclass(kw_only=True)
class SlackerMsg:
    """Canonical content for a message to be sent to Slack."""

    source_id: str
    source_name: str
    subject: str | None
    text: str | None
    timestamp: float = None
    colour: str = None
    preamble: str = None
    channel: str = None
    slacker_id: str = field(default_factory=short_oid, init=False)
    _data: Any = field(default=None, repr=False, compare=False)

    @classmethod
    def from_object(cls, obj: dict[str, Any], **kwargs) -> SlackerMsg:
        """Create a SlackMsg from an already-decoded object."""
        return cls(text=json.dumps(obj, indent=4), _data=obj, **kwargs)

    @property
    def data(self) -> Any | None:
        """Try to decode the message as an object."""
        # If we have a pre-decoded object, use it
        if self._data is not None:
            return self._data

        # Otherwise try to decode from message string
        with suppress(Exception):
            return json.loads(self.text)
        return None

    def __str__(self) -> str:
        """Get the string representation of the SlackMsg object."""
        return self.text

    # ------------------------------------------------------------------------------
    def send(self, webhook_info: dict[str, Any], include_slacker_id: bool = True) -> None:
        """
        Send a message to slack.

        :param webhook_info:    Destination webhook info.
        :param include_slacker_id: If True, include the slackerId in the message.

        At this point, any channel->url mapping (for the slacker webhook) must be
        fully resolved.
        """

        try:
            url = webhook_info['url']
        except KeyError:
            raise SlackerError(f'Cannot determine URL for webhook {webhook_info.get("sourceId")}')

        footer = [account_name(), region_name()]
        if include_slacker_id:
            footer.append(self.slacker_id)

        slack_msg = {
            'attachments': [
                {
                    'fallback': self.text[:MAX_MESSAGE_LEN],
                    'author_name': self.source_name,
                    'color': self.colour
                    or webhook_info.get('colour')
                    or webhook_info.get('color', DEFAULT_COLOUR),
                    'title': self.subject,
                    'text': self.text[:MAX_MESSAGE_LEN],
                    'footer': ' | '.join(footer),
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
def process_msg_rules(msg: SlackerMsg, rules: Iterable[dict[str, Any]]) -> None:
    """
    Process the message transformation rules against a Slack message.

    If the message element is None, the message should be dropped.

    :param msg:     The message to process.
    :param rules:   The transformation / filtering rules from the webhooks table.
    """

    jenv = get_jenv()

    for rule_no, rule in enumerate(rules, 1):
        data = msg.data

        if 'match' in rule:
            if data:
                log.debug(
                    '"match" in rule %d does not apply to object messages - skipping', rule_no
                )
                continue
            # For plain text messages we allow a regex to extract an object via capture groups
            if m := re.search(rule['match'], msg.text):
                # Capture groups take priority but if there are none we supply a tuple of matched
                # components.
                data = m.groupdict() or m.groups() or m.group(0)
            else:
                log.debug('Match failed in rule %d - skipping', rule_no)
                continue

        # Filter directive applies to messages from which we've managed to extract an
        # object, either by decoding JSON or via regex capture groups.

        if 'if' in rule:
            if not data:
                log.debug('"if" in rule %d only applies to object messages - skipping', rule_no)
                continue

            try:
                condition = str2bool(jenv.from_string(rule['if']).render(data=data, msg=msg))
            except Exception as e:
                log.warning('Error evaluating if condition for rule %d: %s', rule_no, e)
                condition = False
            if not condition:
                log.debug('"if" condition not satisfied in rule %d - skipping', rule_no)
                continue

        match rule.get('action', DEFAULT_ACTION):
            case 'drop':
                log.info('Dropping message due to rule %d: %s', rule_no, msg.text)
                msg.text = None
                return
            case 'send':
                log.debug('Proceeding to prepare phase for rule %d: %s', rule_no, msg.text)
            case _:
                raise SlackerError(f'Unknown action in rule {rule_no}: {rule["action"]}')

        if 'template' not in rule:
            # Send message unchanged
            msg.colour = rule.get('colour') or rule.get('color')
            msg.preamble = rule.get('preamble')
            msg.channel = rule.get('channel')
            return

        if not data:
            # Templates only apply to messages from which an object has been extracted.
            log.debug('Cannot transform plain text msg - skipping rule: %s', msg.text)
            continue

        # Prepare the transformed message content
        try:
            msg.colour = rule.get('colour', rule.get('color'))
            msg.preamble = rule.get('preamble')
            msg.channel = rule.get('channel')
            msg.text = jenv.from_string(rule['template']).render(data=data, msg=msg)
            return
        except Exception as e:
            log.warning('Error evaluating template for rule %d: %s', rule_no, e)
            continue

    # Final return equivalent to an implicit unconditional send as the last rule.
