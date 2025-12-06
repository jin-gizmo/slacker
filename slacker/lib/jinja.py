"""Jinja related utilities."""

import re
from datetime import date, datetime
from functools import cache
from zoneinfo import ZoneInfo

import jinja2

from lib.aws import Arn, account_id, account_name, region_name
from lib.utils import NoLoader, current_time, now


# ------------------------------------------------------------------------------
def slack_link(href: str, text: str | None = None) -> str:
    """Generate link syntax for Slack."""

    if not href:
        raise ValueError('Slack link requires href')

    if not text:
        return f'<{href}>'

    return f'<{href}|{text}>'


# ------------------------------------------------------------------------------
@cache
def get_jenv() -> jinja2.Environment:
    """Create a Jinja environment with some useful extras."""

    # We really do want autoescape=False here.
    jenv = jinja2.Environment(loader=NoLoader(), autoescape=False)  # noqa S701
    jenv.globals |= {
        'date': date,
        'datetime': datetime,
        'tz': ZoneInfo,
        'now': now,
        'current_time': current_time,
        're': re,
        'aws': {
            'Arn': Arn,
            'account': account_id(),
            'account_name': account_name(),
            'region': region_name(),
        },
        'link': slack_link,
    }
    return jenv
