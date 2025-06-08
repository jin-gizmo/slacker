"""Jinja related utilities."""

import re
from datetime import date, datetime
from functools import cache
from zoneinfo import ZoneInfo

import jinja2

from lib.aws import Arn, account_id
from lib.utils import NoLoader, current_time, now


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
        'aws': {'Arn': Arn, 'account': account_id()},
    }
    return jenv
