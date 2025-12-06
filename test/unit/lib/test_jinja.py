"""Unit tests for Jinja related utils."""

import pytest
from slacker.lib.jinja import *


# ------------------------------------------------------------------------------
@pytest.mark.parametrize(
    'href,text,expected',
    [
        ('https://example.com', None, '<https://example.com>'),
        ('https://example.com', 'Example', '<https://example.com|Example>'),
    ],
)
def test_slack_link_ok(href, text, expected):
    assert slack_link(href, text) == expected


def test_slack_link_fail():
    with pytest.raises(ValueError):
        slack_link('', 'whatever')
