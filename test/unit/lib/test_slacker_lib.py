"""Edge case tests for lib/slacker.py."""

import pytest

from slacker.lib.slacker import *


# ------------------------------------------------------------------------------
class TestSlackMsg:
    """SlackMsg tests."""

    # --------------------------------------------------------------------------
    def test_from_object(self):
        obj = {'a': 'A'}
        msg = SlackerMsg.from_object(
            obj, source_id='source_id', source_name='source_name', subject='subject'
        )
        assert msg.source_id == 'source_id'
        assert msg.source_name == 'source_name'
        assert msg.data == obj
