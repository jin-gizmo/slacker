"""Tests for the common utilities."""

from datetime import date, timezone

import pytest
import yaml
from jinja2 import Environment

from lib.utils import *


# ------------------------------------------------------------------------------
@pytest.mark.parametrize(
    'level, expected',
    [
        ('Debug', logging.DEBUG),
        ('info', logging.INFO),
        ('WARNING', logging.WARNING),
    ],
)
def test_get_log_level(level: str, expected: int):
    assert get_log_level(level) == expected


# ------------------------------------------------------------------------------
@pytest.mark.parametrize('level', ['', 'unknown'])
def test_get_log_level_fail(level: str):
    with pytest.raises(ValueError, match='Bad log level'):
        get_log_level(level)


@pytest.mark.parametrize('level', ('debug', 'info', 'warning', 'error', 'critical'))
def test_setup_logging_to_stderr(level, caplog):
    setup_logging(level=level, name=LOGNAME)
    logger = logging.getLogger(LOGNAME)
    logger.log(get_log_level(level), f'{level}: Hello world')
    with caplog.at_level(get_log_level(level)):
        assert f'{level}: Hello world' in caplog.text


# ------------------------------------------------------------------------------
@pytest.mark.parametrize(
    'value, expected',
    [
        (datetime(2024, 1, 1, 10, 20, 30, tzinfo=timezone.utc), '"2024-01-01T10:20:30+00:00"'),
        (Decimal(10), '10'),
        (date(2024, 12, 31), '"2024-12-31"'),
    ],
)
def test_json_default_ok(value, expected):
    assert json.dumps(value, default=json_default) == expected


def test_json_default_fail():
    class Unserialisable:
        """Dummy unserialisable class."""

        def __init__(self, *args, **kwargs):
            pass

        def __str__(self):
            raise TypeError('Unserialisable')

    with pytest.raises(TypeError, match='Cannot serialize .*Unserialisable'):
        json.dumps({'a': 10, 'b': Unserialisable()}, default=json_default)


# ------------------------------------------------------------------------------
@pytest.mark.parametrize(
    'iso8601, expected',
    [
        ('1970-01-01T00:00:00.000Z', 0),
        ('2024-12-31T10:20:30.000Z', 1735640430),
    ],
)
def test_iso8601_to_ts_ok(iso8601: str, expected: float):
    assert iso8601_to_ts(iso8601) == expected


@pytest.mark.parametrize(
    'iso8601, error, match',
    [
        ('Bad timestamp', ValueError, 'can only handle UTC'),
        ('Bad timestampZ', ValueError, 'Unknown string format'),
    ],
)
def test_iso8601_to_ts_fail(iso8601: str, error, match: str):
    with pytest.raises(error, match=match):
        iso8601_to_ts(iso8601)


# ------------------------------------------------------------------------------
def test_zip64_decode_data(td):
    # Copied from the AWS Lambda cloudwatch-logs test template

    encoded_data = json.loads((td / 'cwatch-log-message.json').read_text())['awslogs']['data']
    expected = json.loads((td / 'cwatch-log-decoded.json').read_text())
    assert zip64_decode_data(encoded_data) == expected


# ------------------------------------------------------------------------------
@pytest.mark.parametrize(
    's,expected',
    [
        (True, True),
        (False, False),
        ('yes', True),
        ('y', True),
        ('t', True),
        ('trUE', True),
        ('1', True),
        ('no', False),
        ('N', False),
        ('f', False),
        ('FALSE', False),
        ('0', False),
    ],
)
def test_str2bool_ok(s, expected):
    assert str2bool(s) == expected


@pytest.mark.parametrize(
    's,exc',
    [
        (21, TypeError),
        ([], TypeError),
        ('no-idea', ValueError),
    ],
)
def test_str2bool_bad(s, exc):
    with pytest.raises(exc):
        str2bool(s)


# ------------------------------------------------------------------------------
def test_noloader():
    with pytest.raises(Exception, match='loading prohibited'):
        NoLoader().get_source(Environment(), 'whatever')


# ------------------------------------------------------------------------------
def test_now():
    t = datetime.now().astimezone(timezone.utc)
    assert (now() - t).total_seconds() < 2


# ------------------------------------------------------------------------------
def test_current_time():
    # Yes ... this has a vulnerability window. Deal with it.
    n = datetime.now().astimezone(timezone.utc)
    t1 = sum(a * b for a, b in zip([n.hour, n.minute, n.second], [3600, 60, 1]))
    t2 = sum(int(a) * b for a, b in zip(current_time().split(':'), [3600, 60, 1]))
    assert t2 - t1 < 2


# ------------------------------------------------------------------------------
@pytest.mark.parametrize(
    'data, expected',
    [
        (
            {'a': [1, 2, 3]},
            """
a:
  - 1
  - 2
  - 3
""",
        )
    ],
)
def test_yaml_indent_dumper(data, expected):
    assert yaml.dump(data, Dumper=YamlIndentDumper, default_flow_style=False) == expected.lstrip()
