"""Common code, utilities etc."""

from __future__ import annotations

import json
import logging
import os
import secrets
from base64 import b64decode, urlsafe_b64encode
from datetime import UTC, datetime
from decimal import Decimal
from gzip import GzipFile
from io import BytesIO
from time import time_ns
from typing import Any
from zoneinfo import ZoneInfo

import dateutil.parser
from jinja2 import BaseLoader
from yaml import Dumper

LOGNAME = 'slacker'
LOGLEVEL = os.environ.get('LOGLEVEL', 'info')
LOG = logging.getLogger(LOGNAME)

EPOCH = datetime(year=1970, month=1, day=1)


# ------------------------------------------------------------------------------
def get_log_level(s: str) -> int:
    """
    Convert string log level to the corresponding integer log level.

    Raises ValueError if a bad string is provided.

    :param s:       A string version of a log level (e.g. 'error', 'info').
                    Case is not significant.

    :return:        The numeric logLevel equivalent.

    :raises:        ValueError if the supplied string cannot be converted.
    """

    if not s or not isinstance(s, str):
        raise ValueError('Bad log level:' + str(s))

    t = s.upper()

    if not hasattr(logging, t):
        raise ValueError('Bad log level: ' + s)

    return getattr(logging, t)


# ------------------------------------------------------------------------------
def setup_logging(level: str, name: str | None = None) -> None:
    """
    Set up logging.

    :param level:   Logging level. The string format of a level (eg 'debug').
    :param name:    Logger name. Default None implies root logger.

    """

    logger = logging.getLogger(name)
    logger.setLevel(get_log_level(level))
    logger.debug('Log level set to %s (%d)', level, logger.getEffectiveLevel())


# ------------------------------------------------------------------------------
def json_default(obj: Any) -> Any:
    """
    Serialise non-standard objects for json.dumps().

    This is a helper function for JSON serialisation with json.dumps() to allow
    (UTC) datetime and time objects to be serialised. It should be used thus ...

    .. code:: python

        json_string = json.dumps(object_of_some_kind, default=json_default)

    It is primarily used in API responses.

    :param obj:             An object.
    :return:                A serialisable version. For datetime objects we just
                            convert them to a string that strptime() could handle.

    :raise TypeError:       If obj cannot be serialised.
    """

    if isinstance(obj, datetime):
        return obj.isoformat()

    if isinstance(obj, Decimal):
        return float(obj) if '.' in str(obj) else int(obj)

    try:
        return str(obj)
    except Exception:
        raise TypeError(f'Cannot serialize {type(obj)}')


# ------------------------------------------------------------------------------
def iso8601_to_ts(iso: str) -> float:
    """
    Convert an ISO-8601 timestamp to a UNIX timestamp.

    WARNING: Only handles UTC timestamps.

    :param iso:     ISO-8601 timestamp. Must be UTC.
    :return:        Unix timestamp.
    """

    if not iso.endswith('Z'):
        raise ValueError('iso8601_to_ts can only handle UTC')

    d = dateutil.parser.parse(iso).replace(tzinfo=None)

    return (d - EPOCH).total_seconds()


# ------------------------------------------------------------------------------
def zip64_decode_data(data: str) -> Any:
    """
    Decode a base64, gzipped JSON string into a Python object.

    :param data:    The data to decode.
    :return:        A Python object.

    :raise Exception:   If there is a decoding problem.

    """

    return json.loads(GzipFile(fileobj=BytesIO(b64decode(data))).read())


# ------------------------------------------------------------------------------
def str2bool(s: str | bool) -> bool:
    """
    Convert a string to a boolean.

    This is a (case insensitive) semantic conversion.

        'true', 't', 'yes', 'y', non-zero int as str --> True
        'false', 'f', 'no', 'n', zero as str --> False

    :param s:       A boolean or a string representing a boolean. Whitespace is
                    stripped. Boolean values are passed back unchanged.

    :return:        A boolean derived from the input value.

    :raise ValueError:  If the value cannot be converted.

    """

    if isinstance(s, bool):
        return s

    if not isinstance(s, str):
        raise TypeError(f'Expected str, got {type(s)}')

    t = s.lower().strip()
    if t in ('true', 't', 'yes', 'y'):
        return True
    if t in ('false', 'f', 'no', 'n'):
        return False

    try:
        t = int(t)
    except ValueError:
        pass
    else:
        return bool(t)

    raise ValueError(f'Cannot convert string to bool: {s}')


# ------------------------------------------------------------------------------
# noinspection PyUnusedLocal
class NoLoader(BaseLoader):
    """Jinja2 loader that prevents loading."""

    def get_source(self, environment, template: str):
        """Block template loading."""
        raise Exception('Jinja2 loading prohibited')


# ------------------------------------------------------------------------------
def now(tzname: str = 'UTC') -> datetime:
    """Return the current datetime in the specified timezone."""

    return datetime.now(tz=ZoneInfo(tzname))


# ------------------------------------------------------------------------------
def current_time(tzname: str = 'UTC') -> str:
    """Return the current time of day in the specified timezone (no microseconds)."""

    return str(now(tzname=tzname).replace(microsecond=0).time())


# ------------------------------------------------------------------------------
class YamlIndentDumper(Dumper):
    """Correct indentation for yaml.dump."""

    def increase_indent(self, flow=False, indentless=False):
        """Correct indentation for yaml.dump."""
        return super().increase_indent(flow, False)


# ------------------------------------------------------------------------------
CUSTOM_EPOCH_NS = int(datetime(2025, 12, 1, tzinfo=UTC).timestamp()) * 1_000_000_000


def short_oid(randomiser_length: int = 4) -> str:
    """
    Generate a compact, URL-safe object identifier.

    This is based on the current timestamp with some random bytes appended, all
    base64 encoded. It is not easily decodeable (not cryptographically strong,
    just awkward).

    .. warning::
        This is NOT a general purpose replacement for a UUID. It is suitable for
        use in a well defined context where the number of events per nanosecond
        is not huge on a sustained basis.

    .. warning::
        This is NOT cryptographically secure and is not intended to be. Do NOT
        use this for things like "unguessable URLs".

    .. warning::
        This will break one day deep in the future. You won't be here.

    Comparison with a UUID:
    *   It is a lot shorter than a UUID. With the default 5 byte randomiser the
        result is 16 chars vs 36 for a UUID.
    *   They are (mostly) sortable (modulo non-monotonicity in the clock)
    *   A double click on a GUI selects the whole thing in one go.
    *   Much much much easier to brute force in a security context
        (i.e. not suitable).
    *   Not as discriminating as a UUID for a 4 byte randomiser but not bad either.

    :param randomiser_length:   The length of the randomiser. Default is 4 bytes
                which gives pretty good discrimination for hundreds of events per
                nanosecond. Set it to 8 to approximate a UUID.
    :return:    A URL safe string.

    """

    timestamp_bytes = (time_ns() - CUSTOM_EPOCH_NS).to_bytes(8, 'big')
    random_bytes = secrets.token_bytes(randomiser_length)
    # We replace '-' with '_' to ensure the result is a single "word". Yes this causes
    # some rare collisions bit it's really not a problem.
    return (
        urlsafe_b64encode(timestamp_bytes + random_bytes)
        .decode('ascii')
        .rstrip('=')
        .replace('-', '_')
    )
