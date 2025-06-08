"""Static config."""

import os

DEFAULT_COLOUR = os.environ.get('SLACKER_COLOUR', '#BBBBBB')
MAX_MESSAGE_LEN = int(os.environ.get('SLACKER_MSG_LEN', 4000))
CACHE_TTL = int(os.environ.get('SLACKER_CACHE_TTL', 300))

LOGNAME = 'slacker'
LOGLEVEL = os.environ.get('LOGLEVEL', 'info')

SLACKER_DOC_URL = 'https://jin-gizmo.github.io/slacker'
SCHEMA_BASE_URL = f'{SLACKER_DOC_URL}/schemas/latest'

SLACK_API_TIMEOUT = 10  # seconds timeout for slack API

# This sourceId is the one used if the sourceId of an incoming message doesn't
# match any entry in the webhooks table. It is also used as a set of tail end
# message rules for all webhooks entries. It is up to the users to decide
# whether or not to deploy a webhook that uses the sourceId of last reaort.
WILDCARD_SOURCE_ID = '*'

DEFAULT_ACTION = 'send'
