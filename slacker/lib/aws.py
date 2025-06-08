"""AWS related utilities."""

from __future__ import annotations

from collections.abc import Iterator
from enum import IntEnum
from functools import cache
from typing import Any

import boto3


# ------------------------------------------------------------------------------
class Arn:
    """
    Fast and flimsy model of an AWS ARN.

    ARNs look like this:
        arn:aws:sns:ap-southeast-2:123456789012:my-topic
    """

    ArnComponent = IntEnum(
        'ArnComponent', ['partition', 'service', 'region', 'account', 'resource']
    )

    def __init__(self, arn: str):
        """Create an AWS Arn object."""

        self.arn = arn
        self._arn_parts = arn.split(':', len(self.ArnComponent))
        # The leading aws: has to be included in the len() hence the <=
        if (
            len(self._arn_parts) <= len(self.ArnComponent)
            or self._arn_parts[0] != 'arn'
            or not self.partition
            or not self.service
            or not self.resource
        ):
            raise ValueError(f'Bad ARN: {self.arn}')

    def __getattr__(self, attr: str):
        """Get a component of the ARN."""
        try:
            return self._arn_parts[self.ArnComponent[attr]]  # noqa
        except KeyError:
            raise AttributeError(attr)

    def __str__(self) -> str:
        """Return the original ARN."""
        return self.arn

    def __repr__(self) -> str:
        """Represent the ARN as a string."""
        return f'<{self.__class__.__name__}: {self.arn}>'


# ------------------------------------------------------------------------------
@cache
def account_id() -> str:
    """Get the AWS account ID."""
    return boto3.client('sts').get_caller_identity()['Account']


# ------------------------------------------------------------------------------
def dynamo_scan_table(table_name: str, aws_session: boto3.Session) -> Iterator[dict[str, Any]]:
    """
    Scan the specified DynamoDB table and return the items one at a time.

    :param table_name:      The table name.
    :param aws_session:     A boto3 Session().

    :return:                An iterator yielding items from the table.
    """

    dynamo = aws_session.resource('dynamodb')
    table = dynamo.Table(table_name)
    yield from table.scan(Select='ALL_ATTRIBUTES').get('Items', [])
