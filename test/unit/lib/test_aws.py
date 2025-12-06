"""Test AWS utils."""

import pytest

from lib import aws
from slacker.lib.aws import *


# ------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "arn, partition, service, region, account, resource",
    [
        (
            'arn:aws:ses:ap-southeast-2:123456789012:identity/whatever.com',
            'aws',
            'ses',
            'ap-southeast-2',
            '123456789012',
            'identity/whatever.com',
        ),
        (
            'arn:aws:iam::123456789012:user/fred',
            'aws',
            'iam',
            '',
            '123456789012',
            'user/fred',
        ),
    ],
)
def test_arn_ok(arn, partition, service, region, account, resource):
    a = Arn(arn)
    assert a.partition == partition
    assert a.service == service
    assert a.region == region
    assert a.account == account
    assert a.resource == resource
    assert str(a) == arn
    assert arn in repr(a)


# ------------------------------------------------------------------------------
def test_arn_bad_attribute_fail():

    a = Arn('arn:aws:ses:ap-southeast-2:123456789012:identity/whatever.com')
    with pytest.raises(AttributeError, match='nope'):
        _ = a.nope


# ------------------------------------------------------------------------------
@pytest.mark.parametrize(
    'arn',
    [
        'xxx:aws:ses:ap-southeast-2:123456789012:identity/whatever.com',
        'xxx::ses:ap-southeast-2:123456789012:identity/whatever.com',
        'xxx:aws::ap-southeast-2:123456789012:identity/whatever.com',
        'xxx:aws:ses:ap-southeast-2::identity/whatever.com',
        'xxx:aws:ses:ap-southeast-2:123456789012:',
        'xxx:aws:ses:ap-southeast-2:123456789012',
    ],
)
def test_arn_bad_fail(arn):
    with pytest.raises(ValueError, match='Bad ARN'):
        Arn(arn)


# ------------------------------------------------------------------------------
def test_account_name_env_var(monkeypatch):
    monkeypatch.setenv('AWS_ACCOUNT_NAME', 'whatever')
    # We need to bypass the cache in case it was populated in an earlier test.
    assert aws.account_name.__wrapped__() == 'whatever'
