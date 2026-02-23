"""Test AWS utils."""

import pytest
from moto.core.models import DEFAULT_ACCOUNT_ID

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
class TestAccountName:
    """
    Unit tests for aws.account_name().

    These are in a class because test ordering may matter here.
    """

    def test_account_name_env_var(self, monkeypatch):
        monkeypatch.setenv('AWS_ACCOUNT_NAME', 'whatever')
        # We need to bypass the cache in case it was populated in an earlier test.
        assert aws.account_name.__wrapped__() == 'whatever'

    def test_account_name_account_alias(self, monkeypatch):
        monkeypatch.delenv('AWS_ACCOUNT_NAME', raising=False)
        # Create an account alias
        iam = boto3.client('iam', region_name='us-east-1')
        account_alias = 'slacker-test-account'
        iam.create_account_alias(AccountAlias=account_alias)
        assert aws.account_name.__wrapped__() == account_alias

    def test_account_name_no_account_alias(self, monkeypatch):
        monkeypatch.delenv('AWS_ACCOUNT_NAME', raising=False)
        assert aws.account_name.__wrapped__() == DEFAULT_ACCOUNT_ID


# ------------------------------------------------------------------------------
def test_dynamo_scan_table(mock_slacker_dynamodb_tables):
    dynamodb_rsc, webhooks_table, channels_table = mock_slacker_dynamodb_tables

    aws_session = boto3.Session(region_name='us-east-1')
    items = list(dynamo_scan_table(webhooks_table.name, aws_session))
    assert len(items) == 0

    webhooks_table.put_item(Item={'sourceId': 'whatever'})
    items = list(dynamo_scan_table(webhooks_table.name, aws_session))
    assert len(items) == 1


# ------------------------------------------------------------------------------
def test_lambda_restart(mock_slacker_lambda):
    lambda_client, func_name, _ = mock_slacker_lambda
    lambda_config = lambda_client.get_function_configuration(FunctionName=func_name)
    lambda_env = lambda_config.get('Environment', {}).get('Variables', {})
    assert 'TEST_RESTART' not in lambda_env

    aws_session = boto3.Session(region_name='us-east-1')
    lambda_restart(func_name, 'TEST_RESTART', aws_session=aws_session)
    lambda_config = lambda_client.get_function_configuration(FunctionName=func_name)
    lambda_env = lambda_config.get('Environment', {}).get('Variables', {})
    assert 'TEST_RESTART' in lambda_env
