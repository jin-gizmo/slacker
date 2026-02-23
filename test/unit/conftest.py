"""
Pytest conf.

Note: auto_mock_aws() at the end is effectively a global mock.

"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import Any
from zipfile import ZipFile

import boto3
import pytest
import yaml
from moto import mock_aws

# Prevent accidents against a real AWS account.
os.environ['AWS_ACCESS_KEY_ID'] = 'testing'
os.environ['AWS_SECRET_ACCESS_KEY'] = 'testing'
os.environ['AWS_SECURITY_TOKEN'] = 'testing'
os.environ['AWS_SESSION_TOKEN'] = 'testing'
os.environ['AWS_DEFAULT_REGION'] = 'us-east-1'
os.environ.pop('AWS_PROFILE', None)

# Disable caching for tests.
os.environ['SLACKER_CACHE_TTL'] = '0'


# ------------------------------------------------------------------------------
class DotDict:
    """
    Access dict values with dot notation or conventional dict notation or mix and match.

    ..warning:: This does not handle all dict syntax, just what is needed here.

    """

    def __init__(self, *data: Mapping[str, Any]):
        """Create dotable dict from dict(s)."""
        self._data = {}

        for d in data:
            self._data.update(d)

    def __getattr__(self, item: str) -> Any:
        """Access config elements with dot notation support for keys."""

        if not item or not isinstance(item, str):
            raise ValueError(f'Bad config item name: {item}')

        try:
            value = self._data[item]
        except KeyError:
            raise AttributeError(item)
        return self.__class__(value) if isinstance(value, dict) else value

    def __getitem__(self, item):
        value = self._data[item]
        return self.__class__(value) if isinstance(value, dict) else value

    def __str__(self):
        return str(self._data)

    def __repr__(self):
        return repr(self._data)

    @property
    def dict(self) -> dict[str, Any]:
        """Return the underlying data as a dict."""
        return self._data


# ------------------------------------------------------------------------------
@pytest.fixture(scope='session')
def td() -> Path:
    """Path for test data."""
    return Path(__file__).parent.parent / 'data'


# ------------------------------------------------------------------------------
@pytest.fixture(scope='session')
def dirs(td) -> DotDict:
    """Package to access useful directories in the source tree."""

    return DotDict(
        {
            'cwd': Path('.').resolve(),
            'base': Path(__file__).parent.parent.parent,
            'src': Path(__file__).parent.parent.parent / 'slacker',
            'test': Path(__file__).parent.parent,
            'data': td,
        }
    )


# ------------------------------------------------------------------------------
@pytest.fixture(scope='function')
def aws_mock_creds(monkeypatch):
    """Mocked AWS Credentials for moto."""

    with suppress(KeyError):
        monkeypatch.delenv('AWS_PROFILE')

    monkeypatch.setenv('AWS_ACCESS_KEY_ID', 'testing')
    monkeypatch.setenv('AWS_SECRET_ACCESS_KEY', 'testing')
    monkeypatch.setenv('AWS_SECURITY_TOKEN', 'testing')
    monkeypatch.setenv('AWS_SESSION_TOKEN', 'testing')
    monkeypatch.setenv('AWS_DEFAULT_REGION', 'us-east-1')


# ------------------------------------------------------------------------------
@dataclass
class RulesTestScenario:
    """Test scenario for evaluating slack filtering rules."""

    input: str
    rules: list[dict[str, Any]]
    output: str | None = None
    error: str | None = None

    @classmethod
    def from_file(cls, file: Path | str) -> RulesTestScenario:
        """Load a test scenario from a YAML file."""
        path = file if isinstance(file, Path) else Path(file)
        scenario = yaml.safe_load(path.read_text())
        if not isinstance(scenario['input'], str):
            # Convenience for specifying JSON encoded test data in the YAML.
            scenario['input'] = json.dumps(scenario['input'])
        return cls(**scenario)


# ------------------------------------------------------------------------------
@pytest.fixture
def mock_sns_client():
    """Mock boto3 sns client."""
    with mock_aws():
        yield boto3.client('sns', region_name='us-east-1')


# ------------------------------------------------------------------------------
@pytest.fixture
def mock_logs_client():
    """Mock boto3 CloudWatch logs client."""
    # Strictly speaking we don't need the mock context here because of the
    # global level mock from the autouse fixture auto_mock_aws().
    with mock_aws():
        yield boto3.client('logs', region_name='us-east-1')


# ------------------------------------------------------------------------------
@pytest.fixture
def mock_slacker_lambda():
    """Create a dummy slacker lambda."""
    function_name = 'slacker'

    # Strictly speaking we don't need the mock context here because of the
    # global level mock from the autouse fixture auto_mock_aws().
    with mock_aws():
        # Create IAM client and role
        iam_client = boto3.client("iam", region_name="us-east-1")
        role_arn = iam_client.create_role(
            RoleName="lambda-test-role",
            AssumeRolePolicyDocument=(
                '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
                '"Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
            ),
        )["Role"]["Arn"]

        lambda_client = boto3.client('lambda', region_name='us-east-1')

        # Create an in-memory zip file with proper Lambda handler
        code_bytes = BytesIO()
        with ZipFile(code_bytes, 'w') as zf:
            zf.writestr('lambda_function.py', "def lambda_handler(event, context): pass")

        function_arn = lambda_client.create_function(
            FunctionName=function_name,
            Runtime='python3.13',
            Role=role_arn,
            Handler='lambda_function.lambda_handler',
            Code={'ZipFile': code_bytes.getvalue()},
        )['FunctionArn']
        yield lambda_client, function_name, function_arn


# ------------------------------------------------------------------------------
@pytest.fixture
def mock_slacker_dynamodb_tables():
    """Mock the DynamoDB tables used by slacker."""

    # Strictly speaking we don't need the mock context here because of the
    # global level mock from the autouse fixture auto_mock_aws().
    with mock_aws():
        dynamodb_rsc = boto3.resource('dynamodb', region_name='us-east-1')
        webhooks_table = dynamodb_rsc.create_table(
            TableName='slacker.webhooks',
            KeySchema=[{'AttributeName': 'sourceId', 'KeyType': 'HASH'}],
            AttributeDefinitions=[{'AttributeName': 'sourceId', 'AttributeType': 'S'}],
            ProvisionedThroughput={'ReadCapacityUnits': 3, 'WriteCapacityUnits': 1},
        )
        channels_table = dynamodb_rsc.create_table(
            TableName='slacker.channels',
            KeySchema=[{'AttributeName': 'channel', 'KeyType': 'HASH'}],
            AttributeDefinitions=[{'AttributeName': 'channel', 'AttributeType': 'S'}],
            ProvisionedThroughput={'ReadCapacityUnits': 3, 'WriteCapacityUnits': 1},
        )
        webhooks_table.wait_until_exists()
        channels_table.wait_until_exists()
        yield dynamodb_rsc, webhooks_table, channels_table


# ------------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def auto_mock_aws(request):
    """Apply mock_aws to all tests unless marked with @pytest.mark.real_aws."""
    if request.node.get_closest_marker('real_aws'):
        yield
    else:
        with mock_aws():
            yield
