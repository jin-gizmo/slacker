"""Test the main CLI (part 2)."""

import pytest
from moto.core import DEFAULT_ACCOUNT_ID
from shortuuid import uuid

from slacker.cli.slacker import *


# We could autouse this but as its a bit dodgy, test functions must opt in.
@pytest.fixture
def dedup_moto_list_rule_names_by_target(monkeypatch):
    """Compensate for failure to dedup bug moto list_rule_names_by_target."""
    from moto.events import models as events_models

    original = events_models.EventsBackend.list_rule_names_by_target

    def deduped(self, *args, **kwargs):
        """Deduplicate rule names to handle multiple targets with same ARN in a rule."""
        rule_names, next_token = original(self, *args, **kwargs)
        return list(dict.fromkeys(rule_names)), next_token  # noqa

    monkeypatch.setattr(
        events_models.EventsBackend,
        "list_rule_names_by_target",
        deduped,
    )


# ------------------------------------------------------------------------------
class TestCheckResults:
    """Test CheckResults class (edge cases mostly)."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup."""
        self.cr = CheckResults()
        self.cr.error('1', 'ERROR')
        self.cr.warning('2', 'WARNING')
        self.cr.info('3', 'INFO')

    def test_pprint_all(self, capsys):
        self.cr.pprint()
        out, err = capsys.readouterr()
        assert '1: ERROR' in out
        assert '2: WARNING' in out
        assert '3: INFO' in out
        assert err == ''

    def test_pprint_no_info(self, capsys):
        self.cr.pprint(CheckResults.ERROR | CheckResults.WARNING)
        out, err = capsys.readouterr()
        assert '1: ERROR' in out
        assert '2: WARNING' in out
        assert '3: INFO' not in out  # Not selected
        assert err == ''

    def test_str(self):
        s = str(self.cr)
        assert '1: ERROR' in s
        assert '2: WARNING' in s
        assert '3: INFO' in s


# ------------------------------------------------------------------------------
@pytest.mark.parametrize('fmt', ('json', 'yaml'))
def test_extra_webhook_fields_ok(fmt):
    d = extra_webhook_fields(fmt)
    assert 'account' in d
    assert '$schema' in d and d['$schema'].endswith(fmt)


def test_extra_webhook_fields_fail():
    with pytest.raises(ValueError, match='Bad format'):
        extra_webhook_fields('bad to the bone')


# ------------------------------------------------------------------------------
def test_sns_topic_exists_yes(mock_sns_client):
    topic_name = 'this-is-a-random-topic-name'
    arn = mock_sns_client.create_topic(Name=topic_name)['TopicArn']
    assert sns_topic_exists(arn, mock_sns_client)


def test_sns_topic_exists_no(mock_sns_client):
    topic_name = 'this-is-a-random-topic-name'
    arn = mock_sns_client.create_topic(Name=topic_name)['TopicArn'] + '-no-such'
    assert not sns_topic_exists(arn, mock_sns_client)


# ------------------------------------------------------------------------------
def test_sns_topic_has_slacker_subscription_yes(mock_sns_client, mock_slacker_lambda):
    topic_name = 'this-is-a-random-topic-name'
    topic_arn = mock_sns_client.create_topic(Name=topic_name)['TopicArn']
    lambda_client, func_name, func_arn = mock_slacker_lambda

    # Subscribe mock slacker Lambda to the SNS topic
    mock_sns_client.subscribe(TopicArn=topic_arn, Protocol='lambda', Endpoint=func_arn)
    assert sns_topic_has_slacker_subscription(topic_arn, mock_sns_client)


def test_sns_topic_has_slacker_subscription_no(mock_sns_client):
    topic_name = 'this-is-a-random-topic-name'
    arn = mock_sns_client.create_topic(Name=topic_name)['TopicArn']

    assert not sns_topic_has_slacker_subscription(arn, mock_sns_client)


# ------------------------------------------------------------------------------
def test_log_group_has_slacker_subscription_yes(mock_logs_client, mock_slacker_lambda):
    group_name = 'this-is-a-random-group-name'
    mock_logs_client.create_log_group(logGroupName=group_name)
    lambda_client, func_name, func_arn = mock_slacker_lambda
    mock_logs_client.put_subscription_filter(
        logGroupName=group_name,
        filterName='slacker',
        filterPattern='slacker',
        destinationArn=func_arn,
    )

    assert log_group_has_slacker_subscription(group_name, mock_logs_client)


# ------------------------------------------------------------------------------
def test_log_group_has_slacker_subscription_no(mock_logs_client):
    group_name = 'this-is-a-random-group-name'
    mock_logs_client.create_log_group(logGroupName=group_name)

    assert not log_group_has_slacker_subscription(group_name, mock_logs_client)


class TestCheckWebhookItemContext:
    """Test check_webhook_item_context function."""

    @staticmethod
    def has_error(results: CheckResults, pattern: str):
        """Check if the specified pattern is present in any errors."""
        return any(re.search(pattern, w) for w in results.errors)

    @pytest.fixture(autouse=True)
    def setup(self, mock_slacker_dynamodb_tables):
        """Set up mock dynamodb tables."""
        self.aws_session = boto3.Session(region_name='us-east-1')
        self.dynamodb_rsc, self.webhooks_table, self.channels_table = mock_slacker_dynamodb_tables
        self.webhook_item = {'sourceId': 'the-source-id', 'channel': 'the-channel'}
        self.channel_item = {'channel': 'the-channel', 'url': 'https://example.com'}
        self.webhooks_table.put_item(Item=self.webhook_item)
        self.channels_table.put_item(Item=self.channel_item)
        self.topic_arn = self.aws_session.client('sns').create_topic(Name='topic')['TopicArn']

    def test_check_webhook_item_context_generic_message_ok(self, mock_slacker_dynamodb_tables):
        results = check_webhook_item_context(self.webhook_item)
        # results = check_webhook_item_context(self.webhook_item, aws_session=self.aws_session)
        assert not any((results.errors, results.warnings))

    def test_check_webhook_item_context_no_such_channel(self, mock_slacker_dynamodb_tables):
        bad_webhook_item = {'sourceId': 'the-source-id', 'channel': 'no-such-channel'}
        self.webhooks_table.put_item(Item=bad_webhook_item)
        results = check_webhook_item_context(bad_webhook_item, aws_session=self.aws_session)
        assert self.has_error(results, 'Channel "no-such-channel" does not exist')

    def test_check_webhook_item_context_no_url_in_channel(self, mock_slacker_dynamodb_tables):
        webhook_item = {'sourceId': 'the-source-id', 'channel': 'bad-channel'}
        bad_channel_item = {'channel': 'bad-channel'}
        self.webhooks_table.put_item(Item=webhook_item)
        self.channels_table.put_item(Item=bad_channel_item)
        results = check_webhook_item_context(webhook_item, aws_session=self.aws_session)
        assert self.has_error(results, 'Channel "bad-channel" has no URL')

    def test_check_webhook_item_context_sns_source_no_topic(self, mock_slacker_dynamodb_tables):
        webhook_item = {'sourceId': self.topic_arn + 'none-such', 'channel': 'the-channel'}
        self.webhooks_table.put_item(Item=webhook_item)
        results = check_webhook_item_context(webhook_item, aws_session=self.aws_session)
        assert self.has_error(results, 'No such SNS topic')

    def test_check_webhook_item_context_sns_source_no_sub(self, mock_slacker_dynamodb_tables):
        webhook_item = {'sourceId': self.topic_arn, 'channel': self.channel_item['channel']}
        self.webhooks_table.put_item(Item=webhook_item)
        results = check_webhook_item_context(webhook_item, aws_session=self.aws_session)
        assert self.has_error(results, 'No slacker subscription on topic')

    def test_check_webhook_item_context_log_no_sub(self, mock_slacker_dynamodb_tables):
        group_name = 'log-group'
        self.aws_session.client('logs').create_log_group(logGroupName=group_name)
        webhook_item = {'sourceId': f'logs:{group_name}', 'channel': 'the-channel'}
        self.webhooks_table.put_item(Item=webhook_item)
        results = check_webhook_item_context(webhook_item, aws_session=self.aws_session)
        assert self.has_error(results, 'No subscription filter feeding slacker from log group')


# ------------------------------------------------------------------------------
class TestCmdList:
    """Test CLI list command."""

    @pytest.fixture(autouse=True)
    def setup(self, mock_slacker_dynamodb_tables):
        """Set up mock dynamodb tables."""
        self.aws_session = boto3.Session(region_name='us-east-1')
        self.dynamodb_rsc, self.webhooks_table, _ = mock_slacker_dynamodb_tables
        self.webhook_item = {'sourceId': 'the-source-id', 'channel': 'the-channel'}
        self.webhooks_table.put_item(Item=self.webhook_item)

    def test_cmd_list_execute(self, capsys):
        cmd = CmdList(ArgumentParser().add_subparsers())
        cmd.execute(Namespace())
        assert capsys.readouterr().out.strip() == self.webhook_item['sourceId']


# ------------------------------------------------------------------------------
class TestCmdDump:
    """Test CLI dump command."""

    @pytest.fixture(autouse=True)
    def setup(self, mock_slacker_dynamodb_tables):
        """Set up mock dynamodb tables."""
        self.aws_session = boto3.Session(region_name='us-east-1')
        self.dynamodb_rsc, self.webhooks_table, _ = mock_slacker_dynamodb_tables
        self.webhook_items = [
            {'sourceId': 'source_id', 'channel': 'the-channel'},
            {'sourceId': 'source*id', 'channel': 'the-channel'},  # Will map to same as previous
            {
                'sourceId': f'arn:aws:sns:us-east-1:{DEFAULT_ACCOUNT_ID}:topic',
                'channel': 'the-channel',
            },
            {'sourceId': 'logs:group-name', 'channel': 'the-channel'},
        ]
        for item in self.webhook_items:
            self.webhooks_table.put_item(Item=item)

    @pytest.mark.parametrize(
        'fmt, loader',
        [
            ('yaml', yaml.safe_load),
            ('json', json.loads),
        ],
    )
    def test_cmd_dump_execute(self, fmt, loader, tmp_path):
        cmd = CmdDump(ArgumentParser().add_subparsers())
        cmd.execute(Namespace(json=(fmt == 'json'), zip_file=str(tmp_path / 'dump.zip')))

        assert (tmp_path / 'dump.zip').exists()
        with ZipFile(str(tmp_path / 'dump.zip')) as zf:
            assert len(zf.namelist()) == len(self.webhook_items)

            # Compare contents
            webhooks = {item['sourceId']: item for item in self.webhook_items}
            extras = extra_webhook_fields(fmt)
            for filename in zf.namelist():
                assert filename.endswith(f'.{fmt}')
                data = loader(zf.read(filename))
                assert data == webhooks[data['sourceId']] | extras


# ------------------------------------------------------------------------------
class TestCmdGet:
    """Test CLI get command."""

    @pytest.fixture(autouse=True)
    def setup(self, mock_slacker_dynamodb_tables):
        """Set up mock dynamodb tables."""
        self.aws_session = boto3.Session(region_name='us-east-1')
        self.dynamodb_rsc, self.webhooks_table, _ = mock_slacker_dynamodb_tables
        self.webhook_item = {'sourceId': 'the-source-id', 'channel': 'the-channel'}
        self.webhooks_table.put_item(Item=self.webhook_item)

    @pytest.mark.parametrize(
        'fmt, loader',
        [
            ('yaml', yaml.safe_load),
            ('json', json.loads),
        ],
    )
    def test_cmd_get_execute_ok(self, fmt, loader, capfd):
        cmd = CmdGet(ArgumentParser().add_subparsers())
        cmd.execute(Namespace(source_id=self.webhook_item['sourceId'], json=(fmt == 'json')))
        # We need to use capfd not capsys here because we need fileno to work on stdout.
        data = loader(capfd.readouterr().out)
        assert data == self.webhook_item | extra_webhook_fields(fmt)

    def test_cmd_get_execute_fail(self, capfd):
        cmd = CmdGet(ArgumentParser().add_subparsers())
        with pytest.raises(KeyError, match='No such item'):
            cmd.execute(Namespace(source_id='no-such-source-id', json=False))


# ------------------------------------------------------------------------------
class TestCmdPut:
    """Test CLI put command."""

    @pytest.fixture(autouse=True)
    def setup(self, mock_slacker_dynamodb_tables):
        """Set up mock dynamodb tables."""
        self.aws_session = boto3.Session(region_name='us-east-1')
        self.dynamodb_rsc, self.webhooks_table, _ = mock_slacker_dynamodb_tables
        self.webhook_item_chan = {
            'sourceId': 'the-source-id',
            'account': DEFAULT_ACCOUNT_ID,
            'channel': str(uuid()),  # Ensure uniqueness
        }
        self.webhook_item_url = {
            'sourceId': 'the-source-id',
            'account': DEFAULT_ACCOUNT_ID,
            'url': 'https://example.com',
        }

    @pytest.mark.parametrize(
        'fmt, loader, dumper',
        [
            ('yaml', yaml.safe_load, yaml.safe_dump),
            ('json', json.loads, json.dumps),
        ],
    )
    def test_cmd_put_execute_ok(self, fmt, loader, dumper, tmp_path, capsys):
        (tmp_path / f'item.{fmt}').write_text(dumper(self.webhook_item_url))

        cmd = CmdPut(ArgumentParser().add_subparsers())
        cmd.execute(
            Namespace(
                file=str(tmp_path / f'item.{fmt}'),
                backup=str(tmp_path / f'backup.{fmt}'),
                force=False,
                restart=False,
                strip_schema_keywords=False,
            )
        )

        assert 'Item created' in capsys.readouterr().out
        # Nothing to backup at this point
        assert not (tmp_path / f'backup.{fmt}').exists()

        cmd.execute(
            Namespace(
                file=str(tmp_path / f'item.{fmt}'),
                backup=str(tmp_path / f'backup.{fmt}'),
                force=False,
                restart=False,
                strip_schema_keywords=False,
            )
        )
        assert (tmp_path / f'backup.{fmt}').exists()
        # Check the backup file is correct
        backup_data = loader((tmp_path / f'backup.{fmt}').read_text())
        del backup_data['x-slacker']
        assert backup_data == self.webhook_item_url

    def test_cmd_put_execute_no_account_key(self, tmp_path):
        item = dict(self.webhook_item_url)
        del item['account']
        (tmp_path / f'item.yaml').write_text(yaml.safe_dump(item))
        cmd = CmdPut(ArgumentParser().add_subparsers())
        with pytest.raises(SlackerError, match='Missing "account" key'):
            cmd.execute(Namespace(file=str(tmp_path / 'item.yaml'), force=True))

    def test_cmd_put_execute_wrong_account_key(self, tmp_path):
        item = dict(self.webhook_item_url)
        item['account'] = '000000000000'
        (tmp_path / f'item.yaml').write_text(yaml.safe_dump(item))
        cmd = CmdPut(ArgumentParser().add_subparsers())
        with pytest.raises(SlackerError, match='does not match AWS account ID'):
            cmd.execute(Namespace(file=str(tmp_path / 'item.yaml'), force=True))

    def test_cmd_put_execute_unknown_channel_no_force(self, tmp_path, capsys):
        (tmp_path / 'item.yaml').write_text(yaml.safe_dump(self.webhook_item_chan))
        cmd = CmdPut(ArgumentParser().add_subparsers())
        with pytest.raises(SlackerError, match=r'Error\(s\) in webhooks entry'):
            cmd.execute(Namespace(file=str(tmp_path / 'item.yaml'), force=False))
        out, err = capsys.readouterr()
        assert f'Channel "{self.webhook_item_chan["channel"]}" does not exist' in err

    def test_cmd_put_execute_unknown_channel_force(self, tmp_path, capsys):
        (tmp_path / 'item.yaml').write_text(yaml.safe_dump(self.webhook_item_chan))
        cmd = CmdPut(ArgumentParser().add_subparsers())
        # No exception this time but we still print the error to stderr
        cmd.execute(
            Namespace(
                file=str(tmp_path / 'item.yaml'),
                force=True,
                strip_schema_keywords=True,
                backup=False,
                restart=False,
            )
        )
        out, err = capsys.readouterr()
        assert 'Item created' in out
        assert f'Channel "{self.webhook_item_chan["channel"]}" does not exist' in err
        # Make sure item got into the table.
        hook = get_webhook.__wrapped__(self.webhook_item_chan['sourceId'], self.webhooks_table)
        assert all(self.webhook_item_chan[k] == hook[k] for k in self.webhook_item_chan.keys())

    def test_cmd_put_execute_restart_lambda(self, tmp_path, capsys, mock_slacker_lambda):
        (tmp_path / 'item.yaml').write_text(yaml.safe_dump(self.webhook_item_url))

        # Make sure lambda doesn't currently have a RESTART env var
        lambda_client, func_name, _ = mock_slacker_lambda
        lambda_config = lambda_client.get_function_configuration(FunctionName=func_name)
        lambda_env = lambda_config.get('Environment', {}).get('Variables', {})
        assert 'RESTART' not in lambda_env

        cmd = CmdPut(ArgumentParser().add_subparsers())
        cmd.execute(
            Namespace(
                file=str(tmp_path / 'item.yaml'),
                backup=None,
                force=False,
                restart=True,
                strip_schema_keywords=False,
            )
        )
        out, err = capsys.readouterr()
        assert 'Item created' in out
        lambda_config = lambda_client.get_function_configuration(FunctionName=func_name)
        lambda_env = lambda_config.get('Environment', {}).get('Variables', {})
        assert 'RESTART' in lambda_env


# ------------------------------------------------------------------------------
class TestCmdCheck:
    """Test CLI check command."""

    @pytest.fixture(autouse=True)
    def setup(self, mock_slacker_dynamodb_tables, mock_slacker_lambda, mock_sns_client):
        """Set up mock dynamodb tables."""
        self.aws_session = boto3.Session(region_name='us-east-1')
        self.dynamodb_rsc, self.webhooks_table, self.channels_table = mock_slacker_dynamodb_tables
        _, self.func_name, self.func_arn = mock_slacker_lambda

    @staticmethod
    def results_match(results: CheckResults, match: str) -> str | None:
        """Check if any of the items in results matches the given regex."""

        pat = re.compile(match)
        for severity in (results.infos, results.warnings, results.errors):
            for s in severity:
                if pat.search(s):
                    return s
        return None  # pragma: no cover

    @pytest.mark.parametrize(
        'tag, topic_exists, is_subscribed, is_used_in_wh, expected',
        [
            ('t0', False, False, False, None),  # null case
            ('t1', True, False, False, None),  # Also null
            ('t2', True, True, False, 'Subscribed topic with no active webhooks'),
            # The next one is counterintuitive - we have a webhook referencing
            # a topic that doesn't exist. This is not seen as a subscription
            # problem but rather a webhook problem so gets caught elsewhere.
            ('t3', False, False, True, None),
            # # Same comments as previous.
            ('t4', True, False, True, None),
            ('t5', True, True, True, 'arn:aws:sns:.*: OK'),
        ],
    )
    def test_check_sns_subscriptions(
        self, tag, topic_exists, is_subscribed, is_used_in_wh, expected, mock_sns_client
    ):
        topic_name = f'{tag}-{uuid()}'
        topic_arn = (
            self.aws_session.client('sns').create_topic(Name=topic_name)['TopicArn']
            if topic_exists
            else f'arn:aws:sns:us-east-1:{DEFAULT_ACCOUNT_ID}:{topic_name}'
        )
        if topic_exists and is_subscribed:
            # Subscribe the topic to the lambda (if the topic exists).
            mock_sns_client.subscribe(TopicArn=topic_arn, Protocol='lambda', Endpoint=self.func_arn)
        if is_used_in_wh:
            # Create a webhook that uses the topic as a source. Only need sourceId here.
            self.webhooks_table.put_item(Item={'sourceId': topic_arn})

        cmd = CmdCheck(ArgumentParser().add_subparsers())
        cmd._setup()
        results = cmd.check_sns_subscriptions()
        assert expected or not results.infos, f'Unexpected infos: {results.infos}'
        assert expected or not results.warnings, f'Unexpected warnings: {results.warnings}'
        assert expected or not results.errors, f'Unexpected errors: {results.errors}'
        if not expected:
            return
        m = self.results_match(results, expected)  # noqa
        assert m, f'Expected results: "{expected}" did not match any result:\n{results}\n{80*"-"}'

    def test_check_sns_subscriptions_wildcard(self, mock_sns_client):
        """Test situation where a wildcard webhook catches an SNS sourceId."""
        topic_name = uuid()
        topic_arn = self.aws_session.client('sns').create_topic(Name=topic_name)['TopicArn']
        mock_sns_client.subscribe(TopicArn=topic_arn, Protocol='lambda', Endpoint=self.func_arn)
        # Add our wildcard webhook instead of one matching our SNS topic.
        self.webhooks_table.put_item(Item={'sourceId': '*'})
        cmd = CmdCheck(ArgumentParser().add_subparsers())
        cmd._setup()
        results = cmd.check_sns_subscriptions()
        expected = 'Relying on wildcard webhook'
        m = self.results_match(results, expected)
        assert m, f'Expected results: "{expected}" did not match any result:\n{results}\n{80*"-"}'

    @pytest.mark.parametrize(
        'target, expected',
        [
            (
                # This target is a fully formed valid target for slacker.
                {
                    'Id': 'aimed-at-slacker',
                    'InputTransformer': {
                        'InputPathsMap': {'src': '$.detail.source'},
                        'InputTemplate': json.dumps(
                            {'SlackerSourceId': '<src>', 'SlackerSourceName': 'Unit tests'}
                        ),
                    },
                },
                ('aimed-at-slacker', '<src>', 'Unit tests', None),
            ),
            (
                # Does not point at the slacker lambda and will be ignored
                {
                    'Id': 'not-aimed-at-slacker',
                    'Arn': f'arn:aws:sns:us-east-1:{DEFAULT_ACCOUNT_ID}:{uuid}',
                    'InputTransformer': {
                        'InputPathsMap': {'src': '$.detail.source'},
                        'InputTemplate': json.dumps(
                            {'SlackerSourceId': '<src>', 'SlackerSourceName': 'Unit tests'}
                        ),
                    },
                },
                None,
            ),
            (
                # No input transformer - will be ignored
                {'Id': 'not-input-transformer', 'Input': 'A string'},
                None,
            ),
            (
                # Input transformer with bad payload.
                {
                    'Id': 'bad-template',
                    'InputTransformer': {
                        'InputPathsMap': {'src': '$.detail.source'},
                        'InputTemplate': '{ BAD JSON',
                    },
                },
                ('bad-template', '', '', 'Target bad-template: Bad JSON input template'),
            ),
        ],
    )
    def test_get_source_info_from_event_bridge_rule_ok(self, target, expected):
        rule_name = uuid()
        events = self.aws_session.client('events')
        # Create an EventBridge rule
        events.put_rule(
            Name=rule_name,
            EventPattern=json.dumps({'source': ['test-source'], 'detail-type': ['slacker-test']}),
            State='ENABLED',
            Description='Slacker unit test',
        )
        # Add target
        events.put_targets(Rule=rule_name, Targets=[{'Arn': self.func_arn} | target])
        cmd = CmdCheck(ArgumentParser().add_subparsers())
        cmd._setup()
        results = list(cmd.get_source_info_from_event_bridge_rule(rule_name))
        assert len(results) == (1 if expected else 0)
        if expected:
            assert results[0] == expected

    @pytest.mark.parametrize(
        'target, expected',
        [
            (
                # This target is a fully formed valid target for slacker.
                {
                    'Id': 'all-ok',
                    'InputTransformer': {
                        'InputPathsMap': {'src': '$.detail.source'},
                        'InputTemplate': json.dumps(
                            {'SlackerSourceId': '<src>', 'SlackerSourceName': 'Unit tests'}
                        ),
                    },
                },
                'OK',
            ),
            (
                # This one is valid but omits optional SlackerSourceName so we get a warning
                {
                    'Id': 'missing-source-name',
                    'InputTransformer': {
                        'InputPathsMap': {'src': '$.detail.source'},
                        'InputTemplate': json.dumps({'SlackerSourceId': '<src>'}),
                    },
                },
                'SlackerSourceName missing',
            ),
            (
                # This one is not valid ... omits mandatory SlackerSourceId
                {
                    'Id': 'missing-source-id',
                    'InputTransformer': {
                        'InputPathsMap': {'src': '$.detail.source'},
                        'InputTemplate': json.dumps({'SlackerSourceName': 'Unit tests'}),
                    },
                },
                'SlackerSourceId missing',
            ),
            (
                # No input transformer, so ok by default as we can't really check it properly
                {'Id': 'not-input-transformer', 'Input': 'A string'},
                'OK',
            ),
            (
                # Input transformer with bad payload.
                {
                    'Id': 'bad-input-template',
                    'InputTransformer': {
                        'InputPathsMap': {'src': '$.detail.source'},
                        'InputTemplate': '{ BAD JSON',
                    },
                },
                'Bad JSON input template',
            ),
        ],
    )
    def test_check_event_rules(self, target, expected, dedup_moto_list_rule_names_by_target):
        rule_name = uuid()
        events = self.aws_session.client('events')
        # Create an EventBridge rule
        events.put_rule(
            Name=rule_name,
            EventPattern=json.dumps({'source': ['test-source'], 'detail-type': ['slacker-test']}),
            State='ENABLED',
            Description='Slacker unit test',
        )
        events.put_targets(Rule=rule_name, Targets=[{'Arn': self.func_arn, **target}])
        cmd = CmdCheck(ArgumentParser().add_subparsers())
        cmd._setup()
        results = cmd.check_event_rules()
        assert self.results_match(results, expected)

    def test_cmd_check_execute(self, capsys):
        """
        Check the main entry point for the check command.

        This is really just a coverage thing as other tests cover all the nitty
        gritty.
        """

        cmd = CmdCheck(ArgumentParser().add_subparsers())
        cmd.execute(Namespace())
        out, err = capsys.readouterr()
        assert 'Checking webhooks' in out
        assert 'Checking SNS subscriptions' in out
        assert 'Checking EventBridge rules' in out


# ------------------------------------------------------------------------------
class TestCmdRestart:
    """Test CLI restart command."""

    def test_cmd_restart_execute(self, mock_slacker_lambda):
        # Make sure lambda doesn't currently have a RESTART env var
        lambda_client, func_name, _ = mock_slacker_lambda
        lambda_config = lambda_client.get_function_configuration(FunctionName=func_name)
        lambda_env = lambda_config.get('Environment', {}).get('Variables', {})
        assert 'RESTART' not in lambda_env

        cmd = CmdRestart(ArgumentParser().add_subparsers())
        cmd.execute(Namespace())

        lambda_config = lambda_client.get_function_configuration(FunctionName=func_name)
        lambda_env = lambda_config.get('Environment', {}).get('Variables', {})
        assert 'RESTART' in lambda_env


# ------------------------------------------------------------------------------
class TestCmdCompletion:
    """Test CLI completion command."""

    def test_cmd_completion_execute(self, capsys):

        cmd = CmdCompletion(ArgumentParser().add_subparsers())
        cmd.execute(Namespace(shell='zsh'))
        out, err = capsys.readouterr()
        assert out.strip().startswith('#compdef ')
