#!/usr/bin/env python3

"""Manage slacker webhooks and rules."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from abc import ABC, abstractmethod
from argparse import ArgumentParser, Namespace
from collections.abc import Callable, Iterator
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import datetime
from functools import cache, partial
from getpass import getuser
from importlib import resources
from pathlib import Path
from socket import gethostname
from typing import Any, ClassVar
from zipfile import ZipFile

import boto3
import jsonschema
import yaml
from colorama import Fore, Style, init
from pygments import highlight
from pygments.formatters import Terminal256Formatter as TerminalFormatter
from pygments.lexers import JsonLexer, YamlLexer

import slacker.schemas
import slacker.version
from slacker.config import SCHEMA_BASE_URL, SLACKER_DOC_URL, WILDCARD_SOURCE_ID

# This is a bit of a hack to allow the same package structure to be used for the
# lambda bundle as for the pip-installable bundle. Yes, I should work it out properly.
sys.path.insert(0, str(Path(slacker.version.__file__).parent))

from lib.aws import Arn, account_id, dynamo_scan_table, lambda_restart, region_name  # noqa E402
from lib.slacker import (  # noqa E402
    SlackerMsg,
    SlackerError,
    get_channel,
    get_webhook,
    process_msg_rules,
)
from lib.utils import YamlIndentDumper, setup_logging, json_default  # noqa E402

PROG = Path(sys.argv[0]).stem

# Must match the lambda function name
SLACKER_APP_NAME = os.environ.get('SLACKER_APP_NAME', 'slacker')
WEBHOOKS_TABLE = f'{SLACKER_APP_NAME}.webhooks'
CHANNELS_TABLE = f'{SLACKER_APP_NAME}.channels'

command_handlers = {}

init()


# ------------------------------------------------------------------------------
def _cprint(colour, *args, **kwargs):
    """Print in colour."""

    print(colour, sep='', end='', **kwargs)
    print(*args, end='', **kwargs)
    print(Style.RESET_ALL, **kwargs)


info = partial(_cprint, Fore.GREEN)
warning = partial(_cprint, Fore.YELLOW)
error = partial(_cprint, Fore.RED)
heading = partial(_cprint, Fore.BLUE)


# ------------------------------------------------------------------------------
@cache
def get_webhook_schema_validator():
    """Load the webhook schema and return a validator for it."""
    schema = yaml.safe_load(
        resources.files(slacker.schemas).joinpath('latest', 'webhook.schema.yaml').read_text()
    )
    validator_class = jsonschema.validators.validator_for(schema)
    return validator_class(schema)


# ------------------------------------------------------------------------------
def validate_webhook_schema(webhook: dict[str, Any]) -> None:
    """
    Do a schema validation on a webhook item.

    :raises jsonschema.exceptions.ValidationError: If validation fails.
    """

    validator = get_webhook_schema_validator()
    validator.validate(webhook)


# ------------------------------------------------------------------------------
@cache
def extra_webhook_fields(fmt: str) -> dict[str, Any]:
    """
    Generate extra webhook fields to add when downloading.

    :param fmt: The intended output format. This influences which version of the
                JSON schema is used. Must be one of: json or yaml.

    :return: A dict with extra webhook fields.
    """

    if fmt.lower() not in ('json', 'yaml'):
        raise ValueError(f'Bad format: {fmt}')

    return {
        'account': account_id(),
        '$schema': f'{SCHEMA_BASE_URL}/webhook.schema.{fmt.lower()}',
    }


# ------------------------------------------------------------------------------
@cache
def sns_topic_exists(topic_arn: str, sns_client) -> bool:
    """Check if an SNS topic exists."""

    try:
        sns_client.get_topic_attributes(TopicArn=topic_arn)
        return True
    except sns_client.exceptions.NotFoundException:
        return False


# ------------------------------------------------------------------------------
@cache
def sns_topic_has_slacker_subscription(topic_arn: str, sns_client) -> bool:
    """Check if an SNS topic has a slacker subscription."""

    paginator = sns_client.get_paginator('list_subscriptions_by_topic')

    with suppress(sns_client.exceptions.ResourceNotFoundException):
        for result in paginator.paginate(TopicArn=topic_arn):
            for subscription in result.get('Subscriptions', []):
                if subscription['Protocol'] == 'lambda' and subscription['Endpoint'].endswith(
                    f':function:{SLACKER_APP_NAME}'
                ):
                    return True
    return False


# ------------------------------------------------------------------------------
@cache
def log_group_has_slacker_subscription(log_group_name: str, logs_client) -> bool:
    """Check if a log group has a subscription filter feeding slacker."""

    paginator = logs_client.get_paginator('describe_subscription_filters')

    with suppress(logs_client.exceptions.ResourceNotFoundException):
        for result in paginator.paginate(logGroupName=log_group_name):
            for sf in result.get('subscriptionFilters', []):
                dest_arn = Arn(sf['destinationArn'])
                if (
                    dest_arn.service == 'lambda'
                    and dest_arn.resource == f'function:{SLACKER_APP_NAME}'
                ):
                    return True

    return False


# ------------------------------------------------------------------------------
@dataclass(frozen=True)
class CheckResults:
    """Container for check results."""

    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# ------------------------------------------------------------------------------
def check_webhook_item_content(item: dict[str, Any], results: CheckResults = None) -> CheckResults:
    """
    Check if a webhook item has valid content.

    This does not check the context in which the webhook is deployed, such as
    whether any channel reference exists etc.

    :param item:    The webhook item to check.
    :param results: If specified, add results to an existing CheckResults object.
    """

    if not results:
        results = CheckResults()

    # The next couple of checks could be handled by the schema check. We
    # do it here instead because this will produce a much clearer error
    # message for these particular errors
    if not item.get('sourceId'):
        results.errors.append('sourceId is required')
    if not any(item.get(f) for f in ('url', 'channel')):
        results.errors.append('No "channel" or "url" key')
    elif all(item.get(f) for f in ('url', 'channel')):
        results.errors.append('Should not have both "channel" and "url" key')
    else:
        try:
            validate_webhook_schema(item)
        except jsonschema.exceptions.ValidationError as e:
            results.errors.append(e.message)

    if 'url' in item:
        results.warnings.append('"url" key is deprecated - use "channel" instead')

    return results


# ------------------------------------------------------------------------------
def check_webhook_item_context(
    item: dict[str, Any], results: CheckResults = None, aws_session: boto3.Session = None
) -> CheckResults:
    """
    Check the deployment context for a webhook item.

    This does not check that the content is valid (schema compliance etc).
    Instead, it checks that things such as channel references exist, message
    source is valid etc.

    :param item:    The webhook item to check.
    :param results: If specified, add results to an existing CheckResults object.
    :param aws_session: A boto3.Session object.
    """

    if not results:
        results = CheckResults()
    if not aws_session:
        aws_session = boto3.Session()

    if channel := item.get('channel'):
        channels_table = aws_session.resource('dynamodb').Table(CHANNELS_TABLE)
        if channel_spec := get_channel(channel, channels_table):
            if not channel_spec.get('url'):
                results.errors.append(f'Channel "{channel}" has no URL')
        else:
            results.errors.append(f'Channel "{channel}" does not exist')

    # Check that the message source is valid
    source_id = item.get('sourceId', '')
    if source_id.startswith('arn:aws:sns:'):
        sns = aws_session.client('sns')
        if not sns_topic_exists(source_id, sns):
            results.errors.append('No such SNS topic')
        elif not sns_topic_has_slacker_subscription(source_id, sns):
            # Check for a subscription on the topic to slacker Lambda
            results.errors.append('No slacker subscription on topic')
    elif source_id.startswith('logs:'):
        logs = aws_session.client('logs')
        _, log_group_name = source_id.split(':', 1)
        if not log_group_has_slacker_subscription(log_group_name, logs):
            results.errors.append('No subscription filter feeding slacker from log group')

    return results


# ..............................................................................
# region subcommand handlers
# ..............................................................................


# ------------------------------------------------------------------------------
class CliCommand(ABC):
    """ClI command handler."""

    commands: ClassVar[dict[str, type[CliCommand]]] = {}
    name = None  # Set by @register decorator for subclasses.
    help_ = None  # Set by @register from first line of docstring.

    # --------------------------------------------------------------------------
    @classmethod
    def register(cls, name: str) -> Callable:
        """Register a CLI command handler class."""

        def decorate(cmd: type[CliCommand]):
            """Register the command handler class."""
            cmd.name = name
            try:
                cmd.help_ = cmd.__doc__.strip().splitlines()[0]
            except (AttributeError, IndexError):
                raise Exception(f'Class {cmd.__name__} must have a docstring')
            cls.commands[name] = cmd
            return cmd

        return decorate

    # --------------------------------------------------------------------------
    def __init__(self, subparser):
        """Initialize the command handler."""
        self.argp = subparser.add_parser(self.name, help=self.help_)
        self.argp.set_defaults(handler=self)

    # --------------------------------------------------------------------------
    def add_arguments(self):  # noqa B027
        """Add arguments to the command handler."""
        pass

    # --------------------------------------------------------------------------
    @staticmethod  # noqa B027
    def check_arguments(args: Namespace):
        """
        Validate arguments.

        :param args:        The namespace containing the arguments.
        :raise ValueError:  If the arguments are invalid.
        """

        pass

    # --------------------------------------------------------------------------
    @staticmethod
    @abstractmethod
    def execute(args: Namespace) -> None:
        """Execute the CLI command with the specified arguments."""
        raise NotImplementedError('execute')


# ------------------------------------------------------------------------------
@CliCommand.register('list')
class CmdList(CliCommand):
    """List source IDs in the DynamoDB webhooks table."""

    def execute(self, args: Namespace) -> None:
        """List DynamoDB table entries."""
        aws_session = boto3.Session()
        source_ids = (v['sourceId'] for v in dynamo_scan_table(WEBHOOKS_TABLE, aws_session))
        for item in sorted(source_ids):
            print(item)


# ------------------------------------------------------------------------------
@CliCommand.register('dump')
class CmdDump(CliCommand):
    """Dump the DynamoDB webhooks table."""

    def add_arguments(self):
        """Add arguments to the command handler."""

        self.argp.add_argument(
            '-j',
            '--json',
            action='store_true',
            help='Output data in JSON format rather than YAML.',
        )
        self.argp.add_argument(
            'zip_file',
            metavar='file.zip',
            help='Name of ZIP file in which to store webhooks table entries.',
        )

    def execute(self, args: Namespace) -> None:
        """Dump the DynamoDB webhooks table."""
        aws_session = boto3.Session()

        if args.json:
            dumper = partial(json.dumps, indent=4, sort_keys=True, default=json_default)
            suffix = '.json'
        else:
            # Can't use safe_dump here because we want to override the dumper.
            dumper = partial(yaml.dump, default_flow_style=False, Dumper=YamlIndentDumper)
            suffix = '.yaml'

        unsafe_filename_chars = re.compile(r'[^\w:=+-]+')
        filenames = set()
        with ZipFile(args.zip_file, 'w', compresslevel=9) as zf:
            for item in dynamo_scan_table(WEBHOOKS_TABLE, aws_session):
                try:
                    arn = Arn(item['sourceId'])
                    name = f'{arn.service}:{arn.resource}'
                except ValueError:
                    name = item['sourceId']
                name = unsafe_filename_chars.sub('_', name)
                # In case of filename duplicates ...
                while name in filenames:
                    name += '+'
                filenames.add(name)

                try:
                    zf.writestr(
                        f'{name}{suffix}',
                        dumper(item | extra_webhook_fields('json' if args.json else 'yaml')),
                    )
                except Exception as e:
                    raise SlackerError(f'SourceId: {item["sourceId"]}: {e}') from e


# ------------------------------------------------------------------------------
@CliCommand.register('get')
class CmdGet(CliCommand):
    """Fetch an entry from the DynamoDB webhooks table."""

    def add_arguments(self):
        """Add arguments to the command handler."""

        self.argp.add_argument(
            '-j',
            '--json',
            action='store_true',
            help='Output data in JSON format rather than YAML.',
        )
        self.argp.add_argument(
            'source_id',
            metavar='source-id',
            action='store',
            help='Fetch the table entry with the specified source ID.',
        )

    def execute(self, args: Namespace) -> None:
        """Fetch an entry from the DynamoDB webhooks table."""

        aws_session = boto3.Session()
        webhooks_table = aws_session.resource('dynamodb').Table(WEBHOOKS_TABLE)
        response = webhooks_table.get_item(Key={'sourceId': args.source_id})
        if args.json:
            dumper = partial(json.dumps, indent=4, sort_keys=True, default=json_default)
            lexer = JsonLexer()
        else:
            # We deliberately don't use yaml.safe_dump here because we want to
            # override the dumper to fix indenting, and it's not really needed here.
            dumper = partial(yaml.dump, default_flow_style=False, Dumper=YamlIndentDumper)
            lexer = YamlLexer()

        try:
            whook_str = dumper(
                response['Item'] | extra_webhook_fields('json' if args.json else 'yaml')
            ).rstrip('\n')
        except KeyError:
            raise KeyError(f'{args.source_id}: No such item')

        if os.isatty(sys.stdout.fileno()):
            whook_str = highlight(whook_str, lexer, TerminalFormatter())

        print(whook_str)


# ------------------------------------------------------------------------------
@CliCommand.register('put')
class CmdPut(CliCommand):
    """Create / update an entry in the DynamoDB webhooks table."""

    def add_arguments(self):
        """Add arguments to the command handler."""

        self.argp.add_argument(
            '-b',
            '--backup',
            metavar='FILENAME',
            action='store',
            help=(
                'Backup the existing entry in the specified file.'
                ' If the suffix is .json, JSON format is used, otherwise YAML.'
            ),
        )

        self.argp.add_argument(
            '-f',
            '--force',
            action='store_true',
            help=(
                'Force a deployment even if the webhook item has errors. This is '
                ' not a good idea. AWS account number mismatches cannot be forced.'
                ' Thank me later.'
            ),
        )

        self.argp.add_argument(
            '-R',
            '--no-restart',
            dest='restart',
            action='store_false',
            help=(
                'Don\'t restart the slacker Lambda to clear the internal webhook'
                ' cache. By default a restart is done after a successful webhook'
                ' upload. Using this option will result in webhook changes taking'
                ' some minutes to propagate. Use this option when deploying multiple'
                ' webhooks, followed by a final "restart" command.'
            ),
        )

        self.argp.add_argument(
            '-S',
            '--no-strip-schema-keywords',
            dest='strip_schema_keywords',
            action='store_false',
            help=(
                'Don\'t strip schema keywords from the the webhook item before'
                ' uploading. By default, schema keywords starting with "$" are'
                ' removed.'
            ),
        )

        self.argp.add_argument(
            'file',
            action='store',
            help='The name of a YAML or JSON file containing the data for the entry.',
        )

    # --------------------------------------------------------------------------
    @staticmethod
    def _execute(args: Namespace) -> None:
        """Create / update an entry in the DynamoDB webhooks table."""
        aws_session = boto3.Session()
        dynamodb = aws_session.resource('dynamodb')
        webhooks_table = dynamodb.Table(WEBHOOKS_TABLE)
        with open(args.file) as fp:
            item = yaml.safe_load(fp)

        results = check_webhook_item_content(item)
        check_webhook_item_context(item, results=results, aws_session=aws_session)
        for msg in results.warnings:
            warning(msg, file=sys.stderr)
        if results.errors:
            for msg in results.errors:
                error(msg, file=sys.stderr)
            if not args.force:
                raise SlackerError('Errors in webhooks entry')

        try:
            if str(item['account']) != account_id():
                raise SlackerError(
                    f'account={item["account"]} does not match AWS account ID ({account_id()})'
                )
        except KeyError:
            raise SlackerError('Missing "account" key')

        ts = datetime.now().astimezone().replace(microsecond=0)
        with suppress(Exception):
            item['x-slacker'] = f'Updated at {ts.isoformat()} by {getuser()}@{gethostname()}'
        if args.strip_schema_keywords:
            item = {k: v for k, v in item.items() if not k.startswith('$')}
        response = webhooks_table.put_item(Item=item, ReturnValues='ALL_OLD')
        action = 'updated' if 'Attributes' in response else 'created'
        print(f'{item["sourceId"]}: Item {action}')
        if args.backup and action == 'updated':
            dumper = (
                partial(json.dump, indent=4, sort_keys=True, default=json_default)
                if args.backup.endswith('.json')
                else partial(yaml.dump, default_flow_style=False, Dumper=YamlIndentDumper)
            )
            with open(args.backup, 'w') as fp:
                dumper(response['Attributes'], fp)
            print(f'{response["Attributes"]["sourceId"]}: Previous data stored in {args.backup}')

            if args.restart:
                lambda_restart(SLACKER_APP_NAME)
                print(f'{SLACKER_APP_NAME} restarted')

    # --------------------------------------------------------------------------
    def execute(self, args: Namespace) -> None:
        """Create / update an entry in the DynamoDB webhooks table."""

        try:
            self._execute(args)
        except Exception as e:
            raise SlackerError(f'{args.file}: {e}') from e


# ------------------------------------------------------------------------------
@CliCommand.register('test')
class CmdTest(CliCommand):
    """Test a message for processing against a webhooks entry."""

    def add_arguments(self):
        """Add arguments to the command handler."""

        self.argp.add_argument(
            'file',
            action='store',
            help='The name of a YAML or JSON file containing the data for the webhooks entry.',
        )

    @staticmethod
    def _execute(args: Namespace) -> None:
        """Test a message for processing against a webhooks entry."""
        with open(args.file) as fp:
            item = yaml.safe_load(fp)

        results = check_webhook_item_content(item)
        for msg in results.warnings:
            warning(msg, file=sys.stderr)
        if results.errors:
            for msg in results.errors:
                error(msg, file=sys.stderr)
            raise SlackerError('Errors in webhooks entry')

        msg_text = sys.stdin.read()
        msg = SlackerMsg(
            source_id=item['sourceId'], source_name='...', subject='Test', text=msg_text
        )
        process_msg_rules(msg, item.get('rules', []))
        if msg.text:
            print(msg.text)

    def execute(self, args: Namespace) -> None:
        """Test a message for processing against a webhooks entry."""

        try:
            self._execute(args)
        except Exception as e:
            raise SlackerError(f'{args.file}: {e}') from e


# ------------------------------------------------------------------------------
@CliCommand.register('check')
class CmdCheck(CliCommand):
    """
    Check slacker configuration.

    .. warning::
        This assumes everything is in a single account and region. i.e. SNS topic
        in one region is not feeding messages to a slacker instance in a different
        region.
    """

    def __init__(self, *args, **kwargs):
        """Initialize the check."""

        super().__init__(*args, **kwargs)
        self.aws_session = None
        self.webhooks_table = None
        self.ebridge = None
        self.slacker_arn = None

    def execute(self, args: Namespace) -> None:
        """Check slacker configuration."""

        self.aws_session = boto3.Session()
        dynamodb = self.aws_session.resource('dynamodb')
        self.ebridge = self.aws_session.client('events')
        self.slacker_arn = (
            f'arn:aws:lambda:{region_name()}:{account_id()}:function:{SLACKER_APP_NAME}'
        )
        self.webhooks_table = dynamodb.Table(WEBHOOKS_TABLE)

        self.check_webhooks()
        self.check_sns_subscriptions()
        self.check_event_rules()

    def check_sns_subscriptions(self) -> None:
        """
        Check SNS subscriptions to the slacker Lambda are ok.

        We're looking for things such as active subscriptions without a
        corresponding webhook, subscriptions for which the topic is missing etc.
        """

        heading('Checking SNS subscriptions...')
        sns = self.aws_session.client('sns')
        paginator = sns.get_paginator('list_subscriptions')
        for response in paginator.paginate():
            # Note that the SubscriptionArn will be something like 'PendingConfirmation'
            # if still pending -- not interested in those.
            for subscription in response['Subscriptions']:
                topic_arn = subscription['TopicArn']
                if (
                    subscription['Protocol'] != 'lambda'
                    or not subscription['Endpoint'].endswith(f':function:{SLACKER_APP_NAME}')
                    or not subscription['SubscriptionArn'].startswith('arn:')
                ):
                    continue

                if webhook := get_webhook(topic_arn, self.webhooks_table):
                    webhook_enabled = webhook.get('enabled', True)
                else:
                    webhook_enabled = False

                topic_exists = sns_topic_exists(topic_arn, sns)
                match (topic_exists, webhook_enabled):
                    case (True, True):
                        info(f'{topic_arn}: OK')
                    case (False, True):
                        warning(f'{topic_arn}: Orphan SNS subscription and enabled webhooks entry')
                    case (True, False):
                        # No webhook for this source. Maybe there is a wildcard
                        wildcard_webhook = get_webhook(WILDCARD_SOURCE_ID, self.webhooks_table)
                        if wildcard_webhook:
                            info(f'{topic_arn}: Relying on wildcard webhook')
                        else:
                            error(f'{topic_arn}: Webhooks entry is missing or disabled')
                    case (False, False):
                        warning(f'{topic_arn}: Orphan SNS subscription')
        print()

    def check_webhooks(self):
        """Check basic hygiene on webhooks."""

        heading('Checking webhooks...')
        for item in self.webhooks_table.scan(Select='ALL_ATTRIBUTES').get('Items', []):
            # Check some basic hygiene
            source_id = item['sourceId']
            results = check_webhook_item_content(item)
            check_webhook_item_context(item, results=results, aws_session=self.aws_session)

            for msg in results.warnings:
                warning(f'{source_id}: {msg}')
            for msg in results.errors:
                error(f'{source_id}: {msg}')
        print()

    def check_event_rules(self):
        """Check EventBridge rules."""

        paginator = self.ebridge.get_paginator('list_rule_names_by_target')
        heading('Checking EventBridge rules...')
        for response in paginator.paginate(TargetArn=self.slacker_arn):
            for rule_name in response.get('RuleNames', []):
                # Check SlackerSourceId / SlackerSourceName present in input templates
                rule_ok = True
                for (
                    target_id,
                    source_id,
                    source_name,
                ) in self.get_source_info_from_event_bridge_rule(rule_name):
                    if not source_id:
                        rule_ok = False
                        error(f'Rule {rule_name}: Target {target_id}: SlackerSourceId missing')
                    if not source_name:
                        rule_ok = False
                        warning(f'Rule {rule_name}: Target {target_id}: SlackerSourceName missing')
                if rule_ok:
                    info(f'Rule {rule_name}: OK')

    def get_source_info_from_event_bridge_rule(
        self, rule_name: str
    ) -> Iterator[tuple[str, str, str]]:
        """
        Get the source id / name slacker will see for a given EventBridge rule.

        This can only handle objects with an input transformer and we are
        looking for the `SlackerSourceId` and `SlackerSourceName` fields in the
        input template. We can't know their values until runtime but we can see
        if they are present.

        There is a bit of a heuristic here in that we cannot full determine this
        until runtime but this will be pretty close except for some very rare
        edge cases.

        :return:    A tuple (target ID, SlackerSourceId, SlackerSourceName) for
                    each target pointed at slacker.
        """

        paginator = self.ebridge.get_paginator('list_targets_by_rule')
        for response in paginator.paginate(Rule=rule_name):
            for target in response.get('Targets', []):
                if target.get('Arn') != self.slacker_arn:
                    continue

                template_s = target.get('InputTransformer', {}).get('InputTemplate')
                if not template_s:
                    continue

                try:
                    template = json.loads(template_s)
                except json.JSONDecodeError:
                    error(f'{rule_name}: Target {target["Id"]}: Invalid JSON template')
                    continue
                yield target['Id'], template.get('SlackerSourceId'), template.get(
                    'SlackerSourceName'
                )


# ------------------------------------------------------------------------------
@CliCommand.register('restart')
class CmdRestart(CliCommand):
    """
    Restart the slacker Lambda.

    This is done by updating an environment variable on the Lambda. It can be
    useful when you need to flush the table caches.
    """

    def execute(self, args: Namespace) -> None:
        """Restart the Lambda."""

        lambda_restart(SLACKER_APP_NAME)


# ..............................................................................
# endregion subcommand handlers
# ..............................................................................


# ------------------------------------------------------------------------------
def process_cli_args() -> argparse.Namespace:
    """Process the command line arguments."""

    argp = ArgumentParser(
        prog=PROG, description=__doc__, epilog=f'Full user guide at {SLACKER_DOC_URL}'
    )

    argp.add_argument(
        '-v',
        '--version',
        action='version',
        version=slacker.version.__version__,
        help='Show version and exit.',
    )

    # Add the sub-commonads
    subp = argp.add_subparsers(required=True)
    for cmd in sorted(CliCommand.commands.values(), key=lambda c: c.name):
        cmd(subp).add_arguments()

    args = argp.parse_args()

    try:
        args.handler.check_arguments(args)
    except ValueError as e:
        argp.error(str(e))

    return args


# ------------------------------------------------------------------------------
def main() -> int:
    """Show time."""
    try:
        args = process_cli_args()
        args.handler.execute(args)
        return 0
    except Exception as ex:
        # Uncomment for debugging
        # raise  # noqa: ERA001
        print(ex, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('Interrupt', file=sys.stderr)
        return 2


# ------------------------------------------------------------------------------
# This only gets used during dev/test. Once deployed as a package, main() gets
# imported and run directly.
if __name__ == '__main__':
    exit(main())
