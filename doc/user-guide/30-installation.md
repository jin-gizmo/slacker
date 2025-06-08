
# Installation and Usage

## Prerequisites

Python 3.11+ is required for the [slacker CLI](#the-slacker-cli). The slacker
Lambda function uses the Python 3.13 runtime.

The AWS components (slacker Lambda function, DynamoDB tables etc) are installed
from the repo using [AWS SAM](https://aws.amazon.com/serverless/sam/). This will
need to be
[installed](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html)
first.

SAM is not required for the slacker CLI.

!!! note "Editorial"
    AWS SAM used to be installable from PyPI. It may be still, but AWS doesn't
    seem to support it. The rest of the world seem to manage OK(-ish) with PyPI
    for far more complex packages than SAM.  ¯\_(ツ)_/¯

## Installing the Slacker AWS Components { data-toc-label="AWS Components" }

With AWS SAM installed, the installation / update process for slacker is as
follows:

```bash
# Clone the repo and prepare the working area (create virtualenv etc)
git clone git@github.com:jin-gizmo/slacker.git
cd slacker
make init

# Activate the venv
source venv/bin/activate

# Do a guided install.
make install
```

!!! note
    Slacker can be deployed in as many AWS regions and accounts as required.

!!! info
    The CloudFormation stack name should be left as `slacker`, if at all
    possible. This affects the naming of the Lambda function and the DynamoDB
    tables, among other things.

### Slacker Lambda Configuration Parameters { data-toc-label="Configuration Parameters" }

The guided install process prompts for any required configuration values. The
defaults should be fine in most cases but this is what the less obvious ones
relating to the CloudFormation stack mean:

|Parameter|Description|
|-|-|
|defaultSideBarColour|Slack messages will have a colour bar displayed down the left margin specified by the value of this field unless overridden for a given source ID in the [webhooks table](#the-webhooks-table). This can be any hex colour code (prefixed with `#`), or one of the Slack special values `good`, `warning`, or `danger`. This parameter sets the `SLACKER_COLOUR` [environment variable](#slacker-lambda-environment-variables) for the Lambda function.|
|dynamoDbReadCapacity|Read capacity units for the DynamoDB table. The default is 5. While this seems quite low, it should be adequate in most environments as a result of caching in the slacker Lambda.|
|maxMessageLen|The maximum length in bytes of messages sent to Slacker. Longer messages are truncated. This parameter sets the `SLACKER_MSG_LEN` [environment variable](#slacker-lambda-environment-variables) for the Lambda function.|

Other stack parameters are self-explanatory.

### Logging

If slacker is configured to log messages in CloudWatch, the log entries look
like this:

```json
{
  "message": "...",
  "sourceId": "arn:aws:sns:us-east-1:...",
  "sourceName": "SNS:...",
  "subject": "Whatever",
  "timestamp": 1749106337.055,
  "type": "incoming"
}
```

### Slacker Lambda Environment Variables { data-toc-label="Environment Variables" }

The slacker Lambda supports the following environment variables.

|Name|Description|Default|
|-|-|-|
|LOGLEVEL|One of the standard Python logging levels (`debug`, `info`, ...).|`info`|
|LOG_MESSAGES|If set to `1`, log messages to CloudWatch prior to processing.|`0`|
|SLACKER_COLOUR|The default colour for the bar on the left hand margin of messages sent to Slack unless overridden for a given source ID in the [webhooks table](#the-webhooks-table). This can be any hex colour code or one of the Slack special values `good`, `warning` or `danger`.|`#bbbbbb`|
|SLACKER_MSG_LEN|The maximum length in bytes of messages sent to Slacker. Longer messages are truncated.|4000|
|SLACKER_CACHE_TTL|Number of seconds to cache lookups from the DynamoDB tables.|300|

## The Slacker CLI { data-toc-label="Slacker CLI" }

The [slacker CLI](#the-slacker-cli) is installed with pip:

```bash
pip install jinslacker
slacker --help
```
It can also be built from the repo:

```bash
# Output is in dist/pkg directory
make pkg
```

### Slacker CLI Environment Variables { data-toc-label="Environment Variables" }

The slacker CLI supports the following environment variables.

| Name             | Description                          | Default   |
|------------------|--------------------------------------|-----------|
| SLACKER_APP_NAME | Name of the slacker Lambda function. | `slacker` |

### CLI Usage

??? "Command Usage"
    ```text
    usage: slacker [-h] [-v] {check,dump,get,list,put,restart,test} ...

    Manage slacker webhooks and rules.

    positional arguments:
      {check,dump,get,list,put,restart,test}
        check           Check slacker configuration.
        dump            Dump the DynamoDB webhooks table.
        get             Fetch an entry from the DynamoDB webhooks table.
        list            List source IDs in the DynamoDB webhooks table.
        put             Create / update an entry in the DynamoDB webhooks table.
        restart         Restart the slacker Lambda.
        test            Test a message for processing against a webhooks entry.

    options:
      -h, --help        show this help message and exit
      -v, --version     Show version and exit.

    Full user guide at https://jin-gizmo.github.io/slacker
    ```

Typical usage might be something like this:

```bash
# Get help
slacker --help
# Get help on a subcommand
slacker list --help

# List webhooks table source IDs
slacker list

# Download one. Note that this will populate the `account` field in the
# downloaded webhook data.
slacker get my-source-id > my-source-id.yaml

# Test out the rules in a webhook file to see what they do to a message.
slacker test my-source-id.yaml < message.txt

# Upload the webhooks entry back to DynamoDB but keep a backup of the original
slacker put --backup my-source-id-orig.yaml my-source-id.yaml

# Backup all webhooks to a zip file
slacker dump webhooks.zip
```

## Adding Message Sources

Slacker supports messages received from:

*   [Amazon SNS](#amazon-sns)
*   [CloudWatch Logs](#cloudwatch-logs)
*   [Amazon EventBridge](#amazon-eventbridge)
*   [Direct invocation](#direct-invocation) of the slacker Lambda.

!!! tip
    It is often easier to use the AWS Lambda console, rather than the console
    for the originating service when setting up Lambda triggers. The former
    seems to get the permissions correct more consistently. IMO.

### Amazon SNS

To add an SNS topic as a slacker message source:

1.  Create the SNS topic, if necessary, and get the topic ARN.
2.  Add the topic ARN as a trigger to the slacker Lambda.
3.  Create a new entry in the [webhooks table](#the-webhooks-table) with the
    `sourceId` set to the topic ARN, and whatever destination Slack channel and
    [rules](#message-rules) are appropriate.

### CloudWatch Logs

To add a CloudWatch Log group as a slacker message source:

1.  Create the log group, if necessary.
2.  Add a [subscription filter](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/SubscriptionFilters.html)
    to the log group. You can either add filtering at the log group level or in
    the slacker rules. Note that CloudWatch only permits two subscription filters
    per log group, which may limit your options.
3.  Create a new entry in the [webhooks table](#the-webhooks-table) with the
    `sourceId` set to the log group name prefixed with `logs:`, and whatever
    rules and destination Slack channel and [rules](#message-rules) are
    appropriate.

!!! warning
    **Do not** connect the slacker Lambda log group `/aws/lambda/slacker` as a
    slacker message source. Trust me on this, do not cross the streams.

### Amazon EventBridge

Slacker can receive messages from Amazon EventBridge either directly, or via
SNS. The target(s) for the EventBridge rule determine the path.

#### EventBridge Rule Targets without Input Transformation

If the EventBridge input message is to be sent to Slacker as-is (without an
input transformation), it can either be sent directly with the slacker Lambda as
a rule target, or via SNS. In the former case, slacker will use the message
`source` attribute as the `sourceId` to lookup in the [webhooks
table](#the-webhooks-table). In the latter case, it uses the topic ARN as the
`sourceId`.

#### EventBridge Rule Targets with Input Transformation

If the EventBridge rule is using an input transformation to create a new
message, it can be sent to slacker via SNS. Messages received by slacker from
SNS use the topic ARN as the `sourceId` to lookup in the [webhooks
table](#the-webhooks-table).

Alternatively, an EventBridge rule with an input transformation can send a
custom object directly to the slacker Lambda. In this case, slacker needs to
know which webhooks entry to apply. The input template should include the
following fields in the custom object for this purpose:

| Name | Required | Type | String |
|-|-|-|-|
|SlackerSourceId|Yes|String|The slacker `sourceId`. This is used as the key into the [webhooks table](#the-webhooks-table) to obtain the appropriate webhooks entry.|
|SlackerSourceName|No|String|A human readable description for the source. Defaults to the `SlackerSourceId`.|

Refer to the
[AWS documentation](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-transform-target-input.html)
for more information.

### Direct Invocation

Object messages can be sent directly to the slacker Lambda. The message should
include the following fields for this purpose:

| Name | Required | Type | String |
|-|-|-|-|
|SlackerSourceId|Yes|String|The slacker `sourceId`. This is used as the key into the [webhooks table](#the-webhooks-table) to obtain the appropriate webhooks entry.|
|SlackerSourceName|No|String|A human readable description for the source. Defaults to the `SlackerSourceId`.|

This example shows how to do it using the AWS CLI:

```bash
aws lambda invoke --function-name slacker response.json \
    --cli-binary-format raw-in-base64-out \
    --payload '
{
    "SlackerSourceId": "my-source-id",
    "SlackerSourceName": "My App",
    "more": "data",
    "...": "..."
}'
```
