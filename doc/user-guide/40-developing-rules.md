
# Developing and Testing Message Rules { x-nav="Developing Message Rules" }

## Developing Rules

!!! tip "Tips"
    1.  When developing rules to handle a particular message type, the first
        step is to obtain real samples of the message. A good way to do this is
        to let slacker capture some initial events without any transformation.
        These are handy for developing and testing rules.

    2.  With careful use of the [wildcard webhook](#the-wildcard-webhook), the
        need to create new webhooks and rules can be minimised.

The recommended approach to developing rules is to write the [webhooks
table](#the-webhooks-table) entries in YAML, under version control, and then
test and deploy them with the [slacker CLI](#the-slacker-cli).

The webhook entry file can either be an existing entry that has been extracted
from DynamoDB using `slacker get`, and then modified, or one created from
scratch.

JSON schema definitions are provided for [webhooks](#the-webhooks-table) and
[channels](#the-channels-table) entries. This can make creating entries a lot
easier in IDEs that support these (like the JetBrains suite), particularly for
webhooks.

The definitions are available at:

=== "Latest"
    ```text
    https://jin-gizmo.github.io/slacker/schemas/latest/channel.schema.json
    https://jin-gizmo.github.io/slacker/schemas/latest/webhook.schema.json
    ```

=== "Versioned"
    ```text
    https://jin-gizmo.github.io/slacker/schemas/v2/channel.schema.json
    https://jin-gizmo.github.io/slacker/schemas/v2/webhook.schema.json
    ```

These schemas are referenced in the entries like so:

```yaml
$schema: https://jin-gizmo.github.io/slacker/schemas/latest/webhook.schema.json
```

!!! note
    The slacker Lambda itself does not use the JSON schema for validation. It
    will do its best to work with an entry with minimal judgement. The `test`
    and `check` subcommands on the slacker CLI do perform schema validation.

## Testing Rules

The [slacker CLI](#the-slacker-cli) provides the `test` subcommand that
facilitates the process of experimenting with rules and messages to see how they
will be treated. Usage is:

```bash
slacker test webhook-entry.yaml < message.txt
# ... or ...
slacker test webhook-entry.yaml < message.json
```

This will apply exactly the same processing to the test message as the slacker
Lambda will, showing the resulting message that will be sent, if any.
Additionally, full schema validation of the webhook entry will be performed.

The message file will contain *the actual message text that is sent* (which
slacker will decode as JSON if it can).

For messages arriving via SNS, this does not include all of the delivery
wrapping in which SNS embeds the message.  The `slacker test` subcommand
requires the value of the `message` key from the SNS message, not the whole
envelope.  The `message` field may be either a text message or an object if
slacker has decoded a JSON blob.

## Deploying Rules

The [slacker CLI](#the-slacker-cli) provides the `put` subcommand that deploys
webhook entries to the [webhooks table](#the-webhooks-table). The following
checks are made prior to upload:

*   The AWS account number in the entry must match the target environment.
*   A full schema verification of the webhook contents will be done.

Usage is:

```bash
slacker put webhook-entry.yaml

# To keep a backup of the previous entry...
slacker put --backup webhook-entry-orig.yaml webhook-entry.yaml
```

!!! note "Notes"
    1.  Slacker caches webhook entries for 5 minutes. Table updates can take
        this amount of time to become effective. The duration can be changed by
        setting the [`SLACKER_CACHE_TTL`](#slacker-lambda-environment-variables)
        environment variable. The `slacker restart` command can be used to
        flush the caches.
    2.  The DynamoDB tables have point-in-time recovery enabled, just in case.

## Validating Webhook Entries

The [slacker CLI](#the-slacker-cli) is the primary tool for managing slacker
table entries. It has a `check` subcommand that will perform a basic suite of
configuration hygiene checks, looking for problems such as:

*   Schema violations
*   Webhooks that have odd combinations of `url` and `channel` keys
*   Webhooks that reference channels that don't exist
*   Webhooks with a `sourceId` that points to a resource that either doesn't
    exist or isn't configured to send messages to slacker
*   Unknown `sourceId` types
*   SNS subscriptions to the slacker Lambda where either the SNS topic doesn't
    exist or the corresponding webhook doesn't exist.

```bash
slacker check
```
