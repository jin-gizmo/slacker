
# Release Notes

## Version 2

#### Version 2.6.0

This version is functionally compatible with v2.5 insofar as the main code is
concerned. A number of incremental functional enhancements have been made.
Changes have also been made to elements of packaging, deployment and
documentation.

Changes are:

*   Slacker now supports direct messages from Amazon EventBridge as well as
    direct invocation of the slacker Lambda.

*   Introduced the [wildcard webhook](#the-wildcard-webhook). This serves two
    purposes:

    1.  **Webhook of last resort:** If an incoming message has a source ID that
        doesn't match any entry in the [webhooks table](#the-webhooks-table),
        the wildcard webhook is used to process the message.
    2.  **Container for common webhook rules:** Any rules in the wildcard webhook
        are implicitly appended to the rules of all other webhooks.

*   The following changes have been made to the [slacker CLI](#the-slacker-cli):

    *   The `slacker check` command now does full schema validation on
        [webhooks](#the-webhooks-table) items.
        See [Testing Rules](#testing-rules) for more information.
    *   The `slacker get` command now does syntax colouring when the output is
        to a terminal.
    *   The `slacker restart` command has been added to restart the slacker
        Lambda. This will clear the caches holding DynamoDB entries.

*   AWS SAM is now used for installation, rather than raw CloudFormation. Not
    totally convinced that's a real step forward but it's done.

*   Some extra information, examples and the elementary
    [rule library](#rule-library), have been added into this user guide.
    Contributions welcome.

*   JSON schema definitions are now provided for [webhooks](#the-webhooks-table)
    and [channels](#the-channels-table) entries. This can make creating entries
    a lot easier in IDEs that support these (like the JetBrains suite).
