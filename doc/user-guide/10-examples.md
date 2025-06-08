# Examples

!!! note
    Examples are shown in YAML format for simplicity and because this is the
    preferred format when using the [slacker CLI](#the-slacker-cli).

!!! tip
    See also [Rule Library](#rule-library) for some real-world reusable rules.

The simplest possible [webhooks table](#the-webhooks-table) item is like so:

```yaml
account: '123456789012'
channel: channels-table-reference
sourceId: 'arn:aws:sns:us-east-1:123456789012:my-topic'
```

This will pass all incoming messages on the specified SNS topic to the specified
Slack channel, unmodified.

Slacker gets more useful with the addition of [message rules](#message-rules) to
filter or transform incoming messages. The following examples relate to the
`rules` list attribute in [webhooks table](#the-webhooks-table) items.

## Text Message Examples { data-toc-label="Text Messages" }

Consider the following **text message**:

```text
ERROR: The wheels have fallen off 3 little red wagons
```

The following rule set would force the message to be discarded (dropped):

```yaml
account: ...
channel: ...
sourceId: ...
rules:
  - '#': Comment -- ignored
    match: '^ERROR:.*wagons$'
    action: drop
```

The following rule set would:

*   Discard messages about a small number of wagons suffering wheels detaching.
*   Add different colour bars for more severe wheel loss on red and blue wagons
    but send the message unmodified. Messages about blue wagons will be diverted
    to a different Slack channel.
*   Send a custom message for severe wheel loss on other coloured wagons.

```yaml
account: ...
channel: ...
sourceId: ...
rules:
  - match: '^ERROR:.* fallen off (?P<count>[0-9]+) little [a-z]+ wagons'
    if: '{{ data.count | int < 4 }}'
    action: drop
  - '#': This rule only reached for matching messages with wagon count >= 4
    match: '^ERROR:.* fallen off [0-9]+ little (?P<colour>[a-z]+) wagons'
    if: '{{ data.colour == "red" }}'
    colour: '#ff0000'
    action: send
  - '#': This rule for blue wagons has an implicit send action
    match: '^ERROR:.* fallen off [0-9]+ little (?P<colour>[a-z]+) wagons'
    if: '{{ data.colour == "blue" }}'
    colour: '#0000ff'
    channel: still-got-the-blues
  - '#': This rule produces a custom message for odd colour wagons
    match: '^ERROR:.* fallen off (?P<count>[0-9]+) little (?P<colour>[a-z]+) wagons'
    template: |
      WANTED: {{ data.count }} {{ data.colour }} wagons with wheels

```

## Object Message Examples { data-toc-label="Object Messages" }

Consider the following message indicating the number, and colour, of wagons for
which a wheel has fallen off.

```text
{ "event": "wheels off", "count": 3, "wagon_colour": "red" }
```

This will be received by slacker as a string but will will be JSON decoded to
an object.

The following rule set would force the message above to be discarded:

```yaml
account: ...
channel: ...
sourceId: ...
rules:
  - '#': Comment -- ignored
    if: '{{ event == "wheels off" and count | int < 4 }}'
    action: drop
```

The following rule set would:

*   Discard messages about a small number of wagons suffering wheels detaching.
*   Add different colour bars for more severe wheel loss on red and blue wagons
    but send the message unmodified. Messages about blue wagons will be diverted
    to a different Slack channel.
*   Send a custom message for severe wheel loss on other coloured wagons.

```yaml
account: ...
channel: ...
sourceId: ...
rules:
  - if: '{{ data.event == "wheels off" and data.count | int < 4 }}'
    action: drop
  - '#': This rule only reached for matching messages with wagon count >= 4
    if: '{{ data.event == "wheels off" and data.colour == "red" }}'
    colour: '#ff0000'
    action: send
  - '#': This rule for blue wagons has an implicit send action
    if: '{{ data.event == "wheels off" and data.colour == "blue" }}'
    colour: '#0000ff'
    channel: still-got-the-blues
  - '#': This rule produces a custom message for odd colour wagons
    if: '{{ data.event == "wheels off" }}'
    template: |
      WANTED: {{ data.count }} {{ data.colour }} wagons with wheels
```

The following rule set would format **object messages** nicely and pass other
messages through unchanged.

```yaml
account: ...
channel: ...
sourceId: ...
rules:
  - template: |
      ```
      {{ data | tojson(4) }}
      ```

```

The following rule set would discard messages sent between 5pm and 6pm Sydney time:

```yaml
account: ...
channel: ...
sourceId: ...
rules:
  - if: '{{ "17:00:00" <= current_time("Australia/Sydney") <= "18:00:00" }}'
    action: drop

```
