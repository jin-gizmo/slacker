## General Purpose Rules

??? "JSON Formatting"

    Lot's of AWS events show up in (densely packed) JSON format. A handy rule of
    last resort simply formats the JSON nicely before passing it to Slack.

    This rule should generally go low in the rules list. It will not touch
    messages that are not JSON.


    === "Message"
        ```json
        {"a": "alpha", "c": "gamma", "b": "beta", "...":["d", "e", "etc"]}
        ```

    === "Rule"
        ```yaml
        rules:
          - '#': Pretty print messages consisting of JSON
            template: |
              ```
              {{ data | tojson(4) }}
              ```
        ```

    === "Result"
        ![](img/samples/json.png)

??? "Wildcard Webhook Rules"

    The [wildcard webhook](#the-wildcard-webhook) is a special purpose
    [webhooks table](#the-webhooks-table) entry with a `sourceId` of `*`. Any rules
    in the wildcard webhook are implicitly added to the end of the rules list for
    all other webhooks. It is a good place for common rules that would otherwise
    need to be duplicated in individual webhooks.

    The following sample can be modified as needed.

    === "Rule"
        ```yaml
        sourceId: '*'
        rules:
          - '#': AWS Health Event
            if: "{{ data['detail-type'] == 'AWS Health Event' }}"
            template: >-
              {% set icons = {
                 'scheduledChange': ':calendar:',
                 'issue': ':zap:',
                 'accountNotification': ':information_source:',
                 'investigation': ':magnifying_glass_right:',
               } %}
              {%- set sep=':black_small_square:' -%}
              {{ icons.get(data.detail.eventTypeCategory, ':large_purple_circle:') }}
              *{{ data.detail.eventTypeCode }}*
              {{ sep }}
              {{ data.detail.eventTypeCategory }}

              *{{ data.detail.startTime }} ... {{ data.detail.endTime }}*

              {% if data.resources -%}
              ```

              {% for resource in data.resources %}
              * {{ resource }}

              {% endfor -%}
              ```
              {% endif %}

              {{ (data.detail.eventDescription | first).latestDescription | replace('\\n', '\n')  }}

          - '#': CloudWatch Alarm ON
            if: "{{ data.NewStateValue == 'ALARM' }}"
            colour: '#ff0000'
            preamble: <!channel>
            template: >
              {%- set sep=':black_small_square:' -%}
              {%- set desc=(data.AlarmDescription or data.AlarmName or '?').splitlines() -%}

              :red_circle:
              *{{ desc[0].strip() }}*
              {{ sep }}
              {{ data.StateChangeTime.split('.')[0] }}Z
              {%- if desc | length > 1 %}


              {{ data.AlarmDescription }}{%endif %}


              _{{ data.NewStateReason }}_

          - '#': CloudWatch Alarm OFF
            if: "{{ data.NewStateValue == 'OK' }}"
            colour: '#00ff00'
            template: >
              {%- set sep=':black_small_square:' -%}
              {%- set desc=(data.AlarmDescription or data.AlarmName or '?').splitlines() -%}

              :white_check_mark:
              *{{ desc[0].strip() }}*
              {{ sep }}
              {{ data.StateChangeTime.split('.')[0] }}Z

          - '#': Pretty print messages consisting of JSON
            template: |
              ```
              {{ data | tojson(4) }}
              ```
        ```
