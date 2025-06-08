
## CloudWatch Alarms

A core use case for slacker is to reformat CloudWatch alarm messages delivered
via SNS into something readable.

Some alarms will naturally be sent to a paging service, but it's almost always
worth mirroring them in Slack. Also, a lot of alarms reveal something
interesting about the environment without being serious enough to page someone.

??? "CloudWatch Generic Alarm On"

    === "Message"
        ```json
        {
          "AlarmName": "my-sqs-queue-depth",
          "AlarmDescription": "Too many messages queued for my-sqs-queue",
          "AWSAccountId": "123456789012",
          "AlarmConfigurationUpdatedTimestamp": "2023-04-19T05:17:32.984+0000",
          "NewStateValue": "ALARM",
          "NewStateReason": "Threshold Crossed: 30 out of the last 30 datapoints were greater than the threshold (20.0). The most recent datapoints which crossed the threshold: [60.0 (06/12/24 05:34:00), 60.0 (06/12/24 05:33:00), 59.0 (06/12/24 05:32:00), 59.0 (06/12/24 05:31:00), 59.0 (06/12/24 05:30:00)] (minimum 30 datapoints for OK -> ALARM transition).",
          "StateChangeTime": "2024-12-06T05:36:35.649+0000",
          "Region": "Asia Pacific (Sydney)",
          "AlarmArn": "arn:aws:cloudwatch:ap-southeast-2:123456789012:alarm:my-sqs-queue-queue-depth",
          "OldStateValue": "OK",
          "OKActions": [
            "arn:aws:sns:ap-southeast-2:123456789012:slacker-demo"
          ],
          "AlarmActions": [
            "arn:aws:sns:ap-southeast-2:123456789012:slacker-demo"
          ],
          "InsufficientDataActions": [],
          "Trigger": {
            "MetricName": "ApproximateNumberOfMessagesVisible",
            "Namespace": "AWS/SQS",
            "StatisticType": "Statistic",
            "Statistic": "MAXIMUM",
            "Unit": null,
            "Dimensions": [
              {
                "value": "my-sqs-queue",
                "name": "QueueName"
              }
            ],
            "Period": 60,
            "EvaluationPeriods": 30,
            "DatapointsToAlarm": 30,
            "ComparisonOperator": "GreaterThanThreshold",
            "Threshold": 20.0,
            "TreatMissingData": "ignore",
            "EvaluateLowSampleCountPercentile": ""
          }
        }
        ```

    === "Rule"
        ```yaml
        rules:
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
        ```

    === "Result"
        ![](img/samples/cwatch-metric-alarm-on.png)


??? "CloudWatch Generic Alarm Off"

    === "Message"
        ```json
        {
          "AlarmName": "my-sqs-queue-depth",
          "AlarmDescription": "Too many messages queued for my-sqs-queue",
          "AWSAccountId": "123456789012",
          "AlarmConfigurationUpdatedTimestamp": "2024-11-19T23:16:17.097+0000",
          "NewStateValue": "OK",
          "NewStateReason": "Threshold Crossed: 1 out of the last 50 datapoints [48.0 (04/12/24 00:34:00)] was not greater than the threshold (50.0) (minimum 1 datapoint for ALARM -> OK transition).",
          "StateChangeTime": "2024-12-04T00:36:01.796+0000",
          "Region": "Asia Pacific (Sydney)",
          "AlarmArn": "arn:aws:cloudwatch:ap-southeast-2:123456789012:alarm:my-sqs-queue-queue-depth",
          "OldStateValue": "ALARM",
          "OKActions": [
            "arn:aws:sns:ap-southeast-2:123456789012:slacker-demo"
          ],
          "AlarmActions": [
            "arn:aws:sns:ap-southeast-2:123456789012:slacker-demo"
          ],
          "InsufficientDataActions": [],
          "Trigger": {
            "MetricName": "ApproximateNumberOfMessagesVisible",
            "Namespace": "AWS/SQS",
            "StatisticType": "Statistic",
            "Statistic": "MAXIMUM",
            "Unit": null,
            "Dimensions": [
              {
                "value": "my-sqs-queue",
                "name": "QueueName"
              }
            ],
            "Period": 60,
            "EvaluationPeriods": 50,
            "DatapointsToAlarm": 50,
            "ComparisonOperator": "GreaterThanThreshold",
            "Threshold": 50.0,
            "TreatMissingData": "ignore",
            "EvaluateLowSampleCountPercentile": ""
          }
        }
        ```

    === "Rule"
        ```yaml
        rules:
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
        ```

    === "Result"
        ![](img/samples/cwatch-metric-alarm-off.png)

??? "CloudWatch API Gateway Alarm On"

    This variant on the generic CloudWatch alarm is specific to API Gateway
    related alarms. It needs to be placed earlier in the rules than the generic
    CloudWatch alarm rule.

    === "Message"
        ```json
        {
          "AlarmName": "my-portal-api-4XX-error",
          "AlarmDescription": "Api gateway my-portal-api 4XX error more than 50 for 10 minutes. Observation required. More information: https://jin-gizmo.github.io",
          "AWSAccountId": "123456789012",
          "AlarmConfigurationUpdatedTimestamp": "2024-04-18T00:31:54.519+0000",
          "NewStateValue": "ALARM",
          "NewStateReason": "Threshold Crossed: 2 out of the last 2 datapoints [63.0 (11/12/24 06:04:00), 66.0 (11/12/24 05:59:00)] were greater than the threshold (50.0) (minimum 2 datapoints for OK -> ALARM transition).",
          "StateChangeTime": "2024-12-11T06:09:47.192+0000",
          "Region": "Asia Pacific (Sydney)",
          "AlarmArn": "arn:aws:cloudwatch:ap-southeast-2:123456789012:alarm:my-portal-api-4XX-error",
          "OldStateValue": "OK",
          "OKActions": [],
          "AlarmActions": [
            "arn:aws:sns:ap-southeast-2:123456789012:slacker-demo"
          ],
          "InsufficientDataActions": [],
          "Trigger": {
            "MetricName": "4XXError",
            "Namespace": "AWS/ApiGateway",
            "StatisticType": "Statistic",
            "Statistic": "SUM",
            "Unit": null,
            "Dimensions": [
              {
                "value": "my-portal-api",
                "name": "ApiName"
              }
            ],
            "Period": 300,
            "EvaluationPeriods": 2,
            "DatapointsToAlarm": 2,
            "ComparisonOperator": "GreaterThanThreshold",
            "Threshold": 50.0,
            "TreatMissingData": "notBreaching",
            "EvaluateLowSampleCountPercentile": ""
          }
        }
        ```

    === "Rule"
        ```yaml
        rules:
          - '#': CloudWatch Alarm ON (API Gateway Alarm)
            if: "{{ data.NewStateValue == 'ALARM' and data.Trigger.Namespace == 'AWS/ApiGateway' }}"
            colour: '#ff0000'
            preamble: <!channel>
            template: >
              {%- set sep=':black_small_square:' -%}
              {#- Get the API name from alarm dimensions -#}
              {%- set api=(data.Trigger.Dimensions | selectattr('name', 'equalto', 'ApiName') | first) or {'value': '?'} -%}
              {#- Get a Python re.Match object for the event counts from the alarm reason -#}
              {%- set m=re.search('\[[^]]*\]', data.NewStateReason) -%}

              :red_circle:
              *{{ data.AlarmName }}*
              {{ sep }}
              {{ api.value }}
              {{ sep }}
              {{ data.StateChangeTime.split('.')[0] }}Z
              
              
              {% if m -%}
              {#- Get rid of the timetamps in the clause containing event counts -#}
              {%- set counts=re.sub(' *\([^)]*\)','',m.group(0)) -%}
              *Count {{ counts }} > {{ data.Trigger.Threshold | int }}*{% endif %}
              {%- if data.AlarmDescription %}
              
              
              _{{ data.AlarmDescription }}_{% endif %}
        ```

    === "Result"
        ![](img/samples/cwatch-api-gw-alarm-on.png)
