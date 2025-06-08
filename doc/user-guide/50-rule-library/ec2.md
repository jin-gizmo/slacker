## EC2 Events

??? "Auto Scaling Instance Launch"

    These events occur when an auto scaling group launches new instances. It is
    sometimes handy to know about this but rarely interesting enough to page
    someone. What is not handy is 50 lines of JSON bumph spewing into your
    operations Slack channel when an instance launches.

    Slacker is a good fit for these messages.
 
    === "Message"
        ```json
        {
          "Origin": "EC2",
          "Destination": "AutoScalingGroup",
          "Progress": 50,
          "AccountId": "123456789012",
          "Description": "Launching a new EC2 instance: i-01918b2230392f631",
          "RequestId": "59864e62-e212-6604-627d-5ac06f09f7ec",
          "EndTime": "2024-12-05T21:27:35.517Z",
          "AutoScalingGroupARN": "arn:aws:autoscaling:ap-southeast-2:123456789012:autoScalingGroup:8dc6c859-8cbd-4549-94f1-72678f7a5a0a:autoScalingGroupName/my-asg",
          "ActivityId": "59864e62-e212-6604-627d-5ac06f09f7ec",
          "StartTime": "2024-12-05T21:27:29.689Z",
          "Service": "AWS Auto Scaling",
          "Time": "2024-12-05T21:27:35.517Z",
          "EC2InstanceId": "i-01918b2230392f631",
          "StatusCode": "InProgress",
          "StatusMessage": "",
          "Details": {
            "Subnet ID": "subnet-abcdefab",
            "Availability Zone": "ap-southeast-2b",
            "InvokingAlarms": [
              {
                "AlarmArn": "arn:aws:cloudwatch:ap-southeast-2:123456789012:alarm:TargetTracking-my-asg-AlarmHigh-1bd75141-14b2-4f14-ad2b-6d26ea7c94a8",
                "Trigger": {
                  "MetricName": "WorkerBacklog",
                  "EvaluateLowSampleCountPercentile": "",
                  "ComparisonOperator": "GreaterThanThreshold",
                  "TreatMissingData": "",
                  "Statistic": "AVERAGE",
                  "StatisticType": "Statistic",
                  "Period": 60,
                  "EvaluationPeriods": 3,
                  "Unit": null,
                  "Namespace": "MyApp",
                  "Threshold": 20
                },
                "AlarmName": "TargetTracking-my-asg-AlarmHigh-1bd75141-14b2-4f14-ad2b-6d26ea7c94a8",
                "AlarmDescription": "DO NOT EDIT OR DELETE. For TargetTrackingScaling policy arn:aws:autoscaling:ap-southeast-2:123456789012:scalingPolicy:a2c49e03-5a24-4a34-93a6-4d1aab48ad6d:autoScalingGroupName/my-asg:policyName/my-asg-asgWorkerScalingPolicy-crdTF9",
                "AWSAccountId": "123456789012",
                "OldStateValue": "ALARM",
                "Region": "Asia Pacific (Sydney)",
                "NewStateValue": "ALARM",
                "AlarmConfigurationUpdatedTimestamp": 1732249141214,
                "StateChangeTime": 1733433742189
              }
            ]
          },
          "AutoScalingGroupName": "my-asg",
          "Cause": "At 2024-12-05T21:27:22Z a monitor alarm TargetTracking-my-asg-AlarmHigh-1bd75141-14b2-4f14-ad2b-6d26ea7c94a8 in state ALARM triggered policy my-asg-asgWorkerScalingPolicy-crdTF9lGieul changing the desired capacity from 2 to 3.  At 2024-12-05T21:27:28Z an instance was started in response to a difference between desired and actual capacity, increasing the capacity from 2 to 3.",
          "Event": "autoscaling:EC2_INSTANCE_LAUNCH"
        }
        ```

    === "Rule"
        The same rule handles both launch and termination events.

        ```yaml
        rules:
          - '#': Auto scaling launch / termination
            if: "{{ data.Service == 'AWS Auto Scaling' }}"
            template: >
              {% set icons = {
                'autoscaling:EC2_INSTANCE_LAUNCH': ':arrow_heading_up:',
                'autoscaling:EC2_INSTANCE_TERMINATE': ':arrow_heading_down:',
              } %}
              {%- set sep = ':black_small_square:' -%}
              {{- icons.get(data.Event, data.Event.split(':')[-1]) }}
              *{{ data.AutoScalingGroupName }}*
              {{ sep }}
              {{ data.EC2InstanceId }}
              {{ sep }}
              {{ data.StartTime.split('.')[0] }}Z
              
              _{{ data.StatusCode }}_
        ```

    === "Result"
        ![](img/samples/ec2-autoscaling-launch.png)

??? "Auto Scaling Instance Termination"

    === "Message"
        ```json
        {
          "Origin": "AutoScalingGroup",
          "Destination": "EC2",
          "Progress": 60,
          "AccountId": "123456789012",
          "Description": "Terminating EC2 instance: i-0bc09f781ddd6f516",
          "RequestId": "f6c642e2-21ec-4bcb-a28e-892808bfa29e",
          "EndTime": "2024-12-05T21:50:47.987Z",
          "AutoScalingGroupARN": "arn:aws:autoscaling:ap-southeast-2:123456789012:autoScalingGroup:8dc6c859-8cbd-4549-94f1-72678f7a5a0a:autoScalingGroupName/my-asg",
          "ActivityId": "f6c642e2-21ec-4bcb-a28e-892808bfa29e",
          "StartTime": "2024-12-05T21:48:52.881Z",
          "Service": "AWS Auto Scaling",
          "Time": "2024-12-05T21:50:47.988Z",
          "EC2InstanceId": "i-0bc09f781ddd6f516",
          "StatusCode": "MidTerminatingLifecycleAction",
          "StatusMessage": "",
          "Details": {
            "Subnet ID": "subnet-abcdefab",
            "Availability Zone": "ap-southeast-2c",
            "InvokingAlarms": [
              {
                "AlarmArn": "arn:aws:cloudwatch:ap-southeast-2:123456789012:alarm:TargetTracking-my-asg-AlarmLow-7a95c75c-aaf8-482d-9516-90723ad7ea91",
                "Trigger": {
                  "MetricName": "WorkerBacklog",
                  "EvaluateLowSampleCountPercentile": "",
                  "ComparisonOperator": "LessThanThreshold",
                  "TreatMissingData": "",
                  "Statistic": "AVERAGE",
                  "StatisticType": "Statistic",
                  "Period": 60,
                  "EvaluationPeriods": 15,
                  "Unit": null,
                  "Namespace": "MyApp",
                  "Threshold": 14
                },
                "AlarmName": "TargetTracking-my-asg-AlarmLow-7a95c75c-aaf8-482d-9516-90723ad7ea91",
                "AlarmDescription": "DO NOT EDIT OR DELETE. For TargetTrackingScaling policy arn:aws:autoscaling:ap-southeast-2:123456789012:scalingPolicy:a2c49e03-5a24-4a34-93a6-4d1aab48ad6d:autoScalingGroupName/my-asg:policyName/my-asg-asgWorkerScalingPolicy-crdTF9",
                "AWSAccountId": "123456789012",
                "OldStateValue": "ALARM",
                "Region": "Asia Pacific (Sydney)",
                "NewStateValue": "ALARM",
                "AlarmConfigurationUpdatedTimestamp": 1732250795584,
                "StateChangeTime": 1733435027153
              }
            ]
          },
          "AutoScalingGroupName": "my-asg",
          "Cause": "At 2024-12-05T21:48:47Z a monitor alarm TargetTracking-my-asg-AlarmLow-7a95c75c-aaf8-482d-9516-90723ad7ea91 in state ALARM triggered policy my-asg-asgWorkerScalingPolicy-crdTF9lGieul changing the desired capacity from 2 to 1.  At 2024-12-05T21:48:52Z an instance was taken out of service in response to a difference between desired and actual capacity, shrinking the capacity from 2 to 1.  At 2024-12-05T21:48:52Z instance i-0bc09f781ddd6f516 was selected for termination.",
          "Event": "autoscaling:EC2_INSTANCE_TERMINATE"
        }
        ```

    === "Rule"
        The same rule is used to handle both auto scaling launches and terminations.

    === "Result"
        ![](img/samples/ec2-autoscaling-termination.png)
