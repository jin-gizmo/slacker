
# Overview

!!! info ""
    **Slacker** was developed at [Origin Energy](https://www.originenergy.com.au)
    as part of the *Jindabyne* initiative. While not part of our core IP, it
    proved valuable internally, and we're sharing it in the hope it's useful to
    others.

    [![Jin Gizmo Home](https://img.shields.io/badge/Jin_Gizmo_Home-d30000?logo=GitHub&color=d30000)](https://jin-gizmo.github.io)

    Kudos to Origin for fostering a culture that empowers its people
    to build complex technology solutions in-house.

<div style="text-align: center;">
  <img src="img/slacker-icon.png" alt="Slacker Logo" 
       alt="Slacker Logo" 
       width="120px" 
       height="auto"
       class="slacker-logo">
</div>

**Slacker** (aka *JinSlacker*) sends messages from AWS services to Slack
channels.

This is hardly revolutionary, and there are
[other mechanisms](https://docs.aws.amazon.com/prometheus/latest/userguide/AMP-alertmanager-SNS-otherdestinations.html)
to achieve this in an AWS environment. These mechanisms are fine if you're happy
with limited control of where messages can come from or go to, as well as having
your Slack channels filling up with the incomprehensible gibberish produced in a
typical AWS environment.

Features:

*   Message content analysis using regular expressions and JSON parsing
*   Message routing and filtering based on message source, content, and time of day
*   Message content rewriting using
    [Jinja](https://jinja.palletsprojects.com/en/stable/) templates.

Currently supported AWS sources are:

*   SNS
*   CloudWatch logs
*   Amazon EventBridge
*   Direct invocation.

!!! question "What about AWS Chatbot?"

    AWS Chatbot can also integrate with Slack. Unlike slacker, it also has some
    limited interactive capability.

    *Subjectivity warning ...*

    Slacker is much more flexible in it's ability to do dynamic content
    analysis, and message routing and rewriting. We also believe slacker is
    simpler to deploy and use. We'd argue that the interactive capabilities of
    the AWS Chatbot solution are so limited by the (essential) security
    restrictions as to be of marginal value in a real operational environment.
