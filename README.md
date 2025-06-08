# Slacker

<div align="center">
    <img src="doc/img/slacker-icon.png" alt="Slacker Icon" width="150px" height="auto">
</div>

**Slacker** (aka *JinSlacker*) sends messages from AWS services to Slack
channels.

![AWS](https://img.shields.io/badge/AWS-FF9900?logoColor=black)
[![PyPI version](https://img.shields.io/pypi/v/jinslacker)](https://pypi.org/project/jinslacker/)
[![Python versions](https://img.shields.io/pypi/pyversions/jinslacker)](https://pypi.org/project/jinslacker/)
[![GitHub Licence](https://img.shields.io/github/license/jin-gizmo/slacker)](https://github.com/jin-gizmo/slacker/blob/master/LICENCE.txt)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

Turn this ...

<div align="center">
    <img src="doc/img/json-mess.png" alt="JSON mess" width="auto" height="200px">
</div>

... into this ...

<div align="center">
    <img src="doc/img/cwatch-metric-alarm-on.png" alt="Oooh" width="auto" height="150px">
</div>

## Features

**Slacker** features include:

*   Message content analysis using regular expressions and JSON parsing
*   Message routing and filtering based on message source, content, and time of day
*   Message content rewriting using
    [Jinja](https://jinja.palletsprojects.com/en/stable/) templates.

Currently supported AWS sources are:

*   SNS
*   CloudWatch logs
*   Amazon EventBridge
*   Direct invocation.

## Genesis

**Slacker** was developed at [Origin Energy](https://www.originenergy.com.au)
as part of the *Jindabyne* initiative. While not part of our core IP, it proved
valuable internally, and we're sharing it in the hope it's useful to others.

Kudos to Origin for fostering a culture that empowers its people to build
complex technology solutions in-house.

[![Jin Gizmo Home](https://img.shields.io/badge/Jin_Gizmo_Home-d30000?logo=GitHub&color=d30000)](https://jin-gizmo.github.io)

## Installation and Usage

See the [user guide](https://jin-gizmo.github.io/slacker/) for details.
