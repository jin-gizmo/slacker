# Slacker

**Slacker** (aka *JinSlacker*) sends messages from AWS services to Slack
channels.

![AWS](https://img.shields.io/badge/AWS-FF9900?logoColor=black)
[![PyPI version](https://img.shields.io/pypi/v/jinslacker)](https://pypi.org/project/jinslacker/)
[![Python versions](https://img.shields.io/pypi/pyversions/jinslacker)](https://pypi.org/project/jinslacker/)
![PyPI - Format](https://img.shields.io/pypi/format/jinslacker)
[![GitHub Licence](https://img.shields.io/github/license/jin-gizmo/slacker)](https://github.com/jin-gizmo/slacker/blob/master/LICENCE.txt)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

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

The **jinslacker** Python package contains the slacker CLI. The AWS components
must be installed from the [repo](https://github.com/jin-gizmo/slacker).

See the [user guide](https://jin-gizmo.github.io/slacker/) for details.

## Genesis

**Slacker** was developed at [Origin Energy](https://www.originenergy.com.au)
as part of the *Jindabyne* initiative. While not part of our core IP, it proved
valuable internally, and we're sharing it in the hope it's useful to others.

Kudos to Origin for fostering a culture that empowers its people to build
complex technology solutions in-house.

[![Jin Gizmo Home](https://img.shields.io/badge/Jin_Gizmo_Home-d30000?logo=GitHub&color=d30000)](https://jin-gizmo.github.io)
