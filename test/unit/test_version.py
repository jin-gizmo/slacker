"""Test version."""

from subprocess import run

import version


def test_version():
    assert version.__version__


def test_version_cli():
    result = run(version.__file__, check=True, capture_output=True, text=True)
    assert result.returncode == 0
    assert result.stdout.strip() == version.__version__
