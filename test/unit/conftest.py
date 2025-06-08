"""Pytest conf."""

from __future__ import annotations

from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any
import json

import pytest
import yaml


# ------------------------------------------------------------------------------
class DotDict:
    """
    Access dict values with dot notation or conventional dict notation or mix and match.

    ..warning:: This does not handle all dict syntax, just what is needed here.

    """

    def __init__(self, *data: Mapping[str, Any]):
        """Create dotable dict from dict(s)."""
        self._data = {}

        for d in data:
            self._data.update(d)

    def __getattr__(self, item: str) -> Any:
        """Access config elements with dot notation support for keys."""

        if not item or not isinstance(item, str):
            raise ValueError(f'Bad config item name: {item}')

        try:
            value = self._data[item]
        except KeyError:
            raise AttributeError(item)
        return self.__class__(value) if isinstance(value, dict) else value

    def __getitem__(self, item):
        value = self._data[item]
        return self.__class__(value) if isinstance(value, dict) else value

    def __str__(self):
        return str(self._data)

    def __repr__(self):
        return repr(self._data)

    @property
    def dict(self) -> dict:
        """Return the underlying data as a dict."""
        return self._data


# ------------------------------------------------------------------------------
@pytest.fixture(scope='session')
def td() -> Path:
    """Path for test data."""
    return Path(__file__).parent.parent / 'data'


# ------------------------------------------------------------------------------
@pytest.fixture(scope='session')
def dirs(td) -> DotDict:
    """Package to access useful directories in the source tree."""

    return DotDict(
        {
            'cwd': Path('.').resolve(),
            'base': Path(__file__).parent.parent.parent,
            'src': Path(__file__).parent.parent.parent / 'slacker',
            'test': Path(__file__).parent.parent,
            'data': td,
        }
    )


# ------------------------------------------------------------------------------
@pytest.fixture(scope='function')
def aws_mock_creds(monkeypatch):
    """Mocked AWS Credentials for moto."""

    with suppress(KeyError):
        monkeypatch.delenv('AWS_PROFILE')

    monkeypatch.setenv('AWS_ACCESS_KEY_ID', 'testing')
    monkeypatch.setenv('AWS_SECRET_ACCESS_KEY', 'testing')
    monkeypatch.setenv('AWS_SECURITY_TOKEN', 'testing')
    monkeypatch.setenv('AWS_SESSION_TOKEN', 'testing')
    monkeypatch.setenv('AWS_DEFAULT_REGION', 'us-east-1')


# ------------------------------------------------------------------------------
@dataclass
class RulesTestScenario:
    """Test scenario for evaluating slack filtering rules."""

    input: str
    rules: list[dict[str, Any]]
    output: str | None = None
    error: str | None = None

    @classmethod
    def from_file(cls, file: Path | str) -> RulesTestScenario:
        """Load a test scenario from a YAML file."""
        path = file if isinstance(file, Path) else Path(file)
        scenario = yaml.safe_load(path.read_text())
        if not isinstance(scenario['input'], str):
            # Convenience for specifying JSON encoded test data in the YAML.
            scenario['input'] = json.dumps(scenario['input'])
        return cls(**scenario)
