"""Shared pytest fixtures."""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from _support import MockServer

# Never let botocore probe the EC2 instance metadata service from unit tests.
os.environ["AWS_EC2_METADATA_DISABLED"] = "true"


@pytest.fixture
def server() -> Iterator[MockServer]:
    srv = MockServer()
    yield srv
    srv.stop()
