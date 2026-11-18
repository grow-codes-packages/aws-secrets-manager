"""Grow Codes SDK for AWS Secrets Manager.

>>> from grow_aws_secrets_manager import AwsSecretsManagerClient, AwsSecretsManagerConfig
>>> client = AwsSecretsManagerClient.from_env()  # doctest: +SKIP
"""

from . import _core
from ._core import *  # noqa: F403
from ._version import __version__
from .client import AsyncAwsSecretsManagerClient, AwsSecretsManagerClient
from .config import DEFAULT_URL, AwsSecretsManagerConfig

__all__ = [
    "__version__",
    "AwsSecretsManagerClient",
    "AsyncAwsSecretsManagerClient",
    "AwsSecretsManagerConfig",
    "DEFAULT_URL",
]
__all__ += _core.__all__

from . import _secrets  # noqa: E402
from ._secrets import *  # noqa: E402, F403

__all__ += _secrets.__all__
