"""Grow Codes SDK for AWS Secrets Manager (boto3 / aioboto3).

>>> from grow_aws_secrets_manager import AwsSecretsManagerClient
>>> with AwsSecretsManagerClient.from_env() as client:  # doctest: +SKIP
...     client.get_secret_value("app/db").value.reveal()

Not affiliated with or endorsed by Amazon Web Services. Amazon Web Services, AWS and AWS Secrets
Manager are trademarks of Amazon.com, Inc. or its affiliates.
"""

from . import _core
from ._core import *  # noqa: F403
from ._version import __version__
from .client import AsyncAwsSecretsManagerClient, AwsSecretsManagerClient
from .config import (
    DEFAULT_RECOVERY_WINDOW_DAYS,
    DEFAULT_ROLE_SESSION_NAME,
    URL_PLACEHOLDER,
    VENDOR_ENV,
    AwsSecretsManagerConfig,
)
from .errors_map import (
    AWS_ERROR_CODES,
    aws_error_code,
    code_for_status,
    error_code_from_body,
    map_aws_error,
)
from .models import (
    API_VERSION,
    AWSCURRENT,
    AWSPENDING,
    AWSPREVIOUS,
    BATCH_GET_MAX_IDS,
    AwsSecretValue,
    BatchGetError,
    BatchGetResult,
    DeleteSecretResult,
    PolicyValidationError,
    PutSecretValueResult,
    ReplicaRegion,
    ReplicationStatus,
    ResourcePolicyResult,
    RotationRules,
    SecretDescription,
    SecretFilter,
    SecretFilterKey,
    SecretRef,
    SecretVersion,
    SecretWriteResult,
    SortOrder,
    ValidateResourcePolicyResult,
)
from .paginator import AsyncPaginator, Paginator
from .provider import (
    AsyncAwsSecretsManagerSecretsProvider,
    AwsSecretsManagerSecretsProvider,
    full_name,
    to_metadata,
)
from .secret_cache import (
    AWS_SECRET_CACHE_DEFAULTS,
    AsyncAwsSecretCache,
    AsyncSecretCacheSource,
    AwsSecretCache,
    AwsSecretCacheStats,
    SecretCacheSource,
)

__all__ = [
    "__version__",
    # clients + config
    "AwsSecretsManagerClient",
    "AsyncAwsSecretsManagerClient",
    "AwsSecretsManagerConfig",
    "DEFAULT_RECOVERY_WINDOW_DAYS",
    "DEFAULT_ROLE_SESSION_NAME",
    "URL_PLACEHOLDER",
    "VENDOR_ENV",
    # error mapping
    "AWS_ERROR_CODES",
    "aws_error_code",
    "code_for_status",
    "error_code_from_body",
    "map_aws_error",
    # models
    "API_VERSION",
    "AWSCURRENT",
    "AWSPREVIOUS",
    "AWSPENDING",
    "BATCH_GET_MAX_IDS",
    "AwsSecretValue",
    "BatchGetError",
    "BatchGetResult",
    "DeleteSecretResult",
    "PolicyValidationError",
    "PutSecretValueResult",
    "ReplicaRegion",
    "ReplicationStatus",
    "ResourcePolicyResult",
    "RotationRules",
    "SecretDescription",
    "SecretFilter",
    "SecretFilterKey",
    "SecretRef",
    "SecretVersion",
    "SecretWriteResult",
    "SortOrder",
    "ValidateResourcePolicyResult",
    # pagination, provider, cache
    "Paginator",
    "AsyncPaginator",
    "AwsSecretsManagerSecretsProvider",
    "AsyncAwsSecretsManagerSecretsProvider",
    "full_name",
    "to_metadata",
    "AWS_SECRET_CACHE_DEFAULTS",
    "AwsSecretCache",
    "AsyncAwsSecretCache",
    "AwsSecretCacheStats",
    "SecretCacheSource",
    "AsyncSecretCacheSource",
]
__all__ += _core.__all__

from . import _secrets  # noqa: E402
from ._secrets import *  # noqa: E402, F403

__all__ += _secrets.__all__
