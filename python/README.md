# grow-aws-secrets-manager (Python)

Python SDK for [AWS Secrets Manager](https://grow-codes-packages.github.io/aws-secrets-manager/) by Grow Codes.
Unofficial and community maintained; "AWS Secrets Manager" is a trademark of Amazon.com, Inc. or its affiliates.

```bash
pip install grow-aws-secrets-manager
```

```python
from grow_aws_secrets_manager import AwsSecretsManagerClient, AwsSecretsManagerConfig

# Reads GROW_AWS_SECRETS_MANAGER_URL, GROW_AWS_SECRETS_MANAGER_TOKEN, ... from the environment.
with AwsSecretsManagerClient.from_env() as client:
    print(client.health())
    print(client.server_version())
```

The async client has the same methods:

```python
import asyncio
from grow_aws_secrets_manager import AsyncAwsSecretsManagerClient

async def main() -> None:
    async with AsyncAwsSecretsManagerClient.from_env() as client:
        print(await client.health())

asyncio.run(main())
```

- Python 3.10 or newer, typed (`py.typed`), `httpx` based, environment proxies ignored unless
  configured.
- Retries with full-jitter backoff and `Retry-After`, connect/request/total timeouts,
  cancellation, hooks and a silent-by-default `logging` logger named `grow_aws_secrets_manager`.
- Credentials are wrapped in `Secret` and never appear in `repr()`, logs or error messages.
- `grow_aws_secrets_manager.testing` ships in-memory fakes and the conformance runner.

Documentation: https://grow-codes-packages.github.io/aws-secrets-manager/ ·
Source: https://github.com/grow-codes-packages/aws-secrets-manager · Licence: Apache-2.0
