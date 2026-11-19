# grow-aws-secrets-manager (Python)

Python SDK for [AWS Secrets Manager](https://grow-codes-packages.github.io/aws-secrets-manager/) by
Grow Codes, built on the official AWS SDK for Python (boto3; aioboto3 for the async client).
Unofficial and community maintained; not affiliated with or endorsed by AWS. Amazon Web Services,
AWS and AWS Secrets Manager are trademarks of Amazon.com, Inc. or its affiliates.

```bash
pip install grow-aws-secrets-manager            # sync client (boto3)
pip install "grow-aws-secrets-manager[async]"   # + AsyncAwsSecretsManagerClient (aioboto3)
```

```python
from grow_aws_secrets_manager import AWSPREVIOUS, AwsSecretsManagerClient

# GROW_AWS_SECRETS_MANAGER_* first, then the standard AWS variables and credential chain.
with AwsSecretsManagerClient.from_env() as client:
    client.create_secret("app/db", {"user": "app", "password": "s3cr3t"}, tags={"team": "a"})
    print(client.get_json_field("app/db", "user"))
    client.put_secret_value("app/db", {"user": "app", "password": "rotated"})
    print(client.get_secret_value("app/db", version_stage=AWSPREVIOUS).value)  # [REDACTED]

    secrets = client.secrets()                     # SecretsProvider (Grow category API)
    print(secrets.get_string("app/db"))
    cache = client.secret_cache()                  # AWS caching-client semantics (TTL 1 h)
    print(cache.get_secret_string("app/db"))
```

The async client has the same methods:

```python
import asyncio
from grow_aws_secrets_manager import AsyncAwsSecretsManagerClient

async def main() -> None:
    async with AsyncAwsSecretsManagerClient.from_env() as client:
        print((await client.get_secret_value("app/db")).value.json())

asyncio.run(main())
```

- Python 3.10 or newer, typed (`py.typed`). The Grow config maps onto the boto3 client: `url` →
  endpoint override, timeouts → botocore timeouts, `retry.max_retries` → standard retry mode
  (`max_attempts = max_retries + 1`), TLS CA bundle / client certificate / `insecure_skip_verify`,
  proxy (environment proxies are ignored unless configured), User-Agent
  `grow-codes-aws-secrets-manager/<version> (python)`; or pass an existing boto3 client
  (`AwsSecretsManagerClient.with_sdk_client(boto3.client("secretsmanager"))`).
- Credentials: explicit keys, `profile`, a botocore credentials object, the default chain, and an
  STS assume-role helper (`role_arn`, `role_session_name`, `external_id`, `role_duration_s`).
- Errors are mapped by AWS error code (`ResourceNotFoundException` → `NotFoundError`, …); the
  code stays available with `aws_error_code(err)`.
- Hooks (`on_request` / `on_response` / `on_error`) fire from botocore events; credentials are
  wrapped in `Secret` and never appear in `repr()`, logs or error messages.
- `grow_aws_secrets_manager.testing` ships in-memory fakes and the conformance runner.

Documentation: https://grow-codes-packages.github.io/aws-secrets-manager/ ·
Source: https://github.com/grow-codes-packages/aws-secrets-manager · Licence: Apache-2.0
