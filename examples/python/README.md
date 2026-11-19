# Python examples

Install the package (with the `async` extra for `async_basic.py`), point it at AWS or an emulator
and run an example. Each example creates its own secrets under `grow-sdk-example/<random>/` and
force-deletes them at the end.

```bash
pip install "grow-aws-secrets-manager[async]"
# real AWS: the standard credential chain (profile, SSO, env, instance role)
AWS_REGION=eu-central-1 AWS_PROFILE=dev python examples/python/basic.py
# Moto / LocalStack
GROW_AWS_SECRETS_MANAGER_URL=http://127.0.0.1:5000 AWS_REGION=us-east-1 \
  AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... python examples/python/basic.py
```

| File | Shows |
| - | - |
| `basic.py` | sync client: health, ping, create → read → new version → JSON field → stages, random password, error handling |
| `async_basic.py` | async client (aioboto3), the async SecretsProvider, cancellation by task |
| `secrets_cache.py` | `SecretsProvider` (`set`/`get`/`get_many`/`load_env`/`watch`) and the version-stage aware `AwsSecretCache` |
