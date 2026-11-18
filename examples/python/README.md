# Python examples

Install the package, point it at a running AWS Secrets Manager and run an example:

```bash
pip install grow-aws-secrets-manager
export GROW_AWS_SECRETS_MANAGER_URL=http://127.0.0.1:5000
export GROW_AWS_SECRETS_MANAGER_TOKEN=...   # when the service needs one
python examples/python/basic.py
```

| File | Shows |
| - | - |
| `basic.py` | sync client: health, ping, server version, error handling |
| `async_basic.py` | async client, cancellation by task |
| `hooks_and_logging.py` | request hooks, the `grow_aws_secrets_manager` logger, retries and timeouts |
| `secrets_cache.py` | cached secret reads, typed getters, `load_env`, `watch` (in-memory provider) |
