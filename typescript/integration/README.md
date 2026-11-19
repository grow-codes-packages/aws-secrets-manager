# TypeScript integration tests

A consumer project: it installs the packed `@grow-codes/aws-secrets-manager` tarball (never the source tree)
and runs the integration and conformance tests with `node --test` against the AWS Secrets Manager API (Moto in Docker).

```sh
cd typescript && make pack            # writes dist/grow-codes-aws-secrets-manager-<version>.tgz
cd integration && npm run install-package
GROW_AWS_SECRETS_MANAGER_URL=http://127.0.0.1:<port> AWS_REGION=us-east-1 AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... npm test
```

In CI and locally with Docker this runs inside `docker/Dockerfile.typescript`
(`make test-docker LANGS=typescript` from the repository root), which reads `/bootstrap/env`.
