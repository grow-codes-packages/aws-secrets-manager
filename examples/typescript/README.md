# TypeScript example

Creates one secret, reads it back (value, JSON field, previous version, cache, provider list)
and deletes it again without a recovery window.

```sh
(cd ../../typescript && npm install && npm run build)
npm install
# real AWS: standard credential chain (profile, SSO, env, IMDS ...)
AWS_REGION=eu-central-1 AWS_PROFILE=dev npm start
# Moto / LocalStack
GROW_AWS_SECRETS_MANAGER_URL=http://127.0.0.1:5000 AWS_REGION=us-east-1 \
  AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... npm start
```

Replace the `file:` dependency in `package.json` with a version (`npm install @grow-codes/aws-secrets-manager`)
to run it against the published package.
