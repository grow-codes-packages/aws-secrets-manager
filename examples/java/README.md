# Java examples

Install the package into your local Maven repository, point it at a running AWS Secrets Manager and run an
example:

```bash
make -C ../../java pack            # builds and installs codes.grow.packages:aws-secrets-manager
export AWS_REGION=us-east-1                          # or AWS_PROFILE / the default credential chain
export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=...
export GROW_AWS_SECRETS_MANAGER_URL=http://127.0.0.1:5000   # only for an emulator such as Moto
mvn -q compile exec:java                                                  # BasicExample
mvn -q compile exec:java -Dexec.mainClass=codes.grow.packages.awssecretsmanager.examples.AwsSecretsManagerExample
mvn -q compile exec:java -Dexec.mainClass=codes.grow.packages.awssecretsmanager.examples.AsyncExample
```

Against the published package, set `-Dsdk.version=<version>` (or edit `pom.xml`) instead of
installing it locally.

| Class | Shows |
| - | - |
| `BasicExample` | blocking client: health, ping, server version (unsupported on AWS), error handling |
| `AwsSecretsManagerExample` | create, read, versions and stages, tags, list, batch read, JSON fields, random password, `AwsSecretCache`, `SecretsProvider` |
| `AsyncExample` | `…Async` methods, combining futures, cancellation |
| `HooksAndLoggingExample` | request hooks, a logger, retries and timeouts |
| `secrets.SecretsCacheExample` | cached secret reads, typed getters, `loadEnv`, `watch` (in-memory provider) |
