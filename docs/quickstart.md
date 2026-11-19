# Quickstart

Connect to AWS Secrets Manager, check that it is reachable, verify the credentials, write and read a
secret and close the client. The client reads `GROW_AWS_SECRETS_MANAGER_*` first and then the
standard AWS variables and credential chain (see [Functions → Service configuration](functions.md#service-configuration)).

```sh
export AWS_REGION=eu-central-1
export AWS_PROFILE=dev                # or AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY, SSO, IAM role …
# Emulator (Moto) instead of AWS:
# export GROW_AWS_SECRETS_MANAGER_URL=http://127.0.0.1:5000
```

=== "TypeScript"

    ```ts
    import { AwsSecretsManagerClient } from "@grow-codes/aws-secrets-manager";

    const client = AwsSecretsManagerClient.fromEnv();
    try {
      const health = await client.health(); // never throws for an unreachable service
      console.log("healthy:", health.healthy, health.status);
      console.log("ping:", await client.ping(), "ms");
      await client.createSecret("demo/db", { user: "app", password: "s3cret" });
      console.log("user:", await client.getJsonField("demo/db", "user"));
      const secret = await client.getSecretValue("demo/db");
      console.log(secret.versionId, `${secret.value}`); // value prints as [REDACTED]
      await client.deleteSecret("demo/db", { forceDeleteWithoutRecovery: true });
    } finally {
      await client.close();
    }
    ```

=== "Rust"

    ```rust
    use grow_aws_secrets_manager::models::{CreateSecretOptions, DeleteSecretOptions};
    use grow_aws_secrets_manager::AwsSecretsManagerClient;

    #[tokio::main]
    async fn main() -> grow_aws_secrets_manager::Result<()> {
        let client = AwsSecretsManagerClient::from_env()?;
        let health = client.health().await?;
        println!("healthy: {} {}", health.healthy, health.status);
        println!("ping: {:?}", client.ping().await?);
        let value = serde_json::json!({"user": "app", "password": "s3cret"});
        client.create_secret("demo/db", Some(value.into()), CreateSecretOptions::default()).await?;
        println!("user: {:?}", client.get_json_field("demo/db", "user", Default::default()).await?);
        let secret = client.get_secret_value("demo/db", Default::default()).await?;
        println!("{:?} {}", secret.version_id, secret.value); // value prints as [REDACTED]
        client
            .delete_secret("demo/db", DeleteSecretOptions { force_delete_without_recovery: Some(true), ..Default::default() })
            .await?;
        client.close().await;
        Ok(())
    }
    ```

=== "Go"

    ```go
    package main

    import (
        "context"
        "fmt"
        "log"

        asm "github.com/grow-codes-packages/aws-secrets-manager/go"
    )

    func main() {
        ctx := context.Background()
        client, err := asm.NewClientFromEnv()
        if err != nil {
            log.Fatal(err) // CONFIG error naming the variable, never its value
        }
        defer client.Close()

        health, err := client.Health(ctx)
        if err != nil {
            log.Fatal(err)
        }
        fmt.Println("healthy:", health.Healthy, health.Status)
        if _, err := client.Ping(ctx); err != nil {
            log.Fatal(err) // AUTHENTICATION / PERMISSION_DENIED
        }
        if _, err := client.CreateSecret(ctx, "demo/db", map[string]any{"user": "app", "password": "s3cret"}, nil); err != nil {
            log.Fatal(err)
        }
        user, _, err := client.GetJSONField(ctx, "demo/db", "user", nil)
        fmt.Println("user:", user, err)
        secret, err := client.GetSecretValue(ctx, "demo/db", nil)
        if err != nil {
            log.Fatal(err)
        }
        fmt.Println(secret.VersionID, secret.Value) // value prints as [REDACTED]
        _, _ = client.DeleteSecret(ctx, "demo/db", &asm.DeleteSecretOptions{ForceDeleteWithoutRecovery: true})
    }
    ```

=== "Python"

    ```python
    from grow_aws_secrets_manager import AwsSecretsManagerClient

    with AwsSecretsManagerClient.from_env() as client:
        health = client.health()
        print("healthy:", health.healthy, health.status)
        print("ping:", client.ping(), "ms")
        client.create_secret("demo/db", {"user": "app", "password": "s3cret"})
        print("user:", client.get_json_field("demo/db", "user"))
        secret = client.get_secret_value("demo/db")
        print(secret.version_id, secret.value)  # value prints as [REDACTED]
        client.delete_secret("demo/db", force_delete_without_recovery=True)
    ```

    Async code uses `AsyncAwsSecretsManagerClient` (install `grow-aws-secrets-manager[async]`)
    with the same methods:

    ```python
    import asyncio
    from grow_aws_secrets_manager import AsyncAwsSecretsManagerClient

    async def main() -> None:
        async with AsyncAwsSecretsManagerClient.from_env() as client:
            print(await client.health())
            print(await client.get_json_field("demo/db", "user"))

    asyncio.run(main())
    ```

=== "Java"

    ```java
    import codes.grow.packages.awssecretsmanager.AwsSecretValue;
    import codes.grow.packages.awssecretsmanager.AwsSecretsManagerClient;
    import codes.grow.packages.awssecretsmanager.DeleteSecretOptions;
    import codes.grow.packages.awssecretsmanager.core.HealthStatus;
    import java.util.Map;

    public final class Quickstart {
      public static void main(String[] args) {
        try (AwsSecretsManagerClient client = AwsSecretsManagerClient.fromEnv()) {
          HealthStatus health = client.health();
          System.out.println("healthy: " + health.healthy() + " " + health.status());
          System.out.println("ping: " + client.ping().toMillis() + " ms");
          client.createSecret("demo/db", Map.of("user", "app", "password", "s3cret"));
          System.out.println("user: " + client.getJsonField("demo/db", "user").orElse(null));
          AwsSecretValue secret = client.getSecretValue("demo/db");
          System.out.println(secret.versionId() + " " + secret.value()); // value prints as [REDACTED]
          client.deleteSecret("demo/db", DeleteSecretOptions.builder().forceDeleteWithoutRecovery(true).build());
        }
      }
    }
    ```

## Next steps

- [Functions](functions.md): every AWS Secrets Manager call, with examples in all five languages.
- [Configuration](configuration.md): timeouts, retries, TLS, proxy, environment variables.
- [Secrets](secrets.md): the portable provider API (`client.secrets()`).
- [Error handling](errors.md): error codes and retries.
