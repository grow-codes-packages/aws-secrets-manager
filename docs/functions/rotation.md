# Rotation

| Function | AWS operation | Notes |
| - | - | - |
| `rotateSecret(id, {lambdaArn?, rules?, rotateImmediately?, clientRequestToken?})` | `RotateSecret` | configures and/or starts rotation. `rules`: `automaticallyAfterDays` (1–1000) **or** `scheduleExpression` (`rate(…)` / `cron(…)`), optional window `duration` (e.g. `"3h"`). Without `lambdaArn` the secret's managed or existing rotation function is used. Returns `{arn, name, versionId}`; rotation in progress → `CONFLICT` |
| `cancelRotateSecret(id)` | `CancelRotateSecret` | turns rotation off (`rotationEnabled = false`) and cancels a rotation in progress |

!!! warning "Emulator limits"
    Moto 5.2.4 has no Lambda runtime in the Docker fixture: a rules-only rotation works (Moto copies
    the current value into a new `AWSCURRENT` version and sets `rotationEnabled` /
    `nextRotationDate`), a rotation with a Lambda ARN answers `NOT_FOUND`, and
    `cancelRotateSecret` only works once a Lambda ARN is recorded on the secret. Real Lambda
    rotation is unit-tested against the AWS wire shapes (see [Compatibility](../compatibility.md)).

=== "TypeScript"

    ```ts
    await client.rotateSecret("app/db", {
      lambdaArn: "arn:aws:lambda:eu-central-1:123456789012:function:rotate-db",
      rules: { automaticallyAfterDays: 30, duration: "3h" },
      rotateImmediately: false,
    });
    await client.rotateSecret("app/api", { rules: { scheduleExpression: "rate(10 days)" } });
    await client.cancelRotateSecret("app/db");
    ```

=== "Rust"

    ```rust
    use grow_aws_secrets_manager::models::{RotateSecretOptions, RotationRules};

    client
        .rotate_secret("app/db", RotateSecretOptions {
            lambda_arn: Some("arn:aws:lambda:eu-central-1:123456789012:function:rotate-db".into()),
            rules: Some(RotationRules { automatically_after_days: Some(30), duration: Some("3h".into()), ..Default::default() }),
            rotate_immediately: Some(false),
            ..Default::default()
        })
        .await?;
    client.cancel_rotate_secret("app/db").await?;
    ```

=== "Go"

    ```go
    _, err := client.RotateSecret(ctx, "app/db", &asm.RotateSecretOptions{
        LambdaARN:         "arn:aws:lambda:eu-central-1:123456789012:function:rotate-db",
        Rules:             &asm.RotationRules{AutomaticallyAfterDays: 30, Duration: "3h"},
        RotateImmediately: aws.Bool(false),
    })
    _, err = client.RotateSecret(ctx, "app/api", &asm.RotateSecretOptions{Rules: &asm.RotationRules{ScheduleExpression: "rate(10 days)"}})
    _, err = client.CancelRotateSecret(ctx, "app/db")
    ```

=== "Python"

    ```python
    import grow_aws_secrets_manager as sdk

    client.rotate_secret(
        "app/db",
        lambda_arn="arn:aws:lambda:eu-central-1:123456789012:function:rotate-db",
        rules=sdk.RotationRules(automatically_after_days=30, duration="3h"),
        rotate_immediately=False,
    )
    client.rotate_secret("app/api", rules=sdk.RotationRules(schedule_expression="rate(10 days)"))
    client.cancel_rotate_secret("app/db")
    ```

=== "Java"

    ```java
    client.rotateSecret("app/db",
        RotateSecretOptions.builder()
            .lambdaArn("arn:aws:lambda:eu-central-1:123456789012:function:rotate-db")
            .rules(RotationRules.everyDays(30))
            .rotateImmediately(false)
            .build());
    client.rotateSecret("app/api",
        RotateSecretOptions.builder().rules(RotationRules.schedule("rate(10 days)")).build());
    client.cancelRotateSecret("app/db");
    ```
