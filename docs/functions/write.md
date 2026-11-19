# Write

Create secrets, add versions, move stage labels, delete and restore. A value is encoded the same
way in every language: **text → `SecretString`, bytes → `SecretBinary`, any other object → JSON
`SecretString`**; no value creates a secret without a version.

| Function | AWS operation | Notes |
| - | - | - |
| `createSecret(name, value?, {description?, kmsKeyId?, tags?, clientRequestToken?, addReplicaRegions?, forceOverwriteReplicaSecret?})` | `CreateSecret` | returns `{arn, name, versionId?}`. Name exists (or is scheduled for deletion) → `CONFLICT`. The AWS SDK fills `ClientRequestToken` (idempotency) unless you give one; a retry with the same token and value returns the same version |
| `putSecretValue(id, value, {versionStages?, clientRequestToken?})` | `PutSecretValue` | new version, by default labelled `AWSCURRENT` (the old current becomes `AWSPREVIOUS`); custom stages only leave `AWSCURRENT` unchanged. Returns `{arn, name, versionId, versionStages}` |
| `updateSecret(id, {value?, description?, kmsKeyId?, clientRequestToken?})` | `UpdateSecret` | a new version only when `value` is given |
| `updateSecretVersionStage(id, stage, {moveToVersionId?, removeFromVersionId?})` | `UpdateSecretVersionStage` | moving `AWSCURRENT` needs `removeFromVersionId` = the current version (`VALIDATION` otherwise); the old current gets `AWSPREVIOUS` |
| `deleteSecret(id, {recoveryWindowDays? \| forceDeleteWithoutRecovery?})` | `DeleteSecret` | schedules deletion after the window (7–30 days; unset = AWS default **30**) or deletes at once with `forceDeleteWithoutRecovery`. Both options together or a window outside 7–30 → `VALIDATION` before any call. Returns `{arn, name, deletionDate}`. A forced delete of a **missing** secret succeeds (AWS behaviour); a secret already scheduled → `CONFLICT` |
| `restoreSecret(id)` | `RestoreSecret` | cancels a scheduled deletion; a no-op for a live secret |

The config's `recoveryWindowDays` (default 30) is used by `SecretsProvider.delete`; the raw
`deleteSecret` sends only what you pass.

=== "TypeScript"

    ```ts
    const created = await client.createSecret("app/db", { user: "app", password: "s3cret" }, {
      description: "database login",
      tags: { team: "platform" },
    });
    const put = await client.putSecretValue("app/db", { user: "app", password: "rotated" });
    await client.putSecretValue("app/db", "candidate", { versionStages: ["STAGED"] });
    await client.updateSecret("app/db", { description: "primary database login" });
    await client.updateSecretVersionStage("app/db", "AWSCURRENT", {
      moveToVersionId: created.versionId, // roll back
      removeFromVersionId: put.versionId,
    });
    await client.createSecret("app/blob", new Uint8Array([0, 1, 2, 254, 255]));
    await client.deleteSecret("app/db", { recoveryWindowDays: 7 });
    await client.restoreSecret("app/db");
    await client.deleteSecret("app/blob", { forceDeleteWithoutRecovery: true });
    ```

=== "Rust"

    ```rust
    use grow_aws_secrets_manager::models::{
        CreateSecretOptions, DeleteSecretOptions, PutSecretValueOptions, UpdateSecretOptions,
        UpdateSecretVersionStageOptions,
    };
    use grow_aws_secrets_manager::secrets::SecretData;
    use serde_json::json;

    let created = client
        .create_secret("app/db", Some(SecretData::Json(json!({"user": "app", "password": "s3cret"}))), CreateSecretOptions {
            description: Some("database login".into()),
            tags: [("team".to_owned(), "platform".to_owned())].into(),
            ..Default::default()
        })
        .await?;
    let put = client.put_secret_value("app/db", json!({"user": "app", "password": "rotated"}), PutSecretValueOptions::default()).await?;
    client
        .put_secret_value("app/db", "candidate", PutSecretValueOptions { version_stages: vec!["STAGED".into()], ..Default::default() })
        .await?;
    client
        .update_secret("app/db", UpdateSecretOptions { description: Some("primary database login".into()), ..Default::default() })
        .await?;
    client
        .update_secret_version_stage("app/db", "AWSCURRENT", UpdateSecretVersionStageOptions {
            move_to_version_id: created.version_id.clone(),
            remove_from_version_id: Some(put.version_id.clone()),
        })
        .await?;
    client.create_secret("app/blob", Some(vec![0u8, 1, 2, 254, 255].into()), CreateSecretOptions::default()).await?;
    client.delete_secret("app/db", DeleteSecretOptions { recovery_window_days: Some(7), ..Default::default() }).await?;
    client.restore_secret("app/db").await?;
    client
        .delete_secret("app/blob", DeleteSecretOptions { force_delete_without_recovery: Some(true), ..Default::default() })
        .await?;
    ```

=== "Go"

    ```go
    created, err := client.CreateSecret(ctx, "app/db", map[string]any{"user": "app", "password": "s3cret"},
        &asm.CreateSecretOptions{Description: "database login", Tags: map[string]string{"team": "platform"}})
    put, err := client.PutSecretValue(ctx, "app/db", map[string]any{"user": "app", "password": "rotated"}, nil)
    _, err = client.PutSecretValue(ctx, "app/db", "candidate", &asm.PutSecretValueOptions{VersionStages: []string{"STAGED"}})
    _, err = client.UpdateSecret(ctx, "app/db", asm.UpdateSecretOptions{Description: "primary database login"})
    _, err = client.UpdateSecretVersionStage(ctx, "app/db", asm.StageCurrent, asm.UpdateSecretVersionStageOptions{
        MoveToVersionID: created.VersionID, RemoveFromVersionID: put.VersionID,
    })
    _, err = client.CreateSecret(ctx, "app/blob", []byte{0, 1, 2, 254, 255}, nil)
    _, err = client.DeleteSecret(ctx, "app/db", &asm.DeleteSecretOptions{RecoveryWindowDays: 7})
    _, err = client.RestoreSecret(ctx, "app/db")
    _, err = client.DeleteSecret(ctx, "app/blob", &asm.DeleteSecretOptions{ForceDeleteWithoutRecovery: true})
    ```

=== "Python"

    ```python
    created = client.create_secret(
        "app/db", {"user": "app", "password": "s3cret"},
        description="database login", tags={"team": "platform"},
    )
    put = client.put_secret_value("app/db", {"user": "app", "password": "rotated"})
    client.put_secret_value("app/db", "candidate", version_stages=["STAGED"])
    client.update_secret("app/db", description="primary database login")
    client.update_secret_version_stage(
        "app/db", "AWSCURRENT",
        move_to_version_id=created.version_id, remove_from_version_id=put.version_id,
    )
    client.create_secret("app/blob", bytes([0, 1, 2, 254, 255]))
    client.delete_secret("app/db", recovery_window_days=7)
    client.restore_secret("app/db")
    client.delete_secret("app/blob", force_delete_without_recovery=True)
    ```

=== "Java"

    ```java
    SecretWriteResult created =
        client.createSecret("app/db", Map.of("user", "app", "password", "s3cret"),
            CreateSecretOptions.builder().description("database login").tags(Map.of("team", "platform")).build());
    PutSecretValueResult put = client.putSecretValue("app/db", Map.of("user", "app", "password", "rotated"));
    client.putSecretValue("app/db", "candidate",
        PutSecretValueOptions.builder().versionStages(List.of("STAGED")).build());
    client.updateSecret("app/db", UpdateSecretOptions.builder().description("primary database login").build());
    client.updateSecretVersionStage("app/db", "AWSCURRENT",
        UpdateSecretVersionStageOptions.builder()
            .moveToVersionId(created.versionId()).removeFromVersionId(put.versionId()).build());
    client.createSecret("app/blob", new byte[] {0, 1, 2, (byte) 254, (byte) 255});
    client.deleteSecret("app/db", DeleteSecretOptions.builder().recoveryWindowDays(7).build());
    client.restoreSecret("app/db");
    client.deleteSecret("app/blob", DeleteSecretOptions.builder().forceDeleteWithoutRecovery(true).build());
    ```
