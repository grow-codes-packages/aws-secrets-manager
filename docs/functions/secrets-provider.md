# Secrets over AWS Secrets Manager

`client.secrets()` returns the [SecretsProvider](../secrets.md) shared by every Grow Codes secrets
SDK, implemented on AWS Secrets Manager. Capabilities: **`write`, `versions`, `delete`**.
`close()` of the client stops the provider's watchers.

| Primitive | AWS mapping | Notes |
| - | - | - |
| names and paths | `fullName = path ? trim(path, "/") + "/" + name : name` | AWS names are flat strings that may contain `/`; an ARN works as a name |
| `get(name, {version})` | `GetSecretValue(SecretId, VersionId = version)` | `version` is the AWS `VersionId`; stage labels only through the service `getSecretValue`. Missing **or scheduled for deletion** → `null` / `None` / `nil` |
| `getMany(names)` / `getAll(path)` | `BatchGetSecretValue` in chunks of 20 | `getAll` lists `path/` and keeps direct children only (non-recursive). Missing entries are omitted; any other per-secret error is raised |
| `list(prefix)` | `ListSecrets(Filters=[name=prefix])`, all pages | re-filtered client side with `startsWith(prefix)` (AWS's `name` filter also matches word prefixes) and sorted by name; metadata comes from the list entries |
| `set(name, value, {description, tags})` | `PutSecretValue`, on `NOT_FOUND` → `CreateSecret`, on a create race → `PutSecretValue` again | returns the new `VersionId`. UTF-8 bytes → `SecretString`, other bytes → `SecretBinary`, objects → JSON. On an existing secret `tags` → `TagResource`, `description` → `UpdateSecret`. `cas` → `VALIDATION` (AWS has no compare-and-set) |
| `delete(name, {permanent})` | `DescribeSecret` (missing or already scheduled → `NOT_FOUND`), then `DeleteSecret` | `permanent: true` → `ForceDeleteWithoutRecovery`; otherwise `RecoveryWindowInDays = recoveryWindowDays` (provider option, default the config's `recoveryWindowDays` = 30). `versions` → `VALIDATION` (AWS cannot delete one version; use `updateSecretVersionStage`) |
| `metadata(name)` | `DescribeSecret` | `version` = the version labelled `AWSCURRENT`, `createdAt`, `updatedAt` = `LastChangedDate`, `tags`, `versions` = number of versions with a stage, `extra`: `arn`, `description`, `kmsKeyId`, `rotationEnabled`, `nextRotationDate`, `deletedDate`, `primaryRegion` |

A name deleted with a recovery window cannot be re-created until it is restored
(`restoreSecret`) or the window ends — use `permanent: true` for throw-away names.

=== "TypeScript"

    ```ts
    const p = client.secrets({ recoveryWindowDays: 7 });
    const version = await p.set("app/db/password", "s3cret", { tags: { team: "platform" } });
    const pw = await p.require("app/db/password");
    const port = await p.getNumber("port", { path: "app/db" });
    const all = await p.getAll("app/db");
    const names = (await p.list("app/")).map((m) => m.name);
    await p.delete("app/db/password", { permanent: true });
    ```

=== "Rust"

    ```rust
    use grow_aws_secrets_manager::secrets::{DeleteOptions, SecretsProvider};

    let p = client.secrets();
    let version = p.set("app/db/password", "s3cret".into(), None).await?;
    let pw = p.require("app/db/password", None).await?;
    let all = p.get_all(Some("app/db")).await?;
    let names = p.list(Some("app/")).await?;
    p.delete("app/db/password", Some(&DeleteOptions { permanent: true, ..Default::default() })).await?;
    ```

=== "Go"

    ```go
    p, err := client.Secrets(asm.SecretsOptions{RecoveryWindowDays: 7})
    version, err := p.Set(ctx, "app/db/password", "s3cret", nil)
    pw, err := p.Require(ctx, "app/db/password", nil)
    all, err := p.GetAll(ctx, "app/db")
    names, err := p.List(ctx, "app/")
    err = p.Delete(ctx, "app/db/password", &asm.DeleteOptions{Permanent: true})
    ```

=== "Python"

    ```python
    p = client.secrets(recovery_window_days=7)
    version = p.set("app/db/password", "s3cret", tags={"team": "platform"})
    pw = p.require("app/db/password")
    port = p.get_number("port", path="app/db")
    everything = p.get_all("app/db")
    names = [m.name for m in p.list("app/")]
    p.delete("app/db/password", permanent=True)
    ```

=== "Java"

    ```java
    AwsSecretsManagerSecretsProvider p = client.secrets(AwsSecretsManagerSecretsOptions.recoveryWindow(7));
    String version = p.set("app/db/password", "s3cret");
    SecretValue pw = p.require("app/db/password");
    Map<String, SecretValue> all = p.getAll("app/db");
    List<SecretMetadata> names = p.list("app/");
    p.delete("app/db/password", DeleteOptions.builder().permanent(true).build());
    ```
