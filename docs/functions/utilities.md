# Utilities

| Function | Implementation | Notes |
| - | - | - |
| `getRandomPassword({length = 32, excludeCharacters?, excludeNumbers?, excludePunctuation?, excludeUppercase?, excludeLowercase?, includeSpace?, requireEachIncludedType?})` | `GetRandomPassword` | returns the redacting `Secret` (`reveal()` for the text). `length` 1–4096; `requireEachIncludedType` defaults to `true` on AWS. A length too short for the required types → `VALIDATION`. The password may contain `"` and `\` |
| `getJsonField(id, field, {versionId?, versionStage?})` | `GetSecretValue` + JSON parse | `field` is an exact top-level key first, otherwise a dot path (`"db.host"`). Absent or JSON `null` → `null` / `None` / `Optional.empty()` / Go `ok == false`; binary secret or a value that is not a JSON object → `VALIDATION`; missing secret → `NOT_FOUND` |

=== "TypeScript"

    ```ts
    const password = await client.getRandomPassword({ length: 24, excludePunctuation: true });
    await client.createSecret("app/db", { user: "app", password: password.reveal(), db: { host: "db.internal", port: 5432 } });
    const host = await client.getJsonField("app/db", "db.host"); // "db.internal"
    const old = await client.getJsonField("app/db", "password", { versionStage: "AWSPREVIOUS" });
    ```

=== "Rust"

    ```rust
    use grow_aws_secrets_manager::models::{GetSecretValueOptions, RandomPasswordOptions};

    let password = client
        .get_random_password(RandomPasswordOptions { length: Some(24), exclude_punctuation: Some(true), ..Default::default() })
        .await?;
    let host = client.get_json_field("app/db", "db.host", GetSecretValueOptions::default()).await?; // Some(Value)
    ```

=== "Go"

    ```go
    password, err := client.GetRandomPassword(ctx, &asm.RandomPasswordOptions{Length: 24, ExcludePunctuation: true})
    _, err = client.CreateSecret(ctx, "app/db", map[string]any{"user": "app", "password": password.Reveal()}, nil)
    host, ok, err := client.GetJSONField(ctx, "app/db", "db.host", nil)
    ```

=== "Python"

    ```python
    password = client.get_random_password(length=24, exclude_punctuation=True)
    client.create_secret("app/db", {"user": "app", "password": password.reveal(), "db": {"host": "db.internal"}})
    host = client.get_json_field("app/db", "db.host")  # "db.internal" or None
    ```

=== "Java"

    ```java
    Secret password =
        client.getRandomPassword(RandomPasswordOptions.builder().length(24).excludePunctuation(true).build());
    Optional<JsonNode> host = client.getJsonField("app/db", "db.host");
    ```
