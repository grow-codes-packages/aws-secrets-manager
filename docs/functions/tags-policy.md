# Tags and resource policy

| Function | AWS operation | Notes |
| - | - | - |
| `tagResource(id, tags)` | `TagResource` | adds or replaces tags given as a map |
| `untagResource(id, keys)` | `UntagResource` | removes tags by key |
| `putResourcePolicy(id, policy, {blockPublicPolicy?})` | `PutResourcePolicy` | `policy` is a JSON string or an object (JSON-encoded by the SDK). Returns `{arn, name}`. AWS: `MalformedPolicyDocumentException` / `PublicPolicyException` → `VALIDATION` |
| `getResourcePolicy(id)` | `GetResourcePolicy` | `{arn, name, resourcePolicy?, policy?}`: the JSON text and the parsed object; both absent when the secret has no policy |
| `deleteResourcePolicy(id)` | `DeleteResourcePolicy` | returns `{arn, name}` |
| `validateResourcePolicy(policy, {secretId?})` | `ValidateResourcePolicy` | IAM Access Analyzer check: `{policyValidationPassed, validationErrors[{checkName, errorMessage}]}`. **Moto 5.2.4 does not implement it** (HTTP 500 HTML) → the SDK raises `UNSUPPORTED` for that answer; the AWS result is unit-tested |

=== "TypeScript"

    ```ts
    await client.tagResource("app/db", { team: "platform", env: "prod" });
    await client.untagResource("app/db", ["env"]);
    const policy = {
      Version: "2012-10-17",
      Statement: [{ Effect: "Allow", Principal: { AWS: "arn:aws:iam::123456789012:role/app" },
        Action: "secretsmanager:GetSecretValue", Resource: "*" }],
    };
    await client.putResourcePolicy("app/db", policy, { blockPublicPolicy: true });
    const { resourcePolicy, policy: parsed } = await client.getResourcePolicy("app/db");
    const check = await client.validateResourcePolicy(policy, { secretId: "app/db" });
    await client.deleteResourcePolicy("app/db");
    ```

=== "Rust"

    ```rust
    use grow_aws_secrets_manager::models::{PutResourcePolicyOptions, ValidateResourcePolicyOptions};

    client.tag_resource("app/db", [("team", "platform"), ("env", "prod")]).await?;
    client.untag_resource("app/db", ["env"]).await?;
    let policy = serde_json::json!({"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::123456789012:role/app"},
        "Action": "secretsmanager:GetSecretValue", "Resource": "*"}]});
    client
        .put_resource_policy("app/db", policy.clone(), PutResourcePolicyOptions { block_public_policy: Some(true) })
        .await?;
    let current = client.get_resource_policy("app/db").await?; // resource_policy, policy
    let check = client
        .validate_resource_policy(policy, ValidateResourcePolicyOptions { secret_id: Some("app/db".into()) })
        .await?;
    client.delete_resource_policy("app/db").await?;
    ```

=== "Go"

    ```go
    err := client.TagResource(ctx, "app/db", map[string]string{"team": "platform", "env": "prod"})
    err = client.UntagResource(ctx, "app/db", []string{"env"})
    policy := map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{
        "Effect": "Allow", "Principal": map[string]any{"AWS": "arn:aws:iam::123456789012:role/app"},
        "Action": "secretsmanager:GetSecretValue", "Resource": "*"}}}
    _, err = client.PutResourcePolicy(ctx, "app/db", policy, &asm.PutResourcePolicyOptions{BlockPublicPolicy: aws.Bool(true)})
    current, err := client.GetResourcePolicy(ctx, "app/db") // ResourcePolicy, Policy
    check, err := client.ValidateResourcePolicy(ctx, policy, &asm.ValidateResourcePolicyOptions{SecretID: "app/db"})
    _, err = client.DeleteResourcePolicy(ctx, "app/db")
    ```

=== "Python"

    ```python
    client.tag_resource("app/db", {"team": "platform", "env": "prod"})
    client.untag_resource("app/db", ["env"])
    policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::123456789012:role/app"},
        "Action": "secretsmanager:GetSecretValue", "Resource": "*"}]}
    client.put_resource_policy("app/db", policy, block_public_policy=True)
    current = client.get_resource_policy("app/db")  # .resource_policy, .policy
    check = client.validate_resource_policy(policy, secret_id="app/db")
    client.delete_resource_policy("app/db")
    ```

=== "Java"

    ```java
    client.tagResource("app/db", Map.of("team", "platform", "env", "prod"));
    client.untagResource("app/db", List.of("env"));
    Map<String, Object> policy = Map.of("Version", "2012-10-17", "Statement", List.of(Map.of(
        "Effect", "Allow", "Principal", Map.of("AWS", "arn:aws:iam::123456789012:role/app"),
        "Action", "secretsmanager:GetSecretValue", "Resource", "*")));
    client.putResourcePolicy("app/db", policy, PutResourcePolicyOptions.builder().blockPublicPolicy(true).build());
    ResourcePolicyResult current = client.getResourcePolicy("app/db");
    ValidateResourcePolicyResult check =
        client.validateResourcePolicy(policy, ValidateResourcePolicyOptions.builder().secretId("app/db").build());
    client.deleteResourcePolicy("app/db");
    ```
