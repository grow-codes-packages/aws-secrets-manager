# Read

Read values and metadata. `secretId` is a secret name or ARN everywhere. Values are always wrapped
in the redacting `SecretValue` (`reveal()` / `revealBytes()` return the plain value).

| Function | AWS operation | Notes |
| - | - | - |
| `getSecretValue(id, {versionId?, versionStage?})` | `GetSecretValue` | default stage `AWSCURRENT`. Returns `{arn, name, versionId, versionStages, createdDate, binary, value}`; `binary` is true for `SecretBinary`. Missing secret, version, stage or a secret without any value → `NOT_FOUND`; a secret scheduled for deletion → `CONFLICT` (`InvalidRequestException`) |
| `batchGetSecretValue(ids \| filters, {maxResults?})` | `BatchGetSecretValue` | ids: lists longer than 20 are split into several calls and the values come back **in request order**; filters: every page is read (`maxResults` = page size, 1–20). Per-secret failures are returned in `errors` (`{secretId, errorCode, message}`), the call itself succeeds |
| `describeSecret(id)` | `DescribeSecret` | metadata only: description, KMS key, rotation settings, dates (`deletedDate` when scheduled for deletion), tags as a map, `versionIdsToStages`, primary region, replication status |
| `listSecrets({filters?, includePlannedDeletion?, sortOrder?, maxResults?})` | `ListSecrets` | lazy paginator over all pages (`maxResults` = page size, ≤ 100). Filter keys `name`, `description`, `tag-key`, `tag-value`, `primary-region`, `owning-service`, `all`; a value prefixed `!` negates it. AWS's `name` filter also matches word prefixes inside names |
| `listSecretVersionIds(id, {includeDeprecated?, maxResults?})` | `ListSecretVersionIds` | lazy paginator of `{versionId, versionStages, createdDate, lastAccessedDate, kmsKeyIds}` |

Stage constants: `AWSCURRENT`, `AWSPREVIOUS`, `AWSPENDING` (Go `StageCurrent`, `StagePrevious`,
`StagePending`). The end of a list is an absent, `null` **or empty** `NextToken`.

=== "TypeScript"

    ```ts
    const s = await client.getSecretValue("app/db");
    const prev = await client.getSecretValue("app/db", { versionStage: "AWSPREVIOUS" });
    console.log(s.versionId, s.versionStages, s.binary, s.value.reveal());

    const batch = await client.batchGetSecretValue(["app/db", "app/api", "app/missing"]);
    const tagged = await client.batchGetSecretValue({ filters: [{ key: "tag-key", values: ["team"] }] });
    console.log(batch.secretValues.length, batch.errors); // [{ secretId: "app/missing", errorCode: "ResourceNotFoundException", … }]

    const d = await client.describeSecret("app/db");
    for await (const meta of client.listSecrets({ filters: [{ key: "name", values: ["app/"] }] })) {
      console.log(meta.name, meta.tags);
    }
    const versions = await client.listSecretVersionIds("app/db", { includeDeprecated: true }).toArray();
    ```

=== "Rust"

    ```rust
    use grow_aws_secrets_manager::models::{
        GetSecretValueOptions, ListSecretVersionIdsOptions, ListSecretsOptions, SecretFilter,
    };

    let s = client.get_secret_value("app/db", GetSecretValueOptions::default()).await?;
    let prev = client
        .get_secret_value("app/db", GetSecretValueOptions { version_stage: Some("AWSPREVIOUS".into()), ..Default::default() })
        .await?;
    println!("{:?} {:?} {}", s.version_id, s.version_stages, s.binary);

    let batch = client.batch_get_secret_value(["app/db", "app/api", "app/missing"], Default::default()).await?;
    let tagged = client.batch_get_secret_value(vec![SecretFilter::tag_key("team")], Default::default()).await?;

    let d = client.describe_secret("app/db").await?;
    let mut pages = client.list_secrets(ListSecretsOptions { filters: vec![SecretFilter::name("app/")], ..Default::default() });
    while let Some(meta) = pages.next().await? {
        println!("{} {:?}", meta.name, meta.tags);
    }
    let versions = client
        .list_secret_version_ids("app/db", ListSecretVersionIdsOptions { include_deprecated: Some(true), ..Default::default() })
        .try_collect()
        .await?;
    ```

=== "Go"

    ```go
    s, err := client.GetSecretValue(ctx, "app/db", nil)
    prev, err := client.GetSecretValue(ctx, "app/db", &asm.GetSecretValueOptions{VersionStage: asm.StagePrevious})
    fmt.Println(s.VersionID, s.VersionStages, s.Binary, s.Value.Reveal())

    batch, err := client.BatchGetSecretValue(ctx, asm.BatchGetSelector{SecretIDs: []string{"app/db", "app/api", "app/missing"}}, nil)
    tagged, err := client.BatchGetSecretValue(ctx, asm.BatchGetSelector{
        Filters: []asm.SecretFilter{{Key: asm.FilterTagKey, Values: []string{"team"}}},
    }, nil)

    d, err := client.DescribeSecret(ctx, "app/db")
    for meta, err := range client.ListSecrets(ctx, &asm.ListSecretsOptions{
        Filters: []asm.SecretFilter{{Key: asm.FilterName, Values: []string{"app/"}}},
    }) {
        if err != nil {
            return err
        }
        fmt.Println(meta.Name, meta.Tags)
    }
    for v, err := range client.ListSecretVersionIDs(ctx, "app/db", &asm.ListSecretVersionIDsOptions{IncludeDeprecated: true}) {
        if err != nil {
            return err
        }
        fmt.Println(v.VersionID, v.VersionStages)
    }
    ```

=== "Python"

    ```python
    import grow_aws_secrets_manager as sdk

    s = client.get_secret_value("app/db")
    prev = client.get_secret_value("app/db", version_stage=sdk.AWSPREVIOUS)
    print(s.version_id, s.version_stages, s.binary, s.value.reveal())

    batch = client.batch_get_secret_value(["app/db", "app/api", "app/missing"])
    tagged = client.batch_get_secret_value(filters=[sdk.SecretFilter("tag-key", ["team"])])

    d = client.describe_secret("app/db")
    for meta in client.list_secrets(filters=[sdk.SecretFilter("name", ["app/"])]):
        print(meta.name, dict(meta.tags))
    versions = client.list_secret_version_ids("app/db", include_deprecated=True).to_list()
    ```

=== "Java"

    ```java
    AwsSecretValue s = client.getSecretValue("app/db");
    AwsSecretValue prev = client.getSecretValue("app/db", GetSecretValueOptions.ofVersionStage("AWSPREVIOUS"));
    System.out.println(s.versionId() + " " + s.versionStages() + " " + s.binary());

    BatchGetResult batch = client.batchGetSecretValue(List.of("app/db", "app/api", "app/missing"));
    BatchGetResult tagged =
        client.batchGetSecretValue(BatchGetSelector.filters(SecretFilter.of(SecretFilter.TAG_KEY, "team")));

    SecretDescription d = client.describeSecret("app/db");
    for (SecretDescription meta :
        client.listSecrets(ListSecretsOptions.builder().filters(List.of(SecretFilter.name("app/"))).build())) {
      System.out.println(meta.name() + " " + meta.tags());
    }
    List<SecretVersion> versions =
        client.listSecretVersionIds("app/db", ListSecretVersionIdsOptions.builder().includeDeprecated(true).build())
            .toList();
    ```
