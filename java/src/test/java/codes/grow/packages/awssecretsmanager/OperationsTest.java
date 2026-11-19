package codes.grow.packages.awssecretsmanager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import codes.grow.packages.awssecretsmanager.core.AwsSecretsManagerException;
import codes.grow.packages.awssecretsmanager.core.ConflictException;
import codes.grow.packages.awssecretsmanager.core.ErrorCode;
import codes.grow.packages.awssecretsmanager.core.NotFoundException;
import codes.grow.packages.awssecretsmanager.core.PermissionDeniedException;
import codes.grow.packages.awssecretsmanager.core.Secret;
import codes.grow.packages.awssecretsmanager.core.UnsupportedException;
import codes.grow.packages.awssecretsmanager.core.ValidationException;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Every service-specific operation against recorded Moto fixtures. */
class OperationsTest {
  private static final String DB = "sdkv-0badc0de/app/db";
  private AwsMock mock;
  private AwsSecretsManagerClient client;

  @BeforeEach
  void start() {
    mock = new AwsMock();
    client = mock.client();
  }

  @AfterEach
  void stop() {
    client.close();
    mock.close();
  }

  @Test
  void getSecretValueStringBinaryVersionAndStage() {
    mock.fixture("getSecretValue.ok-string").fixture("getSecretValue.ok-binary");
    mock.fixture("getSecretValue.ok-version-id").fixture("getSecretValue.ok-version-stage");
    AwsSecretValue s = client.getSecretValue(DB);
    assertThat(s.binary()).isFalse();
    assertThat(s.value().reveal()).isEqualTo("hello-0badc0de");
    assertThat(s.versionStages()).containsExactly("AWSCURRENT");
    assertThat(s.createdDate()).isNotNull();
    assertThat(s.value().version()).contains(s.versionId());
    assertThat(s.toString()).doesNotContain("hello-0badc0de");
    AwsSecretValue b = client.getSecretValue("sdkv-0badc0de/app/blob");
    assertThat(b.binary()).isTrue();
    assertThat(b.value().revealBytes()).containsExactly(0, 1, 2, 0xfe, 0xff);
    client.getSecretValue(DB, GetSecretValueOptions.ofVersionId("v-id"));
    assertThat(mock.last("GetSecretValue").get("VersionId").asText()).isEqualTo("v-id");
    client.getSecretValue(DB, GetSecretValueOptions.ofVersionStage("AWSPREVIOUS"));
    assertThat(mock.last("GetSecretValue").get("VersionStage").asText()).isEqualTo("AWSPREVIOUS");
    assertThat(mock.last("GetSecretValue").has("VersionId")).isFalse();
  }

  @Test
  void getSecretValueErrors() {
    mock.fixture("getSecretValue.not-found").fixture("getSecretValue.marked-deleted");
    mock.fixture("getSecretValue.version-not-found").fixture("getSecretValue.no-version");
    assertThatThrownBy(() -> client.getSecretValue("x"))
        .isInstanceOf(NotFoundException.class)
        .satisfies(
            e -> {
              AwsSecretsManagerException ex = (AwsSecretsManagerException) e;
              assertThat(ex.httpStatus()).hasValue(404);
              assertThat(ex.requestId()).isPresent();
              assertThat(ex.getMessage()).startsWith("getSecretValue x: ResourceNotFoundException");
            });
    assertThatThrownBy(() -> client.getSecretValue("x")).isInstanceOf(ConflictException.class);
    assertThatThrownBy(() -> client.getSecretValue("x")).isInstanceOf(NotFoundException.class);
    assertThatThrownBy(() -> client.getSecretValue("x")).isInstanceOf(NotFoundException.class);
    assertThatThrownBy(() -> client.getSecretValue(" ")).isInstanceOf(ValidationException.class);
    assertThatThrownBy(() -> client.getSecretValue(null)).isInstanceOf(ValidationException.class);
  }

  @Test
  void getJsonField() {
    for (int i = 0; i < 5; i++) {
      mock.fixture("getSecretValue.json-seed");
    }
    String seed = "grow-bootstrap/seed-json";
    assertThat(client.getJsonField(seed, "username"))
        .hasValueSatisfying(n -> assertThat(n.asText()).isEqualTo("seed-user"));
    assertThat(client.getJsonField(seed, "port").map(JsonNode::asInt)).contains(5432);
    assertThat(client.getJsonField(seed, "enabled").map(JsonNode::asBoolean)).contains(true);
    assertThat(client.getJsonField(seed, "absent")).isEmpty();
    assertThat(client.getJsonField(seed, "username.deeper")).isEmpty();
    mock.json("GetSecretValue", 200, value("{\"db\":{\"host\":\"h\",\"n\":null},\"a.b\":1}"));
    mock.json("GetSecretValue", 200, value("{\"db\":{\"host\":\"h\",\"n\":null}}"));
    mock.json("GetSecretValue", 200, value("{\"db\":{\"host\":\"h\",\"n\":null}}"));
    assertThat(client.getJsonField("s", "a.b").map(JsonNode::asInt)).contains(1);
    assertThat(
            client.getJsonField("s", "db.host", GetSecretValueOptions.ofVersionStage("AWSCURRENT")))
        .hasValueSatisfying(n -> assertThat(n.asText()).isEqualTo("h"));
    assertThat(client.getJsonField("s", "db.n")).isEmpty();
    mock.fixture("getSecretValue.ok-binary");
    mock.json("GetSecretValue", 200, value("not json"));
    mock.json("GetSecretValue", 200, value("[1,2]"));
    for (int i = 0; i < 3; i++) {
      assertThatThrownBy(() -> client.getJsonField("s", "x"))
          .isInstanceOf(ValidationException.class);
    }
  }

  private static String value(String secretString) {
    return "{\"ARN\":\"arn:aws:secretsmanager:us-east-1:1:secret:s-AbCdEf\",\"Name\":\"s\","
        + "\"VersionId\":\"v1\",\"VersionStages\":[\"AWSCURRENT\"],\"SecretString\":"
        + codes.grow.packages.awssecretsmanager.core.Json.stringify(secretString)
        + "}";
  }

  @Test
  void batchGetByIdsKeepsRequestOrderAndReportsErrors() {
    mock.fixture("batchGetSecretValue.ids-partial");
    BatchGetResult r =
        client.batchGetSecretValue(List.of("sdkv-0badc0de/app/blob", "sdkv-0badc0de/missing", DB));
    assertThat(r.secretValues())
        .extracting(AwsSecretValue::name)
        .containsExactly("sdkv-0badc0de/app/blob", DB);
    assertThat(r.errors()).hasSize(1);
    assertThat(r.errors().get(0).errorCode()).isEqualTo("ResourceNotFoundException");
    assertThat(r.errors().get(0).code()).isEqualTo(ErrorCode.NOT_FOUND);
    assertThat(r.errors().get(0).toString()).doesNotContain("Message");
    assertThat(new BatchGetError(null, "Weird", null).code()).isEqualTo(ErrorCode.UNAVAILABLE);
  }

  @Test
  void batchGetSplitsLongIdListsAndFollowsTokens() {
    List<String> ids = new ArrayList<>();
    IntStream.range(0, 25).forEach(i -> ids.add("s" + i));
    mock.json(
        "BatchGetSecretValue", 200, "{\"SecretValues\":[" + entry("s1") + "],\"NextToken\":\"t\"}");
    mock.json("BatchGetSecretValue", 200, "{\"SecretValues\":[" + entry("s0") + "]}");
    mock.json(
        "BatchGetSecretValue",
        200,
        "{\"SecretValues\":["
            + entry("s24")
            + ",{\"ARN\":\"arn:x:s20-AbCdEf\",\"Name\":\"other\",\"SecretString\":\"x\"}]}");
    BatchGetResult r = client.batchGetSecretValue(ids);
    assertThat(r.secretValues())
        .extracting(AwsSecretValue::name)
        .containsExactly("s0", "s1", "s24", "other");
    List<JsonNode> bodies = mock.bodies("BatchGetSecretValue");
    assertThat(bodies).hasSize(3);
    assertThat(bodies.get(0).get("SecretIdList")).hasSize(20);
    assertThat(bodies.get(1).get("NextToken").asText()).isEqualTo("t");
    assertThat(bodies.get(2).get("SecretIdList")).hasSize(5);
    // order by ARN prefix
    assertThat(
            AwsSecretsManagerClient.orderByIds(
                List.of(
                    Models.secretValue("arn:b-1", "b", null, null, null, "", null),
                    Models.secretValue("arn:a-1", "a", null, null, null, "", null)),
                List.of("arn:a", "b")))
        .extracting(AwsSecretValue::name)
        .containsExactly("a", "b");
  }

  private static String entry(String name) {
    return "{\"ARN\":\"arn:aws:secretsmanager:us-east-1:1:secret:"
        + name
        + "-AbCdEf\",\"Name\":\""
        + name
        + "\",\"VersionId\":\"v\",\"VersionStages\":[\"AWSCURRENT\"],\"SecretString\":\"x\"}";
  }

  @Test
  void batchGetByFiltersPaginates() {
    mock.fixture("batchGetSecretValue.filters").fixture("batchGetSecretValue.filters-page2");
    BatchGetResult r =
        client.batchGetSecretValue(
            BatchGetSelector.filters(SecretFilter.name("sdkv-0badc0de/page/")),
            new BatchGetOptions(2));
    assertThat(r.secretValues()).hasSize(3);
    assertThat(mock.last("BatchGetSecretValue").get("NextToken").asText()).isEqualTo("2");
    assertThat(mock.last("BatchGetSecretValue").get("MaxResults").asInt()).isEqualTo(2);
    assertThatThrownBy(
            () ->
                client.batchGetSecretValue(
                    new BatchGetSelector(List.of("a"), List.of(SecretFilter.name("a"))),
                    BatchGetOptions.none()))
        .isInstanceOf(ValidationException.class);
    assertThatThrownBy(
            () ->
                client.batchGetSecretValue(
                    BatchGetSelector.filters(List.of()), BatchGetOptions.none()))
        .isInstanceOf(ValidationException.class);
    assertThatThrownBy(
            () ->
                client.batchGetSecretValue(
                    new BatchGetSelector(null, null), BatchGetOptions.none()))
        .isInstanceOf(ValidationException.class);
    mock.fixture("batchGetSecretValue.both");
    assertThatThrownBy(() -> client.batchGetSecretValue(BatchGetSelector.ids("a", "b")))
        .isInstanceOf(ValidationException.class);
  }

  @Test
  void describeSecret() {
    mock.fixture("describeSecret.ok").fixture("describeSecret.not-found");
    SecretDescription d = client.describeSecret(DB);
    assertThat(d.description()).isEqualTo("grow sdk verify");
    assertThat(d.tags()).containsEntry("team", "sdk").containsEntry("env", "test");
    assertThat(d.currentVersionId()).contains("73aafff8-79d7-4072-979c-81f2920c7e30");
    assertThat(d.versionWithStage("STAGEX")).contains("013a6645-866f-42f8-9f70-2b4ab862e83a");
    assertThat(d.versionWithStage("NOPE")).isEmpty();
    assertThat(d.rotationEnabled()).isFalse();
    assertThat(d.pendingDeletion()).isFalse();
    assertThat(d.createdDate()).isNotNull();
    assertThatThrownBy(() -> client.describeSecret(DB)).isInstanceOf(NotFoundException.class);
    mock.json(
        "DescribeSecret",
        200,
        "{\"ARN\":\"a\",\"Name\":\"n\",\"RotationEnabled\":true,\"RotationLambdaARN\":\"arn:l\","
            + "\"RotationRules\":{\"AutomaticallyAfterDays\":30,\"Duration\":\"3h\"},"
            + "\"DeletedDate\":1795033095,\"ReplicationStatus\":[{\"Region\":\"eu-west-1\",\"Status\":\"InSync\"}]}");
    SecretDescription r = client.describeSecret("n");
    assertThat(r.rotationRules()).isEqualTo(new RotationRules(30, "3h", null));
    assertThat(r.pendingDeletion()).isTrue();
    assertThat(r.replicationStatus())
        .extracting(ReplicationStatus::status)
        .containsExactly("InSync");
  }

  @Test
  void listSecretsPaginatesLazily() {
    mock.fixture("listSecrets.page1").fixture("listSecrets.page2");
    Paginator<SecretDescription> p =
        client.listSecrets(
            ListSecretsOptions.builder()
                .filters(List.of(SecretFilter.name("sdkv-0badc0de/page/")))
                .maxResults(2)
                .includePlannedDeletion(false)
                .sortOrder("asc")
                .build());
    assertThat(mock.count("ListSecrets")).isZero();
    assertThat(p.toList()).extracting(SecretDescription::name).hasSize(3);
    JsonNode first = mock.bodies("ListSecrets").get(0);
    assertThat(first.get("SortOrder").asText()).isEqualTo("asc");
    assertThat(mock.last("ListSecrets").get("NextToken").asText()).isEqualTo("2");
    mock.fixture("listSecrets.include-planned-deletion");
    List<String> names = new ArrayList<>();
    for (SecretDescription d :
        client.listSecrets(ListSecretsOptions.builder().includePlannedDeletion(true).build())) {
      names.add(d.name());
    }
    assertThat(names).hasSize(3);
    assertThat(mock.last("ListSecrets").has("Filters")).isFalse();
    mock.fixture("listSecrets.filter-word");
    assertThat(client.listSecrets().stream().count()).isZero();
    mock.fixture("listSecrets.bad-filter");
    assertThatThrownBy(
            () ->
                client
                    .listSecrets(
                        ListSecretsOptions.builder()
                            .filters(List.of(SecretFilter.of("bogus", "x")))
                            .build())
                    .toList())
        .isInstanceOf(ValidationException.class);
  }

  @Test
  void listSecretVersionIds() {
    mock.fixture("listSecretVersionIds.ok");
    List<SecretVersion> v =
        client
            .listSecretVersionIds(
                DB, ListSecretVersionIdsOptions.builder().includeDeprecated(true).build())
            .toList();
    assertThat(v).hasSize(4);
    assertThat(v.get(1).versionStages()).containsExactly("AWSCURRENT");
    assertThat(v.get(0).kmsKeyIds()).isEmpty();
    assertThat(mock.last("ListSecretVersionIds").get("IncludeDeprecated").asBoolean()).isTrue();
    mock.json(
        "ListSecretVersionIds", 200, "{\"Versions\":[{\"VersionId\":\"a\"}],\"NextToken\":\"n\"}");
    mock.json(
        "ListSecretVersionIds", 200, "{\"Versions\":[{\"VersionId\":\"b\"}],\"NextToken\":\"n\"}");
    assertThat(client.listSecretVersionIds(DB).toList())
        .extracting(SecretVersion::versionId)
        .containsExactly("a", "b");
    mock.fixture("listSecretVersionIds.not-found-moto-500");
    assertThatThrownBy(() -> client.listSecretVersionIds(DB).toList())
        .isInstanceOf(AwsSecretsManagerException.class)
        .satisfies(
            e ->
                assertThat(((AwsSecretsManagerException) e).code())
                    .isEqualTo(ErrorCode.UNAVAILABLE));
    mock.error("ListSecretVersionIds", 400, "ResourceNotFoundException");
    assertThatThrownBy(() -> client.listSecretVersionIds(DB).toList())
        .isInstanceOf(NotFoundException.class);
  }

  @Test
  void createSecretVariants() {
    mock.fixture("createSecret.ok-string")
        .fixture("createSecret.ok-binary")
        .fixture("createSecret.no-value");
    mock.fixture("createSecret.ok-string")
        .fixture("createSecret.exists")
        .fixture("createSecret.access-denied");
    SecretWriteResult r =
        client.createSecret(
            DB,
            "s3cr3t",
            CreateSecretOptions.builder()
                .description("d")
                .kmsKeyId("alias/k")
                .tags(Map.of("team", "sdk"))
                .clientRequestToken("11111111-1111-4111-8111-11110badc0de")
                .addReplicaRegions(
                    List.of(ReplicaRegion.of("eu-west-1"), new ReplicaRegion("eu-central-1", "k2")))
                .forceOverwriteReplicaSecret(true)
                .build());
    assertThat(r.version()).contains("11111111-1111-4111-8111-11110badc0de");
    JsonNode body = mock.last("CreateSecret");
    assertThat(body.get("SecretString").asText()).isEqualTo("s3cr3t");
    assertThat(body.get("Tags").get(0).get("Key").asText()).isEqualTo("team");
    assertThat(body.get("AddReplicaRegions")).hasSize(2);
    assertThat(body.get("KmsKeyId").asText()).isEqualTo("alias/k");
    client.createSecret("b", new byte[] {7, 0, (byte) 255});
    assertThat(Base64.getDecoder().decode(mock.last("CreateSecret").get("SecretBinary").asText()))
        .containsExactly(7, 0, 255);
    SecretWriteResult empty = client.createSecret("e", null);
    assertThat(empty.version()).isEmpty();
    assertThat(mock.last("CreateSecret").has("SecretString")).isFalse();
    client.createSecret("o", Map.of("a", 1));
    assertThat(mock.last("CreateSecret").get("SecretString").asText()).isEqualTo("{\"a\":1}");
    assertThatThrownBy(() -> client.createSecret("x", "v")).isInstanceOf(ConflictException.class);
    assertThatThrownBy(() -> client.createSecret("x", "v"))
        .isInstanceOf(PermissionDeniedException.class);
    assertThatThrownBy(() -> client.createSecret("x", new Object()))
        .isInstanceOf(ValidationException.class);
  }

  @Test
  void putSecretValueAndVersionStages() {
    mock.fixture("putSecretValue.ok").fixture("putSecretValue.custom-stage");
    mock.fixture("putSecretValue.not-found").fixture("putSecretValue.token-reuse-different");
    PutSecretValueResult r = client.putSecretValue(DB, Secret.of("two"));
    assertThat(r.versionStages()).containsExactly("AWSCURRENT");
    assertThat(mock.last("PutSecretValue").get("SecretString").asText()).isEqualTo("two");
    client.putSecretValue(
        DB,
        "three",
        PutSecretValueOptions.builder()
            .versionStages(List.of("STAGEX"))
            .clientRequestToken("tok-0123456789012345678901234567890")
            .build());
    assertThat(mock.last("PutSecretValue").get("VersionStages").get(0).asText())
        .isEqualTo("STAGEX");
    assertThatThrownBy(() -> client.putSecretValue(DB, "x")).isInstanceOf(NotFoundException.class);
    assertThatThrownBy(() -> client.putSecretValue(DB, "x")).isInstanceOf(ConflictException.class);
    assertThatThrownBy(() -> client.putSecretValue(DB, null))
        .isInstanceOf(ValidationException.class);
    mock.fixture("updateSecretVersionStage.move")
        .fixture("updateSecretVersionStage.promote-current");
    mock.fixture("updateSecretVersionStage.missing-remove");
    assertThat(
            client
                .updateSecretVersionStage(
                    DB,
                    "STAGEZ",
                    UpdateSecretVersionStageOptions.builder().moveToVersionId("v2").build())
                .name())
        .isEqualTo(DB);
    client.updateSecretVersionStage(
        DB, "AWSCURRENT", new UpdateSecretVersionStageOptions("v3", "v2"));
    assertThat(mock.last("UpdateSecretVersionStage").get("RemoveFromVersionId").asText())
        .isEqualTo("v2");
    assertThatThrownBy(
            () ->
                client.updateSecretVersionStage(
                    DB, "AWSCURRENT", new UpdateSecretVersionStageOptions("v3", null)))
        .isInstanceOf(ValidationException.class);
    assertThatThrownBy(
            () -> client.updateSecretVersionStage(DB, "S", UpdateSecretVersionStageOptions.none()))
        .isInstanceOf(ValidationException.class);
  }

  @Test
  void updateSecret() {
    mock.fixture("updateSecret.description")
        .fixture("updateSecret.value")
        .fixture("updateSecret.not-found");
    assertThat(
            client
                .updateSecret(
                    DB, UpdateSecretOptions.builder().description("new").kmsKeyId("k").build())
                .version())
        .isEmpty();
    assertThat(mock.last("UpdateSecret").has("SecretString")).isFalse();
    SecretWriteResult r =
        client.updateSecret(
            DB,
            UpdateSecretOptions.builder()
                .value(Map.of("rotated", true))
                .clientRequestToken("t".repeat(32))
                .build());
    assertThat(r.version()).isPresent();
    assertThat(mock.last("UpdateSecret").get("SecretString").asText())
        .isEqualTo("{\"rotated\":true}");
    assertThatThrownBy(() -> client.updateSecret(DB, UpdateSecretOptions.none()))
        .isInstanceOf(NotFoundException.class);
  }

  @Test
  void deleteAndRestore() {
    mock.fixture("deleteSecret.recovery-window")
        .fixture("deleteSecret.force")
        .fixture("deleteSecret.force-missing");
    mock.fixture("deleteSecret.not-found").fixture("deleteSecret.already-deleted");
    DeleteSecretResult r =
        client.deleteSecret("b", DeleteSecretOptions.builder().recoveryWindowDays(7).build());
    assertThat(r.deletionDate()).isNotNull();
    assertThat(mock.last("DeleteSecret").get("RecoveryWindowInDays").asInt()).isEqualTo(7);
    client.deleteSecret(
        "b", DeleteSecretOptions.builder().forceDeleteWithoutRecovery(true).build());
    assertThat(mock.last("DeleteSecret").get("ForceDeleteWithoutRecovery").asBoolean()).isTrue();
    client.deleteSecret("missing", new DeleteSecretOptions(null, true));
    assertThatThrownBy(() -> client.deleteSecret("x")).isInstanceOf(NotFoundException.class);
    assertThatThrownBy(() -> client.deleteSecret("x")).isInstanceOf(ConflictException.class);
    assertThatThrownBy(() -> client.deleteSecret("x", new DeleteSecretOptions(7, true)))
        .isInstanceOf(ValidationException.class);
    assertThatThrownBy(() -> client.deleteSecret("x", new DeleteSecretOptions(6, null)))
        .isInstanceOf(ValidationException.class);
    assertThatThrownBy(() -> client.deleteSecret("x", new DeleteSecretOptions(31, false)))
        .isInstanceOf(ValidationException.class);
  }

  @Test
  void restore() {
    mock.fixture("restoreSecret.ok")
        .fixture("restoreSecret.not-deleted")
        .fixture("restoreSecret.not-found");
    assertThat(client.restoreSecret("b").name()).isEqualTo("sdkv-0badc0de/app/blob");
    assertThat(client.restoreSecret(DB).arn()).contains("app/db");
    assertThatThrownBy(() -> client.restoreSecret("x")).isInstanceOf(NotFoundException.class);
  }

  @Test
  void tagsAndPolicies() {
    mock.fixture("tagResource.ok")
        .fixture("tagResource.not-found")
        .fixture("untagResource.ok")
        .fixture("untagResource.not-found");
    client.tagResource(DB, Map.of("env", "dev"));
    assertThat(mock.last("TagResource").get("Tags").get(0).get("Value").asText()).isEqualTo("dev");
    assertThatThrownBy(() -> client.tagResource(DB, Map.of()))
        .isInstanceOf(NotFoundException.class);
    client.untagResource(DB, List.of("env"));
    assertThat(mock.last("UntagResource").get("TagKeys").get(0).asText()).isEqualTo("env");
    assertThatThrownBy(() -> client.untagResource(DB, List.of()))
        .isInstanceOf(NotFoundException.class);
    mock.fixture("putResourcePolicy.ok")
        .fixture("putResourcePolicy.malformed-accepted")
        .fixture("putResourcePolicy.not-found");
    Map<String, Object> policy = Map.of("Version", "2012-10-17");
    client.putResourcePolicy(DB, policy, new PutResourcePolicyOptions(true));
    assertThat(mock.last("PutResourcePolicy").get("ResourcePolicy").asText())
        .isEqualTo("{\"Version\":\"2012-10-17\"}");
    assertThat(mock.last("PutResourcePolicy").get("BlockPublicPolicy").asBoolean()).isTrue();
    client.putResourcePolicy(DB, "not json");
    assertThat(mock.last("PutResourcePolicy").get("ResourcePolicy").asText()).isEqualTo("not json");
    assertThatThrownBy(() -> client.putResourcePolicy(DB, "{}"))
        .isInstanceOf(NotFoundException.class);
    assertThatThrownBy(() -> client.putResourcePolicy(DB, null))
        .isInstanceOf(ValidationException.class);
    assertThatThrownBy(() -> client.putResourcePolicy(DB, new Object()))
        .isInstanceOf(ValidationException.class);
    mock.fixture("getResourcePolicy.ok").fixture("getResourcePolicy.none");
    ResourcePolicyResult got = client.getResourcePolicy(DB);
    assertThat(got.policyJson())
        .hasValueSatisfying(p -> assertThat(p.get("Version").asText()).isEqualTo("2012-10-17"));
    ResourcePolicyResult none = client.getResourcePolicy(DB);
    assertThat(none.resourcePolicy()).isNull();
    assertThat(none.policyJson()).isEmpty();
    mock.json(
        "GetResourcePolicy", 200, "{\"ARN\":\"a\",\"Name\":\"n\",\"ResourcePolicy\":\"[1]\"}");
    mock.json(
        "GetResourcePolicy", 200, "{\"ARN\":\"a\",\"Name\":\"n\",\"ResourcePolicy\":\"{oops\"}");
    assertThat(client.getResourcePolicy(DB).policy()).isNull();
    assertThat(client.getResourcePolicy(DB).policy()).isNull();
    mock.fixture("deleteResourcePolicy.ok");
    assertThat(client.deleteResourcePolicy(DB).name()).isEqualTo(DB);
  }

  @Test
  void validateResourcePolicy() {
    mock.fixture("validateResourcePolicy.moto-unsupported");
    assertThatThrownBy(() -> client.validateResourcePolicy(Map.of("Version", "2012-10-17")))
        .isInstanceOf(UnsupportedException.class);
    mock.json(
        "ValidateResourcePolicy",
        200,
        "{\"PolicyValidationPassed\":false,\"ValidationErrors\":[{\"CheckName\":\"c\",\"ErrorMessage\":\"m\"}]}");
    ValidateResourcePolicyResult r =
        client.validateResourcePolicy("{}", new ValidateResourcePolicyOptions(DB));
    assertThat(r.policyValidationPassed()).isFalse();
    assertThat(r.validationErrors()).containsExactly(new PolicyValidationError("c", "m"));
    assertThat(mock.last("ValidateResourcePolicy").get("SecretId").asText()).isEqualTo(DB);
    mock.error("ValidateResourcePolicy", 400, "MalformedPolicyDocumentException");
    assertThatThrownBy(() -> client.validateResourcePolicy("x"))
        .isInstanceOf(ValidationException.class);
  }

  @Test
  void rotation() {
    mock.fixture("rotateSecret.rules-only").fixture("rotateSecret.lambda-not-found");
    SecretWriteResult r =
        client.rotateSecret(
            DB, RotateSecretOptions.builder().rules(RotationRules.everyDays(30)).build());
    assertThat(r.versionId()).isNotNull();
    assertThat(mock.last("RotateSecret").get("RotationRules").get("AutomaticallyAfterDays").asInt())
        .isEqualTo(30);
    assertThatThrownBy(
            () ->
                client.rotateSecret(
                    DB,
                    RotateSecretOptions.builder()
                        .lambdaArn("arn:aws:lambda:us-east-1:123456789012:function:grow-rotate")
                        .rules(RotationRules.schedule("rate(10 days)"))
                        .rotateImmediately(false)
                        .clientRequestToken("c".repeat(32))
                        .build()))
        .isInstanceOf(NotFoundException.class);
    JsonNode body = mock.last("RotateSecret");
    assertThat(body.get("RotationLambdaARN").asText()).endsWith("grow-rotate");
    assertThat(body.get("RotationRules").get("ScheduleExpression").asText())
        .isEqualTo("rate(10 days)");
    mock.json("RotateSecret", 200, "{\"ARN\":\"a\",\"Name\":\"n\"}");
    assertThat(client.rotateSecret(DB, RotateSecretOptions.none()).version()).isEmpty();
    assertThat(mock.last("RotateSecret").has("RotationRules")).isFalse();
    mock.error("RotateSecret", 400, "InvalidRequestException");
    assertThatThrownBy(() -> client.rotateSecret(DB, RotateSecretOptions.none()))
        .isInstanceOf(ConflictException.class);
    mock.fixture("cancelRotateSecret.ok").fixture("cancelRotateSecret.not-found");
    assertThat(client.cancelRotateSecret(DB).versionId()).isNotNull();
    assertThatThrownBy(() -> client.cancelRotateSecret(DB)).isInstanceOf(NotFoundException.class);
  }

  @Test
  void randomPassword() {
    mock.fixture("getRandomPassword.ok")
        .fixture("getRandomPassword.exclude-chars")
        .fixture("getRandomPassword.too-short");
    Secret p = client.getRandomPassword();
    assertThat(p.reveal()).isEqualTo("BiYPTvM2E89ybngdA5jYmzN8");
    assertThat(p.toString()).doesNotContain(p.reveal());
    assertThat(mock.last("GetRandomPassword").get("PasswordLength").asInt()).isEqualTo(32);
    client.getRandomPassword(
        RandomPasswordOptions.builder()
            .length(40)
            .excludeCharacters("abc")
            .excludeNumbers(false)
            .excludePunctuation(true)
            .excludeUppercase(false)
            .excludeLowercase(false)
            .includeSpace(false)
            .requireEachIncludedType(true)
            .build());
    JsonNode body = mock.last("GetRandomPassword");
    assertThat(body.get("PasswordLength").asInt()).isEqualTo(40);
    assertThat(body.get("ExcludeCharacters").asText()).isEqualTo("abc");
    assertThatThrownBy(
            () -> client.getRandomPassword(RandomPasswordOptions.builder().length(2).build()))
        .isInstanceOf(ValidationException.class);
    mock.json("GetRandomPassword", 200, "{}");
    assertThat(client.getRandomPassword().reveal()).isEmpty();
  }

  @Test
  void optionsToBuilderRoundTrips() {
    CreateSecretOptions c =
        CreateSecretOptions.builder().description("d").tags(Map.of("a", "b")).build();
    assertThat(c.toBuilder().build()).isEqualTo(c);
    assertThat(
            GetSecretValueOptions.builder().versionId("v").versionStage("s").build().toBuilder()
                .build()
                .versionStage())
        .isEqualTo("s");
    assertThat(RandomPasswordOptions.none().length()).isNull();
    assertThat(ListSecretVersionIdsOptions.none().toBuilder().maxResults(5).build().maxResults())
        .isEqualTo(5);
    assertThat(BatchGetOptions.builder().maxResults(3).build().toBuilder().build().maxResults())
        .isEqualTo(3);
    assertThat(PutSecretValueOptions.none().toBuilder().build().versionStages()).isNull();
    assertThat(UpdateSecretOptions.none().toBuilder().build())
        .isEqualTo(UpdateSecretOptions.none());
    assertThat(
            UpdateSecretVersionStageOptions.builder().removeFromVersionId("r").build().toBuilder()
                .build()
                .removeFromVersionId())
        .isEqualTo("r");
    assertThat(DeleteSecretOptions.none().toBuilder().build())
        .isEqualTo(DeleteSecretOptions.none());
    assertThat(
            PutResourcePolicyOptions.builder().blockPublicPolicy(false).build().toBuilder()
                .build()
                .blockPublicPolicy())
        .isFalse();
    assertThat(
            ValidateResourcePolicyOptions.builder().secretId("s").build().toBuilder()
                .build()
                .secretId())
        .isEqualTo("s");
    assertThat(RotateSecretOptions.none().toBuilder().build())
        .isEqualTo(RotateSecretOptions.none());
    assertThat(ListSecretsOptions.none().toBuilder().build()).isEqualTo(ListSecretsOptions.none());
    assertThat(RandomPasswordOptions.none().toBuilder().build())
        .isEqualTo(RandomPasswordOptions.none());
    assertThat(AwsSecretsManagerSecretsOptions.recoveryWindow(7).recoveryWindowDays()).isEqualTo(7);
    assertThat(SecretFilter.of(SecretFilter.TAG_KEY, "k").values()).containsExactly("k");
  }
}
