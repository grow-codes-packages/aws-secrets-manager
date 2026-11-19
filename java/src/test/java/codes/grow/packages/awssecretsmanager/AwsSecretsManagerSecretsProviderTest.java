package codes.grow.packages.awssecretsmanager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import codes.grow.packages.awssecretsmanager.core.ConflictException;
import codes.grow.packages.awssecretsmanager.core.Json;
import codes.grow.packages.awssecretsmanager.core.NotFoundException;
import codes.grow.packages.awssecretsmanager.core.PermissionDeniedException;
import codes.grow.packages.awssecretsmanager.core.ValidationException;
import codes.grow.packages.awssecretsmanager.secrets.DeleteOptions;
import codes.grow.packages.awssecretsmanager.secrets.GetOptions;
import codes.grow.packages.awssecretsmanager.secrets.SecretMetadata;
import codes.grow.packages.awssecretsmanager.secrets.SecretValue;
import codes.grow.packages.awssecretsmanager.secrets.SetOptions;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** The SecretsProvider mapping (API.md section 3) against an AWS JSON mock. */
class AwsSecretsManagerSecretsProviderTest {
  private AwsMock mock;
  private AwsSecretsManagerClient client;
  private AwsSecretsManagerSecretsProvider p;

  @BeforeEach
  void start() {
    mock = new AwsMock();
    client = mock.client();
    p = client.secrets();
  }

  @AfterEach
  void stop() {
    client.close();
    mock.close();
  }

  private static String value(String name, String version, String secret) {
    return "{\"ARN\":\"arn:aws:secretsmanager:us-east-1:1:secret:"
        + name
        + "-AbCdEf\",\"Name\":\""
        + name
        + "\",\"VersionId\":\""
        + version
        + "\",\"VersionStages\":[\"AWSCURRENT\"],\"SecretString\":"
        + Json.stringify(secret)
        + "}";
  }

  private static String listEntry(String name, boolean deleted) {
    return "{\"ARN\":\"arn:aws:secretsmanager:us-east-1:1:secret:"
        + name
        + "-AbCdEf\",\"Name\":\""
        + name
        + "\",\"CreatedDate\":1795033095,\"LastChangedDate\":1795033096,"
        + "\"Tags\":[{\"Key\":\"a\",\"Value\":\"1\"}],"
        + (deleted ? "\"DeletedDate\":1795033097," : "")
        + "\"SecretVersionsToStages\":{\"v1\":[\"AWSCURRENT\"]}}";
  }

  @Test
  void getWithPathAndVersionAndMissing() {
    mock.json("GetSecretValue", 200, value("app/db", "v2", "two"));
    mock.json("GetSecretValue", 200, value("app/db", "v1", "one"));
    mock.error("GetSecretValue", 400, "ResourceNotFoundException");
    mock.error("GetSecretValue", 400, "InvalidRequestException");
    mock.error("GetSecretValue", 400, "ResourceExistsException");
    mock.error("GetSecretValue", 400, "AccessDeniedException");
    assertThat(p.getString("db", GetOptions.builder().path("/app/").build())).contains("two");
    assertThat(mock.last("GetSecretValue").get("SecretId").asText()).isEqualTo("app/db");
    SecretValue v1 = p.require("app/db", GetOptions.builder().version("v1").build());
    assertThat(v1.version()).contains("v1");
    assertThat(mock.last("GetSecretValue").get("VersionId").asText()).isEqualTo("v1");
    assertThat(p.get("missing")).isEmpty();
    assertThat(p.exists("deleted")).isFalse();
    assertThatThrownBy(() -> p.get("conflict")).isInstanceOf(ConflictException.class);
    assertThatThrownBy(() -> p.get("denied")).isInstanceOf(PermissionDeniedException.class);
    assertThat(AwsSecretsManagerSecretsProvider.fullName("x", "")).isEqualTo("x");
    assertThat(AwsSecretsManagerSecretsProvider.fullName("x", "//")).isEqualTo("x");
    assertThat(p.client()).isSameAs(client);
    assertThat(p.recoveryWindowDays()).isEqualTo(30);
  }

  @Test
  void listFiltersByStringPrefixAndSkipsDeleted() {
    mock.json(
        "ListSecrets",
        200,
        "{\"SecretList\":["
            + listEntry("app/b", false)
            + ","
            + listEntry("app/a", false)
            + ","
            + listEntry("app/gone", true)
            + ","
            + listEntry("other/app/x", false)
            + "]}");
    List<SecretMetadata> list = p.list("app/");
    assertThat(list).extracting(SecretMetadata::name).containsExactly("app/a", "app/b");
    assertThat(list.get(0).path()).contains("app");
    assertThat(list.get(0).version()).contains("v1");
    assertThat(list.get(0).tags()).containsEntry("a", "1");
    assertThat(list.get(0).createdAt()).isPresent();
    assertThat(list.get(0).updatedAt()).isPresent();
    JsonNode body = mock.last("ListSecrets");
    assertThat(body.get("Filters").get(0).get("Values").get(0).asText()).isEqualTo("app/");
    mock.json("ListSecrets", 200, "{\"SecretList\":[" + listEntry("root", false) + "]}");
    assertThat(p.list()).extracting(SecretMetadata::name).containsExactly("root");
    assertThat(mock.last("ListSecrets").has("Filters")).isFalse();
  }

  @Test
  void getAllIsNonRecursiveAndUsesBatchGet() {
    mock.json(
        "ListSecrets",
        200,
        "{\"SecretList\":["
            + listEntry("env/user", false)
            + ","
            + listEntry("env/nested/deep", false)
            + ","
            + listEntry("env/pass", false)
            + "]}");
    mock.json(
        "BatchGetSecretValue",
        200,
        "{\"SecretValues\":["
            + value("env/user", "v", "u")
            + ","
            + value("env/pass", "v", "pw")
            + "]}");
    Map<String, SecretValue> all = p.getAll("/env/");
    assertThat(all.keySet()).containsExactly("env/pass", "env/user");
    assertThat(mock.last("BatchGetSecretValue").get("SecretIdList").toString())
        .isEqualTo("[\"env/pass\",\"env/user\"]");
    mock.json("ListSecrets", 200, "{\"SecretList\":[" + listEntry("top", false) + "]}");
    mock.json("BatchGetSecretValue", 200, "{\"SecretValues\":[" + value("top", "v", "t") + "]}");
    assertThat(p.getAll(null)).containsOnlyKeys("top");
  }

  @Test
  void getManyOrdersSkipsMissingAndRaisesOtherErrors() {
    mock.json(
        "BatchGetSecretValue",
        200,
        "{\"SecretValues\":["
            + value("b", "v", "B")
            + ","
            + value("a", "v", "A")
            + "],"
            + "\"Errors\":[{\"SecretId\":\"gone\",\"ErrorCode\":\"ResourceNotFoundException\"},"
            + "{\"SecretId\":\"del\",\"ErrorCode\":\"InvalidRequestException\"}]}");
    Map<String, SecretValue> many = p.getMany(List.of("a", "gone", "b", "a", "del"));
    assertThat(many.keySet()).containsExactly("a", "b");
    mock.json(
        "BatchGetSecretValue",
        200,
        "{\"SecretValues\":[],\"Errors\":[{\"SecretId\":\"x\",\"ErrorCode\":\"AccessDeniedException\"}]}");
    assertThatThrownBy(() -> p.getMany(List.of("x"))).isInstanceOf(PermissionDeniedException.class);
    mock.json("BatchGetSecretValue", 200, "{\"SecretValues\":[],\"Errors\":[{}]}");
    assertThatThrownBy(() -> p.getMany(List.of("x")))
        .hasMessageContaining("secrets.getMany : error");
    // by ARN, with a path
    mock.json("BatchGetSecretValue", 200, "{\"SecretValues\":[" + value("p/n", "v", "N") + "]}");
    assertThat(p.getMany(List.of("n"), GetOptions.builder().path("p").build()))
        .containsOnlyKeys("n");
    // a version is read per name
    mock.json("GetSecretValue", 200, value("a", "v9", "A9"));
    assertThat(
            p.getMany(List.of("a"), GetOptions.builder().version("v9").build()).get("a").reveal())
        .isEqualTo("A9");
    mock.json("BatchGetSecretValue", 200, "{\"SecretValues\":[" + value("zz", "v", "Z") + "]}");
    assertThat(p.getMany(List.of("q"))).isEmpty();
  }

  @Test
  void setPutsExistingAndUpdatesTagsAndDescription() {
    mock.json(
        "PutSecretValue",
        200,
        "{\"ARN\":\"a\",\"Name\":\"p/db\",\"VersionId\":\"v2\",\"VersionStages\":[\"AWSCURRENT\"]}");
    mock.json("TagResource", 200, "{}");
    mock.json("UpdateSecret", 200, "{\"ARN\":\"a\",\"Name\":\"p/db\"}");
    String v =
        p.set(
            "db", "two", SetOptions.builder().path("p").tag("b", "2").description("desc").build());
    assertThat(v).isEqualTo("v2");
    assertThat(mock.last("PutSecretValue").get("SecretString").asText()).isEqualTo("two");
    assertThat(mock.last("TagResource").get("Tags").get(0).get("Key").asText()).isEqualTo("b");
    assertThat(mock.last("UpdateSecret").get("Description").asText()).isEqualTo("desc");
    // binary
    mock.json(
        "PutSecretValue",
        200,
        "{\"ARN\":\"a\",\"Name\":\"bin\",\"VersionId\":\"v3\",\"VersionStages\":[]}");
    p.set("bin", new byte[] {(byte) 0xff, (byte) 0xfe});
    assertThat(Base64.getDecoder().decode(mock.last("PutSecretValue").get("SecretBinary").asText()))
        .containsExactly(0xff, 0xfe);
    assertThat(mock.count("TagResource")).isEqualTo(1);
  }

  @Test
  void setCreatesMissingSecretsAndHandlesTheCreateRace() {
    mock.error("PutSecretValue", 400, "ResourceNotFoundException");
    mock.json("CreateSecret", 200, "{\"ARN\":\"a\",\"Name\":\"n\",\"VersionId\":\"v1\"}");
    assertThat(
            p.set("n", Map.of("a", 1), SetOptions.builder().tag("t", "1").description("d").build()))
        .isEqualTo("v1");
    JsonNode create = mock.last("CreateSecret");
    assertThat(create.get("SecretString").asText()).isEqualTo("{\"a\":1}");
    assertThat(create.get("Description").asText()).isEqualTo("d");
    assertThat(create.get("Tags")).hasSize(1);
    // race: create says exists -> put again
    mock.error("PutSecretValue", 400, "ResourceNotFoundException");
    mock.error("CreateSecret", 400, "ResourceExistsException");
    mock.json(
        "PutSecretValue",
        200,
        "{\"ARN\":\"a\",\"Name\":\"n\",\"VersionId\":\"v2\",\"VersionStages\":[]}");
    assertThat(p.set("n", "x")).isEqualTo("v2");
    // pending deletion -> InvalidRequestException stays a conflict
    mock.error("PutSecretValue", 400, "ResourceNotFoundException");
    mock.error("CreateSecret", 400, "InvalidRequestException");
    assertThatThrownBy(() -> p.set("n", "x")).isInstanceOf(ConflictException.class);
    mock.error("PutSecretValue", 400, "AccessDeniedException");
    assertThatThrownBy(() -> p.set("n", "x")).isInstanceOf(PermissionDeniedException.class);
    mock.error("PutSecretValue", 400, "ResourceNotFoundException");
    mock.json("CreateSecret", 200, "{\"ARN\":\"a\",\"Name\":\"n\"}");
    assertThat(p.set("n", "x")).isEmpty();
    assertThatThrownBy(() -> p.set("n", "x", SetOptions.builder().cas(1).build()))
        .isInstanceOf(ValidationException.class);
  }

  @Test
  void deleteUsesTheRecoveryWindowOrForceAndChecksExistence() {
    String live = "{\"ARN\":\"a\",\"Name\":\"n\",\"VersionIdsToStages\":{\"v\":[\"AWSCURRENT\"]}}";
    mock.json("DescribeSecret", 200, live);
    mock.json("DeleteSecret", 200, "{\"ARN\":\"a\",\"Name\":\"n\",\"DeletionDate\":1795033097}");
    p.delete("n");
    assertThat(mock.last("DeleteSecret").get("RecoveryWindowInDays").asInt()).isEqualTo(30);
    mock.json("DescribeSecret", 200, live);
    mock.json("DeleteSecret", 200, "{\"ARN\":\"a\",\"Name\":\"n\"}");
    p.delete("n", DeleteOptions.builder().permanent(true).build());
    assertThat(mock.last("DeleteSecret").get("ForceDeleteWithoutRecovery").asBoolean()).isTrue();
    mock.error("DescribeSecret", 400, "ResourceNotFoundException");
    assertThatThrownBy(() -> p.delete("n")).isInstanceOf(NotFoundException.class);
    mock.json("DescribeSecret", 200, "{\"ARN\":\"a\",\"Name\":\"n\",\"DeletedDate\":1795033097}");
    assertThatThrownBy(() -> p.delete("n")).isInstanceOf(NotFoundException.class);
    mock.error("DescribeSecret", 400, "AccessDeniedException");
    assertThatThrownBy(() -> p.delete("n")).isInstanceOf(PermissionDeniedException.class);
    assertThatThrownBy(() -> p.delete("n", DeleteOptions.builder().versions("v1").build()))
        .isInstanceOf(ValidationException.class);
    try (AwsSecretsManagerSecretsProvider seven =
        client.secrets(AwsSecretsManagerSecretsOptions.recoveryWindow(7))) {
      mock.json("DescribeSecret", 200, live);
      mock.json("DeleteSecret", 200, "{\"ARN\":\"a\",\"Name\":\"n\"}");
      seven.delete("n");
      assertThat(mock.last("DeleteSecret").get("RecoveryWindowInDays").asInt()).isEqualTo(7);
    }
    assertThatThrownBy(() -> client.secrets(AwsSecretsManagerSecretsOptions.recoveryWindow(3)))
        .isInstanceOf(ValidationException.class);
  }

  @Test
  void metadataMapsDescribeSecret() {
    mock.json(
        "DescribeSecret",
        200,
        "{\"ARN\":\"arn:x\",\"Name\":\"team/db\",\"Description\":\"d\",\"KmsKeyId\":\"k\","
            + "\"RotationEnabled\":true,\"NextRotationDate\":1795033097,\"PrimaryRegion\":\"us-east-1\","
            + "\"CreatedDate\":1795033095,\"LastChangedDate\":1795033096,"
            + "\"Tags\":[{\"Key\":\"a\",\"Value\":\"1\"}],"
            + "\"VersionIdsToStages\":{\"v1\":[\"AWSPREVIOUS\"],\"v2\":[\"AWSCURRENT\"]}}");
    SecretMetadata m = p.metadata("db", GetOptions.builder().path("team").build()).orElseThrow();
    assertThat(m.version()).contains("v2");
    assertThat(m.versions()).hasValue(2);
    assertThat(m.path()).contains("team");
    assertThat(m.extra())
        .containsEntry("arn", "arn:x")
        .containsEntry("description", "d")
        .containsEntry("kmsKeyId", "k")
        .containsEntry("rotationEnabled", "true")
        .containsEntry("primaryRegion", "us-east-1")
        .containsKey("nextRotationDate");
    mock.error("DescribeSecret", 404, "ResourceNotFoundException");
    assertThat(p.metadata("missing")).isEmpty();
    SecretDescription deleted =
        new SecretDescription(
            "a",
            "plain",
            null,
            null,
            false,
            null,
            null,
            null,
            null,
            null,
            java.time.Instant.EPOCH,
            null,
            null,
            null,
            null,
            Map.of(),
            Map.of(),
            List.of());
    SecretMetadata dm = AwsSecretsManagerSecretsProvider.toMetadata(deleted);
    assertThat(dm.extra()).containsKey("deletedDate");
    assertThat(dm.path()).isEmpty();
    assertThat(dm.version()).isEmpty();
  }

  @Test
  void closeRemovesTheProviderFromTheClient() {
    AwsSecretsManagerSecretsProvider other = client.secrets();
    other.close();
    other.close();
    client.close();
  }
}
