package codes.grow.packages.awssecretsmanager.integration;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import codes.grow.packages.awssecretsmanager.AwsSecretCache;
import codes.grow.packages.awssecretsmanager.AwsSecretValue;
import codes.grow.packages.awssecretsmanager.AwsSecretsManagerClient;
import codes.grow.packages.awssecretsmanager.BatchGetOptions;
import codes.grow.packages.awssecretsmanager.BatchGetResult;
import codes.grow.packages.awssecretsmanager.BatchGetSelector;
import codes.grow.packages.awssecretsmanager.CreateSecretOptions;
import codes.grow.packages.awssecretsmanager.DeleteSecretOptions;
import codes.grow.packages.awssecretsmanager.GetSecretValueOptions;
import codes.grow.packages.awssecretsmanager.ListSecretVersionIdsOptions;
import codes.grow.packages.awssecretsmanager.ListSecretsOptions;
import codes.grow.packages.awssecretsmanager.PutResourcePolicyOptions;
import codes.grow.packages.awssecretsmanager.PutSecretValueOptions;
import codes.grow.packages.awssecretsmanager.PutSecretValueResult;
import codes.grow.packages.awssecretsmanager.RandomPasswordOptions;
import codes.grow.packages.awssecretsmanager.ResourcePolicyResult;
import codes.grow.packages.awssecretsmanager.RotateSecretOptions;
import codes.grow.packages.awssecretsmanager.RotationRules;
import codes.grow.packages.awssecretsmanager.SecretDescription;
import codes.grow.packages.awssecretsmanager.SecretFilter;
import codes.grow.packages.awssecretsmanager.SecretVersion;
import codes.grow.packages.awssecretsmanager.SecretWriteResult;
import codes.grow.packages.awssecretsmanager.UpdateSecretOptions;
import codes.grow.packages.awssecretsmanager.UpdateSecretVersionStageOptions;
import codes.grow.packages.awssecretsmanager.ValidateResourcePolicyOptions;
import codes.grow.packages.awssecretsmanager.ValidateResourcePolicyResult;
import codes.grow.packages.awssecretsmanager.core.AwsSecretsManagerException;
import codes.grow.packages.awssecretsmanager.core.ConflictException;
import codes.grow.packages.awssecretsmanager.core.ErrorCode;
import codes.grow.packages.awssecretsmanager.core.NotFoundException;
import codes.grow.packages.awssecretsmanager.core.Secret;
import codes.grow.packages.awssecretsmanager.core.UnsupportedException;
import codes.grow.packages.awssecretsmanager.core.ValidationException;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

/**
 * Every service-specific function against the real service, each with a round-trip assertion
 * (write, then read back). Moto gaps (API.md section 7) assert the documented emulator behaviour.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class OperationsIntegrationTest {
  private Map<String, String> env;
  private AwsSecretsManagerClient c;
  private String base;
  private final List<String> created = new ArrayList<>();

  @BeforeAll
  void start() {
    env = Env.load();
    c = Env.client(env);
    base = Env.uid(env, "java");
  }

  @AfterAll
  void stop() {
    if (c != null) {
      Env.purge(c, created);
      c.close();
    }
  }

  private String name(String leaf) {
    String n = base + "/" + leaf;
    created.add(n);
    return n;
  }

  @Test
  void getSecretValueReadsTheSeeds() throws Exception {
    AwsSecretValue json = c.getSecretValue(Env.get(env, "GROW_TEST_SEED_JSON_SECRET"));
    assertFalse(json.binary());
    assertEquals("seed-user", json.value().jsonNode().get("username").asText());
    assertTrue(json.versionStages().contains("AWSCURRENT"));
    assertNotNull(json.createdDate());
    AwsSecretValue byArn = c.getSecretValue(Env.get(env, "GROW_TEST_SEED_JSON_SECRET_ARN"));
    assertEquals(json.versionId(), byArn.versionId());
    AwsSecretValue bin =
        c.getSecretValueAsync(Env.get(env, "GROW_TEST_SEED_BINARY_SECRET")).get(30, TimeUnit.SECONDS);
    assertTrue(bin.binary());
    assertArrayEquals(new byte[] {0, 1, 2, (byte) 0xfe, (byte) 0xff}, bin.value().revealBytes());
    assertFalse(bin.toString().contains("AAEC"));
    assertFalse(json.toString().contains("seed-pass-123"));
    assertThrows(NotFoundException.class, () -> c.getSecretValue(base + "/missing"));
  }

  @Test
  void createSecretThenRead() {
    String s = name("create/string");
    SecretWriteResult r =
        c.createSecret(
            s,
            "s3cr3t",
            CreateSecretOptions.builder().description("made by java").tags(Map.of("team", "sdk")).build());
    assertEquals(s, r.name());
    assertNotNull(r.versionId());
    assertEquals("s3cr3t", c.getSecretValue(s).value().reveal());
    String b = name("create/bytes");
    c.createSecret(b, new byte[] {7, 0, (byte) 255});
    assertArrayEquals(new byte[] {7, 0, (byte) 255}, c.getSecretValue(b).value().revealBytes());
    String o = name("create/object");
    c.createSecret(o, Map.of("a", 1));
    assertEquals(1, c.getSecretValue(o).value().jsonNode().get("a").asInt());
    String e = name("create/empty");
    SecretWriteResult empty =
        c.createSecret(e, null, CreateSecretOptions.builder().kmsKeyId("alias/aws/secretsmanager").build());
    assertNull(empty.versionId());
    assertThrows(NotFoundException.class, () -> c.getSecretValue(e));
    SecretDescription d = c.describeSecret(s);
    assertEquals("made by java", d.description());
    assertEquals(Map.of("team", "sdk"), d.tags());
    assertFalse(d.rotationEnabled());
    AwsSecretsManagerException conflict = assertThrows(AwsSecretsManagerException.class, () -> c.createSecret(s, "again"));
    assertEquals(ErrorCode.CONFLICT, conflict.code());
  }

  @Test
  void putSecretValueVersionsAndStages() {
    String s = name("versions");
    String v1 = c.createSecret(s, "one").versionId();
    PutSecretValueResult put = c.putSecretValue(s, "two");
    assertEquals(List.of("AWSCURRENT"), put.versionStages());
    String v2 = put.versionId();
    assertEquals("one", c.getSecretValue(s, GetSecretValueOptions.ofVersionStage("AWSPREVIOUS")).value().reveal());
    PutSecretValueResult custom =
        c.putSecretValue(s, "three", PutSecretValueOptions.builder().versionStages(List.of("STAGED")).build());
    assertEquals("three", c.getSecretValue(s, GetSecretValueOptions.ofVersionStage("STAGED")).value().reveal());
    assertEquals("two", c.getSecretValue(s, GetSecretValueOptions.ofVersionStage("AWSCURRENT")).value().reveal());
    assertEquals(v1, c.getSecretValue(s, GetSecretValueOptions.ofVersionId(v1)).versionId());
    // promote the staged version (read back with an explicit stage: Moto quirk)
    c.updateSecretVersionStage(
        s, "AWSCURRENT", new UpdateSecretVersionStageOptions(custom.versionId(), v2));
    assertEquals("three", c.getSecretValue(s, GetSecretValueOptions.ofVersionStage("AWSCURRENT")).value().reveal());
    List<SecretVersion> versions =
        c.listSecretVersionIds(s, ListSecretVersionIdsOptions.builder().includeDeprecated(true).build()).toList();
    assertEquals(3, versions.size());
    Map<String, List<String>> byId =
        versions.stream().collect(Collectors.toMap(SecretVersion::versionId, SecretVersion::versionStages));
    assertTrue(byId.get(custom.versionId()).contains("AWSCURRENT"));
    assertTrue(byId.get(v2).contains("AWSPREVIOUS"));
    assertTrue(c.describeSecret(s).versionIdsToStages().get(custom.versionId()).contains("AWSCURRENT"));
    assertThrows(
        ValidationException.class,
        () -> c.updateSecretVersionStage(s, "AWSCURRENT", new UpdateSecretVersionStageOptions(v1, null)));
  }

  @Test
  void updateSecretDescriptionAndValue() {
    String s = name("update");
    c.createSecret(s, "v1");
    c.updateSecret(s, UpdateSecretOptions.builder().description("new description").build());
    assertEquals("new description", c.describeSecret(s).description());
    SecretWriteResult r = c.updateSecret(s, UpdateSecretOptions.builder().value(Map.of("rotated", true)).build());
    assertNotNull(r.versionId());
    assertTrue(
        c.getSecretValue(s, GetSecretValueOptions.ofVersionStage("AWSCURRENT")).value().jsonNode().get("rotated").asBoolean());
    assertThrows(
        NotFoundException.class,
        () -> c.updateSecret(base + "/nope", UpdateSecretOptions.builder().description("x").build()));
  }

  @Test
  void batchGetByIdsAndByFilters() {
    String a = name("batch/a");
    String b = name("batch/b");
    c.createSecret(a, "A");
    c.createSecret(b, "B");
    BatchGetResult res = c.batchGetSecretValue(List.of(b, base + "/batch/missing", a));
    assertEquals(List.of(b, a), res.secretValues().stream().map(AwsSecretValue::name).collect(Collectors.toList()));
    assertEquals("B", res.secretValues().get(0).value().reveal());
    assertEquals(1, res.errors().size());
    assertEquals("ResourceNotFoundException", res.errors().get(0).errorCode());
    BatchGetResult filtered =
        c.batchGetSecretValue(BatchGetSelector.filters(SecretFilter.name(base + "/batch/")), new BatchGetOptions(1));
    assertEquals(
        List.of(a, b),
        filtered.secretValues().stream().map(AwsSecretValue::name).sorted().collect(Collectors.toList()));
  }

  @Test
  void listSecretsPaginatesAndShowsPlannedDeletions() throws Exception {
    List<String> names = List.of(name("list/one"), name("list/two"), name("list/three"));
    for (String n : names) {
      c.createSecret(n, n, CreateSecretOptions.builder().tags(Map.of("group", base + "-list")).build());
    }
    List<SecretFilter> byName = List.of(SecretFilter.name(base + "/list/"));
    List<String> listed =
        c.listSecrets(ListSecretsOptions.builder().filters(byName).maxResults(1).build()).stream()
            .map(SecretDescription::name)
            .sorted()
            .collect(Collectors.toList());
    assertEquals(names.stream().sorted().collect(Collectors.toList()), listed);
    List<SecretDescription> byTag =
        c.listSecretsAsync(
                ListSecretsOptions.builder()
                    .filters(List.of(SecretFilter.of(SecretFilter.TAG_VALUE, base + "-list")))
                    .sortOrder("asc")
                    .build())
            .get(30, TimeUnit.SECONDS);
    assertEquals(3, byTag.size());
    c.deleteSecret(names.get(0), DeleteSecretOptions.builder().recoveryWindowDays(7).build());
    assertEquals(2, c.listSecrets(ListSecretsOptions.builder().filters(byName).build()).toList().size());
    List<SecretDescription> planned =
        c.listSecrets(ListSecretsOptions.builder().filters(byName).includePlannedDeletion(true).build()).toList();
    assertEquals(3, planned.size());
    assertTrue(planned.stream().filter(d -> d.name().equals(names.get(0))).findFirst().orElseThrow().pendingDeletion());
  }

  @Test
  void deleteWithWindowOrForceAndRestore() {
    String s = name("delete/restore");
    c.createSecret(s, "keep");
    assertNotNull(c.deleteSecret(s, DeleteSecretOptions.builder().recoveryWindowDays(7).build()).deletionDate());
    assertTrue(c.describeSecret(s).pendingDeletion());
    assertThrows(ConflictException.class, () -> c.getSecretValue(s));
    c.restoreSecret(s);
    assertFalse(c.describeSecret(s).pendingDeletion());
    assertEquals("keep", c.getSecretValue(s).value().reveal());
    String f = name("delete/force");
    c.createSecret(f, "bye");
    c.deleteSecret(f, DeleteSecretOptions.builder().forceDeleteWithoutRecovery(true).build());
    assertThrows(NotFoundException.class, () -> c.describeSecret(f));
    // AWS and Moto answer success for a forced delete of a missing secret
    c.deleteSecret(f, DeleteSecretOptions.builder().forceDeleteWithoutRecovery(true).build());
    assertThrows(NotFoundException.class, () -> c.deleteSecret(f));
    assertThrows(ValidationException.class, () -> c.deleteSecret(f, new DeleteSecretOptions(7, true)));
  }

  @Test
  void tagAndUntagRoundTrip() {
    String s = name("tags");
    c.createSecret(s, "v");
    c.tagResource(s, Map.of("env", "dev", "owner", "sdk"));
    assertEquals(Map.of("env", "dev", "owner", "sdk"), c.describeSecret(s).tags());
    c.untagResource(s, List.of("env"));
    assertEquals(Map.of("owner", "sdk"), c.describeSecret(s).tags());
  }

  @Test
  void resourcePolicyRoundTripAndValidation() {
    String s = name("policy");
    c.createSecret(s, "v");
    Map<String, Object> policy =
        Map.of(
            "Version", "2012-10-17",
            "Statement",
                List.of(
                    Map.of(
                        "Effect", "Allow",
                        "Principal", Map.of("AWS", "arn:aws:iam::" + Env.get(env, "GROW_TEST_ACCOUNT_ID") + ":root"),
                        "Action", "secretsmanager:GetSecretValue",
                        "Resource", "*")));
    c.putResourcePolicy(s, policy, new PutResourcePolicyOptions(true));
    ResourcePolicyResult got = c.getResourcePolicy(s);
    JsonNode p = got.policyJson().orElseThrow();
    assertEquals("2012-10-17", p.get("Version").asText());
    assertEquals("Allow", p.get("Statement").get(0).get("Effect").asText());
    c.deleteResourcePolicy(s);
    assertNull(c.getResourcePolicy(s).resourcePolicy());
    if (Env.isMoto(env)) {
      // Not implemented in Moto 5.2.4 (API.md section 7): unit tests cover the AWS answer.
      assertThrows(
          UnsupportedException.class,
          () -> c.validateResourcePolicy(policy, new ValidateResourcePolicyOptions(s)));
    } else {
      ValidateResourcePolicyResult v = c.validateResourcePolicy(policy, new ValidateResourcePolicyOptions(s));
      assertNotNull(v.validationErrors());
    }
  }

  @Test
  void rotationRulesOnlyThenLambdaAndCancel() {
    assumeTrue(Env.isMoto(env), "rotation needs a rotation Lambda on real AWS (unit tests + live job)");
    String s = name("rotation");
    c.createSecret(s, "rot-v1");
    SecretWriteResult r = c.rotateSecret(s, RotateSecretOptions.builder().rules(RotationRules.everyDays(30)).build());
    assertNotNull(r.versionId());
    SecretDescription d = c.describeSecret(s);
    assertTrue(d.rotationEnabled());
    assertEquals(30, d.rotationRules().automaticallyAfterDays());
    // Moto looks the Lambda up and has none (API.md section 7)
    assertThrows(
        NotFoundException.class,
        () ->
            c.rotateSecret(
                s,
                RotateSecretOptions.builder()
                    .lambdaArn("arn:aws:lambda:us-east-1:123456789012:function:grow-rotate")
                    .rules(RotationRules.schedule("rate(10 days)"))
                    .build()));
    c.cancelRotateSecret(s);
    assertFalse(c.describeSecret(s).rotationEnabled());
    assertThrows(NotFoundException.class, () -> c.cancelRotateSecret(base + "/rotation-missing"));
  }

  @Test
  void getRandomPasswordHonoursItsOptions() {
    Secret p =
        c.getRandomPassword(
            RandomPasswordOptions.builder().length(40).excludePunctuation(true).excludeCharacters("abc").build());
    String text = p.reveal();
    assertEquals(40, text.length());
    assertTrue(text.matches("[A-Za-z0-9]+"));
    assertFalse(text.matches(".*[abc].*"));
    assertFalse(p.toString().contains(text));
    assertEquals(32, c.getRandomPassword().reveal().length());
    AwsSecretsManagerException e =
        assertThrows(
            AwsSecretsManagerException.class,
            () -> c.getRandomPassword(RandomPasswordOptions.builder().length(2).build()));
    assertEquals(ErrorCode.VALIDATION, e.code());
  }

  @Test
  void getJsonFieldReadsFields() {
    String seed = Env.get(env, "GROW_TEST_SEED_JSON_SECRET");
    assertEquals("seed-user", c.getJsonField(seed, "username").orElseThrow().asText());
    assertEquals(5432, c.getJsonField(seed, "port").orElseThrow().asInt());
    assertTrue(c.getJsonField(seed, "enabled").orElseThrow().asBoolean());
    assertTrue(c.getJsonField(seed, "absent").isEmpty());
    String s = name("json");
    c.createSecret(s, Map.of("db", Map.of("host", "db.local")));
    assertEquals(
        "db.local",
        c.getJsonField(s, "db.host", GetSecretValueOptions.ofVersionStage("AWSCURRENT")).orElseThrow().asText());
    assertThrows(
        ValidationException.class, () -> c.getJsonField(Env.get(env, "GROW_TEST_SEED_BINARY_SECRET"), "x"));
  }

  @Test
  void secretCachePicksUpANewCurrentVersionOnRefresh() {
    String s = name("cache");
    c.createSecret(s, "c1");
    AwsSecretCache cache = c.secretCache(AwsSecretCache.Options.builder().ttl(Duration.ofMinutes(1)).build());
    assertEquals("c1", cache.getSecretString(s));
    c.putSecretValue(s, "c2");
    assertEquals("c1", cache.getSecretString(s));
    assertEquals("c2", cache.refreshNow(s).value().reveal());
    assertEquals("c1", cache.getSecretString(s, "AWSPREVIOUS"));
    assertEquals(1, cache.stats().versionChanges());
    assertNotEquals(0, cache.stats().size());
    assertInstanceOf(byte[].class, cache.getSecretBinary(s));
  }
}
