package codes.grow.packages.awssecretsmanager;

import codes.grow.packages.awssecretsmanager.core.Json;
import codes.grow.packages.awssecretsmanager.core.Secret;
import codes.grow.packages.awssecretsmanager.core.ValidationException;
import codes.grow.packages.awssecretsmanager.secrets.SecretValue;
import com.fasterxml.jackson.databind.JsonNode;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.secretsmanager.model.APIErrorType;
import software.amazon.awssdk.services.secretsmanager.model.DescribeSecretResponse;
import software.amazon.awssdk.services.secretsmanager.model.Filter;
import software.amazon.awssdk.services.secretsmanager.model.ReplicationStatusType;
import software.amazon.awssdk.services.secretsmanager.model.RotationRulesType;
import software.amazon.awssdk.services.secretsmanager.model.SecretListEntry;
import software.amazon.awssdk.services.secretsmanager.model.SecretVersionsListEntry;
import software.amazon.awssdk.services.secretsmanager.model.Tag;

/** Converters between the AWS SDK shapes and the package models. */
final class Models {
  private Models() {}

  /** A value encoded for {@code SecretString} or {@code SecretBinary} (exactly one is set). */
  record Encoded(String string, SdkBytes binary) {}

  /**
   * Encodes a value: {@code String} and {@link Secret} → {@code SecretString}, {@code byte[]} and
   * {@link SdkBytes} → {@code SecretBinary}, {@link SecretValue} by content (UTF-8 text stays
   * text), anything else as JSON {@code SecretString}.
   */
  static Encoded encodeValue(String operation, Object value) {
    if (value == null) {
      throw new ValidationException(operation + ": value must not be null");
    }
    if (value instanceof String) {
      return new Encoded((String) value, null);
    }
    if (value instanceof Secret) {
      return new Encoded(((Secret) value).reveal(), null);
    }
    if (value instanceof byte[]) {
      return new Encoded(null, SdkBytes.fromByteArray((byte[]) value));
    }
    if (value instanceof SdkBytes) {
      return new Encoded(null, (SdkBytes) value);
    }
    if (value instanceof SecretValue) {
      return encodeBytes(((SecretValue) value).revealBytes());
    }
    try {
      return new Encoded(Json.stringify(value), null);
    } catch (RuntimeException e) {
      throw new ValidationException(operation + ": value must be JSON-serialisable", e);
    }
  }

  /** Raw bytes: valid UTF-8 → {@code SecretString}, anything else → {@code SecretBinary}. */
  static Encoded encodeBytes(byte[] bytes) {
    try {
      String text =
          StandardCharsets.UTF_8
              .newDecoder()
              .onMalformedInput(CodingErrorAction.REPORT)
              .onUnmappableCharacter(CodingErrorAction.REPORT)
              .decode(ByteBuffer.wrap(bytes))
              .toString();
      return new Encoded(text, null);
    } catch (CharacterCodingException e) {
      return new Encoded(null, SdkBytes.fromByteArray(bytes));
    }
  }

  /** JSON text of a policy: strings as given, anything else JSON-encoded. */
  static String policyText(String operation, Object policy) {
    if (policy == null) {
      throw new ValidationException(operation + ": policy must not be null");
    }
    if (policy instanceof String) {
      return (String) policy;
    }
    try {
      return Json.stringify(policy);
    } catch (RuntimeException e) {
      throw new ValidationException(operation + ": policy must be JSON-serialisable", e);
    }
  }

  /** Parses a policy text into a JSON object ({@code null} when absent or not an object). */
  static JsonNode parsePolicy(String text) {
    if (text == null || text.isEmpty()) {
      return null;
    }
    try {
      JsonNode n = Json.tree(text.getBytes(StandardCharsets.UTF_8));
      return n != null && n.isObject() ? n : null;
    } catch (RuntimeException e) {
      return null;
    }
  }

  static AwsSecretValue secretValue(
      String arn,
      String name,
      String versionId,
      List<String> stages,
      Instant created,
      String string,
      SdkBytes binary) {
    boolean isBinary = binary != null;
    SecretValue value =
        isBinary
            ? SecretValue.ofBytes(binary.asByteArray(), versionId)
            : SecretValue.of(string == null ? "" : string, versionId);
    return new AwsSecretValue(
        nz(arn),
        nz(name),
        versionId,
        stages == null ? List.of() : stages,
        created,
        isBinary,
        value);
  }

  static String nz(String s) {
    return s == null ? "" : s;
  }

  static List<Tag> toAwsTags(Map<String, String> tags) {
    List<Tag> out = new ArrayList<>();
    tags.forEach((k, v) -> out.add(Tag.builder().key(k).value(v).build()));
    return out;
  }

  static Map<String, String> fromAwsTags(List<Tag> tags) {
    Map<String, String> out = new LinkedHashMap<>();
    if (tags != null) {
      for (Tag t : tags) {
        if (t.key() != null) {
          out.put(t.key(), t.value() == null ? "" : t.value());
        }
      }
    }
    return out;
  }

  static List<Filter> toAwsFilters(List<SecretFilter> filters) {
    List<Filter> out = new ArrayList<>();
    for (SecretFilter f : filters) {
      out.add(Filter.builder().key(f.key()).values(f.values()).build());
    }
    return out;
  }

  static RotationRulesType toAwsRules(RotationRules r) {
    return RotationRulesType.builder()
        .automaticallyAfterDays(
            r.automaticallyAfterDays() == null ? null : r.automaticallyAfterDays().longValue())
        .duration(r.duration())
        .scheduleExpression(r.scheduleExpression())
        .build();
  }

  static RotationRules fromAwsRules(RotationRulesType r) {
    if (r == null) {
      return null;
    }
    Long days = r.automaticallyAfterDays();
    return new RotationRules(
        days == null ? null : days.intValue(), r.duration(), r.scheduleExpression());
  }

  private static List<ReplicationStatus> replication(List<ReplicationStatusType> list) {
    List<ReplicationStatus> out = new ArrayList<>();
    if (list != null) {
      for (ReplicationStatusType r : list) {
        out.add(
            new ReplicationStatus(
                r.region(),
                r.kmsKeyId(),
                r.statusAsString(),
                r.statusMessage(),
                r.lastAccessedDate()));
      }
    }
    return out;
  }

  private static Map<String, List<String>> stages(Map<String, List<String>> m) {
    return m == null ? Map.of() : m;
  }

  static SecretDescription describe(DescribeSecretResponse d) {
    return new SecretDescription(
        nz(d.arn()),
        nz(d.name()),
        d.description(),
        d.kmsKeyId(),
        Boolean.TRUE.equals(d.rotationEnabled()),
        d.rotationLambdaARN(),
        fromAwsRules(d.rotationRules()),
        d.lastRotatedDate(),
        d.lastChangedDate(),
        d.lastAccessedDate(),
        d.deletedDate(),
        d.nextRotationDate(),
        d.createdDate(),
        d.primaryRegion(),
        d.owningService(),
        fromAwsTags(d.tags()),
        stages(d.versionIdsToStages()),
        replication(d.replicationStatus()));
  }

  static SecretDescription describe(SecretListEntry d) {
    return new SecretDescription(
        nz(d.arn()),
        nz(d.name()),
        d.description(),
        d.kmsKeyId(),
        Boolean.TRUE.equals(d.rotationEnabled()),
        d.rotationLambdaARN(),
        fromAwsRules(d.rotationRules()),
        d.lastRotatedDate(),
        d.lastChangedDate(),
        d.lastAccessedDate(),
        d.deletedDate(),
        d.nextRotationDate(),
        d.createdDate(),
        d.primaryRegion(),
        d.owningService(),
        fromAwsTags(d.tags()),
        stages(d.secretVersionsToStages()),
        List.of());
  }

  static SecretVersion version(SecretVersionsListEntry v) {
    return new SecretVersion(
        nz(v.versionId()),
        v.versionStages() == null ? List.of() : v.versionStages(),
        v.createdDate(),
        v.lastAccessedDate(),
        v.kmsKeyIds() == null ? List.of() : v.kmsKeyIds());
  }

  static BatchGetError batchError(APIErrorType e) {
    return new BatchGetError(e.secretId(), e.errorCode(), e.message());
  }
}
