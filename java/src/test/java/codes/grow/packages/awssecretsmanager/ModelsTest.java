package codes.grow.packages.awssecretsmanager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import codes.grow.packages.awssecretsmanager.core.Secret;
import codes.grow.packages.awssecretsmanager.core.ValidationException;
import codes.grow.packages.awssecretsmanager.secrets.SecretValue;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.secretsmanager.model.APIErrorType;
import software.amazon.awssdk.services.secretsmanager.model.SecretVersionsListEntry;
import software.amazon.awssdk.services.secretsmanager.model.Tag;

class ModelsTest {
  @Test
  void encodesEveryValueKind() {
    assertThat(Models.encodeValue("op", "s").string()).isEqualTo("s");
    assertThat(Models.encodeValue("op", Secret.of("sec")).string()).isEqualTo("sec");
    assertThat(Models.encodeValue("op", new byte[] {1}).binary().asByteArray()).containsExactly(1);
    assertThat(
            Models.encodeValue("op", SdkBytes.fromByteArray(new byte[] {2})).binary().asByteArray())
        .containsExactly(2);
    assertThat(Models.encodeValue("op", SecretValue.of("text")).string()).isEqualTo("text");
    assertThat(
            Models.encodeValue("op", SecretValue.ofBytes(new byte[] {(byte) 0xff}, null)).binary())
        .isNotNull();
    assertThat(Models.encodeValue("op", List.of(1, 2)).string()).isEqualTo("[1,2]");
    assertThatThrownBy(() -> Models.encodeValue("op", null))
        .isInstanceOf(ValidationException.class);
    assertThatThrownBy(() -> Models.policyText("op", null)).isInstanceOf(ValidationException.class);
    assertThat(Models.policyText("op", Map.of("a", 1))).isEqualTo("{\"a\":1}");
    assertThat(Models.parsePolicy(null)).isNull();
    assertThat(Models.parsePolicy("")).isNull();
  }

  @Test
  void convertsSdkShapes() {
    assertThat(Models.fromAwsTags(null)).isEmpty();
    assertThat(
            Models.fromAwsTags(
                List.of(Tag.builder().key("k").build(), Tag.builder().value("orphan").build())))
        .containsExactly(Map.entry("k", ""));
    assertThat(Models.fromAwsRules(null)).isNull();
    assertThat(Models.toAwsRules(new RotationRules(null, "2h", null)).automaticallyAfterDays())
        .isNull();
    SecretVersion v = Models.version(SecretVersionsListEntry.builder().build());
    assertThat(v.versionId()).isEmpty();
    assertThat(v.versionStages()).isEmpty();
    BatchGetError e =
        Models.batchError(APIErrorType.builder().secretId("s").errorCode("c").message("m").build());
    assertThat(e).isEqualTo(new BatchGetError("s", "c", "m"));
    AwsSecretValue nulls = Models.secretValue(null, null, null, null, null, null, null);
    assertThat(nulls.arn()).isEmpty();
    assertThat(nulls.value().reveal()).isEmpty();
    assertThat(new SecretWriteResult("a", "n", null).version()).isEmpty();
  }
}
