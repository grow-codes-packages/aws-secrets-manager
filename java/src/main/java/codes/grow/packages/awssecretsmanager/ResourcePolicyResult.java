package codes.grow.packages.awssecretsmanager;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.Optional;

/**
 * Result of {@code getResourcePolicy}.
 *
 * @param arn full ARN
 * @param name secret name
 * @param resourcePolicy the policy JSON text, or {@code null} when the secret has no policy
 * @param policy the parsed policy object, or {@code null} when there is none or it is not a JSON
 *     object
 */
public record ResourcePolicyResult(
    String arn, String name, String resourcePolicy, JsonNode policy) {
  /**
   * Returns the parsed policy.
   *
   * @return the policy object, or empty
   */
  public Optional<JsonNode> policyJson() {
    return Optional.ofNullable(policy);
  }
}
