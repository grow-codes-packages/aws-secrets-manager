package codes.grow.packages.awssecretsmanager;

/**
 * Options of {@link AwsSecretsManagerSecretsProvider} ({@code client.secrets(options)}).
 *
 * @param recoveryWindowDays recovery window of {@code delete()} in days (7–30), or {@code null} for
 *     the client's {@code recoveryWindowDays} (default 30)
 */
public record AwsSecretsManagerSecretsOptions(Integer recoveryWindowDays) {
  /**
   * Returns options with every field unset.
   *
   * @return empty options
   */
  public static AwsSecretsManagerSecretsOptions none() {
    return new AwsSecretsManagerSecretsOptions(null);
  }

  /**
   * Sets the recovery window of deletes.
   *
   * @param days 7–30
   * @return the options
   */
  public static AwsSecretsManagerSecretsOptions recoveryWindow(int days) {
    return new AwsSecretsManagerSecretsOptions(days);
  }
}
