package codes.grow.packages.awssecretsmanager;

/**
 * A rotation schedule. Components are {@code null} when not set.
 *
 * @param automaticallyAfterDays rotate every N days (1–1000)
 * @param duration rotation window length, e.g. {@code 3h}
 * @param scheduleExpression {@code rate(...)} or {@code cron(...)} expression
 */
public record RotationRules(
    Integer automaticallyAfterDays, String duration, String scheduleExpression) {
  /**
   * Rotates every {@code days} days.
   *
   * @param days interval in days
   * @return the rules
   */
  public static RotationRules everyDays(int days) {
    return new RotationRules(days, null, null);
  }

  /**
   * Rotates on a schedule expression.
   *
   * @param expression {@code rate(...)} or {@code cron(...)}
   * @return the rules
   */
  public static RotationRules schedule(String expression) {
    return new RotationRules(null, null, expression);
  }
}
