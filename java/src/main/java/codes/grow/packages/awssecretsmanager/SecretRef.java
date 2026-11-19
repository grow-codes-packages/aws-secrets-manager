package codes.grow.packages.awssecretsmanager;

/**
 * ARN and name of a secret.
 *
 * @param arn full ARN
 * @param name secret name
 */
public record SecretRef(String arn, String name) {}
