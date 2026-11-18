// Package awssecretsmanager is the Grow Codes SDK for AWS Secrets Manager, built
// on the official AWS SDK for Go v2 (service/secretsmanager).
//
// Create a client from the standard AWS environment (AWS_REGION,
// AWS_ACCESS_KEY_ID, AWS_PROFILE, AWS_ENDPOINT_URL_SECRETS_MANAGER, ...) and the
// GROW_AWS_SECRETS_MANAGER_* variables, or from a Config literal:
//
//	client, err := awssecretsmanager.NewClientFromEnv()
//	if err != nil {
//		return err
//	}
//	defer client.Close()
//	secret, err := client.GetSecretValue(ctx, "prod/db", nil)
//	password, ok, err := client.GetJSONField(ctx, "prod/db", "password", nil)
//
// The client wraps every Secrets Manager operation (GetSecretValue,
// BatchGetSecretValue, DescribeSecret, ListSecrets, ListSecretVersionIDs,
// CreateSecret, PutSecretValue, UpdateSecret, UpdateSecretVersionStage,
// DeleteSecret, RestoreSecret, TagResource, UntagResource, the resource-policy
// calls, RotateSecret, CancelRotateSecret and GetRandomPassword). Client.Secrets
// returns the common SecretsProvider and Client.SecretCache a version-stage
// aware cache with the AWS caching-client semantics.
//
// Every error is an *Error; compare codes with errors.Is against the Err*
// sentinels (errors.Is(err, awssecretsmanager.ErrNotFound)). AWS errors are
// mapped by AWS error code; AWSErrorCode returns the original code.
// Credentials and secret values are wrapped in Secret / SecretValue and never
// appear in errors, hooks or logs.
//
// Amazon Web Services, AWS and AWS Secrets Manager are trademarks of Amazon.com,
// Inc. or its affiliates. This package is not affiliated with or endorsed by
// Amazon.com, Inc. or its affiliates.
package awssecretsmanager
