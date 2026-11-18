// Package awssecretsmanager is the Grow Codes SDK for AWS Secrets Manager.
//
// Create a client from the environment (GROW_AWS_SECRETS_MANAGER_URL,
// GROW_AWS_SECRETS_MANAGER_TOKEN, ...) or from a Config literal:
//
//	client, err := awssecretsmanager.NewClientFromEnv()
//	if err != nil {
//		return err
//	}
//	defer client.Close()
//	status, err := client.Health(ctx)
//
// Every error is an *Error; compare codes with errors.Is against the Err*
// sentinels (errors.Is(err, awssecretsmanager.ErrNotFound)). Credentials are wrapped in
// Secret and never appear in errors, hooks or logs.
//
// AWS Secrets Manager is a trademark of Amazon.com, Inc. or its affiliates. This package is not affiliated
// with or endorsed by Amazon.com, Inc. or its affiliates.
package awssecretsmanager
