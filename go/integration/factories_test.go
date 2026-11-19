package integration

import (
	"context"
	"strings"
	"testing"

	awssecretsmanager "github.com/grow-codes-packages/aws-secrets-manager/go"
	"github.com/grow-codes-packages/aws-secrets-manager/go/testkit"
)

// capabilities the deployment under test offers (see conformance "requires").
// AWS Secrets Manager supports writes, versions (VersionId) and deletes; it
// exposes no server version, so "version" is not declared (docs/compatibility.md).
var capabilities = []string{"write", "versions", "delete"}

// categories runs "core" plus this service's categories.
func categories() []string {
	return append([]string{"core"}, strings.Split("secrets", ",")...)
}

// factories builds the conformance targets: the client for "core" and its
// SecretsProvider for "secrets".
func factories(t *testing.T) testkit.Factories {
	t.Helper()
	return testkit.Factories{
		"core": testkit.CoreFactory(func(context.Context) (testkit.CoreTarget, error) {
			return awssecretsmanager.NewClientFromEnv()
		}),
		"secrets": testkit.SecretsFactory(func(context.Context) (awssecretsmanager.SecretsProvider, error) {
			c, err := awssecretsmanager.NewClientFromEnv()
			if err != nil {
				return nil, err
			}
			p, err := c.Secrets()
			if err != nil {
				_ = c.Close()
				return nil, err
			}
			return &closingProvider{SecretsManagerProvider: p, client: c}, nil
		}),
	}
}

// closingProvider closes its client when the scenario ends.
type closingProvider struct {
	*awssecretsmanager.SecretsManagerProvider
	client *awssecretsmanager.Client
}

func (p *closingProvider) Close() error { return p.client.Close() }
