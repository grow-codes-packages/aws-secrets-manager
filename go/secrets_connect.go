package awssecretsmanager

// Service-owned: generated once by sdk-kit, then maintained in this repository.

import "context"

// connectSecrets is the LoadConfig connector: AWS keeps its own variables (region, credentials,
// GROW_AWS_SECRETS_MANAGER_*); GROW_SECRETS_ADDR overrides the endpoint when set.
func connectSecrets(_ context.Context, b *SecretsBootstrap, env map[string]string) (*SecretsConnection, error) {
	explicit := Config{}
	explicit.URL = b.Addr
	cfg, err := ConfigFromEnvWith(explicit, env)
	if err != nil {
		return nil, err
	}
	client, err := NewClient(cfg)
	if err != nil {
		return nil, err
	}
	provider, err := client.Secrets()
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	return &SecretsConnection{Provider: provider, Close: client.Close}, nil
}
