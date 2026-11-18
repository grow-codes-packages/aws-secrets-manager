package awssecretsmanager

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// maxHealthTimeout bounds the health probe.
const maxHealthTimeout = 10 * time.Second

// Client is the AWS Secrets Manager client, built on the AWS SDK for Go v2.
// It is safe for concurrent use. Every method takes a context first; the
// call is bounded by Config.TotalTimeout and fails with CANCELLED when ctx is
// cancelled.
type Client struct {
	cfg       Config
	api       SecretsManagerAPI
	transport *httpTransport // nil when the caller supplied the SDK client
	secrets   []string

	closed    atomic.Bool
	closeOnce sync.Once

	mu        sync.Mutex
	providers []*SecretsManagerProvider
}

// NewClient validates cfg and returns a client. With Config.SDKClient the
// client wraps that SDK client; otherwise it builds one from the region,
// credentials (static, profile, standard chain, optional assume-role),
// endpoint override, timeouts, retries, TLS, proxy and headers of cfg.
func NewClient(cfg Config) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	cfg = cfg.withServiceDefaults()
	c := &Client{cfg: cfg}
	c.secrets = []string{cfg.SecretAccessKey.Reveal(), cfg.SessionToken.Reveal()}
	if cfg.SDKClient != nil {
		c.api = cfg.SDKClient
		return c, nil
	}
	t, err := newHTTPTransport(cfg.CommonConfig)
	if err != nil {
		return nil, err
	}
	t.addSecret(c.secrets...)
	c.secrets = t.knownSecrets()
	c.transport = t
	api, err := buildSDKClient(cfg, t)
	if err != nil {
		t.close()
		return nil, err
	}
	c.api = api
	return c, nil
}

// buildSDKClient loads the AWS configuration and builds the SDK client.
func buildSDKClient(cfg Config, t *httpTransport) (*secretsmanager.Client, error) {
	policy := cfg.Retry.withDefaults()
	httpClient := &hookedHTTPClient{
		client:      &http.Client{Transport: t.transport, Timeout: cfg.RequestTimeout, CheckRedirect: noCrossHostRedirect},
		userAgent:   t.userAgent,
		headers:     cfg.Headers,
		hooks:       cfg.Hooks,
		logger:      cfg.Logger,
		maxAttempts: policy.MaxRetries + 1,
		now:         time.Now,
	}
	opts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithHTTPClient(httpClient),
		awsconfig.WithRetryer(func() aws.Retryer { return newRetryer(policy, time.Now) }),
	}
	if cfg.Region != "" {
		opts = append(opts, awsconfig.WithRegion(cfg.Region))
	}
	if cfg.Profile != "" {
		opts = append(opts, awsconfig.WithSharedConfigProfile(cfg.Profile))
	}
	if cfg.Credentials != nil {
		opts = append(opts, awsconfig.WithCredentialsProvider(cfg.Credentials))
	}
	if cfg.AccessKeyID != "" {
		opts = append(opts, awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			cfg.AccessKeyID, cfg.SecretAccessKey.Reveal(), cfg.SessionToken.Reveal())))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(), opts...)
	if err != nil {
		return nil, ConfigError("cannot load the AWS configuration (check the profile and shared config files)")
	}
	if awsCfg.Region == "" {
		return nil, ConfigError("region is not set (GROW_AWS_SECRETS_MANAGER_REGION, AWS_REGION or the profile)")
	}
	if cfg.RoleARN != "" {
		provider := stscreds.NewAssumeRoleProvider(sts.NewFromConfig(awsCfg), cfg.RoleARN, func(o *stscreds.AssumeRoleOptions) {
			o.RoleSessionName = cfg.RoleSessionName
			if cfg.ExternalID != "" {
				o.ExternalID = aws.String(cfg.ExternalID)
			}
			if cfg.RoleDuration > 0 {
				o.Duration = cfg.RoleDuration
			}
		})
		awsCfg.Credentials = aws.NewCredentialsCache(provider)
	}
	return secretsmanager.NewFromConfig(awsCfg, func(o *secretsmanager.Options) {
		if cfg.URL != "" {
			o.BaseEndpoint = aws.String(cfg.URL)
		}
		o.APIOptions = append(o.APIOptions, addAttemptCounter)
	}), nil
}

// NewClientFromEnv builds a client from the environment (see ConfigFromEnv).
func NewClientFromEnv() (*Client, error) {
	cfg, err := ConfigFromEnv()
	if err != nil {
		return nil, err
	}
	return NewClient(cfg)
}

// Config returns the effective configuration.
func (c *Client) Config() Config { return c.cfg }

// SDK returns the underlying AWS SDK client for calls this package does not
// wrap. It is a *secretsmanager.Client unless Config.SDKClient was set.
func (c *Client) SDK() SecretsManagerAPI { return c.api }

// SecretsOptions configure a provider returned by Client.Secrets.
type SecretsOptions struct {
	// RecoveryWindowDays is the recovery window of Delete, 7–30
	// (0 = Config.RecoveryWindowDays, default 30).
	RecoveryWindowDays int
}

// Secrets returns a SecretsProvider (SPEC §3) on this client. Close of the
// client stops the watchers of every provider it returned. An invalid
// RecoveryWindowDays is a VALIDATION error.
func (c *Client) Secrets(opts ...SecretsOptions) (*SecretsManagerProvider, error) {
	days := c.cfg.RecoveryWindowDays
	for _, o := range opts {
		if o.RecoveryWindowDays != 0 {
			days = o.RecoveryWindowDays
		}
	}
	if days < 7 || days > 30 {
		return nil, ValidationError("secrets", "recoveryWindowDays must be between 7 and 30")
	}
	p := newSecretsManagerProvider(c, days)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed.Load() {
		_ = p.Close()
	}
	c.providers = append(c.providers, p)
	return p, nil
}

// SecretCache returns a version-stage aware cache with the AWS caching-client
// semantics (see AWSSecretCache).
func (c *Client) SecretCache(opts *AWSSecretCacheOptions) (*AWSSecretCache, error) {
	return NewAWSSecretCache(c, opts)
}

func (c *Client) redact(s string) string { return RedactText(s, c.secrets) }

// begin starts a call: it fails when the client is closed and bounds ctx by
// the total timeout.
func (c *Client) begin(ctx context.Context, op string) (context.Context, context.CancelFunc, error) {
	if c.closed.Load() {
		return nil, nil, &Error{Code: ErrorCodeCancelled, Message: op + ": client is closed"}
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, contextErr(op, err)
	}
	ctx, cancel := context.WithTimeout(ctx, c.cfg.TotalTimeout)
	return ctx, cancel, nil
}

// call runs one SDK operation with the client's timeout and error mapping.
func call[T any](ctx context.Context, c *Client, op string, fn func(ctx context.Context) (T, error)) (T, error) {
	var zero T
	ctx, cancel, err := c.begin(ctx, op)
	if err != nil {
		return zero, err
	}
	defer cancel()
	out, err := fn(ctx)
	if err != nil {
		return zero, c.mapError(op, err)
	}
	return out, nil
}

// Health probes the service with a signed ListSecrets (MaxResults 1, no
// retries, short timeout). AWS has no unauthenticated health endpoint, so an
// authentication or permission failure still counts as reachable
// (details auth=failed). It fails only for CANCELLED and CONFIG.
func (c *Client) Health(ctx context.Context) (HealthStatus, error) {
	timeout := min(c.cfg.RequestTimeout, maxHealthTimeout)
	hctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	_, err := call(hctx, c, "health", func(ctx context.Context) (*secretsmanager.ListSecretsOutput, error) {
		return c.api.ListSecrets(ctx, &secretsmanager.ListSecretsInput{MaxResults: aws.Int32(1)}, noRetry)
	})
	if err == nil {
		return HealthStatus{Healthy: true, Status: "ok", Details: map[string]string{}}, nil
	}
	if ctx.Err() != nil {
		return HealthStatus{}, contextErr("health", ctx.Err())
	}
	var e *Error
	if !errors.As(err, &e) {
		return HealthStatus{Healthy: false, Status: "unreachable", Details: map[string]string{"error": err.Error()}}, nil
	}
	switch e.Code {
	case ErrorCodeCancelled, ErrorCodeConfig:
		return HealthStatus{}, err
	case ErrorCodeRateLimited:
		return HealthStatus{Healthy: true, Status: "degraded", Details: map[string]string{"code": string(e.Code)}}, nil
	case ErrorCodeAuthentication, ErrorCodePermissionDenied:
		return HealthStatus{Healthy: true, Status: "ok", Details: map[string]string{"auth": "failed", "code": string(e.Code)}}, nil
	}
	if e.HTTPStatus >= 500 {
		return HealthStatus{Healthy: false, Status: "unhealthy", Details: map[string]string{"httpStatus": strconv.Itoa(e.HTTPStatus), "error": e.Message}}, nil
	}
	if e.HTTPStatus > 0 {
		return HealthStatus{Healthy: true, Status: "ok", Details: map[string]string{"httpStatus": strconv.Itoa(e.HTTPStatus), "code": string(e.Code)}}, nil
	}
	return HealthStatus{Healthy: false, Status: "unreachable", Details: map[string]string{"error": e.Message}}, nil
}

// Ping makes a signed ListSecrets (MaxResults 1) round trip and returns its
// latency: AUTHENTICATION for unknown keys or bad signatures,
// PERMISSION_DENIED without secretsmanager:ListSecrets.
func (c *Client) Ping(ctx context.Context) (time.Duration, error) {
	start := time.Now()
	_, err := call(ctx, c, "ping", func(ctx context.Context) (*secretsmanager.ListSecretsOutput, error) {
		return c.api.ListSecrets(ctx, &secretsmanager.ListSecretsInput{MaxResults: aws.Int32(1)})
	})
	if err != nil {
		return 0, err
	}
	return time.Since(start), nil
}

// ServerVersion always fails with UNSUPPORTED: AWS Secrets Manager exposes no
// server version (the API contract date is the constant APIVersion).
func (c *Client) ServerVersion(context.Context) (string, error) {
	return "", UnsupportedError("serverVersion", "AWS Secrets Manager does not expose a server version")
}

// Close stops the provider's watchers and releases idle connections. Later
// calls fail with CANCELLED. A caller-supplied SDK client is never closed.
// Close is idempotent.
func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed.Store(true)
		providers := c.providers
		c.providers = nil
		c.mu.Unlock()
		for _, p := range providers {
			_ = p.Close()
		}
		if c.transport != nil {
			c.transport.close()
		}
	})
	return nil
}
