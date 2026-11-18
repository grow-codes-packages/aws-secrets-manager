package awssecretsmanager

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

func TestClientConfig(t *testing.T) {
	t.Run("core.config.env-precedence", func(t *testing.T) {
		env := map[string]string{
			EnvPrefix + "URL": "http://grow:1", "AWS_ENDPOINT_URL_SECRETS_MANAGER": "http://vendor:2", "AWS_ENDPOINT_URL": "http://all:3",
			"AWS_REGION": "eu-west-1", "AWS_DEFAULT_REGION": "us-west-2",
			"AWS_ACCESS_KEY_ID": "AKIDVENDOR", "AWS_SECRET_ACCESS_KEY": "vendor-secret", "AWS_SESSION_TOKEN": "vendor-session",
			"AWS_PROFILE": "vendor-profile",
		}
		cfg, err := ConfigFromEnvWith(Config{}, env)
		if err != nil || cfg.URL != "http://grow:1" || cfg.Region != "eu-west-1" || cfg.AccessKeyID != "AKIDVENDOR" ||
			cfg.SecretAccessKey.Reveal() != "vendor-secret" || cfg.SessionToken.Reveal() != "vendor-session" || cfg.Profile != "vendor-profile" {
			t.Fatalf("env: %v %s", err, cfg)
		}
		delete(env, EnvPrefix+"URL")
		if cfg, _ = ConfigFromEnvWith(Config{}, env); cfg.URL != "http://vendor:2" {
			t.Fatalf("service endpoint: %s", cfg.URL)
		}
		delete(env, "AWS_ENDPOINT_URL_SECRETS_MANAGER")
		delete(env, "AWS_REGION")
		if cfg, _ = ConfigFromEnvWith(Config{}, env); cfg.URL != "http://all:3" || cfg.Region != "us-west-2" {
			t.Fatalf("global endpoint/default region: %s", cfg)
		}
		env[EnvPrefix+"REGION"] = "ap-south-1"
		env[EnvPrefix+"ACCESS_KEY_ID"] = "AKIDGROW"
		env[EnvPrefix+"SECRET_ACCESS_KEY"] = "grow-secret"
		env[EnvPrefix+"SESSION_TOKEN"] = "grow-session"
		env[EnvPrefix+"PROFILE"] = "grow-profile"
		env[EnvPrefix+"ROLE_ARN"] = "arn:aws:iam::123456789012:role/app"
		env[EnvPrefix+"EXTERNAL_ID"] = "ext-1"
		env[EnvPrefix+"RECOVERY_WINDOW_DAYS"] = "7"
		cfg, err = ConfigFromEnvWith(Config{}, env)
		if err != nil || cfg.Region != "ap-south-1" || cfg.AccessKeyID != "AKIDGROW" || cfg.SecretAccessKey.Reveal() != "grow-secret" ||
			cfg.SessionToken.Reveal() != "grow-session" || cfg.Profile != "grow-profile" || cfg.RoleARN == "" ||
			cfg.RoleSessionName != DefaultRoleSessionName || cfg.ExternalID != "ext-1" || cfg.RecoveryWindowDays != 7 {
			t.Fatalf("GROW_* must beat AWS_*: %v %s", err, cfg)
		}
		cfg, _ = ConfigFromEnvWith(Config{CommonConfig: CommonConfig{URL: "https://explicit"}, Region: "explicit-1"}, env)
		if cfg.URL != "https://explicit" || cfg.Region != "explicit-1" {
			t.Fatal("explicit must win")
		}
		cfg, err = ConfigFromEnvWith(Config{}, map[string]string{})
		if err != nil || cfg.URL != "" || cfg.RequestTimeout != DefaultRequestTimeout || cfg.RecoveryWindowDays != DefaultRecoveryWindowDays {
			t.Fatalf("defaults: %v %s", err, cfg)
		}
		_, err = ConfigFromEnvWith(Config{}, map[string]string{EnvPrefix + "TOTAL_TIMEOUT": "forever-xyz"})
		if !errors.Is(err, ErrConfig) || !strings.Contains(err.Error(), EnvPrefix+"TOTAL_TIMEOUT") || strings.Contains(err.Error(), "forever-xyz") {
			t.Fatalf("invalid value: %v", err)
		}
		if _, err := ConfigFromEnvWith(Config{}, map[string]string{EnvPrefix + "RECOVERY_WINDOW_DAYS": "x"}); !errors.Is(err, ErrConfig) {
			t.Fatalf("invalid int: %v", err)
		}
		if _, err := ConfigFromEnvWith(Config{}, map[string]string{EnvPrefix + "URL": "ftp://nope"}); !errors.Is(err, ErrConfig) {
			t.Fatalf("invalid url: %v", err)
		}
		withSDK, err := ConfigFromEnvWith(Config{SDKClient: &secretsmanager.Client{}}, map[string]string{"AWS_ACCESS_KEY_ID": "a", "AWS_SECRET_ACCESS_KEY": "b",
			"AWS_REGION": "us-east-1", "AWS_ENDPOINT_URL": "http://x", "AWS_PROFILE": "p"})
		if err != nil || withSDK.AccessKeyID != "" || withSDK.Region != "" || withSDK.URL != "" || withSDK.Profile != "" {
			t.Fatalf("credentials env must be ignored with an SDK client: %v", err)
		}
		withCreds, err := ConfigFromEnvWith(Config{Credentials: credentials.NewStaticCredentialsProvider("a", "b", "")},
			map[string]string{"AWS_ACCESS_KEY_ID": "x", "AWS_SECRET_ACCESS_KEY": "y"})
		if err != nil || withCreds.AccessKeyID != "" {
			t.Fatalf("explicit credentials must win over the env keys: %v", err)
		}
		t.Setenv(EnvPrefix+"REGION", "process-1")
		if cfg, err := ConfigFromEnv(); err != nil || cfg.Region != "process-1" {
			t.Fatalf("process env: %v %s", err, cfg)
		}
	})

	t.Run("validate", func(t *testing.T) {
		bad := []Config{
			{CommonConfig: CommonConfig{URL: "mailto:x"}},
			{AccessKeyID: "a"},
			{SecretAccessKey: NewSecret("s")},
			{SessionToken: NewSecret("s")},
			{RecoveryWindowDays: 3},
			{RecoveryWindowDays: 31},
			{RoleARN: "arn:aws:iam::1:role/r", RoleDuration: time.Minute},
			{RoleARN: "role/r"},
			{Credentials: credentials.NewStaticCredentialsProvider("a", "b", ""), AccessKeyID: "a", SecretAccessKey: NewSecret("b")},
			{SDKClient: &secretsmanager.Client{}, Region: "us-east-1"},
			{SDKClient: &secretsmanager.Client{}, CommonConfig: CommonConfig{URL: "http://x"}},
			{ExternalID: "x"},
			{Region: "us east"},
			{SDKClient: &secretsmanager.Client{}, Profile: "p"},
		}
		for i, c := range bad {
			if err := c.Validate(); !errors.Is(err, ErrConfig) {
				t.Errorf("case %d: %v", i, err)
			}
		}
		if err := (Config{Region: "us-east-1", RoleARN: "arn:aws:iam::1:role/r", ExternalID: "x", RoleDuration: time.Hour, RecoveryWindowDays: 30}).Validate(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("core.redaction.config", func(t *testing.T) {
		cfg := Config{
			CommonConfig:    CommonConfig{URL: "https://h", Headers: map[string]string{"X-Api-Key": "hdr-xyz"}},
			Region:          "us-east-1",
			AccessKeyID:     "AKIDxyz",
			SecretAccessKey: NewSecret("sk-xyz"),
			SessionToken:    NewSecret("st-xyz"),
			Profile:         "dev",
			RoleARN:         "arn:aws:iam::1:role/r",
			ExternalID:      "ext-xyz",
			Credentials:     credentials.NewStaticCredentialsProvider("a", "cred-xyz", ""),
			SDKClient:       &secretsmanager.Client{},
		}
		forms := fmt.Sprintf("%v|%+v|%#v|%s", cfg, cfg, cfg, cfg.String())
		for _, s := range []string{"sk-xyz", "st-xyz", "hdr-xyz", "ext-xyz", "AKIDxyz", "cred-xyz"} {
			if strings.Contains(forms, s) {
				t.Fatalf("%s leaked: %s", s, forms)
			}
		}
		if !strings.Contains(forms, "SecretAccessKey:"+Redacted) || !strings.Contains(forms, "SDKClient:custom") {
			t.Fatalf("forms: %s", forms)
		}
	})
}

func TestNewClient(t *testing.T) {
	t.Run("invalid config", func(t *testing.T) {
		if _, err := NewClient(Config{CommonConfig: CommonConfig{URL: "mailto:x"}}); !errors.Is(err, ErrConfig) {
			t.Fatalf("NewClient: %v", err)
		}
		if _, err := NewClient(Config{Region: "us-east-1", CommonConfig: CommonConfig{TLS: TLSConfig{CACertPEM: "bad"}}}); !errors.Is(err, ErrConfig) {
			t.Fatalf("bad TLS: %v", err)
		}
	})
	t.Run("region required", func(t *testing.T) {
		if _, err := NewClient(Config{}); !errors.Is(err, ErrConfig) || !strings.Contains(err.Error(), "region") {
			t.Fatalf("no region: %v", err)
		}
	})
	t.Run("missing profile", func(t *testing.T) {
		if _, err := NewClient(Config{Region: "us-east-1", Profile: "does-not-exist"}); !errors.Is(err, ErrConfig) {
			t.Fatalf("profile: %v", err)
		}
	})
	t.Run("profile from shared config", func(t *testing.T) {
		dir := t.TempDir()
		conf := filepath.Join(dir, "config")
		if err := os.WriteFile(conf, []byte("[profile dev]\nregion = eu-central-1\naws_access_key_id = AKIDPROFILE\naws_secret_access_key = profile-secret\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("AWS_CONFIG_FILE", conf)
		m := newAWSMock(t).serve("ping.ok")
		c, err := NewClient(Config{CommonConfig: CommonConfig{URL: m.server.URL}, Profile: "dev"})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		if _, err := c.Ping(t.Context()); err != nil {
			t.Fatal(err)
		}
		auth := m.lastRequest().Header.Get("Authorization")
		if !strings.Contains(auth, "AKIDPROFILE/") || !strings.Contains(auth, "/eu-central-1/secretsmanager/") {
			t.Fatalf("profile credentials/region not used: %s", auth)
		}
	})
	t.Run("explicit credentials provider", func(t *testing.T) {
		m := newAWSMock(t).serve("ping.ok")
		c, err := NewClient(Config{CommonConfig: CommonConfig{URL: m.server.URL}, Region: "us-east-1",
			Credentials: credentials.NewStaticCredentialsProvider("AKIDPROVIDER", "provider-secret", "")})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		if _, err := c.Ping(t.Context()); err != nil || !strings.Contains(m.lastRequest().Header.Get("Authorization"), "AKIDPROVIDER/") {
			t.Fatalf("provider credentials: %v", err)
		}
	})
	t.Run("no credentials is AUTHENTICATION", func(t *testing.T) {
		m := newAWSMock(t).serve("ping.ok")
		c, err := NewClient(Config{CommonConfig: CommonConfig{URL: m.server.URL, Retry: fastRetry(0)}, Region: "us-east-1"})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		if _, err := c.Ping(t.Context()); !errors.Is(err, ErrAuthentication) {
			t.Fatalf("no credentials: %v", err)
		}
	})
	t.Run("from env", func(t *testing.T) {
		m := newAWSMock(t).serve("ping.ok")
		t.Setenv(EnvPrefix+"URL", m.server.URL)
		t.Setenv("AWS_REGION", "us-east-1")
		t.Setenv("AWS_ACCESS_KEY_ID", testAccessKey)
		t.Setenv("AWS_SECRET_ACCESS_KEY", testSecretKey)
		c, err := NewClientFromEnv()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		if _, err := c.Ping(t.Context()); err != nil {
			t.Fatal(err)
		}
		if c.Config().URL != m.server.URL || c.SDK() == nil {
			t.Fatal("Config()/SDK()")
		}
		t.Setenv(EnvPrefix+"URL", "mailto:x")
		if _, err := NewClientFromEnv(); !errors.Is(err, ErrConfig) {
			t.Fatalf("bad env: %v", err)
		}
	})
	t.Run("assume role", func(t *testing.T) {
		var stsCalls int
		var mu sync.Mutex
		sts := newTestServer(t, func(w http.ResponseWriter, r *http.Request, _ int) {
			_ = r.ParseForm()
			mu.Lock()
			stsCalls++
			mu.Unlock()
			if r.Form.Get("Action") != "AssumeRole" || r.Form.Get("RoleSessionName") != DefaultRoleSessionName || r.Form.Get("ExternalId") != "ext-1" ||
				r.Form.Get("DurationSeconds") != "900" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "text/xml")
			_, _ = w.Write([]byte(`<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult>
<Credentials><AccessKeyId>ASIAASSUMED</AccessKeyId><SecretAccessKey>assumed-secret</SecretAccessKey><SessionToken>assumed-session</SessionToken>
<Expiration>2099-01-01T00:00:00Z</Expiration></Credentials><AssumedRoleUser><Arn>arn:aws:sts::1:assumed-role/app/grow-sdk</Arn>
<AssumedRoleId>AROA:grow-sdk</AssumedRoleId></AssumedRoleUser></AssumeRoleResult></AssumeRoleResponse>`))
		})
		t.Setenv("AWS_ENDPOINT_URL_STS", sts.URL)
		m := newAWSMock(t).serve("ping.ok")
		c := m.client(func(cfg *Config) {
			cfg.RoleARN = "arn:aws:iam::123456789012:role/app"
			cfg.ExternalID = "ext-1"
			cfg.RoleDuration = 15 * time.Minute
		})
		if _, err := c.Ping(t.Context()); err != nil {
			t.Fatal(err)
		}
		req := m.lastRequest()
		if !strings.Contains(req.Header.Get("Authorization"), "ASIAASSUMED/") || req.Header.Get("X-Amz-Security-Token") != "assumed-session" || stsCalls != 1 {
			t.Fatalf("assumed credentials not used: %s calls=%d", req.Header.Get("Authorization"), stsCalls)
		}
	})
}

// fakeAPI is a SecretsManagerAPI double: embedding the interface panics for
// every method that is not overridden.
type fakeAPI struct {
	SecretsManagerAPI
	listSecrets func(context.Context, *secretsmanager.ListSecretsInput) (*secretsmanager.ListSecretsOutput, error)
}

func (f *fakeAPI) ListSecrets(ctx context.Context, in *secretsmanager.ListSecretsInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error) {
	return f.listSecrets(ctx, in)
}

func TestClientCore(t *testing.T) {
	t.Run("health ping version", func(t *testing.T) {
		m := newAWSMock(t).serve("ping.ok")
		c := m.client(nil)
		if hs, err := c.Health(t.Context()); err != nil || !hs.Healthy || hs.Status != "ok" {
			t.Fatalf("health %+v %v", hs, err)
		}
		if d, err := c.Ping(t.Context()); err != nil || d <= 0 {
			t.Fatalf("ping %s %v", d, err)
		}
		if got := m.body("ListSecrets", 0)["MaxResults"]; got != float64(1) {
			t.Fatalf("MaxResults %v", got)
		}
		if _, err := c.ServerVersion(t.Context()); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("version: %v", err)
		}
	})

	t.Run("ping authentication errors (Moto XML 403)", func(t *testing.T) {
		for _, fx := range []string{"ping.auth-unknown-key", "ping.auth-bad-signature"} {
			c := newAWSMock(t).serve(fx).client(nil)
			_, err := c.Ping(t.Context())
			if e := asError(t, err); e.Code != ErrorCodeAuthentication || e.HTTPStatus != 403 || e.RequestID == "" || e.Retryable {
				t.Fatalf("%s: %+v", fx, e)
			}
		}
		c := newAWSMock(t).serve("createSecret.access-denied").client(nil)
		if _, err := c.CreateSecret(t.Context(), "x", "v", nil); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("access denied: %v", err)
		}
	})

	t.Run("health states", func(t *testing.T) {
		cases := []struct {
			name    string
			h       mockHandler
			healthy bool
			status  string
		}{
			{"auth failure counts as reachable", func(w http.ResponseWriter, _ *http.Request, _ map[string]any, _ int) {
				loadFixture(t, "ping.auth-unknown-key").write(w)
			}, true, "ok"},
			{"throttled", func(w http.ResponseWriter, _ *http.Request, _ map[string]any, _ int) {
				awsError(w, 400, "ThrottlingException", "slow down")
			}, true, "degraded"},
			{"server error", func(w http.ResponseWriter, _ *http.Request, _ map[string]any, _ int) {
				awsError(w, 503, "ServiceUnavailable", "down")
			}, false, "unhealthy"},
			{"validation answer", func(w http.ResponseWriter, _ *http.Request, _ map[string]any, _ int) {
				awsError(w, 400, "InvalidParameterException", "bad")
			}, true, "ok"},
		}
		for _, tc := range cases {
			m := newAWSMock(t).on("ListSecrets", tc.h)
			hs, err := m.client(nil).Health(t.Context())
			if err != nil || hs.Healthy != tc.healthy || hs.Status != tc.status {
				t.Fatalf("%s: %+v %v", tc.name, hs, err)
			}
			if m.count("ListSecrets") != 1 {
				t.Fatalf("%s: health must not retry (%d calls)", tc.name, m.count("ListSecrets"))
			}
		}
	})

	t.Run("core.health.unreachable", func(t *testing.T) {
		c := newTestClient(t, "http://"+closedAddr(t), func(cfg *Config) { cfg.ConnectTimeout = time.Second })
		if hs, err := c.Health(t.Context()); err != nil || hs.Healthy || hs.Status != "unreachable" {
			t.Fatalf("hs=%+v err=%v", hs, err)
		}
	})

	t.Run("health cancelled", func(t *testing.T) {
		c := newAWSMock(t).serve("ping.ok").client(nil)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := c.Health(ctx); !errors.Is(err, ErrCancelled) {
			t.Fatalf("cancelled: %v", err)
		}
		_ = c.Close()
		if _, err := c.Health(t.Context()); !errors.Is(err, ErrCancelled) {
			t.Fatalf("closed: %v", err)
		}
	})

	t.Run("core.close.idempotent", func(t *testing.T) {
		c := newAWSMock(t).serve("ping.ok").client(nil)
		_ = provider(t, c)
		first, second := c.Close(), c.Close()
		if first != nil || second != nil {
			t.Fatal("close")
		}
		if _, err := c.Ping(t.Context()); !errors.Is(err, ErrCancelled) {
			t.Fatalf("after close: %v", err)
		}
	})

	t.Run("core.useragent and headers", func(t *testing.T) {
		m := newAWSMock(t).serve("ping.ok")
		c := m.client(func(cfg *Config) {
			cfg.UserAgentSuffix = "my-app/1"
			cfg.Headers = map[string]string{"X-Team": "grow"}
		})
		if _, err := c.Ping(t.Context()); err != nil {
			t.Fatal(err)
		}
		req := m.lastRequest()
		ua := req.Header.Get("User-Agent")
		if !strings.Contains(ua, "grow-codes-aws-secrets-manager/"+Version+" (go) my-app/1") || !strings.Contains(ua, "aws-sdk-go-v2") {
			t.Fatalf("user agent %q", ua)
		}
		if req.Header.Get("X-Team") != "grow" {
			t.Fatal("extra header missing")
		}
	})

	t.Run("wraps a caller SDK client", func(t *testing.T) {
		calls := 0
		api := &fakeAPI{listSecrets: func(context.Context, *secretsmanager.ListSecretsInput) (*secretsmanager.ListSecretsOutput, error) {
			calls++
			return &secretsmanager.ListSecretsOutput{}, nil
		}}
		c, err := NewClient(Config{SDKClient: api})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Ping(t.Context()); err != nil || calls != 1 || c.SDK() != api {
			t.Fatalf("ping via SDK client: %v calls=%d", err, calls)
		}
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestTransportBehaviour(t *testing.T) {
	t.Run("core.retry.503-backoff", func(t *testing.T) {
		m := newAWSMock(t).on("ListSecrets", func(w http.ResponseWriter, _ *http.Request, _ map[string]any, n int) {
			if n < 3 {
				awsError(w, 503, "ServiceUnavailable", "busy")
				return
			}
			writeAWS(w, 200, `{"SecretList":[]}`)
		})
		if _, err := m.client(nil).Ping(t.Context()); err != nil || m.count("ListSecrets") != 3 {
			t.Fatalf("err=%v calls=%d", err, m.count("ListSecrets"))
		}
	})

	t.Run("core.retry.exhausted", func(t *testing.T) {
		m := newAWSMock(t).json("ListSecrets", 503, `{"__type":"ServiceUnavailable","message":"busy"}`)
		_, err := m.client(nil).Ping(t.Context())
		e := asError(t, err)
		if e.Code != ErrorCodeUnavailable || !e.Retryable || e.HTTPStatus != 503 || m.count("ListSecrets") != 4 {
			t.Fatalf("%+v calls=%d", e, m.count("ListSecrets"))
		}
	})

	t.Run("core.retry.429-retry-after", func(t *testing.T) {
		m := newAWSMock(t).on("ListSecrets", func(w http.ResponseWriter, _ *http.Request, _ map[string]any, n int) {
			if n == 1 {
				w.Header().Set("Retry-After", "1")
				awsError(w, 429, "TooManyRequestsException", "slow")
				return
			}
			writeAWS(w, 200, `{"SecretList":[]}`)
		})
		start := time.Now()
		if _, err := m.client(nil).Ping(t.Context()); err != nil || time.Since(start) < time.Second {
			t.Fatalf("err=%v elapsed=%s", err, time.Since(start))
		}
	})

	t.Run("core.retry.retry-after-too-long", func(t *testing.T) {
		m := newAWSMock(t).on("ListSecrets", func(w http.ResponseWriter, _ *http.Request, _ map[string]any, _ int) {
			w.Header().Set("Retry-After", "3600")
			awsError(w, 400, "ThrottlingException", "slow")
		})
		_, err := m.client(nil).Ping(t.Context())
		e := asError(t, err)
		if e.Code != ErrorCodeRateLimited || e.RetryAfter != time.Hour || m.count("ListSecrets") != 1 {
			t.Fatalf("%+v calls=%d", e, m.count("ListSecrets"))
		}
	})

	t.Run("core.timeout.request", func(t *testing.T) {
		m := newAWSMock(t).on("ListSecrets", func(w http.ResponseWriter, r *http.Request, _ map[string]any, _ int) {
			select {
			case <-r.Context().Done():
			case <-time.After(2 * time.Second):
			}
		})
		c := m.client(func(cfg *Config) { cfg.RequestTimeout = 50 * time.Millisecond; cfg.Retry = fastRetry(0) })
		if _, err := c.Ping(t.Context()); !errors.Is(err, ErrTimeout) {
			t.Fatalf("request timeout: %v", err)
		}
	})

	t.Run("core.timeout.total", func(t *testing.T) {
		m := newAWSMock(t).json("ListSecrets", 503, `{"__type":"ServiceUnavailable","message":"busy"}`)
		c := m.client(func(cfg *Config) {
			cfg.TotalTimeout = 150 * time.Millisecond
			p := DefaultRetryPolicy()
			p.MaxRetries = 10
			p.InitialBackoff = 100 * time.Millisecond
			p.Rand = func() float64 { return 0.99 }
			cfg.Retry = &p
		})
		if _, err := c.Ping(t.Context()); !errors.Is(err, ErrTimeout) {
			t.Fatalf("total timeout: %v", err)
		}
	})

	t.Run("core.cancel", func(t *testing.T) {
		m := newAWSMock(t).on("ListSecrets", func(w http.ResponseWriter, r *http.Request, _ map[string]any, _ int) {
			<-r.Context().Done()
		})
		ctx, cancel := context.WithTimeout(t.Context(), 0)
		defer cancel()
		ctx2, cancel2 := context.WithCancel(t.Context())
		go func() { time.Sleep(50 * time.Millisecond); cancel2() }()
		if _, err := m.client(nil).Ping(ctx2); !errors.Is(err, ErrCancelled) || !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel during request: %v", err)
		}
		if _, err := m.client(nil).Ping(ctx); !errors.Is(err, ErrTimeout) {
			t.Fatalf("expired ctx: %v", err)
		}
		// during backoff
		m2 := newAWSMock(t).json("ListSecrets", 503, `{"__type":"ServiceUnavailable","message":"busy"}`)
		c := m2.client(func(cfg *Config) {
			p := DefaultRetryPolicy()
			p.InitialBackoff, p.MaxBackoff, p.Rand = 5*time.Second, 5*time.Second, func() float64 { return 0.99 }
			cfg.Retry = &p
		})
		ctx3, cancel3 := context.WithCancel(t.Context())
		go func() { time.Sleep(100 * time.Millisecond); cancel3() }()
		if _, err := c.Ping(ctx3); !errors.Is(err, ErrCancelled) {
			t.Fatalf("cancel during backoff: %v", err)
		}
	})

	t.Run("core.hooks and core.redaction.error-text", func(t *testing.T) {
		var mu sync.Mutex
		var reqs []RequestInfo
		var resps []ResponseInfo
		var errs []ErrorInfo
		var logs strings.Builder
		m := newAWSMock(t).on("ListSecrets", func(w http.ResponseWriter, _ *http.Request, _ map[string]any, n int) {
			if n == 1 {
				awsError(w, 500, "InternalServiceError", "leaked "+testSecretKey)
				return
			}
			awsError(w, 400, "ValidationException", "bad token "+testSecretKey)
		})
		c := m.client(func(cfg *Config) {
			cfg.Logger = slog.New(slog.NewTextHandler(&lockedWriter{b: &logs, mu: &mu}, &slog.HandlerOptions{Level: slog.LevelDebug}))
			cfg.Hooks = &Hooks{
				OnRequest:  func(i RequestInfo) { mu.Lock(); reqs = append(reqs, i); mu.Unlock(); panic("ignored") },
				OnResponse: func(i ResponseInfo) { mu.Lock(); resps = append(resps, i); mu.Unlock() },
				OnError:    func(i ErrorInfo) { mu.Lock(); errs = append(errs, i); mu.Unlock() },
			}
		})
		_, err := c.Ping(t.Context())
		if !errors.Is(err, ErrValidation) || strings.Contains(err.Error(), testSecretKey) || !strings.Contains(err.Error(), Redacted) {
			t.Fatalf("err: %v", err)
		}
		mu.Lock()
		defer mu.Unlock()
		if len(reqs) != 2 || reqs[0].Attempt != 1 || reqs[1].Attempt != 2 || len(resps) != 2 || resps[0].Status != 500 || resps[0].RequestID != "req-123" {
			t.Fatalf("hooks: %+v %+v", reqs, resps)
		}
		if len(errs) != 2 || !errs[0].WillRetry || errs[1].WillRetry {
			t.Fatalf("error hooks: %+v", errs)
		}
		all := fmt.Sprintf("%v %v %v %s", reqs, resps, errs, logs.String())
		if strings.Contains(all, testSecretKey) || reqs[0].Headers.Get("Authorization") != Redacted {
			t.Fatalf("hook data not redacted: %s", all)
		}
		if !strings.Contains(logs.String(), "status=500") {
			t.Fatalf("logs: %s", logs.String())
		}
	})

	t.Run("network error hook", func(t *testing.T) {
		var errs []ErrorInfo
		c := newTestClient(t, "http://"+closedAddr(t), func(cfg *Config) {
			cfg.Retry = fastRetry(1)
			cfg.Hooks = &Hooks{OnError: func(i ErrorInfo) { errs = append(errs, i) }}
		})
		if _, err := c.Ping(t.Context()); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("network: %v", err)
		}
		if len(errs) != 2 || !errs[0].WillRetry || errs[1].WillRetry {
			t.Fatalf("hooks: %+v", errs)
		}
	})
}

type lockedWriter struct {
	b  *strings.Builder
	mu *sync.Mutex
}

func (w *lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}
