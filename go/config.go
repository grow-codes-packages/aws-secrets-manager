package awssecretsmanager

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

var regionPattern = regexp.MustCompile(`^[a-z0-9-]+$`)

// APIVersion is the AWS Secrets Manager API contract date. AWS publishes no
// server version; ServerVersion returns an UNSUPPORTED error instead.
const APIVersion = "2017-10-17"

// DefaultRecoveryWindowDays is the recovery window used by DeleteSecret and
// SecretsProvider.Delete when none is given (the AWS default).
const DefaultRecoveryWindowDays = 30

// DefaultRoleSessionName is the session name used by the assume-role helper.
const DefaultRoleSessionName = "grow-sdk"

// urlPlaceholder stands in for an empty URL (the SDK resolves the regional
// endpoint) when the common configuration rules are checked.
const urlPlaceholder = "https://secretsmanager.amazonaws.com"

// vendorEnv lists the vendor variables consulted after GROW_AWS_SECRETS_MANAGER_*.
var vendorEnv = VendorEnv{URL: []string{"AWS_ENDPOINT_URL_SECRETS_MANAGER", "AWS_ENDPOINT_URL"}}

// Vendor variables of the AWS-specific fields, in precedence order.
var (
	vendorRegionEnv       = []string{"AWS_REGION", "AWS_DEFAULT_REGION"}
	vendorAccessKeyEnv    = []string{"AWS_ACCESS_KEY_ID"}
	vendorSecretKeyEnv    = []string{"AWS_SECRET_ACCESS_KEY"}
	vendorSessionTokenEnv = []string{"AWS_SESSION_TOKEN"}
	vendorProfileEnv      = []string{"AWS_PROFILE"}
)

// Config configures a Client. Build it with a struct literal or ConfigFromEnv;
// zero values mean "use the default". Call Validate to check it.
//
// URL is the endpoint override (for example http://localhost:5000 for an
// emulator); empty means the SDK resolves https://secretsmanager.<region>.amazonaws.com.
// Credentials left empty come from the standard AWS chain (environment, shared
// config and SSO, web identity, container and instance metadata).
type Config struct {
	CommonConfig

	// Region is the AWS region (env GROW_AWS_SECRETS_MANAGER_REGION, AWS_REGION,
	// AWS_DEFAULT_REGION, then the profile's region).
	Region string
	// AccessKeyID is a static access key id (env GROW_AWS_SECRETS_MANAGER_ACCESS_KEY_ID,
	// AWS_ACCESS_KEY_ID). It requires SecretAccessKey.
	AccessKeyID string
	// SecretAccessKey is the static secret key (env ..._SECRET_ACCESS_KEY, AWS_SECRET_ACCESS_KEY).
	SecretAccessKey Secret
	// SessionToken is the optional session token of temporary credentials
	// (env ..._SESSION_TOKEN, AWS_SESSION_TOKEN).
	SessionToken Secret
	// Credentials is an AWS SDK credentials provider used instead of the key
	// fields and the default chain (for example from stscreds or ssocreds).
	Credentials aws.CredentialsProvider
	// Profile selects a shared config profile (env ..._PROFILE, AWS_PROFILE).
	Profile string
	// RoleARN makes the client assume this IAM role with STS on top of the base
	// credentials (env ..._ROLE_ARN; AWS_ROLE_ARN stays with the SDK web-identity chain).
	RoleARN string
	// RoleSessionName is the assume-role session name (default "grow-sdk",
	// env ..._ROLE_SESSION_NAME).
	RoleSessionName string
	// ExternalID is the assume-role external id (env ..._EXTERNAL_ID).
	ExternalID string
	// RoleDuration is the assumed-role session duration (0 = STS default of 1 h).
	RoleDuration time.Duration
	// RecoveryWindowDays is the default recovery window of deletes, 7–30 (default 30).
	RecoveryWindowDays int
	// SDKClient wraps an existing AWS SDK client (*secretsmanager.Client or any
	// SecretsManagerAPI). It excludes the credential, profile, role, region and
	// URL fields; timeouts,
	// retries, TLS, proxy, headers and hooks then belong to that client, and
	// Close never closes it.
	SDKClient SecretsManagerAPI
}

// ConfigFromEnv reads the configuration from the process environment.
func ConfigFromEnv() (Config, error) { return ConfigFromEnvWith(Config{}, nil) }

// ConfigFromEnvWith resolves explicit values > GROW_AWS_SECRETS_MANAGER_* > AWS
// variables > defaults. env replaces the process environment when non-nil.
func ConfigFromEnvWith(explicit Config, env map[string]string) (Config, error) {
	r := NewEnvReader(EnvPrefix, env)
	c := explicit
	if err := c.applyEnv(r, vendorEnv); err != nil {
		return Config{}, err
	}
	if c.SDKClient != nil {
		c.URL = explicit.URL // the caller's client has its own endpoint
	}
	setString := func(dst *string, name string, vendor []string) {
		if *dst == "" {
			if v, ok := r.String(name, vendor...); ok {
				*dst = v
			}
		}
	}
	setSecret := func(dst *Secret, name string, vendor []string) {
		if dst.IsZero() {
			if v, ok := r.String(name, vendor...); ok {
				*dst = NewSecret(v)
			}
		}
	}
	if c.SDKClient == nil {
		setString(&c.Region, "REGION", vendorRegionEnv)
		if c.Credentials == nil {
			setString(&c.AccessKeyID, "ACCESS_KEY_ID", vendorAccessKeyEnv)
			setSecret(&c.SecretAccessKey, "SECRET_ACCESS_KEY", vendorSecretKeyEnv)
			setSecret(&c.SessionToken, "SESSION_TOKEN", vendorSessionTokenEnv)
		}
		setString(&c.Profile, "PROFILE", vendorProfileEnv)
		setString(&c.RoleARN, "ROLE_ARN", nil)
		setString(&c.RoleSessionName, "ROLE_SESSION_NAME", nil)
		setString(&c.ExternalID, "EXTERNAL_ID", nil)
	}
	if c.RecoveryWindowDays == 0 {
		n, ok, err := r.Int("RECOVERY_WINDOW_DAYS")
		if err != nil {
			return Config{}, err
		}
		if ok {
			c.RecoveryWindowDays = n
		}
	}
	c = c.withServiceDefaults()
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// withServiceDefaults applies the common and AWS-specific defaults; URL stays
// empty when unset (the SDK resolves the endpoint).
func (c Config) withServiceDefaults() Config {
	url := c.URL
	c.CommonConfig = c.withDefaults(urlPlaceholder)
	c.URL = url
	if c.RecoveryWindowDays == 0 {
		c.RecoveryWindowDays = DefaultRecoveryWindowDays
	}
	if c.RoleARN != "" && c.RoleSessionName == "" {
		c.RoleSessionName = DefaultRoleSessionName
	}
	return c
}

// Validate checks the configuration and returns a CONFIG error.
func (c Config) Validate() error {
	common := c.withDefaults(urlPlaceholder)
	if common.URL == "" {
		common.URL = urlPlaceholder
	}
	if err := common.validate(); err != nil {
		return err
	}
	if c.SDKClient != nil && (c.AccessKeyID != "" || !c.SecretAccessKey.IsZero() || !c.SessionToken.IsZero() ||
		c.Credentials != nil || c.Profile != "" || c.RoleARN != "" || c.Region != "" || c.URL != "") {
		return ConfigError("sdkClient cannot be combined with credentials, profile, roleArn, region or url")
	}
	if c.Credentials != nil && c.AccessKeyID != "" {
		return ConfigError("credentials and accessKeyId/secretAccessKey are mutually exclusive")
	}
	if (c.AccessKeyID == "") != c.SecretAccessKey.IsZero() {
		return ConfigError("accessKeyId and secretAccessKey must be given together")
	}
	if !c.SessionToken.IsZero() && c.AccessKeyID == "" {
		return ConfigError("sessionToken requires accessKeyId and secretAccessKey")
	}
	if c.RecoveryWindowDays != 0 && (c.RecoveryWindowDays < 7 || c.RecoveryWindowDays > 30) {
		return ConfigError("recoveryWindowDays must be between 7 and 30")
	}
	if c.RoleARN != "" && !strings.HasPrefix(c.RoleARN, "arn:") {
		return ConfigError("roleArn must be an ARN")
	}
	if c.RoleDuration != 0 && (c.RoleDuration < 15*time.Minute || c.RoleDuration > 12*time.Hour) {
		return ConfigError("roleDuration must be between 15m and 12h")
	}
	if c.RoleARN == "" && (c.ExternalID != "" || c.RoleDuration != 0) {
		return ConfigError("externalId and roleDuration require roleArn")
	}
	if c.Region != "" && !regionPattern.MatchString(c.Region) {
		return ConfigError("region must look like us-east-1")
	}
	return nil
}

// String renders the configuration with every credential redacted.
func (c Config) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Config{%s Region:%s", c.describe(), c.Region)
	if c.AccessKeyID != "" {
		fmt.Fprintf(&b, " AccessKeyID:%s SecretAccessKey:%s", Redacted, c.SecretAccessKey)
	}
	if !c.SessionToken.IsZero() {
		fmt.Fprintf(&b, " SessionToken:%s", c.SessionToken)
	}
	if c.Credentials != nil {
		b.WriteString(" Credentials:custom")
	}
	if c.Profile != "" {
		fmt.Fprintf(&b, " Profile:%s", c.Profile)
	}
	if c.RoleARN != "" {
		fmt.Fprintf(&b, " RoleARN:%s RoleSessionName:%s", c.RoleARN, c.RoleSessionName)
		if c.ExternalID != "" {
			fmt.Fprintf(&b, " ExternalID:%s", Redacted)
		}
	}
	fmt.Fprintf(&b, " RecoveryWindowDays:%d", c.RecoveryWindowDays)
	if c.SDKClient != nil {
		b.WriteString(" SDKClient:custom")
	}
	b.WriteString("}")
	return b.String()
}

// GoString renders the configuration with every credential redacted.
func (c Config) GoString() string { return c.String() }
