package awssecretsmanager

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/ratelimit"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// SecretsManagerAPI is the subset of the AWS SDK for Go v2 Secrets Manager
// client this package uses. *secretsmanager.Client implements it; pass your own
// client (or a test double) in Config.SDKClient.
type SecretsManagerAPI interface {
	GetSecretValue(context.Context, *secretsmanager.GetSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
	BatchGetSecretValue(context.Context, *secretsmanager.BatchGetSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.BatchGetSecretValueOutput, error)
	DescribeSecret(context.Context, *secretsmanager.DescribeSecretInput, ...func(*secretsmanager.Options)) (*secretsmanager.DescribeSecretOutput, error)
	ListSecrets(context.Context, *secretsmanager.ListSecretsInput, ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error)
	ListSecretVersionIds(context.Context, *secretsmanager.ListSecretVersionIdsInput, ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretVersionIdsOutput, error)
	CreateSecret(context.Context, *secretsmanager.CreateSecretInput, ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error)
	PutSecretValue(context.Context, *secretsmanager.PutSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error)
	UpdateSecret(context.Context, *secretsmanager.UpdateSecretInput, ...func(*secretsmanager.Options)) (*secretsmanager.UpdateSecretOutput, error)
	UpdateSecretVersionStage(context.Context, *secretsmanager.UpdateSecretVersionStageInput, ...func(*secretsmanager.Options)) (*secretsmanager.UpdateSecretVersionStageOutput, error)
	DeleteSecret(context.Context, *secretsmanager.DeleteSecretInput, ...func(*secretsmanager.Options)) (*secretsmanager.DeleteSecretOutput, error)
	RestoreSecret(context.Context, *secretsmanager.RestoreSecretInput, ...func(*secretsmanager.Options)) (*secretsmanager.RestoreSecretOutput, error)
	TagResource(context.Context, *secretsmanager.TagResourceInput, ...func(*secretsmanager.Options)) (*secretsmanager.TagResourceOutput, error)
	UntagResource(context.Context, *secretsmanager.UntagResourceInput, ...func(*secretsmanager.Options)) (*secretsmanager.UntagResourceOutput, error)
	PutResourcePolicy(context.Context, *secretsmanager.PutResourcePolicyInput, ...func(*secretsmanager.Options)) (*secretsmanager.PutResourcePolicyOutput, error)
	GetResourcePolicy(context.Context, *secretsmanager.GetResourcePolicyInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetResourcePolicyOutput, error)
	DeleteResourcePolicy(context.Context, *secretsmanager.DeleteResourcePolicyInput, ...func(*secretsmanager.Options)) (*secretsmanager.DeleteResourcePolicyOutput, error)
	ValidateResourcePolicy(context.Context, *secretsmanager.ValidateResourcePolicyInput, ...func(*secretsmanager.Options)) (*secretsmanager.ValidateResourcePolicyOutput, error)
	RotateSecret(context.Context, *secretsmanager.RotateSecretInput, ...func(*secretsmanager.Options)) (*secretsmanager.RotateSecretOutput, error)
	CancelRotateSecret(context.Context, *secretsmanager.CancelRotateSecretInput, ...func(*secretsmanager.Options)) (*secretsmanager.CancelRotateSecretOutput, error)
	GetRandomPassword(context.Context, *secretsmanager.GetRandomPasswordInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetRandomPasswordOutput, error)
}

var _ SecretsManagerAPI = (*secretsmanager.Client)(nil)

// attemptKey carries the per-call attempt counter through the SDK stack.
type attemptKey struct{}

// attemptCounter is an Initialize middleware that puts a fresh attempt counter
// into the context of every operation; the HTTP client increments it.
var attemptCounter = middleware.InitializeMiddlewareFunc("GrowAttemptCounter",
	func(ctx context.Context, in middleware.InitializeInput, next middleware.InitializeHandler) (
		middleware.InitializeOutput, middleware.Metadata, error,
	) {
		return next.HandleInitialize(context.WithValue(ctx, attemptKey{}, new(atomic.Int32)), in)
	})

func addAttemptCounter(stack *middleware.Stack) error {
	return stack.Initialize.Add(attemptCounter, middleware.Before)
}

// hookedHTTPClient is the SDK's HTTP client: it adds the Grow User-Agent and
// extra headers (after signing; neither is signed), fires the hooks and logs
// every attempt at debug level.
type hookedHTTPClient struct {
	client      *http.Client
	userAgent   string
	headers     map[string]string
	hooks       *Hooks
	logger      *slog.Logger
	maxAttempts int
	now         func() time.Time
}

// Do implements the SDK HTTPClient interface.
func (h *hookedHTTPClient) Do(req *http.Request) (*http.Response, error) {
	attempt := 1
	if c, ok := req.Context().Value(attemptKey{}).(*atomic.Int32); ok {
		attempt = int(c.Add(1))
	}
	for k, v := range h.headers {
		req.Header.Set(k, v)
	}
	if ua := req.Header.Get("User-Agent"); ua != "" {
		req.Header.Set("User-Agent", ua+" "+h.userAgent)
	} else {
		req.Header.Set("User-Agent", h.userAgent)
	}
	safeURL := RedactURL(req.URL.String())
	op := req.Header.Get("X-Amz-Target")
	h.hooks.request(RequestInfo{Method: req.Method, URL: safeURL, Headers: RedactHeaders(req.Header), Attempt: attempt})
	start := h.now()
	res, err := h.client.Do(req) //nolint:gosec // the SDK built req for the configured endpoint
	if err != nil {
		willRetry := attempt < h.maxAttempts && req.Context().Err() == nil
		h.hooks.error(ErrorInfo{Method: req.Method, URL: safeURL, Err: errors.New("request failed: " + innerMessage(err)), Attempt: attempt, WillRetry: willRetry})
		h.log(slog.LevelDebug, "request failed", slog.String("operation", op), slog.Int("attempt", attempt))
		return nil, err
	}
	rid := requestID(res.Header)
	h.hooks.response(ResponseInfo{Method: req.Method, URL: safeURL, Status: res.StatusCode, Duration: h.now().Sub(start), Attempt: attempt, RequestID: rid})
	if res.StatusCode >= 400 {
		willRetry := attempt < h.maxAttempts && (res.StatusCode >= 500 || res.StatusCode == http.StatusTooManyRequests)
		h.hooks.error(ErrorInfo{Method: req.Method, URL: safeURL, Err: StatusError(op, res.StatusCode, rid, "", nil), Attempt: attempt, WillRetry: willRetry})
	}
	h.log(slog.LevelDebug, "response", slog.String("operation", op), slog.Int("status", res.StatusCode),
		slog.Int("attempt", attempt), slog.String("requestId", rid))
	return res, nil
}

func (h *hookedHTTPClient) log(level slog.Level, msg string, attrs ...slog.Attr) {
	safeCall(func() { h.logger.LogAttrs(context.Background(), level, msg, attrs...) })
}

// growBackoff applies the SPEC full-jitter backoff (RetryPolicy.Backoff) to
// the SDK standard retryer and honours Retry-After up to MaxRetryAfter.
type growBackoff struct {
	policy RetryPolicy
	now    func() time.Time
}

// BackoffDelay implements retry.BackoffDelayer. attempt is 1-based.
func (b growBackoff) BackoffDelay(attempt int, err error) (time.Duration, error) {
	d := b.policy.Backoff(attempt - 1)
	if ra, ok := retryAfterOf(err, b.now()); ok {
		if ra > b.policy.MaxRetryAfter {
			return 0, err // stop retrying; the mapped error carries RetryAfter
		}
		if ra > d {
			d = ra
		}
	}
	return d, nil
}

// retryAfterOf returns the Retry-After of the HTTP response behind err.
func retryAfterOf(err error, now time.Time) (time.Duration, bool) {
	var re *smithyhttp.ResponseError
	if errors.As(err, &re) && re.Response != nil {
		return ParseRetryAfter(re.Response.Header.Get("Retry-After"), now)
	}
	return 0, false
}

// newRetryer maps the Grow retry policy onto the SDK standard retry mode
// (maxAttempts = maxRetries + 1, no client-side retry quota).
func newRetryer(p RetryPolicy, now func() time.Time) aws.Retryer {
	p = p.withDefaults()
	return retry.NewStandard(func(o *retry.StandardOptions) {
		o.MaxAttempts = p.MaxRetries + 1
		o.MaxBackoff = p.MaxBackoff
		o.Backoff = growBackoff{policy: p, now: now}
		o.RateLimiter = ratelimit.None
	})
}

// noRetry disables retries for one call (health).
func noRetry(o *secretsmanager.Options) { o.Retryer = aws.NopRetryer{} }
