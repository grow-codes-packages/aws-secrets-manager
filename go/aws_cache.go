package awssecretsmanager

import (
	"container/list"
	"context"
	"strings"
	"sync"
	"time"
)

// AWS caching-client defaults (aws-secretsmanager-caching-*).
const (
	DefaultAWSCacheTTL        = time.Hour
	DefaultAWSCacheMaxEntries = 1024
)

// refreshRetry is the first delay before a failed refresh is retried; it
// doubles per failure and is capped at the TTL.
const refreshRetry = time.Second

// AWSCacheOptions returns options for the generic SecretCache with the AWS
// caching-client defaults: TTL 1 h and 1024 entries (SPEC defaults are 60 s / 1000).
//
//	p, _ := client.Secrets()
//	cache := awssecretsmanager.NewSecretCache(p, awssecretsmanager.AWSCacheOptions())
func AWSCacheOptions() *CacheOptions {
	return &CacheOptions{TTL: DefaultAWSCacheTTL, MaxEntries: DefaultAWSCacheMaxEntries}
}

// SecretCacheSource is what AWSSecretCache reads from; *Client implements it.
type SecretCacheSource interface {
	GetSecretValue(ctx context.Context, id string, opts *GetSecretValueOptions) (*AWSSecretValue, error)
	DescribeSecret(ctx context.Context, id string) (*SecretDescription, error)
}

var _ SecretCacheSource = (*Client)(nil)

// AWSSecretCacheOptions configure an AWSSecretCache. Zero values use the defaults.
type AWSSecretCacheOptions struct {
	// TTL is the refresh interval (default 1 h).
	TTL time.Duration
	// MaxEntries is the LRU capacity (default 1024).
	MaxEntries int
	// VersionStage is the default stage label (default AWSCURRENT).
	VersionStage string
	// Clock returns the current time (default time.Now).
	Clock func() time.Time
	// OnRefreshError is called when a refresh fails and the cached value is
	// served instead.
	OnRefreshError func(error)
}

// CacheGetOptions select the stage of an AWSSecretCache read.
type CacheGetOptions struct {
	// VersionStage overrides the cache's default stage.
	VersionStage string
}

// AWSSecretCacheStats are AWSSecretCache counters.
type AWSSecretCacheStats struct {
	Hits   int `json:"hits"`
	Misses int `json:"misses"`
	// Refreshes counts expired entries checked with DescribeSecret.
	Refreshes int `json:"refreshes"`
	// VersionChanges counts refreshes that fetched a new version.
	VersionChanges int `json:"versionChanges"`
	Evictions      int `json:"evictions"`
	Size           int `json:"size"`
}

// AWSSecretCache is a version-stage aware cache with the semantics of the AWS
// caching clients: entries per (secretId, versionStage), TTL 1 h and 1024
// entries by default. When an entry expires, DescribeSecret checks whether the
// stage moved to another version and GetSecretValue runs only when it did.
// Concurrent reads of one key share one request. A refresh that fails keeps
// serving the cached value and is retried with exponential backoff; a first
// read that fails returns the error. It is safe for concurrent use.
type AWSSecretCache struct {
	source SecretCacheSource
	opts   AWSSecretCacheOptions

	mu       sync.Mutex
	items    map[string]*list.Element
	lru      *list.List
	inflight map[string]*cacheFlight
	stats    AWSSecretCacheStats
}

type awsCacheEntry struct {
	key       string
	secretID  string
	value     *AWSSecretValue
	checkedAt time.Time
	failures  int
}

type cacheFlight struct {
	done  chan struct{}
	value *AWSSecretValue
	err   error
}

// NewAWSSecretCache returns a cache over source (usually a *Client). opts may
// be nil. A negative TTL or MaxEntries or a blank VersionStage is a VALIDATION error.
func NewAWSSecretCache(source SecretCacheSource, opts *AWSSecretCacheOptions) (*AWSSecretCache, error) {
	var o AWSSecretCacheOptions
	if opts != nil {
		o = *opts
	}
	switch {
	case o.TTL < 0:
		return nil, ValidationError("secretCache", "ttl must be > 0")
	case o.MaxEntries < 0:
		return nil, ValidationError("secretCache", "maxEntries must be >= 1")
	case o.VersionStage != "" && strings.TrimSpace(o.VersionStage) == "":
		return nil, ValidationError("secretCache", "versionStage must not be blank")
	}
	if o.TTL == 0 {
		o.TTL = DefaultAWSCacheTTL
	}
	if o.MaxEntries == 0 {
		o.MaxEntries = DefaultAWSCacheMaxEntries
	}
	if o.VersionStage == "" {
		o.VersionStage = StageCurrent
	}
	if o.Clock == nil {
		o.Clock = time.Now
	}
	return &AWSSecretCache{source: source, opts: o, items: map[string]*list.Element{}, lru: list.New(),
		inflight: map[string]*cacheFlight{}}, nil
}

func (c *AWSSecretCache) stage(opts *CacheGetOptions) string {
	if opts != nil && opts.VersionStage != "" {
		return opts.VersionStage
	}
	return c.opts.VersionStage
}

func cacheKeyOf(id, stage string) string { return id + "\x00" + stage }

// GetSecretValue returns the cached value of id at the stage (default AWSCURRENT).
func (c *AWSSecretCache) GetSecretValue(ctx context.Context, id string, opts *CacheGetOptions) (*AWSSecretValue, error) {
	stage := c.stage(opts)
	key := cacheKeyOf(id, stage)
	c.mu.Lock()
	if el, ok := c.items[key]; ok {
		c.stats.Hits++
		c.lru.MoveToFront(el)
		e := el.Value.(*awsCacheEntry)
		if c.opts.Clock().Sub(e.checkedAt) < c.nextCheckAfter(e) {
			v := e.value
			c.mu.Unlock()
			return v, nil
		}
		c.mu.Unlock()
		return c.coalesce(key, func() (*AWSSecretValue, error) { return c.refresh(ctx, e, stage), nil })
	}
	c.stats.Misses++
	c.mu.Unlock()
	return c.coalesce(key, func() (*AWSSecretValue, error) {
		v, err := c.source.GetSecretValue(ctx, id, &GetSecretValueOptions{VersionStage: stage})
		if err != nil {
			return nil, err
		}
		c.store(&awsCacheEntry{key: key, secretID: id, value: v, checkedAt: c.opts.Clock()})
		return v, nil
	})
}

// GetSecretString returns the cached value as text (VALIDATION error for
// binary data that is not UTF-8).
func (c *AWSSecretCache) GetSecretString(ctx context.Context, id string, opts *CacheGetOptions) (string, error) {
	v, err := c.GetSecretValue(ctx, id, opts)
	if err != nil {
		return "", err
	}
	return v.Value.Reveal()
}

// GetSecretBinary returns the cached value as bytes.
func (c *AWSSecretCache) GetSecretBinary(ctx context.Context, id string, opts *CacheGetOptions) ([]byte, error) {
	v, err := c.GetSecretValue(ctx, id, opts)
	if err != nil {
		return nil, err
	}
	return v.Value.RevealBytes(), nil
}

// RefreshNow forces a refresh check now (and a fetch when the stage moved)
// and returns the value.
func (c *AWSSecretCache) RefreshNow(ctx context.Context, id string, opts *CacheGetOptions) (*AWSSecretValue, error) {
	c.mu.Lock()
	if el, ok := c.items[cacheKeyOf(id, c.stage(opts))]; ok {
		e := el.Value.(*awsCacheEntry)
		e.checkedAt = time.Time{}
		e.failures = 0
	}
	c.mu.Unlock()
	return c.GetSecretValue(ctx, id, opts)
}

// Invalidate drops every cached stage of id.
func (c *AWSSecretCache) Invalidate(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, el := range c.items {
		if el.Value.(*awsCacheEntry).secretID == id {
			c.lru.Remove(el)
			delete(c.items, key)
		}
	}
}

// Clear drops every entry.
func (c *AWSSecretCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = map[string]*list.Element{}
	c.lru.Init()
}

// Stats returns the counters and the current size.
func (c *AWSSecretCache) Stats() AWSSecretCacheStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.stats
	s.Size = c.lru.Len()
	return s
}

// nextCheckAfter is the TTL, or the backoff after failed refreshes. Caller holds mu.
func (c *AWSSecretCache) nextCheckAfter(e *awsCacheEntry) time.Duration {
	if e.failures == 0 {
		return c.opts.TTL
	}
	d := refreshRetry << min(e.failures-1, 30)
	return min(d, c.opts.TTL)
}

// refresh checks the stage with DescribeSecret and refetches when it moved.
// On failure it keeps the cached value and backs off.
func (c *AWSSecretCache) refresh(ctx context.Context, e *awsCacheEntry, stage string) *AWSSecretValue {
	c.mu.Lock()
	c.stats.Refreshes++
	old := e.value
	c.mu.Unlock()
	value, err := func() (*AWSSecretValue, error) {
		d, err := c.source.DescribeSecret(ctx, e.secretID)
		if err != nil {
			return nil, err
		}
		current := versionWithStage(d.VersionIDsToStages, stage)
		if current != "" && current == old.VersionID {
			return old, nil
		}
		v, err := c.source.GetSecretValue(ctx, e.secretID, &GetSecretValueOptions{VersionStage: stage})
		if err != nil {
			return nil, err
		}
		c.mu.Lock()
		c.stats.VersionChanges++
		c.mu.Unlock()
		return v, nil
	}()
	if err != nil {
		c.mu.Lock()
		e.failures++
		e.checkedAt = c.opts.Clock()
		c.mu.Unlock()
		if c.opts.OnRefreshError != nil {
			safeCall(func() { c.opts.OnRefreshError(err) })
		}
		return old
	}
	c.store(&awsCacheEntry{key: e.key, secretID: e.secretID, value: value, checkedAt: c.opts.Clock()})
	return value
}

// coalesce runs load once per key at a time; concurrent callers share the result.
func (c *AWSSecretCache) coalesce(key string, load func() (*AWSSecretValue, error)) (*AWSSecretValue, error) {
	c.mu.Lock()
	if f, ok := c.inflight[key]; ok {
		c.mu.Unlock()
		<-f.done
		return f.value, f.err
	}
	f := &cacheFlight{done: make(chan struct{})}
	c.inflight[key] = f
	c.mu.Unlock()
	f.value, f.err = load()
	c.mu.Lock()
	delete(c.inflight, key)
	c.mu.Unlock()
	close(f.done)
	return f.value, f.err
}

// store inserts or replaces an entry and evicts the least recently used ones.
func (c *AWSSecretCache) store(e *awsCacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[e.key]; ok {
		c.lru.Remove(el)
	}
	c.items[e.key] = c.lru.PushFront(e)
	for c.lru.Len() > c.opts.MaxEntries {
		last := c.lru.Back()
		c.lru.Remove(last)
		delete(c.items, last.Value.(*awsCacheEntry).key)
		c.stats.Evictions++
	}
}
