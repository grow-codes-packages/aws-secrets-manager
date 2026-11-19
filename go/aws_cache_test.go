package awssecretsmanager

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeSource is a SecretCacheSource whose current version can be moved.
type fakeSource struct {
	mu          sync.Mutex
	versions    map[string]string // stage -> version id
	values      map[string]string // version id -> value
	gets        atomic.Int32
	describes   atomic.Int32
	failGet     error
	failDesc    error
	block       chan struct{}
	binaryValue bool
}

func newFakeSource() *fakeSource {
	return &fakeSource{versions: map[string]string{StageCurrent: "v1", StagePrevious: "v0"}, values: map[string]string{"v1": "one", "v0": "zero"}}
}

func (f *fakeSource) GetSecretValue(_ context.Context, id string, opts *GetSecretValueOptions) (*AWSSecretValue, error) {
	f.gets.Add(1)
	if f.block != nil {
		<-f.block
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failGet != nil {
		return nil, f.failGet
	}
	vid, ok := f.versions[opts.VersionStage]
	if !ok {
		return nil, NotFoundError("getSecretValue "+id, "no such stage")
	}
	if f.binaryValue {
		return &AWSSecretValue{Name: id, VersionID: vid, Binary: true, Value: NewSecretValue([]byte{0xff}, vid)}, nil
	}
	return &AWSSecretValue{Name: id, VersionID: vid, Value: NewSecretString(f.values[vid], vid)}, nil
}

func (f *fakeSource) DescribeSecret(_ context.Context, id string) (*SecretDescription, error) {
	f.describes.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failDesc != nil {
		return nil, f.failDesc
	}
	m := map[string][]string{}
	for stage, vid := range f.versions {
		m[vid] = append(m[vid], stage)
	}
	return &SecretDescription{Name: id, VersionIDsToStages: m}, nil
}

func (f *fakeSource) move(stage, vid, value string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.versions[stage] = vid
	f.values[vid] = value
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func TestAWSSecretCache(t *testing.T) {
	ctx := t.Context()
	t.Run("defaults and validation", func(t *testing.T) {
		c, err := NewAWSSecretCache(newFakeSource(), nil)
		if err != nil || c.opts.TTL != time.Hour || c.opts.MaxEntries != 1024 || c.opts.VersionStage != StageCurrent {
			t.Fatalf("%+v %v", c.opts, err)
		}
		for _, o := range []AWSSecretCacheOptions{{TTL: -1}, {MaxEntries: -1}, {VersionStage: " "}} {
			if _, err := NewAWSSecretCache(newFakeSource(), &o); !errors.Is(err, ErrValidation) {
				t.Fatalf("%+v: %v", o, err)
			}
		}
		if o := AWSCacheOptions(); o.TTL != time.Hour || o.MaxEntries != 1024 {
			t.Fatal("AWSCacheOptions")
		}
	})

	t.Run("hits, stage-aware refresh, version change", func(t *testing.T) {
		src, clock := newFakeSource(), &fakeClock{now: time.Unix(1000, 0)}
		c, _ := NewAWSSecretCache(src, &AWSSecretCacheOptions{TTL: time.Minute, Clock: clock.Now})
		if s, err := c.GetSecretString(ctx, "app", nil); err != nil || s != "one" {
			t.Fatalf("%q %v", s, err)
		}
		if s, _ := c.GetSecretString(ctx, "app", nil); s != "one" || src.gets.Load() != 1 {
			t.Fatal("second read must be a hit")
		}
		if s, _ := c.GetSecretString(ctx, "app", &CacheGetOptions{VersionStage: StagePrevious}); s != "zero" || src.gets.Load() != 2 {
			t.Fatal("stage is part of the key")
		}
		clock.Add(2 * time.Minute)
		if s, _ := c.GetSecretString(ctx, "app", nil); s != "one" || src.describes.Load() != 1 || src.gets.Load() != 2 {
			t.Fatal("unchanged version: DescribeSecret only")
		}
		src.move(StageCurrent, "v2", "two")
		clock.Add(2 * time.Minute)
		if s, _ := c.GetSecretString(ctx, "app", nil); s != "two" || src.gets.Load() != 3 {
			t.Fatalf("moved stage must refetch: %q", s)
		}
		st := c.Stats()
		if st.Hits != 3 || st.Misses != 2 || st.Refreshes != 2 || st.VersionChanges != 1 || st.Size != 2 {
			t.Fatalf("%+v", st)
		}
		src.move(StageCurrent, "v3", "three")
		if v, err := c.RefreshNow(ctx, "app", nil); err != nil || v.VersionID != "v3" {
			t.Fatalf("refreshNow %+v %v", v, err)
		}
		if v, err := c.RefreshNow(ctx, "other", nil); err != nil || v.VersionID != "v3" {
			t.Fatal("refreshNow of an uncached id reads it")
		}
		if b, err := c.GetSecretBinary(ctx, "app", nil); err != nil || string(b) != "three" {
			t.Fatal("binary")
		}
		c.Invalidate("app")
		if c.Stats().Size != 1 {
			t.Fatalf("invalidate: %+v", c.Stats())
		}
		c.Clear()
		if c.Stats().Size != 0 {
			t.Fatal("clear")
		}
	})

	t.Run("failed refresh serves the cached value with backoff", func(t *testing.T) {
		src, clock := newFakeSource(), &fakeClock{now: time.Unix(1000, 0)}
		var refreshErrs atomic.Int32
		c, _ := NewAWSSecretCache(src, &AWSSecretCacheOptions{TTL: time.Minute, Clock: clock.Now,
			OnRefreshError: func(error) { refreshErrs.Add(1); panic("ignored") }})
		if _, err := c.GetSecretValue(ctx, "app", nil); err != nil {
			t.Fatal(err)
		}
		src.failDesc = errors.New("boom")
		clock.Add(2 * time.Minute)
		if s, err := c.GetSecretString(ctx, "app", nil); err != nil || s != "one" || refreshErrs.Load() != 1 {
			t.Fatalf("%q %v", s, err)
		}
		if _, _ = c.GetSecretString(ctx, "app", nil); src.describes.Load() != 1 {
			t.Fatal("backoff: no new check within 1 s")
		}
		clock.Add(1500 * time.Millisecond)
		_, _ = c.GetSecretString(ctx, "app", nil)
		if src.describes.Load() != 2 {
			t.Fatal("retry after the backoff")
		}
		src.failDesc = nil
		src.move(StageCurrent, "v9", "nine")
		src.failGet = errors.New("get failed")
		clock.Add(5 * time.Second)
		if s, _ := c.GetSecretString(ctx, "app", nil); s != "one" {
			t.Fatal("a failed refetch keeps the value")
		}
	})

	t.Run("first read error, eviction, coalescing, binary", func(t *testing.T) {
		src := newFakeSource()
		c, _ := NewAWSSecretCache(src, &AWSSecretCacheOptions{MaxEntries: 1})
		if _, err := c.GetSecretValue(ctx, "app", &CacheGetOptions{VersionStage: "NOPE"}); !errors.Is(err, ErrNotFound) {
			t.Fatal(err)
		}
		if _, err := c.GetSecretString(ctx, "app", &CacheGetOptions{VersionStage: "NOPE"}); err == nil {
			t.Fatal("string error")
		}
		if _, err := c.GetSecretBinary(ctx, "app", &CacheGetOptions{VersionStage: "NOPE"}); err == nil {
			t.Fatal("binary error")
		}
		_, _ = c.GetSecretValue(ctx, "a", nil)
		_, _ = c.GetSecretValue(ctx, "b", nil)
		if st := c.Stats(); st.Evictions != 1 || st.Size != 1 {
			t.Fatalf("%+v", st)
		}
		src2 := newFakeSource()
		src2.block = make(chan struct{})
		c2, _ := NewAWSSecretCache(src2, nil)
		var wg sync.WaitGroup
		for range 5 {
			wg.Add(1)
			go func() { defer wg.Done(); _, _ = c2.GetSecretValue(ctx, "app", nil) }()
		}
		time.Sleep(50 * time.Millisecond)
		close(src2.block)
		wg.Wait()
		if src2.gets.Load() != 1 {
			t.Fatalf("coalescing: %d gets", src2.gets.Load())
		}
		src3 := newFakeSource()
		src3.binaryValue = true
		c3, _ := NewAWSSecretCache(src3, nil)
		if _, err := c3.GetSecretString(ctx, "bin", nil); !errors.Is(err, ErrValidation) {
			t.Fatal("non-UTF-8 binary as string")
		}
	})

	t.Run("over the client", func(t *testing.T) {
		m := newAWSMock(t).serve("getSecretValue.ok-version-stage").serve("describeSecret.ok")
		c := m.client(nil)
		cache, err := c.SecretCache(&AWSSecretCacheOptions{VersionStage: StagePrevious})
		if err != nil {
			t.Fatal(err)
		}
		v, err := cache.GetSecretValue(ctx, db, nil)
		if err != nil || v.VersionStages[0] != StagePrevious || m.body("GetSecretValue", 0)["VersionStage"] != StagePrevious {
			t.Fatalf("%+v %v", v, err)
		}
	})
}

func TestProviderRecoveryWindow(t *testing.T) {
	b, m := newFakeBackend(t)
	b.put("a", "1")
	c := m.client(nil)
	p, err := c.Secrets(SecretsOptions{RecoveryWindowDays: 7})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Delete(t.Context(), "a", nil); err != nil || m.body("DeleteSecret", 0)["RecoveryWindowInDays"] != float64(7) {
		t.Fatalf("%v %v", err, m.body("DeleteSecret", 0))
	}
	_ = c.Close()
	if p2, err := c.Secrets(); err != nil || p2 == nil {
		t.Fatal("Secrets after Close still returns a (stopped) provider")
	}
}
