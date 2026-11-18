package awssecretsmanager

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestProviderRoundTrip(t *testing.T) {
	b, m := newFakeBackend(t)
	c := m.client(nil)
	p := provider(t, c)
	if _, err := c.Secrets(SecretsOptions{RecoveryWindowDays: 3}); !errors.Is(err, ErrValidation) {
		t.Fatal("bad recovery window")
	}
	ctx := t.Context()

	v1, err := p.Set(ctx, "app/alpha", "s3cr3t", &SetOptions{Tags: map[string]string{"team": "a"}, Description: "first"})
	if err != nil || v1 == "" {
		t.Fatalf("create: %q %v", v1, err)
	}
	if b.secrets["app/alpha"].desc != "first" || b.secrets["app/alpha"].tags["team"] != "a" || m.count("CreateSecret") != 1 {
		t.Fatal("create options not applied")
	}
	v2, err := p.Set(ctx, "alpha", "s3cr3t-2", &SetOptions{Path: "/app/", Tags: map[string]string{"env": "x"}, Description: "second"})
	if err != nil || v2 == v1 || m.count("PutSecretValue") != 2 || b.secrets["app/alpha"].tags["env"] != "x" || b.secrets["app/alpha"].desc != "second" {
		t.Fatalf("update: %q %v", v2, err)
	}
	got, err := p.Get(ctx, "app/alpha", nil)
	if s, _ := got.Reveal(); err != nil || s != "s3cr3t-2" || got.Version() != v2 {
		t.Fatalf("get: %v", err)
	}
	old, err := p.Get(ctx, "alpha", &GetOptions{Path: "app", Version: v1})
	if s, _ := old.Reveal(); err != nil || s != "s3cr3t" {
		t.Fatalf("get version: %v", err)
	}
	if missing, err := p.Get(ctx, "app/alpha", &GetOptions{Version: "nope"}); err != nil || missing != nil {
		t.Fatal("unknown version must be nil")
	}
	if _, err := p.Set(ctx, "bin", []byte{0xff, 0x00}, nil); err != nil {
		t.Fatal(err)
	}
	if bv, _ := p.Get(ctx, "bin", nil); !bytes.Equal(bv.RevealBytes(), []byte{0xff, 0}) || b.secrets["bin"].versions[b.secrets["bin"].order[0]].bin == nil {
		t.Fatal("binary round trip")
	}
	if _, err := p.Set(ctx, "obj", map[string]any{"a": 1}, nil); err != nil {
		t.Fatal(err)
	}
	var obj map[string]int
	if ok, err := p.GetJSON(ctx, "obj", &obj, nil); !ok || err != nil || obj["a"] != 1 {
		t.Fatal("json")
	}

	md, err := p.Metadata(ctx, "app/alpha", nil)
	if err != nil || md == nil || md.Version != v2 || md.Versions != 2 || md.Path != "app" || md.Tags["team"] != "a" || md.Extra["arn"] == "" ||
		md.Extra["description"] != "second" || md.Extra["nextRotationDate"] == "" || md.CreatedAt.IsZero() || md.UpdatedAt.IsZero() {
		t.Fatalf("metadata %+v %v", md, err)
	}
	if ok, err := p.Exists(ctx, "app/alpha", nil); !ok || err != nil {
		t.Fatal("exists")
	}

	if err := p.Delete(ctx, "app/alpha", nil); err != nil {
		t.Fatal(err)
	}
	if body := m.body("DeleteSecret", 0); body["RecoveryWindowInDays"] != float64(30) || body["ForceDeleteWithoutRecovery"] != nil {
		t.Fatalf("default delete: %v", body)
	}
	if v, err := p.Get(ctx, "app/alpha", nil); v != nil || err != nil {
		t.Fatal("pending deletion must read as missing")
	}
	if md, err := p.Metadata(ctx, "app/alpha", nil); md != nil || err != nil {
		t.Fatal("pending deletion metadata must be nil")
	}
	if err := p.Delete(ctx, "app/alpha", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
	if err := p.Delete(ctx, "obj", &DeleteOptions{Permanent: true}); err != nil || b.secrets["obj"] != nil {
		t.Fatalf("permanent: %v", err)
	}
	if err := p.Delete(ctx, "nope", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	if err := p.Delete(ctx, "bin", &DeleteOptions{Versions: []string{"x"}}); !errors.Is(err, ErrValidation) {
		t.Fatal("versions delete")
	}
	if _, err := p.Set(ctx, "x", "v", &SetOptions{CAS: new(int)}); !errors.Is(err, ErrValidation) {
		t.Fatal("cas")
	}
	if _, err := p.Require(ctx, "nope", nil); !errors.Is(err, ErrNotFound) {
		t.Fatal("require")
	}
}

func TestProviderBulk(t *testing.T) {
	b, m := newFakeBackend(t)
	for _, n := range []string{"cfg/one", "cfg/two", "cfg/three", "cfg/deep/x", "cfgother", "top"} {
		b.put(n, "v-"+n)
	}
	c := m.client(nil)
	p := provider(t, c)
	ctx := t.Context()

	list, err := p.List(ctx, "cfg/")
	if err != nil || len(list) != 4 || list[0].Name != "cfg/deep/x" || list[3].Name != "cfg/two" {
		t.Fatalf("list %+v %v", list, err)
	}
	if all, err := p.List(ctx, ""); err != nil || len(all) != 6 {
		t.Fatalf("list all: %d %v", len(all), err)
	}
	many, err := p.GetMany(ctx, []string{"cfg/one", "cfg/two", "cfg/nope", "cfg/one"}, nil)
	if err != nil || len(many) != 2 || m.count("BatchGetSecretValue") != 1 {
		t.Fatalf("getMany %v %v", many, err)
	}
	if s, _ := many["cfg/two"].Reveal(); s != "v-cfg/two" {
		t.Fatal("getMany value")
	}
	viaPath, err := p.GetMany(ctx, []string{"one"}, &GetOptions{Path: "cfg"})
	if err != nil || viaPath["one"] == nil {
		t.Fatalf("getMany path %v", err)
	}
	if empty, err := p.GetMany(ctx, nil, nil); err != nil || len(empty) != 0 {
		t.Fatal("empty getMany")
	}
	if _, err := p.GetMany(ctx, []string{""}, nil); !errors.Is(err, ErrValidation) {
		t.Fatal("empty name")
	}
	cid, _ := b.secrets["cfg/one"].current()
	if byVersion, err := p.GetMany(ctx, []string{"cfg/one"}, &GetOptions{Version: cid}); err != nil || byVersion["cfg/one"] == nil {
		t.Fatal("getMany with version")
	}

	all, err := p.GetAll(ctx, "cfg")
	if err != nil || len(all) != 3 || all["cfg/three"] == nil || all["cfg/deep/x"] != nil {
		t.Fatalf("getAll %v %v", all, err)
	}
	if top, err := p.GetAll(ctx, ""); err != nil || len(top) != 2 || top["top"] == nil || top["cfgother"] == nil {
		t.Fatalf("getAll root %v %v", top, err)
	}
	if none, err := p.GetAll(ctx, "nothing/"); err != nil || len(none) != 0 {
		t.Fatal("getAll empty")
	}

	prefix := fmt.Sprintf("GROWTEST_%d_", time.Now().UnixNano())
	set, err := p.LoadEnv(ctx, "cfg/", &LoadEnvOptions{Prefix: prefix})
	if err != nil || len(set) != 3 || os.Getenv(prefix+"ONE") != "v-cfg/one" {
		t.Fatalf("loadEnv %v %v", set, err)
	}
	for k := range set {
		_ = os.Unsetenv(k)
	}

	b.fail["BatchGetSecretValue"] = "AccessDeniedException"
	if _, err := p.GetMany(ctx, []string{"cfg/one"}, nil); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("batch failure: %v", err)
	}
	if _, err := p.GetAll(ctx, "cfg"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("getAll batch failure: %v", err)
	}
	delete(b.fail, "BatchGetSecretValue")
	b.fail["ListSecrets"] = "AccessDeniedException"
	if _, err := p.GetAll(ctx, "cfg"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("list failure")
	}
	if _, err := p.List(ctx, "cfg"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("list failure")
	}
}

func TestProviderBatchErrorsAndDeleted(t *testing.T) {
	b, m := newFakeBackend(t)
	b.put("a", "1")
	b.put("gone", "2")
	b.secrets["gone"].deleted = true
	p := provider(t, m.client(nil))
	got, err := p.GetMany(t.Context(), []string{"a", "gone"}, nil)
	if err != nil || len(got) != 1 {
		t.Fatalf("%v %v", got, err)
	}
	if list, _ := p.List(t.Context(), ""); len(list) != 1 {
		t.Fatal("deleted secrets must not be listed")
	}
	other := newAWSMock(t).json("BatchGetSecretValue", 200,
		`{"SecretValues":[{"Name":"x","ARN":"arn:x","SecretString":"v"}],"Errors":[{"SecretId":"y","ErrorCode":"DecryptionFailure","Message":"kms"}]}`).client(nil)
	if _, err := provider(t, other).GetMany(t.Context(), []string{"x", "y"}, nil); !errors.Is(err, ErrValidation) || !strings.Contains(err.Error(), "DecryptionFailure") {
		t.Fatalf("per-secret error: %v", err)
	}
	byARN := newAWSMock(t).json("BatchGetSecretValue", 200, `{"SecretValues":[{"Name":"x","ARN":"arn:x","SecretString":"v"}]}`).client(nil)
	if got, err := provider(t, byARN).GetMany(t.Context(), []string{"arn:x"}, nil); err != nil || got["arn:x"] == nil {
		t.Fatalf("by ARN: %v %v", got, err)
	}
}

func TestProviderErrors(t *testing.T) {
	b, m := newFakeBackend(t)
	b.put("a", "1")
	p := provider(t, m.client(nil))
	ctx := t.Context()
	for op, call := range map[string]func() error{
		"GetSecretValue": func() error { _, err := p.Get(ctx, "a", nil); return err },
		"DescribeSecret": func() error { _, err := p.Metadata(ctx, "a", nil); return err },
		"PutSecretValue": func() error { _, err := p.Set(ctx, "a", "v", nil); return err },
		"TagResource": func() error {
			_, err := p.Set(ctx, "a", "v", &SetOptions{Tags: map[string]string{"k": "v"}})
			return err
		},
		"UpdateSecret": func() error { _, err := p.Set(ctx, "a", "v", &SetOptions{Description: "d"}); return err },
		"DeleteSecret": func() error { return p.Delete(ctx, "a", nil) },
	} {
		b.fail[op] = "AccessDeniedException"
		if err := call(); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("%s: %v", op, err)
		}
		delete(b.fail, op)
	}
	b.fail["DescribeSecret"] = "AccessDeniedException"
	if err := p.Delete(ctx, "a", nil); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("describe before delete")
	}
	delete(b.fail, "DescribeSecret")
	b.fail["CreateSecret"] = "AccessDeniedException"
	if _, err := p.Set(ctx, "new", "v", nil); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("create failure")
	}
	delete(b.fail, "CreateSecret")

	// create race: PutSecretValue says missing, CreateSecret says exists, the retry put wins.
	race := newAWSMock(t)
	race.on("PutSecretValue", func(w http.ResponseWriter, _ *http.Request, _ map[string]any, n int) {
		if n == 1 {
			awsError(w, 404, "ResourceNotFoundException", "missing")
			return
		}
		writeAWS(w, 200, `{"Name":"r","VersionId":"v-race"}`)
	}).json("CreateSecret", 400, `{"__type":"ResourceExistsException","message":"exists"}`)
	if v, err := provider(t, race.client(nil)).Set(ctx, "r", "v", nil); err != nil || v != "v-race" {
		t.Fatalf("race: %q %v", v, err)
	}
}

func TestProviderWatchAndCache(t *testing.T) {
	b, m := newFakeBackend(t)
	b.put("w", "1")
	c := m.client(nil)
	p := provider(t, c)
	changes := make(chan string, 4)
	h := p.Watch(t.Context(), "w", 10*time.Millisecond, func(n, _ *SecretValue) {
		if n == nil {
			changes <- "deleted"
			return
		}
		s, _ := n.Reveal()
		changes <- s
	}, nil)
	select {
	case <-changes: // initial value
	case <-time.After(2 * time.Second):
	}
	b.put("w", "2")
	deadline := time.After(3 * time.Second)
	for got := ""; got != "2"; {
		select {
		case got = <-changes:
		case <-deadline:
			t.Fatal("no change seen")
		}
	}
	_ = c.Close()
	select {
	case <-h.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("Close must stop watchers")
	}

	opts := AWSCacheOptions()
	if opts.TTL != time.Hour || opts.MaxEntries != 1024 {
		t.Fatalf("%+v", opts)
	}
	b2, m2 := newFakeBackend(t)
	b2.put("k", "v")
	cache := NewSecretCache(provider(t, m2.client(nil)), AWSCacheOptions())
	for range 3 {
		if v, err := cache.Get(t.Context(), "k", nil); err != nil || v == nil {
			t.Fatal(err)
		}
	}
	if m2.count("GetSecretValue") != 1 || cache.Stats().Hits != 2 {
		t.Fatalf("cache: calls=%d stats=%+v", m2.count("GetSecretValue"), cache.Stats())
	}
}

// provider returns a SecretsProvider of c with default options.
func provider(t *testing.T, c *Client) *SecretsManagerProvider {
	t.Helper()
	p, err := c.Secrets()
	if err != nil {
		t.Fatal(err)
	}
	return p
}
