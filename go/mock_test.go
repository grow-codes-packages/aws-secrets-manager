package awssecretsmanager

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Test credentials (fake, valid only against the mock servers).
const (
	testAccessKey = "AKIDGROWTEST0001"
	testSecretKey = "sk-SECRET-0123456789abcdef"
)

// TestMain isolates the AWS SDK from the host: no shared config files, no
// instance metadata and no AWS_* variables.
func TestMain(m *testing.M) {
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); strings.HasPrefix(k, "AWS_") || strings.HasPrefix(k, EnvPrefix) {
			_ = os.Unsetenv(k)
		}
	}
	dir, err := os.MkdirTemp("", "asm-go-test")
	if err != nil {
		panic(err)
	}
	_ = os.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "config"))
	_ = os.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "credentials"))
	_ = os.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// newTestClient builds a client for url with static test credentials and
// fast retries; mutate adjusts the config. Used by the generated TLS tests.
func newTestClient(t *testing.T, url string, mutate func(*Config)) *Client {
	t.Helper()
	cfg := Config{
		CommonConfig:    CommonConfig{URL: url, Retry: fastRetry(3)},
		Region:          "us-east-1",
		AccessKeyID:     testAccessKey,
		SecretAccessKey: NewSecret(testSecretKey),
	}
	if mutate != nil {
		mutate(&cfg)
	}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// fixture is a recorded Moto exchange (testdata/fixtures, API.md §6).
type fixture struct {
	Operation string `json:"operation"`
	Request   struct {
		Body map[string]any `json:"body"`
	} `json:"request"`
	Response struct {
		Status  int               `json:"status"`
		Headers map[string]string `json:"headers"`
		Body    json.RawMessage   `json:"body"`
	} `json:"response"`
}

func loadFixture(t *testing.T, name string) fixture {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "fixtures", name+".json"))
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	var fx fixture
	if err := json.Unmarshal(data, &fx); err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return fx
}

// write serves the fixture's recorded response.
func (fx fixture) write(w http.ResponseWriter) {
	for k, v := range fx.Response.Headers {
		switch strings.ToLower(k) {
		case "content-length", "status":
			continue
		}
		w.Header().Set(k, v)
	}
	var body []byte
	raw := strings.TrimSpace(string(fx.Response.Body))
	switch {
	case raw == "" || raw == "null":
	case strings.HasPrefix(raw, `"`):
		var s string
		_ = json.Unmarshal(fx.Response.Body, &s)
		body = []byte(s)
	default:
		body = fx.Response.Body
	}
	w.WriteHeader(fx.Response.Status)
	_, _ = w.Write(body)
}

// mockHandler answers one AWS JSON request; n counts calls of the operation (1-based).
type mockHandler func(w http.ResponseWriter, r *http.Request, body map[string]any, n int)

// awsMock is a Secrets Manager endpoint dispatching on X-Amz-Target.
type awsMock struct {
	t      *testing.T
	server *httptest.Server
	mu     sync.Mutex
	h      map[string]mockHandler
	bodies map[string][]map[string]any
	reqs   []*http.Request
}

func newAWSMock(t *testing.T) *awsMock {
	t.Helper()
	m := &awsMock{t: t, h: map[string]mockHandler{}, bodies: map[string][]map[string]any{}}
	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		op := strings.TrimPrefix(r.Header.Get("X-Amz-Target"), "secretsmanager.")
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		m.mu.Lock()
		m.bodies[op] = append(m.bodies[op], body)
		m.reqs = append(m.reqs, r.Clone(r.Context()))
		n := len(m.bodies[op])
		h := m.h[op]
		m.mu.Unlock()
		if h == nil {
			w.Header().Set("X-Amzn-ErrorType", "UnknownOperationException")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"__type":"UnknownOperationException","message":"no mock for ` + op + `"}`))
			return
		}
		h(w, r, body, n)
	}))
	t.Cleanup(m.server.Close)
	return m
}

// on sets the handler of op.
func (m *awsMock) on(op string, h mockHandler) *awsMock {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.h[op] = h
	return m
}

// serve answers op with the given fixtures in order (the last one repeats).
// The operation is taken from the first fixture.
func (m *awsMock) serve(names ...string) *awsMock {
	m.t.Helper()
	fxs := make([]fixture, len(names))
	for i, n := range names {
		fxs[i] = loadFixture(m.t, n)
	}
	return m.on(fxs[0].Operation, func(w http.ResponseWriter, _ *http.Request, _ map[string]any, n int) {
		fxs[min(n, len(fxs))-1].write(w)
	})
}

// json answers op with status and a JSON document.
func (m *awsMock) json(op string, status int, doc string) *awsMock {
	return m.on(op, func(w http.ResponseWriter, _ *http.Request, _ map[string]any, _ int) {
		writeAWS(w, status, doc)
	})
}

func writeAWS(w http.ResponseWriter, status int, doc string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.Header().Set("X-Amzn-RequestId", "req-123")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(doc))
}

// awsError writes an AWS JSON error.
func awsError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("X-Amzn-ErrorType", code)
	writeAWS(w, status, `{"__type":"`+code+`","message":"`+msg+`"}`)
}

// body returns the i-th request body of op.
func (m *awsMock) body(op string, i int) map[string]any {
	m.t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if i >= len(m.bodies[op]) {
		m.t.Fatalf("no request %d for %s (got %d)", i, op, len(m.bodies[op]))
	}
	return m.bodies[op][i]
}

// count returns the number of requests of op.
func (m *awsMock) count(op string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.bodies[op])
}

func (m *awsMock) lastRequest() *http.Request {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.reqs[len(m.reqs)-1]
}

// client returns a client for the mock.
func (m *awsMock) client(mutate func(*Config)) *Client {
	return newTestClient(m.t, m.server.URL, mutate)
}
