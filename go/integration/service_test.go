package integration

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	asm "github.com/grow-codes-packages/aws-secrets-manager/go"
)

// setup loads /bootstrap/env and returns a client plus a unique name prefix.
func setup(t *testing.T) (*asm.Client, string) {
	t.Helper()
	bootstrap := os.Getenv("GROW_BOOTSTRAP_ENV")
	if bootstrap == "" {
		bootstrap = "/bootstrap/env"
	}
	loadBootstrapEnv(t, bootstrap)
	if os.Getenv("GROW_AWS_SECRETS_MANAGER_URL") == "" {
		t.Skip("GROW_AWS_SECRETS_MANAGER_URL is not set; run through docker/compose.yml")
	}
	c, err := asm.NewClientFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, fmt.Sprintf("grow-it-go/%08x/", rand.Uint32())
}

// check turns a (value, error) pair into a function that fails the test on error:
// check(c.Ping(ctx))(t).
func check[T any](v T, err error) func(*testing.T) T {
	return func(t *testing.T) T {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
}

func reveal(t *testing.T, v *asm.SecretValue) string {
	t.Helper()
	s, err := v.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func wantCode(t *testing.T, err error, code asm.ErrorCode) {
	t.Helper()
	if asm.CodeOf(err) != code {
		t.Fatalf("want %s, got %v", code, err)
	}
}

// TestServiceFunctions calls every public function against the real service
// (Moto in Docker) with a write → read-back assertion.
func TestServiceFunctions(t *testing.T) {
	c, prefix := setup(t)
	ctx := t.Context()
	app := prefix + "app/db"
	blob := prefix + "app/blob"

	t.Run("health ping serverVersion", func(t *testing.T) {
		hs := check(c.Health(ctx))(t)
		if !hs.Healthy || hs.Status != "ok" {
			t.Fatalf("%+v", hs)
		}
		if d := check(c.Ping(ctx))(t); d <= 0 {
			t.Fatal("latency")
		}
		_, err := c.ServerVersion(ctx)
		wantCode(t, err, asm.ErrorCodeUnsupported)
	})

	var v1, v2, v3 string
	t.Run("createSecret getSecretValue describeSecret", func(t *testing.T) {
		ref := check(c.CreateSecret(ctx, app, "v1", &asm.CreateSecretOptions{
			Description: "grow sdk it", Tags: map[string]string{"team": "sdk", "env": "it"},
		}))(t)
		v1 = ref.VersionID
		e := check(c.GetSecretValue(ctx, app, nil))(t)
		if reveal(t, e.Value) != "v1" || e.VersionID != v1 || e.Binary {
			t.Fatalf("%+v", e)
		}
		d := check(c.DescribeSecret(ctx, app))(t)
		if d.Description != "grow sdk it" || d.Tags["team"] != "sdk" || d.CurrentVersionID() != v1 {
			t.Fatalf("%+v", d)
		}
		_, err := c.CreateSecret(ctx, app, "again", nil)
		wantCode(t, err, asm.ErrorCodeConflict)
		_, err = c.GetSecretValue(ctx, prefix+"missing", nil)
		wantCode(t, err, asm.ErrorCodeNotFound)
	})

	t.Run("binary secret", func(t *testing.T) {
		data := []byte{0, 1, 2, 0xfe, 0xff}
		check(c.CreateSecret(ctx, blob, data, nil))(t)
		e := check(c.GetSecretValue(ctx, blob, nil))(t)
		if !e.Binary || !bytes.Equal(e.Value.RevealBytes(), data) {
			t.Fatalf("%+v", e)
		}
	})

	t.Run("putSecretValue and stages", func(t *testing.T) {
		res := check(c.PutSecretValue(ctx, app, "v2", nil))(t)
		v2 = res.VersionID
		cur := check(c.GetSecretValue(ctx, app, &asm.GetSecretValueOptions{VersionStage: asm.StageCurrent}))(t)
		prev := check(c.GetSecretValue(ctx, app, &asm.GetSecretValueOptions{VersionStage: asm.StagePrevious}))(t)
		if reveal(t, cur.Value) != "v2" || reveal(t, prev.Value) != "v1" {
			t.Fatal("AWSCURRENT/AWSPREVIOUS")
		}
		res = check(c.PutSecretValue(ctx, app, "v3", &asm.PutSecretValueOptions{VersionStages: []string{"STAGEX"}}))(t)
		v3 = res.VersionID
		x := check(c.GetSecretValue(ctx, app, &asm.GetSecretValueOptions{VersionStage: "STAGEX"}))(t)
		byID := check(c.GetSecretValue(ctx, app, &asm.GetSecretValueOptions{VersionID: v3}))(t)
		if reveal(t, x.Value) != "v3" || reveal(t, byID.Value) != "v3" {
			t.Fatal("custom stage / version id")
		}
	})

	t.Run("listSecretVersionIds", func(t *testing.T) {
		vs := check(asm.Collect(c.ListSecretVersionIDs(ctx, app, &asm.ListSecretVersionIDsOptions{IncludeDeprecated: true})))(t)
		var ids []string
		for _, v := range vs {
			ids = append(ids, v.VersionID)
		}
		for _, id := range []string{v1, v2, v3} {
			if !slices.Contains(ids, id) {
				t.Fatalf("%s missing in %v", id, ids)
			}
		}
	})

	t.Run("updateSecretVersionStage", func(t *testing.T) {
		check(c.UpdateSecretVersionStage(ctx, app, "STAGEX", asm.UpdateSecretVersionStageOptions{MoveToVersionID: v2, RemoveFromVersionID: v3}))(t)
		x := check(c.GetSecretValue(ctx, app, &asm.GetSecretValueOptions{VersionStage: "STAGEX"}))(t)
		if x.VersionID != v2 {
			t.Fatalf("STAGEX on %s", x.VersionID)
		}
		_, err := c.UpdateSecretVersionStage(ctx, app, asm.StageCurrent, asm.UpdateSecretVersionStageOptions{MoveToVersionID: v1})
		wantCode(t, err, asm.ErrorCodeValidation)
	})

	t.Run("updateSecret", func(t *testing.T) {
		check(c.UpdateSecret(ctx, app, asm.UpdateSecretOptions{Description: "updated"}))(t)
		ref := check(c.UpdateSecret(ctx, app, asm.UpdateSecretOptions{Value: map[string]any{"user": "u", "port": 5432}}))(t)
		if ref.VersionID == "" {
			t.Fatal("value update must create a version")
		}
		e := check(c.GetSecretValue(ctx, app, &asm.GetSecretValueOptions{VersionStage: asm.StageCurrent}))(t)
		if reveal(t, e.Value) != `{"port":5432,"user":"u"}` || check(c.DescribeSecret(ctx, app))(t).Description != "updated" {
			t.Fatal("update read back")
		}
	})

	t.Run("getJsonField", func(t *testing.T) {
		seed := os.Getenv("GROW_TEST_SEED_JSON_SECRET")
		v, ok, err := c.GetJSONField(ctx, seed, "username", nil)
		if err != nil || !ok || v != "seed-user" {
			t.Fatalf("%v %v %v", v, ok, err)
		}
		if v, _, _ := c.GetJSONField(ctx, os.Getenv("GROW_TEST_SEED_JSON_SECRET_ARN"), "port", nil); v != float64(5432) {
			t.Fatalf("port %v", v)
		}
		if _, ok, err := c.GetJSONField(ctx, app, "missing", nil); ok || err != nil {
			t.Fatal("absent field")
		}
		bin := check(c.GetSecretValue(ctx, os.Getenv("GROW_TEST_SEED_BINARY_SECRET"), nil))(t)
		if !bytes.Equal(bin.Value.RevealBytes(), []byte{0, 1, 2, 0xfe, 0xff}) {
			t.Fatal("seed binary")
		}
	})

	t.Run("listSecrets", func(t *testing.T) {
		list := check(asm.Collect(c.ListSecrets(ctx, &asm.ListSecretsOptions{
			Filters: []asm.SecretFilter{{Key: asm.FilterName, Values: []string{prefix + "app/"}}}, MaxResults: 1, SortOrder: "asc",
		})))(t)
		var names []string
		for _, d := range list {
			names = append(names, d.Name)
		}
		if !slices.Contains(names, app) || !slices.Contains(names, blob) {
			t.Fatalf("%v", names)
		}
	})

	t.Run("batchGetSecretValue", func(t *testing.T) {
		res := check(c.BatchGetSecretValue(ctx, asm.BatchGetSelector{SecretIDs: []string{blob, prefix + "missing", app}}, nil))(t)
		if len(res.SecretValues) != 2 || res.SecretValues[0].Name != blob || res.SecretValues[1].Name != app || len(res.Errors) != 1 ||
			res.Errors[0].Code() != asm.ErrorCodeNotFound {
			t.Fatalf("%+v", res)
		}
		byFilter := check(c.BatchGetSecretValue(ctx, asm.BatchGetSelector{Filters: []asm.SecretFilter{{Key: asm.FilterName, Values: []string{prefix + "app/"}}}},
			&asm.BatchGetOptions{MaxResults: 1}))(t)
		if len(byFilter.SecretValues) != 2 {
			t.Fatalf("filters: %+v", byFilter)
		}
	})

	t.Run("tagResource untagResource", func(t *testing.T) {
		if err := c.TagResource(ctx, app, map[string]string{"owner": "grow"}); err != nil {
			t.Fatal(err)
		}
		if err := c.UntagResource(ctx, app, []string{"env"}); err != nil {
			t.Fatal(err)
		}
		tags := check(c.DescribeSecret(ctx, app))(t).Tags
		if tags["owner"] != "grow" || tags["team"] != "sdk" || tags["env"] != "" {
			t.Fatalf("%v", tags)
		}
		wantCode(t, c.TagResource(ctx, prefix+"missing", map[string]string{"a": "b"}), asm.ErrorCodeNotFound)
	})

	t.Run("resource policy", func(t *testing.T) {
		account := os.Getenv("GROW_TEST_ACCOUNT_ID")
		policy := map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{
			"Effect": "Allow", "Principal": map[string]any{"AWS": "arn:aws:iam::" + account + ":root"},
			"Action": "secretsmanager:GetSecretValue", "Resource": "*",
		}}}
		check(c.PutResourcePolicy(ctx, app, policy, nil))(t)
		got := check(c.GetResourcePolicy(ctx, app))(t)
		if got.Policy["Version"] != "2012-10-17" || !strings.Contains(got.ResourcePolicy, "secretsmanager:GetSecretValue") {
			t.Fatalf("%+v", got)
		}
		check(c.DeleteResourcePolicy(ctx, app))(t)
		if check(c.GetResourcePolicy(ctx, app))(t).ResourcePolicy != "" {
			t.Fatal("policy not deleted")
		}
		res, err := c.ValidateResourcePolicy(ctx, policy, &asm.ValidateResourcePolicyOptions{SecretID: app})
		if os.Getenv("GROW_TEST_EMULATOR") == "moto" {
			wantCode(t, err, asm.ErrorCodeUnsupported) // not implemented in Moto 5.2.4
		} else if err != nil || !res.PolicyValidationPassed {
			t.Fatalf("%+v %v", res, err)
		}
	})

	t.Run("rotateSecret cancelRotateSecret", func(t *testing.T) {
		// A dedicated secret: Moto's rotation without a working Lambda leaves the
		// stage labels in a state other tests should not depend on.
		rot := prefix + "rot"
		check(c.CreateSecret(ctx, rot, "r1", nil))(t)
		ref := check(c.RotateSecret(ctx, rot, &asm.RotateSecretOptions{Rules: &asm.RotationRules{AutomaticallyAfterDays: 30}}))(t)
		if ref.VersionID == "" {
			t.Fatal("rotation version")
		}
		d := check(c.DescribeSecret(ctx, rot))(t)
		if !d.RotationEnabled || d.RotationRules == nil || d.RotationRules.AutomaticallyAfterDays != 30 {
			t.Fatalf("%+v", d)
		}
		lambda := "arn:aws:lambda:us-east-1:" + os.Getenv("GROW_TEST_ACCOUNT_ID") + ":function:grow-rotate"
		_, err := c.RotateSecret(ctx, rot, &asm.RotateSecretOptions{LambdaARN: lambda, Rules: &asm.RotationRules{ScheduleExpression: "rate(10 days)"}})
		wantCode(t, err, asm.ErrorCodeNotFound) // no Lambda function in the emulator
		check(c.CancelRotateSecret(ctx, rot))(t)
		if check(c.DescribeSecret(ctx, rot))(t).RotationEnabled {
			t.Fatal("rotation still enabled")
		}
		_, err = c.CancelRotateSecret(ctx, prefix+"missing")
		wantCode(t, err, asm.ErrorCodeNotFound)
		check(c.DeleteSecret(ctx, rot, &asm.DeleteSecretOptions{ForceDeleteWithoutRecovery: true}))(t)
	})

	t.Run("getRandomPassword", func(t *testing.T) {
		pw := check(c.GetRandomPassword(ctx, &asm.RandomPasswordOptions{Length: 24, ExcludePunctuation: true}))(t)
		if len(pw.Reveal()) != 24 || strings.ContainsAny(pw.Reveal(), "!@#$%^&*") || fmt.Sprint(pw) != asm.Redacted {
			t.Fatal("password")
		}
		_, err := c.GetRandomPassword(ctx, &asm.RandomPasswordOptions{Length: 2})
		wantCode(t, err, asm.ErrorCodeValidation)
	})

	t.Run("deleteSecret restoreSecret", func(t *testing.T) {
		del := check(c.DeleteSecret(ctx, blob, &asm.DeleteSecretOptions{RecoveryWindowDays: 7}))(t)
		if del.DeletionDate.IsZero() || !check(c.DescribeSecret(ctx, blob))(t).PendingDeletion() {
			t.Fatal("scheduled deletion")
		}
		_, err := c.GetSecretValue(ctx, blob, nil)
		wantCode(t, err, asm.ErrorCodeConflict)
		planned := check(asm.Collect(c.ListSecrets(ctx, &asm.ListSecretsOptions{IncludePlannedDeletion: true,
			Filters: []asm.SecretFilter{{Key: asm.FilterName, Values: []string{blob}}}})))(t)
		if len(planned) != 1 {
			t.Fatal("includePlannedDeletion")
		}
		check(c.RestoreSecret(ctx, blob))(t)
		if check(c.GetSecretValue(ctx, blob, nil))(t).Name != blob {
			t.Fatal("restore")
		}
		check(c.DeleteSecret(ctx, blob, &asm.DeleteSecretOptions{ForceDeleteWithoutRecovery: true}))(t)
		_, err = c.DescribeSecret(ctx, blob)
		wantCode(t, err, asm.ErrorCodeNotFound)
	})

	t.Run("caches", func(t *testing.T) {
		cache := check(c.SecretCache(nil))(t)
		s := check(cache.GetSecretString(ctx, app, nil))(t)
		if s2 := check(cache.GetSecretString(ctx, app, nil))(t); s2 != s || cache.Stats().Hits != 1 {
			t.Fatal("AWSSecretCache hit")
		}
		check(c.PutSecretValue(ctx, app, "v-cached", nil))(t)
		if v := check(cache.RefreshNow(ctx, app, nil))(t); reveal(t, v.Value) != "v-cached" {
			t.Fatal("RefreshNow must see the new AWSCURRENT")
		}
		p := check(c.Secrets())(t)
		generic := asm.NewSecretCache(p, asm.AWSCacheOptions())
		if v := check(generic.Get(ctx, app, nil))(t); reveal(t, v) != "v-cached" {
			t.Fatal("SecretCache")
		}
	})

	t.Run("provider watch and loadEnv", func(t *testing.T) {
		p := check(c.Secrets())(t)
		check(p.Set(ctx, prefix+"env/db_user", "alice", nil))(t)
		check(p.Set(ctx, prefix+"env/deep/x", "skip", nil))(t)
		envPrefix := fmt.Sprintf("GROWIT%d_", rand.Uint32())
		set := check(p.LoadEnv(ctx, prefix+"env", &asm.LoadEnvOptions{Prefix: envPrefix}))(t)
		if len(set) != 1 || os.Getenv(envPrefix+"DB_USER") != "alice" {
			t.Fatalf("%v", set)
		}
		_ = os.Unsetenv(envPrefix + "DB_USER")

		var mu sync.Mutex
		var seen []string
		h := p.Watch(ctx, prefix+"env/db_user", 200*time.Millisecond, func(n, _ *asm.SecretValue) {
			mu.Lock()
			defer mu.Unlock()
			if n == nil {
				seen = append(seen, "<deleted>")
				return
			}
			s, _ := n.Reveal()
			seen = append(seen, s)
		}, nil)
		defer h.Stop()
		time.Sleep(500 * time.Millisecond)
		check(p.Set(ctx, prefix+"env/db_user", "bob", nil))(t)
		deadline := time.Now().Add(10 * time.Second)
		for {
			mu.Lock()
			done := slices.Contains(seen, "bob")
			mu.Unlock()
			if done {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("watch saw %v", seen)
			}
			time.Sleep(100 * time.Millisecond)
		}
		md := check(p.Metadata(ctx, prefix+"env/db_user", nil))(t)
		if md == nil || md.Versions < 2 {
			t.Fatalf("%+v", md)
		}
		if err := p.Delete(ctx, prefix+"env/db_user", &asm.DeleteOptions{Permanent: true}); err != nil {
			t.Fatal(err)
		}
		if err := p.Delete(ctx, prefix+"env/db_user", nil); !errors.Is(err, asm.ErrNotFound) {
			t.Fatalf("second delete: %v", err)
		}
	})

	t.Run("cleanup", func(t *testing.T) {
		if _, err := c.DeleteSecret(ctx, app, &asm.DeleteSecretOptions{ForceDeleteWithoutRecovery: true}); err != nil {
			t.Fatal(err)
		}
	})
}

// TestAuthErrors checks the error mapping of real IAM failures.
func TestAuthErrors(t *testing.T) {
	c, prefix := setup(t)
	ctx := t.Context()
	base := c.Config()

	ro := base
	ro.AccessKeyID = os.Getenv("GROW_TEST_READONLY_ACCESS_KEY_ID")
	ro.SecretAccessKey = asm.NewSecret(os.Getenv("GROW_TEST_READONLY_SECRET_ACCESS_KEY"))
	roClient := check(asm.NewClient(ro))(t)
	defer func() { _ = roClient.Close() }()
	if _, err := roClient.GetSecretValue(ctx, os.Getenv("GROW_TEST_SEED_JSON_SECRET"), nil); err != nil {
		t.Fatalf("read-only read: %v", err)
	}
	_, err := roClient.CreateSecret(ctx, prefix+"ro", "x", nil)
	wantCode(t, err, asm.ErrorCodePermissionDenied)

	badSecret := base
	badSecret.SecretAccessKey = asm.NewSecret("not-the-secret-key")
	bc := check(asm.NewClient(badSecret))(t)
	defer func() { _ = bc.Close() }()
	_, err = bc.Ping(ctx)
	wantCode(t, err, asm.ErrorCodeAuthentication)
	if strings.Contains(err.Error(), "not-the-secret-key") {
		t.Fatal("secret in error text")
	}
	hs := check(bc.Health(ctx))(t)
	if !hs.Healthy || hs.Details["auth"] != "failed" {
		t.Fatalf("health with bad credentials: %+v", hs)
	}

	badKey := base
	badKey.AccessKeyID = "AKIDUNKNOWN0000000"
	kc := check(asm.NewClient(badKey))(t)
	defer func() { _ = kc.Close() }()
	_, err = kc.Ping(ctx)
	wantCode(t, err, asm.ErrorCodeAuthentication)

	cctx, cancel := context.WithCancel(ctx)
	cancel()
	_, err = c.Ping(cctx)
	wantCode(t, err, asm.ErrorCodeCancelled)
	if asm.AWSErrorCode(err) != "" {
		t.Fatal("no AWS code for a cancelled call")
	}
}
