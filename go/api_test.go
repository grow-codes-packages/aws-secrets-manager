package awssecretsmanager

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

const db = "sdkv-0badc0de/app/db"

func TestGetSecretValue(t *testing.T) {
	t.Run("string", func(t *testing.T) {
		m := newAWSMock(t).serve("getSecretValue.ok-string")
		e, err := m.client(nil).GetSecretValue(t.Context(), db, nil)
		if err != nil {
			t.Fatal(err)
		}
		s, _ := e.Value.Reveal()
		if e.Name != db || e.VersionID != "11111111-1111-4111-8111-11110badc0de" || e.Binary || s == "" || e.Value.Version() != e.VersionID ||
			e.CreatedDate.IsZero() || len(e.VersionStages) == 0 || !strings.HasPrefix(e.ARN, "arn:aws:secretsmanager:") {
			t.Fatalf("%+v", e)
		}
		if out := fmt.Sprintf("%v %+v %s", e, *e, e.String()); strings.Contains(out, s) {
			t.Fatalf("value leaked: %s", out)
		}
		if b := m.body("GetSecretValue", 0); b["SecretId"] != db || b["VersionId"] != nil || b["VersionStage"] != nil {
			t.Fatalf("request %v", b)
		}
	})
	t.Run("binary", func(t *testing.T) {
		e, err := newAWSMock(t).serve("getSecretValue.ok-binary").client(nil).GetSecretValue(t.Context(), "x", nil)
		if err != nil || !e.Binary || !bytes.Equal(e.Value.RevealBytes(), []byte{0, 1, 2, 0xfe, 0xff}) {
			t.Fatalf("%+v %v", e, err)
		}
	})
	t.Run("version id and stage", func(t *testing.T) {
		m := newAWSMock(t).serve("getSecretValue.ok-version-id")
		e, err := m.client(nil).GetSecretValue(t.Context(), db, &GetSecretValueOptions{VersionID: "013a6645-866f-42f8-9f70-2b4ab862e83a"})
		if err != nil || e.VersionStages[0] != "STAGEX" || m.body("GetSecretValue", 0)["VersionId"] != "013a6645-866f-42f8-9f70-2b4ab862e83a" {
			t.Fatalf("%+v %v", e, err)
		}
		m = newAWSMock(t).serve("getSecretValue.ok-version-stage")
		e, err = m.client(nil).GetSecretValue(t.Context(), db, &GetSecretValueOptions{VersionStage: StagePrevious})
		if err != nil || e.VersionStages[0] != StagePrevious || m.body("GetSecretValue", 0)["VersionStage"] != StagePrevious {
			t.Fatalf("%+v %v", e, err)
		}
	})
	t.Run("errors", func(t *testing.T) {
		cases := map[string]ErrorCode{
			"getSecretValue.not-found":         ErrorCodeNotFound,
			"getSecretValue.version-not-found": ErrorCodeNotFound,
			"getSecretValue.stage-not-found":   ErrorCodeNotFound,
			"getSecretValue.no-version":        ErrorCodeNotFound,
			"getSecretValue.marked-deleted":    ErrorCodeConflict,
		}
		for fx, want := range cases {
			_, err := newAWSMock(t).serve(fx).client(nil).GetSecretValue(t.Context(), db, nil)
			e := asError(t, err)
			if e.Code != want || e.HTTPStatus == 0 || e.RequestID == "" || !strings.HasPrefix(e.Message, "getSecretValue "+db+": ") {
				t.Fatalf("%s: %+v", fx, e)
			}
		}
		if _, err := newAWSMock(t).client(nil).GetSecretValue(t.Context(), " ", nil); !errors.Is(err, ErrValidation) {
			t.Fatalf("empty id: %v", err)
		}
	})
}

func TestGetJSONField(t *testing.T) {
	m := newAWSMock(t).serve("getSecretValue.json-seed")
	c := m.client(nil)
	v, ok, err := c.GetJSONField(t.Context(), "grow-bootstrap/seed-json", "username", nil)
	if err != nil || !ok || v != "seed-user" {
		t.Fatalf("%v %v %v", v, ok, err)
	}
	if v, ok, _ := c.GetJSONField(t.Context(), "grow-bootstrap/seed-json", "port", nil); !ok || v != float64(5432) {
		t.Fatalf("port %v", v)
	}
	if _, ok, err := c.GetJSONField(t.Context(), "grow-bootstrap/seed-json", "nope", nil); ok || err != nil {
		t.Fatal("absent field")
	}
	if _, ok, _ := c.GetJSONField(t.Context(), "grow-bootstrap/seed-json", "username.deep", nil); ok {
		t.Fatal("path through a string")
	}
	if _, _, err := c.GetJSONField(t.Context(), "x", "", nil); !errors.Is(err, ErrValidation) {
		t.Fatal("empty field")
	}
	nested := newAWSMock(t).json("GetSecretValue", 200, `{"Name":"n","VersionId":"v","SecretString":"{\"db\":{\"host\":\"h\"}}"}`).client(nil)
	if v, ok, _ := nested.GetJSONField(t.Context(), "n", "db.host", nil); !ok || v != "h" {
		t.Fatalf("dot path %v", v)
	}
	if _, ok, _ := nested.GetJSONField(t.Context(), "n", "db.port", nil); ok {
		t.Fatal("missing nested")
	}
	bin := newAWSMock(t).serve("getSecretValue.ok-binary").client(nil)
	if _, _, err := bin.GetJSONField(t.Context(), "x", "a", nil); !errors.Is(err, ErrValidation) {
		t.Fatalf("binary: %v", err)
	}
	text := newAWSMock(t).serve("getSecretValue.ok-string").client(nil)
	if _, _, err := text.GetJSONField(t.Context(), "x", "a", nil); !errors.Is(err, ErrValidation) {
		t.Fatalf("not json: %v", err)
	}
	missing := newAWSMock(t).serve("getSecretValue.not-found").client(nil)
	if _, _, err := missing.GetJSONField(t.Context(), "x", "a", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
}

func TestBatchGetSecretValue(t *testing.T) {
	t.Run("ids partial in request order", func(t *testing.T) {
		m := newAWSMock(t).serve("batchGetSecretValue.ids-partial")
		ids := []string{"sdkv-0badc0de/app/blob", "sdkv-0badc0de/missing", db}
		res, err := m.client(nil).BatchGetSecretValue(t.Context(), BatchGetSelector{SecretIDs: ids}, nil)
		if err != nil || len(res.SecretValues) != 2 || res.SecretValues[0].Name != "sdkv-0badc0de/app/blob" || res.SecretValues[1].Name != db ||
			len(res.Errors) != 1 || res.Errors[0].SecretID != "sdkv-0badc0de/missing" || res.Errors[0].Code() != ErrorCodeNotFound {
			t.Fatalf("%+v %v", res, err)
		}
		if !res.SecretValues[0].Binary {
			t.Fatal("binary entry")
		}
	})
	t.Run("ids chunked by 20", func(t *testing.T) {
		m := newAWSMock(t).on("BatchGetSecretValue", func(w http.ResponseWriter, _ *http.Request, body map[string]any, _ int) {
			ids := body["SecretIdList"].([]any)
			var vals []string
			for i := len(ids) - 1; i >= 0; i-- { // reverse order: the client must restore request order
				vals = append(vals, fmt.Sprintf(`{"Name":%q,"ARN":"arn:%s","VersionId":"v","SecretString":"s"}`, ids[i], ids[i]))
			}
			writeAWS(w, 200, `{"SecretValues":[`+strings.Join(vals, ",")+`],"Errors":[]}`)
		})
		ids := make([]string, 45)
		for i := range ids {
			ids[i] = fmt.Sprintf("s%02d", i)
		}
		res, err := m.client(nil).BatchGetSecretValue(t.Context(), BatchGetSelector{SecretIDs: ids}, nil)
		if err != nil || len(res.SecretValues) != 45 || m.count("BatchGetSecretValue") != 3 || len(m.body("BatchGetSecretValue", 0)["SecretIdList"].([]any)) != 20 {
			t.Fatalf("%v calls=%d", err, m.count("BatchGetSecretValue"))
		}
		for i, v := range res.SecretValues {
			if v.Name != ids[i] {
				t.Fatalf("order at %d: %s", i, v.Name)
			}
		}
	})
	t.Run("ids paged and by ARN", func(t *testing.T) {
		m := newAWSMock(t).on("BatchGetSecretValue", func(w http.ResponseWriter, _ *http.Request, _ map[string]any, n int) {
			if n == 1 {
				writeAWS(w, 200, `{"SecretValues":[{"Name":"b","ARN":"arn:aws:secretsmanager:r:1:secret:b-XyZ","SecretString":"2"}],"NextToken":"t"}`)
				return
			}
			writeAWS(w, 200, `{"SecretValues":[{"Name":"a","ARN":"arn:aws:secretsmanager:r:1:secret:a-AbC","SecretString":"1"},{"Name":"z","ARN":"arn:z","SecretString":"9"}]}`)
		})
		res, err := m.client(nil).BatchGetSecretValue(t.Context(), BatchGetSelector{SecretIDs: []string{"arn:aws:secretsmanager:r:1:secret:a", "arn:aws:secretsmanager:r:1:secret:b-XyZ"}}, nil)
		if err != nil || len(res.SecretValues) != 3 || res.SecretValues[0].Name != "a" || res.SecretValues[1].Name != "b" || res.SecretValues[2].Name != "z" ||
			m.body("BatchGetSecretValue", 1)["NextToken"] != "t" {
			t.Fatalf("%+v %v", res, err)
		}
	})
	t.Run("filters auto-paginate", func(t *testing.T) {
		m := newAWSMock(t).serve("batchGetSecretValue.filters", "batchGetSecretValue.filters-page2")
		res, err := m.client(nil).BatchGetSecretValue(t.Context(), BatchGetSelector{Filters: []SecretFilter{{Key: FilterName, Values: []string{"sdkv-0badc0de/page/"}}}}, &BatchGetOptions{MaxResults: 2})
		if err != nil || len(res.SecretValues) != 3 || m.body("BatchGetSecretValue", 1)["NextToken"] != "2" || m.body("BatchGetSecretValue", 0)["MaxResults"] != float64(2) {
			t.Fatalf("%+v %v", res, err)
		}
	})
	t.Run("validation", func(t *testing.T) {
		c := newAWSMock(t).serve("batchGetSecretValue.both").client(nil)
		for i, tc := range []struct {
			sel  BatchGetSelector
			opts *BatchGetOptions
		}{{BatchGetSelector{}, nil}, {BatchGetSelector{SecretIDs: []string{"a"}, Filters: []SecretFilter{{Key: "name"}}}, nil},
			{BatchGetSelector{Filters: []SecretFilter{{Key: "name"}}}, &BatchGetOptions{MaxResults: 21}}} {
			if _, err := c.BatchGetSecretValue(t.Context(), tc.sel, tc.opts); !errors.Is(err, ErrValidation) {
				t.Fatalf("case %d: %v", i, err)
			}
		}
		if _, err := c.BatchGetSecretValue(t.Context(), BatchGetSelector{Filters: []SecretFilter{{Key: "name", Values: []string{"x"}}}}, nil); !errors.Is(err, ErrValidation) {
			t.Fatalf("server validation: %v", err)
		}
		fail := newAWSMock(t).json("BatchGetSecretValue", 400, `{"__type":"AccessDeniedException","message":"no"}`).client(nil)
		if _, err := fail.BatchGetSecretValue(t.Context(), BatchGetSelector{SecretIDs: []string{"a"}}, nil); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("ids error: %v", err)
		}
	})
}

func TestDescribeAndList(t *testing.T) {
	t.Run("describe", func(t *testing.T) {
		d, err := newAWSMock(t).serve("describeSecret.ok").client(nil).DescribeSecret(t.Context(), db)
		if err != nil || d.Name != db || d.Description != "grow sdk verify" || d.Tags["team"] != "sdk" || len(d.VersionIDsToStages) != 4 ||
			d.CurrentVersionID() != "73aafff8-79d7-4072-979c-81f2920c7e30" || d.PendingDeletion() || d.CreatedDate.IsZero() || d.LastChangedDate.IsZero() {
			t.Fatalf("%+v %v", d, err)
		}
		if _, err := newAWSMock(t).serve("describeSecret.not-found").client(nil).DescribeSecret(t.Context(), "x"); !errors.Is(err, ErrNotFound) {
			t.Fatal(err)
		}
		rot := newAWSMock(t).json("DescribeSecret", 200, `{"Name":"r","RotationEnabled":true,"RotationLambdaARN":"arn:l","RotationRules":{"AutomaticallyAfterDays":7,"Duration":"2h"},"NextRotationDate":1795033096,"DeletedDate":1795033096}`).client(nil)
		d, err = rot.DescribeSecret(t.Context(), "r")
		if err != nil || !d.RotationEnabled || d.RotationRules.AutomaticallyAfterDays != 7 || d.RotationRules.Duration != "2h" || !d.PendingDeletion() || d.CurrentVersionID() != "" {
			t.Fatalf("%+v %v", d, err)
		}
		if _, err := rot.DescribeSecret(t.Context(), ""); !errors.Is(err, ErrValidation) {
			t.Fatal("empty id")
		}
	})
	t.Run("list paginates", func(t *testing.T) {
		m := newAWSMock(t).serve("listSecrets.page1", "listSecrets.page2")
		list, err := Collect(m.client(nil).ListSecrets(t.Context(), &ListSecretsOptions{
			Filters: []SecretFilter{{Key: FilterName, Values: []string{"sdkv-0badc0de/page/"}}}, MaxResults: 2, SortOrder: "asc", IncludePlannedDeletion: true,
		}))
		if err != nil || len(list) != 3 || list[2].Name != "sdkv-0badc0de/page/p3" {
			t.Fatalf("%+v %v", list, err)
		}
		b := m.body("ListSecrets", 0)
		if b["MaxResults"] != float64(2) || b["SortOrder"] != "asc" || b["IncludePlannedDeletion"] != true || m.body("ListSecrets", 1)["NextToken"] != "2" {
			t.Fatalf("request %v", b)
		}
	})
	t.Run("list stops early and on errors", func(t *testing.T) {
		m := newAWSMock(t).serve("listSecrets.page1", "listSecrets.page2")
		for _, err := range m.client(nil).ListSecrets(t.Context(), nil) {
			_ = err
			break
		}
		if m.count("ListSecrets") != 1 {
			t.Fatal("early stop must not fetch more pages")
		}
		if _, err := Collect(newAWSMock(t).serve("listSecrets.bad-filter").client(nil).ListSecrets(t.Context(), &ListSecretsOptions{Filters: []SecretFilter{{Key: "bogus", Values: []string{"x"}}}})); !errors.Is(err, ErrValidation) {
			t.Fatalf("bad filter: %v", err)
		}
		if _, err := Collect(newAWSMock(t).client(nil).ListSecrets(t.Context(), &ListSecretsOptions{SortOrder: "up"})); !errors.Is(err, ErrValidation) {
			t.Fatalf("bad sort: %v", err)
		}
	})
	t.Run("list versions", func(t *testing.T) {
		m := newAWSMock(t).serve("listSecretVersionIds.ok")
		vs, err := Collect(m.client(nil).ListSecretVersionIDs(t.Context(), db, &ListSecretVersionIDsOptions{IncludeDeprecated: true, MaxResults: 10}))
		if err != nil || len(vs) != 4 || vs[0].VersionID == "" || vs[0].CreatedDate.IsZero() || m.body("ListSecretVersionIds", 0)["IncludeDeprecated"] != true {
			t.Fatalf("%+v %v", vs, err)
		}
		paged := newAWSMock(t).on("ListSecretVersionIds", func(w http.ResponseWriter, _ *http.Request, _ map[string]any, n int) {
			if n == 1 {
				writeAWS(w, 200, `{"Versions":[{"VersionId":"a","VersionStages":["AWSCURRENT"],"KmsKeyIds":["k"]}],"NextToken":"n"}`)
				return
			}
			writeAWS(w, 200, `{"Versions":[{"VersionId":"b"}],"NextToken":""}`)
		})
		vs, err = Collect(paged.client(nil).ListSecretVersionIDs(t.Context(), db, nil))
		if err != nil || len(vs) != 2 || vs[0].KmsKeyIDs[0] != "k" {
			t.Fatalf("%+v %v", vs, err)
		}
		for _, err := range paged.client(nil).ListSecretVersionIDs(t.Context(), db, nil) {
			_ = err
			break
		}
		if _, err := Collect(newAWSMock(t).serve("listSecretVersionIds.not-found-moto-500").client(func(c *Config) { c.Retry = fastRetry(0) }).ListSecretVersionIDs(t.Context(), "x", nil)); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("moto 500: %v", err)
		}
		notFound := newAWSMock(t).on("ListSecretVersionIds", func(w http.ResponseWriter, _ *http.Request, _ map[string]any, _ int) {
			awsError(w, 400, "ResourceNotFoundException", "missing")
		}).client(nil)
		if _, err := Collect(notFound.ListSecretVersionIDs(t.Context(), "x", nil)); !errors.Is(err, ErrNotFound) {
			t.Fatalf("aws not found: %v", err)
		}
		if _, err := Collect(notFound.ListSecretVersionIDs(t.Context(), "", nil)); !errors.Is(err, ErrValidation) {
			t.Fatal("empty id")
		}
	})
}

func TestWrites(t *testing.T) {
	t.Run("create string with options", func(t *testing.T) {
		m := newAWSMock(t).serve("createSecret.ok-string")
		ref, err := m.client(nil).CreateSecret(t.Context(), db, "v1", &CreateSecretOptions{
			Description: "grow sdk verify", KmsKeyID: "alias/aws/secretsmanager", Tags: map[string]string{"team": "sdk", "env": "test"},
			ClientRequestToken: "11111111-1111-4111-8111-11110badc0de", AddReplicaRegions: []ReplicaRegion{{Region: "eu-west-1", KmsKeyID: "k"}},
			ForceOverwriteReplicaSecret: true,
		})
		if err != nil || ref.VersionID != "11111111-1111-4111-8111-11110badc0de" || ref.Name != db {
			t.Fatalf("%+v %v", ref, err)
		}
		b := m.body("CreateSecret", 0)
		tags := b["Tags"].([]any)
		if b["SecretString"] != "v1" || b["KmsKeyId"] != "alias/aws/secretsmanager" || len(tags) != 2 || tags[0].(map[string]any)["Key"] != "env" ||
			b["ForceOverwriteReplicaSecret"] != true || len(b["AddReplicaRegions"].([]any)) != 1 {
			t.Fatalf("request %v", b)
		}
	})
	t.Run("create binary, json, none", func(t *testing.T) {
		m := newAWSMock(t).serve("createSecret.ok-binary")
		c := m.client(nil)
		if _, err := c.CreateSecret(t.Context(), "b", []byte{0, 1, 2, 0xfe, 0xff}, nil); err != nil || m.body("CreateSecret", 0)["SecretBinary"] != "AAEC/v8=" {
			t.Fatalf("binary: %v %v", err, m.body("CreateSecret", 0))
		}
		if _, err := c.CreateSecret(t.Context(), "j", map[string]any{"a": 1}, nil); err != nil || m.body("CreateSecret", 1)["SecretString"] != `{"a":1}` {
			t.Fatalf("json: %v", err)
		}
		if _, err := c.CreateSecret(t.Context(), "n", nil, nil); err != nil || m.body("CreateSecret", 2)["SecretString"] != nil {
			t.Fatalf("none: %v", err)
		}
		if _, err := c.CreateSecret(t.Context(), "f", func() {}, nil); !errors.Is(err, ErrValidation) {
			t.Fatalf("unencodable: %v", err)
		}
		if _, err := c.CreateSecret(t.Context(), "", "v", nil); !errors.Is(err, ErrValidation) {
			t.Fatal("empty name")
		}
		if _, err := c.CreateSecret(t.Context(), "r", json.RawMessage(`{"x":1}`), nil); err != nil || m.body("CreateSecret", 3)["SecretString"] != `{"x":1}` {
			t.Fatal("raw json")
		}
		if _, err := c.CreateSecret(t.Context(), "s", NewSecret("pw"), nil); err != nil || m.body("CreateSecret", 4)["SecretString"] != "pw" {
			t.Fatal("secret")
		}
		if _, err := c.CreateSecret(t.Context(), "sv", NewSecretValue([]byte{0xff}, ""), nil); err != nil || m.body("CreateSecret", 5)["SecretBinary"] != "/w==" {
			t.Fatal("binary secret value")
		}
		if _, err := c.CreateSecret(t.Context(), "st", NewSecretString("txt", ""), nil); err != nil || m.body("CreateSecret", 6)["SecretString"] != "txt" {
			t.Fatal("text secret value")
		}
	})
	t.Run("create errors", func(t *testing.T) {
		for fx, want := range map[string]ErrorCode{"createSecret.exists": ErrorCodeConflict, "createSecret.pending-deletion": ErrorCodeConflict} {
			if _, err := newAWSMock(t).serve(fx).client(nil).CreateSecret(t.Context(), db, "x", nil); CodeOf(err) != want || AWSErrorCode(err) != "ResourceExistsException" {
				t.Fatalf("%s: %v", fx, err)
			}
		}
	})
	t.Run("put", func(t *testing.T) {
		m := newAWSMock(t).serve("putSecretValue.custom-stage")
		res, err := m.client(nil).PutSecretValue(t.Context(), db, "v3-0badc0de", &PutSecretValueOptions{VersionStages: []string{"STAGEX"}, ClientRequestToken: "tok-0000000000000000000000000000000001"})
		if err != nil || res.VersionStages[0] != "STAGEX" || res.VersionID == "" || m.body("PutSecretValue", 0)["ClientRequestToken"] == nil {
			t.Fatalf("%+v %v", res, err)
		}
		if _, err := newAWSMock(t).serve("putSecretValue.not-found").client(nil).PutSecretValue(t.Context(), "x", "v", nil); !errors.Is(err, ErrNotFound) {
			t.Fatal(err)
		}
		if _, err := newAWSMock(t).serve("putSecretValue.token-reuse-different").client(nil).PutSecretValue(t.Context(), db, "v", nil); !errors.Is(err, ErrConflict) {
			t.Fatal(err)
		}
		c := newAWSMock(t).client(nil)
		if _, err := c.PutSecretValue(t.Context(), db, nil, nil); !errors.Is(err, ErrValidation) {
			t.Fatal("nil value")
		}
		if _, err := c.PutSecretValue(t.Context(), "", "v", nil); !errors.Is(err, ErrValidation) {
			t.Fatal("empty id")
		}
		if _, err := c.PutSecretValue(t.Context(), "x", make(chan int), nil); !errors.Is(err, ErrValidation) {
			t.Fatal("unencodable")
		}
	})
	t.Run("update", func(t *testing.T) {
		m := newAWSMock(t).serve("updateSecret.value")
		ref, err := m.client(nil).UpdateSecret(t.Context(), db, UpdateSecretOptions{Value: "v4-0badc0de", ClientRequestToken: "33333333-3333-4333-8333-0badc0de0002"})
		if err != nil || ref.VersionID != "33333333-3333-4333-8333-0badc0de0002" || m.body("UpdateSecret", 0)["SecretString"] != "v4-0badc0de" {
			t.Fatalf("%+v %v", ref, err)
		}
		m = newAWSMock(t).serve("updateSecret.description")
		if ref, err := m.client(nil).UpdateSecret(t.Context(), db, UpdateSecretOptions{Description: "updated", KmsKeyID: "k"}); err != nil || ref.VersionID != "" ||
			m.body("UpdateSecret", 0)["ClientRequestToken"] == nil {
			t.Fatalf("description: %v (the SDK must fill the token)", err)
		}
		if _, err := newAWSMock(t).serve("updateSecret.not-found").client(nil).UpdateSecret(t.Context(), "x", UpdateSecretOptions{Description: "x"}); !errors.Is(err, ErrNotFound) {
			t.Fatal(err)
		}
		c := newAWSMock(t).client(nil)
		if _, err := c.UpdateSecret(t.Context(), "x", UpdateSecretOptions{}); !errors.Is(err, ErrValidation) {
			t.Fatal("nothing to update")
		}
		if _, err := c.UpdateSecret(t.Context(), "", UpdateSecretOptions{Description: "d"}); !errors.Is(err, ErrValidation) {
			t.Fatal("empty id")
		}
		if _, err := c.UpdateSecret(t.Context(), "x", UpdateSecretOptions{Value: make(chan int)}); !errors.Is(err, ErrValidation) {
			t.Fatal("unencodable")
		}
	})
	t.Run("update version stage", func(t *testing.T) {
		m := newAWSMock(t).serve("updateSecretVersionStage.promote-current")
		ref, err := m.client(nil).UpdateSecretVersionStage(t.Context(), db, StageCurrent, UpdateSecretVersionStageOptions{MoveToVersionID: "a", RemoveFromVersionID: "b"})
		if err != nil || ref.Name != db || m.body("UpdateSecretVersionStage", 0)["RemoveFromVersionId"] != "b" {
			t.Fatalf("%+v %v", ref, err)
		}
		if _, err := newAWSMock(t).serve("updateSecretVersionStage.missing-remove").client(nil).UpdateSecretVersionStage(t.Context(), db, StageCurrent, UpdateSecretVersionStageOptions{MoveToVersionID: "a"}); !errors.Is(err, ErrValidation) {
			t.Fatal(err)
		}
		c := newAWSMock(t).client(nil)
		for _, tc := range []struct {
			id, stage string
			o         UpdateSecretVersionStageOptions
		}{{"", "S", UpdateSecretVersionStageOptions{MoveToVersionID: "a"}}, {"x", "", UpdateSecretVersionStageOptions{MoveToVersionID: "a"}}, {"x", "S", UpdateSecretVersionStageOptions{}}} {
			if _, err := c.UpdateSecretVersionStage(t.Context(), tc.id, tc.stage, tc.o); !errors.Is(err, ErrValidation) {
				t.Fatalf("%+v: %v", tc, err)
			}
		}
	})
	t.Run("delete", func(t *testing.T) {
		m := newAWSMock(t).serve("deleteSecret.recovery-window")
		c := m.client(nil)
		res, err := c.DeleteSecret(t.Context(), "sdkv-0badc0de/app/blob", &DeleteSecretOptions{RecoveryWindowDays: 7})
		if err != nil || res.DeletionDate.IsZero() || m.body("DeleteSecret", 0)["RecoveryWindowInDays"] != float64(7) {
			t.Fatalf("%+v %v", res, err)
		}
		if _, err := c.DeleteSecret(t.Context(), "x", nil); err != nil || m.body("DeleteSecret", 1)["RecoveryWindowInDays"] != float64(30) {
			t.Fatalf("default window: %v", m.body("DeleteSecret", 1))
		}
		m = newAWSMock(t).serve("deleteSecret.force")
		if _, err := m.client(nil).DeleteSecret(t.Context(), "x", &DeleteSecretOptions{ForceDeleteWithoutRecovery: true}); err != nil ||
			m.body("DeleteSecret", 0)["ForceDeleteWithoutRecovery"] != true || m.body("DeleteSecret", 0)["RecoveryWindowInDays"] != nil {
			t.Fatal(err)
		}
		for fx, want := range map[string]ErrorCode{"deleteSecret.not-found": ErrorCodeNotFound, "deleteSecret.already-deleted": ErrorCodeConflict} {
			if _, err := newAWSMock(t).serve(fx).client(nil).DeleteSecret(t.Context(), "x", nil); CodeOf(err) != want {
				t.Fatalf("%s: %v", fx, err)
			}
		}
		c = newAWSMock(t).client(nil)
		for _, o := range []*DeleteSecretOptions{{RecoveryWindowDays: 3}, {RecoveryWindowDays: 7, ForceDeleteWithoutRecovery: true}} {
			if _, err := c.DeleteSecret(t.Context(), "x", o); !errors.Is(err, ErrValidation) {
				t.Fatalf("%+v: %v", o, err)
			}
		}
		if _, err := c.DeleteSecret(t.Context(), "", nil); !errors.Is(err, ErrValidation) {
			t.Fatal("empty id")
		}
	})
	t.Run("restore", func(t *testing.T) {
		if ref, err := newAWSMock(t).serve("restoreSecret.ok").client(nil).RestoreSecret(t.Context(), "sdkv-0badc0de/app/blob"); err != nil || ref.Name != "sdkv-0badc0de/app/blob" {
			t.Fatal(err)
		}
		if _, err := newAWSMock(t).serve("restoreSecret.not-found").client(nil).RestoreSecret(t.Context(), "x"); !errors.Is(err, ErrNotFound) {
			t.Fatal(err)
		}
		if _, err := newAWSMock(t).client(nil).RestoreSecret(t.Context(), ""); !errors.Is(err, ErrValidation) {
			t.Fatal("empty id")
		}
	})
}

func TestTagsPolicyRotation(t *testing.T) {
	t.Run("tags", func(t *testing.T) {
		m := newAWSMock(t).serve("tagResource.ok")
		c := m.client(nil)
		if err := c.TagResource(t.Context(), db, map[string]string{"owner": "grow-0badc0de"}); err != nil {
			t.Fatal(err)
		}
		if tags := m.body("TagResource", 0)["Tags"].([]any); tags[0].(map[string]any)["Value"] != "grow-0badc0de" {
			t.Fatalf("%v", tags)
		}
		m.serve("untagResource.ok")
		if err := c.UntagResource(t.Context(), db, []string{"env"}); err != nil || m.body("UntagResource", 0)["TagKeys"].([]any)[0] != "env" {
			t.Fatal(err)
		}
		if err := newAWSMock(t).serve("tagResource.not-found").client(nil).TagResource(t.Context(), "x", map[string]string{"a": "b"}); !errors.Is(err, ErrNotFound) {
			t.Fatal(err)
		}
		if err := newAWSMock(t).serve("untagResource.not-found").client(nil).UntagResource(t.Context(), "x", []string{"a"}); !errors.Is(err, ErrNotFound) {
			t.Fatal(err)
		}
		for _, err := range []error{c.TagResource(t.Context(), "x", nil), c.TagResource(t.Context(), "", map[string]string{"a": "b"}),
			c.UntagResource(t.Context(), "x", nil), c.UntagResource(t.Context(), "", []string{"a"})} {
			if !errors.Is(err, ErrValidation) {
				t.Fatal(err)
			}
		}
	})
	t.Run("resource policy", func(t *testing.T) {
		yes := true
		policy := map[string]any{"Version": "2012-10-17", "Statement": []any{}}
		m := newAWSMock(t).serve("putResourcePolicy.ok")
		c := m.client(nil)
		if ref, err := c.PutResourcePolicy(t.Context(), db, policy, &PutResourcePolicyOptions{BlockPublicPolicy: &yes}); err != nil || ref.Name != db {
			t.Fatal(err)
		}
		if b := m.body("PutResourcePolicy", 0); b["ResourcePolicy"] != `{"Statement":[],"Version":"2012-10-17"}` || b["BlockPublicPolicy"] != true {
			t.Fatalf("%v", b)
		}
		for i, p := range []any{"{}", []byte("{}"), json.RawMessage("{}")} {
			if _, err := c.PutResourcePolicy(t.Context(), db, p, nil); err != nil || m.body("PutResourcePolicy", i+1)["ResourcePolicy"] != "{}" {
				t.Fatalf("policy form %d: %v", i, err)
			}
		}
		for _, p := range []any{"", nil, func() {}} {
			if _, err := c.PutResourcePolicy(t.Context(), db, p, nil); !errors.Is(err, ErrValidation) {
				t.Fatalf("%T: %v", p, err)
			}
		}
		if _, err := c.PutResourcePolicy(t.Context(), "", "{}", nil); !errors.Is(err, ErrValidation) {
			t.Fatal("empty id")
		}
		if _, err := newAWSMock(t).serve("putResourcePolicy.not-found").client(nil).PutResourcePolicy(t.Context(), "x", "{}", nil); !errors.Is(err, ErrNotFound) {
			t.Fatal(err)
		}
		rp, err := newAWSMock(t).serve("getResourcePolicy.ok").client(nil).GetResourcePolicy(t.Context(), db)
		var doc map[string]any
		if err != nil || rp.ResourcePolicy == "" || rp.JSON(&doc) != nil || doc["Version"] != "2012-10-17" || rp.Policy["Version"] != "2012-10-17" {
			t.Fatalf("%+v %v", rp, err)
		}
		none, err := newAWSMock(t).serve("getResourcePolicy.none").client(nil).GetResourcePolicy(t.Context(), db)
		if err != nil || none.ResourcePolicy != "" || none.Policy != nil || !errors.Is(none.JSON(&doc), ErrValidation) {
			t.Fatalf("%+v %v", none, err)
		}
		if !errors.Is(ResourcePolicyResult{ResourcePolicy: "not-json"}.JSON(&doc), ErrValidation) {
			t.Fatal("bad json")
		}
		if ref, err := newAWSMock(t).serve("deleteResourcePolicy.ok").client(nil).DeleteResourcePolicy(t.Context(), db); err != nil || ref.Name != db {
			t.Fatal(err)
		}
		if _, err := c.GetResourcePolicy(t.Context(), ""); !errors.Is(err, ErrValidation) {
			t.Fatal("empty id")
		}
		if _, err := c.DeleteResourcePolicy(t.Context(), ""); !errors.Is(err, ErrValidation) {
			t.Fatal("empty id")
		}
		nf := newAWSMock(t).json("GetResourcePolicy", 400, `{"__type":"ResourceNotFoundException"}`).json("DeleteResourcePolicy", 400, `{"__type":"ResourceNotFoundException"}`).client(nil)
		if _, err := nf.GetResourcePolicy(t.Context(), "x"); !errors.Is(err, ErrNotFound) {
			t.Fatal(err)
		}
		if _, err := nf.DeleteResourcePolicy(t.Context(), "x"); !errors.Is(err, ErrNotFound) {
			t.Fatal(err)
		}
	})
	t.Run("validate resource policy", func(t *testing.T) {
		m := newAWSMock(t).json("ValidateResourcePolicy", 200, `{"PolicyValidationPassed":false,"ValidationErrors":[{"CheckName":"BLOCK_PUBLIC","ErrorMessage":"public"}]}`)
		v, err := m.client(nil).ValidateResourcePolicy(t.Context(), map[string]any{"Version": "2012-10-17"}, &ValidateResourcePolicyOptions{SecretID: db})
		if err != nil || v.PolicyValidationPassed || len(v.ValidationErrors) != 1 || v.ValidationErrors[0].CheckName != "BLOCK_PUBLIC" || m.body("ValidateResourcePolicy", 0)["SecretId"] != db {
			t.Fatalf("%+v %v", v, err)
		}
		unsupported := newAWSMock(t).serve("validateResourcePolicy.moto-unsupported").client(func(c *Config) { c.Retry = fastRetry(1) })
		if _, err := unsupported.ValidateResourcePolicy(t.Context(), "{}", nil); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("moto: %v", err)
		}
		if _, err := unsupported.ValidateResourcePolicy(t.Context(), "", nil); !errors.Is(err, ErrValidation) {
			t.Fatal("empty policy")
		}
		malformed := newAWSMock(t).json("ValidateResourcePolicy", 400, `{"__type":"MalformedPolicyDocumentException","message":"bad"}`).client(nil)
		if _, err := malformed.ValidateResourcePolicy(t.Context(), "x", nil); !errors.Is(err, ErrValidation) {
			t.Fatal(err)
		}
	})
	t.Run("rotation", func(t *testing.T) {
		m := newAWSMock(t).serve("rotateSecret.rules-only")
		ref, err := m.client(nil).RotateSecret(t.Context(), db, &RotateSecretOptions{Rules: &RotationRules{AutomaticallyAfterDays: 30}})
		if err != nil || ref.VersionID == "" || m.body("RotateSecret", 0)["RotationRules"].(map[string]any)["AutomaticallyAfterDays"] != float64(30) {
			t.Fatalf("%+v %v", ref, err)
		}
		m = newAWSMock(t).serve("rotateSecret.lambda-not-found")
		no := false
		_, err = m.client(nil).RotateSecret(t.Context(), db, &RotateSecretOptions{LambdaARN: "arn:aws:lambda:us-east-1:123456789012:function:grow-rotate",
			Rules: &RotationRules{ScheduleExpression: "rate(10 days)", Duration: "2h"}, RotateImmediately: &no, ClientRequestToken: "tok"})
		b := m.body("RotateSecret", 0)
		if !errors.Is(err, ErrNotFound) || b["RotateImmediately"] != false || b["RotationLambdaARN"] == nil || b["RotationRules"].(map[string]any)["ScheduleExpression"] != "rate(10 days)" {
			t.Fatalf("%v %v", err, b)
		}
		c := newAWSMock(t).client(nil)
		if _, err := c.RotateSecret(t.Context(), db, &RotateSecretOptions{Rules: &RotationRules{AutomaticallyAfterDays: 1, ScheduleExpression: "rate(1 days)"}}); !errors.Is(err, ErrValidation) {
			t.Fatal(err)
		}
		if _, err := c.RotateSecret(t.Context(), "", nil); !errors.Is(err, ErrValidation) {
			t.Fatal("empty id")
		}
		plain := newAWSMock(t).serve("rotateSecret.rules-only")
		if _, err := plain.client(nil).RotateSecret(t.Context(), db, nil); err != nil || plain.body("RotateSecret", 0)["RotationRules"] != nil {
			t.Fatal(err)
		}
		if ref, err := newAWSMock(t).serve("cancelRotateSecret.ok").client(nil).CancelRotateSecret(t.Context(), db); err != nil || ref.VersionID == "" {
			t.Fatal(err)
		}
		if _, err := newAWSMock(t).serve("cancelRotateSecret.not-found").client(nil).CancelRotateSecret(t.Context(), "x"); !errors.Is(err, ErrNotFound) {
			t.Fatal(err)
		}
		if _, err := c.CancelRotateSecret(t.Context(), ""); !errors.Is(err, ErrValidation) {
			t.Fatal("empty id")
		}
	})
	t.Run("random password", func(t *testing.T) {
		m := newAWSMock(t).serve("getRandomPassword.ok")
		pw, err := m.client(nil).GetRandomPassword(t.Context(), &RandomPasswordOptions{Length: 24, ExcludePunctuation: true})
		if err != nil || len(pw.Reveal()) != 24 || fmt.Sprint(pw) != Redacted {
			t.Fatalf("%v", err)
		}
		if b := m.body("GetRandomPassword", 0); b["PasswordLength"] != float64(24) || b["ExcludePunctuation"] != true || b["RequireEachIncludedType"] != true || b["ExcludeNumbers"] != nil {
			t.Fatalf("%v", b)
		}
		m = newAWSMock(t).serve("getRandomPassword.exclude-chars")
		f := false
		if _, err := m.client(nil).GetRandomPassword(t.Context(), &RandomPasswordOptions{Length: 40, ExcludeCharacters: "abc", ExcludeNumbers: true,
			ExcludeUppercase: true, ExcludeLowercase: true, IncludeSpace: true, RequireEachIncludedType: &f}); err != nil {
			t.Fatal(err)
		}
		if b := m.body("GetRandomPassword", 0); b["ExcludeCharacters"] != "abc" || b["IncludeSpace"] != true || b["RequireEachIncludedType"] != false || b["ExcludeLowercase"] != true {
			t.Fatalf("%v", b)
		}
		m = newAWSMock(t).serve("getRandomPassword.ok")
		if _, err := m.client(nil).GetRandomPassword(t.Context(), nil); err != nil || m.body("GetRandomPassword", 0)["PasswordLength"] != float64(32) {
			t.Fatal("default length")
		}
		if _, err := newAWSMock(t).serve("getRandomPassword.too-short").client(nil).GetRandomPassword(t.Context(), &RandomPasswordOptions{Length: 2}); !errors.Is(err, ErrValidation) {
			t.Fatal(err)
		}
		if _, err := m.client(nil).GetRandomPassword(t.Context(), &RandomPasswordOptions{Length: 5000}); !errors.Is(err, ErrValidation) {
			t.Fatal("too long")
		}
	})
}

func TestErrorMapping(t *testing.T) {
	cases := []struct {
		status int
		code   string
		want   ErrorCode
	}{
		{400, "ResourceNotFoundException", ErrorCodeNotFound},
		{400, "ResourceExistsException", ErrorCodeConflict},
		{400, "PreconditionNotMetException", ErrorCodeConflict},
		{400, "InvalidRequestException", ErrorCodeConflict},
		{400, "InvalidParameterException", ErrorCodeValidation},
		{400, "InvalidNextTokenException", ErrorCodeValidation},
		{400, "LimitExceededException", ErrorCodeValidation},
		{400, "DecryptionFailure", ErrorCodeValidation},
		{400, "AccessDeniedException", ErrorCodePermissionDenied},
		{400, "UnrecognizedClientException", ErrorCodeAuthentication},
		{400, "ExpiredTokenException", ErrorCodeAuthentication},
		{400, "ThrottlingException", ErrorCodeRateLimited},
		{500, "InternalServiceError", ErrorCodeUnavailable},
		{400, "SomethingNew", ErrorCodeValidation},
		{404, "SomethingNew", ErrorCodeNotFound},
		{409, "", ErrorCodeConflict},
		{413, "", ErrorCodeValidation},
		{401, "", ErrorCodeAuthentication},
		{403, "", ErrorCodePermissionDenied},
		{501, "", ErrorCodeUnsupported},
		{502, "", ErrorCodeUnavailable},
		{504, "", ErrorCodeTimeout},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("core.errors.mapping %d %s", tc.status, tc.code), func(t *testing.T) {
			m := newAWSMock(t).on("DescribeSecret", func(w http.ResponseWriter, _ *http.Request, _ map[string]any, _ int) {
				if tc.code == "" {
					w.WriteHeader(tc.status)
					_, _ = w.Write([]byte("<html>oops</html>"))
					return
				}
				awsError(w, tc.status, tc.code, "msg")
			})
			_, err := m.client(func(c *Config) { c.Retry = fastRetry(0) }).DescribeSecret(t.Context(), "x")
			e := asError(t, err)
			if e.Code != tc.want || e.HTTPStatus != tc.status || e.Retryable != tc.want.Retryable() || !strings.Contains(e.Message, fmt.Sprintf("(HTTP %d)", tc.status)) {
				t.Fatalf("%+v", e)
			}
			if tc.code != "" && AWSErrorCode(err) != tc.code {
				t.Fatalf("AWSErrorCode %q", AWSErrorCode(err))
			}
		})
	}
	t.Run("batch error code", func(t *testing.T) {
		if (BatchGetError{ErrorCode: "Weird"}).Code() != ErrorCodeUnavailable || (BatchGetError{ErrorCode: "AccessDeniedException"}).Code() != ErrorCodePermissionDenied {
			t.Fatal("batch code")
		}
		if AWSErrorCode(errors.New("x")) != "" {
			t.Fatal("non-aws")
		}
	})
	t.Run("message is redacted and truncated", func(t *testing.T) {
		long := strings.Repeat("y", 400)
		m := newAWSMock(t).on("DescribeSecret", func(w http.ResponseWriter, _ *http.Request, _ map[string]any, _ int) {
			awsError(w, 400, "InvalidParameterException", testSecretKey+"   "+long)
		})
		_, err := m.client(nil).DescribeSecret(t.Context(), "x")
		if strings.Contains(err.Error(), testSecretKey) || strings.Contains(err.Error(), long) || strings.Contains(err.Error(), "   ") {
			t.Fatalf("%v", err)
		}
	})
	t.Run("context deadline", func(t *testing.T) {
		m := newAWSMock(t).on("DescribeSecret", func(_ http.ResponseWriter, r *http.Request, _ map[string]any, _ int) {
			select {
			case <-r.Context().Done():
			case <-time.After(time.Second):
			}
		})
		c := m.client(func(c *Config) { c.TotalTimeout = 50 * time.Millisecond })
		if _, err := c.DescribeSecret(t.Context(), "x"); !errors.Is(err, ErrTimeout) {
			t.Fatalf("%v", err)
		}
	})
}
