package awssecretsmanager

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"
)

// fakeSecret is one secret of the in-memory backend.
type fakeSecret struct {
	name     string
	desc     string
	tags     map[string]string
	versions map[string]*fakeVersion
	order    []string
	deleted  bool
}

type fakeVersion struct {
	str    *string
	bin    []byte
	stages []string
}

// fakeBackend is a minimal stateful Secrets Manager behind an awsMock, used
// by the provider tests (Moto semantics: not found = 404).
type fakeBackend struct {
	mu      sync.Mutex
	secrets map[string]*fakeSecret
	seq     int
	// fail makes the named operation answer with this AWS error code.
	fail map[string]string
}

func newFakeBackend(t *testing.T) (*fakeBackend, *awsMock) {
	t.Helper()
	b := &fakeBackend{secrets: map[string]*fakeSecret{}, fail: map[string]string{}}
	m := newAWSMock(t)
	for _, op := range []string{"GetSecretValue", "BatchGetSecretValue", "DescribeSecret", "ListSecrets", "CreateSecret",
		"PutSecretValue", "UpdateSecret", "DeleteSecret", "TagResource"} {
		op := op
		m.on(op, func(w http.ResponseWriter, _ *http.Request, body map[string]any, _ int) {
			b.mu.Lock()
			defer b.mu.Unlock()
			if code := b.fail[op]; code != "" {
				awsError(w, 400, code, "injected")
				return
			}
			status, doc := b.handle(op, body)
			if status != 200 {
				awsError(w, status, doc, "fake")
				return
			}
			writeAWS(w, 200, doc)
		})
	}
	return b, m
}

func (b *fakeBackend) put(name, value string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.store(name, &value, nil)
}

func (b *fakeBackend) store(name string, s *string, bin []byte) string {
	sec := b.secrets[name]
	if sec == nil {
		sec = &fakeSecret{name: name, tags: map[string]string{}, versions: map[string]*fakeVersion{}}
		b.secrets[name] = sec
	}
	b.seq++
	id := fmt.Sprintf("v-%04d", b.seq)
	for _, v := range sec.versions {
		v.stages = removeStage(v.stages, StagePrevious)
		if hasStage(v.stages, StageCurrent) {
			v.stages = append(removeStage(v.stages, StageCurrent), StagePrevious)
		}
	}
	sec.versions[id] = &fakeVersion{str: s, bin: bin, stages: []string{StageCurrent}}
	sec.order = append(sec.order, id)
	return id
}

func hasStage(stages []string, s string) bool {
	for _, x := range stages {
		if x == s {
			return true
		}
	}
	return false
}

func removeStage(stages []string, s string) []string {
	out := stages[:0]
	for _, x := range stages {
		if x != s {
			out = append(out, x)
		}
	}
	return out
}

func (sec *fakeSecret) current() (string, *fakeVersion) {
	for id, v := range sec.versions {
		if hasStage(v.stages, StageCurrent) {
			return id, v
		}
	}
	return "", nil
}

func (sec *fakeSecret) valueJSON(id string, v *fakeVersion) map[string]any {
	doc := map[string]any{"ARN": "arn:aws:secretsmanager:us-east-1:1:secret:" + sec.name + "-AbCdEf", "Name": sec.name,
		"VersionId": id, "VersionStages": v.stages, "CreatedDate": 1795033096}
	if v.str != nil {
		doc["SecretString"] = *v.str
	} else {
		doc["SecretBinary"] = base64.StdEncoding.EncodeToString(v.bin)
	}
	return doc
}

func (sec *fakeSecret) describeJSON() map[string]any {
	tags := []map[string]string{}
	for k, v := range sec.tags {
		tags = append(tags, map[string]string{"Key": k, "Value": v})
	}
	stages := map[string][]string{}
	for id, v := range sec.versions {
		stages[id] = v.stages
	}
	doc := map[string]any{"ARN": "arn:aws:secretsmanager:us-east-1:1:secret:" + sec.name + "-AbCdEf", "Name": sec.name,
		"Description": sec.desc, "Tags": tags, "VersionIdsToStages": stages, "SecretVersionsToStages": stages,
		"CreatedDate": 1795033095, "LastChangedDate": 1795033096, "NextRotationDate": 1795033099}
	if sec.deleted {
		doc["DeletedDate"] = 1795637897
	}
	return doc
}

func marshal(v any) string {
	data, _ := json.Marshal(v)
	return string(data)
}

func strArg(body map[string]any, k string) string {
	s, _ := body[k].(string)
	return s
}

func valueArgs(body map[string]any) (*string, []byte) {
	if s, ok := body["SecretString"].(string); ok {
		return &s, nil
	}
	if s, ok := body["SecretBinary"].(string); ok {
		data, _ := base64.StdEncoding.DecodeString(s)
		return nil, data
	}
	return nil, nil
}

// handle serves op; a non-200 status returns the AWS error code as doc.
func (b *fakeBackend) handle(op string, body map[string]any) (int, string) {
	id := strArg(body, "SecretId")
	sec := b.secrets[id]
	switch op {
	case "GetSecretValue":
		if sec == nil {
			return 404, "ResourceNotFoundException"
		}
		if sec.deleted {
			return 400, "InvalidRequestException"
		}
		if vid := strArg(body, "VersionId"); vid != "" {
			v := sec.versions[vid]
			if v == nil {
				return 404, "ResourceNotFoundException"
			}
			return 200, marshal(sec.valueJSON(vid, v))
		}
		cid, v := sec.current()
		if v == nil {
			return 404, "ResourceNotFoundException"
		}
		return 200, marshal(sec.valueJSON(cid, v))
	case "BatchGetSecretValue":
		vals, errs := []any{}, []any{}
		for _, raw := range body["SecretIdList"].([]any) {
			name := raw.(string)
			s := b.secrets[name]
			switch {
			case s == nil:
				errs = append(errs, map[string]string{"SecretId": name, "ErrorCode": "ResourceNotFoundException", "Message": "nope"})
			case s.deleted:
				errs = append(errs, map[string]string{"SecretId": name, "ErrorCode": "InvalidRequestException", "Message": "deleted"})
			default:
				cid, v := s.current()
				vals = append(vals, s.valueJSON(cid, v))
			}
		}
		return 200, marshal(map[string]any{"SecretValues": vals, "Errors": errs})
	case "DescribeSecret":
		if sec == nil {
			return 404, "ResourceNotFoundException"
		}
		return 200, marshal(sec.describeJSON())
	case "ListSecrets":
		prefix := ""
		if fs, ok := body["Filters"].([]any); ok && len(fs) > 0 {
			prefix = fs[0].(map[string]any)["Values"].([]any)[0].(string)
		}
		names := make([]string, 0, len(b.secrets))
		for n := range b.secrets {
			names = append(names, n)
		}
		sort.Sort(sort.Reverse(sort.StringSlice(names)))
		list := []any{}
		for _, n := range names {
			s := b.secrets[n]
			if strings.HasPrefix(n, prefix) && (!s.deleted || body["IncludePlannedDeletion"] == true) {
				list = append(list, s.describeJSON())
			}
		}
		// one entry per page to exercise pagination
		token, _ := body["NextToken"].(string)
		start := 0
		_, _ = fmt.Sscan(token, &start)
		if start >= len(list) {
			return 200, `{"SecretList":[]}`
		}
		doc := map[string]any{"SecretList": list[start : start+1]}
		if start+1 < len(list) {
			doc["NextToken"] = fmt.Sprint(start + 1)
		}
		return 200, marshal(doc)
	case "CreateSecret":
		name := strArg(body, "Name")
		if b.secrets[name] != nil {
			return 400, "ResourceExistsException"
		}
		s, bin := valueArgs(body)
		vid := b.store(name, s, bin)
		b.secrets[name].desc = strArg(body, "Description")
		if tags, ok := body["Tags"].([]any); ok {
			for _, tg := range tags {
				m := tg.(map[string]any)
				b.secrets[name].tags[m["Key"].(string)] = m["Value"].(string)
			}
		}
		return 200, marshal(map[string]string{"Name": name, "VersionId": vid})
	case "PutSecretValue":
		if sec == nil {
			return 404, "ResourceNotFoundException"
		}
		if sec.deleted {
			return 400, "InvalidRequestException"
		}
		s, bin := valueArgs(body)
		vid := b.store(id, s, bin)
		return 200, marshal(map[string]any{"Name": id, "VersionId": vid, "VersionStages": []string{StageCurrent}})
	case "UpdateSecret":
		if sec == nil {
			return 404, "ResourceNotFoundException"
		}
		sec.desc = strArg(body, "Description")
		return 200, marshal(map[string]string{"Name": id})
	case "TagResource":
		if sec == nil {
			return 404, "ResourceNotFoundException"
		}
		for _, tg := range body["Tags"].([]any) {
			m := tg.(map[string]any)
			sec.tags[m["Key"].(string)] = m["Value"].(string)
		}
		return 200, `{}`
	case "DeleteSecret":
		if sec == nil {
			return 404, "ResourceNotFoundException"
		}
		if body["ForceDeleteWithoutRecovery"] == true {
			delete(b.secrets, id)
		} else {
			sec.deleted = true
		}
		return 200, marshal(map[string]any{"Name": id, "DeletionDate": 1795637897})
	}
	return 400, "UnknownOperationException"
}
