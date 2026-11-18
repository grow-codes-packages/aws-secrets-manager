package awssecretsmanager

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

// Version stage labels managed by AWS Secrets Manager.
const (
	StageCurrent  = "AWSCURRENT"
	StagePrevious = "AWSPREVIOUS"
	StagePending  = "AWSPENDING"
)

// ListSecrets filter keys (Filter.Key). A value prefixed with "!" negates it.
const (
	FilterName          = "name"
	FilterDescription   = "description"
	FilterTagKey        = "tag-key"
	FilterTagValue      = "tag-value"
	FilterPrimaryRegion = "primary-region"
	FilterOwningService = "owning-service"
	FilterAll           = "all"
)

// Limits enforced client side.
const (
	// MaxBatchGetIDs is the largest SecretIdList of one BatchGetSecretValue
	// request; BatchGetSecretValue splits longer id lists.
	MaxBatchGetIDs = 20
	// DefaultPasswordLength is the GetRandomPassword default length.
	DefaultPasswordLength = 32
)

// SecretFilter is a ListSecrets / BatchGetSecretValue filter.
type SecretFilter struct {
	// Key is one of the Filter* constants.
	Key string
	// Values are matched by prefix; "!" negates.
	Values []string
}

// SecretRef identifies a secret by ARN and name.
type SecretRef struct {
	ARN  string `json:"arn"`
	Name string `json:"name"`
}

// SecretWriteResult is the result of writes that may create a version.
type SecretWriteResult struct {
	ARN  string `json:"arn"`
	Name string `json:"name"`
	// VersionID is the version created by the call ("" when none).
	VersionID string `json:"versionId,omitempty"`
}

// AWSSecretValue is one secret version with its value. The value is wrapped in a
// redacting *SecretValue: printing or logging an entry never shows it.
type AWSSecretValue struct {
	ARN           string    `json:"arn"`
	Name          string    `json:"name"`
	VersionID     string    `json:"versionId"`
	VersionStages []string  `json:"versionStages"`
	CreatedDate   time.Time `json:"createdDate,omitzero"`
	// Binary is true when the secret holds SecretBinary instead of SecretString.
	Binary bool `json:"binary"`
	// Value is the secret value; Value.Version() is the VersionID.
	Value *SecretValue `json:"value"`
}

// String implements fmt.Stringer; the value is redacted.
func (e AWSSecretValue) String() string {
	return fmt.Sprintf("AWSSecretValue{Name:%s VersionID:%s VersionStages:%v Binary:%t Value:%s}",
		e.Name, e.VersionID, e.VersionStages, e.Binary, secretValueForm)
}

// RotationRules configure automatic rotation.
type RotationRules struct {
	// AutomaticallyAfterDays rotates every n days (0 = unset).
	AutomaticallyAfterDays int `json:"automaticallyAfterDays,omitempty"`
	// ScheduleExpression is a cron() or rate() expression.
	ScheduleExpression string `json:"scheduleExpression,omitempty"`
	// Duration is the rotation window, for example "3h".
	Duration string `json:"duration,omitempty"`
}

// SecretDescription is a secret's metadata (DescribeSecret, ListSecrets). It
// never contains the value. Absent timestamps are zero.
type SecretDescription struct {
	ARN                string              `json:"arn"`
	Name               string              `json:"name"`
	Description        string              `json:"description,omitempty"`
	KmsKeyID           string              `json:"kmsKeyId,omitempty"`
	RotationEnabled    bool                `json:"rotationEnabled"`
	RotationLambdaARN  string              `json:"rotationLambdaArn,omitempty"`
	RotationRules      *RotationRules      `json:"rotationRules,omitempty"`
	LastRotatedDate    time.Time           `json:"lastRotatedDate,omitzero"`
	LastChangedDate    time.Time           `json:"lastChangedDate,omitzero"`
	LastAccessedDate   time.Time           `json:"lastAccessedDate,omitzero"`
	DeletedDate        time.Time           `json:"deletedDate,omitzero"`
	NextRotationDate   time.Time           `json:"nextRotationDate,omitzero"`
	CreatedDate        time.Time           `json:"createdDate,omitzero"`
	Tags               map[string]string   `json:"tags"`
	VersionIDsToStages map[string][]string `json:"versionIdsToStages"`
	PrimaryRegion      string              `json:"primaryRegion,omitempty"`
	OwningService      string              `json:"owningService,omitempty"`
}

// CurrentVersionID returns the version id labelled AWSCURRENT ("" when none).
func (d SecretDescription) CurrentVersionID() string {
	return versionWithStage(d.VersionIDsToStages, StageCurrent)
}

// PendingDeletion reports whether the secret is scheduled for deletion.
func (d SecretDescription) PendingDeletion() bool { return !d.DeletedDate.IsZero() }

// SecretVersion describes one version (ListSecretVersionIDs).
type SecretVersion struct {
	VersionID        string    `json:"versionId"`
	VersionStages    []string  `json:"versionStages"`
	CreatedDate      time.Time `json:"createdDate,omitzero"`
	LastAccessedDate time.Time `json:"lastAccessedDate,omitzero"`
	KmsKeyIDs        []string  `json:"kmsKeyIds,omitempty"`
}

// BatchGetError is a per-secret failure of BatchGetSecretValue.
type BatchGetError struct {
	SecretID string `json:"secretId"`
	// ErrorCode is the AWS error code, for example ResourceNotFoundException.
	ErrorCode string `json:"errorCode"`
	Message   string `json:"message"`
}

// Code returns the canonical code of the AWS error code.
func (b BatchGetError) Code() ErrorCode {
	if c, ok := awsErrorCodes[b.ErrorCode]; ok {
		return c
	}
	return ErrorCodeUnavailable
}

// BatchGetResult is the merged result of BatchGetSecretValue.
type BatchGetResult struct {
	// SecretValues in request order (ids mode) or service order (filters mode).
	SecretValues []AWSSecretValue `json:"secretValues"`
	// Errors lists the secrets that could not be read (partial failure).
	Errors []BatchGetError `json:"errors"`
}

// PutSecretValueResult is the result of PutSecretValue.
type PutSecretValueResult struct {
	ARN           string   `json:"arn"`
	Name          string   `json:"name"`
	VersionID     string   `json:"versionId"`
	VersionStages []string `json:"versionStages"`
}

// DeleteSecretResult is the result of DeleteSecret.
type DeleteSecretResult struct {
	ARN          string    `json:"arn"`
	Name         string    `json:"name"`
	DeletionDate time.Time `json:"deletionDate,omitzero"`
}

// ResourcePolicyResult is the result of GetResourcePolicy.
type ResourcePolicyResult struct {
	ARN  string `json:"arn"`
	Name string `json:"name"`
	// ResourcePolicy is the JSON policy text ("" when the secret has none).
	ResourcePolicy string `json:"resourcePolicy,omitempty"`
	// Policy is the parsed policy (nil when there is none or it is not a JSON object).
	Policy map[string]any `json:"policy,omitempty"`
}

// JSON decodes the policy document into out (VALIDATION error when there is
// no policy or it is not JSON).
func (p ResourcePolicyResult) JSON(out any) error {
	if p.ResourcePolicy == "" {
		return ValidationError("getResourcePolicy", "the secret has no resource policy")
	}
	if err := json.Unmarshal([]byte(p.ResourcePolicy), out); err != nil {
		return ValidationError("getResourcePolicy", "the resource policy is not valid JSON")
	}
	return nil
}

// PolicyValidationError is one finding of ValidateResourcePolicy.
type PolicyValidationError struct {
	CheckName    string `json:"checkName"`
	ErrorMessage string `json:"errorMessage"`
}

// ValidateResourcePolicyResult is the result of ValidateResourcePolicy.
type ValidateResourcePolicyResult struct {
	PolicyValidationPassed bool                    `json:"policyValidationPassed"`
	ValidationErrors       []PolicyValidationError `json:"validationErrors"`
}

// ---------------------------------------------------------------- converters

func str(p *string) string { return aws.ToString(p) }

func tm(p *time.Time) time.Time {
	if p == nil {
		return time.Time{}
	}
	return p.UTC()
}

func optStr(s string) *string {
	if s == "" {
		return nil
	}
	return aws.String(s)
}

func tagsToSDK(tags map[string]string) []types.Tag {
	if len(tags) == 0 {
		return nil
	}
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]types.Tag, len(keys))
	for i, k := range keys {
		out[i] = types.Tag{Key: aws.String(k), Value: aws.String(tags[k])}
	}
	return out
}

func tagsFromSDK(tags []types.Tag) map[string]string {
	out := make(map[string]string, len(tags))
	for _, t := range tags {
		out[str(t.Key)] = str(t.Value)
	}
	return out
}

func stagesMap(m map[string][]string) map[string][]string {
	out := make(map[string][]string, len(m))
	for k, v := range m {
		out[k] = append([]string(nil), v...)
	}
	return out
}

func versionWithStage(m map[string][]string, stage string) string {
	for id, stages := range m {
		for _, s := range stages {
			if s == stage {
				return id
			}
		}
	}
	return ""
}

func rulesFromSDK(r *types.RotationRulesType) *RotationRules {
	if r == nil {
		return nil
	}
	out := &RotationRules{ScheduleExpression: str(r.ScheduleExpression), Duration: str(r.Duration)}
	if r.AutomaticallyAfterDays != nil {
		out.AutomaticallyAfterDays = int(*r.AutomaticallyAfterDays)
	}
	return out
}

func rulesToSDK(r *RotationRules) *types.RotationRulesType {
	if r == nil {
		return nil
	}
	out := &types.RotationRulesType{ScheduleExpression: optStr(r.ScheduleExpression), Duration: optStr(r.Duration)}
	if r.AutomaticallyAfterDays > 0 {
		out.AutomaticallyAfterDays = aws.Int64(int64(r.AutomaticallyAfterDays))
	}
	return out
}

func filtersToSDK(fs []SecretFilter) []types.Filter {
	if len(fs) == 0 {
		return nil
	}
	out := make([]types.Filter, len(fs))
	for i, f := range fs {
		out[i] = types.Filter{Key: types.FilterNameStringType(f.Key), Values: append([]string(nil), f.Values...)}
	}
	return out
}

func entryOf(arn, name, versionID *string, stages []string, created *time.Time, s *string, b []byte) AWSSecretValue {
	e := AWSSecretValue{
		ARN: str(arn), Name: str(name), VersionID: str(versionID),
		VersionStages: append([]string(nil), stages...), CreatedDate: tm(created),
	}
	if s == nil && b != nil {
		e.Binary = true
		e.Value = NewSecretValue(b, e.VersionID)
	} else {
		e.Value = NewSecretString(str(s), e.VersionID)
	}
	return e
}

func describeFromList(l types.SecretListEntry) SecretDescription {
	return SecretDescription{
		ARN: str(l.ARN), Name: str(l.Name), Description: str(l.Description), KmsKeyID: str(l.KmsKeyId),
		RotationEnabled: aws.ToBool(l.RotationEnabled), RotationLambdaARN: str(l.RotationLambdaARN),
		RotationRules: rulesFromSDK(l.RotationRules), LastRotatedDate: tm(l.LastRotatedDate),
		LastChangedDate: tm(l.LastChangedDate), LastAccessedDate: tm(l.LastAccessedDate),
		DeletedDate: tm(l.DeletedDate), NextRotationDate: tm(l.NextRotationDate), CreatedDate: tm(l.CreatedDate),
		Tags: tagsFromSDK(l.Tags), VersionIDsToStages: stagesMap(l.SecretVersionsToStages),
		PrimaryRegion: str(l.PrimaryRegion), OwningService: str(l.OwningService),
	}
}

// encodeValue converts a write value: string → SecretString, []byte →
// SecretBinary, *SecretValue / Secret → their text (binary when not UTF-8),
// json.RawMessage verbatim, anything else JSON-encoded into SecretString.
func encodeValue(op string, value any) (s *string, b []byte, err error) {
	switch v := value.(type) {
	case nil:
		return nil, nil, nil
	case string:
		return aws.String(v), nil, nil
	case []byte:
		return nil, append([]byte(nil), v...), nil
	case json.RawMessage:
		return aws.String(string(v)), nil, nil
	case Secret:
		return aws.String(v.Reveal()), nil, nil
	case *SecretValue:
		data := v.RevealBytes()
		if utf8.Valid(data) {
			return aws.String(string(data)), nil, nil
		}
		return nil, data, nil
	}
	data, jerr := json.Marshal(value)
	if jerr != nil {
		return nil, nil, ValidationError(op, "value cannot be JSON-encoded")
	}
	return aws.String(string(data)), nil, nil
}

func policyString(op string, policy any) (string, error) {
	switch p := policy.(type) {
	case string:
		if p == "" {
			return "", ValidationError(op, "policy is empty")
		}
		return p, nil
	case []byte:
		return string(p), nil
	case json.RawMessage:
		return string(p), nil
	case nil:
		return "", ValidationError(op, "policy is empty")
	}
	data, err := json.Marshal(policy)
	if err != nil {
		return "", ValidationError(op, "policy cannot be JSON-encoded")
	}
	return string(data), nil
}
