package awssecretsmanager

import (
	"context"
	"encoding/json"
	"iter"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// GetSecretValueOptions select the version GetSecretValue and GetJSONField read.
// Without both, AWS returns the AWSCURRENT version.
type GetSecretValueOptions struct {
	// VersionID selects a version by id.
	VersionID string
	// VersionStage selects a version by stage label (AWSCURRENT, AWSPREVIOUS, AWSPENDING or custom).
	VersionStage string
}

// BatchGetSelector selects the secrets of BatchGetSecretValue: SecretIDs or
// Filters, never both.
type BatchGetSelector struct {
	// SecretIDs are names or ARNs; lists longer than 20 are split into several
	// requests and merged in request order.
	SecretIDs []string
	// Filters select secrets like ListSecrets; every page is fetched.
	Filters []SecretFilter
}

// BatchGetOptions control BatchGetSecretValue.
type BatchGetOptions struct {
	// MaxResults is the page size in filters mode (1–20, 0 = service default).
	MaxResults int
}

// ListSecretsOptions control ListSecrets.
type ListSecretsOptions struct {
	Filters []SecretFilter
	// IncludePlannedDeletion also lists secrets scheduled for deletion.
	IncludePlannedDeletion bool
	// SortOrder is "asc" or "desc" (by creation date; "" = service default).
	SortOrder string
	// MaxResults is the page size (1–100, 0 = service default).
	MaxResults int
}

// ListSecretVersionIDsOptions control ListSecretVersionIDs.
type ListSecretVersionIDsOptions struct {
	// IncludeDeprecated also lists versions without a stage label.
	IncludeDeprecated bool
	// MaxResults is the page size (0 = service default).
	MaxResults int
}

func opName(op, id string) string {
	if id == "" {
		return op
	}
	return op + " " + id
}

func checkID(op, id string) error {
	if strings.TrimSpace(id) == "" {
		return ValidationError(op, "secret id is empty")
	}
	return nil
}

// GetSecretValue reads a secret version (AWSCURRENT unless opts selects one).
// The value (SecretString or SecretBinary) is wrapped in a redacting
// *SecretValue. A missing secret, version or stage is NOT_FOUND; a secret
// scheduled for deletion is CONFLICT.
func (c *Client) GetSecretValue(ctx context.Context, id string, opts *GetSecretValueOptions) (*AWSSecretValue, error) {
	op := opName("getSecretValue", id)
	if err := checkID(op, id); err != nil {
		return nil, err
	}
	in := &secretsmanager.GetSecretValueInput{SecretId: aws.String(id)}
	if opts != nil {
		in.VersionId, in.VersionStage = optStr(opts.VersionID), optStr(opts.VersionStage)
	}
	out, err := call(ctx, c, op, func(ctx context.Context) (*secretsmanager.GetSecretValueOutput, error) {
		return c.api.GetSecretValue(ctx, in)
	})
	if err != nil {
		return nil, err
	}
	e := entryOf(out.ARN, out.Name, out.VersionId, out.VersionStages, out.CreatedDate, out.SecretString, out.SecretBinary)
	return &e, nil
}

// BatchGetSecretValue reads several secrets in as few requests as possible.
// Per-secret failures (for example a missing id) are returned in
// BatchGetResult.Errors, not as an error.
func (c *Client) BatchGetSecretValue(ctx context.Context, sel BatchGetSelector, opts *BatchGetOptions) (*BatchGetResult, error) {
	const op = "batchGetSecretValue"
	in := struct {
		BatchGetSelector
		BatchGetOptions
	}{BatchGetSelector: sel}
	if opts != nil {
		in.BatchGetOptions = *opts
	}
	switch {
	case len(in.SecretIDs) > 0 && len(in.Filters) > 0:
		return nil, ValidationError(op, "give either secret ids or filters, not both")
	case len(in.SecretIDs) == 0 && len(in.Filters) == 0:
		return nil, ValidationError(op, "give secret ids or filters")
	case in.MaxResults < 0 || in.MaxResults > MaxBatchGetIDs:
		return nil, ValidationError(op, "maxResults must be between 1 and 20")
	}
	res := &BatchGetResult{SecretValues: []AWSSecretValue{}, Errors: []BatchGetError{}}
	collect := func(out *secretsmanager.BatchGetSecretValueOutput) {
		for _, v := range out.SecretValues {
			res.SecretValues = append(res.SecretValues, entryOf(v.ARN, v.Name, v.VersionId, v.VersionStages, v.CreatedDate, v.SecretString, v.SecretBinary))
		}
		for _, e := range out.Errors {
			res.Errors = append(res.Errors, BatchGetError{SecretID: str(e.SecretId), ErrorCode: str(e.ErrorCode), Message: c.redact(str(e.Message))})
		}
	}
	if len(in.SecretIDs) > 0 {
		for start := 0; start < len(in.SecretIDs); start += MaxBatchGetIDs {
			chunk := in.SecretIDs[start:min(start+MaxBatchGetIDs, len(in.SecretIDs))]
			req := &secretsmanager.BatchGetSecretValueInput{SecretIdList: append([]string(nil), chunk...)}
			for {
				out, err := call(ctx, c, op, func(ctx context.Context) (*secretsmanager.BatchGetSecretValueOutput, error) {
					return c.api.BatchGetSecretValue(ctx, req)
				})
				if err != nil {
					return nil, err
				}
				collect(out)
				if str(out.NextToken) == "" {
					break
				}
				req.NextToken = out.NextToken
			}
		}
		sortByRequestOrder(res.SecretValues, in.SecretIDs)
		return res, nil
	}
	req := &secretsmanager.BatchGetSecretValueInput{Filters: filtersToSDK(in.Filters)}
	if in.MaxResults > 0 {
		req.MaxResults = aws.Int32(pageSize(in.MaxResults))
	}
	for {
		out, err := call(ctx, c, op, func(ctx context.Context) (*secretsmanager.BatchGetSecretValueOutput, error) {
			return c.api.BatchGetSecretValue(ctx, req)
		})
		if err != nil {
			return nil, err
		}
		collect(out)
		if str(out.NextToken) == "" {
			return res, nil
		}
		req.NextToken = out.NextToken
	}
}

// sortByRequestOrder orders values by the position of their name or ARN in ids.
func sortByRequestOrder(values []AWSSecretValue, ids []string) {
	pos := make(map[string]int, len(ids))
	for i, id := range ids {
		if _, dup := pos[id]; !dup {
			pos[id] = i
		}
	}
	index := func(e AWSSecretValue) int {
		if p, ok := pos[e.Name]; ok {
			return p
		}
		if p, ok := pos[e.ARN]; ok {
			return p
		}
		for id, p := range pos { // partial ARN
			if strings.HasPrefix(e.ARN, id) {
				return p
			}
		}
		return len(ids)
	}
	for i := 1; i < len(values); i++ { // stable insertion sort; batches are small
		for j := i; j > 0 && index(values[j]) < index(values[j-1]); j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

// DescribeSecret returns a secret's metadata (no value). A secret scheduled
// for deletion is returned with DeletedDate set.
func (c *Client) DescribeSecret(ctx context.Context, id string) (*SecretDescription, error) {
	op := opName("describeSecret", id)
	if err := checkID(op, id); err != nil {
		return nil, err
	}
	out, err := call(ctx, c, op, func(ctx context.Context) (*secretsmanager.DescribeSecretOutput, error) {
		return c.api.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{SecretId: aws.String(id)})
	})
	if err != nil {
		return nil, err
	}
	return &SecretDescription{
		ARN: str(out.ARN), Name: str(out.Name), Description: str(out.Description), KmsKeyID: str(out.KmsKeyId),
		RotationEnabled: aws.ToBool(out.RotationEnabled), RotationLambdaARN: str(out.RotationLambdaARN),
		RotationRules: rulesFromSDK(out.RotationRules), LastRotatedDate: tm(out.LastRotatedDate),
		LastChangedDate: tm(out.LastChangedDate), LastAccessedDate: tm(out.LastAccessedDate),
		DeletedDate: tm(out.DeletedDate), NextRotationDate: tm(out.NextRotationDate), CreatedDate: tm(out.CreatedDate),
		Tags: tagsFromSDK(out.Tags), VersionIDsToStages: stagesMap(out.VersionIdsToStages),
		PrimaryRegion: str(out.PrimaryRegion), OwningService: str(out.OwningService),
		ReplicationStatus: replicationFromSDK(out.ReplicationStatus),
	}, nil
}

// ListSecrets iterates over the secrets matching opts, fetching pages on
// demand. Iteration stops at the first error, which is yielded once:
//
//	for d, err := range client.ListSecrets(ctx, nil) {
//		if err != nil { return err }
//		fmt.Println(d.Name)
//	}
func (c *Client) ListSecrets(ctx context.Context, opts *ListSecretsOptions) iter.Seq2[SecretDescription, error] {
	const op = "listSecrets"
	return func(yield func(SecretDescription, error) bool) {
		var o ListSecretsOptions
		if opts != nil {
			o = *opts
		}
		if o.SortOrder != "" && o.SortOrder != "asc" && o.SortOrder != "desc" {
			yield(SecretDescription{}, ValidationError(op, `sortOrder must be "asc" or "desc"`))
			return
		}
		in := &secretsmanager.ListSecretsInput{Filters: filtersToSDK(o.Filters)}
		if o.IncludePlannedDeletion {
			in.IncludePlannedDeletion = aws.Bool(true)
		}
		if o.SortOrder != "" {
			in.SortOrder = sortOrder(o.SortOrder)
		}
		if o.MaxResults > 0 {
			in.MaxResults = aws.Int32(pageSize(o.MaxResults))
		}
		for {
			out, err := call(ctx, c, op, func(ctx context.Context) (*secretsmanager.ListSecretsOutput, error) {
				return c.api.ListSecrets(ctx, in)
			})
			if err != nil {
				yield(SecretDescription{}, err)
				return
			}
			for _, e := range out.SecretList {
				if !yield(describeFromList(e), nil) {
					return
				}
			}
			if str(out.NextToken) == "" {
				return
			}
			in.NextToken = out.NextToken
		}
	}
}

// ListSecretVersionIDs iterates over the versions of a secret (AWS
// ListSecretVersionIds), fetching pages on demand.
func (c *Client) ListSecretVersionIDs(ctx context.Context, id string, opts *ListSecretVersionIDsOptions) iter.Seq2[SecretVersion, error] {
	op := opName("listSecretVersionIds", id)
	return func(yield func(SecretVersion, error) bool) {
		if err := checkID(op, id); err != nil {
			yield(SecretVersion{}, err)
			return
		}
		in := &secretsmanager.ListSecretVersionIdsInput{SecretId: aws.String(id)}
		if opts != nil {
			if opts.IncludeDeprecated {
				in.IncludeDeprecated = aws.Bool(true)
			}
			if opts.MaxResults > 0 {
				in.MaxResults = aws.Int32(pageSize(opts.MaxResults))
			}
		}
		for {
			out, err := call(ctx, c, op, func(ctx context.Context) (*secretsmanager.ListSecretVersionIdsOutput, error) {
				return c.api.ListSecretVersionIds(ctx, in)
			})
			if err != nil {
				yield(SecretVersion{}, err)
				return
			}
			for _, v := range out.Versions {
				info := SecretVersion{
					VersionID: str(v.VersionId), VersionStages: append([]string(nil), v.VersionStages...),
					CreatedDate: tm(v.CreatedDate), LastAccessedDate: tm(v.LastAccessedDate),
					KmsKeyIDs: append([]string(nil), v.KmsKeyIds...),
				}
				if !yield(info, nil) {
					return
				}
			}
			if str(out.NextToken) == "" {
				return
			}
			in.NextToken = out.NextToken
		}
	}
}

// Collect drains an iterator from ListSecrets or ListSecretVersionIDs into a
// slice, stopping at the first error.
func Collect[T any](seq iter.Seq2[T, error]) ([]T, error) {
	out := []T{}
	for v, err := range seq {
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// GetJSONField reads a secret, parses its SecretString as a JSON object and
// returns the value of field (a top-level key, or a dot path such as
// "db.host" when no top-level key matches). ok is false when the field is
// absent or JSON null. Binary or non-JSON secrets are VALIDATION errors; a missing secret is
// NOT_FOUND.
func (c *Client) GetJSONField(ctx context.Context, id, field string, opts *GetSecretValueOptions) (value any, ok bool, err error) {
	op := opName("getJsonField", id)
	if field == "" {
		return nil, false, ValidationError(op, "field is empty")
	}
	e, err := c.GetSecretValue(ctx, id, opts)
	if err != nil {
		return nil, false, err
	}
	if e.Binary {
		return nil, false, ValidationError(op, "secret is binary, not a JSON object")
	}
	var doc map[string]any
	if err := json.Unmarshal(e.Value.RevealBytes(), &doc); err != nil || doc == nil {
		return nil, false, ValidationError(op, "secret is not a JSON object")
	}
	v, found := lookupField(doc, field)
	return v, found, nil
}

func lookupField(doc map[string]any, field string) (any, bool) {
	if v, ok := doc[field]; ok {
		return v, v != nil // JSON null counts as absent (same as the other languages)
	}
	var cur any = doc
	for part := range strings.SplitSeq(field, ".") {
		m, isMap := cur.(map[string]any)
		if !isMap {
			return nil, false
		}
		v, ok := m[part]
		if !ok {
			return nil, false
		}
		cur = v
	}
	return cur, cur != nil
}

// pageSize converts a validated page size; values above 100 (the largest AWS
// page) are clamped.
func pageSize(n int) int32 {
	if n > 100 {
		return 100
	}
	return int32(n) // #nosec G115 -- 0 < n <= 100
}
