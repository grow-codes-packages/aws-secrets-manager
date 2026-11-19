package awssecretsmanager

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// SecretsManagerProvider is the SecretsProvider (SPEC §3) of AWS Secrets
// Manager. Get it from Client.Secrets.
//
// Mapping: a name (joined with GetOptions.Path / SetOptions.Path as
// "path/name") is the AWS secret name; GetOptions.Version is an AWS VersionId.
// Secrets scheduled for deletion count as missing. Set writes a new version
// (PutSecretValue) or creates the secret; Delete schedules deletion with the
// configured recovery window (default 30 days) or deletes immediately with
// DeleteOptions.Permanent. GetMany and GetAll use BatchGetSecretValue.
type SecretsManagerProvider struct {
	*BaseSecretsProvider
	prims *smPrimitives
}

var _ SecretsProvider = (*SecretsManagerProvider)(nil)

func newSecretsManagerProvider(c *Client, recoveryWindowDays int) *SecretsManagerProvider {
	prims := &smPrimitives{c: c, recoveryWindowDays: recoveryWindowDays}
	return &SecretsManagerProvider{BaseSecretsProvider: NewSecretsProvider(prims), prims: prims}
}

// GetMany reads the existing secrets among names with BatchGetSecretValue
// (chunks of 20); missing names are omitted. With GetOptions.Version it reads
// them one by one.
func (p *SecretsManagerProvider) GetMany(ctx context.Context, names []string, opts *GetOptions) (map[string]*SecretValue, error) {
	o := getOpts(opts)
	if o.Version != "" {
		return p.BaseSecretsProvider.GetMany(ctx, names, opts)
	}
	byFull := make(map[string][]string, len(names))
	ids := make([]string, 0, len(names))
	for _, n := range names {
		if err := checkName("secrets.getMany", n); err != nil {
			return nil, err
		}
		full := fullName(o.Path, n)
		if _, seen := byFull[full]; !seen {
			ids = append(ids, full)
		}
		byFull[full] = append(byFull[full], n)
	}
	vals, err := p.prims.batchGet(ctx, ids)
	if err != nil {
		return nil, err
	}
	out := make(map[string]*SecretValue, len(names))
	for full, v := range vals {
		for _, n := range byFull[full] {
			out[n] = v
		}
	}
	return out, nil
}

// GetAll returns every secret directly under path (names "path/<name>"
// without a further "/"), keyed by full name.
func (p *SecretsManagerProvider) GetAll(ctx context.Context, path string) (map[string]*SecretValue, error) {
	mds, err := p.prims.directChildren(ctx, path)
	if err != nil {
		return nil, err
	}
	ids := make([]string, len(mds))
	for i, md := range mds {
		ids[i] = md.Name
	}
	return p.prims.batchGet(ctx, ids)
}

// LoadEnv sets one environment variable per secret directly under path.
func (p *SecretsManagerProvider) LoadEnv(ctx context.Context, path string, opts *LoadEnvOptions) (map[string]string, error) {
	return loadEnvPath(ctx, p.prims.directChildren, p.Get, path, opts)
}

// smPrimitives implements SecretPrimitives on the client.
type smPrimitives struct {
	c                  *Client
	recoveryWindowDays int
}

func fullName(path, name string) string {
	path = strings.Trim(path, "/")
	if path == "" {
		return name
	}
	return path + "/" + name
}

// isMissing reports whether err means "no such live secret": not found, or
// scheduled for deletion (InvalidRequestException).
func isMissing(err error) bool {
	return errors.Is(err, ErrNotFound) || AWSErrorCode(err) == "InvalidRequestException"
}

// FetchSecret implements SecretPrimitives (GetSecretValue by VersionId).
func (s *smPrimitives) FetchSecret(ctx context.Context, name string, opts GetOptions) (*SecretValue, error) {
	e, err := s.c.GetSecretValue(ctx, fullName(opts.Path, name), &GetSecretValueOptions{VersionID: opts.Version})
	if err != nil {
		if isMissing(err) {
			return nil, nil
		}
		return nil, err
	}
	return e.Value, nil
}

// ListSecrets implements SecretPrimitives: every secret whose name starts with
// prefix (recursive), with metadata from the list entries.
func (s *smPrimitives) ListSecrets(ctx context.Context, prefix string) ([]SecretMetadata, error) {
	var opts *ListSecretsOptions
	if prefix != "" {
		opts = &ListSecretsOptions{Filters: []SecretFilter{{Key: FilterName, Values: []string{prefix}}}}
	}
	out := []SecretMetadata{}
	for d, err := range s.c.ListSecrets(ctx, opts) {
		if err != nil {
			return nil, err
		}
		// AWS's name filter also matches word prefixes inside names: re-filter.
		if strings.HasPrefix(d.Name, prefix) && !d.PendingDeletion() {
			out = append(out, metadataOf(d))
		}
	}
	return out, nil
}

// directChildren lists the secrets directly under path (non-recursive).
func (s *smPrimitives) directChildren(ctx context.Context, path string) ([]SecretMetadata, error) {
	prefix := strings.Trim(path, "/")
	if prefix != "" {
		prefix += "/"
	}
	all, err := s.ListSecrets(ctx, prefix)
	if err != nil {
		return nil, err
	}
	out := all[:0]
	for _, md := range all {
		if !strings.Contains(strings.TrimPrefix(md.Name, prefix), "/") {
			out = append(out, md)
		}
	}
	return out, nil
}

// batchGet reads ids with BatchGetSecretValue; missing and pending-deletion
// secrets are omitted, any other per-secret error is returned.
func (s *smPrimitives) batchGet(ctx context.Context, ids []string) (map[string]*SecretValue, error) {
	out := make(map[string]*SecretValue, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	res, err := s.c.BatchGetSecretValue(ctx, BatchGetSelector{SecretIDs: ids}, nil)
	if err != nil {
		return nil, err
	}
	for _, be := range res.Errors {
		switch be.ErrorCode {
		case "ResourceNotFoundException", "InvalidRequestException":
			continue
		}
		return nil, NewError(be.Code(), "secrets.getMany "+be.SecretID+": "+be.ErrorCode, nil)
	}
	requested := make(map[string]bool, len(ids))
	for _, id := range ids {
		requested[id] = true
	}
	for _, e := range res.SecretValues {
		key := e.Name
		if !requested[key] && requested[e.ARN] {
			key = e.ARN
		}
		out[key] = e.Value
	}
	return out, nil
}

// PutSecret implements SecretPrimitives: PutSecretValue, or CreateSecret when
// the secret does not exist. Tags and description of an existing secret are
// applied with TagResource / UpdateSecret. CAS is not supported by AWS.
func (s *smPrimitives) PutSecret(ctx context.Context, name string, value []byte, opts SetOptions) (string, error) {
	const op = "secrets.set"
	if opts.CAS != nil {
		return "", ValidationError(op, "AWS Secrets Manager has no compare-and-set")
	}
	full := fullName(opts.Path, name)
	var v any = value
	if utf8.Valid(value) {
		v = string(value)
	}
	put := func() (string, error) {
		res, err := s.c.PutSecretValue(ctx, full, v, nil)
		if err != nil {
			return "", err
		}
		if len(opts.Tags) > 0 {
			if err := s.c.TagResource(ctx, full, opts.Tags); err != nil {
				return "", err
			}
		}
		if opts.Description != "" {
			if _, err := s.c.UpdateSecret(ctx, full, UpdateSecretOptions{Description: opts.Description}); err != nil {
				return "", err
			}
		}
		return res.VersionID, nil
	}
	version, err := put()
	if !errors.Is(err, ErrNotFound) {
		return version, err
	}
	ref, err := s.c.CreateSecret(ctx, full, v, &CreateSecretOptions{Description: opts.Description, Tags: opts.Tags})
	if AWSErrorCode(err) == "ResourceExistsException" { // created concurrently
		return put()
	}
	if err != nil {
		return "", err
	}
	return ref.VersionID, nil
}

// RemoveSecret implements SecretPrimitives. A missing secret or one already
// scheduled for deletion is NOT_FOUND (checked with DescribeSecret, because a
// forced delete of a missing secret succeeds).
func (s *smPrimitives) RemoveSecret(ctx context.Context, name string, opts DeleteOptions) error {
	full := fullName(opts.Path, name)
	if len(opts.Versions) > 0 {
		return ValidationError("secrets.delete "+full, "AWS Secrets Manager cannot delete single versions; use UpdateSecretVersionStage")
	}
	d, err := s.c.DescribeSecret(ctx, full)
	if errors.Is(err, ErrNotFound) || (err == nil && d.PendingDeletion()) {
		return NotFoundError("secrets.delete "+full, "not found")
	}
	if err != nil {
		return err
	}
	o := &DeleteSecretOptions{ForceDeleteWithoutRecovery: opts.Permanent}
	if !opts.Permanent {
		o.RecoveryWindowDays = s.recoveryWindowDays
	}
	_, err = s.c.DeleteSecret(ctx, full, o)
	return err
}

// FetchMetadata implements SecretPrimitives (DescribeSecret).
func (s *smPrimitives) FetchMetadata(ctx context.Context, name string, opts GetOptions) (*SecretMetadata, error) {
	d, err := s.c.DescribeSecret(ctx, fullName(opts.Path, name))
	if err != nil {
		if isMissing(err) {
			return nil, nil
		}
		return nil, err
	}
	if d.PendingDeletion() {
		return nil, nil
	}
	md := metadataOf(*d)
	return &md, nil
}

// metadataOf converts a description: version = the AWSCURRENT VersionId,
// updatedAt = LastChangedDate, versions = number of versions with a stage.
func metadataOf(d SecretDescription) SecretMetadata {
	md := SecretMetadata{
		Name: d.Name, Version: d.CurrentVersionID(), CreatedAt: d.CreatedDate, UpdatedAt: d.LastChangedDate,
		Tags: d.Tags, Versions: len(d.VersionIDsToStages), Extra: map[string]string{},
	}
	if i := strings.LastIndex(d.Name, "/"); i > 0 {
		md.Path = d.Name[:i]
	}
	if md.Tags == nil {
		md.Tags = map[string]string{}
	}
	put := func(k, v string) {
		if v != "" {
			md.Extra[k] = v
		}
	}
	put("arn", d.ARN)
	put("description", d.Description)
	put("kmsKeyId", d.KmsKeyID)
	put("rotationEnabled", strconv.FormatBool(d.RotationEnabled))
	put("primaryRegion", d.PrimaryRegion)
	if !d.NextRotationDate.IsZero() {
		put("nextRotationDate", d.NextRotationDate.Format(time.RFC3339))
	}
	if !d.DeletedDate.IsZero() {
		put("deletedDate", d.DeletedDate.Format(time.RFC3339))
	}
	return md
}
