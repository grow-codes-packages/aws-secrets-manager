package awssecretsmanager

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

// ReplicaRegion is a region to replicate a new secret to.
type ReplicaRegion struct {
	Region   string
	KmsKeyID string
}

// CreateSecretOptions control CreateSecret.
type CreateSecretOptions struct {
	Description string
	// KmsKeyID encrypts the secret with this KMS key (default aws/secretsmanager).
	KmsKeyID string
	Tags     map[string]string
	// ClientRequestToken makes retries idempotent and becomes the VersionId
	// (32–64 characters). The SDK generates one when empty.
	ClientRequestToken          string
	AddReplicaRegions           []ReplicaRegion
	ForceOverwriteReplicaSecret bool
}

// PutSecretValueOptions control PutSecretValue.
type PutSecretValueOptions struct {
	// VersionStages label the new version (default [AWSCURRENT]).
	VersionStages      []string
	ClientRequestToken string
}

// UpdateSecretOptions control UpdateSecret. Zero fields are left unchanged; a
// new version is created only when Value is set.
type UpdateSecretOptions struct {
	// Value is the new value (string, []byte or JSON-encodable value).
	Value              any
	Description        string
	KmsKeyID           string
	ClientRequestToken string
}

// UpdateSecretVersionStageOptions control UpdateSecretVersionStage.
type UpdateSecretVersionStageOptions struct {
	// MoveToVersionID attaches the stage to this version.
	MoveToVersionID string
	// RemoveFromVersionID detaches the stage from this version (required when
	// moving AWSCURRENT: the current version's id).
	RemoveFromVersionID string
}

// DeleteSecretOptions control DeleteSecret: a recovery window or an immediate
// delete, never both.
type DeleteSecretOptions struct {
	// RecoveryWindowDays is 7–30 (0 = Config.RecoveryWindowDays, default 30).
	RecoveryWindowDays int
	// ForceDeleteWithoutRecovery deletes immediately (cannot be undone).
	ForceDeleteWithoutRecovery bool
}

// CreateSecret creates a secret. value is a string (SecretString), []byte
// (SecretBinary), a JSON-encodable value (JSON SecretString) or nil (a secret
// without a version). An existing name is CONFLICT.
func (c *Client) CreateSecret(ctx context.Context, name string, value any, opts *CreateSecretOptions) (*SecretWriteResult, error) {
	op := opName("createSecret", name)
	if err := checkID(op, name); err != nil {
		return nil, err
	}
	s, b, err := encodeValue(op, value)
	if err != nil {
		return nil, err
	}
	in := &secretsmanager.CreateSecretInput{Name: aws.String(name), SecretString: s, SecretBinary: b}
	if opts != nil {
		in.Description, in.KmsKeyId = optStr(opts.Description), optStr(opts.KmsKeyID)
		in.Tags, in.ClientRequestToken = tagsToSDK(opts.Tags), optStr(opts.ClientRequestToken)
		for _, r := range opts.AddReplicaRegions {
			in.AddReplicaRegions = append(in.AddReplicaRegions, types.ReplicaRegionType{Region: optStr(r.Region), KmsKeyId: optStr(r.KmsKeyID)})
		}
		if opts.ForceOverwriteReplicaSecret {
			in.ForceOverwriteReplicaSecret = true
		}
	}
	out, err := call(ctx, c, op, func(ctx context.Context) (*secretsmanager.CreateSecretOutput, error) {
		return c.api.CreateSecret(ctx, in)
	})
	if err != nil {
		return nil, err
	}
	return &SecretWriteResult{ARN: str(out.ARN), Name: str(out.Name), VersionID: str(out.VersionId)}, nil
}

// PutSecretValue stores a new version. By default it becomes AWSCURRENT and
// the old current version AWSPREVIOUS. A missing secret is NOT_FOUND.
func (c *Client) PutSecretValue(ctx context.Context, id string, value any, opts *PutSecretValueOptions) (*PutSecretValueResult, error) {
	op := opName("putSecretValue", id)
	if err := checkID(op, id); err != nil {
		return nil, err
	}
	if value == nil {
		return nil, ValidationError(op, "value is nil")
	}
	s, b, err := encodeValue(op, value)
	if err != nil {
		return nil, err
	}
	in := &secretsmanager.PutSecretValueInput{SecretId: aws.String(id), SecretString: s, SecretBinary: b}
	if opts != nil {
		in.VersionStages = append([]string(nil), opts.VersionStages...)
		in.ClientRequestToken = optStr(opts.ClientRequestToken)
	}
	out, err := call(ctx, c, op, func(ctx context.Context) (*secretsmanager.PutSecretValueOutput, error) {
		return c.api.PutSecretValue(ctx, in)
	})
	if err != nil {
		return nil, err
	}
	return &PutSecretValueResult{ARN: str(out.ARN), Name: str(out.Name), VersionID: str(out.VersionId),
		VersionStages: append([]string(nil), out.VersionStages...)}, nil
}

// UpdateSecret changes the description, KMS key and/or value of a secret.
func (c *Client) UpdateSecret(ctx context.Context, id string, opts UpdateSecretOptions) (*SecretWriteResult, error) {
	op := opName("updateSecret", id)
	if err := checkID(op, id); err != nil {
		return nil, err
	}
	if opts.Value == nil && opts.Description == "" && opts.KmsKeyID == "" {
		return nil, ValidationError(op, "nothing to update: give a value, description or kmsKeyId")
	}
	s, b, err := encodeValue(op, opts.Value)
	if err != nil {
		return nil, err
	}
	in := &secretsmanager.UpdateSecretInput{SecretId: aws.String(id), SecretString: s, SecretBinary: b,
		Description: optStr(opts.Description), KmsKeyId: optStr(opts.KmsKeyID), ClientRequestToken: optStr(opts.ClientRequestToken)}
	out, err := call(ctx, c, op, func(ctx context.Context) (*secretsmanager.UpdateSecretOutput, error) {
		return c.api.UpdateSecret(ctx, in)
	})
	if err != nil {
		return nil, err
	}
	return &SecretWriteResult{ARN: str(out.ARN), Name: str(out.Name), VersionID: str(out.VersionId)}, nil
}

// UpdateSecretVersionStage moves a stage label between versions. Moving
// AWSCURRENT needs RemoveFromVersionID = the current version; the old current
// version then gets AWSPREVIOUS.
func (c *Client) UpdateSecretVersionStage(ctx context.Context, id, stage string, opts UpdateSecretVersionStageOptions) (*SecretRef, error) {
	op := opName("updateSecretVersionStage", id)
	if err := checkID(op, id); err != nil {
		return nil, err
	}
	if stage == "" {
		return nil, ValidationError(op, "version stage is empty")
	}
	if opts.MoveToVersionID == "" && opts.RemoveFromVersionID == "" {
		return nil, ValidationError(op, "give moveToVersionId and/or removeFromVersionId")
	}
	in := &secretsmanager.UpdateSecretVersionStageInput{SecretId: aws.String(id), VersionStage: aws.String(stage),
		MoveToVersionId: optStr(opts.MoveToVersionID), RemoveFromVersionId: optStr(opts.RemoveFromVersionID)}
	out, err := call(ctx, c, op, func(ctx context.Context) (*secretsmanager.UpdateSecretVersionStageOutput, error) {
		return c.api.UpdateSecretVersionStage(ctx, in)
	})
	if err != nil {
		return nil, err
	}
	return &SecretRef{ARN: str(out.ARN), Name: str(out.Name)}, nil
}

// DeleteSecret schedules a secret for deletion after the recovery window
// (RecoveryWindowDays; unset = the AWS default of 30 days, as in the other
// languages; Config.RecoveryWindowDays applies to SecretsProvider.Delete) or
// deletes it immediately with
// ForceDeleteWithoutRecovery. AWS returns success for a forced delete of a
// missing secret; a secret already scheduled for deletion is CONFLICT.
func (c *Client) DeleteSecret(ctx context.Context, id string, opts *DeleteSecretOptions) (*DeleteSecretResult, error) {
	op := opName("deleteSecret", id)
	if err := checkID(op, id); err != nil {
		return nil, err
	}
	var o DeleteSecretOptions
	if opts != nil {
		o = *opts
	}
	in := &secretsmanager.DeleteSecretInput{SecretId: aws.String(id)}
	switch {
	case o.ForceDeleteWithoutRecovery && o.RecoveryWindowDays != 0:
		return nil, ValidationError(op, "recoveryWindowDays and forceDeleteWithoutRecovery are mutually exclusive")
	case o.ForceDeleteWithoutRecovery:
		in.ForceDeleteWithoutRecovery = aws.Bool(true)
	case o.RecoveryWindowDays != 0 && (o.RecoveryWindowDays < 7 || o.RecoveryWindowDays > 30):
		return nil, ValidationError(op, "recoveryWindowDays must be between 7 and 30")
	case o.RecoveryWindowDays != 0:
		in.RecoveryWindowInDays = aws.Int64(int64(o.RecoveryWindowDays))
	}
	out, err := call(ctx, c, op, func(ctx context.Context) (*secretsmanager.DeleteSecretOutput, error) {
		return c.api.DeleteSecret(ctx, in)
	})
	if err != nil {
		return nil, err
	}
	return &DeleteSecretResult{ARN: str(out.ARN), Name: str(out.Name), DeletionDate: tm(out.DeletionDate)}, nil
}

// RestoreSecret cancels a scheduled deletion (a no-op for a live secret).
func (c *Client) RestoreSecret(ctx context.Context, id string) (*SecretRef, error) {
	op := opName("restoreSecret", id)
	if err := checkID(op, id); err != nil {
		return nil, err
	}
	out, err := call(ctx, c, op, func(ctx context.Context) (*secretsmanager.RestoreSecretOutput, error) {
		return c.api.RestoreSecret(ctx, &secretsmanager.RestoreSecretInput{SecretId: aws.String(id)})
	})
	if err != nil {
		return nil, err
	}
	return &SecretRef{ARN: str(out.ARN), Name: str(out.Name)}, nil
}
