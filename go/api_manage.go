package awssecretsmanager

import (
	"context"
	"encoding/json"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

// PutResourcePolicyOptions control PutResourcePolicy.
type PutResourcePolicyOptions struct {
	// BlockPublicPolicy rejects policies that grant broad public access
	// (nil = AWS default true).
	BlockPublicPolicy *bool
}

// ValidateResourcePolicyOptions control ValidateResourcePolicy.
type ValidateResourcePolicyOptions struct {
	// SecretID validates the policy against this secret.
	SecretID string
}

// RotateSecretOptions control RotateSecret.
type RotateSecretOptions struct {
	// LambdaARN is the rotation function (omit for managed rotation or to
	// rotate with the function already configured).
	LambdaARN string
	// Rules set the rotation schedule.
	Rules *RotationRules
	// RotateImmediately rotates now (nil = AWS default true).
	RotateImmediately  *bool
	ClientRequestToken string
}

// RandomPasswordOptions control GetRandomPassword. Zero values mean the AWS
// defaults (length 32, every character class, each included class required).
type RandomPasswordOptions struct {
	// Length is 1–4096 (default 32).
	Length             int
	ExcludeCharacters  string
	ExcludeNumbers     bool
	ExcludePunctuation bool
	ExcludeUppercase   bool
	ExcludeLowercase   bool
	IncludeSpace       bool
	// RequireEachIncludedType requires one character of every included class
	// (nil = true).
	RequireEachIncludedType *bool
}

// TagResource adds or replaces tags on a secret.
func (c *Client) TagResource(ctx context.Context, id string, tags map[string]string) error {
	op := opName("tagResource", id)
	if err := checkID(op, id); err != nil {
		return err
	}
	if len(tags) == 0 {
		return ValidationError(op, "no tags given")
	}
	_, err := call(ctx, c, op, func(ctx context.Context) (*secretsmanager.TagResourceOutput, error) {
		return c.api.TagResource(ctx, &secretsmanager.TagResourceInput{SecretId: aws.String(id), Tags: tagsToSDK(tags)})
	})
	return err
}

// UntagResource removes tags (by key) from a secret.
func (c *Client) UntagResource(ctx context.Context, id string, keys []string) error {
	op := opName("untagResource", id)
	if err := checkID(op, id); err != nil {
		return err
	}
	if len(keys) == 0 {
		return ValidationError(op, "no tag keys given")
	}
	_, err := call(ctx, c, op, func(ctx context.Context) (*secretsmanager.UntagResourceOutput, error) {
		return c.api.UntagResource(ctx, &secretsmanager.UntagResourceInput{SecretId: aws.String(id), TagKeys: append([]string(nil), keys...)})
	})
	return err
}

// PutResourcePolicy attaches a resource policy. policy is a JSON string or a
// JSON-encodable value (map or struct).
func (c *Client) PutResourcePolicy(ctx context.Context, id string, policy any, opts *PutResourcePolicyOptions) (*SecretRef, error) {
	op := opName("putResourcePolicy", id)
	if err := checkID(op, id); err != nil {
		return nil, err
	}
	doc, err := policyString(op, policy)
	if err != nil {
		return nil, err
	}
	in := &secretsmanager.PutResourcePolicyInput{SecretId: aws.String(id), ResourcePolicy: aws.String(doc)}
	if opts != nil {
		in.BlockPublicPolicy = opts.BlockPublicPolicy
	}
	out, err := call(ctx, c, op, func(ctx context.Context) (*secretsmanager.PutResourcePolicyOutput, error) {
		return c.api.PutResourcePolicy(ctx, in)
	})
	if err != nil {
		return nil, err
	}
	return &SecretRef{ARN: str(out.ARN), Name: str(out.Name)}, nil
}

// GetResourcePolicy returns the secret's resource policy (ResourcePolicy is
// "" when none is attached; Policy holds the parsed JSON object).
func (c *Client) GetResourcePolicy(ctx context.Context, id string) (*ResourcePolicyResult, error) {
	op := opName("getResourcePolicy", id)
	if err := checkID(op, id); err != nil {
		return nil, err
	}
	out, err := call(ctx, c, op, func(ctx context.Context) (*secretsmanager.GetResourcePolicyOutput, error) {
		return c.api.GetResourcePolicy(ctx, &secretsmanager.GetResourcePolicyInput{SecretId: aws.String(id)})
	})
	if err != nil {
		return nil, err
	}
	res := &ResourcePolicyResult{ARN: str(out.ARN), Name: str(out.Name), ResourcePolicy: str(out.ResourcePolicy)}
	var doc map[string]any
	if res.ResourcePolicy != "" && json.Unmarshal([]byte(res.ResourcePolicy), &doc) == nil {
		res.Policy = doc
	}
	return res, nil
}

// DeleteResourcePolicy removes the secret's resource policy.
func (c *Client) DeleteResourcePolicy(ctx context.Context, id string) (*SecretRef, error) {
	op := opName("deleteResourcePolicy", id)
	if err := checkID(op, id); err != nil {
		return nil, err
	}
	out, err := call(ctx, c, op, func(ctx context.Context) (*secretsmanager.DeleteResourcePolicyOutput, error) {
		return c.api.DeleteResourcePolicy(ctx, &secretsmanager.DeleteResourcePolicyInput{SecretId: aws.String(id)})
	})
	if err != nil {
		return nil, err
	}
	return &SecretRef{ARN: str(out.ARN), Name: str(out.Name)}, nil
}

// ValidateResourcePolicy checks a policy with AWS's policy checks
// (UNSUPPORTED on emulators that do not implement it, such as Moto 5.2.4).
func (c *Client) ValidateResourcePolicy(ctx context.Context, policy any, opts *ValidateResourcePolicyOptions) (*ValidateResourcePolicyResult, error) {
	const op = "validateResourcePolicy"
	doc, err := policyString(op, policy)
	if err != nil {
		return nil, err
	}
	in := &secretsmanager.ValidateResourcePolicyInput{ResourcePolicy: aws.String(doc)}
	if opts != nil {
		in.SecretId = optStr(opts.SecretID)
	}
	out, err := call(ctx, c, op, func(ctx context.Context) (*secretsmanager.ValidateResourcePolicyOutput, error) {
		return c.api.ValidateResourcePolicy(ctx, in)
	})
	if err != nil {
		return nil, err
	}
	res := &ValidateResourcePolicyResult{PolicyValidationPassed: out.PolicyValidationPassed, ValidationErrors: []PolicyValidationError{}}
	for _, e := range out.ValidationErrors {
		res.ValidationErrors = append(res.ValidationErrors, PolicyValidationError{CheckName: str(e.CheckName), ErrorMessage: str(e.ErrorMessage)})
	}
	return res, nil
}

// RotateSecret configures and/or starts rotation. Without LambdaARN it
// rotates with the function already configured (or managed rotation).
func (c *Client) RotateSecret(ctx context.Context, id string, opts *RotateSecretOptions) (*SecretWriteResult, error) {
	op := opName("rotateSecret", id)
	if err := checkID(op, id); err != nil {
		return nil, err
	}
	in := &secretsmanager.RotateSecretInput{SecretId: aws.String(id)}
	if opts != nil {
		if opts.Rules != nil && opts.Rules.AutomaticallyAfterDays > 0 && opts.Rules.ScheduleExpression != "" {
			return nil, ValidationError(op, "automaticallyAfterDays and scheduleExpression are mutually exclusive")
		}
		in.RotationLambdaARN, in.RotationRules = optStr(opts.LambdaARN), rulesToSDK(opts.Rules)
		in.RotateImmediately, in.ClientRequestToken = opts.RotateImmediately, optStr(opts.ClientRequestToken)
	}
	out, err := call(ctx, c, op, func(ctx context.Context) (*secretsmanager.RotateSecretOutput, error) {
		return c.api.RotateSecret(ctx, in)
	})
	if err != nil {
		return nil, err
	}
	return &SecretWriteResult{ARN: str(out.ARN), Name: str(out.Name), VersionID: str(out.VersionId)}, nil
}

// CancelRotateSecret turns automatic rotation off (RotationEnabled = false).
func (c *Client) CancelRotateSecret(ctx context.Context, id string) (*SecretWriteResult, error) {
	op := opName("cancelRotateSecret", id)
	if err := checkID(op, id); err != nil {
		return nil, err
	}
	out, err := call(ctx, c, op, func(ctx context.Context) (*secretsmanager.CancelRotateSecretOutput, error) {
		return c.api.CancelRotateSecret(ctx, &secretsmanager.CancelRotateSecretInput{SecretId: aws.String(id)})
	})
	if err != nil {
		return nil, err
	}
	return &SecretWriteResult{ARN: str(out.ARN), Name: str(out.Name), VersionID: str(out.VersionId)}, nil
}

// GetRandomPassword generates a password with AWS. The result is a redacting
// Secret; call Reveal to use it.
func (c *Client) GetRandomPassword(ctx context.Context, opts *RandomPasswordOptions) (Secret, error) {
	const op = "getRandomPassword"
	var o RandomPasswordOptions
	if opts != nil {
		o = *opts
	}
	if o.Length == 0 {
		o.Length = DefaultPasswordLength
	}
	if o.Length < 1 || o.Length > 4096 {
		return Secret{}, ValidationError(op, "length must be between 1 and 4096")
	}
	in := &secretsmanager.GetRandomPasswordInput{
		PasswordLength: aws.Int64(int64(o.Length)), ExcludeCharacters: optStr(o.ExcludeCharacters),
		RequireEachIncludedType: aws.Bool(o.RequireEachIncludedType == nil || *o.RequireEachIncludedType),
	}
	setTrue := func(dst **bool, v bool) {
		if v {
			*dst = aws.Bool(true)
		}
	}
	setTrue(&in.ExcludeNumbers, o.ExcludeNumbers)
	setTrue(&in.ExcludePunctuation, o.ExcludePunctuation)
	setTrue(&in.ExcludeUppercase, o.ExcludeUppercase)
	setTrue(&in.ExcludeLowercase, o.ExcludeLowercase)
	setTrue(&in.IncludeSpace, o.IncludeSpace)
	out, err := call(ctx, c, op, func(ctx context.Context) (*secretsmanager.GetRandomPasswordOutput, error) {
		return c.api.GetRandomPassword(ctx, in)
	})
	if err != nil {
		return Secret{}, err
	}
	return NewSecret(str(out.RandomPassword)), nil
}

func sortOrder(s string) types.SortOrderType { return types.SortOrderType(s) }
