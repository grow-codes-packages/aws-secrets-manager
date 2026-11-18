package awssecretsmanager

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// awsErrorCodes maps AWS error codes to canonical codes (API.md §1.1). AWS JSON
// services answer 400 for throttling and access denied, so the code decides,
// the HTTP status is only the fallback.
var awsErrorCodes = map[string]ErrorCode{
	"ResourceNotFoundException":        ErrorCodeNotFound,
	"ResourceExistsException":          ErrorCodeConflict,
	"PreconditionNotMetException":      ErrorCodeConflict,
	"InvalidRequestException":          ErrorCodeConflict,
	"InvalidParameterException":        ErrorCodeValidation,
	"InvalidParameterValue":            ErrorCodeValidation,
	"ValidationException":              ErrorCodeValidation,
	"InvalidNextTokenException":        ErrorCodeValidation,
	"MalformedPolicyDocumentException": ErrorCodeValidation,
	"PublicPolicyException":            ErrorCodeValidation,
	"LimitExceededException":           ErrorCodeValidation,
	"EncryptionFailure":                ErrorCodeValidation,
	"DecryptionFailure":                ErrorCodeValidation,
	"AccessDeniedException":            ErrorCodePermissionDenied,
	"AccessDenied":                     ErrorCodePermissionDenied,
	"UnrecognizedClientException":      ErrorCodeAuthentication,
	"InvalidClientTokenId":             ErrorCodeAuthentication,
	"InvalidSignatureException":        ErrorCodeAuthentication,
	"SignatureDoesNotMatch":            ErrorCodeAuthentication,
	"IncompleteSignature":              ErrorCodeAuthentication,
	"MissingAuthenticationToken":       ErrorCodeAuthentication,
	"ExpiredToken":                     ErrorCodeAuthentication,
	"ExpiredTokenException":            ErrorCodeAuthentication,
	"ThrottlingException":              ErrorCodeRateLimited,
	"TooManyRequestsException":         ErrorCodeRateLimited,
	"RequestLimitExceeded":             ErrorCodeRateLimited,
	"InternalServiceError":             ErrorCodeUnavailable,
	"InternalFailure":                  ErrorCodeUnavailable,
	"ServiceUnavailable":               ErrorCodeUnavailable,
	"RequestTimeout":                   ErrorCodeTimeout,
	"RequestTimeoutException":          ErrorCodeTimeout,
}

// unsupportedOnServerError lists operations an emulator may not implement: an
// HTTP 500/501 without an AWS error code means UNSUPPORTED for them.
var unsupportedOnServerError = map[string]bool{"validateResourcePolicy": true}

// authMarkers identify an authentication failure in a 403 body without a
// parseable AWS error code (Moto answers IAM errors with XML).
var authMarkers = []string{"InvalidClientTokenId", "SignatureDoesNotMatch", "security token", "UnrecognizedClient"}

// mapError converts an AWS SDK error into an *Error (SPEC §2.1). op is the
// Grow operation name ("getSecretValue app/db"). Messages are redacted with
// the client's known secrets and never contain request bodies.
func (c *Client) mapError(op string, err error) error {
	if err == nil {
		return nil
	}
	var ge *Error
	if errors.As(err, &ge) {
		return ge
	}
	switch {
	case errors.Is(err, context.Canceled):
		return &Error{Code: ErrorCodeCancelled, Message: op + ": cancelled", Err: context.Canceled}
	case errors.Is(err, context.DeadlineExceeded):
		return &Error{Code: ErrorCodeTimeout, Message: op + ": deadline exceeded", Retryable: true, Err: context.DeadlineExceeded}
	}

	status, reqID := 0, ""
	var re *awshttp.ResponseError
	if errors.As(err, &re) {
		status, reqID = re.HTTPStatusCode(), re.ServiceRequestID()
	} else {
		var sre *smithyhttp.ResponseError
		if errors.As(err, &sre) {
			status = sre.HTTPStatusCode()
		}
	}
	retryAfter, _ := retryAfterOf(err, time.Now())

	var apiErr smithy.APIError
	if errors.As(err, &apiErr) && apiErr.ErrorCode() != "" && apiErr.ErrorCode() != "UnknownError" {
		awsCode := apiErr.ErrorCode()
		code, known := awsErrorCodes[awsCode]
		if !known {
			code = c.codeForStatus(op, status, "")
		}
		msg := c.redact(apiErr.ErrorMessage())
		return c.newError(op, code, status, reqID, retryAfter, awsCode, msg)
	}

	if status > 0 {
		body := ""
		var de *smithy.DeserializationError
		if errors.As(err, &de) {
			body = string(de.Snapshot)
		}
		code := c.codeForStatus(op, status, body)
		reason := strings.ToLower(statusReason(status))
		return c.newError(op, code, status, reqID, retryAfter, "", reason)
	}

	var se *v4.SigningError
	if errors.As(err, &se) || isCredentialsError(err) {
		return &Error{Code: ErrorCodeAuthentication, Message: op + ": no usable AWS credentials found", Err: errors.New(c.redact(err.Error()))}
	}
	var mre *aws.MissingRegionError
	if errors.As(err, &mre) {
		return ConfigError("region is not set (GROW_AWS_SECRETS_MANAGER_REGION or AWS_REGION)")
	}
	var rte *awshttp.ResponseTimeoutError
	var nerr net.Error
	if errors.As(err, &rte) || (errors.As(err, &nerr) && nerr.Timeout()) {
		return &Error{Code: ErrorCodeTimeout, Message: op + ": request timeout exceeded", Retryable: true, Err: errors.New(c.redact(innerMessage(err)))}
	}
	var send *smithyhttp.RequestSendError
	if errors.As(err, &send) {
		return &Error{Code: ErrorCodeUnavailable, Message: op + ": network error: " + c.redact(innerMessage(send.Err)), Retryable: true,
			Err: errors.New(c.redact(innerMessage(send.Err)))}
	}
	return &Error{Code: ErrorCodeUnavailable, Message: op + ": " + truncate(c.redact(err.Error()), maxVendorText), Retryable: true,
		Err: errors.New(c.redact(err.Error()))}
}

// codeForStatus maps a status without a recognised AWS error code.
func (c *Client) codeForStatus(op string, status int, body string) ErrorCode {
	opName, _, _ := strings.Cut(op, " ")
	switch {
	case status == 403:
		for _, m := range authMarkers {
			if strings.Contains(body, m) {
				return ErrorCodeAuthentication
			}
		}
		return ErrorCodePermissionDenied
	case (status == 500 || status == 501) && unsupportedOnServerError[opName]:
		return ErrorCodeUnsupported
	case status == 0:
		return ErrorCodeUnavailable
	}
	return CodeForStatus(status)
}

func (c *Client) newError(op string, code ErrorCode, status int, reqID string, retryAfter time.Duration, awsCode, msg string) *Error {
	reason := awsCode
	msg = strings.Join(strings.Fields(msg), " ")
	switch {
	case reason == "":
		reason = msg
	case msg != "" && msg != awsCode:
		reason += ": " + truncate(msg, maxVendorText)
	}
	text := fmt.Sprintf("%s: %s", op, reason)
	if status > 0 {
		text += fmt.Sprintf(" (HTTP %d)", status)
	}
	e := &Error{Code: code, Message: text, HTTPStatus: status, RequestID: reqID, Retryable: code.Retryable(), RetryAfter: retryAfter}
	if awsCode != "" {
		e.Err = &smithy.GenericAPIError{Code: awsCode, Message: msg}
	}
	return e
}

// AWSErrorCode returns the AWS error code behind err ("ResourceNotFoundException"),
// or "" when err did not come from an AWS error response.
func AWSErrorCode(err error) string {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode()
	}
	return ""
}

// isCredentialsError reports an SDK failure to resolve credentials (no
// HTTP response involved).
func isCredentialsError(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "get identity") || strings.Contains(msg, "retrieve credentials") ||
		strings.Contains(msg, "get credentials")
}
