"""Maps boto3 / botocore errors to the SPEC section 2.1 error classes by AWS error code.

AWS JSON services answer HTTP 400 for throttling and access denied, so mapping by status alone
is wrong; the AWS error code decides and the status is only the fallback (API.md section 1.1).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

from botocore import exceptions as boto_exc

from ._core import (
    AwsSecretsManagerError,
    ErrorCode,
    Secret,
    error_for_code,
    parse_retry_after,
    redact_text,
    truncate,
)

__all__ = [
    "AWS_ERROR_CODES",
    "aws_error_code",
    "code_for_status",
    "error_code_from_body",
    "map_aws_error",
]

#: AWS error code → Grow :class:`ErrorCode`.
AWS_ERROR_CODES: Mapping[str, ErrorCode] = {
    "ResourceNotFoundException": ErrorCode.NOT_FOUND,
    "ResourceExistsException": ErrorCode.CONFLICT,
    "PreconditionNotMetException": ErrorCode.CONFLICT,
    "InvalidRequestException": ErrorCode.CONFLICT,
    "InvalidParameterException": ErrorCode.VALIDATION,
    "InvalidParameterValue": ErrorCode.VALIDATION,
    "ValidationException": ErrorCode.VALIDATION,
    "InvalidNextTokenException": ErrorCode.VALIDATION,
    "MalformedPolicyDocumentException": ErrorCode.VALIDATION,
    "PublicPolicyException": ErrorCode.VALIDATION,
    "LimitExceededException": ErrorCode.VALIDATION,
    "EncryptionFailure": ErrorCode.VALIDATION,
    "DecryptionFailure": ErrorCode.VALIDATION,
    "SerializationException": ErrorCode.VALIDATION,
    "AccessDeniedException": ErrorCode.PERMISSION_DENIED,
    "AccessDenied": ErrorCode.PERMISSION_DENIED,
    "UnrecognizedClientException": ErrorCode.AUTHENTICATION,
    "InvalidClientTokenId": ErrorCode.AUTHENTICATION,
    "InvalidSignatureException": ErrorCode.AUTHENTICATION,
    "SignatureDoesNotMatch": ErrorCode.AUTHENTICATION,
    "IncompleteSignature": ErrorCode.AUTHENTICATION,
    "IncompleteSignatureException": ErrorCode.AUTHENTICATION,
    "MissingAuthenticationToken": ErrorCode.AUTHENTICATION,
    "MissingAuthenticationTokenException": ErrorCode.AUTHENTICATION,
    "ExpiredToken": ErrorCode.AUTHENTICATION,
    "ExpiredTokenException": ErrorCode.AUTHENTICATION,
    "InvalidAccessKeyId": ErrorCode.AUTHENTICATION,
    "ThrottlingException": ErrorCode.RATE_LIMITED,
    "Throttling": ErrorCode.RATE_LIMITED,
    "TooManyRequestsException": ErrorCode.RATE_LIMITED,
    "RequestLimitExceeded": ErrorCode.RATE_LIMITED,
    "InternalServiceError": ErrorCode.UNAVAILABLE,
    "InternalServiceErrorException": ErrorCode.UNAVAILABLE,
    "InternalFailure": ErrorCode.UNAVAILABLE,
    "ServiceUnavailable": ErrorCode.UNAVAILABLE,
    "ServiceUnavailableException": ErrorCode.UNAVAILABLE,
    "RequestTimeout": ErrorCode.TIMEOUT,
    "RequestTimeoutException": ErrorCode.TIMEOUT,
}

_XML_CODE = re.compile(r"<Code>\s*([^<\s]+)\s*</Code>")
_AUTH_HINT = re.compile(r"InvalidClientTokenId|SignatureDoesNotMatch|security token", re.I)
_MARKUP = re.compile(r"^\s*<")
_REASONS: Mapping[ErrorCode, str] = {
    ErrorCode.CONFIG: "invalid configuration",
    ErrorCode.AUTHENTICATION: "authentication failed",
    ErrorCode.PERMISSION_DENIED: "permission denied",
    ErrorCode.NOT_FOUND: "not found",
    ErrorCode.CONFLICT: "conflict",
    ErrorCode.RATE_LIMITED: "rate limited",
    ErrorCode.VALIDATION: "invalid request",
    ErrorCode.UNAVAILABLE: "service unavailable",
    ErrorCode.TIMEOUT: "timed out",
    ErrorCode.UNSUPPORTED: "not supported by this service or emulator",
    ErrorCode.CANCELLED: "cancelled",
}


def code_for_status(status: int) -> ErrorCode:
    """SPEC 2.1 status mapping (used only when the AWS error code is unknown)."""
    fixed = {
        401: ErrorCode.AUTHENTICATION,
        403: ErrorCode.PERMISSION_DENIED,
        404: ErrorCode.NOT_FOUND,
        408: ErrorCode.TIMEOUT,
        409: ErrorCode.CONFLICT,
        412: ErrorCode.CONFLICT,
        429: ErrorCode.RATE_LIMITED,
        501: ErrorCode.UNSUPPORTED,
        504: ErrorCode.TIMEOUT,
    }
    if status in fixed:
        return fixed[status]
    if status >= 500:
        return ErrorCode.UNAVAILABLE
    return ErrorCode.VALIDATION


def error_code_from_body(text: str) -> str | None:
    """The error code of an XML (``<Code>``) error body, ``None`` when there is none."""
    match = _XML_CODE.search(text)
    return match.group(1) if match else None


def aws_error_code(err: BaseException) -> str | None:
    """The AWS error code behind an SDK error (or a botocore ``ClientError``), if known."""
    code = getattr(err, "aws_code", None)
    if isinstance(code, str):
        return code
    if isinstance(err, boto_exc.ClientError):
        raw = err.response.get("Error", {}).get("Code")
        return raw if isinstance(raw, str) and raw else None
    return None


def _clean(text: str, known: list[str]) -> str:
    collapsed = " ".join(text.split())
    return truncate(redact_text(collapsed, known), 300)


def _new(
    code: ErrorCode,
    message: str,
    *,
    known: list[str],
    aws_code: str | None = None,
    cause: BaseException | None = None,
    **kw: Any,
) -> AwsSecretsManagerError:
    err = error_for_code(code)(redact_text(message, known), cause=cause, **kw)
    err.aws_code = aws_code  # type: ignore[attr-defined]
    return err


def _from_client_error(
    exc: boto_exc.ClientError, operation: str, known: list[str], unsupported_on_html_500: bool
) -> AwsSecretsManagerError:
    response: Mapping[str, Any] = exc.response
    error = response.get("Error") or {}
    meta = response.get("ResponseMetadata") or {}
    headers = {str(k).lower(): str(v) for k, v in (meta.get("HTTPHeaders") or {}).items()}
    status = meta.get("HTTPStatusCode")
    status = status if isinstance(status, int) else None
    request_id = meta.get("RequestId") or headers.get("x-amzn-requestid")
    raw_code = str(error.get("Code") or "")
    text = str(error.get("Message") or "")
    is_markup = bool(_MARKUP.match(text))
    aws_code: str | None = raw_code if raw_code and not raw_code.isdigit() else None
    if aws_code is None or aws_code not in AWS_ERROR_CODES:
        aws_code = error_code_from_body(text) or aws_code
    code = AWS_ERROR_CODES.get(aws_code) if aws_code else None
    if code is None:
        if status == 403:
            auth = _AUTH_HINT.search(text)
            code = ErrorCode.AUTHENTICATION if auth else ErrorCode.PERMISSION_DENIED
        elif status == 500 and unsupported_on_html_500 and "<html" in text.lower():
            code = ErrorCode.UNSUPPORTED
        elif status is not None:
            code = code_for_status(status)
        else:
            code = ErrorCode.UNAVAILABLE
    vendor = "" if is_markup or not text else _clean(text, known)
    reason = (
        _REASONS[code] if aws_code is None else (f"{aws_code}: {vendor}" if vendor else aws_code)
    )
    suffix = "" if status is None else f" (HTTP {status})"
    retry_after = None
    if code is ErrorCode.RATE_LIMITED and "retry-after" in headers:
        retry_after = parse_retry_after(headers["retry-after"])
    return _new(
        code,
        f"{operation}: {reason}{suffix}",
        known=known,
        aws_code=aws_code,
        cause=exc,
        http_status=status,
        request_id=request_id,
        retry_after=retry_after,
    )


def map_aws_error(
    exc: BaseException,
    operation: str,
    *,
    known_secrets: Iterable[str | Secret | None] = (),
    unsupported_on_html_500: bool = False,
) -> AwsSecretsManagerError:
    """Converts anything boto3 / aiobotocore raises into an SDK error.

    The message is ``"<operation>: <AwsCode>: <redacted vendor text> (HTTP <status>)"``; the AWS
    code is kept on the error (:func:`aws_error_code`). ``unsupported_on_html_500`` marks an
    operation some emulators lack: a non-JSON HTTP 500 then maps to ``UNSUPPORTED``.
    """
    if isinstance(exc, AwsSecretsManagerError):
        return exc
    known = [
        s.reveal() if isinstance(s, Secret) else s for s in known_secrets if s is not None and s
    ]
    if isinstance(exc, boto_exc.ClientError):
        return _from_client_error(exc, operation, known, unsupported_on_html_500)
    detail = _clean(str(exc), known)
    if isinstance(exc, boto_exc.NoRegionError):
        message = f"{operation}: no AWS region configured (set region or AWS_REGION)"
        return _new(ErrorCode.CONFIG, message, known=known, cause=exc)
    if isinstance(exc, boto_exc.ProfileNotFound):
        return _new(ErrorCode.CONFIG, f"{operation}: {detail}", known=known, cause=exc)
    if isinstance(
        exc,
        (
            boto_exc.NoCredentialsError,
            boto_exc.PartialCredentialsError,
            boto_exc.CredentialRetrievalError,
        ),
    ):
        message = f"{operation}: no usable AWS credentials: {detail}"
        return _new(ErrorCode.AUTHENTICATION, message, known=known, cause=exc)
    if isinstance(exc, boto_exc.ParamValidationError):
        return _new(ErrorCode.VALIDATION, f"{operation}: {detail}", known=known, cause=exc)
    if isinstance(exc, (boto_exc.ConnectTimeoutError, boto_exc.ReadTimeoutError)):
        return _new(ErrorCode.TIMEOUT, f"{operation}: timed out: {detail}", known=known, cause=exc)
    reason = _REASONS[ErrorCode.UNAVAILABLE]
    if not isinstance(exc, boto_exc.BotoCoreError):
        detail = f"{type(exc).__name__}: {detail}" if detail else type(exc).__name__
    return _new(ErrorCode.UNAVAILABLE, f"{operation}: {reason}: {detail}", known=known, cause=exc)
