"""AWS error mapping: AWS code first, HTTP status as fallback, Moto quirks, redaction."""

from __future__ import annotations

from typing import Any

import pytest
from botocore import exceptions as bx

import grow_aws_secrets_manager as sdk

SECRET = "grow-test-secret-key-0001"


def client_error(
    code: str,
    status: int | None = 400,
    message: str = "boom",
    headers: dict[str, str] | None = None,
    request_id: str | None = "req-1",
) -> bx.ClientError:
    meta: dict[str, Any] = {"HTTPHeaders": headers or {}}
    if status is not None:
        meta["HTTPStatusCode"] = status
    if request_id is not None:
        meta["RequestId"] = request_id
    return bx.ClientError(
        {"Error": {"Code": code, "Message": message}, "ResponseMetadata": meta}, "Op"
    )


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("ResourceNotFoundException", sdk.NotFoundError),
        ("ResourceExistsException", sdk.ConflictError),
        ("InvalidRequestException", sdk.ConflictError),
        ("PreconditionNotMetException", sdk.ConflictError),
        ("InvalidParameterException", sdk.ValidationError),
        ("MalformedPolicyDocumentException", sdk.ValidationError),
        ("AccessDeniedException", sdk.PermissionDeniedError),
        ("UnrecognizedClientException", sdk.AuthenticationError),
        ("ExpiredTokenException", sdk.AuthenticationError),
        ("ThrottlingException", sdk.RateLimitError),
        ("InternalServiceError", sdk.UnavailableError),
        ("RequestTimeoutException", sdk.TimeoutError),
    ],
)
def test_aws_codes_win_over_status(code: str, expected: type[Exception]) -> None:
    err = sdk.map_aws_error(client_error(code), "op x")
    assert isinstance(err, expected)
    assert err.http_status == 400
    assert err.request_id == "req-1"
    assert sdk.aws_error_code(err) == code
    assert err.message.startswith(f"op x: {code}: boom")


def test_status_fallback_and_moto_xml() -> None:
    xml = (
        "<?xml version='1.0'?><ErrorResponse><Errors><Error><Code>InvalidClientTokenId</Code>"
        "<Message>The security token included in the request is invalid.</Message>"
        "</Error></Errors></ErrorResponse>"
    )
    err = sdk.map_aws_error(client_error("403", 403, xml, request_id=None), "ping")
    assert isinstance(err, sdk.AuthenticationError)
    assert err.message == "ping: InvalidClientTokenId (HTTP 403)"
    assert err.request_id is None
    denied = sdk.map_aws_error(client_error("403", 403, "<html>Forbidden</html>"), "op")
    assert isinstance(denied, sdk.PermissionDeniedError)
    assert denied.message == "op: permission denied (HTTP 403)"
    sig = sdk.map_aws_error(client_error("403", 403, "SignatureDoesNotMatch"), "op")
    assert isinstance(sig, sdk.AuthenticationError)
    for status, cls in (
        (404, sdk.NotFoundError),
        (409, sdk.ConflictError),
        (429, sdk.RateLimitError),
        (418, sdk.ValidationError),
        (501, sdk.UnsupportedError),
        (502, sdk.UnavailableError),
        (504, sdk.TimeoutError),
    ):
        assert isinstance(sdk.map_aws_error(client_error(str(status), status, ""), "op"), cls)
    assert sdk.code_for_status(401) is sdk.ErrorCode.AUTHENTICATION
    unknown = sdk.map_aws_error(client_error("WeirdException", 400, ""), "op")
    assert isinstance(unknown, sdk.ValidationError)
    assert unknown.message == "op: WeirdException (HTTP 400)"
    no_status = sdk.map_aws_error(client_error("", None, ""), "op")
    assert isinstance(no_status, sdk.UnavailableError)
    assert no_status.message == "op: service unavailable"


def test_html_500_is_unsupported_only_when_flagged() -> None:
    html = "<!doctype html><html><title>500 Internal Server Error</title></html>"
    plain = sdk.map_aws_error(client_error("500", 500, html), "validate")
    assert isinstance(plain, sdk.UnavailableError)
    flagged = sdk.map_aws_error(
        client_error("500", 500, html), "validate", unsupported_on_html_500=True
    )
    assert isinstance(flagged, sdk.UnsupportedError)
    assert flagged.retryable is False


def test_retry_after_and_redaction() -> None:
    err = sdk.map_aws_error(
        client_error(
            "ThrottlingException",
            message=f"slow down {SECRET}   please",
            headers={"Retry-After": "3"},
        ),
        "op",
        known_secrets=[sdk.Secret(SECRET), None, ""],
    )
    assert isinstance(err, sdk.RateLimitError)
    assert err.retry_after == 3.0
    assert err.retryable
    assert SECRET not in err.message
    assert "slow down [REDACTED] please" in err.message
    long = sdk.map_aws_error(client_error("ValidationException", message="x" * 500), "op")
    assert len(long.message) < 360


def test_botocore_exceptions() -> None:
    cases: list[tuple[BaseException, type[Exception]]] = [
        (bx.NoRegionError(), sdk.ConfigError),
        (bx.ProfileNotFound(profile="nope"), sdk.ConfigError),
        (bx.NoCredentialsError(), sdk.AuthenticationError),
        (
            bx.PartialCredentialsError(provider="env", cred_var="AWS_SECRET_ACCESS_KEY"),
            sdk.AuthenticationError,
        ),
        (bx.ParamValidationError(report="bad"), sdk.ValidationError),
        (bx.ConnectTimeoutError(endpoint_url="http://x"), sdk.TimeoutError),
        (bx.ReadTimeoutError(endpoint_url="http://x"), sdk.TimeoutError),
        (bx.EndpointConnectionError(endpoint_url="http://x"), sdk.UnavailableError),
        (RuntimeError(f"boom {SECRET}"), sdk.UnavailableError),
        (RuntimeError(), sdk.UnavailableError),
    ]
    for exc, cls in cases:
        err = sdk.map_aws_error(exc, "op", known_secrets=[SECRET])
        assert isinstance(err, cls), (exc, err)
        assert err.cause is exc
        assert SECRET not in err.message
    region = sdk.map_aws_error(bx.NoRegionError(), "op")
    assert "no AWS region configured" in region.message
    same = sdk.NotFoundError("x")
    assert sdk.map_aws_error(same, "op") is same
    assert sdk.map_aws_error(RuntimeError(), "op").message.endswith("RuntimeError")


def test_aws_error_code_helper() -> None:
    assert (
        sdk.aws_error_code(client_error("ResourceNotFoundException")) == "ResourceNotFoundException"
    )
    assert sdk.aws_error_code(client_error("")) is None
    assert sdk.aws_error_code(ValueError()) is None
    assert sdk.error_code_from_body("<Code> AccessDenied </Code>") == "AccessDenied"
    assert sdk.error_code_from_body("{}") is None
