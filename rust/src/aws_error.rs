//! Maps AWS SDK errors to the SPEC §2.1 error codes **by AWS error code** (AWS JSON services
//! answer HTTP 400 for throttling and access denied, so status-only mapping is wrong; API.md §1.1).

use std::error::Error as StdError;
use std::fmt;
use std::time::SystemTime;

use aws_sdk_secretsmanager::error::{ProvideErrorMetadata, SdkError};
use aws_smithy_runtime_api::client::orchestrator::HttpResponse;

use crate::core::redact::{redact_text, truncate};
use crate::core::retry::parse_retry_after;
use crate::core::transport::MAX_VENDOR_MESSAGE;
use crate::core::{Error, ErrorCode};

/// AWS error code → Grow [`ErrorCode`] (API.md §1.1).
pub const AWS_ERROR_CODES: &[(&str, ErrorCode)] = &[
    ("ResourceNotFoundException", ErrorCode::NotFound),
    ("ResourceExistsException", ErrorCode::Conflict),
    ("PreconditionNotMetException", ErrorCode::Conflict),
    ("InvalidRequestException", ErrorCode::Conflict),
    ("InvalidParameterException", ErrorCode::Validation),
    ("InvalidParameterValue", ErrorCode::Validation),
    ("ValidationException", ErrorCode::Validation),
    ("InvalidNextTokenException", ErrorCode::Validation),
    ("MalformedPolicyDocumentException", ErrorCode::Validation),
    ("PublicPolicyException", ErrorCode::Validation),
    ("LimitExceededException", ErrorCode::Validation),
    ("EncryptionFailure", ErrorCode::Validation),
    ("DecryptionFailure", ErrorCode::Validation),
    ("SerializationException", ErrorCode::Validation),
    ("AccessDeniedException", ErrorCode::PermissionDenied),
    ("AccessDenied", ErrorCode::PermissionDenied),
    ("UnrecognizedClientException", ErrorCode::Authentication),
    ("InvalidClientTokenId", ErrorCode::Authentication),
    ("InvalidSignatureException", ErrorCode::Authentication),
    ("SignatureDoesNotMatch", ErrorCode::Authentication),
    ("IncompleteSignature", ErrorCode::Authentication),
    ("IncompleteSignatureException", ErrorCode::Authentication),
    ("MissingAuthenticationToken", ErrorCode::Authentication),
    (
        "MissingAuthenticationTokenException",
        ErrorCode::Authentication,
    ),
    ("ExpiredToken", ErrorCode::Authentication),
    ("ExpiredTokenException", ErrorCode::Authentication),
    ("InvalidAccessKeyId", ErrorCode::Authentication),
    ("ThrottlingException", ErrorCode::RateLimited),
    ("Throttling", ErrorCode::RateLimited),
    ("TooManyRequestsException", ErrorCode::RateLimited),
    ("RequestLimitExceeded", ErrorCode::RateLimited),
    ("InternalServiceError", ErrorCode::Unavailable),
    ("InternalServiceErrorException", ErrorCode::Unavailable),
    ("InternalFailure", ErrorCode::Unavailable),
    ("ServiceUnavailable", ErrorCode::Unavailable),
    ("ServiceUnavailableException", ErrorCode::Unavailable),
    ("RequestTimeout", ErrorCode::Timeout),
    ("RequestTimeoutException", ErrorCode::Timeout),
];

/// Operations Moto 5.2.4 does not implement: an HTML HTTP 500 maps to `UNSUPPORTED` for them.
pub(crate) const EMULATOR_GAPS: &[&str] = &["validateResourcePolicy"];

/// The Grow code for an AWS error code (`None` when unknown).
pub fn error_code_for_aws(aws_code: &str) -> Option<ErrorCode> {
    AWS_ERROR_CODES
        .iter()
        .find(|(name, _)| *name == aws_code)
        .map(|(_, code)| *code)
}

/// Extracts an AWS error code from an XML (`<Code>`) or JSON (`__type`, `code`) error body.
pub fn error_code_from_body(text: &str) -> Option<String> {
    if let Some(start) = text.find("<Code>") {
        let rest = &text[start + 6..];
        if let Some(end) = rest.find("</Code>") {
            let code = rest[..end].trim();
            if !code.is_empty() {
                return Some(code.to_owned());
            }
        }
    }
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let raw = value
        .get("__type")
        .and_then(|v| v.as_str())
        .or_else(|| value.get("code").and_then(|v| v.as_str()))?;
    clean_code(raw)
}

/// `com.amazonaws…#Code` / `Code:http://…` → `Code`.
fn clean_code(raw: &str) -> Option<String> {
    let code = raw.rsplit('#').next()?.split(':').next()?.trim();
    (!code.is_empty()).then(|| code.to_owned())
}

/// The AWS error code behind an SDK error (e.g. `ResourceNotFoundException`), when the error
/// came from an AWS response with a recognisable code.
pub fn aws_error_code(err: &Error) -> Option<&str> {
    err.cause()
        .and_then(|c| c.downcast_ref::<AwsErrorDetail>())
        .and_then(|d| d.code.as_deref())
}

/// Redacted details of an AWS error, kept as the [`Error`] source. It never holds the raw
/// response (which could echo request data).
#[derive(Debug, Clone)]
pub struct AwsErrorDetail {
    code: Option<String>,
    message: String,
}

impl AwsErrorDetail {
    /// AWS error code.
    pub fn code(&self) -> Option<&str> {
        self.code.as_deref()
    }
    /// Redacted, truncated vendor message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for AwsErrorDetail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.code {
            Some(code) if self.message.is_empty() => f.write_str(code),
            Some(code) => write!(f, "{code}: {}", self.message),
            None => f.write_str(&self.message),
        }
    }
}

impl StdError for AwsErrorDetail {}

/// Mapping options.
#[derive(Debug, Clone, Default)]
pub(crate) struct MapOptions {
    pub known_secrets: Vec<String>,
    pub unsupported_on_html_500: bool,
}

impl MapOptions {
    pub(crate) fn for_op(known_secrets: &[String], operation: &str) -> Self {
        let base = operation.split(' ').next().unwrap_or_default();
        MapOptions {
            known_secrets: known_secrets.to_vec(),
            unsupported_on_html_500: EMULATOR_GAPS.contains(&base),
        }
    }

    fn clean(&self, text: &str) -> String {
        let collapsed = text.split_whitespace().collect::<Vec<_>>().join(" ");
        truncate(
            &redact_text(&collapsed, &self.known_secrets),
            MAX_VENDOR_MESSAGE,
        )
    }
}

/// What is known about an HTTP error response.
#[derive(Debug, Default)]
pub(crate) struct ResponseParts<'a> {
    pub status: u16,
    /// Code parsed by the SDK (or from the `x-amzn-errortype` header).
    pub aws_code: Option<String>,
    /// Vendor message parsed by the SDK.
    pub message: Option<String>,
    pub body: Option<&'a [u8]>,
    pub request_id: Option<String>,
    pub retry_after: Option<String>,
}

impl<'a> ResponseParts<'a> {
    /// Parts of a raw response (code from the `x-amzn-errortype` header or the body).
    pub(crate) fn from_response(resp: &'a HttpResponse) -> Self {
        let headers = resp.headers();
        ResponseParts {
            status: resp.status().as_u16(),
            aws_code: headers.get("x-amzn-errortype").and_then(clean_code),
            message: None,
            body: resp.body().bytes(),
            request_id: request_id_of(resp),
            retry_after: headers.get("retry-after").map(str::to_owned),
        }
    }
}

/// The request id header of a response (`x-amzn-requestid`, `x-amz-request-id`).
pub(crate) fn request_id_of(resp: &HttpResponse) -> Option<String> {
    ["x-amzn-requestid", "x-amz-request-id", "x-amz-id-2"]
        .iter()
        .find_map(|h| resp.headers().get(*h))
        .map(str::to_owned)
}

/// Maps an HTTP error response.
pub(crate) fn map_response(operation: &str, parts: ResponseParts<'_>, opts: &MapOptions) -> Error {
    let status = parts.status;
    let body_text = parts
        .body
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .unwrap_or_default();
    let aws_code = parts
        .aws_code
        .clone()
        .or_else(|| error_code_from_body(&body_text));
    let code = aws_code
        .as_deref()
        .and_then(error_code_for_aws)
        .unwrap_or_else(|| {
            if status == 403 {
                let lower = body_text.to_ascii_lowercase();
                if body_text.contains("InvalidClientTokenId")
                    || body_text.contains("SignatureDoesNotMatch")
                    || lower.contains("security token")
                {
                    ErrorCode::Authentication
                } else {
                    ErrorCode::PermissionDenied
                }
            } else if status == 500
                && opts.unsupported_on_html_500
                && body_text.to_ascii_lowercase().contains("<html")
            {
                ErrorCode::Unsupported
            } else {
                ErrorCode::from_http_status(status).unwrap_or(ErrorCode::Unavailable)
            }
        });
    let vendor = parts
        .message
        .as_deref()
        .map(|m| opts.clean(m))
        .unwrap_or_default();
    let reason = match &aws_code {
        None => code.reason().to_owned(),
        Some(c) if vendor.is_empty() => c.clone(),
        Some(c) => format!("{c}: {vendor}"),
    };
    let mut err = Error::new(code, format!("{operation}: {reason} (HTTP {status})"))
        .with_status(status)
        .with_source(AwsErrorDetail {
            code: aws_code,
            message: vendor,
        });
    if let Some(id) = parts.request_id {
        err = err.with_request_id(id);
    }
    if code == ErrorCode::RateLimited {
        if let Some(wait) = parts
            .retry_after
            .as_deref()
            .and_then(|v| parse_retry_after(v, SystemTime::now()))
        {
            err = err.with_retry_after(wait);
        }
    }
    err
}

/// Display of an error and its sources, `: `-joined.
fn chain_text(err: &(dyn StdError + 'static)) -> String {
    let mut parts = vec![err.to_string()];
    let mut current = err.source();
    while let Some(e) = current {
        let text = e.to_string();
        if !parts.iter().any(|p| p.contains(&text)) {
            parts.push(text);
        }
        current = e.source();
    }
    parts.join(": ")
}

fn has_credentials_error(err: &(dyn StdError + 'static)) -> bool {
    let mut current = Some(err);
    while let Some(e) = current {
        if e.is::<aws_credential_types::provider::error::CredentialsError>() {
            return true;
        }
        current = e.source();
    }
    false
}

/// Maps a failure without an HTTP response (connector, timeout, construction).
fn map_transport_failure(
    operation: &str,
    err: &(dyn StdError + 'static),
    opts: &MapOptions,
    default: ErrorCode,
) -> Error {
    let text = opts.clean(&chain_text(err));
    let lower = text.to_ascii_lowercase();
    let code = if has_credentials_error(err) || lower.contains("credentials") {
        ErrorCode::Authentication
    } else if lower.contains("missing region") || lower.contains("region must be set") {
        ErrorCode::Config
    } else {
        default
    };
    let message = match code {
        ErrorCode::Authentication => {
            format!("{operation}: no usable AWS credentials: {text}")
        }
        ErrorCode::Config => {
            format!("{operation}: no AWS region configured (set region or AWS_REGION): {text}")
        }
        _ => format!("{operation}: {}: {text}", code.reason()),
    };
    Error::new(code, message).with_source(AwsErrorDetail {
        code: None,
        message: text,
    })
}

/// Converts anything the AWS SDK returns into an SDK [`Error`] with the message
/// `"<operation>: <AwsCode>: <redacted vendor text> (HTTP <status>)"`.
pub(crate) fn map_sdk_error<E>(
    operation: &str,
    err: SdkError<E, HttpResponse>,
    opts: &MapOptions,
) -> Error
where
    E: ProvideErrorMetadata + StdError + Send + Sync + 'static,
{
    match &err {
        SdkError::ServiceError(ctx) => {
            let raw = ctx.raw();
            let mut parts = ResponseParts::from_response(raw);
            if let Some(code) = ctx.err().code() {
                parts.aws_code = Some(code.to_owned());
                parts.message = ctx.err().message().map(str::to_owned);
            }
            if let Some(id) = ctx.err().meta().extra("aws_request_id") {
                parts.request_id.get_or_insert_with(|| id.to_owned());
            }
            map_response(operation, parts, opts)
        }
        SdkError::ResponseError(ctx) => {
            let raw = ctx.raw();
            if raw.status().is_success() {
                // A 200 whose body could not be parsed.
                let text = opts.clean(&chain_text(&err));
                return Error::unavailable(format!(
                    "{operation}: invalid response from the service: {text}"
                ))
                .with_status(raw.status().as_u16());
            }
            map_response(operation, ResponseParts::from_response(raw), opts)
        }
        SdkError::TimeoutError(_) => Error::timeout(format!("{operation}: timed out")),
        SdkError::DispatchFailure(d) => {
            if d.is_timeout() {
                Error::timeout(format!("{operation}: timed out"))
            } else if d.is_user() {
                Error::cancelled(format!("{operation}: cancelled"))
            } else {
                map_transport_failure(operation, &err, opts, ErrorCode::Unavailable)
            }
        }
        _ => map_transport_failure(operation, &err, opts, ErrorCode::Validation),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_from_bodies() {
        assert_eq!(
            error_code_from_body("<Error><Code> AccessDenied </Code></Error>").as_deref(),
            Some("AccessDenied")
        );
        assert_eq!(
            error_code_from_body(
                r#"{"__type":"com.amazonaws.secretsmanager#ResourceNotFoundException"}"#
            )
            .as_deref(),
            Some("ResourceNotFoundException")
        );
        assert_eq!(
            error_code_from_body(r#"{"code":"Throttling:http://x"}"#).as_deref(),
            Some("Throttling")
        );
        assert_eq!(error_code_from_body("<Code></Code>"), None);
        assert_eq!(error_code_from_body("not json"), None);
        assert_eq!(error_code_from_body(r#"{"__type":""}"#), None);
        assert_eq!(error_code_for_aws("Nope"), None);
    }

    #[test]
    fn detail_display() {
        let d = AwsErrorDetail {
            code: Some("X".into()),
            message: String::new(),
        };
        assert_eq!(d.to_string(), "X");
        assert_eq!(d.code(), Some("X"));
        assert_eq!(d.message(), "");
        let d = AwsErrorDetail {
            code: Some("X".into()),
            message: "m".into(),
        };
        assert_eq!(d.to_string(), "X: m");
        let d = AwsErrorDetail {
            code: None,
            message: "m".into(),
        };
        assert_eq!(d.to_string(), "m");
    }

    #[test]
    fn response_mapping_rules() {
        let opts = MapOptions {
            known_secrets: vec!["topsecretvalue".into()],
            unsupported_on_html_500: true,
        };
        let e = map_response(
            "op",
            ResponseParts {
                status: 500,
                body: Some(b"<html>oops</html>"),
                ..Default::default()
            },
            &opts,
        );
        assert_eq!(e.code(), ErrorCode::Unsupported);
        assert!(!e.is_retryable());
        let e = map_response(
            "op",
            ResponseParts {
                status: 403,
                body: Some(b"<x>The security token is bad</x>"),
                ..Default::default()
            },
            &opts,
        );
        assert_eq!(e.code(), ErrorCode::Authentication);
        let e = map_response(
            "op",
            ResponseParts {
                status: 403,
                body: Some(b"nope"),
                ..Default::default()
            },
            &opts,
        );
        assert_eq!(e.code(), ErrorCode::PermissionDenied);
        let e = map_response(
            "op",
            ResponseParts {
                status: 400,
                aws_code: Some("ThrottlingException".into()),
                message: Some("slow   down topsecretvalue".into()),
                retry_after: Some("2".into()),
                request_id: Some("rid".into()),
                ..Default::default()
            },
            &opts,
        );
        assert_eq!(e.code(), ErrorCode::RateLimited);
        assert!(e.is_retryable());
        assert_eq!(e.retry_after(), Some(std::time::Duration::from_secs(2)));
        assert_eq!(e.request_id(), Some("rid"));
        assert_eq!(
            e.message(),
            "op: ThrottlingException: slow down [REDACTED] (HTTP 400)"
        );
        assert_eq!(aws_error_code(&e), Some("ThrottlingException"));
        let e = map_response(
            "op",
            ResponseParts {
                status: 418,
                ..Default::default()
            },
            &opts,
        );
        assert_eq!(e.code(), ErrorCode::Validation);
        assert_eq!(e.message(), "op: invalid request (HTTP 418)");
        assert_eq!(aws_error_code(&e), None);
        let e = map_response(
            "op",
            ResponseParts {
                status: 302,
                ..Default::default()
            },
            &opts,
        );
        assert_eq!(e.code(), ErrorCode::Unavailable);
    }

    #[derive(Debug)]
    struct Wrapper(Box<dyn StdError + Send + Sync>);
    impl fmt::Display for Wrapper {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("dispatch failure")
        }
    }
    impl StdError for Wrapper {
        fn source(&self) -> Option<&(dyn StdError + 'static)> {
            Some(self.0.as_ref())
        }
    }

    #[test]
    fn transport_failures() {
        let opts = MapOptions::default();
        let creds = Wrapper(Box::new(
            aws_credential_types::provider::error::CredentialsError::not_loaded("none"),
        ));
        let e = map_transport_failure("op", &creds, &opts, ErrorCode::Unavailable);
        assert_eq!(e.code(), ErrorCode::Authentication);
        let region = Wrapper(Box::new(std::io::Error::other(
            "Invalid Configuration: Missing Region",
        )));
        let e = map_transport_failure("op", &region, &opts, ErrorCode::Unavailable);
        assert_eq!(e.code(), ErrorCode::Config);
        let io = Wrapper(Box::new(std::io::Error::other("connection refused")));
        let e = map_transport_failure("op", &io, &opts, ErrorCode::Unavailable);
        assert_eq!(e.code(), ErrorCode::Unavailable);
        assert!(
            e.message().contains("connection refused"),
            "{}",
            e.message()
        );
        assert!(MapOptions::for_op(&[], "validateResourcePolicy").unsupported_on_html_500);
        assert!(!MapOptions::for_op(&[], "getSecretValue x").unsupported_on_html_500);
    }
}
