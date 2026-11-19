//! `AwsSecretsManagerConfig`: AWS fields, validation and environment precedence.

use std::time::Duration;

use grow_aws_secrets_manager as sdk;
use sdk::core::EnvReader;
use sdk::{AwsSecretsManagerConfig as Config, ErrorCode};

fn env(pairs: &[(&str, &str)]) -> EnvReader {
    EnvReader::from_map(
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned())),
    )
}

fn fake_sdk_client() -> sdk::aws_sdk_secretsmanager::Client {
    let conf = sdk::aws_sdk_secretsmanager::Config::builder()
        .behavior_version(sdk::aws_sdk_secretsmanager::config::BehaviorVersion::latest())
        .region(sdk::aws_sdk_secretsmanager::config::Region::new(
            "us-east-1",
        ))
        .build();
    sdk::aws_sdk_secretsmanager::Client::from_conf(conf)
}

#[test]
fn defaults_and_accessors() {
    let c = Config::builder().build().unwrap();
    assert_eq!(
        c.url().as_str(),
        "https://secretsmanager.us-east-1.amazonaws.com/"
    );
    assert!(c.endpoint().is_none());
    assert!(c.region().is_none());
    assert_eq!(c.recovery_window_days(), 30);
    assert_eq!(c.role_session_name(), "grow-sdk");
    assert!(c.known_secrets().is_empty());

    let c = Config::builder()
        .url("http://localhost:5000")
        .region("eu-central-1")
        .access_key_id("AKID")
        .secret_access_key("secret-key-1")
        .session_token("session-1")
        .profile("p")
        .role_arn("arn:aws:iam::1:role/r")
        .role_session_name("s")
        .external_id("ext-1")
        .role_duration(Duration::from_secs(3600))
        .recovery_window_days(7)
        .connect_timeout(Duration::from_secs(1))
        .request_timeout(Duration::from_secs(2))
        .total_timeout(Duration::from_secs(3))
        .max_retries(1)
        .build()
        .unwrap();
    assert_eq!(c.endpoint().unwrap().as_str(), "http://localhost:5000/");
    assert_eq!(c.region(), Some("eu-central-1"));
    assert_eq!(c.access_key_id(), Some("AKID"));
    assert_eq!(
        c.secret_access_key().unwrap().expose_secret(),
        "secret-key-1"
    );
    assert_eq!(c.session_token().unwrap().expose_secret(), "session-1");
    assert_eq!(c.profile(), Some("p"));
    assert_eq!(c.role_arn(), Some("arn:aws:iam::1:role/r"));
    assert_eq!(c.role_session_name(), "s");
    assert_eq!(c.external_id().unwrap().expose_secret(), "ext-1");
    assert_eq!(c.role_duration(), Some(Duration::from_secs(3600)));
    assert_eq!(c.recovery_window_days(), 7);
    assert!(c.credentials().is_none() && c.sdk_client().is_none());
    assert_eq!(c.known_secrets().len(), 3);
    let text = format!("{c:?}");
    for secret in ["secret-key-1", "session-1", "ext-1"] {
        assert!(!text.contains(secret), "{secret} leaked: {text}");
    }
    assert!(text.contains("AKID"));
    let region_only = Config::builder().region("ap-south-1").build().unwrap();
    assert_eq!(
        region_only.url().as_str(),
        "https://secretsmanager.ap-south-1.amazonaws.com/"
    );
    // blank values count as unset
    let blank = Config::builder()
        .region(" ")
        .profile("")
        .secret_access_key("")
        .build()
        .unwrap();
    assert!(
        blank.region().is_none()
            && blank.profile().is_none()
            && blank.secret_access_key().is_none()
    );
}

#[test]
fn validation_rules() {
    let cases: Vec<(sdk::AwsSecretsManagerConfigBuilder, &str)> = vec![
        (Config::builder().region("US_EAST"), "region must look like"),
        (
            Config::builder().access_key_id("A"),
            "accessKeyId requires secretAccessKey",
        ),
        (
            Config::builder().secret_access_key("s"),
            "secretAccessKey requires accessKeyId",
        ),
        (
            Config::builder().session_token("t"),
            "sessionToken requires",
        ),
        (Config::builder().role_arn("role"), "roleArn must be an ARN"),
        (
            Config::builder().role_duration(Duration::from_secs(60)),
            "roleDuration",
        ),
        (
            Config::builder().recovery_window_days(31),
            "recoveryWindowDays",
        ),
        (Config::builder().url("ftp://x"), "scheme"),
        (
            Config::builder()
                .access_key_id("A")
                .secret_access_key("s")
                .credentials_provider(sdk::aws_sdk_secretsmanager::config::Credentials::new(
                    "a", "b", None, None, "t",
                )),
            "mutually exclusive",
        ),
        (
            Config::builder()
                .sdk_client(fake_sdk_client())
                .profile("p")
                .role_arn("arn:x"),
            "profile, roleArn",
        ),
    ];
    for (b, needle) in cases {
        let err = b.build().unwrap_err();
        assert_eq!(err.code(), ErrorCode::Config);
        assert!(
            err.message().contains(needle),
            "{needle}: {}",
            err.message()
        );
    }
    let c = Config::builder()
        .credentials_provider(sdk::aws_sdk_secretsmanager::config::Credentials::new(
            "a", "b", None, None, "t",
        ))
        .build()
        .unwrap();
    assert!(c.credentials().is_some());
    assert!(format!("{c:?}").contains("[REDACTED]"));
}

#[test]
fn env_precedence() {
    // GROW_* > AWS_*; explicit > env
    let e = env(&[
        ("GROW_AWS_SECRETS_MANAGER_URL", "http://grow:1"),
        ("AWS_ENDPOINT_URL_SECRETS_MANAGER", "http://svc:2"),
        ("AWS_ENDPOINT_URL", "http://all:3"),
        ("GROW_AWS_SECRETS_MANAGER_REGION", "eu-west-1"),
        ("AWS_REGION", "us-west-2"),
        ("AWS_PROFILE", "vendor-profile"),
        ("GROW_AWS_SECRETS_MANAGER_ROLE_ARN", "arn:aws:iam::1:role/r"),
        ("GROW_AWS_SECRETS_MANAGER_ROLE_SESSION_NAME", "sess"),
        ("GROW_AWS_SECRETS_MANAGER_EXTERNAL_ID", "ext"),
        ("GROW_AWS_SECRETS_MANAGER_RECOVERY_WINDOW_DAYS", "10"),
        ("AWS_ACCESS_KEY_ID", "AKIDAWS"),
        ("AWS_SECRET_ACCESS_KEY", "aws-secret"),
        ("AWS_SESSION_TOKEN", "aws-session"),
    ]);
    let c = Config::builder().build_with_env(&e).unwrap();
    assert_eq!(c.endpoint().unwrap().as_str(), "http://grow:1/");
    assert_eq!(c.region(), Some("eu-west-1"));
    assert_eq!(c.profile(), Some("vendor-profile"));
    assert_eq!(c.role_arn(), Some("arn:aws:iam::1:role/r"));
    assert_eq!(c.role_session_name(), "sess");
    assert_eq!(c.external_id().unwrap().expose_secret(), "ext");
    assert_eq!(c.recovery_window_days(), 10);
    assert_eq!(c.access_key_id(), Some("AKIDAWS"));
    assert_eq!(c.session_token().unwrap().expose_secret(), "aws-session");

    let c = Config::builder()
        .url("http://explicit:9")
        .region("ap-south-1")
        .profile("explicit")
        .role_arn("arn:aws:iam::2:role/x")
        .role_session_name("mine")
        .external_id("mine-ext")
        .recovery_window_days(20)
        .access_key_id("AKIDEXPLICIT")
        .secret_access_key("explicit-secret")
        .build_with_env(&e)
        .unwrap();
    assert_eq!(c.endpoint().unwrap().as_str(), "http://explicit:9/");
    assert_eq!(c.region(), Some("ap-south-1"));
    assert_eq!(c.recovery_window_days(), 20);
    assert_eq!(c.access_key_id(), Some("AKIDEXPLICIT"));
    assert!(
        c.session_token().is_none(),
        "explicit keys never mix with env tokens"
    );

    // vendor fallbacks in order
    let c = Config::builder()
        .build_with_env(&env(&[
            ("AWS_ENDPOINT_URL", "http://all:3"),
            ("AWS_DEFAULT_REGION", "sa-east-1"),
        ]))
        .unwrap();
    assert_eq!(c.endpoint().unwrap().as_str(), "http://all:3/");
    assert_eq!(c.region(), Some("sa-east-1"));

    // GROW credentials are one set
    let c = Config::builder()
        .build_with_env(&env(&[
            ("GROW_AWS_SECRETS_MANAGER_ACCESS_KEY_ID", "AKIDGROW"),
            ("GROW_AWS_SECRETS_MANAGER_SECRET_ACCESS_KEY", "grow-secret"),
            ("GROW_AWS_SECRETS_MANAGER_SESSION_TOKEN", "grow-session"),
            ("AWS_ACCESS_KEY_ID", "AKIDAWS"),
            ("AWS_SECRET_ACCESS_KEY", "aws-secret"),
        ]))
        .unwrap();
    assert_eq!(c.access_key_id(), Some("AKIDGROW"));
    assert_eq!(
        c.secret_access_key().unwrap().expose_secret(),
        "grow-secret"
    );
    assert_eq!(c.session_token().unwrap().expose_secret(), "grow-session");

    // an explicit SDK client ignores the AWS settings of the environment
    let c = Config::builder()
        .sdk_client(fake_sdk_client())
        .build_with_env(&e)
        .unwrap();
    assert!(c.region().is_none() && c.endpoint().is_none() && c.access_key_id().is_none());
    assert_eq!(c.recovery_window_days(), 10);

    // invalid values name the variable, never the value
    for (k, v) in [
        ("GROW_AWS_SECRETS_MANAGER_RECOVERY_WINDOW_DAYS", "abc"),
        ("GROW_AWS_SECRETS_MANAGER_RECOVERY_WINDOW_DAYS", "-3"),
        ("GROW_AWS_SECRETS_MANAGER_REQUEST_TIMEOUT", "soon"),
    ] {
        let err = Config::builder()
            .build_with_env(&env(&[(k, v)]))
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Config);
        assert!(err.message().contains(k), "{}", err.message());
        assert!(!err.message().contains(v), "{}", err.message());
    }
}
