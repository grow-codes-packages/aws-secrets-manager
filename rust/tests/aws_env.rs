//! Behaviour that depends on the process environment (own test binary, one test, so setting
//! variables cannot race other tests): missing region, shared config profiles, the assume-role
//! helper against a mocked STS endpoint, and `from_env`.

mod support;

use grow_aws_secrets_manager as sdk;
use sdk::{AwsSecretsManagerClient as Client, AwsSecretsManagerConfig as Config, ErrorCode};
use support::*;
use wiremock::matchers::{body_string_contains, header};
use wiremock::{Mock, MockServer, ResponseTemplate};

const STS_OK: &str = r#"<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <Credentials>
      <AccessKeyId>ASIAASSUMEDKEY</AccessKeyId>
      <SecretAccessKey>assumed-secret-key-1</SecretAccessKey>
      <SessionToken>assumed-session-token-1</SessionToken>
      <Expiration>2099-01-01T00:00:00Z</Expiration>
    </Credentials>
    <AssumedRoleUser>
      <AssumedRoleId>AROAEXAMPLE:grow-sdk</AssumedRoleId>
      <Arn>arn:aws:sts::123456789012:assumed-role/reader/grow-sdk</Arn>
    </AssumedRoleUser>
  </AssumeRoleResult>
  <ResponseMetadata><RequestId>sts-1</RequestId></ResponseMetadata>
</AssumeRoleResponse>"#;

fn authorization_of(req: &wiremock::Request) -> String {
    req.headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned()
}

#[tokio::test]
async fn environment_dependent_behaviour() {
    let dir = std::env::temp_dir().join(format!("grow-asm-env-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let config_file = dir.join("config");
    let credentials_file = dir.join("credentials");
    std::fs::write(&config_file, "[profile grow-test]\nregion = eu-west-1\n").unwrap();
    std::fs::write(
        &credentials_file,
        "[grow-test]\naws_access_key_id = AKIDPROFILE\naws_secret_access_key = profile-secret-1\n",
    )
    .unwrap();
    for (k, v) in [
        ("AWS_EC2_METADATA_DISABLED", "true"),
        ("AWS_CONFIG_FILE", config_file.to_str().unwrap()),
        (
            "AWS_SHARED_CREDENTIALS_FILE",
            credentials_file.to_str().unwrap(),
        ),
    ] {
        std::env::set_var(k, v);
    }
    for k in [
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
        "AWS_PROFILE",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_ENDPOINT_URL",
        "AWS_ENDPOINT_URL_SECRETS_MANAGER",
    ] {
        std::env::remove_var(k);
    }

    let server = MockServer::start().await;
    Mock::given(body_string_contains("Action=AssumeRole"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(STS_OK, "text/xml"))
        .mount(&server)
        .await;
    Mock::given(header("x-amz-target", "secretsmanager.ListSecrets"))
        .respond_with(replay(&fixture("ping.ok")))
        .mount(&server)
        .await;

    // 1. no region anywhere → CONFIG on the first call
    let c = Client::new(
        Config::builder()
            .url(server.uri())
            .access_key_id(ACCESS_KEY)
            .secret_access_key(SECRET_KEY)
            .build()
            .unwrap(),
    )
    .unwrap();
    let err = c.ping().await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Config, "{err}");
    assert!(err.message().contains("region"));
    assert_eq!(c.health().await.unwrap_err().code(), ErrorCode::Config);
    assert_eq!(c.sdk().await.unwrap_err().code(), ErrorCode::Config);

    // 2. a shared config profile gives region and credentials
    let c = Client::new(
        Config::builder()
            .url(server.uri())
            .profile("grow-test")
            .build()
            .unwrap(),
    )
    .unwrap();
    c.ping().await.unwrap();
    let reqs = server.received_requests().await.unwrap();
    let auth = authorization_of(reqs.last().unwrap());
    assert!(auth.contains("AKIDPROFILE/"), "{auth}");
    assert!(auth.contains("/eu-west-1/secretsmanager/"), "{auth}");

    // 3. assume-role helper: STS at AWS_ENDPOINT_URL_STS, assumed keys sign the call
    std::env::set_var("AWS_ENDPOINT_URL_STS", server.uri());
    let c = Client::new(
        builder(&server.uri())
            .role_arn("arn:aws:iam::123456789012:role/reader")
            .external_id("ext-id-1")
            .role_duration(std::time::Duration::from_secs(900))
            .build()
            .unwrap(),
    )
    .unwrap();
    c.ping().await.unwrap();
    let reqs = server.received_requests().await.unwrap();
    let sts = reqs
        .iter()
        .find(|r| String::from_utf8_lossy(&r.body).contains("Action=AssumeRole"))
        .expect("STS was called");
    let form = String::from_utf8_lossy(&sts.body).into_owned();
    assert!(form.contains("RoleSessionName=grow-sdk"), "{form}");
    assert!(form.contains("ExternalId=ext-id-1"), "{form}");
    assert!(form.contains("DurationSeconds=900"), "{form}");
    assert!(authorization_of(sts).contains(&format!("{ACCESS_KEY}/")));
    let last = authorization_of(reqs.last().unwrap());
    assert!(last.contains("ASIAASSUMEDKEY/"), "{last}");

    // 4. from_env: GROW_* over AWS_*, credentials as one set
    std::env::set_var("GROW_AWS_SECRETS_MANAGER_URL", server.uri());
    std::env::set_var("AWS_REGION", "us-east-1");
    std::env::set_var("AWS_ACCESS_KEY_ID", ACCESS_KEY);
    std::env::set_var("AWS_SECRET_ACCESS_KEY", SECRET_KEY);
    let c = Client::from_env().unwrap();
    assert_eq!(c.config().region(), Some("us-east-1"));
    assert_eq!(c.config().access_key_id(), Some(ACCESS_KEY));
    c.ping().await.unwrap();
    std::env::set_var("GROW_AWS_SECRETS_MANAGER_ACCESS_KEY_ID", "AKIDGROWONLY");
    let err = Config::from_env().unwrap_err();
    assert_eq!(
        err.code(),
        ErrorCode::Config,
        "GROW key never pairs with AWS secret"
    );
    assert!(err
        .message()
        .contains("accessKeyId requires secretAccessKey"));

    std::fs::remove_dir_all(&dir).unwrap();
}
