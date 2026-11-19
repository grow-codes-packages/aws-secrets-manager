"""AWS Secrets Manager with the sync client: configuration from the standard AWS environment,
health/ping, create → read → new version → JSON field → stages, random password, errors."""

from __future__ import annotations

import secrets

import grow_aws_secrets_manager as sdk


def main() -> None:
    # GROW_AWS_SECRETS_MANAGER_* first, then AWS_REGION / AWS_PROFILE / AWS_ACCESS_KEY_ID …
    with sdk.AwsSecretsManagerClient.from_env() as client:
        print(f"config: {client.config}")  # credentials print as [REDACTED]
        print(f"health: {client.health()}")  # never raises for an unreachable service
        print(f"ping: {client.ping():.1f} ms")
        name = f"grow-sdk-example/{secrets.token_hex(4)}/db"
        try:
            password = client.get_random_password(length=24, exclude_punctuation=True)
            created = client.create_secret(
                name,
                {"username": "app", "password": password.reveal(), "port": 5432},
                description="Grow SDK example",
                tags={"grow:purpose": "sdk-example"},
            )
            print(f"created {created.name} version {created.version_id}")
            print(f"port = {client.get_json_field(name, 'port')}")
            client.put_secret_value(name, {"username": "app", "password": "rotated", "port": 5433})
            previous = client.get_secret_value(name, version_stage=sdk.AWSPREVIOUS)
            print(f"previous version {previous.version_id}: {previous.value}")  # redacted
            for version in client.list_secret_version_ids(name):
                print(f"  {version.version_id} {list(version.version_stages)}")
            meta = client.describe_secret(name)
            print(f"tags={dict(meta.tags)} current={meta.version_id_for_stage()}")
        except sdk.NotFoundError as err:
            print(f"not found: {err}")
        except sdk.AwsSecretsManagerError as err:
            code = sdk.aws_error_code(err)
            print(f"failed with {err.code} ({code}): {err} (retryable={err.retryable})")
        finally:
            client.delete_secret(name, force_delete_without_recovery=True)


if __name__ == "__main__":
    main()
