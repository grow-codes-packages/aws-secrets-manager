"""SecretsProvider helpers (typed getters, get_many, load_env, watch) and the version-stage
aware AwsSecretCache (AWS caching-client semantics: TTL 1 h, 1024 entries)."""

from __future__ import annotations

import secrets
import time

import grow_aws_secrets_manager as sdk


def main() -> None:
    with sdk.AwsSecretsManagerClient.from_env() as client:
        provider = client.secrets()
        base = f"grow-sdk-example/{secrets.token_hex(4)}"
        try:
            provider.set(f"{base}/db-user", "app")
            provider.set(f"{base}/db-port", "5432")
            print(f"port = {provider.get_number(f'{base}/db-port')}")
            print(f"many = {sorted(provider.get_many([f'{base}/db-user', f'{base}/none']))}")
            exported = provider.load_env(base, prefix="APP_", environ={})
            print(f"load_env would set {sorted(exported)}")

            cache = client.secret_cache(**sdk.AwsSecretCache.aws_defaults())
            print(f"cached user = {cache.get_secret_string(f'{base}/db-user')}")
            provider.set(f"{base}/db-user", "app2")
            print(f"still cached = {cache.get_secret_string(f'{base}/db-user')}")
            print(f"after refresh = {cache.refresh_now(f'{base}/db-user').value.reveal()}")
            print(f"stats = {cache.stats()}")

            handle = provider.watch(
                f"{base}/db-port", 1.0, lambda new, old: print(f"changed: {old} -> {new}")
            )
            time.sleep(1.5)
            provider.set(f"{base}/db-port", "5433")
            time.sleep(2.5)
            handle.stop()
        finally:
            for meta in provider.list(f"{base}/"):
                provider.delete(meta.name, permanent=True)


if __name__ == "__main__":
    main()
