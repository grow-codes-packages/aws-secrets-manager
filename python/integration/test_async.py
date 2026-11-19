"""The async client (aioboto3) against the real service: every async method once, with
round-trip assertions, plus the async provider and cache. Cancellation maps to the SDK's
CancelledError."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from factories import async_core_client

import grow_aws_secrets_manager as sdk
from conftest import uid


def run(coro: Any) -> Any:
    return asyncio.run(coro)


def test_async_core(env: dict[str, str]) -> None:
    async def body() -> None:
        async with async_core_client(env) as c:
            assert await c.health() == sdk.HealthStatus(True, "ok", {})
            assert await c.ping() >= 0
            with pytest.raises(sdk.UnsupportedError):
                await c.server_version()
        assert c.closed
        await c.aclose()
        with pytest.raises(sdk.ConfigError):
            await c.ping()
        async with async_core_client(
            env,
            access_key_id="AKIAUNKNOWNKEY000000",
            secret_access_key="wrong-secret-for-integration-0123456789",  # noqa: S106 - deliberately wrong
            retry=sdk.RetryPolicy(max_retries=0),
        ) as bad:
            with pytest.raises(sdk.AuthenticationError):
                await bad.ping()
            assert (await bad.health()).details.get("auth") == "failed"

    run(body())


def test_async_operations_round_trip(env: dict[str, str], is_moto: bool) -> None:
    base = uid("pya")

    async def body() -> None:
        async with async_core_client(env) as c:
            s = f"{base}/one"
            created = await c.create_secret(s, "v1", description="async", tags={"k": "v"})
            assert created.version_id
            assert (await c.get_secret_value(s)).value.reveal() == "v1"
            put = await c.put_secret_value(s, {"db": {"host": "h"}})
            assert await c.get_json_field(s, "db.host", version_stage="AWSCURRENT") == "h"
            await c.update_secret(s, description="changed")
            d = await c.describe_secret(s)
            assert d.description == "changed"
            assert d.version_id_for_stage("AWSCURRENT") == put.version_id
            prev = d.version_id_for_stage("AWSPREVIOUS")
            await c.update_secret_version_stage(
                s, "AWSCURRENT", move_to_version_id=prev, remove_from_version_id=put.version_id
            )
            current = await c.get_secret_value(s, version_stage="AWSCURRENT")
            assert current.value.reveal() == "v1"
            versions = await c.list_secret_version_ids(s, include_deprecated=True).to_list()
            assert {v.version_id for v in versions} == {created.version_id, put.version_id}
            await c.tag_resource(s, {"extra": "1"})
            await c.untag_resource(s, ["k"])
            assert dict((await c.describe_secret(s)).tags) == {"extra": "1"}
            policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{env['GROW_TEST_ACCOUNT_ID']}:root"},
                        "Action": "secretsmanager:GetSecretValue",
                        "Resource": "*",
                    }
                ],
            }
            await c.put_resource_policy(s, policy)
            assert (await c.get_resource_policy(s)).policy == policy
            await c.delete_resource_policy(s)
            assert (await c.get_resource_policy(s)).resource_policy is None
            if is_moto:
                with pytest.raises(sdk.UnsupportedError):
                    await c.validate_resource_policy(policy)
            two = f"{base}/two"
            await c.create_secret(two, b"\x00\xff")
            batch = await c.batch_get_secret_value([two, s])
            assert [v.name for v in batch.secret_values] == [two, s]
            filtered = await c.batch_get_secret_value(
                filters=[sdk.SecretFilter("name", [f"{base}/"])]
            )
            assert len(filtered.secret_values) == 2
            listed = [
                x.name
                async for x in c.list_secrets(filters=[sdk.SecretFilter("name", [f"{base}/"])])
            ]
            assert sorted(listed) == [s, two]
            if is_moto:
                rotated = await c.rotate_secret(
                    s, rules=sdk.RotationRules(automatically_after_days=7)
                )
                assert rotated.version_id
                assert (await c.describe_secret(s)).rotation_enabled
                # Moto keeps the Lambda ARN although it has no such function (API.md section 7);
                # cancelling needs one configured.
                with pytest.raises(sdk.NotFoundError):
                    await c.rotate_secret(
                        s, lambda_arn="arn:aws:lambda:us-east-1:123456789012:function:grow-rotate"
                    )
                await c.cancel_rotate_secret(s)
                assert not (await c.describe_secret(s)).rotation_enabled
            password = await c.get_random_password(length=20, exclude_punctuation=True)
            assert len(password.reveal()) == 20
            cache = c.secret_cache()
            assert await cache.get_secret_binary(two) == b"\x00\xff"
            assert (await cache.refresh_now(two)).binary
            assert await cache.get_secret_string(s) == "v1"
            p = c.secrets()
            three, four = f"{base}/sub/three", f"{base}/sub/four"
            version = await p.set(three, "p1")
            await p.set(four, "p2")
            assert (await p.get(three)).version == version  # type: ignore[union-attr]
            # (a separate path: Moto fails a whole BatchGetSecretValue for a secret whose
            # AWSCURRENT label was moved, instead of reporting it per secret)
            assert sorted(await p.get_all(f"{base}/sub")) == [four, three]
            deleted = await c.delete_secret(s, recovery_window_days=7)
            assert deleted.deletion_date is not None
            await c.restore_secret(s)
            for name in (s, two, three, four):
                await c.delete_secret(name, force_delete_without_recovery=True)
            with pytest.raises(sdk.NotFoundError):
                await c.describe_secret(s)

    run(body())


def test_async_cancellation(env: dict[str, str]) -> None:
    async def body() -> None:
        async with async_core_client(env) as c:
            await c.ping()  # build the client first
            task = asyncio.ensure_future(c.get_random_password())
            await asyncio.sleep(0)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

    run(body())
