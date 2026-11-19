"""The async client (aioboto3, extra ``async``) and the async SecretsProvider; cancelling the
task raises the SDK's CancelledError."""

from __future__ import annotations

import asyncio
import secrets

import grow_aws_secrets_manager as sdk


async def main() -> None:
    async with sdk.AsyncAwsSecretsManagerClient.from_env() as client:
        print(f"health: {await client.health()}")
        provider = client.secrets()
        base = f"grow-sdk-example/{secrets.token_hex(4)}"
        try:
            await provider.set("api-key", "k-123", path=base, tags={"grow:purpose": "sdk-example"})
            await provider.set("feature-flag", "true", path=base)
            print(f"flag = {await provider.get_bool('feature-flag', path=base)}")
            values = await provider.get_all(base)
            print(f"secrets under {base}: {sorted(values)}")
            task = asyncio.ensure_future(client.get_secret_value(f"{base}/api-key"))
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                print("cancelled")
        finally:
            for meta in await provider.list(f"{base}/"):
                await provider.delete(meta.name, permanent=True)


if __name__ == "__main__":
    asyncio.run(main())
