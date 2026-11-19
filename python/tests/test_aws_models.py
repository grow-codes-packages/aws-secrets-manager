"""Model converters and the paginators."""

from __future__ import annotations

import datetime as dt

import grow_aws_secrets_manager as sdk
from grow_aws_secrets_manager import models


def test_utc_and_tags() -> None:
    naive = dt.datetime(2026, 1, 1, 12, 0)
    assert models.utc(naive) == naive.replace(tzinfo=dt.timezone.utc)
    plus2 = dt.datetime(2026, 1, 1, 14, 0, tzinfo=dt.timezone(dt.timedelta(hours=2)))
    assert models.utc(plus2) == dt.datetime(2026, 1, 1, 12, 0, tzinfo=dt.timezone.utc)
    assert models.utc(0) == dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
    assert models.utc(True) is None
    assert models.utc("x") is None
    assert models.from_aws_tags(
        [{"Key": "a"}, {"Value": "orphan"}, {"Key": "b", "Value": "2"}]
    ) == {
        "a": "",
        "b": "2",
    }
    assert models.from_aws_tags(None) == {}


def test_policy_and_descriptions() -> None:
    assert models.parse_policy(None) is None
    assert models.parse_policy("not json") is None
    assert models.parse_policy("[1]") is None
    assert models.parse_policy('{"a": 1}') == {"a": 1}
    assert models.policy_text({"a": 1}) == '{"a": 1}'
    d = models.to_description(
        {
            "ARN": "arn",
            "Name": "n",
            "RotationEnabled": True,
            "RotationRules": {"AutomaticallyAfterDays": 3, "ScheduleExpression": "rate(3 days)"},
            "ReplicationStatus": [{"Region": "eu-west-1", "Status": "InSync"}],
            "OwningService": "rds",
            "SecretVersionsToStages": {"v1": ["AWSCURRENT"]},
        }
    )
    assert d.rotation_rules == sdk.RotationRules(3, None, "rate(3 days)")
    assert d.replication_status == (sdk.ReplicationStatus(region="eu-west-1", status="InSync"),)
    assert d.owning_service == "rds"
    assert d.version_ids_to_stages == {"v1": ("AWSCURRENT",)}
    assert models.to_description({}).rotation_rules is None
    assert models.encode_bytes(b"\xff") == {"SecretBinary": b"\xff"}
    assert models.encode_bytes(b"ok") == {"SecretString": "ok"}


def test_order_by_ids_handles_arns_and_unknowns() -> None:
    def v(name: str, arn: str) -> sdk.AwsSecretValue:
        return sdk.AwsSecretValue(arn, name, None, (), None, False, sdk.SecretValue(""))

    a = v("a", "arn:aws:secretsmanager:r:1:secret:a-XyZ123")
    b = v("b", "arn:aws:secretsmanager:r:1:secret:b-AbC456")
    c = v("c", "arn:c")
    ordered = models.order_by_ids([c, b, a], ["arn:aws:secretsmanager:r:1:secret:a", "b"])
    assert [x.name for x in ordered] == ["a", "b", "c"]


def test_paginators_stop_on_repeated_tokens() -> None:
    calls: list[str | None] = []

    def fetch(token: str | None) -> tuple[list[int], str | None]:
        calls.append(token)
        return [len(calls)], "same"

    assert sdk.Paginator(fetch).to_list() == [1, 2]
    assert calls == [None, "same"]


async def test_async_paginator() -> None:
    async def fetch(token: str | None) -> tuple[list[int], str | None]:
        return ([1, 2], "t") if token is None else ([3], None)

    pager = sdk.AsyncPaginator(fetch)
    assert await pager.to_list() == [1, 2, 3]
    assert [page async for page in pager.pages()] == [[1, 2], [3]]

    async def loop(token: str | None) -> tuple[list[int], str | None]:
        return [0], "again"

    assert await sdk.AsyncPaginator(loop).to_list() == [0, 0]
