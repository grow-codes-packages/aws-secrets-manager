"""An in-memory, stateful stand-in for a boto3 ``secretsmanager`` client (sync + async).

It implements the operations the provider and the caches use with AWS semantics (stages,
scheduled deletion, ``BatchGetSecretValue`` partial errors, pagination) and raises botocore
``ClientError`` with AWS error codes, so the SDK's error mapping runs as it does against AWS.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import itertools
import uuid
from typing import Any

from botocore.exceptions import ClientError

NOW = dt.datetime(2026, 11, 18, 12, 0, tzinfo=dt.timezone.utc)


def client_error(code: str, op: str, status: int = 400) -> ClientError:
    return ClientError(
        {
            "Error": {"Code": code, "Message": f"{code} from fake"},
            "ResponseMetadata": {"HTTPStatusCode": status, "RequestId": "fake-req"},
        },
        op,
    )


@dataclasses.dataclass
class _Version:
    vid: str
    string: str | None
    binary: bytes | None
    stages: list[str]


@dataclasses.dataclass
class _Secret:
    name: str
    arn: str
    description: str | None = None
    tags: dict[str, str] = dataclasses.field(default_factory=dict)
    versions: list[_Version] = dataclasses.field(default_factory=list)
    deleted: dt.datetime | None = None


class FakeSecretsManager:
    """Sync fake; ``calls`` records ``(operation, kwargs)``; ``fail`` injects errors per op."""

    def __init__(self) -> None:
        self.secrets: dict[str, _Secret] = {}
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.fail: dict[str, list[BaseException]] = {}
        self.closed = False
        self._ids = itertools.count(1)

    # ---------------------------------------------------------------- helpers
    def _enter(self, op: str, kwargs: dict[str, Any]) -> None:
        self.calls.append((op, kwargs))
        queue = self.fail.get(op)
        if queue:
            raise queue.pop(0)

    def _find(self, sid: str, op: str, *, allow_deleted: bool = True) -> _Secret:
        secret = self.secrets.get(sid) or next(
            (s for s in self.secrets.values() if s.arn == sid), None
        )
        if secret is None:
            raise client_error("ResourceNotFoundException", op)
        if secret.deleted is not None and not allow_deleted:
            raise client_error("InvalidRequestException", op)
        return secret

    def _add_version(
        self, s: _Secret, kwargs: dict[str, Any], stages: list[str] | None
    ) -> _Version:
        labels = list(stages or ["AWSCURRENT"])
        if "AWSCURRENT" in labels:
            for v in s.versions:
                if "AWSPREVIOUS" in v.stages:
                    v.stages.remove("AWSPREVIOUS")
            for v in s.versions:
                if "AWSCURRENT" in v.stages:
                    v.stages.remove("AWSCURRENT")
                    v.stages.append("AWSPREVIOUS")
        for v in s.versions:
            for label in labels:
                if label != "AWSCURRENT" and label in v.stages:
                    v.stages.remove(label)
        binary = kwargs.get("SecretBinary")
        version = _Version(
            kwargs.get("ClientRequestToken") or str(uuid.uuid4()),
            kwargs.get("SecretString"),
            bytes(binary) if binary is not None else None,
            labels,
        )
        s.versions.append(version)
        return version

    @staticmethod
    def _value(s: _Secret, v: _Version) -> dict[str, Any]:
        out: dict[str, Any] = {
            "ARN": s.arn,
            "Name": s.name,
            "VersionId": v.vid,
            "VersionStages": list(v.stages),
            "CreatedDate": NOW,
        }
        if v.binary is not None:
            out["SecretBinary"] = v.binary
        else:
            out["SecretString"] = v.string
        return out

    def _describe(self, s: _Secret) -> dict[str, Any]:
        out: dict[str, Any] = {
            "ARN": s.arn,
            "Name": s.name,
            "Tags": [{"Key": k, "Value": v} for k, v in s.tags.items()],
            "VersionIdsToStages": {v.vid: list(v.stages) for v in s.versions if v.stages},
            "CreatedDate": NOW,
            "LastChangedDate": NOW,
        }
        if s.description is not None:
            out["Description"] = s.description
        if s.deleted is not None:
            out["DeletedDate"] = s.deleted
        return out

    # ---------------------------------------------------------------- operations
    def get_secret_value(self, **kw: Any) -> dict[str, Any]:
        self._enter("GetSecretValue", kw)
        s = self._find(kw["SecretId"], "GetSecretValue", allow_deleted=False)
        stage = kw.get("VersionStage")
        vid = kw.get("VersionId")
        for v in s.versions:
            if (vid is not None and v.vid == vid) or (
                vid is None and (stage or "AWSCURRENT") in v.stages
            ):
                return self._value(s, v)
        raise client_error("ResourceNotFoundException", "GetSecretValue")

    def batch_get_secret_value(self, **kw: Any) -> dict[str, Any]:
        self._enter("BatchGetSecretValue", kw)
        values: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        for sid in kw.get("SecretIdList", []):
            try:
                values.append(self.get_secret_value(SecretId=sid))
            except ClientError as err:
                code = err.response["Error"]["Code"]
                errors.append({"SecretId": sid, "ErrorCode": code, "Message": "x"})
        return {"SecretValues": values, "Errors": errors}

    def describe_secret(self, **kw: Any) -> dict[str, Any]:
        self._enter("DescribeSecret", kw)
        return self._describe(self._find(kw["SecretId"], "DescribeSecret"))

    def list_secrets(self, **kw: Any) -> dict[str, Any]:
        self._enter("ListSecrets", kw)
        prefixes: list[str] = []
        for f in kw.get("Filters", []):
            if f["Key"] == "name":
                prefixes.extend(f["Values"])
        items = [
            self._describe(s)
            for s in self.secrets.values()
            if (kw.get("IncludePlannedDeletion") or s.deleted is None)
            and (not prefixes or any(s.name.startswith(p) for p in prefixes))
        ]
        size = int(kw.get("MaxResults") or 2)
        start = int(kw.get("NextToken") or 0)
        page = items[start : start + size]
        out: dict[str, Any] = {"SecretList": page}
        if start + size < len(items):
            out["NextToken"] = str(start + size)
        return out

    def create_secret(self, **kw: Any) -> dict[str, Any]:
        self._enter("CreateSecret", kw)
        name = kw["Name"]
        if name in self.secrets:
            raise client_error("ResourceExistsException", "CreateSecret")
        s = _Secret(name, f"arn:aws:secretsmanager:us-east-1:123456789012:secret:{name}-AbCdEf")
        s.description = kw.get("Description")
        s.tags = {t["Key"]: t["Value"] for t in kw.get("Tags", [])}
        self.secrets[name] = s
        out = {"ARN": s.arn, "Name": s.name}
        if "SecretString" in kw or "SecretBinary" in kw:
            out["VersionId"] = self._add_version(s, kw, None).vid
        return out

    def put_secret_value(self, **kw: Any) -> dict[str, Any]:
        self._enter("PutSecretValue", kw)
        s = self._find(kw["SecretId"], "PutSecretValue", allow_deleted=False)
        v = self._add_version(s, kw, kw.get("VersionStages"))
        return {"ARN": s.arn, "Name": s.name, "VersionId": v.vid, "VersionStages": v.stages}

    def update_secret(self, **kw: Any) -> dict[str, Any]:
        self._enter("UpdateSecret", kw)
        s = self._find(kw["SecretId"], "UpdateSecret", allow_deleted=False)
        if "Description" in kw:
            s.description = kw["Description"]
        out = {"ARN": s.arn, "Name": s.name}
        if "SecretString" in kw or "SecretBinary" in kw:
            out["VersionId"] = self._add_version(s, kw, None).vid
        return out

    def tag_resource(self, **kw: Any) -> dict[str, Any]:
        self._enter("TagResource", kw)
        s = self._find(kw["SecretId"], "TagResource")
        s.tags.update({t["Key"]: t["Value"] for t in kw["Tags"]})
        return {}

    def delete_secret(self, **kw: Any) -> dict[str, Any]:
        self._enter("DeleteSecret", kw)
        sid = kw["SecretId"]
        if kw.get("ForceDeleteWithoutRecovery"):
            s = self.secrets.pop(sid, None)
            name = s.name if s else sid
            return {"ARN": s.arn if s else "", "Name": name, "DeletionDate": NOW}
        s = self._find(sid, "DeleteSecret", allow_deleted=False)
        s.deleted = NOW + dt.timedelta(days=kw.get("RecoveryWindowInDays", 30))
        return {"ARN": s.arn, "Name": s.name, "DeletionDate": s.deleted}

    def close(self) -> None:
        self.closed = True


class AsyncFakeSecretsManager:
    """Async facade over :class:`FakeSecretsManager` (like an entered aiobotocore client)."""

    def __init__(self, backend: FakeSecretsManager | None = None) -> None:
        self.backend = backend or FakeSecretsManager()

    def __getattr__(self, name: str) -> Any:
        method = getattr(self.backend, name)

        async def call(**kw: Any) -> Any:
            return method(**kw)

        return call
