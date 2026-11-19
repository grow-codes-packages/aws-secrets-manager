"""Test support for the AWS clients: a local AWS JSON 1.1 server fed with recorded fixtures.

``AwsMock`` answers ``POST /`` by the ``X-Amz-Target`` operation: queued replies per operation
first, then the per-operation default, else ``{}``. Every request is recorded with its parsed
JSON body, so tests assert on what boto3 / aiobotocore actually sent.
"""

from __future__ import annotations

import dataclasses
import json
import threading
import time
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import grow_aws_secrets_manager as sdk

FIXTURES = Path(__file__).parent / "fixtures"

#: Throwaway test credentials (never real).
ACCESS_KEY = "AKIAGROWTESTKEY00001"
SECRET_KEY = "grow-test-secret-key-do-not-use-0001"
SESSION_TOKEN = "grow-test-session-token-0001"


@dataclasses.dataclass
class AwsReply:
    status: int = 200
    body: Any = None  # dict/list → JSON; str/bytes → raw
    headers: dict[str, str] = dataclasses.field(default_factory=dict)
    delay: float = 0.0
    content_type: str = "application/x-amz-json-1.1"


@dataclasses.dataclass
class AwsSeen:
    operation: str
    headers: dict[str, str]
    body: dict[str, Any]


def fixture(name: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))
    return data


def reply(name: str, **changes: Any) -> AwsReply:
    """An :class:`AwsReply` from ``fixtures/<name>.json`` (status, headers, body)."""
    resp = fixture(name)["response"]
    headers = {
        k: v
        for k, v in resp["headers"].items()
        if k.lower() not in ("content-length", "content-type", "status", "date", "server")
    }
    ctype = resp["headers"].get("content-type", "application/x-amz-json-1.1")
    if isinstance(resp["body"], (dict, list)):
        ctype = "application/x-amz-json-1.1"
    base = AwsReply(resp["status"], resp["body"], headers, content_type=ctype)
    return dataclasses.replace(base, **changes)


def aws_error(code: str, status: int = 400, message: str = "boom", **headers: str) -> AwsReply:
    """An AWS-shaped JSON error (real AWS answers 400 for most errors)."""
    hdrs = {"x-amzn-requestid": "req-123", "x-amzn-errortype": code, **headers}
    return AwsReply(status, {"__type": code, "message": message}, hdrs)


class AwsMock:
    """Threaded local AWS JSON 1.1 endpoint."""

    def __init__(self) -> None:
        self.replies: dict[str, deque[AwsReply]] = defaultdict(deque)
        self.defaults: dict[str, AwsReply] = {}
        self.seen: list[AwsSeen] = []
        self._lock = threading.Lock()
        server = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                pass

            def do_POST(self) -> None:
                length = int(self.headers.get("content-length") or 0)
                raw = self.rfile.read(length) if length else b""
                target = self.headers.get("X-Amz-Target", "")
                op = target.split(".", 1)[-1]
                try:
                    body = json.loads(raw) if raw else {}
                except ValueError:
                    body = {}
                with server._lock:
                    server.seen.append(AwsSeen(op, dict(self.headers), body))
                    queue = server.replies.get(op)
                    r = queue.popleft() if queue else server.defaults.get(op, AwsReply(200, {}))
                if r.delay:
                    time.sleep(r.delay)
                if isinstance(r.body, (bytes, str)):
                    payload = r.body.encode() if isinstance(r.body, str) else r.body
                else:
                    payload = json.dumps(r.body if r.body is not None else {}).encode()
                try:
                    self.send_response(r.status)
                    self.send_header("Content-Type", r.content_type)
                    for k, v in r.headers.items():
                        self.send_header(k, v)
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                except (BrokenPipeError, ConnectionResetError):
                    pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(
            target=self.httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        )
        self.thread.start()

    @property
    def url(self) -> str:
        host, port = self.httpd.server_address[:2]
        return f"http://{host!s}:{port}"

    def enqueue(self, op: str, *replies: AwsReply) -> None:
        with self._lock:
            self.replies[op].extend(replies)

    def ops(self) -> list[str]:
        return [s.operation for s in self.seen]

    def last(self, op: str) -> AwsSeen:
        return [s for s in self.seen if s.operation == op][-1]

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


def aws_config(url: str, **kw: Any) -> sdk.AwsSecretsManagerConfig:
    """A config pointing at ``url`` with test credentials and fast retries."""
    kw.setdefault("region", "us-east-1")
    kw.setdefault("access_key_id", ACCESS_KEY)
    kw.setdefault("secret_access_key", SECRET_KEY)
    kw.setdefault("retry", sdk.RetryPolicy(max_retries=0))
    return sdk.AwsSecretsManagerConfig(url=url, **kw)
