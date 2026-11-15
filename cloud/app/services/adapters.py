"""Small adapters: e-mail (SES v2 / fake / disabled), blobs (S3 SSE-KMS / memory / disabled),
secret boxes (KMS / Fernet / none) and a token-bucket rate limiter for Rekognition quotas."""

from __future__ import annotations

import base64
import threading
import time
from dataclasses import dataclass


class AdapterUnavailable(Exception):
    pass


# ----------------------------------------------------------------------------- e-mail
@dataclass
class SentMail:
    to: str
    subject: str
    body: str
    sent_at: float


class SesMailer:
    name = "ses"

    def __init__(self, client, sender: str) -> None:
        self._c = client
        self._sender = sender

    def send(self, to: str, subject: str, body: str) -> str:
        try:
            r = self._c.send_email(
                FromEmailAddress=self._sender,
                Destination={"ToAddresses": [to]},
                Content={"Simple": {"Subject": {"Data": subject, "Charset": "UTF-8"},
                                    "Body": {"Text": {"Data": body, "Charset": "UTF-8"}}}},
            )
        except Exception as exc:  # SES sandbox: unverified recipient -> MessageRejected
            raise AdapterUnavailable(f"ses send failed ({type(exc).__name__})") from exc
        return r.get("MessageId", "")

    def ping(self) -> None:
        self._c.get_account()


class FakeMailer:
    """Keeps messages in memory; exposed only via the admin outbox when EMAIL_BACKEND=fake."""

    name = "fake"

    def __init__(self) -> None:
        self.outbox: list[SentMail] = []
        self.fail = False

    def send(self, to: str, subject: str, body: str) -> str:
        if self.fail:
            raise AdapterUnavailable("fake mailer failure")
        self.outbox.append(SentMail(to, subject, body, time.time()))
        return f"fake-{len(self.outbox)}"

    def ping(self) -> None:
        return None


class DisabledMailer:
    name = "disabled"

    def send(self, to: str, subject: str, body: str) -> str:
        raise AdapterUnavailable("email disabled (EMAIL_BACKEND=disabled)")

    def ping(self) -> None:
        raise AdapterUnavailable("email disabled")


# ----------------------------------------------------------------------------- blobs
class S3Blobs:
    name = "s3"

    def __init__(self, client, bucket: str, kms_key_id: str = "") -> None:
        self._c = client
        self.bucket = bucket
        self._kms = kms_key_id

    def put(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> None:
        kw = {"Bucket": self.bucket, "Key": key, "Body": data, "ContentType": content_type,
              "ServerSideEncryption": "aws:kms"}
        if self._kms:
            kw["SSEKMSKeyId"] = self._kms
        self._c.put_object(**kw)

    def get(self, key: str, bucket: str | None = None) -> bytes | None:
        from botocore.exceptions import ClientError

        try:
            return self._c.get_object(Bucket=bucket or self.bucket, Key=key)["Body"].read()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in {"NoSuchKey", "404"}:
                return None
            raise

    def delete(self, key: str) -> None:
        self._c.delete_object(Bucket=self.bucket, Key=key)


class MemoryBlobs:
    name = "memory"

    def __init__(self) -> None:
        self._d: dict[str, bytes] = {}
        self.bucket = "memory"

    def put(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> None:
        self._d[key] = data

    def get(self, key: str, bucket: str | None = None) -> bytes | None:
        return self._d.get(key)

    def delete(self, key: str) -> None:
        self._d.pop(key, None)


class DisabledBlobs:
    name = "disabled"
    bucket = ""

    def put(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> None:
        raise AdapterUnavailable("blob store disabled")

    def get(self, key: str, bucket: str | None = None) -> bytes | None:
        return None

    def delete(self, key: str) -> None:
        return None


# ----------------------------------------------------------------------------- secret boxes
class KmsBox:
    name = "kms"

    def __init__(self, client, key_id: str) -> None:
        self._c = client
        self._key = key_id

    def encrypt(self, plaintext: bytes) -> str:
        r = self._c.encrypt(KeyId=self._key, Plaintext=plaintext)
        return "kms:" + base64.b64encode(r["CiphertextBlob"]).decode()

    def decrypt(self, token: str) -> bytes:
        return self._c.decrypt(CiphertextBlob=base64.b64decode(token.removeprefix("kms:")))["Plaintext"]


class FernetBox:
    name = "fernet"

    def __init__(self, key: str) -> None:
        from cryptography.fernet import Fernet

        self._f = Fernet(key.encode())

    def encrypt(self, plaintext: bytes) -> str:
        return "fernet:" + self._f.encrypt(plaintext).decode()

    def decrypt(self, token: str) -> bytes:
        return self._f.decrypt(token.removeprefix("fernet:").encode())


class NoBox:
    """No key configured: secrets are returned once to the caller and never persisted."""

    name = "none"

    def encrypt(self, plaintext: bytes) -> str | None:
        return None

    def decrypt(self, token: str) -> bytes:
        raise AdapterUnavailable("no secret box configured")


# ----------------------------------------------------------------------------- rate limiting
class TokenBucket:
    """Per-process token bucket (exact on a single warm EC2 process; per-environment on Lambda)."""

    def __init__(self, rate_per_s: float, burst: float | None = None) -> None:
        self.rate = max(rate_per_s, 0.001)
        self.capacity = burst if burst is not None else max(1.0, rate_per_s)
        self._tokens = self.capacity
        self._t = time.monotonic()
        self._lock = threading.Lock()

    def try_acquire(self, max_wait_s: float = 0.0) -> float | None:
        """Returns seconds the caller must sleep before proceeding, or None if it would exceed max_wait_s.
        A successful call reserves the token immediately."""
        with self._lock:
            now = time.monotonic()
            self._tokens = min(self.capacity, self._tokens + (now - self._t) * self.rate)
            self._t = now
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return 0.0
            wait = (1.0 - self._tokens) / self.rate
            if wait > max_wait_s:
                return None
            self._tokens -= 1.0
            return wait


class ConcurrencyGauge:
    """Tracks open Face Liveness sessions (quota: 15 concurrent in ap-south-1, sessions live 3 min)."""

    def __init__(self, limit: int, ttl_s: float = 180.0) -> None:
        self.limit = limit
        self.ttl = ttl_s
        self._open: dict[str, float] = {}
        self._lock = threading.Lock()

    def try_open(self, key: str) -> bool:
        with self._lock:
            now = time.monotonic()
            self._open = {k: v for k, v in self._open.items() if v > now}
            if len(self._open) >= self.limit:
                return False
            self._open[key] = now + self.ttl
            return True

    def close(self, key: str) -> None:
        with self._lock:
            self._open.pop(key, None)
