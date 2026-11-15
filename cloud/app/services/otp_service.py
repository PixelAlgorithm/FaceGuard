"""Email OTP via SES (SMS to India is impossible today: TRAI DLT registration).

6 digits, TTL 300 s, 3 verification attempts, single use (config/thresholds.yaml fallback.email_otp).
Only HMAC-SHA256(OTP pepper, otp_id:code) is stored (a bare SHA-256 of 6 digits is brute-forceable).
State changes use compare-and-set on the OTP item, so concurrent verifies cannot double-spend.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import timedelta

from ..clock import Clock, epoch_s, iso_z, parse_ts
from ..errors import ApiError
from ..metrics import Metrics
from ..thresholds import CloudThresholds
from .adapters import AdapterUnavailable
from .enroll_service import mask_email
from .kv import KV

NS_OTP = "otp"
NS_OTP_BY_ATTEMPT = "otp_attempt"


class OtpService:
    def __init__(self, kv: KV, mailer, thresholds: CloudThresholds, clock: Clock, metrics: Metrics, *,
                 pepper: str, resend_after_s: int) -> None:
        self.kv = kv
        self.mailer = mailer
        self.t = thresholds
        self.clock = clock
        self.metrics = metrics
        self.pepper = pepper
        self.resend_after_s = resend_after_s

    def _hash(self, otp_id: str, code: str) -> str:
        return hmac.new(self.pepper.encode(), f"{otp_id}:{code}".encode(), hashlib.sha256).hexdigest()

    def send(self, *, attempt_id: str, user_id: str, channel: str) -> dict:
        if channel != "email":
            raise ApiError("VALIDATION_ERROR", "only channel=email is supported (SMS to India needs TRAI DLT)")
        user = self.kv.get("users", user_id)
        if not user or not user.get("email"):
            raise ApiError("NOT_FOUND", "no e-mail on file for user", attempt_id=attempt_id)
        now = self.clock.now()
        last = self.kv.get(NS_OTP_BY_ATTEMPT, attempt_id)
        if last and (now - parse_ts(last["sent_at"])).total_seconds() < self.resend_after_s:
            raise ApiError("RATE_LIMITED", f"resend allowed after {self.resend_after_s}s", attempt_id=attempt_id)
        digits = self.t.otp_digits
        code = f"{secrets.randbelow(10 ** digits):0{digits}d}"
        otp_id = "otp_" + secrets.token_urlsafe(9)
        expires = now + timedelta(seconds=self.t.otp_ttl_s)
        try:
            self.mailer.send(user["email"], "Your HID kiosk verification code",
                             f"Your one-time code is {code}. It expires in {self.t.otp_ttl_s // 60} minutes.\n"
                             f"If you are not at the kiosk, ignore this message.")
        except AdapterUnavailable as exc:
            self.metrics.count("OtpSent", Result="email_unavailable")
            raise ApiError("CLOUD_UNAVAILABLE", "email OTP unavailable; use TOTP / staff code / card",
                           attempt_id=attempt_id) from exc
        item = {"otp_id": otp_id, "attempt_id": attempt_id, "user_id": user_id,
                "code_hash": self._hash(otp_id, code), "expires_at": iso_z(expires),
                "attempts_left": self.t.otp_max_attempts, "used": False, "created_at": iso_z(now)}
        ttl = epoch_s(expires) + 3600
        self.kv.put(NS_OTP, otp_id, item, ttl=ttl)
        self.kv.put(NS_OTP_BY_ATTEMPT, attempt_id, {"otp_id": otp_id, "sent_at": iso_z(now)}, ttl=ttl)
        self.metrics.count("OtpSent", Result="sent")
        return {"otp_id": otp_id, "channel": "email", "destination_masked": mask_email(user["email"]),
                "expires_at": iso_z(expires), "resend_after_s": self.resend_after_s, "code_length": digits}

    def verify(self, *, otp_id: str, attempt_id: str, code: str) -> dict:
        for _ in range(5):
            item = self.kv.get(NS_OTP, otp_id)
            if item is None:
                return self._result(otp_id, False, 0, "NOT_FOUND")
            if item.get("attempt_id") != attempt_id:
                return self._result(otp_id, False, int(item.get("attempts_left", 0)), "ATTEMPT_MISMATCH")
            if item.get("used"):
                return self._result(otp_id, False, 0, "USED")
            if self.clock.now() >= parse_ts(item["expires_at"]):
                return self._result(otp_id, False, 0, "EXPIRED")
            left = int(item.get("attempts_left", 0))
            if left <= 0:
                return self._result(otp_id, False, 0, "LOCKED")
            ok = hmac.compare_digest(self._hash(otp_id, code.strip()), item["code_hash"])
            new = {k: v for k, v in item.items() if k != "_rev"}
            if ok:
                new["used"] = True
                new["attempts_left"] = left - 1
            else:
                new["attempts_left"] = left - 1
            if self.kv.cas(NS_OTP, otp_id, new, item["_rev"], ttl=epoch_s(parse_ts(item["expires_at"])) + 3600):
                return self._result(otp_id, ok, 0 if ok else new["attempts_left"], None if ok else "MISMATCH")
        raise ApiError("INTERNAL", "otp contention")

    def _result(self, otp_id: str, verified: bool, remaining: int, reason: str | None) -> dict:
        self.metrics.count("OtpVerified", Result="ok" if verified else (reason or "fail"))
        out = {"otp_id": otp_id, "verified": verified, "attempts_remaining": remaining}
        if reason:
            out["reason"] = reason
        return out
