"""Email OTP via SES (SMS to India is impossible today: TRAI DLT registration).

6 digits, TTL 300 s, 3 verification attempts, single use (config/thresholds.yaml fallback.email_otp); at most
max_sends_per_user codes per user per send_window_s, and a resend for an attempt invalidates its previous code.
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
NS_OTP_USER_SENDS = "otp_user_sends"  # key = user|ts|otp_id, TTL = send window: per-user send cap


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
        """Order (F11): per-user cap -> claim the attempt's resend slot (conditional write) -> store the OTP ->
        send the mail -> invalidate the attempt's previous OTP. A store failure therefore never leaves a mailed
        code that cannot verify, and two concurrent sends for one attempt cannot both mail."""
        if channel != "email":
            raise ApiError("VALIDATION_ERROR", "only channel=email is supported (SMS to India needs TRAI DLT)")
        user = self.kv.get("users", user_id)
        if not user or not user.get("email"):
            raise ApiError("NOT_FOUND", "no e-mail on file for user", attempt_id=attempt_id)
        now = self.clock.now()
        self._check_user_cap(user_id, attempt_id, now)
        previous = self._claim_resend_slot(attempt_id, now)
        digits = self.t.otp_digits
        code = f"{secrets.randbelow(10 ** digits):0{digits}d}"
        otp_id = "otp_" + secrets.token_urlsafe(9)
        expires = now + timedelta(seconds=self.t.otp_ttl_s)
        ttl = epoch_s(expires) + 3600
        item = {"otp_id": otp_id, "attempt_id": attempt_id, "user_id": user_id,
                "code_hash": self._hash(otp_id, code), "expires_at": iso_z(expires),
                "attempts_left": self.t.otp_max_attempts, "used": False, "created_at": iso_z(now)}
        self.kv.put(NS_OTP, otp_id, item, ttl=ttl)  # stored BEFORE the mail leaves
        try:
            self.mailer.send(user["email"], "Your HID kiosk verification code",
                             f"Your one-time code is {code}. It expires in {self.t.otp_ttl_s // 60} minutes.\n"
                             f"If you are not at the kiosk, ignore this message.")
        except AdapterUnavailable as exc:
            self._invalidate(otp_id, "MAIL_FAILED")
            self.metrics.count("OtpSent", Result="email_unavailable")
            raise ApiError("CLOUD_UNAVAILABLE", "email OTP unavailable; use TOTP / staff code / card",
                           attempt_id=attempt_id, reason="EMAIL_UNAVAILABLE") from exc
        self.kv.put(NS_OTP_BY_ATTEMPT, attempt_id, {"otp_id": otp_id, "sent_at": iso_z(now)}, ttl=ttl)
        self.kv.put(NS_OTP_USER_SENDS, f"{user_id}|{iso_z(now)}|{otp_id}", {"attempt_id": attempt_id},
                    ttl=epoch_s(now) + self.t.otp_send_window_s)
        if previous:
            self._invalidate(previous, "SUPERSEDED")  # only the newest code of an attempt verifies
        self.metrics.count("OtpSent", Result="sent")
        return {"otp_id": otp_id, "channel": "email", "destination_masked": mask_email(user["email"]),
                "expires_at": iso_z(expires), "resend_after_s": self.resend_after_s, "code_length": digits}

    def _check_user_cap(self, user_id: str, attempt_id: str, now) -> None:
        start = iso_z(now - timedelta(seconds=self.t.otp_send_window_s))
        recent = [k for k, _ in self.kv.list(NS_OTP_USER_SENDS, prefix=f"{user_id}|")
                  if k.split("|")[1] >= start]
        if len(recent) >= self.t.otp_max_sends_per_user:
            self.metrics.count("OtpSent", Result="user_cap")
            raise ApiError("RATE_LIMITED", "too many codes sent to this user; try again later or use another method",
                           attempt_id=attempt_id, reason="OTP_SEND_CAP")

    def _claim_resend_slot(self, attempt_id: str, now) -> str | None:
        """Conditional write of the attempt's send slot; returns the previous otp_id of this attempt (or None)."""
        slot = {"otp_id": None, "sent_at": iso_z(now)}
        ttl = epoch_s(now) + self.t.otp_ttl_s + 3600
        last = self.kv.get(NS_OTP_BY_ATTEMPT, attempt_id)
        if last is None:
            if self.kv.put_if_absent(NS_OTP_BY_ATTEMPT, attempt_id, slot, ttl=ttl):
                return None
            last = self.kv.get(NS_OTP_BY_ATTEMPT, attempt_id) or {"sent_at": iso_z(now)}
        if (now - parse_ts(last["sent_at"])).total_seconds() < self.resend_after_s or "_rev" not in last:
            raise ApiError("RATE_LIMITED", f"resend allowed after {self.resend_after_s}s", attempt_id=attempt_id)
        if not self.kv.cas(NS_OTP_BY_ATTEMPT, attempt_id, {**slot, "otp_id": last.get("otp_id")}, last["_rev"],
                           ttl=ttl):
            raise ApiError("RATE_LIMITED", f"resend allowed after {self.resend_after_s}s", attempt_id=attempt_id)
        return last.get("otp_id")

    def _invalidate(self, otp_id: str, why: str) -> None:
        for _ in range(3):
            item = self.kv.get(NS_OTP, otp_id)
            if item is None or item.get("used"):
                return
            new = {**{k: v for k, v in item.items() if k != "_rev"}, "used": True, "invalidated": why}
            if self.kv.cas(NS_OTP, otp_id, new, item["_rev"], ttl=epoch_s(parse_ts(item["expires_at"])) + 3600):
                return

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
