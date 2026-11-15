"""Redaction of secrets in cloud API responses printed by the operator tools (CIT-13).

`redact_json` masks one-time staff override codes (`code`), OTP codes and mail bodies (fake outbox), and any
field whose name is a credential (token, secret, api_key, password, pepper, totp seed / otpauth URI), plus
FaceGuard bearer credentials (fgk_/fgs_) embedded in any string. Ids (`code_id`, `key_id`, `otp_id`) stay
visible so the operator can still follow what happened. CI-07: `salt` is masked everywhere and `hash` inside any
`override_codes` subtree (PBKDF2 hash + salt of a 6-8 digit code can be brute-forced); other digests such as
`record_hash`, `chain_head`, `prev_hash`, `sha256`, `content_hash` (and `hash` elsewhere) stay visible.
`reveal_to_file` writes the UNREDACTED response to a new mode-0600 file instead of the terminal (explicit
--reveal-secrets only).
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

MASK = "***"
SECRET_FIELDS = frozenset({
    "code", "otp", "otp_code", "body", "text", "html", "token", "secret", "api_key", "key", "password",
    "pepper", "totp_secret", "otpauth_uri", "seed", "session_token", "mfa_ticket", "temporary_password", "salt",
})
OVERRIDE_CODE_FIELDS = frozenset({"hash", "salt"})
_OVERRIDE_SUBTREE = "override_codes"
_BEARER = re.compile(r"\bfg[ks]_[A-Za-z0-9_.-]{8,}")


def _secret_field(key: str, in_codes: bool) -> bool:
    name = key.lower()
    return name in SECRET_FIELDS or (in_codes and name in OVERRIDE_CODE_FIELDS)


def redact_json(obj: Any, *, _in_codes: bool = False) -> Any:
    if isinstance(obj, dict):
        return {k: (MASK if _secret_field(str(k), _in_codes) and not isinstance(v, (dict, list)) and v is not None
                    else redact_json(v, _in_codes=_in_codes or str(k).lower() == _OVERRIDE_SUBTREE))
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_json(v, _in_codes=_in_codes) for v in obj]
    if isinstance(obj, str):
        return _BEARER.sub(MASK, obj)
    return obj


def redact_text(text: str) -> str:
    try:
        return json.dumps(redact_json(json.loads(text)), indent=2)
    except ValueError:
        return _BEARER.sub(MASK, text)


def reveal_to_file(path: str, payload: str) -> Path:
    """Write `payload` to a NEW file with mode 0600 (refuses to overwrite an existing file)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(payload)
    return Path(path)
