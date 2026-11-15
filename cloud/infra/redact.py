#!/usr/bin/env python3
"""Mask secrets in AWS CLI output, error text and command lines (stdin -> stdout). Stdlib only.

Used by cloud/infra/common.sh for every printed command, error message and (HID_VERBOSE=1) response body.
JSON input: every value under an "Environment"/"Variables" object, and every value whose key looks secret
(token, secret, password, pepper, hmac, signature, user data, credential...), becomes "***". Text input:
KEY=VALUE pairs with secret-looking keys, presigned-URL signature/credential parameters, AWS access key ids
and FaceGuard bearer credentials (fgk_/fgs_) are masked. Ids, ARNs, names and types are kept.

CI-01: the KEY rule also covers quoted / JSON / colon forms (KEY='v', "KEY":"v", "KEY": "v", KEY: v); any JSON
object that follows "String measured:" (Lambda's 4KB environment error) is masked wholesale; JSON objects embedded
in a text line are parsed and redacted like whole-JSON input. If HID_REDACT_VALUES_FILE names a readable KEY=VALUE
.env file, every value from it of length >= 8 is replaced by *** anywhere in the input (missing file: no value
masking; the pattern rules still apply). Every value in that file is treated as a secret.
"""

from __future__ import annotations

import json
import os
import re
import sys

MASK = "***"
_SECRET_KEY = re.compile(r"(key|token|secret|pepper|password|passwd|hmac|signature|userdata|user_data|credential"
                         r"|otp|cookie|session)", re.IGNORECASE)
_NOT_SECRET = re.compile(r"(id|ids|arn|arns|name|names|type|schema|state|status|usage|spec|manager|origin"
                         r"|metadata|version|count|enabled|_ttl)$", re.IGNORECASE)
_ENV_BLOCKS = {"Variables", "Environment"}
_TEXT_RULES = (
    # NAME, up to 3 non-word chars (closing quote, backslash, space), "=" or ":", up to 3 spaces, then either a
    # quoted value (optionally backslash-escaped quote, masked up to the matching quote) or a bare value.
    (re.compile(r"(?i)\b(?P<name>[A-Z0-9_]*(?:KEY|TOKEN|SECRET|PEPPER|PASSWORD|PASSWD|HMAC)[A-Z0-9_]*)"
                r"(?P<sep>[^\w\n]{0,3}?[=:][ \t]{0,3})"
                r"(?:(?P<q>\\?[\"'])(?P<qv>(?:(?!(?P=q))[^\n])*)|(?P<v>[^\s'\",&}\]\\]+))"),
     lambda m: _mask_kv(m)),
    (re.compile(r"(?i)(X-Amz-(?:Signature|Credential|Security-Token))=([^&\s'\"]+)"), lambda m: f"{m.group(1)}={MASK}"),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), lambda m: MASK),
    (re.compile(r"\bfg[ks]_[A-Za-z0-9_.-]{8,}"), lambda m: MASK),
)


_PLAIN_NAMES = {"key", "tagkey", "keytype", "attributename"}
_MEASURED = re.compile(r"(?i)String measured:\s*")
_MIN_VALUE_LEN = 8
_MAX_EMBEDDED_SCAN = 65536  # skip the embedded-JSON scan on very large text (the KEY rules still apply)
_DECODER = json.JSONDecoder()


def _mask_kv(m: re.Match[str]) -> str:
    if _plain_name(m.group("name")):
        return m.group(0)
    quote = m.group("q") or ""
    return f"{m.group('name')}{m.group('sep')}{quote}{MASK}"


def _env_value(raw: str) -> str:
    val = raw.strip()
    if val[:1] in ("'", '"'):
        end = val.find(val[0], 1)
        return val[1:end] if end > 0 else val[1:]
    return re.split(r"\s+#", val, maxsplit=1)[0].rstrip()


def load_values(path: str | None) -> list[str]:
    """Values (len >= 8) from a KEY=VALUE .env file, longest first; [] if unset or unreadable."""
    if not path:
        return []
    try:
        lines = open(path, encoding="utf-8", errors="replace").read().splitlines()  # noqa: SIM115
    except OSError:
        return []
    values: set[str] = set()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        key, _, raw = line.partition("=")
        if not key.strip():
            continue
        val = _env_value(raw)
        if len(val) >= _MIN_VALUE_LEN:
            values.add(val)
            escaped = json.dumps(val)[1:-1]
            if escaped != val:
                values.add(escaped)
    return sorted(values, key=len, reverse=True)


def mask_values(text: str, values: list[str]) -> str:
    for val in values:
        text = text.replace(val, MASK)
    return text


def _json_end(text: str, start: int) -> int:
    """Index just past the {...} object starting at `start` (string-aware); len(text) if it is unterminated."""
    depth, in_str, esc = 0, False, False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i + 1
    return len(text)


def _mask_measured(text: str) -> str:
    out, pos = [], 0
    for m in _MEASURED.finditer(text):
        if m.start() < pos or text[m.end():m.end() + 1] != "{":
            continue
        out.append(text[pos:m.end()] + MASK)
        pos = _json_end(text, m.end())
    out.append(text[pos:])
    return "".join(out)


def _redact_embedded_json(text: str) -> str:
    if len(text) > _MAX_EMBEDDED_SCAN or "{" not in text:
        return text
    out, pos, i = [], 0, text.find("{")
    while i != -1:
        try:
            obj, end = _DECODER.raw_decode(text, i)
        except ValueError:
            i = text.find("{", i + 1)
            continue
        if isinstance(obj, dict):
            out.append(text[pos:i] + json.dumps(redact_obj(obj), separators=(",", ":")))
            pos = end
        i = text.find("{", end)
    out.append(text[pos:])
    return "".join(out)


def _plain_name(name: str) -> bool:
    return name.lower() in _PLAIN_NAMES or bool(_NOT_SECRET.search(name))


def _secret_key(key: str) -> bool:
    return bool(_SECRET_KEY.search(key)) and not _NOT_SECRET.search(key)


def redact_obj(obj: object, *, under_env: bool = False) -> object:
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if under_env and not isinstance(v, (dict, list)):
                out[k] = MASK
            elif _secret_key(str(k)) and not isinstance(v, (dict, list)):
                out[k] = MASK
            else:
                out[k] = redact_obj(v, under_env=under_env or k in _ENV_BLOCKS)
        return out
    if isinstance(obj, list):
        return [redact_obj(v, under_env=under_env) for v in obj]
    if isinstance(obj, str):
        return MASK if under_env else redact_text(obj)
    return MASK if under_env else obj


def redact_text(text: str) -> str:
    text = _redact_embedded_json(_mask_measured(text))
    for pattern, repl in _TEXT_RULES:
        text = pattern.sub(repl, text)
    return text


def redact(text: str, values: list[str] | None = None) -> str:
    values = values or []
    text = mask_values(text, values)
    stripped = text.strip()
    if stripped[:1] in "{[":
        try:
            return mask_values(json.dumps(redact_obj(json.loads(stripped)), indent=1), values)
        except ValueError:
            pass
    return mask_values(redact_text(text), values)


def main() -> int:
    values = load_values(os.environ.get("HID_REDACT_VALUES_FILE"))
    sys.stdout.write(redact(sys.stdin.read(), values))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
