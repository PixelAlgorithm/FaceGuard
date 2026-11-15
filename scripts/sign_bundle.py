#!/usr/bin/env python3
"""Sign a schedule bundle for the edge (HMAC-SHA256 over canonical JSON).

    python scripts/sign_bundle.py                                  # config/schedule.demo.json -> edge/data/bundle.signed.json
    python scripts/sign_bundle.py --src config/schedule.example.json --keep-times
    python scripts/sign_bundle.py --extra-codes 8 --provision-totp u_prj1

Override codes: the publicly documented OVR-001..003 (docs/config, test fixtures) are DROPPED from every
signed bundle unless --allow-doc-codes (fixtures only; refused when --out is the live edge/data bundle), and
fresh random PBKDF2 codes are generated until at least --min-codes (default 4) are present; their values go
only to the codes file. New codes have thresholds.yaml fallback.staff_override.code_length digits (10; the
edge also accepts the legacy 8-digit codes).

Version: by default bundle_version = max(source version, installed version + 1), where "installed" is the
bundle already at --out (the edge persists every installed bundle, cloud-issued ones included, there), so a
re-sign is never rejected by the edge as older than its last valid bundle. An explicit --version below the
installed one is signed as asked but warned about on stderr.

Stamps (round-2 R7): issued_at = now, expires_at = now + 12 h, every override code
valid_until = expires_at + 24 h (unless --keep-times). The publicly documented demo card IDs (DEMO_CARDS)
are hashed with CARD_ID_PEPPER into the bundle ONLY with --demo-cards; without it, any card hash that matches
a documented demo card is removed (a documented card ID must never open a live door). The signed bundle is
written owner-only (0600, fsync, atomic). Key: SCHEDULE_BUNDLE_HMAC_KEY (environment or the project .env);
never printed.
Demo secrets (override codes, TOTP provisioning URIs) go ONLY to edge/data/DEMO_CODES.txt (chmod 600,
gitignored), never to stdout. Canonical form: json.dumps(bundle_without_signature, sort_keys=True,
separators=(",", ":"), ensure_ascii=False).encode("utf-8").
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from edge.offline.bundle import (
    DEFAULT_KEY_ID,
    DOC_OVERRIDE_CODES,
    is_documented_code,
    sign_bundle,
    verify_bundle,
)
from edge.offline.crypto import write_private_atomic

# Documented demo card IDs (SURPRISE_CHALLENGES SC2.4 + operator/teammates). Raw IDs never enter the bundle.
DEMO_CARDS = {
    "HID-CARD-1001": "u_1a2b", "HID-CARD-1002": "u_3c4d", "HID-CARD-1003": "u_5e6f", "HID-CARD-1004": "u_7a8b",
    "HID-CARD-1005": "u_9c0d", "HID-CARD-1006": "u_e1f2", "HID-CARD-1007": "u_a3b4", "HID-CARD-1008": "u_c5d6",
    "HID-DEMO-0001": "u_prj1", "HID-DEMO-0002": "u_tm02", "HID-DEMO-0003": "u_tm03", "HID-DEMO-0004": "u_tm04",
}
# Publicly documented demo override codes: edge.offline.bundle.DOC_OVERRIDE_CODES (re-exported here; the cloud
# reads DOC_OVERRIDE_CODES from this module, cloud/app/policy_bridge.py). They never enter a live bundle.
__all__ = ["DEMO_CARDS", "DOC_OVERRIDE_CODES", "main", "recompute_card_hashes"]
DEFAULT_CODE_LENGTH = 10  # used only when thresholds.yaml cannot be read


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_env() -> dict[str, str]:
    env: dict[str, str] = {}
    f = ROOT / ".env"
    if f.exists():
        for line in f.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.split(" #", 1)[0].strip().strip('"').strip("'")
    env.update({k: v for k, v in os.environ.items() if k in env or k.endswith(("_KEY", "_PEPPER"))})
    return env


def _staff_override_cfg() -> dict:
    try:
        import yaml

        cfg = yaml.safe_load((ROOT / "config" / "thresholds.yaml").read_text(encoding="utf-8"))
        return dict(cfg["fallback"]["staff_override"])
    except Exception:  # noqa: BLE001 - callers fall back to the documented defaults
        return {}


def yaml_code_grace_hours(default: float = 24.0) -> float:
    """config/thresholds.yaml fallback.staff_override.valid_after_expiry_h (open decision, API.md 3.14)."""
    try:
        return float(_staff_override_cfg()["valid_after_expiry_h"])
    except (KeyError, TypeError, ValueError):
        return default


def yaml_code_length(default: int = DEFAULT_CODE_LENGTH) -> int:
    """config/thresholds.yaml fallback.staff_override.code_length (EO-11: 10 digits for new codes)."""
    try:
        n = int(_staff_override_cfg()["code_length"])
    except (KeyError, TypeError, ValueError):
        return default
    return max(n, DEFAULT_CODE_LENGTH)  # never mint the weak legacy length


def installed_version(path: Path) -> int | None:
    """bundle_version of the bundle already at `path` (None if absent/unreadable). Used only to pick a larger
    number, so it is read without verifying the signature (a bigger version can never be rejected as older)."""
    try:
        v = json.loads(path.read_text(encoding="utf-8")).get("bundle_version")
    except (OSError, ValueError, AttributeError):
        return None
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def pick_version(src_version: object, installed: int | None, explicit: int | None) -> int:
    if explicit is not None:
        return explicit
    src = src_version if isinstance(src_version, int) and not isinstance(src_version, bool) else 0
    return src if installed is None else max(src, installed + 1)


def stamp(bundle: dict, now: datetime, valid_hours: float, code_grace_hours: float) -> None:
    expires = now + timedelta(hours=valid_hours)
    bundle["issued_at"] = _iso(now)
    bundle["expires_at"] = _iso(expires)
    for code in (bundle.get("override_codes") or {}).get("codes") or []:
        code["valid_until"] = _iso(expires + timedelta(hours=code_grace_hours))


def recompute_card_hashes(bundle: dict, pepper: bytes) -> int:
    """Demo deployments only (--demo-cards; also the cloud's demo seed): hash the documented DEMO_CARDS."""
    n = 0
    users = bundle.get("users") or {}
    for card, uid in DEMO_CARDS.items():
        if uid in users:
            users[uid].setdefault("fallback", {})["card_id_hash"] = hmac.new(
                pepper, card.encode(), hashlib.sha256).hexdigest()
            n += 1
    return n


def drop_demo_card_hashes(bundle: dict, pepper: bytes) -> int:
    """Remove every card_id_hash that is the hash of a documented demo card ID (SC2-D6). Returns the count."""
    documented = {hmac.new(pepper, card.encode(), hashlib.sha256).hexdigest() for card in DEMO_CARDS}
    n = 0
    for user in (bundle.get("users") or {}).values():
        fb = user.get("fallback") if isinstance(user, dict) else None
        if isinstance(fb, dict) and fb.get("card_id_hash") in documented:
            del fb["card_id_hash"]
            n += 1
    return n


def add_codes(bundle: dict, n: int, now: datetime, valid_until: str,
              length: int = DEFAULT_CODE_LENGTH) -> list[tuple[str, str, str]]:
    oc = bundle.setdefault("override_codes", {"kdf": "PBKDF2-HMAC-SHA256", "iterations": 100000, "codes": []})
    iterations = int(oc.get("iterations") or 100000)
    out = []
    stamp_id = now.strftime("%m%d%H%M")
    for i in range(n):
        code = f"{secrets.randbelow(10**length):0{length}d}"
        salt = secrets.token_hex(8)
        cid = f"OVR-D{stamp_id}-{i + 1:02d}"
        staff = "s_guard01" if i % 2 == 0 else "s_guard02"
        oc["codes"].append({"code_id": cid, "staff_id": staff, "salt": salt, "valid_until": valid_until,
                            "hash": hashlib.pbkdf2_hmac("sha256", code.encode(), bytes.fromhex(salt), iterations).hex()})
        out.append((cid, staff, code))
    return out


def drop_documented_codes(bundle: dict) -> list[str]:
    """Remove every override code whose value or code_id is publicly documented (edge.offline.bundle rule, the
    same as the edge and the cloud apply); returns the dropped code_ids."""
    oc = bundle.get("override_codes") or {}
    it = int(oc.get("iterations") or 100000)
    keep, dropped = [], []
    for c in oc.get("codes") or []:
        (dropped if is_documented_code(c, it) else keep).append(c)
    if dropped:
        oc["codes"] = keep
    return [str(c.get("code_id")) for c in dropped]


def documented_codes(bundle: dict) -> list[tuple[str, str, str]]:
    oc = bundle.get("override_codes") or {}
    it = int(oc.get("iterations") or 100000)
    found = []
    for c in oc.get("codes") or []:
        code = DOC_OVERRIDE_CODES.get(c.get("code_id"))
        if code and hashlib.pbkdf2_hmac("sha256", code.encode(), bytes.fromhex(c["salt"]), it).hex() == c.get("hash"):
            found.append((c["code_id"], c.get("staff_id", "?"), code))
    return found


def write_secret_file(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.chmod(path, 0o600)


def main(argv: list[str] | None = None) -> int:
    default_src = ROOT / "config" / ("schedule.demo.json" if (ROOT / "config" / "schedule.demo.json").exists()
                                     else "schedule.example.json")
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--src", "--in", dest="src", default=str(default_src))
    ap.add_argument("--out", dest="dst", default=str(ROOT / "edge" / "data" / "bundle.signed.json"))
    ap.add_argument("--codes-file", default=str(ROOT / "edge" / "data" / "DEMO_CODES.txt"))
    ap.add_argument("--key-env", default="SCHEDULE_BUNDLE_HMAC_KEY")
    ap.add_argument("--key-id", default=None,
                    help="signature key_id (default: SCHEDULE_BUNDLE_KEY_ID from the environment / .env, else "
                         f"{DEFAULT_KEY_ID}); must equal the edge's pinned key id (EO-02)")
    ap.add_argument("--keep-times", action="store_true", help="do not re-stamp issued_at/expires_at/valid_until")
    ap.add_argument("--valid-hours", type=float, default=12.0)
    ap.add_argument("--code-grace-hours", type=float, default=None,
                    help="override valid_until = expires_at + N h (default: YAML fallback.staff_override."
                         "valid_after_expiry_h)")
    ap.add_argument("--version", type=int, default=None,
                    help="override bundle_version (default: max(source, installed at --out + 1))")
    ap.add_argument("--now", default=None, help="ISO-8601 timestamp to stamp instead of the current time")
    ap.add_argument("--no-card-hashes", action="store_true",
                    help="leave every source card_id_hash untouched (no DEMO_CARDS re-hash, no documented-card drop)")
    ap.add_argument("--demo-cards", action="store_true",
                    help="DEMO ONLY: hash the publicly documented DEMO_CARDS into the bundle with CARD_ID_PEPPER")
    ap.add_argument("--extra-codes", type=int, default=0, help="generate N extra one-time override codes")
    ap.add_argument("--min-codes", type=int, default=4,
                    help="generate fresh codes until at least N override codes are in the bundle (default 4)")
    ap.add_argument("--allow-doc-codes", action="store_true",
                    help="keep the publicly documented OVR-001..003 codes (test fixtures only, never a live kiosk)")
    ap.add_argument("--provision-totp", nargs="*", default=[], metavar="USER_ID",
                    help="ensure a TOTP secret exists for these users (edge/data/credentials.enc)")
    args = ap.parse_args(argv)

    live_out = (ROOT / "edge" / "data" / "bundle.signed.json").resolve()
    if args.allow_doc_codes and Path(args.dst).resolve() == live_out:
        raise SystemExit("error: --allow-doc-codes is for test fixtures only; refusing to write the live bundle "
                         f"{live_out} (pass --out <scratch path>)")
    if args.code_grace_hours is None:
        args.code_grace_hours = yaml_code_grace_hours()
    env = read_env()
    if args.key_id is None:  # OS-4: same key id as the edge pins (read_env copies only *_KEY / *_PEPPER vars)
        args.key_id = os.environ.get("SCHEDULE_BUNDLE_KEY_ID") or env.get("SCHEDULE_BUNDLE_KEY_ID") or DEFAULT_KEY_ID
    key = (env.get(args.key_env) or "").encode()
    if not key:
        raise SystemExit(f"error: {args.key_env} is not set (environment or .env)")
    bundle = json.loads(Path(args.src).read_text(encoding="utf-8"))
    now = (datetime.fromisoformat(args.now) if args.now else datetime.now(UTC))
    installed = installed_version(Path(args.dst))
    bundle["bundle_version"] = pick_version(bundle.get("bundle_version"), installed, args.version)
    if installed is not None and bundle["bundle_version"] <= installed:
        print(f"warning: bundle_version {bundle['bundle_version']} is not newer than the installed v{installed}; "
              "a running edge rejects it as older (or as an older issued_at)", file=sys.stderr)
    if not args.keep_times:
        stamp(bundle, now, args.valid_hours, args.code_grace_hours)
    cards = cards_dropped = 0
    pepper = (env.get("CARD_ID_PEPPER") or "").encode()
    if pepper and args.demo_cards and not args.no_card_hashes:
        cards = recompute_card_hashes(bundle, pepper)
    elif pepper and not args.demo_cards and not args.no_card_hashes:
        cards_dropped = drop_demo_card_hashes(bundle, pepper)
    expires = bundle.get("expires_at", "")
    code_until = (datetime.fromisoformat(expires) + timedelta(hours=args.code_grace_hours)
                  if expires else now + timedelta(hours=36))
    dropped = [] if args.allow_doc_codes else drop_documented_codes(bundle)
    present = len((bundle.get("override_codes") or {}).get("codes") or [])
    n_new = max(args.extra_codes, args.min_codes - present, 0)
    code_length = yaml_code_length()
    new_codes = add_codes(bundle, n_new, now, _iso(code_until), code_length) if n_new > 0 else []
    signed = sign_bundle(bundle, key, key_id=args.key_id)
    if not verify_bundle(signed, key, args.key_id):
        raise SystemExit("error: signature self-check failed")
    out = Path(args.dst)
    # owner-only 0600 + fsync + atomic (SC2-D8 / EO-M2): the bundle holds PBKDF2 code hashes and card hashes
    write_private_atomic(out, json.dumps(signed, ensure_ascii=False, indent=1).encode("utf-8"), prefix=".bundle-")

    totp_lines = []
    if args.provision_totp:
        from edge.offline.credentials import CredentialStore

        data_key = env.get("EDGE_DATA_KEY")
        if not data_key:
            raise SystemExit("error: EDGE_DATA_KEY is not set (needed to store TOTP secrets)")
        store = CredentialStore(out.parent / "credentials.enc", data_key)
        for uid in args.provision_totp:
            secret = store.totp_secret(uid)
            if not secret:
                store.provision_totp(uid)
                secret = store.totp_secret(uid)
            totp_lines.append(f"  {uid}: otpauth://totp/HID-Kiosk:{uid}?secret={secret}&issuer=HID-Kiosk&digits=6&period=30")

    users = signed.get("users") or {}
    lines = [
        "# DEMO ONLY - generated by scripts/sign_bundle.py. Keep private: never commit, never show on screen.",
        f"# written {_iso(now)}  bundle v{signed.get('bundle_version')}  src {Path(args.src).name}",
        (f"# issued_at {signed.get('issued_at')}  expires_at {signed.get('expires_at')}  "
        f"(effective expiry = min(expires_at, issued_at + 12 h))"),
        "",
        (f"Staff override codes (one-time, {code_length} digits for new codes; consumed on first use; "
         "STAFF_OVERRIDE method):"),
    ]
    for cid, staff, code in (documented_codes(signed) if args.allow_doc_codes else []) + new_codes:
        lines.append(f"  {cid:<22} {staff:<10} {code}")
    if cards:
        lines += ["", "Demo cards (type into 'Tap card'; CARD method; must belong to the face candidate):"]
        for card, uid in DEMO_CARDS.items():
            if uid in users:
                lines.append(f"  {card}  ->  {uid} ({users[uid].get('display', '?')})")
    if totp_lines:
        lines += ["", "TOTP provisioning (scan as QR / paste into an authenticator app):"] + totp_lines
    write_secret_file(Path(args.codes_file), "\n".join(lines) + "\n")

    print(f"signed bundle v{signed.get('bundle_version')} -> {out}"
          + (f"  (installed v{installed} before)" if installed is not None else ""))
    print(f"  issued_at {signed.get('issued_at')}  expires_at {signed.get('expires_at')}  alg HMAC-SHA256  "
          f"key_id {args.key_id}  users {len(users)}  demo card hashes {cards}  "
          f"documented card hashes dropped {cards_dropped}  "
          f"new override codes {len(new_codes)}  documented codes dropped {len(dropped)}  "
          f"totp provisioned {len(totp_lines)}")
    print(f"  demo secrets written to {args.codes_file} (mode 600) - not printed here")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
