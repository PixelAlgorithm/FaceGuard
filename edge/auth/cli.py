"""Console administration of staff accounts and API keys: `python -m edge.auth <command>`.

Works with the edge stopped or running (cross-process file lock). Reads EDGE_DATA_DIR / EDGE_DATA_KEY /
STAFF_STORE_KEY from the environment or the project .env (like edge/config.py). Secrets are never printed,
except the one-time API key / TOTP secret the operator asked for. Actions are audited as actor
{kind: "cli", id: "cli:<os user>"}.

Exit codes: 0 ok, 2 usage / validation error, 75 store busy (retry), 1 any other error.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import TextIO

from edge import config as edge_config
from edge.auth.models import AuthError, staff_id_for
from edge.auth.service import AuthService, build_auth_service
from edge.auth.staff_ops import DEFAULT_API_KEY_DAYS, cli_principal

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_BUSY = 75
_USAGE_CODES = frozenset({"VALIDATION_ERROR", "INVALID_STATE", "NOT_FOUND", "FORBIDDEN"})
Handler = Callable[[AuthService, argparse.Namespace, "Io"], int]


class Io:
    def __init__(self, stdin: TextIO, stdout: TextIO, stderr: TextIO) -> None:
        self.stdin, self.stdout, self.stderr = stdin, stdout, stderr

    def out(self, text: str) -> None:
        print(text, file=self.stdout)

    def err(self, text: str) -> None:
        print(text, file=self.stderr)


def load_env(env: Mapping[str, str] | None) -> dict[str, str]:
    if env is not None:
        return dict(env)
    edge_config.load_dotenv(edge_config.PROJECT_ROOT / ".env")
    return dict(os.environ)


def data_dir_from(env: Mapping[str, str]) -> Path:
    return Path(env.get("EDGE_DATA_DIR") or str(edge_config.PROJECT_ROOT / "edge" / "data"))


def read_password(args: argparse.Namespace, io: Io, username: str) -> str:
    if args.password_stdin:
        return io.stdin.readline().rstrip("\r\n")
    first = getpass.getpass(f"New password for {username}: ")
    if first != getpass.getpass("Repeat the password: "):
        raise AuthError("VALIDATION_ERROR", "the two passwords differ")
    return first


# ---------------------------------------------------------------------------- commands
def cmd_create_user(auth: AuthService, args: argparse.Namespace, io: Io) -> int:
    password = read_password(args, io, args.username)
    account = auth.create_staff(cli_principal(), args.username, args.display_name, args.role, password,
                                must_change_password=args.temporary, allow_missing_store=args.recreate_store)
    io.out(f"created {account.staff_id} roles={','.join(account.roles)}")
    return cmd_enable_mfa(auth, args, io) if args.mfa else EXIT_OK


def cmd_set_password(auth: AuthService, args: argparse.Namespace, io: Io) -> int:
    password = read_password(args, io, args.username)
    auth.reset_password(cli_principal(), staff_id_for(args.username), password, must_change_password=args.temporary)
    io.out(f"password set for {staff_id_for(args.username)} (all its sessions ended)")
    return EXIT_OK


def cmd_set_roles(auth: AuthService, args: argparse.Namespace, io: Io) -> int:
    account = auth.update_staff(cli_principal(), staff_id_for(args.username), roles=args.role)
    io.out(f"{account.staff_id} roles={','.join(account.roles)}")
    return EXIT_OK


def _set_status(status: str) -> Handler:
    def handler(auth: AuthService, args: argparse.Namespace, io: Io) -> int:
        account = auth.update_staff(cli_principal(), staff_id_for(args.username), status=status)
        io.out(f"{account.staff_id} status={account.status}")
        return EXIT_OK

    return handler


def cmd_unlock(auth: AuthService, args: argparse.Namespace, io: Io) -> int:
    account = auth.unlock(cli_principal(), staff_id_for(args.username))
    io.out(f"{account.staff_id} unlocked")
    return EXIT_OK


def cmd_list(auth: AuthService, args: argparse.Namespace, io: Io) -> int:
    actor, now = cli_principal(), auth.clock()
    staff = [a.to_public(now) for a in auth.list_staff(actor)]
    keys = [k.to_public(now) for k in auth.list_api_keys(actor)]
    if args.json:
        io.out(json.dumps({"store": auth.store_state, "staff": staff, "api_keys": keys}, indent=2))
        return EXIT_OK
    io.out(f"store: {auth.store_state}")
    for a in staff:
        flags = [f for f, on in (("locked", a["locked"]), ("mfa", a["mfa_enabled"]),
                                 ("must-change", a["must_change_password"])) if on]
        io.out(f"{a['staff_id']:<34} {a['status']:<9} {','.join(a['roles']):<32} {' '.join(flags)}")
    for k in keys:
        io.out(f"key {k['key_id']} {k['status']:<8} {','.join(k['roles']):<32} {k['name']} "
               f"expires={k['expires_at']}")
    return EXIT_OK


def cmd_create_api_key(auth: AuthService, args: argparse.Namespace, io: Io) -> int:
    key, full = auth.create_api_key(cli_principal(), args.name, args.role, expires_days=args.expires_days)
    io.out(full)  # shown once; the store keeps only its digest
    expires = key.to_public(auth.clock())["expires_at"]
    summary = f"created API key {key.key_id} roles={','.join(key.roles)} expires={expires} (shown once)"
    (io.err if args.print_key_only else io.out)(summary)
    return EXIT_OK


def cmd_revoke_api_key(auth: AuthService, args: argparse.Namespace, io: Io) -> int:
    auth.revoke_api_key(cli_principal(), args.key_id)
    io.out(f"API key {args.key_id} revoked")
    return EXIT_OK


def cmd_enable_mfa(auth: AuthService, args: argparse.Namespace, io: Io) -> int:
    actor, staff_id = cli_principal(), staff_id_for(args.username)
    setup = auth.begin_mfa(actor, staff_id)
    io.out("Add this account to an authenticator app (shown once):")
    io.out(f"  secret: {setup.secret}")
    io.out(f"  uri:    {setup.otpauth_uri}")
    io.stdout.flush()
    io.err("Enter the 6-digit code from the app:")
    code = io.stdin.readline().strip()
    auth.confirm_mfa(actor, staff_id, code)
    io.out(f"MFA enabled for {staff_id}")
    return EXIT_OK


def cmd_disable_mfa(auth: AuthService, args: argparse.Namespace, io: Io) -> int:
    auth.reset_mfa(cli_principal(), staff_id_for(args.username))
    io.out(f"MFA removed for {staff_id_for(args.username)} (all its sessions ended)")
    return EXIT_OK


REKEY_WARNING = ("a running edge's staff auth becomes 503 AUTH_UNAVAILABLE immediately and stays down until "
                 "STAFF_STORE_KEY is set to the new key and the edge is restarted: stop the edge first")


def cmd_rekey(auth: AuthService, args: argparse.Namespace, io: Io) -> int:
    if not args.force:
        io.err(f"error: refusing to rekey without --force: {REKEY_WARNING}")
        return EXIT_USAGE
    io.err(f"warning: {REKEY_WARNING}")
    new_key = io.stdin.readline().strip()
    auth.store.rekey(new_key)
    auth.audit.safe_append("store.rekey", actor=cli_principal().actor())
    io.out("staff store re-encrypted; set STAFF_STORE_KEY to the new key before restarting the edge")
    return EXIT_OK


# ---------------------------------------------------------------------------- parser
def _user_arg(p: argparse.ArgumentParser) -> None:
    p.add_argument("--username", required=True)


def _password_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--password-stdin", action="store_true", help="read the password from the first stdin line")
    p.add_argument("--temporary", action="store_true", help="force a password change at next sign-in")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m edge.auth", description="FaceGuard staff accounts and API keys")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("create-user", help="create a staff account")
    _user_arg(p)
    p.add_argument("--display-name", required=True)
    p.add_argument("--role", action="append", required=True, help="repeat for several roles (1..3)")
    p.add_argument("--mfa", action="store_true", help="enrol TOTP right away")
    p.add_argument("--recreate-store", action="store_true",
                   help="allow re-creating a store the audit log says existed (state MISSING)")
    _password_args(p)
    p.set_defaults(handler=cmd_create_user)

    p = sub.add_parser("set-password", help="set a staff account's password (ends its sessions)")
    _user_arg(p)
    _password_args(p)
    p.set_defaults(handler=cmd_set_password)

    p = sub.add_parser("set-roles", help="replace a staff account's roles")
    _user_arg(p)
    p.add_argument("--role", action="append", required=True)
    p.set_defaults(handler=cmd_set_roles)

    for name, handler in (("disable", _set_status("disabled")), ("enable", _set_status("active")),
                          ("unlock", cmd_unlock), ("enable-mfa", cmd_enable_mfa), ("disable-mfa", cmd_disable_mfa)):
        p = sub.add_parser(name)
        _user_arg(p)
        p.set_defaults(handler=handler)

    p = sub.add_parser("list", help="list staff accounts and API keys (no secrets)")
    p.add_argument("--json", action="store_true")
    p.set_defaults(handler=cmd_list)

    p = sub.add_parser("create-api-key", help="create an API key (printed once)")
    p.add_argument("--name", required=True)
    p.add_argument("--role", action="append", required=True, help="repeat for several roles (1..3, not admin)")
    p.add_argument("--expires-days", type=int, default=DEFAULT_API_KEY_DAYS)
    p.add_argument("--print-key-only", action="store_true", help="stdout = the key only (for scripts)")
    p.set_defaults(handler=cmd_create_api_key)

    p = sub.add_parser("revoke-api-key")
    p.add_argument("--key-id", required=True)
    p.set_defaults(handler=cmd_revoke_api_key)

    p = sub.add_parser("rekey", help="re-encrypt the store under a new Fernet key read from stdin "
                                     "(stop the edge first)")
    p.add_argument("--force", action="store_true",
                   help="required: a running edge loses staff auth (503) until restarted with the new key")
    p.set_defaults(handler=cmd_rekey)
    return parser


def main(argv: Sequence[str] | None = None, *, env: Mapping[str, str] | None = None,
         stdin: TextIO | None = None, stdout: TextIO | None = None, stderr: TextIO | None = None) -> int:
    io = Io(stdin or sys.stdin, stdout or sys.stdout, stderr or sys.stderr)
    try:
        args = build_parser().parse_args(argv)
    except SystemExit as exc:
        return EXIT_OK if exc.code == 0 else EXIT_USAGE
    try:
        values = load_env(env)
        auth = build_auth_service(data_dir_from(values), values)
    except ValueError as exc:
        io.err(f"error: {exc}")
        return EXIT_USAGE
    try:
        return run(auth, args, io)
    finally:
        auth.close()


def run(auth: AuthService, args: argparse.Namespace, io: Io) -> int:
    try:
        return args.handler(auth, args, io)
    except AuthError as exc:
        detail = exc.extra.get("problems") or exc.extra.get("reason") or ""
        hint = f" ({auth.store.error})" if exc.code == "AUTH_UNAVAILABLE" and auth.store.error else ""
        io.err(f"error: {exc.message}{hint}" + (f": {detail}" if detail else ""))
        if exc.code == "AUTH_BUSY":
            return EXIT_BUSY
        return EXIT_USAGE if exc.code in _USAGE_CODES else EXIT_ERROR
    except ValueError as exc:
        io.err(f"error: {exc}")
        return EXIT_USAGE
