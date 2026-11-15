"""Stub harness for the cloud/infra bash scripts: NO AWS call is ever made.

A fake `aws` (and `curl`, `sleep`, `openssl`) is put first on PATH. Each call is appended to a JSON-lines log;
responses come from ordered rules `{"match": [substr...], "rc": int, "stdout": str, "stderr": str}` (first rule
whose substrings all occur in the joined argv wins; default rc 0 with empty output). State, build output and
the .env all live in a per-test tmp dir, so the real cloud/infra/.state and the project .env are never read.
"""

# ruff: noqa: S603, S607, S105, S106, S108

from __future__ import annotations

import json
import os
import stat
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
INFRA = ROOT / "cloud" / "infra"

DUMMY_SECRETS = {
    "KIOSK_HMAC_KEY": "dummy-kiosk-hmac-key-0123456789abcdef",
    "SCHEDULE_BUNDLE_HMAC_KEY": "dummy-bundle-key-0123456789abcdef",
    "CLOUD_API_KEY": "dummy-cloud-api-key-0123456789abcdef",
    "ADMIN_TOKEN": "dummy-admin-token-0123456789abcdef",
    "CARD_ID_PEPPER": "dummy-card-pepper-0123456789abcdef",
    "OTP_PEPPER": "dummy-otp-pepper-0123456789abcdef",
    "CLOUD_DATA_KEY": "dummy-cloud-data-key-0123456789abcdef",
}
# Non-secret switches that make DUMMY_SECRETS a configuration cloud/app/config.py accepts: without
# KIOSK_KEYS_JSON the cloud refuses to start unless ALLOW_SHARED_KIOSK_KEY=1 (CI-02). Kept out of DUMMY_SECRETS
# because the leak checks search output for every DUMMY_SECRETS value.
DUMMY_FLAGS = {"ALLOW_SHARED_KIOSK_KEY": "1"}
DUMMY_ENV = {**DUMMY_SECRETS, **DUMMY_FLAGS}

_STUB = r'''#!/usr/bin/env python3
import json, os, sys
name = os.path.basename(sys.argv[0])
argv = sys.argv[1:]
joined = " ".join(argv)
with open(os.environ["STUB_LOG"], "a") as fh:
    fh.write(json.dumps({"tool": name, "argv": argv}) + "\n")
rules = json.load(open(os.environ["STUB_RULES"])) if os.path.exists(os.environ["STUB_RULES"]) else []
for i, r in enumerate(rules):
    if r.get("tool", "aws") == name and all(m in joined for m in r.get("match", [])):
        if r.get("once"):
            done = os.environ["STUB_LOG"] + ".once"
            seen = open(done).read().split("\n") if os.path.exists(done) else []
            key = str(i)
            if key in seen:
                continue
            open(done, "a").write(key + "\n")
        out = r.get("stdout", "")
        if r.get("write_o"):  # curl -o FILE
            if "-o" in argv:
                open(argv[argv.index("-o") + 1], "w").write(r["write_o"])
        if r.get("write_last") is not None:  # positional outfile (aws lambda invoke ... OUTFILE)
            open(argv[-1], "w").write(r["write_last"])
        sys.stdout.write(out)
        sys.stderr.write(r.get("stderr", ""))
        sys.exit(r.get("rc", 0))
sys.exit(0)
'''


@dataclass
class Harness:
    tmp: Path
    bin: Path
    log: Path
    rules_file: Path
    env_file: Path
    state_dir: Path
    build_dir: Path
    rules: list[dict] = field(default_factory=list)

    def rule(self, *match: str, rc: int = 0, stdout: str = "", stderr: str = "", tool: str = "aws",
             once: bool = False, write_o: str | None = None) -> None:
        r: dict = {"tool": tool, "match": list(match), "rc": rc, "stdout": stdout, "stderr": stderr, "once": once}
        if write_o is not None:
            r["write_o"] = write_o
        self.rules.append(r)
        self.rules_file.write_text(json.dumps(self.rules))

    def not_found(self, *match: str, code: str = "ResourceNotFoundException") -> None:
        self.rule(*match, rc=254, stderr=f"An error occurred ({code}) when calling the X operation: not found")

    def calls(self, tool: str = "aws") -> list[list[str]]:
        if not self.log.exists():
            return []
        rows = [json.loads(x) for x in self.log.read_text().splitlines() if x.strip()]
        return [r["argv"] for r in rows if r["tool"] == tool]

    def joined_calls(self, tool: str = "aws") -> list[str]:
        return [" ".join(c) for c in self.calls(tool)]

    def env(self, **extra: str) -> dict[str, str]:
        env = {k: v for k, v in os.environ.items() if not k.startswith(("AWS_", "HID_", "REKOGNITION_"))}
        env.update({
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "STUB_LOG": str(self.log), "STUB_RULES": str(self.rules_file),
            "AWS_ACCESS_KEY_ID": "AKIAEXAMPLEEXAMPLE00", "AWS_SECRET_ACCESS_KEY": "stub-secret",
            "HID_STATE_DIR": str(self.state_dir), "HID_BUILD_DIR": str(self.build_dir),
            "HID_ENV_FILE": str(self.env_file), "TMPDIR": str(self.tmp / "tmpdir"),
        })
        env.update(extra)
        return env

    def run(self, script: str, *args: str, input_text: str | None = None, **extra: str) -> subprocess.CompletedProcess:
        return subprocess.run(["bash", str(INFRA / script), *args], env=self.env(**extra), capture_output=True,
                              text=True, timeout=120, input=input_text if input_text is not None else "")

    def bash(self, code: str, **extra: str) -> subprocess.CompletedProcess:
        return subprocess.run(["bash", "-c", f'source "{INFRA}/common.sh"; {code}'], env=self.env(**extra),
                              capture_output=True, text=True, timeout=60, input="")

    def write_env(self, **values: str) -> None:
        merged = {**DUMMY_ENV, **values}
        self.env_file.write_text("".join(f"{k}={v}\n" for k, v in merged.items() if v is not None))
        os.chmod(self.env_file, 0o600)

    def state(self, name: str = "deploy.env") -> dict[str, str]:
        p = self.state_dir / name
        if not p.exists():
            return {}
        return dict(line.split("=", 1) for line in p.read_text().splitlines() if "=" in line)

    def write_state(self, values: dict[str, str], name: str = "deploy.env") -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        (self.state_dir / name).write_text("".join(f"{k}={v}\n" for k, v in values.items()))


@pytest.fixture
def h(tmp_path: Path) -> Harness:
    b = tmp_path / "bin"
    b.mkdir()
    for tool in ("aws", "curl", "sleep", "openssl"):
        p = b / tool
        p.write_text(_STUB)
        p.chmod(p.stat().st_mode | stat.S_IXUSR)
    (tmp_path / "tmpdir").mkdir()
    hn = Harness(tmp=tmp_path, bin=b, log=tmp_path / "calls.jsonl", rules_file=tmp_path / "rules.json",
                 env_file=tmp_path / "dot.env", state_dir=tmp_path / "state", build_dir=tmp_path / "build")
    hn.write_env()
    hn.build_dir.mkdir()
    (hn.build_dir / "hid-cloud.tgz").write_bytes(b"fake-artifact")
    (hn.build_dir / "hid-cloud-lambda.zip").write_bytes(b"fake-zip")
    hn.rule("sts", "get-caller-identity", stdout="123456789012\n")
    # deploy_lambda.sh health-checks a new version before moving alias live: healthy by default
    hn.rules.append({"tool": "aws", "match": ["lambda invoke"], "rc": 0, "stdout": '{"StatusCode": 200}',
                     "stderr": "", "once": False, "write_last": '{"statusCode": 200, "body": "{}"}'})
    hn.rules_file.write_text(json.dumps(hn.rules))
    return hn
