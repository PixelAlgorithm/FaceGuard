#!/usr/bin/env python3
"""Drop packages from a hash-pinned requirements file (stdin -> stdout), keeping every other block intact.

`uv export` writes one block per package: `name==version \\` followed by `--hash=...` continuation lines and
`# via` comments. A line-based grep would leave orphaned hash lines behind and break `--require-hashes`
(CIT-16), so whole blocks are removed. Usage: filter_requirements.py boto3 botocore ... < in > out
"""

from __future__ import annotations

import re
import sys

_REQ = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?==")


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def drop_packages(text: str, names: set[str]) -> str:
    drop = {_norm(n) for n in names}
    out: list[str] = []
    skipping = False
    for line in text.splitlines(keepends=True):
        m = _REQ.match(line)
        if m:
            skipping = _norm(m.group(1)) in drop
        elif not line.startswith((" ", "\t")):
            skipping = False
        if not skipping:
            out.append(line)
    return "".join(out)


def main(argv: list[str]) -> int:
    sys.stdout.write(drop_packages(sys.stdin.read(), set(argv)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
