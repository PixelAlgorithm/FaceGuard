"""Make marker JPEGs for the FAKE face backend (local tests / edge integration before AWS exists).

    python -m cloud.tools.fakeimg "u_3c4d" /tmp/priya.jpg
    python -m cloud.tools.fakeimg "u_3c4d=97.5;u_1a2b=85" /tmp/ambiguous.jpg
    python -m cloud.tools.fakeimg NOFACE /tmp/noface.jpg

The output is a real (decodable) 16x16 JPEG with a COM segment `HIDFAKE:<spec>`. Real Rekognition
would see a tiny grey square (no face); only FACE_BACKEND=fake interprets the marker.
"""

from __future__ import annotations

import base64
import sys

_BASE_JPEG = base64.b64decode(
    "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDABALDA4MChAODQ4SERATGCgaGBYWGDEjJR0oOjM9PDkzODdASFxOQERXRTc4UG1RV19i"
    "Z2hnPk1xeXBkeFxlZ2P/2wBDARESEhgVGC8aGi9jQjhCY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2Nj"
    "Y2NjY2NjY2P/wAARCAAQABADASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUF"
    "BAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVW"
    "V1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi"
    "4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAEC"
    "AxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVm"
    "Z2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq"
    "8vP09fb3+Pn6/9oADAMBAAIRAxEAPwBaKKK5TqP/2Q=="
)


def make_fake_jpeg(spec: str, salt: str = "") -> bytes:
    """`salt` makes otherwise-identical images byte-distinct (e.g. several enrolment frames)."""
    comment = f"HIDFAKE:{spec} {salt}".strip().encode("ascii")
    seg = b"\xff\xfe" + (len(comment) + 2).to_bytes(2, "big") + comment
    return _BASE_JPEG[:2] + seg + _BASE_JPEG[2:]


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__)
        return 2
    with open(argv[2], "wb") as fh:
        fh.write(make_fake_jpeg(argv[1]))
    print(f"wrote {argv[2]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
