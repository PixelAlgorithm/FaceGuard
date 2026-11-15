"""Consented team face photos for offline FAR/FRR cross-matching -> eval/captures/ (gitignored, deleted after the event).

  ../edge/.venv/bin/python collect_faces.py webcam --subject S01 --n 12 --lighting office --consent-confirmed
  ../edge/.venv/bin/python collect_faces.py webcam --subject S01 --n 3 --role enrol --consent-confirmed
  ../edge/.venv/bin/python collect_faces.py import --subject S02 --from-dir ~/Desktop/S02 --lighting dim --consent-confirmed
  ../edge/.venv/bin/python collect_faces.py list
  ../edge/.venv/bin/python collect_faces.py purge --yes            # delete every image + the embedding cache

Rules: the subject must be in eval/subjects.csv with consent=yes AND the operator passes --consent-confirmed for this
session (logged in captures/consent_log.csv). Images stay in eval/captures/ only; nothing here is ever copied into
eval/results/. `webcam` needs OpenCV (edge venv) and macOS camera permission for the terminal; `import` is stdlib.
Use the kiosk webcam, the three lightings and the 30-60 cm distance so the scores resemble live attempts.
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import sys
import time
from pathlib import Path

EVAL = Path(__file__).resolve().parent
sys.path.insert(0, str(EVAL))

from evallib import CAPTURES_DIR, EVAL_DIR
from evallib import io as eio
from evallib import schema as S

MANIFEST_COLUMNS = ["image_id", "subject_id", "split", "role", "lighting", "distance", "source", "captured_at_utc",
                    "file"]
IMG_EXT = {".jpg", ".jpeg", ".png"}


def _subject(subjects: Path, sid: str) -> dict:
    _, rows = eio.read_csv(subjects)
    reg = {r["subject_id"]: r for r in rows}
    if sid not in reg:
        raise SystemExit(f"{sid} not in {subjects} - register it with plan.py subjects first")
    if (reg[sid].get("consent") or "").lower() not in ("yes", "y", "true", "1"):
        raise SystemExit(f"{sid} has no recorded consent in {subjects}")
    return reg[sid]


def _append(captures: Path, rows: list[dict]) -> int:
    """Append new images; identical content already in the manifest is skipped (duplicates would inflate N)."""
    _, existing = eio.read_csv(captures / "manifest.csv")
    known = {r["image_id"]: r["subject_id"] for r in existing}
    added = 0
    for r in rows:
        if r["image_id"] in known:
            print(f"  skipped duplicate image {r['image_id']} (already registered for {known[r['image_id']]})")
            continue
        known[r["image_id"]] = r["subject_id"]
        eio.append_csv_row(captures / "manifest.csv", MANIFEST_COLUMNS, r)
        added += 1
    return added


def _log_consent(captures: Path, sid: str, a) -> None:
    eio.append_csv_row(captures / "consent_log.csv", ["subject_id", "ts_utc", "operator", "mode", "statement"], {
        "subject_id": sid, "ts_utc": eio.utc_now_iso(), "operator": a.operator, "mode": a.cmd,
        "statement": "subject consented to capture for this evaluation; images deleted after the event"})


def _store(captures: Path, sid: str, data: bytes, ext: str, role: str, lighting: str, distance: str, split: str) -> dict:
    iid = "img_" + hashlib.sha256(data).hexdigest()[:16]
    rel = Path(sid) / f"{role}_{lighting}_{distance}_{iid}{ext}"
    (captures / rel).parent.mkdir(parents=True, exist_ok=True)
    if not (captures / rel).exists():
        (captures / rel).write_bytes(data)
    return {"image_id": iid, "subject_id": sid, "split": split, "role": role, "lighting": lighting,
            "distance": distance, "source": "live", "captured_at_utc": eio.utc_now_iso(), "file": str(rel)}


def cmd_webcam(a) -> int:
    import cv2  # edge venv

    reg = _subject(a.subjects, a.subject)
    _log_consent(a.captures, a.subject, a)
    cap = cv2.VideoCapture(a.camera)
    if not cap.isOpened():
        raise SystemExit("camera not available (check macOS camera permission for this terminal)")
    print(f"{a.subject}: {a.n} frames, {a.lighting}/{a.distance}, role {a.role}; look at the camera, small natural "
          "pose changes between frames")
    for k in (3, 2, 1):
        print(f"  {k}...")
        time.sleep(1)
    rows = []
    try:
        for _ in range(a.n):
            ok, frame = cap.read()
            if not ok:
                continue
            ok, buf = cv2.imencode(".jpg", frame, [cv2.IMWRITE_JPEG_QUALITY, 92])
            if ok:
                rows.append(_store(a.captures, a.subject, buf.tobytes(), ".jpg", a.role, a.lighting, a.distance,
                                   reg["split"]))
            time.sleep(a.interval)
    finally:
        cap.release()
    n = _append(a.captures, rows)
    print(f"stored {n} new images under {a.captures / a.subject}")
    return 0


def cmd_import(a) -> int:
    reg = _subject(a.subjects, a.subject)
    _log_consent(a.captures, a.subject, a)
    files = sorted(p for p in a.from_dir.iterdir() if p.suffix.lower() in IMG_EXT)
    rows = [_store(a.captures, a.subject, f.read_bytes(), f.suffix.lower(), a.role, a.lighting, a.distance,
                   reg["split"]) for f in files]
    n = _append(a.captures, rows)
    print(f"imported {n} new images for {a.subject}")
    return 0


def cmd_list(a) -> int:
    _, rows = eio.read_csv(a.captures / "manifest.csv")
    from collections import Counter

    c = Counter((r["subject_id"], r["split"], r["role"], r["lighting"]) for r in rows)
    for k, v in sorted(c.items()):
        print("  " + " / ".join(k) + f": {v}")
    print(f"{len(rows)} images in {a.captures}")
    return 0


def cmd_purge(a) -> int:
    if not a.yes:
        raise SystemExit("add --yes to delete every captured image and the embedding cache")
    if a.captures.exists():
        shutil.rmtree(a.captures)
    print(f"deleted {a.captures}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--captures", type=Path, default=CAPTURES_DIR)
    ap.add_argument("--subjects", type=Path, default=EVAL_DIR / "subjects.csv")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("webcam", "import"):
        p = sub.add_parser(name)
        p.add_argument("--subject", required=True)
        p.add_argument("--lighting", choices=S.LIGHTING, default="office")
        p.add_argument("--distance", choices=S.DISTANCE, default="mid")
        p.add_argument("--role", choices=["enrol", "probe"], default="probe")
        p.add_argument("--consent-confirmed", action="store_true", required=True)
        p.add_argument("--operator", default="")
        if name == "webcam":
            p.add_argument("--n", type=int, default=12)
            p.add_argument("--camera", type=int, default=0)
            p.add_argument("--interval", type=float, default=0.7)
        else:
            p.add_argument("--from-dir", type=Path, required=True)
    sub.add_parser("list")
    pp = sub.add_parser("purge")
    pp.add_argument("--yes", action="store_true")
    a = ap.parse_args(argv)
    if eio.is_inside(a.captures, EVAL_DIR / "results"):
        raise SystemExit("captures must never live under eval/results/")
    return {"webcam": cmd_webcam, "import": cmd_import, "list": cmd_list, "purge": cmd_purge}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
